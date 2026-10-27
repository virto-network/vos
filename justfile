set shell := ["nu", "-c"]

default:
    @just --list

# The fast suites' crates, which `test` and `check` run.
core_crates := "-p vos-pvm -p vos-pvm-compiler -p vos-pvm-program -p vos-pvm-codec -p vos-raft -p merkle-crdt -p vos-pvm-precompiles -p vos-pvm-poseidon2 -p vos-pvm-proof-verifier -p vos-wire -p vos-tree -p vos-jam -p vos-pvm-recair-air -p vos-pvm-final-verifier -p vos-device -p vos-anchor -p vos-statement -p vos-statement-service --features vos-anchor/vectors,vos-statement/fixtures"

# The agent's suites' crates, which `test-agent` and `check` run.
agent_crates := "-p vos-sdk -p vos-sdk-macros -p vos-testkit -p vos-checker -p vos-api -p vos-http -p vos-gateway -p vos-node -p vos-node-prover -p vos-venue -p vos-net -p vos-cli -p vos-jam-dev -p vos-scale"

# A guest build for the PVM: the statement's target, its standard library
# built from source. Every guest and blob build sets `CARGO_INCREMENTAL` to
# 0: an incremental build, which the environment's `CARGO_INCREMENTAL=1`
# forces over the release profile, links other code, which the program ids
# and blob hashes pin and the transpiler may refuse.
guest_flags := "--target pvm/proof/statement/riscv64em-vos.json -Zbuild-std=core,alloc,compiler_builtins -Zbuild-std-features=compiler-builtins-mem"

# A venue guest of the workspace (`final-verify`, `final-verify-test`,
# `statement-service`), built from `package` with `features`: its panic
# locations name the repository's sources from its root, and the
# registry's, the git checkouts' and the toolchain's under `/cargo` and
# `/rustc`, never this checkout's or this machine's paths, so its bytes are
# the same in every checkout (`blobs.lock`).
_venue-guest package bin features:
    let cargo = ($env.CARGO_HOME? | default ($env.HOME | path join .cargo)); let sysroot = (rustc --print sysroot | str trim); let remaps = [$"--remap-path-prefix=($env.PWD)/=" $"--remap-path-prefix=($cargo)=/cargo" $"--remap-path-prefix=($sysroot)=/rustc"]; with-env { CARGO_INCREMENTAL: "0", CARGO_ENCODED_RUSTFLAGS: ($remaps | str join (char -u "1f")) } { cargo build -p {{package}} --release --features {{features}} --bin {{bin}} {{guest_flags}} }

# Fast suites: runtime, compiler, program format, codec, support crates,
# precompile shim, Poseidon2, verifier, the recursion AIR and its gate VM,
# prover library, wire types. The node runs the agent, so it is tested
# with it.
test:
    cargo test {{core_crates}}
    cargo test -p vos-statement --features heap-peak --test heap
    just test-recair
    cargo test -p vos-pvm-proof --lib

# The phone bench's two Android binaries (arm64-v8a, the NDK s4 builds
# with), the seeded one holding an x86 run's proof hashes: `tools/phone`.
phone out="target/phone":
    tools/phone/build.sh {{out}}

# The recursion AIR's prover tests, four at a time: at every core at once
# its recursion suite passed 12 GiB, the limit the gates run under.
test-recair:
    cargo test -p vos-pvm-recair -- --test-threads=4

# Bench guests, built with the guest toolchain in `pvm/guest`.
build-bench-guests:
    with-env { CARGO_INCREMENTAL: "0" } { for guest in [workflows actor agent hash-software hash-precompile poseidon2 diverse] { do { cd $"pvm/bench/guests/($guest)"; cargo build --release --target ../../../guest/riscv64em-vos.json } } }

# Cross-host checks that need the bench guests. The bench tests that prove
# run in `test-bench-proof`.
test-bench: build-bench-guests
    cargo test -p vos-pvm-bench

# Bench tests that prove end to end, one at a time. Memory-heavy.
test-bench-proof: build-bench-guests
    cargo test -p vos-pvm-bench --features prove --test diverse_proof --test precompile_tamper -- --test-threads=1

# Machine benches: snapshots of suspended workflows, and nested invocation.
bench: build-bench-guests
    cargo run --release -p vos-pvm-bench --bin snapshots
    cargo run --release -p vos-pvm-bench --bin nesting

# Gray Paper 0.8.0 conformance vectors on the interpreter and the JIT.
vectors:
    cargo test -p vos-pvm --test pvm_vectors

# Prover integration suites, including the soundness gates behind
# `debug-internals`, the re-runs of the test actors' kernels from their
# attests on the agent's model, the settlement window's kernel read at a
# cut and proved over its shape, the kernels' leaves and the window
# kernel's folds proved on the recursion AIR, the window's and the
# balance's whole runs folded and wrapped under format 28 and masked under
# 39, their statements judged at the model venue against the space's
# anchors, and the fixtures checked against their generator and judged in
# Wasm.
# The repository's constants (`pvm/proof/src/constants.rs`) are recomputed
# with and without `debug-internals`, and the prover worker's throughput at
# the default window length is measured (`kernel`'s `throughput`).
# Memory-heavy: the library, `gates` and `isa` run two tests at a time, and
# `kernel`, whose proving runs each take several GiB, one at a time: each
# of its tests (a window's up to about 9 GiB at its peak) in a process of
# its own, and `reads` (a million-row fixture held for the process's life)
# in one, as freed heap is not all returned between tests (a masked wrap
# after the balance's, the fixtures' and others' in one process passed 12
# GiB), so the recipe fits under a 12 GiB limit, e.g.
# `systemd-run --user --scope -p MemoryMax=12G -p MemorySwapMax=0 just test-proof`.
# They cover every admitted format, the Poseidon2-M31 segment format among
# them; the verifier's suite runs in `test`.
# Then the masking's heavy gates (`vos-pvm-recair`'s `heavy-gates`): the
# leakage tests at a medium N (500 proofs a witness on the small circuit, 16
# on the real wrap, 64 a kernel on the masked segment; `LEAKAGE_N`,
# `LEAKAGE_WRAP_N` and `LEAKAGE_SEGMENT_N` set others, and `slice-gate` the
# full 2,000, 32 and 256), the masked acceptance above 2^16
# rows, and the final verifier's decode, verify and Wasm gates as the
# maximum over 12 seeds of the masked wrap (on the JAM-only host's
# `final-verify.elf`, built by `check-no-std`, and `judge-wasm`'s blob),
# one test at a time. Last, the wrap files the suites wrote checked to be
# final wraps alone, and the carrier audit (`test-carriers`).
test-proof: build-test-actors judge-wasm
    cargo test -p vos-pvm-proof --features debug-internals --lib --bins --test gates --test isa -- --test-threads=2
    for test in (cargo test -p vos-pvm-proof --features debug-internals --test kernel -- --list --format terse --skip reads:: --skip wrap_files:: | lines | where {|line| $line ends-with ': test' } | each {|line| $line | str replace ': test' '' }) { cargo test -p vos-pvm-proof --features debug-internals --test kernel $test -- --exact --test-threads=1 }
    cargo test -p vos-pvm-proof --features debug-internals --test kernel reads:: -- --test-threads=1
    cargo test -p vos-pvm-proof --test kernel constants:: -- --test-threads=1
    cargo test -p vos-pvm-recair --features heavy-gates --test circuit --test recursion --test segment --test device --test credential -- leakage heavy --test-threads=1
    cargo test -p vos-pvm-proof --features debug-internals --test kernel wrap_files:: -- --test-threads=1
    just test-carriers

# The carrier audit (`proving.md` §5's R7, `vos_checker::carriers`):
# three nodes proving a read's statement with the masked prover, every
# debug output's environment set, and every carrier of the run searched for
# the proof's internals, the served rows and their hashes; alone in its
# process, which it captures whole (its logs at every level, its standard
# error). About two minutes and 6 GiB.
test-carriers: build-test-actors build-agent build-representative
    cargo test -p vos-node --features disclosing --test carriers audit:: -- --nocapture --test-threads=1

# The golden fixtures (`pvm/proof/fixtures`) judged in Wasm, by the final
# verifier's blobs built as a runtime builds them, under the PVF's semantics
# and the client's: the production blob (format 39 alone, a statement of 28
# refused as a format it does not link) and the test blob (`test-formats`,
# 28 beside it), every verdict the one its build reaches, as natively and on
# the JAM-only host (`vos-statement`'s fixtures test); and `vos-anchor`'s
# golden vectors computed by the production blob, every digest the pinned
# bytes.
judge-wasm: build-wasm-blobs
    cd pvm/proof/final-verifier/wasm/run; cargo build --release
    let run = "pvm/proof/final-verifier/wasm/run/target/release/vos-pvm-final-verifier-wasm-run"; for case in [[blob task]; ["wasm32-unknown-unknown" ["judge" "pvm/proof/fixtures" "39"]] ["test-formats/wasm32-unknown-unknown" ["judge" "pvm/proof/fixtures" "28,39"]] ["wasm32-unknown-unknown" ["anchors"]]] { for semantics in [pvf client] { ^$run $"pvm/proof/final-verifier/wasm/blob/target/($case.blob)/release/vos_pvm_final_verifier_wasm.wasm" $semantics ...$case.task } }

# The final verifier's Wasm blobs, built as a runtime builds them: the
# production blob, and the test blob (`test-formats`) in a target
# directory of its own.
build-wasm-blobs:
    with-env { CARGO_INCREMENTAL: "0" } { cd pvm/proof/final-verifier/wasm/blob; cargo build --release }
    with-env { CARGO_INCREMENTAL: "0" } { cd pvm/proof/final-verifier/wasm/blob; cargo build --release --features test-formats --target-dir target/test-formats }

# The proof fixtures under `pvm/proof/fixtures` (`proving.md` A.6), written
# anew by their generator, `pvm/proof/tests/kernel/fixtures.rs`: at a format bump,
# or a change of the AIR or a kernel's shape. `test-proof` refuses fixtures
# the generator does not make.
fixtures:
    with-env { VOS_FIXTURES: "write" } { cargo test -p vos-pvm-proof --test kernel fixtures::the_fixtures_are_the_generators }

# The reproducibility gate on aarch64: `vos program-id`, built for aarch64
# with the masked prover and run under qemu-user, recomputes each known
# kernel's program id from its test actor's ELF and the circuits'
# constants (`H_fold`, the wrap's roots), each the repository's
# (`pvm/proof/src/constants.rs`). It needs `qemu-aarch64`, an aarch64 GNU
# toolchain (`aarch64-linux-gnu-gcc`, its sysroot at
# `/usr/aarch64-linux-gnu`) and the toolchain's `aarch64-unknown-linux-gnu`
# target; on an ARM host, run `vos program-id` natively.
repro-aarch64: build-test-actors
    with-env { CARGO_TARGET_AARCH64_UNKNOWN_LINUX_GNU_LINKER: "aarch64-linux-gnu-gcc", CC_aarch64_unknown_linux_gnu: "aarch64-linux-gnu-gcc", AR_aarch64_unknown_linux_gnu: "aarch64-linux-gnu-ar" } { cargo build -p vos-cli --no-default-features --features prover --target aarch64-unknown-linux-gnu }
    let source = (open --raw pvm/proof/src/constants.rs); let pinned = {|name| $source | parse --regex ("pub const " + $name + ": \\[u\\d+; \\d+\\] = \\[(?<values>[^\\]]*)\\]") | get values.0 | split row "," | each {|value| $value | str trim } | where {|value| $value != "" } | str join " " }; let vos = {|...args| ^qemu-aarch64 -L /usr/aarch64-linux-gnu target/aarch64-unknown-linux-gnu/debug/vos program-id ...$args | str trim }; for case in [[window settle WINDOW_PROGRAM] [balance at_least BALANCE_PROGRAM] [kernels areas PREDICATE_PROGRAM]] { let printed = (do $vos $"agent/test-actors/target/riscv64em-vos/release/($case.0).elf" $case.1); if $printed != (do $pinned $case.2) { error make { msg: $"($case.2) on aarch64: ($printed)" } } }; let circuits = (do $vos "--circuits" | lines); let names = ($circuits | each {|line| $line | split row " " | first }); if $names != [H_FOLD WRAP_ROOT_28 WRAP_ROOT_39] { error make { msg: $"the circuits printed on aarch64: ($names)" } }; for line in $circuits { let parts = ($line | split row " "); if ($parts | skip 1 | str join " ") != (do $pinned $parts.0) { error make { msg: $"($parts.0) on aarch64: ($line)" } } }; print "the program ids and the circuits' constants on aarch64 are the repository's"

# The conformance vectors of Kreivo's spaces pallet and the mutation lists
# (`node/venue/conformance`, `spaces-pallet.md` §10), written anew by the
# reference mock (`node/venue/src/kreivo`) over the golden fixtures: after a
# change of the design, the mock or the fixtures. `check` refuses vectors
# the mock does not write.
conformance:
    with-env { VOS_CONFORMANCE: "write" } { cargo test -p vos-venue kreivo::conformance::the_vectors_are_the_generators }

# The tests run on mimalloc as the node's binary does, and as it does with
# transparent huge pages off.
export MIMALLOC_ALLOW_THP := "0"

# Formatting: the workspace's, and each crate's it excludes.
fmt-check:
    cargo fmt --all -- --check
    for manifest in ([agent/default agent/representative agent/credentials agent/test-actors pvm/bench/guests pvm/proof/fuzz pvm/proof/final-verifier/wasm spikes] | each {|dir| glob $'($dir)/**/Cargo.toml' --exclude ['**/target/**'] } | flatten | where {|manifest| open --raw $manifest | str contains '[package]' }) { cargo fmt --manifest-path $manifest -- --check }

# The docs' links: none broken, and none from a public doc to a private
# item.
doc-check:
    with-env { RUSTDOCFLAGS: "-D rustdoc::broken_intra_doc_links -D rustdoc::private_intra_doc_links" } { cargo doc --workspace --no-deps --quiet }
    with-env { RUSTDOCFLAGS: "-D rustdoc::broken_intra_doc_links -D rustdoc::private_intra_doc_links" } { cargo doc -p vos-venue --features kreivo-mock,model --no-deps --quiet }

clippy:
    cargo clippy --workspace --all-targets --quiet -- -D warnings
    cargo clippy -p vos-pvm-bench --features prove --all-targets --quiet -- -D warnings
    cargo clippy -p vos-cli --features faults --all-targets --quiet -- -D warnings
    cargo clippy -p vos-cli --no-default-features --all-targets --quiet -- -D warnings
    cargo clippy -p vos-pvm-proof --features debug-internals --all-targets --quiet -- -D warnings
    cargo clippy -p vos-venue --all-targets --quiet -- -D warnings
    for features in [model kreivo kreivo-mock] { cargo clippy -p vos-venue --features $features --quiet -- -D warnings }
    just clippy-prover

# The node and `vos` with the masked prover (`prover`): they build and lint
# clean.
clippy-prover:
    cargo clippy -p vos-node -p vos-cli --features vos-node/prover,vos-cli/prover --all-targets --quiet -- -D warnings
    cargo clippy -p vos-node --features chain --tests --quiet -- -D warnings

# Fails on any JAR remnant in the PVM crates: its ISA and gas modes, opcodes,
# exits, capability surface, linker entry points, invocation kernel, CSR
# 0x800 marker and fixtures. The proof crate's own `kernel` module and a
# 0x800 rounding constant are not remnants.
jar-check:
    let hits = (rg -n --glob '!**/target/**' 'IsaMode|CapabilityManifest|\blink_elf\b|link_elf_with_argument_pages|run_with_vos_stubs|ECALL_VOS_|VOS_OBJECT_CAP|Opcode::Ecall\b|ExitReason::Ecall|ExitReason::Trap\b|vos_pvm::kernel::|InvocationKernel|vm_pool|JAR\\x02|\.gp072\.json|\bGasModel\b|\bPerInstruction\b|\bmem_cycles\b|Opcode::Sbrk|\bsbrk\(|(?i:csr\w*,? 0x800)\b|\(\d, 0x800\)|Some\(0x800\)' pvm | complete); if ($hits.exit_code == 0) { print $hits.stdout; error make { msg: "JAR remnants found" } } else { print "no JAR remnants" }

# The SDK's test actors, built with the guest toolchain in `pvm/guest`.
build-test-actors:
    with-env { CARGO_INCREMENTAL: "0" } { cd agent/test-actors; cargo build --release --target ../../pvm/guest/riscv64em-vos.json }

# The default agent program, built in the agent's guest workspace
# (`agent/programs`) with the guest toolchain in `pvm/guest`.
build-agent: (_build-program "vos-agent")

# The space's representative, built in the agent's guest workspace.
build-representative: (_build-program "vos-representative")

# The credential actor, a library actor, built in the agent's guest
# workspace.
build-credentials: (_build-program "vos-credentials")

# One of the agent's guest programs, alone: its features never unified
# with another's.
_build-program package:
    with-env { CARGO_INCREMENTAL: "0" } { cd agent/programs; cargo build --release -p {{package}} --target ../../pvm/guest/riscv64em-vos.json }

# The JAM statements service's program, `statement-service.elf`.
build-statement-service: (_venue-guest "vos-statement-service" "statement-service" "pvm-guest")

# The venue's JAM refine programs: `final-verify.elf`, linking format 39
# alone, and `final-verify-test.elf`, linking 28 beside it.
build-final-verify: (_venue-guest "vos-statement" "final-verify" "pvm-guest") (_venue-guest "vos-statement" "final-verify-test" "pvm-guest,test-formats")

# Every guest blob `blobs.lock` pins, its path from the repository's root:
# the venue's programs, the final verifier's Wasm blobs, the agent's
# programs and the test actors.
_blob-paths:
    let fixed = ["target/riscv64em-vos/release/final-verify.elf" "target/riscv64em-vos/release/final-verify-test.elf" "target/riscv64em-vos/release/statement-service.elf" "pvm/proof/final-verifier/wasm/blob/target/wasm32-unknown-unknown/release/vos_pvm_final_verifier_wasm.wasm" "pvm/proof/final-verifier/wasm/blob/target/test-formats/wasm32-unknown-unknown/release/vos_pvm_final_verifier_wasm.wasm" "agent/programs/target/riscv64em-vos/release/vos-agent.elf" "agent/programs/target/riscv64em-vos/release/vos-representative.elf" "agent/programs/target/riscv64em-vos/release/vos-credentials.elf"]; let actors = (glob agent/test-actors/target/riscv64em-vos/release/*.elf | each {|path| $path | path relative-to $env.PWD } | sort); $fixed ++ $actors | str join "\n" | print

# Every guest blob, built as `check` builds it.
build-blobs: build-final-verify build-statement-service build-wasm-blobs build-agent build-representative build-credentials build-test-actors

# `blobs.lock` written anew from the blobs as built: after a change that
# moves one, which the lock's diff then shows.
blobs-lock: build-blobs
    just _blob-paths | lines | each {|path| $"(open --raw $path | hash sha256)  ($path)" } | prepend ["# Every guest blob's SHA-256, as `just build-blobs` builds it from a clean" "# checkout: `just blobs-lock` writes it, `just check-blobs` checks it."] | str join "\n" | $in + "\n" | save -f blobs.lock

# Every guest blob built and hashed, each its `blobs.lock` hash, and the
# lock naming every blob built: a change that moves a blob moves its line.
check-blobs: build-blobs
    let built = (just _blob-paths | lines | each {|path| $"(open --raw $path | hash sha256)  ($path)" }); let locked = (open --raw blobs.lock | lines | where {|line| not ($line | str starts-with "#") }); let moved = ($built | where {|line| $line not-in $locked }); let gone = ($locked | where {|line| $line not-in $built }); for line in $moved { print -e $"built: ($line)" }; for line in $gone { print -e $"locked: ($line)" }; if ($moved ++ $gone | is-not-empty) { error make { msg: "the guest blobs are not blobs.lock's: `just blobs-lock` after a change that moves them" } }; print $"every guest blob is blobs.lock's: ($built | length) blobs"

# The SDK, its macros' restrictions, the test actors on the testkit, the
# default agent against it, the checker's own model, the node running the
# agent, the network between nodes, and the `vos` command.
test-agent: build-test-actors build-agent build-representative build-credentials
    cargo test {{agent_crates}}
    cargo test -p vos-cli --features faults --test processes faults::
    cargo test -p vos-cli --features faults --test fault_suite
    just test-reads

# The gateway's SSH port and its `vos-api` subsystem (`vos-gateway`'s
# `ssh` feature), on s4-server: a dependency built apart from the default
# workspace build, its crates asking a newer stable Rust than the
# workspace's nightly names, which builds them.
test-gateway-ssh: build-test-actors build-agent
    cargo clippy -p vos-gateway --features ssh --ignore-rust-version --all-targets --quiet -- -D warnings
    cargo test -p vos-gateway --features ssh --ignore-rust-version

# The default agent as a service on a local PolkaJam testnet, which it
# starts and stops: a workflow suspended in one work package and resumed in
# later ones, every read witnessed. Outside `ci`: it needs the PolkaJam
# binaries, in POLKAJAM or the directory `testnet.sh` names by default.
jam-testnet: build-test-actors build-agent
    bash tools/jam-dev/testnet.sh

# The JAM statements service on a local PolkaJam testnet, which it starts
# and stops: deployed, a space registered and a window anchored, the golden
# fixtures' masked statements submitted with their proofs as extrinsics,
# each outcome read back, every refine's gas against the JAM-only host's.
# `bash tools/jam-dev/testnet.sh both` deploys it beside the default agent.
# Outside `ci`, as `jam-testnet` is.
jam-statements-testnet: build-statement-service
    bash tools/jam-dev/testnet.sh statements

# The end to end on chain, on a local PolkaJam testnet it starts and stops
# (`testnet.sh chain`): two spaces of three nodes proving with the masked
# prover, one anchoring and submitting at the Kreivo mock, the other at the JAM
# statements service, deployed twice; statements refused where their roots are
# not anchored, a rootless one refused, and a replay once the testnet's clock
# is moved past `MaxRootAge`; every carrier of the run audited; the latency,
# gas, fees and the prover's throughput measured, written to the run's
# `record.txt`. Outside `ci`, as `jam-testnet` is: it needs the PolkaJam
# binaries and a C compiler. About 25 minutes, one
# masked proof at a time (about 6 GiB): run it under a 12 GiB limit, e.g.
# `systemd-run --user --scope -p MemoryMax=12G -p MemorySwapMax=0 just e2e-chain`.
e2e-chain: build-test-actors build-agent build-representative build-statement-service
    cargo test -p vos-node --features chain --test chain --no-run
    bash tools/jam-dev/testnet.sh chain

# A plain build of `vos` carries no faults: building the fault suite's
# `vos` with the feature must not leak into it, and no workspace member
# turns the feature on for vos-node.
check-no-faults:
    let resolved = (cargo tree --workspace -e features -i vos-node | complete); if $resolved.exit_code != 0 { print -e $resolved.stderr; error make { msg: "cargo tree failed" } }; if ($resolved.stdout | str contains 'feature "faults"') { error make { msg: "a workspace member enables vos-node's faults" } }
    cargo build -p vos-cli
    if ((^target/debug/vos --version) | str contains "faults") { error make { msg: "a plain build of vos injects faults" } } else { print "no faults in a plain build of vos" }

# The gates' table: by gate, each build `cargo tree <args>` resolves (its
# normal and build edges, for every target), the features no package in it
# may enable and the packages it may not hold. Each package's enabled
# features (`{f}`) are compared whole, so one a feature enables through
# another is caught. `_forbidden <gate>...` resolves each build the gates
# name once, prints every feature enabled and package held, and fails on
# any, or when a build does not resolve.
_forbidden +gates:
    let table = [ \
        [gate args features packages]; \
        [jam-dev "-p vos-cli" [] [vos-jam-dev vos-jam]] \
        [jam-dev "-p vos-cli --features prover" [] [vos-jam-dev vos-jam]] \
        [jam-dev "-p vos-node" [] [vos-jam-dev vos-jam]] \
        [jam-dev "-p vos-node --features prover" [] [vos-jam-dev vos-jam]] \
        [venue-clients "--workspace" [kreivo-mock model] []] \
        [venue-clients "-p vos-cli" [kreivo-mock kreivo model] []] \
        [venue-clients "-p vos-cli --features prover" [kreivo-mock kreivo model] []] \
        [venue-clients "-p vos-node" [kreivo-mock kreivo model] []] \
        [venue-clients "-p vos-node --features prover" [kreivo-mock kreivo model] []] \
        [seeded-masks "--workspace" [seeded-masks] []] \
        [seeded-masks "-p vos-cli --features prover" [seeded-masks] []] \
        [seeded-masks "-p vos-device" [seeded-masks] []] \
        [seeded-masks "--manifest-path agent/default/Cargo.toml" [seeded-masks] []] \
        [seeded-masks "--manifest-path pvm/proof/fuzz/Cargo.toml" [seeded-masks] []] \
        [seeded-masks "--manifest-path pvm/proof/final-verifier/wasm/run/Cargo.toml" [seeded-masks] []] \
        [seeded-masks "--manifest-path pvm/proof/final-verifier/wasm/blob/Cargo.toml" [seeded-masks] []] \
        [debug-internals "--workspace" [debug-internals disclosing watch] []] \
        [debug-internals "-p vos-cli --features prover" [debug-internals disclosing watch] []] \
        [debug-internals "-p vos-statement-service --features pvm-guest" [debug-internals] []] \
        [debug-internals "--manifest-path agent/default/Cargo.toml" [debug-internals] []] \
        [debug-internals "--manifest-path pvm/proof/final-verifier/wasm/run/Cargo.toml" [debug-internals] []] \
        [debug-internals "--manifest-path pvm/proof/final-verifier/wasm/blob/Cargo.toml" [debug-internals] []] \
        [test-formats "--workspace" [test-formats] []] \
        [test-formats "-p vos-cli --features prover" [test-formats] []] \
        [test-formats "--manifest-path agent/default/Cargo.toml" [test-formats] []] \
        [test-formats "--manifest-path pvm/proof/final-verifier/wasm/run/Cargo.toml" [test-formats] []] \
        [test-formats "--manifest-path pvm/proof/final-verifier/wasm/blob/Cargo.toml" [test-formats] []] \
        [test-formats "-p vos-statement --features fixtures,pvm-guest" [test-formats] []] \
        [test-formats "-p vos-statement-service --features pvm-guest" [test-formats] []] \
        [store-dump "-p vos-cli" [dump] []] \
        [store-dump "-p vos-cli --features prover" [dump] []] \
        [store-dump "-p vos-node" [dump] []] \
        [store-dump "-p vos-node --features prover" [dump] []] \
        [heap-peak "--workspace" [heap-peak] []] \
        [heap-peak "-p vos-cli --features prover" [heap-peak] []] \
        [heap-peak "-p vos-statement --features pvm-guest" [heap-peak] []] \
        [heap-peak "-p vos-statement-service --features pvm-guest" [heap-peak] []] \
        [scale "-p vos-cli" [] [vos-scale]] \
        [scale "-p vos-cli --features prover" [] [vos-scale]] \
        [scale "-p vos-node" [] [vos-scale]] \
        [scale "-p vos-node --features prover" [] [vos-scale]] \
    ]; \
    let failures = ($table | where gate in [{{gates}}] | group-by args | items {|args, rows| \
        let resolved = (cargo tree ...($args | split row ' ') -e no-dev --target all -f '{p}|{f}' --prefix none | complete); \
        if $resolved.exit_code != 0 { print -e $resolved.stderr; error make { msg: $"cargo tree ($args) failed" } }; \
        let tree = ($resolved.stdout | lines | each {|line| $line | str replace ' (*)' '' | split row '|' }); \
        let held = ($tree | each {|parts| $parts.0 | split row ' ' | first }); \
        let enabled = ($tree | each {|parts| $parts.1? | default '' | split row ',' } | flatten); \
        ($rows.features | flatten | uniq | where {|feature| $feature in $enabled } | each {|feature| $"cargo tree ($args) enables ($feature)" }) \
        ++ ($rows.packages | flatten | uniq | where {|package| $package in $held } | each {|package| $"cargo tree ($args) holds ($package)" }) \
    } | flatten); \
    for failure in $failures { print -e $failure }; \
    if ($failures | is-not-empty) { error make { msg: "a production build enables a forbidden feature or holds a forbidden package" } }

# The proof crate's `debug-internals` does not imply `seeded-masks`.
_seeded-masks-unimplied:
    if (open pvm/proof/Cargo.toml | get features.debug-internals | any {|feature| $feature | str contains 'seeded-masks' }) { error make { msg: "debug-internals implies seeded masks" } }

# The node's binary, built with the prover, names none of the debug
# outputs' environment variables nor the instruction trace's message.
_debug-names-absent:
    cargo build -p vos-cli --features prover
    let binary = (open --raw target/debug/vos); for name in [GREY_PVM_DEBUG CPU_DUMP CPU_EXPR_DUMP ZKPVM_PROFILE pvm-inst] { if ($binary | bytes index-of ($name | into binary)) >= 0 { error make { msg: $"the node's binary names ($name)" } } }

# The venue rules are written once, in `vos_anchor::venue`: no venue's
# source outside its tests (the clients, jam-dev's commands among them)
# holds the arithmetic of an anchor or registration rule: the root age, a
# window's boundary, a comparison with the last window anchored, the window
# lengths a venue registers, the key bounds and the small-order keys, or the
# strict signature check past the one verifier each venue hands the core;
# and each venue calls the core's rules. A tripwire on the rules'
# arithmetic, not a proof that no rule is restated: the clients' reads of a
# space's status and listed keys, which pin D′ keeps, are not flagged.
check-venue-rules:
    let roots = [pvm/proof/statement/src pvm/proof/statement/service/src node/venue/src tools/jam-dev/src]; \
    let markers = ['MAX_ROOT_AGE_MS' '\.boundary\(' 'verify_strict' 'SMALL_ORDER' 'small_order\(' 'registrable' 'MIN_LENGTH_MS' 'MAX_LENGTH_MS' 'MAX_FOUNDING_KEYS' '[<>]=?\s*last\b' '\blast\s*[<>]']; \
    let allowed = [[file marker]; [node/venue/src/lib.rs verify_strict] [pvm/proof/statement/service/src/refine.rs verify_strict] [node/venue/src/kreivo/mock/chain.rs MAX_FOUNDING_KEYS]]; \
    let sources = ($roots | each {|root| glob $"($root)/**/*.rs" } | flatten | each {|path| $path | path relative-to $env.PWD } | where {|path| not ($path =~ '(^|/)(tests?|conformance)(/|\.rs$)') }); \
    let found = ($sources | each {|file| let code = (open --raw $file | lines | take until {|line| $line =~ '^#\[cfg\(test\)\]' } | each {|line| $line | str replace -r '//.*$' '' } | str join "\n" | str replace -a -r '(?m)^\s*(pub )?use [^;]*;' ''); $markers | where {|marker| ($code =~ $marker) and not ($allowed | any {|a| $a.file == $file and $a.marker == $marker }) } | each {|marker| $"($file) holds ($marker)" } } | flatten); \
    let calls = [[file call]; [pvm/proof/statement/src/model.rs 'rules::anchored('] [pvm/proof/statement/service/src/accumulate.rs 'rules::anchor('] [pvm/proof/statement/service/src/accumulate.rs 'rules::register('] [pvm/proof/statement/service/src/accumulate.rs 'rules::anchored('] [pvm/proof/statement/service/src/refine.rs 'rules::registration('] [node/venue/src/model.rs 'rules::anchor('] [node/venue/src/model.rs 'rules::register('] [node/venue/src/model.rs 'rules::registration('] [node/venue/src/model.rs 'rules::anchored('] [node/venue/src/kreivo/mock/pallet.rs 'rules::anchor('] [node/venue/src/kreivo/mock/pallet.rs 'rules::register('] [node/venue/src/kreivo/mock/pallet.rs 'rules::registration('] [node/venue/src/kreivo/mock/pallet.rs 'rules::anchored('] [node/venue/src/kreivo/venue.rs 'rules::anchored('] [tools/jam-dev/src/venue.rs 'rules::anchored('] [node/venue/src/model.rs 'rules::add_key('] [pvm/proof/statement/service/src/accumulate.rs 'rules::add_key('] [node/venue/src/kreivo/mock/pallet.rs 'rules::add_key(']]; \
    let missing = ($calls | where {|row| not (open --raw $row.file | str contains $row.call) } | each {|row| $"($row.file) calls no ($row.call)" }); \
    for failure in ($found ++ $missing) { print -e $failure }; \
    if ($found ++ $missing | is-not-empty) { error make { msg: "an anchor rule lives outside vos_anchor::venue, or a venue does not call it" } }; \
    print $"the venue rules live in vos_anchor::venue alone: ($sources | length) files searched, ($calls | length) calls found"

# Every `check-no-*` gate below, each build resolved once.
check-no-leaks: (_forbidden "jam-dev" "venue-clients" "seeded-masks" "debug-internals" "test-formats" "store-dump" "heap-peak" "scale") _seeded-masks-unimplied _debug-names-absent
    print "no test seam, debug output, test format, store dump, heap peak, JAM client, venue client or scale harness in a production build"

# A node knows no JAM: the JAM client (a PolkaJam node's RPC and `jamt`,
# the statements service's client and `JamVenue`) is development tooling,
# `vos-jam-dev`, and neither the `vos` binary, with or without the prover,
# nor `vos-node` depends on it, nor on the agent-as-JAM-service builder
# (`vos-jam`), on a normal or build edge.
check-no-jam-dev: (_forbidden "jam-dev")
    print "no JAM client in the node"

# A node carries no venue's client: `vos-venue`'s model venue (`model`),
# its client of Kreivo's spaces pallet (`kreivo`) and that pallet's mock
# (`kreivo-mock`) reach neither the `vos` binary, with or without the
# prover, nor `vos-node`, on a normal or build edge (the tests enable them
# on dev edges, the carrier audit's checker `kreivo`), and no normal or
# build edge of any workspace member enables the model or the mock.
check-no-venue-clients: (_forbidden "venue-clients")
    print "no venue client in the node"

# The scale harness (`tools/scale`, `vos-scale`) is development tooling:
# neither the `vos` binary, with or without the prover, nor `vos-node`
# depends on it, on a normal or build edge.
check-no-scale: (_forbidden "scale")
    print "no scale harness in the node"

# The masked prover's test seams (`vos-pvm-recair`'s `seeded-masks`: the
# seeded randomness `MaskRng::Seeded` and the forced proof
# `prove_masked_unchecked`) reach no production build: no normal or build edge
# of any workspace member, nor of the workspaces built apart (the agent,
# the fuzz targets, the final verifier's Wasm blob and its runner), enables
# it (the prover's tests enable it on a dev edge), and the proof crate's
# `debug-internals` does not imply it.
check-no-seeded-masks: (_forbidden "seeded-masks") _seeded-masks-unimplied
    print "no seeded masks in a production build"

# The debug outputs (`vos-pvm`'s and `vos-pvm-proof`'s `debug-internals`:
# the PVM's instruction trace, `GREY_PVM_DEBUG`'s registers and native code,
# `CPU_DUMP`, `CPU_EXPR_DUMP`, `ZKPVM_PROFILE`), which show a run's steps,
# registers and rows, and the carrier audit's seams (`vos-node`'s and
# `vos-node-prover`'s `disclosing`, `vos-pvm-recair`'s `watch`), which hand
# a proof's internals out, reach no production build: no normal or build
# edge of any workspace member, nor of the agent's or the final verifier's
# workspaces, enables the debug outputs, nor of any workspace member the
# seams; and the node's binary, built with the prover, names none of the
# debug outputs' environment variables nor the instruction trace's message,
# so none of them is compiled in.
check-no-debug-internals: (_forbidden "debug-internals") _debug-names-absent
    print "no debug outputs in a production build"

# Format 28, the unmasked wrap (`vos-pvm-final-verifier`'s, its prover
# `vos-pvm-recair`'s and `vos-statement`'s `test-formats`), reaches no
# production build: no normal
# or build edge of any workspace member, nor of the workspaces built apart
# that venues or nodes run (the agent, the final verifier's Wasm blob, its
# runner), enables it (the tests enable it on dev edges, the harnesses' test
# builds by name); and `vos-statement`'s `fixtures` and `pvm-guest`, and the
# JAM statements service's program, do not imply it. The fuzz targets,
# built apart, fuzz format 28's decode and verifier too, and are no venue.
check-no-test-formats: (_forbidden "test-formats")
    print "no test formats in a production build"

# The store's dump (`vos-node`'s `dump`: `store::Fjall::dump`, every row
# the store holds) reaches neither the `vos` binary, with or without the
# prover, nor `vos-node`, on a normal or build edge (the carrier audit's
# checker enables it, a dev edge of both).
check-no-store-dump: (_forbidden "store-dump")
    print "no store dump in a production build"

# The guests' heap peak (`vos-statement`'s and the JAM statements service's
# `heap-peak`), a measurement build's, reaches no production build: no
# normal or build edge of any workspace member, of the `vos` binary with
# the prover, nor of the venues' guests (`final-verify` and the service's
# program) enables it.
check-no-heap-peak: (_forbidden "heap-peak")
    print "no heap peak in a production build"

# The builds without std. vos-raft for an embedded target, on core and alloc
# alone, built from the toolchain's source. The proof verifier, which reads
# every admitted format, with the proof crate's verifier path under it: both are `no_std`
# crates, so a `std` path in either fails the build. The verifier builds for
# the same embedded target, where no dependency has std either, and for
# wasm32, the target of an on-chain verifier; the workspace's toolchain file
# installs wasm32.
# The final verifier, on the recursion AIR's bodies, the space's anchor
# types, and the statement's venue check over both, for the embedded
# target, for wasm32 with every nightly feature refused (their source
# builds on stable), and for the PVM
# with the standard library built from source, with the venue's JAM refine
# program, which `vos-pvm-recair`'s wrap tests and the fixtures' and the
# end-to-end tests run on the JAM-only host: `final-verify.elf`, the
# harness's refine program, linking format 39 alone and accepting nothing
# without a proof, and `final-verify-test.elf`, linking 28 beside it for
# the test policy's fixtures, its `ANCHORS` mode computing `vos-anchor`'s
# golden vectors with no proof read; and the JAM statements service's
# program, `statement-service.elf`, which its tests run on the JAM-only
# host, refine and accumulate. The final verifier and `vos-statement`
# build here without `test-formats`. The guests' bins and the Wasm blob,
# crate roots the workspace's lints do not reach, are linted here under the
# verify path's denies. Last, every guest blob checked against
# `blobs.lock` (`check-blobs`).
check-no-std:
    cargo build -p vos-raft --target thumbv7em-none-eabihf -Zbuild-std=core,alloc
    cargo build -p vos-pvm-proof-verifier --target thumbv7em-none-eabihf -Zbuild-std=core,alloc
    cargo build -p vos-pvm-proof-verifier --target wasm32-unknown-unknown
    cargo build -p vos-pvm-final-verifier --target thumbv7em-none-eabihf -Zbuild-std=core,alloc
    with-env { RUSTFLAGS: "-Zallow-features=" } { cargo build -p vos-pvm-final-verifier --target wasm32-unknown-unknown --target-dir target/no-nightly-features }
    cargo build -p vos-anchor --target thumbv7em-none-eabihf -Zbuild-std=core,alloc
    with-env { RUSTFLAGS: "-Zallow-features=" } { cargo build -p vos-anchor --target wasm32-unknown-unknown --target-dir target/no-nightly-features }
    cargo build -p vos-statement --target thumbv7em-none-eabihf -Zbuild-std=core,alloc
    with-env { RUSTFLAGS: "-Zallow-features=" } { cargo build -p vos-statement --target wasm32-unknown-unknown --target-dir target/no-nightly-features }
    just build-final-verify
    cargo clippy -p vos-statement --release --features pvm-guest --bin final-verify {{guest_flags}} --quiet -- -D warnings
    cargo clippy -p vos-statement --release --features pvm-guest,test-formats --bin final-verify-test {{guest_flags}} --quiet -- -D warnings
    just build-statement-service
    cargo clippy -p vos-statement-service --release --features pvm-guest --bin statement-service {{guest_flags}} --quiet -- -D warnings
    cd pvm/proof/final-verifier/wasm/blob; cargo clippy --release --quiet -- -D warnings
    cd pvm/proof/final-verifier/wasm/blob; cargo clippy --release --features test-formats --target-dir target/test-formats --quiet -- -D warnings
    just check-blobs

# The verifier kit (`pvm/proof/kit/vos_kit.py`), which a chain's runtime
# vendors (Kreivo's `vendor/vos-verifier/`, `spaces-pallet.md` §3), written
# into `dir`: `vos-anchor`, `vos-statement`, `vos-pvm-final-verifier`,
# `vos-pvm-recair-air` and `vos-pvm-poseidon2` with concrete manifests (Stwo
# a git dependency at the pin, without default features; `test-formats`
# and `pvm-guest` left in VOS), the golden fixtures, the conformance
# vectors and a `VENDOR` file naming the commit (and the tag) and the
# tree's hash. From the working tree, or from `rev`, a tag or a commit: a
# release vendors from a tag.
vendor-verifier dir rev="":
    if "{{rev}}" == "" { python3 -I pvm/proof/kit/vos_kit.py vendor {{dir}} } else { python3 -I pvm/proof/kit/vos_kit.py vendor {{dir}} --rev {{rev}} }

# A vendored kit checked against the commit its `VENDOR` names: the tree's
# hash, then the kit vendored anew from that commit by its own script, the
# fixtures and the conformance vectors with it, every file compared; here
# against this checkout, a kit vendored at a commit accepted. A consumer
# runs `pvm/proof/kit/vos-sync.sh`, copied outside its kit, which pins VOS's
# repository and runs the tag's script, never the kit's own:
# `scripts/vos-sync.sh vendor/vos-verifier` (`spaces-pallet.md` §3.1).
vos-sync dir:
    python3 -I pvm/proof/kit/vos_kit.py sync {{dir}} --vos . --allow-untagged --scratch target/kit/scratch

# The kit as Kreivo builds it: vendored from the working tree into a
# workspace of its own, built alone and `--locked` (on the kit's lockfile,
# `pvm/proof/kit/Cargo.lock`) for `wasm32v1-none` on Kreivo's stable
# toolchain (1.94.1, the target installed as Kreivo's CI installs it), no
# `std` feature enabled in any crate it links; `vos-statement`'s `fixtures`
# reader built for the host; and the sync check's own test
# (`pvm/proof/kit/check.py`): a one-byte change in a vendored file refused,
# the kit's own script never trusted, `VENDOR`'s tag required and checked.
check-kit: _kit-workspace
    cd target/kit/build; cargo +1.94.1 build --workspace --target wasm32v1-none --locked --quiet
    cd target/kit/build; let std = (cargo +1.94.1 tree --workspace -e normal --target wasm32v1-none -f '{p}|{f}' --prefix none --locked | lines | where {|line| $line | split row '|' | last | split row ',' | any {|feature| $feature == 'std' } } | uniq); if ($std | is-not-empty) { error make { msg: $"std reaches the kit: ($std | str join ', ')" } } else { print "no std feature in the kit's wasm32v1-none build" }
    cd target/kit/build; cargo +1.94.1 build -p vos-statement --features fixtures --locked --quiet
    python3 -I pvm/proof/kit/check.py --scratch target/kit/sync

# The kit's lockfile, after its crates' dependencies change: VOS's own
# lockfile, pruned to what the kit links.
kit-lock: _kit-workspace
    cp Cargo.lock target/kit/build/Cargo.lock
    cd target/kit/build; cargo +1.94.1 build --workspace --target wasm32v1-none --quiet
    cp target/kit/build/Cargo.lock pvm/proof/kit/Cargo.lock

_kit-workspace:
    if not ((do { rustup target list --installed --toolchain 1.94.1 } | complete).stdout | lines | any {|target| $target == 'wasm32v1-none' }) { rustup toolchain install 1.94.1 --profile minimal --target wasm32v1-none --no-self-update }
    rm -rf target/kit/build
    python3 -I pvm/proof/kit/vos_kit.py vendor target/kit/build/vendor/vos-verifier
    {workspace: {resolver: "3", members: (glob target/kit/build/vendor/vos-verifier/*/Cargo.toml | each {|manifest| $manifest | path dirname | path relative-to ($env.PWD | path join target/kit/build) } | sort)}} | to toml | save -f target/kit/build/Cargo.toml
    cp pvm/proof/kit/Cargo.lock target/kit/build/Cargo.lock

# The fuzz targets (`pvm/proof/fuzz`, built apart with `cargo fuzz`): the
# final verifier on arbitrary bytes, on the golden wraps mutated, on format
# 39's layout past its header and on its queried parts reshaped within the
# layout's bounds; the statement's and the space's decoders and the venue's
# check; prove-then-verify on random programs; and a credentialed call's
# decode and the credential verifier's bytes, ingress's. A target's
# property is no panic and nothing accepted but a golden (a credential
# proof: its one encoding).
fuzz_targets := "final_verifier_bytes final_verifier_mutate statement_decode prove_verify_roundtrip masked_bytes masked_shape anchor_decode api_reader operated_decode credentialed_decode credential_verify_bytes"

# Each target's checked-in corpus (`pvm/proof/fuzz/replay`) run once, every
# input, optimized and without a sanitizer: no crash. `cargo run --example
# paths` there lists what each input reaches. `cargo fuzz` sets RUSTFLAGS,
# which replaces the host's `target-cpu=native` (`.cargo/config.toml`), so
# the recipes pass it again: without it the prover's SIMD falls back to its
# generic code, and one proof takes many minutes.
fuzz-replay:
    cd pvm/proof/fuzz; with-env { RUSTFLAGS: "-C target-cpu=native" } { for target in ("{{fuzz_targets}}" | split row ' ') { cargo fuzz run -O -s none --target-dir target/no-sanitizer $target $"replay/($target)" -- -runs=0 } }

# Each target `secs` seconds from its corpus (a minute in `ci-full`, five in
# `slice-gate`: `just fuzz 300`), seeded from the fixtures and the anchor's
# vectors, the checked-in corpus beside it: no crash. One at a time;
# the sanitized targets with debug assertions and overflow checks (`-a`),
# the prove target optimized and without a sanitizer, its proving too slow
# under either.
fuzz secs="60":
    cd pvm/proof/fuzz; cargo run --release --example seed
    cd pvm/proof/fuzz; with-env { RUSTFLAGS: "-C target-cpu=native" } { for target in ("{{fuzz_targets}}" | split row ' ') { let build = if $target == "prove_verify_roundtrip" { [-O -s none --target-dir target/no-sanitizer] } else { [-a] }; cargo fuzz run ...$build $target $"corpus/($target)" $"replay/($target)" -- -max_total_time={{secs}} -max_len=262145 -len_control=0 -rss_limit_mb=8192 -timeout=600 } }

# Checks before pushing: everything except proving.
# The quick gate, after each change: formatting, the docs' links, the
# builds without std, the verifier kit, the workspace's lints, and the
# suites of the node, the agent, vos-raft and the crates under them.
# Left to `just ci`: the slow fault runs (the five-process fault suite, the
# fault build's process tests), the PVM vectors, the bench and prover
# library tests, and the lints of other feature sets.
check: fmt-check doc-check check-venue-rules check-no-std check-no-leaks check-kit build-test-actors build-agent build-representative build-credentials fuzz-replay
    cargo clippy --workspace --all-targets --quiet -- -D warnings
    cargo clippy -p vos-venue --all-targets --quiet -- -D warnings
    just clippy-prover
    cargo test {{core_crates}}
    just test-recair
    cargo test {{agent_crates}}
    just test-reads

# The live runs of reads at a cut on the agent's model, with no proving:
# the window's, the balance's and a small map's reads, re-traced, and the
# kernels' refusals, so a change of the served contract fails `check`.
# One at a time: four at once were killed past 12 GiB. Each is named
# exactly, and the recipe fails unless every name is a test, so a renamed
# test is not skipped unseen.
reads_tests := "window_kernel::the_window_settles_at_a_cut window_kernel::a_carried_state_that_does_not_open_is_refused window_kernel::an_older_cut_is_refused window_kernel::rows_off_the_cut_are_refused balance::a_balance_is_stated_at_a_cut balance::a_commitment_that_does_not_open_is_refused reads::a_read_at_a_cut_re_runs_as_its_live_run"

test-reads:
    let named = ([{{reads_tests}}] | length); let listed = (cargo test -p vos-pvm-proof --test kernel -- --list --exact {{reads_tests}} | lines | where {|line| $line ends-with ': test' } | length); if $listed != $named { error make { msg: $"test-reads names ($named) tests, of which ($listed) exist" } }
    cargo test -p vos-pvm-proof --test kernel -- --test-threads=1 --exact {{reads_tests}}

# Everything but the prover suites: before a merge, and at the end of each
# planned stage of work.
ci: fmt-check doc-check check-no-std clippy jar-check test vectors test-bench test-agent check-no-faults check-no-leaks check-kit fuzz-replay

# The gate at a milestone: `ci` plus the prover suites, the soundness gates
# (the leakage tests at their medium N), the bench tests that prove and the
# fuzz targets a minute each. Run it under a 12 GiB limit, e.g.
# `systemd-run --user --scope -p MemoryMax=12G -p MemorySwapMax=0 just ci-full`.
# Run alone on the machine, its builds may take `CARGO_BUILD_JOBS` 8 to 12:
# the proving tests keep their own thread limits (`test-proof`'s
# `--test-threads`), so the peak stays under the cap.
ci-full: ci test-proof test-bench-proof (fuzz "60")

# The gate at a slice's end: `ci-full`'s, with the leakage tests at their
# full N (2,000 proofs a witness on the small circuit, 32 on the real wrap,
# 256 a kernel on the masked segment) and the fuzz targets five minutes
# each. Under the same limit.
slice-gate: ci test-bench-proof
    with-env { LEAKAGE_N: "2000", LEAKAGE_WRAP_N: "32", LEAKAGE_SEGMENT_N: "256" } { just test-proof }
    just fuzz 300

# The static x86-64 builds the scale test deploys (`tools/scale`): `vos`
# and `vos-scale` for musl, from the lock file, each built alone so the
# harness's dependencies never unify into the node's. Not incremental: the
# release profile's code, as shipped.
release:
    with-env { CARGO_INCREMENTAL: "0" } { cargo build --release --locked --target x86_64-unknown-linux-musl -p vos-cli }
    with-env { CARGO_INCREMENTAL: "0" } { cargo build --release --locked --target x86_64-unknown-linux-musl -p vos-scale }

# Use the repository's hooks: fmt and clippy before commits, `just ci`
# before pushes.
install-hooks:
    git config core.hooksPath .githooks
