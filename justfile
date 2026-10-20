set shell := ["nu", "-c"]

default:
    @just --list

# Fast suites: runtime, compiler, program format, codec, support crates,
# precompile shim, Poseidon2, verifier, the recursion AIR and its gate VM,
# prover library, wire types. The node runs the
# agent, so it is tested with it.
test:
    cargo test -p vos-pvm -p vos-pvm-compiler -p vos-pvm-program -p vos-pvm-codec -p vos-raft -p merkle-crdt -p vos-pvm-precompiles -p vos-pvm-poseidon2 -p vos-pvm-proof-verifier -p vos-wire -p vos-tree -p vos-jam -p vos-pvm-recair-air -p vos-pvm-final-verifier -p vos-anchor -p vos-statement --features vos-anchor/vectors,vos-statement/fixtures
    just test-recair
    cargo test -p vos-pvm-proof --lib

# The recursion AIR's prover tests, four at a time: at every core at once
# its recursion suite passed 12 GiB, the limit the gates run under.
test-recair:
    cargo test -p vos-pvm-recair -- --test-threads=4

# Bench guests, built with the guest toolchain in `pvm/guest`.
build-bench-guests:
    for guest in [workflows actor agent hash-software hash-precompile diverse] { do { cd $"pvm/bench/guests/($guest)"; cargo build --release --target ../../../guest/riscv64em-vos.json } }

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
# on the real wrap; `LEAKAGE_N` and `LEAKAGE_WRAP_N` set others, and
# `slice-gate` the full 2,000 and 32), the masked acceptance above 2^16
# rows, and the final
# verifier's decode, verify and Wasm gates as the maximum over 12 seeds of
# the masked wrap (on the JAM-only host's `final-verify.elf`, built by
# `check-no-std`, and `judge-wasm`'s blob), one test at a time.
test-proof: build-test-actors judge-wasm
    cargo test -p vos-pvm-proof --features debug-internals --lib --bins --test gates --test isa -- --test-threads=2
    for test in (cargo test -p vos-pvm-proof --features debug-internals --test kernel -- --list --format terse --skip reads:: | lines | where {|line| $line ends-with ': test' } | each {|line| $line | str replace ': test' '' }) { cargo test -p vos-pvm-proof --features debug-internals --test kernel $test -- --exact --test-threads=1 }
    cargo test -p vos-pvm-proof --features debug-internals --test kernel reads:: -- --test-threads=1
    cargo test -p vos-pvm-recair --features heavy-gates --test circuit --test recursion -- leakage heavy --test-threads=1

# The golden fixtures (`pvm/proof/fixtures`) judged in Wasm, by the final
# verifier's blobs built as a runtime builds them, under the PVF's semantics
# and the client's: the production blob (format 39 alone, a statement of 28
# refused as a format it does not link) and the test blob (`test-formats`,
# 28 beside it), every verdict the one its build reaches, as natively and on
# the JAM-only host (`vos-statement`'s fixtures test); and `vos-anchor`'s
# golden vectors computed by the production blob, every digest the pinned
# bytes.
judge-wasm:
    cd pvm/proof/final-verifier/wasm/blob; cargo build --release
    cd pvm/proof/final-verifier/wasm/blob; cargo build --release --features test-formats --target-dir target/test-formats
    cd pvm/proof/final-verifier/wasm/run; cargo build --release
    for semantics in [pvf client] { ^pvm/proof/final-verifier/wasm/run/target/release/vos-pvm-final-verifier-wasm-run pvm/proof/final-verifier/wasm/blob/target/wasm32-unknown-unknown/release/vos_pvm_final_verifier_wasm.wasm $semantics judge pvm/proof/fixtures 39 }
    for semantics in [pvf client] { ^pvm/proof/final-verifier/wasm/run/target/release/vos-pvm-final-verifier-wasm-run pvm/proof/final-verifier/wasm/blob/target/test-formats/wasm32-unknown-unknown/release/vos_pvm_final_verifier_wasm.wasm $semantics judge pvm/proof/fixtures 28,39 }
    for semantics in [pvf client] { ^pvm/proof/final-verifier/wasm/run/target/release/vos-pvm-final-verifier-wasm-run pvm/proof/final-verifier/wasm/blob/target/wasm32-unknown-unknown/release/vos_pvm_final_verifier_wasm.wasm $semantics anchors }

# The proof fixtures under `pvm/proof/fixtures` (`proving.md` A.6), written
# anew by their generator, `pvm/proof/tests/kernel/fixtures.rs`: at a format bump,
# or a change of the AIR or a kernel's shape. `test-proof` refuses fixtures
# the generator no longer makes.
fixtures:
    with-env { VOS_FIXTURES: "write" } { cargo test -p vos-pvm-proof --test kernel fixtures::the_fixtures_are_the_generators }

# The conformance vectors of Kreivo's spaces pallet and the mutation lists
# (`node/venue/conformance`, `spaces-pallet.md` §10), written anew by the
# reference mock (`node/venue/src/kreivo`) over the golden fixtures: after a
# change of the design, the mock or the fixtures. `check` refuses vectors
# the mock no longer writes.
conformance:
    with-env { VOS_CONFORMANCE: "write" } { cargo test -p vos-venue kreivo::conformance::the_vectors_are_the_generators }

# The tests run on mimalloc as the node's binary does, and as it does with
# transparent huge pages off.
export MIMALLOC_ALLOW_THP := "0"

# Formatting: the workspace's, and each crate's it excludes.
fmt-check:
    cargo fmt --all -- --check
    for manifest in ([agent/default agent/representative agent/test-actors pvm/bench/guests pvm/proof/fuzz pvm/proof/final-verifier/wasm spikes] | each {|dir| glob $'($dir)/**/Cargo.toml' --exclude ['**/target/**'] } | flatten | where {|manifest| open --raw $manifest | str contains '[package]' }) { cargo fmt --manifest-path $manifest -- --check }

# The docs' links: none broken, and none from a public doc to a private
# item.
doc-check:
    with-env { RUSTDOCFLAGS: "-D rustdoc::broken_intra_doc_links -D rustdoc::private_intra_doc_links" } { cargo doc --workspace --no-deps --quiet }

clippy:
    cargo clippy --workspace --all-targets --quiet -- -D warnings
    cargo clippy -p vos-pvm-bench --features prove --all-targets --quiet -- -D warnings
    cargo clippy -p vos-cli --features faults --all-targets --quiet -- -D warnings
    cargo clippy -p vos-cli --no-default-features --all-targets --quiet -- -D warnings
    cargo clippy -p vos-pvm-proof --features debug-internals --all-targets --quiet -- -D warnings

# Fails on any JAR remnant in the PVM crates: its ISA and gas modes, opcodes,
# exits, capability surface, linker entry points, invocation kernel, CSR
# 0x800 marker and fixtures. The proof crate's own `kernel` module and a
# 0x800 rounding constant are not remnants.
jar-check:
    let hits = (rg -n --glob '!**/target/**' 'IsaMode|CapabilityManifest|\blink_elf\b|link_elf_with_argument_pages|run_with_vos_stubs|ECALL_VOS_|VOS_OBJECT_CAP|Opcode::Ecall\b|ExitReason::Ecall|ExitReason::Trap\b|vos_pvm::kernel::|InvocationKernel|vm_pool|JAR\\x02|\.gp072\.json|\bGasModel\b|\bPerInstruction\b|\bmem_cycles\b|Opcode::Sbrk|\bsbrk\(|(?i:csr\w*,? 0x800)\b|\(\d, 0x800\)|Some\(0x800\)' pvm | complete); if ($hits.exit_code == 0) { print $hits.stdout; error make { msg: "JAR remnants found" } } else { print "no JAR remnants" }

# The SDK's test actors, built with the guest toolchain in `pvm/guest`.
build-test-actors:
    cd agent/test-actors; cargo build --release --target ../../pvm/guest/riscv64em-vos.json

# The default agent program, built with the guest toolchain in `pvm/guest`.
build-agent:
    cd agent/default; cargo build --release --target ../../pvm/guest/riscv64em-vos.json

# The space's representative, built with the guest toolchain in `pvm/guest`.
build-representative:
    cd agent/representative; cargo build --release --target ../../pvm/guest/riscv64em-vos.json

# The SDK, its macros' restrictions, the test actors on the testkit, the
# default agent against it, the checker's own model, the node running the
# agent, the network between nodes, and the `vos` command.
test-agent: build-test-actors build-agent build-representative
    cargo test -p vos-sdk -p vos-sdk-macros -p vos-testkit -p vos-checker -p vos-node -p vos-venue -p vos-net -p vos-cli
    cargo test -p vos-cli --features faults --test processes faults::
    cargo test -p vos-cli --features faults --test fault_suite
    just test-reads

# The default agent as a service on a local PolkaJam testnet, which it
# starts and stops: a workflow suspended in one work package and resumed in
# later ones, every read witnessed. Outside `ci`: it needs the PolkaJam
# binaries, in POLKAJAM or the directory `testnet.sh` names by default.
jam-testnet: build-test-actors build-agent
    bash node/jam/testnet.sh

# A plain build of `vos` carries no faults: building the fault suite's
# `vos` with the feature must not leak into it, and no workspace member
# turns the feature on for vos-node.
check-no-faults:
    if (cargo tree --workspace -e features -i vos-node | str contains 'feature "faults"') { error make { msg: "a workspace member enables vos-node's faults" } }
    cargo build -p vos-cli
    if ((^target/debug/vos --version) | str contains "faults") { error make { msg: "a plain build of vos injects faults" } } else { print "no faults in a plain build of vos" }

# Fails when the build `cargo tree <args>` resolves (its normal and build
# edges, for every target) enables `feature` in any package: each package's
# enabled features (`{f}`) compared whole, so one a feature enables through
# another is caught.
_no-feature feature +args:
    if (cargo tree {{args}} -e no-dev --target all -f '{f}' --prefix none | lines | each {|line| $line | str replace ' (*)' '' | split row ',' } | flatten | any {|enabled| $enabled == '{{feature}}' }) { error make { msg: "cargo tree {{args}} enables {{feature}}" } }

# The masked prover's test seams (`vos-pvm-recair`'s `seeded-masks`: the
# seeded randomness `MaskRng::Seeded` and the forced proof
# `prove_masked_unchecked`) reach no production build: no normal or build edge
# of any workspace member, nor of the workspaces built apart (the agent,
# the fuzz targets, the final verifier's Wasm blob and its runner), enables
# it (the prover's tests enable it on a dev edge), and the proof crate's
# `debug-internals` does not imply it.
check-no-seeded-masks:
    just _no-feature seeded-masks --workspace
    for manifest in [agent/default pvm/proof/fuzz pvm/proof/final-verifier/wasm/run pvm/proof/final-verifier/wasm/blob] { just _no-feature seeded-masks --manifest-path $"($manifest)/Cargo.toml" }
    if (open pvm/proof/Cargo.toml | get features.debug-internals | any {|feature| $feature | str contains 'seeded-masks' }) { error make { msg: "debug-internals implies seeded masks" } }
    print "no seeded masks in a production build"

# Format 28, the unmasked wrap (`vos-pvm-final-verifier`'s and
# `vos-statement`'s `test-formats`), reaches no production build: no normal
# or build edge of any workspace member, nor of the workspaces built apart
# that venues or nodes run (the agent, the final verifier's Wasm blob, its
# runner), enables it (the tests enable it on dev edges, the harnesses' test
# builds by name); and `vos-statement`'s `fixtures` and `pvm-guest` do not
# imply it. The fuzz targets, built apart, fuzz format 28's decode and
# verifier too, and are no venue.
check-no-test-formats:
    just _no-feature test-formats --workspace
    for manifest in [agent/default pvm/proof/final-verifier/wasm/run pvm/proof/final-verifier/wasm/blob] { just _no-feature test-formats --manifest-path $"($manifest)/Cargo.toml" }
    just _no-feature test-formats -p vos-statement --features fixtures,pvm-guest
    print "no test formats in a production build"

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
# production venue's, linking format 39 alone, and `final-verify-test.elf`,
# linking 28 beside it for the test policy's fixtures. The final verifier and
# `vos-statement` build here without `test-formats`. The guest's two bins and
# the Wasm blob, crate roots the workspace's lints do not reach, are linted
# here under the verify path's denies.
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
    cargo build -p vos-statement --release --features pvm-guest --bin final-verify --target pvm/proof/statement/riscv64em-vos.json -Zbuild-std=core,alloc,compiler_builtins -Zbuild-std-features=compiler-builtins-mem
    cargo build -p vos-statement --release --features pvm-guest,test-formats --bin final-verify-test --target pvm/proof/statement/riscv64em-vos.json -Zbuild-std=core,alloc,compiler_builtins -Zbuild-std-features=compiler-builtins-mem
    cargo clippy -p vos-statement --release --features pvm-guest --bin final-verify --target pvm/proof/statement/riscv64em-vos.json -Zbuild-std=core,alloc,compiler_builtins -Zbuild-std-features=compiler-builtins-mem --quiet -- -D warnings
    cargo clippy -p vos-statement --release --features pvm-guest,test-formats --bin final-verify-test --target pvm/proof/statement/riscv64em-vos.json -Zbuild-std=core,alloc,compiler_builtins -Zbuild-std-features=compiler-builtins-mem --quiet -- -D warnings
    cd pvm/proof/final-verifier/wasm/blob; cargo clippy --release --quiet -- -D warnings
    cd pvm/proof/final-verifier/wasm/blob; cargo clippy --release --features test-formats --target-dir target/test-formats --quiet -- -D warnings

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
# check; and prove-then-verify on random programs. A target's property is
# no panic and nothing accepted but a golden.
fuzz_targets := "final_verifier_bytes final_verifier_mutate statement_decode prove_verify_roundtrip masked_bytes masked_shape anchor_decode"

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
# builds without std, the verifier kit, the workspace's lints, and the suites of the node, the agent, vos-raft and the crates under them.
# Left to `just ci`: the slow fault runs (the five-process fault suite, the
# fault build's process tests), the PVM vectors, the bench and prover
# library tests, and the lints of other feature sets.
check: fmt-check doc-check check-no-std check-no-seeded-masks check-no-test-formats check-kit build-test-actors build-agent build-representative fuzz-replay
    cargo clippy --workspace --all-targets --quiet -- -D warnings
    cargo test -p vos-pvm -p vos-pvm-compiler -p vos-pvm-program -p vos-pvm-codec -p vos-raft -p merkle-crdt -p vos-pvm-precompiles -p vos-pvm-poseidon2 -p vos-pvm-proof-verifier -p vos-wire -p vos-tree -p vos-jam -p vos-pvm-recair-air -p vos-pvm-final-verifier -p vos-anchor -p vos-statement --features vos-anchor/vectors,vos-statement/fixtures
    just test-recair
    cargo test -p vos-sdk -p vos-sdk-macros -p vos-testkit -p vos-checker -p vos-node -p vos-venue -p vos-net -p vos-cli
    just test-reads

# The live runs of reads at a cut on the agent's model, with no proving:
# the window's, the balance's and a small map's reads, re-traced, and the
# kernels' refusals, so a change of the served contract fails `check`.
# One at a time: four at once were killed past 12 GiB.
test-reads:
    cargo test -p vos-pvm-proof --test kernel -- --test-threads=1 window_kernel::the_window_settles_at_a_cut window_kernel::a_carried_state_that_does_not_open_is_refused window_kernel::an_older_cut_is_refused window_kernel::rows_off_the_cut_are_refused balance::a_balance_is_stated_at_a_cut balance::a_commitment_that_does_not_open_is_refused reads::a_read_at_a_cut_re_runs_as_its_live_run

# Everything but the prover suites: before a merge, and at the end of each
# planned stage of work.
ci: fmt-check doc-check check-no-std clippy jar-check test vectors test-bench test-agent check-no-faults check-no-seeded-masks check-no-test-formats check-kit fuzz-replay

# The gate at a milestone: `ci` plus the prover suites, the soundness gates
# (the leakage tests at their medium N), the bench tests that prove and the
# fuzz targets a minute each. Run it under a 12 GiB limit, e.g.
# `systemd-run --user --scope -p MemoryMax=12G -p MemorySwapMax=0 just ci-full`.
# Run alone on the machine, its builds may take `CARGO_BUILD_JOBS` 8 to 12:
# the proving tests keep their own thread limits (`test-proof`'s
# `--test-threads`), so the peak stays under the cap.
ci-full: ci test-proof test-bench-proof (fuzz "60")

# The gate at a slice's end: `ci-full`'s, with the leakage tests at their
# full N (2,000 proofs a witness on the small circuit, 32 on the real wrap)
# and the fuzz targets five minutes each. Under the same limit.
slice-gate: ci test-bench-proof
    with-env { LEAKAGE_N: "2000", LEAKAGE_WRAP_N: "32" } { just test-proof }
    just fuzz 300

# Use the repository's hooks: fmt and clippy before commits, `just ci`
# before pushes.
install-hooks:
    git config core.hooksPath .githooks
