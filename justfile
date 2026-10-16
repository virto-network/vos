set shell := ["nu", "-c"]

default:
    @just --list

# Fast suites: runtime, compiler, program format, codec, support crates,
# precompile shim, verifier, prover library, wire types. The node runs the
# agent, so it is tested with it.
test:
    cargo test -p vos-pvm -p vos-pvm-compiler -p vos-pvm-program -p vos-pvm-codec -p vos-raft -p merkle-crdt -p vos-pvm-precompiles -p vos-pvm-proof-verifier -p vos-wire -p vos-tree -p vos-jam
    cargo test -p vos-pvm-proof --lib

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
# `debug-internals`. Memory-heavy: two threads fit under a 24 GiB limit, e.g.
# `systemd-run --user --scope -p MemoryMax=24G -p MemorySwapMax=0 just test-proof`.
# Then the Poseidon2-M31 channel's proofs (format 25), on the tests whose code
# differs under `poseidon2-channel`, each named by its path or its module's:
# the proof format's generation, its wire codec, the transcript replay, and a
# canonical segment proved and verified, which runs only under it. A test
# joins only by name: the other proving tests check the same AIR under either
# channel, and prove about twenty times slower under this one, the library's
# refine proof alone in five minutes.
test-proof: build-guests
    cargo test -p vos-pvm-proof --features debug-internals --tests -- --test-threads=2
    cargo test -p vos-pvm-proof --features poseidon2-channel --lib -- \
        refine::tests::proof_generation_numbers_reject_previous_formats \
        refine_codec::tests:: \
        proof::query_replay_tests::
    cargo test -p vos-pvm-proof-verifier --features poseidon2-channel --test poseidon2_canonical_segment

# Guest programs the prover suites run.
build-guests: build-settle

# The settlement verifier as a PVM program.
build-settle:
    cd pvm/proof/settlement-verifier; cargo build --release --target riscv64em-vos.json -Zbuild-std=core,alloc,compiler_builtins -Zbuild-std-features=compiler-builtins-mem --features pvm-settle --bin settle

# The tests run on mimalloc as the node's binary does, and as it does with
# transparent huge pages off.
export MIMALLOC_ALLOW_THP := "0"

# Formatting: the workspace's, and each crate's it excludes.
fmt-check:
    cargo fmt --all -- --check
    for manifest in ([agent/default agent/test-actors pvm/bench/guests pvm/proof/fuzz pvm/proof/settlement-verifier pvm/proof/verifier-wasm-bench spikes] | each {|dir| glob $'($dir)/**/Cargo.toml' --exclude ['**/target/**'] } | flatten | where {|manifest| open --raw $manifest | str contains '[package]' }) { cargo fmt --manifest-path $manifest -- --check }

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
    cargo clippy -p vos-pvm-proof -p vos-pvm-proof-verifier --features vos-pvm-proof/debug-internals,vos-pvm-proof-verifier/poseidon2-channel --all-targets --quiet -- -D warnings

# Fails on any JAR remnant in the PVM crates: its ISA and gas modes, opcodes,
# exits, capability surface, linker entry points and fixtures.
jar-check:
    let hits = (rg -n --glob '!**/target/**' 'IsaMode|CapabilityManifest|\blink_elf\b|link_elf_with_argument_pages|run_with_vos_stubs|ECALL_VOS_|VOS_OBJECT_CAP|Opcode::Ecall\b|ExitReason::Ecall|ExitReason::Trap\b|kernel::|vm_pool|JAR\\x02|\.gp072\.json|\bGasModel\b|\bPerInstruction\b|\bmem_cycles\b|Opcode::Sbrk|\bsbrk\(|\b0x800\b' pvm | complete); if ($hits.exit_code == 0) { print $hits.stdout; error make { msg: "JAR remnants found" } } else { print "no JAR remnants" }

# The SDK's test actors, built with the guest toolchain in `pvm/guest`.
build-test-actors:
    cd agent/test-actors; cargo build --release --target ../../pvm/guest/riscv64em-vos.json

# The default agent program, built with the guest toolchain in `pvm/guest`.
build-agent:
    cd agent/default; cargo build --release --target ../../pvm/guest/riscv64em-vos.json

# The SDK, its macros' restrictions, the test actors on the testkit, the
# default agent against it, the checker's own model, the node running the
# agent, the network between nodes, and the `vos` command.
test-agent: build-test-actors build-agent
    cargo test -p vos-sdk -p vos-sdk-macros -p vos-testkit -p vos-checker -p vos-node -p vos-net -p vos-cli
    cargo test -p vos-cli --features faults --test processes faults::
    cargo test -p vos-cli --features faults --test fault_suite

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

# The builds without std. vos-raft for an embedded target, on core and alloc
# alone, built from the toolchain's source. The proof verifier on each
# channel, with the proof crate's verifier path under it: both are `no_std`
# crates, so a `std` path in either fails the build. Their target is wasm32,
# which still has std for their dependencies: the pinned Stwo's verifier path
# depends on dashmap, which needs std; the workspace's toolchain file
# installs the target.
check-no-std:
    cargo build -p vos-raft --target thumbv7em-none-eabihf -Zbuild-std=core,alloc
    cargo build -p vos-pvm-proof-verifier --target wasm32-unknown-unknown
    cargo build -p vos-pvm-proof-verifier --features poseidon2-channel --target wasm32-unknown-unknown

# Checks before pushing: everything except proving.
# The quick gate, after each change: formatting, the docs' links, the
# builds without std, the workspace's lints, and the suites of the node, the
# agent, vos-raft and the crates under them.
# Left to `just ci`: the slow fault runs (the five-process fault suite, the
# fault build's process tests), the PVM vectors, the bench and prover
# library tests, and the lints of other feature sets.
check: fmt-check doc-check check-no-std build-test-actors build-agent
    cargo clippy --workspace --all-targets --quiet -- -D warnings
    cargo test -p vos-pvm -p vos-pvm-compiler -p vos-pvm-program -p vos-pvm-codec -p vos-raft -p merkle-crdt -p vos-pvm-precompiles -p vos-pvm-proof-verifier -p vos-wire -p vos-tree -p vos-jam
    cargo test -p vos-sdk -p vos-sdk-macros -p vos-testkit -p vos-checker -p vos-node -p vos-net -p vos-cli

# Everything but the prover suites: before a merge, and at the end of each
# planned stage of work.
ci: fmt-check doc-check check-no-std clippy jar-check test vectors test-bench test-agent check-no-faults

# The gate before merging: `ci` plus the prover suites, the soundness gates
# and the bench tests that prove. Run it under a memory limit.
ci-full: ci test-proof test-bench-proof

# Use the repository's hooks: fmt and clippy before commits, `just ci`
# before pushes.
install-hooks:
    git config core.hooksPath .githooks
