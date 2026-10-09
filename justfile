set shell := ["nu", "-c"]

default:
    @just --list

# Fast suites: runtime, compiler, program format, codec, support crates,
# precompile shim, verifier, prover library, wire types, node.
test:
    cargo test -p vos-pvm -p vos-pvm-compiler -p vos-pvm-program -p vos-pvm-codec -p vos-raft -p merkle-crdt -p vos-pvm-precompiles -p vos-pvm-proof-verifier -p vos-wire -p vos-node
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

# Spike benches against this tree: S1 snapshots, S2 nesting.
bench: build-bench-guests
    cargo run --release -p vos-pvm-bench --bin snapshots
    cargo run --release -p vos-pvm-bench --bin nesting

# Gray Paper 0.8.0 conformance vectors on the interpreter and the JIT.
vectors:
    cargo test -p vos-pvm --test pvm_vectors

# Prover integration suites, including the soundness gates behind
# `debug-internals`. Memory-heavy: two threads fit under a 24 GiB limit, e.g.
# `systemd-run --user --scope -p MemoryMax=24G -p MemorySwapMax=0 just test-proof`.
test-proof: build-guests
    cargo test -p vos-pvm-proof --features debug-internals --tests -- --test-threads=2

# Guest programs the prover suites run.
build-guests: build-settle

# The settlement verifier as a PVM program.
build-settle:
    cd pvm/proof/settlement-verifier; cargo build --release --target riscv64em-vos.json -Zbuild-std=core,alloc,compiler_builtins -Zbuild-std-features=compiler-builtins-mem --features pvm-settle --bin settle

fmt-check:
    cargo fmt --all -- --check

clippy:
    cargo clippy --workspace --all-targets --quiet -- -D warnings
    cargo clippy -p vos-pvm-bench --features prove --all-targets --quiet -- -D warnings

# Fails on any JAR remnant in the PVM crates: its ISA and gas modes, opcodes,
# exits, capability surface, linker entry points and fixtures.
jar-check:
    let hits = (rg -n --glob '!**/target/**' 'IsaMode|CapabilityManifest|\blink_elf\b|link_elf_with_argument_pages|run_with_vos_stubs|ECALL_VOS_|VOS_OBJECT_CAP|Opcode::Ecall\b|ExitReason::Ecall|ExitReason::Trap\b|kernel::|vm_pool|JAR\\x02|\.gp072\.json|\bGasModel\b|\bPerInstruction\b|\bmem_cycles\b|Opcode::Sbrk|\bsbrk\(|\b0x800\b' pvm | complete); if ($hits.exit_code == 0) { print $hits.stdout; error make { msg: "JAR remnants found" } } else { print "no JAR remnants" }

# The SDK's test actors, built with the guest toolchain in `pvm/guest`.
build-test-actors:
    cd agent/test-actors; cargo build --release --target ../../pvm/guest/riscv64em-vos.json

# The SDK, its macros' restrictions, and the test actors on the testkit.
test-agent: build-test-actors
    cargo test -p vos-sdk -p vos-sdk-macros -p vos-testkit

# Checks before pushing: everything except proving.
ci: fmt-check clippy jar-check test vectors test-bench test-agent

# The gate before merging: `ci` plus the prover suites, the soundness gates
# and the bench tests that prove. Run it under a memory limit.
ci-full: ci test-proof test-bench-proof

# Use the repository's hooks: fmt and clippy before commits, `just ci`
# before pushes.
install-hooks:
    git config core.hooksPath .githooks
