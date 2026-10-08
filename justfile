set shell := ["nu", "-c"]

default:
    @just --list

# Fast suites: runtime, compiler, program format, codec, support crates,
# precompile shim, verifier, prover library.
test:
    cargo test -p vos-pvm -p vos-pvm-compiler -p vos-pvm-program -p vos-pvm-codec -p vos-raft -p merkle-crdt -p vos-pvm-precompiles -p vos-pvm-proof-verifier
    cargo test -p vos-pvm-proof --lib

# Bench guests, built with the guest toolchain in `pvm/guest`.
build-bench-guests:
    for guest in [workflows actor agent hash-software hash-precompile] { do { cd $"pvm/bench/guests/($guest)"; cargo build --release --target ../../../guest/riscv64em-vos.json } }

# Cross-host checks that need the bench guests.
test-bench: build-bench-guests
    cargo test -p vos-pvm-bench

# Spike benches against this tree: S1 snapshots, S2 nesting.
bench: build-bench-guests
    cargo run --release -p vos-pvm-bench --bin snapshots
    cargo run --release -p vos-pvm-bench --bin nesting

# Gray Paper 0.8.0 conformance vectors on the interpreter and the JIT.
vectors:
    cargo test -p vos-pvm --test pvm_vectors

# Prover integration suites, including the soundness gates behind
# `debug-internals`. Memory-heavy: two threads.
test-proof: build-guests
    cargo test -p vos-pvm-proof --features debug-internals --tests -- --test-threads=2

# Guest programs the prover suites run.
build-guests: build-settle build-voucher-check

# The settlement verifier as a PVM program.
build-settle:
    cd pvm/proof/settlement-verifier; cargo build --release --target riscv64em-vos.json -Zbuild-std=core,alloc,compiler_builtins -Zbuild-std-features=compiler-builtins-mem --features pvm-settle --bin settle

# The voucher-check guest.
build-voucher-check:
    cd pvm/proof/fixtures/voucher-check; cargo build --release

fmt-check:
    cargo fmt --all -- --check

clippy:
    cargo clippy --workspace --all-targets --quiet -- -D warnings

# Fails while any JAR remnant is left in the PVM crates. Joins `ci` once
# slice 1 step 1.2 is complete.
jar-check:
    let hits = (rg -n --glob '!**/target/**' --glob '!**/tests/to-port/**' 'IsaMode::Jar|CapabilityManifest|\blink_elf\b|link_elf_with_argument_pages|run_with_vos_stubs|ECALL_VOS_|VOS_OBJECT_CAP|Opcode::Ecall\b|ExitReason::Ecall|kernel::|vm_pool|JAR\\x02|gp072' pvm | complete); if ($hits.exit_code == 0) { print $hits.stdout; error make { msg: "JAR remnants found" } } else { print "no JAR remnants" }

# Checks before pushing.
ci: fmt-check clippy test vectors test-bench

# Use the repository's hooks: fmt and clippy before commits, `just ci`
# before pushes.
install-hooks:
    git config core.hooksPath .githooks
