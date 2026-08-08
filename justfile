# Root justfile for vos
set shell := ["nu", "-c"]

# List available recipes
default:
    @just --list

# ── Build ───────────────────────────────────────────────────────────

# Build the workspace crates, extensions, and PVM actors.
build: build-crates build-extensions build-pvm

# Build workspace crates (vos, vosx, zkpvm, support crates, etc.).
build-crates:
    cargo build

# Build native extension plugins (.so files).
build-extensions:
    cargo build -p echo-extension -p proxy-extension -p fetcher-extension \
                -p byte-echo-extension -p tcp-echo-extension

# Build WASM actors (wasm32-unknown-unknown target).
build-wasm:
    cd tests/fixtures/wasm/echo; cargo build --target wasm32-unknown-unknown --release

# Build the public v2 actors and the legacy PVM regression fixtures.
build-pvm: build-examples build-v2-registry-fixtures build-legacy-pvm-fixtures

# Build the four public v2 examples (private-age + age-gate is one scenario).
build-examples:
    cd examples/actors; cargo +nightly actor -p v2-counter
    cd examples/actors; cargo +nightly actor -p v2-workflow
    cd examples/actors; cargo +nightly actor -p v2-private-age
    cd examples/actors; cargo +nightly actor -p v2-age-gate
    cd examples/actors; cargo +nightly actor -p v2-shared-board

# Build ELFs retained only by the old-host regression suite.
build-legacy-pvm-fixtures:
    cd tests/fixtures/legacy-v1; just build

# Build v2-only programs consumed by package/registry integration tests.
build-v2-registry-fixtures:
    cd tests/fixtures/v2/actors/crdt-counter; cargo +nightly actor

# Build the protocol-pinned generic VOS service guest.
build-vos-service:
    cd services/vos-service; cargo +nightly actor

# Build the package/service pair consumed by the physical daemon-root test.
build-v2-daemon-root-artifacts: build-vos-service
    cd examples/actors; cargo +nightly actor -p v2-counter

# Build every guest consumed by the physical v2 service-PVM gate.
build-v2-pvm-test-artifacts: build-v2-daemon-root-artifacts (build-actor "space-authority")
    cd tests/fixtures/legacy-v1/actors/greeter; cargo +nightly actor
    cd tests/fixtures/legacy-v1/actors/probe; cargo +nightly actor
    cd vos/tests/fixtures/crdt-counter-v2; cargo +nightly actor
    cd vos/tests/fixtures/workflow-v2; cargo +nightly actor
    cd vos/tests/fixtures/cycle-v2; cargo +nightly actor

# Build a single built-in PVM actor by name (e.g., just build-actor space-registry).
build-actor name:
    cd actors/{{name}}; cargo +nightly actor

# Build all generated artifacts consumed by the test suite.
build-test-artifacts: build-extensions build-pvm build-v2-pvm-test-artifacts build-actors build-voucher-check build-witnessed-transfer
    cargo build

# Build all built-in actors used by host tests.
build-actors: (build-actor "space-registry") (build-actor "space-bridge") \
              (build-actor "space-authority") \
              (build-actor "clerk-ledger") (build-actor "clerk-bridge") \
              (build-actor "clerk-settle") build-clerk-apply
    cargo build -p prover-extension
    cargo build -p prover-extension --release

# Build the voucher-check PVM guest used by Mode::External voucher proofs.
build-voucher-check:
    cd tests/fixtures/legacy-v1/actors/voucher-check; cargo +nightly build --release

# Build the pure-verifier Task used by the WitnessedLedger proof gate.
build-witnessed-transfer:
    cd tests/fixtures/legacy-v1/actors/witnessed-transfer; cargo +nightly actor

# Build the flagship #[actor(task, provable)] pure verifier.
build-clerk-apply:
    cd tests/fixtures/provable/clerk-apply; cargo +nightly build --release

# Refresh the bundled space-registry ELF shipped with vosx.
refresh-bundled-registry: (build-actor "space-registry")
    cp actors/space-registry/target/riscv64em-javm/release/space_registry.elf \
       vosx/blobs/space_registry.elf

# Refresh the exact canonical PVM used to construct each space's root-signed
# authority package. The temporary .vos is discarded: package signing belongs
# to the space root at first startup, so every peer installs the same bytes.
refresh-bundled-authority: (build-actor "space-authority")
    cargo run -p vosx -- build actors/space-authority --name space-authority \
      --version artifact-only --out-dir target/bundled-space-authority
    cp target/bundled-space-authority/space-authority.pvm \
       vosx/blobs/space_authority.pvm

# Refresh the bundled dev-project ELF shipped with vosx.
refresh-bundled-dev-project: (build-actor "dev-project")
    cp actors/dev-project/target/riscv64em-javm/release/dev_project.elf \
       vosx/blobs/dev_project.elf

# Build the on-chain settlement-verifier ELF for the JAM PVM (riscv64em-javm).
build-settle:
    cd zkpvm/settlement-verifier; cargo build --release --target riscv64em-javm.json \
      -Zbuild-std=core,alloc,compiler_builtins \
      -Zbuild-std-features=compiler-builtins-mem \
      --features pvm-settle --bin settle

# ── Test ──────────────────────────────────────────────────────────────

# Run all workspace tests and integration tests against freshly-built artifacts.
test: build-test-artifacts
    cargo test --all -- --test-threads=1
    just test-v2-examples

# Build and test the concise runtime-v2 examples in their nested workspace.
test-v2-examples:
    cd examples/actors; cargo test --workspace
    cd examples/actors; cargo +nightly actor -p v2-counter
    cd examples/actors; cargo +nightly actor -p v2-workflow
    cd examples/actors; cargo +nightly actor -p v2-private-age
    cd examples/actors; cargo +nightly actor -p v2-age-gate
    cd examples/actors; cargo +nightly actor -p v2-shared-board

# Run extension tests.
test-extensions: build-extensions
    cargo test -p vos extension -- --nocapture

# Run the PVM/ELF e2e integration tests.
test-pvm: build-test-artifacts
    cargo test -p vos --test elf_integration -- --nocapture --test-threads=1

# Run the signed-package → daemon → durable-reopen acceptance path.
test-v2-daemon-root: build-v2-daemon-root-artifacts
    cargo test -p vosx --test onboarding_e2e signed_v2_package_runs_and_reopens_through_the_space_daemon -- --nocapture --test-threads=1

# Run a single test by name.
test-one name: build-extensions
    cargo test -p vos {{name}} -- --nocapture

# Run the full zkpvm test suite.
test-zkpvm:
    cargo test -p zkpvm

# Run only the fast zkpvm tests.
test-zkpvm-fast:
    cargo test -p zkpvm --lib --test add64_e2e --test memory --test control_flow

# ── Benchmarks ──────────────────────────────────────────────────────

# Run the zkpvm proving benchmarks. Pass a filter to select benches
# (e.g., `just bench log16`).
bench filter="":
    cargo bench -p zkpvm --bench prove -- {{filter}}

# ── Run ───────────────────────────────────────────────────────────────

# Run a retired v1 fixture as a one-shot, no space, no networking.
run-actor name="greeter": build-pvm
    cargo run --bin vosx -- run tests/fixtures/legacy-v1/actors/{{name}}/target/riscv64em-javm/release/{{name}}.elf

# ── zkpvm verifier ──────────────────────────────────────────────────

# Check the verifier-only path builds without std.
check-zkpvm-no-std:
    cargo build -p zkpvm --no-default-features
    cargo build -p zkpvm-verifier

# Build the zkpvm verifier for wasm32-unknown-unknown.
check-zkpvm-wasm:
    rustup target add wasm32-unknown-unknown
    cargo build -p zkpvm-verifier --target wasm32-unknown-unknown

# ── Maintenance ───────────────────────────────────────────────────────

# Check everything compiles without producing artifacts.
check:
    cargo run -p jar-revision-check
    cargo check --all-targets

# Reject mixed JAVM/transpiler/tracer/verifier revisions, including excluded
# fuzz and benchmark workspaces.
check-jar-revisions:
    cargo run -p jar-revision-check

# Run the same checks the pre-commit and pre-push hooks run.
check-all:
    cargo run -p jar-revision-check
    cargo fmt -- --check
    cargo clippy --workspace -- -D warnings \
        -A clippy::too_many_arguments \
        -A clippy::type_complexity \
        -A clippy::result_unit_err \
        -A clippy::manual_async_fn
    cargo test --workspace --lib
    just build-pvm
    just build-v2-pvm-test-artifacts
    cargo test -p vos --test v2_service_pvm -- --nocapture --test-threads=1
    just test-v2-examples

# Lint with clippy.
lint:
    cargo clippy --all-targets -- -D warnings

# Format all code.
fmt:
    cargo fmt --all

# Clean build artifacts.
clean:
    cargo clean
    try { cd examples/actors; cargo clean } catch { }

# Install git hooks (.githooks/pre-commit, .githooks/pre-push).
install-hooks:
    git config core.hooksPath .githooks
    @echo "git hooks installed at .githooks"

# Run cargo-deny (licenses, advisories, bans, sources).
deny:
    cargo deny --all-features check

# Check vos-raft builds on representative no_std embedded targets.
check-no-std:
    cargo build -p vos-raft --no-default-features --target thumbv7em-none-eabihf
    cargo build -p vos-raft --no-default-features --target riscv32imc-unknown-none-elf
