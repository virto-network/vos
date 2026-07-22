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
    cd examples/wasm/echo; cargo build --target wasm32-unknown-unknown --release
    cd examples/wasm/fetcher; cargo build --target wasm32-unknown-unknown --release

# Build the public v2 actors and the legacy PVM regression fixtures.
build-pvm: build-examples build-legacy-pvm-fixtures

# Build the four public v2 examples (private-age + age-gate is one scenario).
build-examples:
    cd examples/actors; cargo +nightly actor -p v2-counter
    cd examples/actors; cargo +nightly actor -p v2-workflow
    cd examples/actors; cargo +nightly actor -p v2-private-age
    cd examples/actors; cargo +nightly actor -p v2-age-gate
    cd examples/actors; cargo +nightly actor -p v2-shared-board

# Package all public v2 scenarios with one PVM and signed external dependencies.
package-examples service_pvm="dist/vos-service.pvm" out_dir="dist/examples": build-examples
    cargo run -p vosx -- build examples/actors/counter --service-pvm {{service_pvm}} --out-dir {{out_dir}}
    cargo run -p vosx -- build examples/actors/workflow --service-pvm {{service_pvm}} --out-dir {{out_dir}} --external-actor peer
    cargo run -p vosx -- build examples/actors/private-age --service-pvm {{service_pvm}} --out-dir {{out_dir}}
    cargo run -p vosx -- build examples/actors/age-gate --service-pvm {{service_pvm}} --out-dir {{out_dir}} --external-actor private-age
    cargo run -p vosx -- build examples/actors/shared-board --service-pvm {{service_pvm}} --out-dir {{out_dir}}

# Build the Clerk acceptance actors without the retired prover extension.
build-clerk:
    cd actors/clerk-ledger; cargo +nightly actor
    cd actors/clerk-bridge; cargo +nightly actor
    cd actors/clerk-settle; cargo +nightly actor

# Package Clerk for the v2 registry path; manifests never install an ELF.
package-clerk service_pvm="dist/vos-service.pvm" out_dir="dist/clerk": build-clerk
    cargo run -p vosx -- build actors/clerk-ledger --name clerk-ledger --version recipe --service-pvm {{service_pvm}} --out-dir {{out_dir}}
    cargo run -p vosx -- build actors/clerk-bridge --name clerk-bridge --version recipe --service-pvm {{service_pvm}} --out-dir {{out_dir}}
    cargo run -p vosx -- build actors/clerk-settle --name clerk-settle --version recipe --service-pvm {{service_pvm}} --out-dir {{out_dir}}

# Build ELFs retained only by the old-host regression suite.
build-legacy-pvm-fixtures:
    cd tests/fixtures/legacy-v1; just build

# Build a single built-in PVM actor by name (e.g., just build-actor space-registry).
build-actor name:
    cd actors/{{name}}; cargo +nightly actor

# The retired voucher-check proof guest is intentionally opt-in: it depends on
# an external cipher-clerk checkout and is not part of the v2 actor/package ABI.
# Build all in-repository artifacts consumed by the default test suite.
build-test-artifacts: build-extensions build-pvm build-actors
    cargo build

# Build all built-in actors used by host tests.
build-actors: (build-actor "space-registry") (build-actor "space-bridge") \
              (build-actor "clerk-ledger") (build-actor "clerk-bridge") \
              (build-actor "clerk-settle")
    cargo build -p prover-extension
    cargo build -p prover-extension --release

# This recipe requires the developer's separate cipher-clerk checkout.
# Build the retired v1 voucher-check proof guest for explicit legacy zk tests.
build-voucher-check:
    cd tests/fixtures/legacy-v1/actors/voucher-check; cargo +nightly build --release

# Refresh the bundled space-registry ELF shipped with vosx.
refresh-bundled-registry: (build-actor "space-registry")
    cp actors/space-registry/target/riscv64em-javm/release/space_registry.elf \
       vosx/blobs/space_registry.elf

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

# Run extension tests.
test-extensions: build-extensions
    cargo test -p vos extension -- --nocapture

# Run the PVM/ELF e2e integration tests.
test-pvm: build-test-artifacts
    cargo test -p vos --test elf_integration -- --nocapture --test-threads=1

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

# Run a retired single-actor fixture through the compatibility harness.
run-legacy-fixture name="greeter": build-legacy-pvm-fixtures
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
