# Root justfile for vos
set shell := ["nu", "-c"]

# List available recipes
default:
    @just --list

# ── Build ───────────────────────────────────────────────────────────

# Build the workspace crates, extensions, and PVM actors.
build: build-crates build-extensions build-pvm

# Build workspace crates (VOS, the PVM toolchain, and support crates).
build-crates:
    cargo build

# Build native extension plugins (.so files).
build-extensions:
    cargo build -p echo-extension -p proxy-extension -p fetcher-extension -p heartbeat-extension
    cargo build -p substrate-extension

# Build WASM actors (wasm32-unknown-unknown target).
build-wasm:
    cd tests/fixtures/wasm/echo; cargo build --target wasm32-unknown-unknown --release

# Build the service and the actors used by examples and integration tests.
build-pvm: build-vos-service build-examples build-registry-fixtures

# Build the four public service examples (private-age + age-gate is one scenario).
build-examples:
    cd examples/actors; cargo +nightly actor -p counter
    cd examples/actors; cargo +nightly actor -p workflow
    cd examples/actors; cargo +nightly actor -p private-age
    cd examples/actors; cargo +nightly actor -p age-gate
    cd examples/actors; cargo +nightly actor -p shared-board

# Build only programs consumed by package/registry integration tests.
build-registry-fixtures:
    cd tests/fixtures/actors/crdt-counter; cargo +nightly actor

# Build the protocol-pinned generic VOS service guest.
build-vos-service:
    scripts/build-production-artifacts.sh service

# Build the package/service pair consumed by the physical daemon-root test.
build-daemon-root-artifacts: build-vos-service
    cd examples/actors; cargo +nightly actor -p counter
    cd vos/tests/fixtures/counter-upgrade; cargo +nightly actor

# Build every guest consumed by the physical service gate.
build-pvm-test-artifacts: build-daemon-root-artifacts build-registry-fixtures (build-actor "space-authority") (build-actor "clerk-ledger") (build-actor "clerk-bridge") build-clerk-apply build-workflow-fixture
    cd vos/tests/fixtures/greeter; cargo +nightly actor
    cd vos/tests/fixtures/probe; cargo +nightly actor
    cd vos/tests/fixtures/tally; cargo +nightly actor
    cd vos/tests/fixtures/crdt-counter; cargo +nightly actor
    cd vos/tests/fixtures/cycle; cargo +nightly actor

# Build the workflow guest shared by the physical and extension hostcall tests.
build-workflow-fixture:
    cd vos/tests/fixtures/workflow; cargo +nightly actor

# Build a single built-in PVM actor by name (e.g., just build-actor space-registry).
build-actor name:
    cd actors/{{name}}; cargo +nightly actor

# Build all generated artifacts consumed by the test suite.
build-test-artifacts: build-extensions build-pvm build-pvm-test-artifacts build-actors build-voucher-check
    cargo build

# Build all built-in actors used by host tests.
build-actors: (build-actor "space-registry") \
              (build-actor "space-authority") \
              (build-actor "clerk-bridge") \
              (build-actor "clerk-settle") build-clerk-apply
    cargo build -p prover-extension
    cargo build -p prover-extension --release

# Build the voucher-check PVM guest used by Mode::External voucher proofs.
build-voucher-check:
    cd pvm/proof/fixtures/voucher-check; cargo +nightly build --release

# Build the flagship Task and a signed package for physical tests. The signer
# is deliberately ephemeral: tests assert the pinned content identity, never
# treat this wrapper as a production release artifact.
build-clerk-apply:
    scripts/build-production-artifacts.sh clerk-test

# Build the signed Clerk production package with its immutable proving Task.
# Package content is reproducible and pinned by ProgramId/DeploymentId/Task
# hash; the exact `.vos` wrapper is operator-specific and therefore requires
# an explicit libp2p identity key rather than consulting ambient XDG state.
build-clerk-package signer:
    scripts/build-production-artifacts.sh clerk "{{signer}}"

# Build current sources only as an explicit release candidate. This never
# replaces the committed production PVM or the pinned fresh-build fixture.
build-vos-service-candidate:
    cd services/vos-service; cargo actor
    @echo "candidate ELF: services/vos-service/target/riscv64em-vos/release/vos_service.elf"

# Refresh the bundled registry from the pinned source and toolchain.
refresh-bundled-registry:
    VOS_REPIN_ARTIFACTS=1 scripts/build-production-artifacts.sh registry

# Build a deliberately distinct, contract-compatible authority PVM for the
# physical UpgradeActor rehearsal. Canonical release builds never enable
# `upgrade-fixture` and must not be replaced through this recipe.
build-authority-upgrade-candidate:
    cd actors/space-authority; cargo +nightly actor --features upgrade-fixture
    cargo run -p vosx -- build \
      actors/space-authority/target/riscv64em-vos/release/space_authority.elf \
      --name space-authority \
      --out-dir target/bundled-space-authority
    @echo "candidate: target/bundled-space-authority/space-authority.pvm"
    @echo "install only through a reviewed UpgradeActor operation"

# Reproduce the canonical authority through vosx's checkout-independent actor
# build and require exact identity with the committed release artifact.
build-authority-release:
    scripts/build-production-artifacts.sh authority

# Assemble the two protocol-pinned production PVMs with a strict manifest.
# The command refuses to replace an existing directory so a release operator
# cannot silently mutate an artifact set that has already been distributed.
package-production-release out="target/production-release": build-authority-release
    cargo run -p vosx -- release bundle \
      --service-pvm services/vos-service/vos-service.pvm --out "{{out}}"
    cargo run -p vosx -- release verify "{{out}}"

# Build the settlement-verifier ELF for the VOS PVM target.
build-settle:
    cd pvm/proof/settlement-verifier; cargo build --release --target riscv64em-vos.json \
      -Zbuild-std=core,alloc,compiler_builtins \
      -Zbuild-std-features=compiler-builtins-mem \
      --features pvm-settle --bin settle

# ── Test ──────────────────────────────────────────────────────────────

# Run all workspace tests and integration tests against freshly-built artifacts.
test: build-test-artifacts
    cargo test --all -- --test-threads=1
    just test-examples

# Build and test the concise runtime examples in their nested workspace.
test-examples:
    cd examples/actors; cargo test --workspace
    cd examples/actors; cargo +nightly actor -p counter
    cd examples/actors; cargo +nightly actor -p workflow
    cd examples/actors; cargo +nightly actor -p private-age
    cd examples/actors; cargo +nightly actor -p age-gate
    cd examples/actors; cargo +nightly actor -p shared-board

# Run extension tests.
test-extensions: build-extensions build-workflow-fixture
    cargo test -p vos extension -- --nocapture
    cargo test -p substrate-extension
    cargo check -p substrate-extension --no-default-features

# Run the physical service integration tests.
test-pvm: build-test-artifacts
    cargo test -p vos --test service_pvm -- --nocapture --test-threads=1

# Run the signed-package → daemon → offline backup → fresh-directory restore
# → durable-reopen release-operations acceptance path.
test-daemon-root: build-daemon-root-artifacts
    cargo test -p vosx --test onboarding_e2e signed_service_package_runs_and_reopens_through_the_space_daemon -- --nocapture --test-threads=1

# Exercise a stopped production voter moving to fresh machine roots and then
# rejoining/catching up under the same full node identity.
test-production-raft-relocation: build-daemon-root-artifacts
    cargo test -p vosx --test onboarding_e2e production_raft_root_survives_voter_join_leader_loss_and_backup_relocation -- --nocapture --test-threads=1

# Stable release check: exact artifact bundle + Local offline restore +
# production Raft voter relocation/failover.
test-release-operations: test-daemon-root test-production-raft-relocation

# Run the production-profile daemon gates against independent VTA1/VTR1
# authority sidecars, including fail-closed recovery, two-node CRDT sync, and
# three-voter Raft failover/catch-up through follower-facing calls.
test-production-daemon: build-daemon-root-artifacts build-registry-fixtures build-authority-upgrade-candidate
    cargo test -p vosx --test onboarding_e2e signed_service_roots_run_under_production_trust_and_recover -- --nocapture --test-threads=1
    cargo test -p vosx --test onboarding_e2e production_crdt_root_converges_across_enrolled_daemons_and_restart -- --nocapture --test-threads=1
    cargo test -p vosx --test onboarding_e2e production_raft_root_survives_voter_join_leader_loss_and_backup_relocation -- --nocapture --test-threads=1

# Run a single test by name.
test-one name: build-extensions
    cargo test -p vos {{name}} -- --nocapture

# Run the full PVM proof test suite.
test-pvm-proof:
    cargo test -p vos-pvm-proof

# Run only the fast PVM proof tests.
test-pvm-proof-fast:
    cargo test -p vos-pvm-proof --lib --test add64_e2e --test memory --test control_flow

# ── Benchmarks ──────────────────────────────────────────────────────

# Run the PVM proving benchmarks. Pass a filter to select benches
# (e.g., `just bench log16`).
bench filter="":
    cargo bench -p vos-pvm-proof --bench prove -- {{filter}}

# ── Run ───────────────────────────────────────────────────────────────

# ── PVM proof verifier ──────────────────────────────────────────────────

# Check the verifier-only path builds without std.
check-pvm-proof-no-std:
    cargo build -p vos-pvm-proof --no-default-features
    cargo build -p vos-pvm-proof-verifier

# Build the PVM proof verifier for wasm32-unknown-unknown.
check-pvm-proof-wasm:
    rustup target add wasm32-unknown-unknown
    cargo build -p vos-pvm-proof-verifier --target wasm32-unknown-unknown

# ── Maintenance ───────────────────────────────────────────────────────

# Check everything compiles without producing artifacts.
check:
    cargo check --all-targets

# Run the same checks the pre-commit and pre-push hooks run.
check-all:
    cargo fmt -- --check
    cargo clippy --workspace -- -D warnings \
        -A clippy::too_many_arguments \
        -A clippy::type_complexity \
        -A clippy::result_unit_err \
        -A clippy::manual_async_fn
    cargo test --workspace --lib
    just build-pvm
    just build-pvm-test-artifacts
    cargo test -p vos --test service_pvm -- --nocapture --test-threads=1
    just test-examples
    just test-release-operations
    just test-production-daemon

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
