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

# Build the retained runtime and actor examples.
build-pvm: verify-agent-runtime-release build-examples (build-actor "space-registry")

# Build the small maintained public Agent example set.
build-examples:
    cd examples/actors; cargo actor --locked -p counter
    cd examples/actors; cargo actor --locked -p shared-board
    cd examples/actors; cargo actor --locked -p private-notes
    cd examples/actors; cargo actor --locked -p local-signer
    cd examples/agent-runtimes/custom-linear; cargo actor --locked

# Build the one retained physical PVM fixture.
build-pvm-test-artifacts: build-probe-fixture

build-probe-fixture:
    cd vos/tests/fixtures/probe; cargo actor --locked

# Execute the artifact-dependent invariant explicitly; it must not silently
# pass when the fixture is missing from an ordinary library-only test run.
check-probe-fixture: build-probe-fixture
    cargo test --locked -p vos --lib node::tests::dispatch_routes_external_transfers_only_after_commit -- --ignored --exact --test-threads=1

# Build a single built-in PVM actor by name (e.g., just build-actor space-registry).
build-actor name:
    cd actors/{{name}}; cargo actor --locked

# Build all generated artifacts consumed by the test suite.
build-test-artifacts: build-extensions build-pvm build-probe-fixture build-actors build-voucher-check
    cargo build

# Build all built-in actors used by host tests.
build-actors: (build-actor "space-registry") \
              (build-actor "clerk-bridge") \
              (build-actor "clerk-settle")
    cargo build -p prover-extension
    cargo build -p prover-extension --release

# Build the voucher-check PVM guest used by Mode::External voucher proofs.
build-voucher-check:
    cd pvm/proof/fixtures/voucher-check; cargo +nightly build --release

# Re-measure every production voucher catalog identity, including its
# ISA-profile-bound AIR commitment. The exact released PVM is checked in in
# compressed form, so this never consults an ignored target directory or
# silently substitutes a current-source candidate for the published artifact.
verify-voucher-check-release:
    cargo test -p vos-pvm-proof --test voucher_check_smoke \
      voucher_check_catalog_ -- --test-threads=1

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

# Build and physically validate the bundled standard agent runtime without
# replacing its committed release artifact.
build-agent-runtime-candidate:
    cd services/agent-runtime; cargo actor --locked
    let guest_target = (do { cd services/agent-runtime; cargo metadata --locked --format-version 1 --no-deps | from json | get target_directory }); cargo run --locked -p vosx -- agent-runtime-pvm \
      ($guest_target | path join "riscv64em-vos" "release" "agent_runtime.elf") \
      --out target/agent-runtime-candidate.pvm
    @echo "candidate PVM: target/agent-runtime-candidate.pvm"

# Require current source and the pinned toolchain to reproduce the exact
# standard runtime bundled in vosx. Candidate generation stays separate so a
# reviewed repin can inspect the new identity before replacing the artifact.
verify-agent-runtime-release: build-agent-runtime-candidate
    cmp target/agent-runtime-candidate.pvm vosx/blobs/agent_runtime.pvm

# Refresh the bundled registry from the pinned source and toolchain.
refresh-bundled-registry:
    VOS_REPIN_ARTIFACTS=1 scripts/build-production-artifacts.sh registry

# Reproduce both complete system packages with pinned source and tooling.
build-system-release:
    bash scripts/build-agent-release-artifacts.sh system

build-authority-release: build-system-release

build-catalog-release: build-system-release

# Reproduce the standard agent runtime from its separately pinned source
# revision and require exact identity with the committed release artifact.
build-agent-runtime-release:
    bash scripts/build-agent-release-artifacts.sh runtime

# Assemble the standard AgentRuntime and both system actors embedded in vosx.
# The command refuses external program paths and never replaces an existing
# directory, so a release cannot silently select or mutate a different pin.
package-production-release out="target/production-release": build-system-release build-agent-runtime-release verify-voucher-check-release
    cargo run -p vosx -- release bundle --out "{{out}}"
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
    cd examples/actors; cargo actor --locked -p counter
    cd examples/actors; cargo actor --locked -p shared-board
    cd examples/actors; cargo actor --locked -p private-notes
    cd examples/actors; cargo actor --locked -p local-signer
    cd services/agent-runtime-guest; cargo test
    cd examples/agent-runtimes/custom-linear; cargo actor
    cd examples/agent-runtimes/custom-linear; cargo test
    cd examples/agent-runtimes/custom-linear; cargo test --lib tests::compiled_runtime_executes_scheduling_and_rejects_attested_context -- --ignored --exact --test-threads=1

# Execute the maintained custom AgentRuntime through its freshly linked SPI
# artifact. The ordinary host tests remain fast and artifact-independent;
# this explicit gate proves that the checked source, target configuration, and
# clean outer ABI produce the same durable scheduling transitions.
test-custom-agent-runtime:
    cd examples/agent-runtimes/custom-linear; cargo actor
    cd examples/agent-runtimes/custom-linear; cargo test
    cd examples/agent-runtimes/custom-linear; cargo test --lib tests::compiled_runtime_executes_scheduling_and_rejects_attested_context -- --ignored --exact --test-threads=1

# Build both explicit guest fixtures and run physical Local recovery gates.
test-local-agent-recovery:
    #!/usr/bin/env bash
    set -euo pipefail
    repository_root="{{justfile_directory()}}"
    test_target="${CARGO_TARGET_DIR:-$repository_root/target}"
    mkdir -p "$test_target"
    test_target=$(cd "$test_target" && pwd)
    export TMPDIR="$test_target/task-tmp"
    mkdir -p "$TMPDIR"
    runtime_target="$test_target/agent-recovery-artifacts/runtime"
    scripted_target="$test_target/agent-recovery-artifacts/scripted"
    (cd "$repository_root/services/agent-runtime"; CARGO_TARGET_DIR="$runtime_target" cargo +nightly-2026-03-20 actor --offline --locked)
    (cd "$repository_root/examples/agent-runtimes/custom-linear"; CARGO_TARGET_DIR="$scripted_target" cargo +nightly-2026-03-20 actor --offline --locked --features scripted-fixture)
    export AGENT_RUNTIME_CANDIDATE_ELF="$runtime_target/riscv64em-vos/release/agent_runtime.elf"
    export AGENT_SCRIPTED_RUNTIME_ELF="$scripted_target/riscv64em-vos/release/custom_linear_agent_runtime.elf"
    CARGO_TARGET_DIR="$test_target" cargo +nightly-2025-05-09 test --offline --locked -p vos --features 'agent-runtime storage network' --lib agent::local_sdk_host::tests -- --test-threads=1

# Run extension tests.
test-extensions: build-extensions
    cargo test -p vos extension -- --nocapture
    cargo test -p substrate-extension
    cargo check -p substrate-extension --no-default-features

# Run the checked-in v0.8 semantic and ROB-gas corpus on both
# runtime backends. This is intentionally an integration test, so workspace
# `--lib` checks do not cover it implicitly.
test-pvm-vectors:
    cargo test -p vos-pvm --test pvm_vectors

# Run a single test by name.
test-one name: build-extensions
    cargo test -p vos {{name}} -- --nocapture

# Run the full PVM proof test suite.
test-pvm-proof: verify-voucher-check-release
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
    just test-pvm-vectors
    just verify-voucher-check-release
    just build-pvm
    just check-probe-fixture
    just test-examples
    just clean-break-check

# Serial clean-cutover regression and negative-surface gate. C3's release
# check invokes this recipe verbatim.
clean-break-check:
    cargo test -p vos --features pvm --lib agent::clean_bootstrap -- --test-threads=1
    cargo test -p vos --lib agent::production_owner -- --test-threads=1
    cargo test -p vos --lib agent::supervisor_adapters -- --test-threads=1
    cargo test -p vosx --bin vosx commands::space::clean -- --test-threads=1
    just agent-recovery-check
    just agent-system-actors-check
    just agent-sdk-doc-check
    bash scripts/check-agent-clean-break.sh

# System actors are nested workspaces: the root workspace tests do not run
# their unit tests, even though vosx links their libraries for bootstrap.
agent-system-actors-check:
    bash -eu -c 'mkdir -p target/task-tmp; TMPDIR="{{justfile_directory()}}/target/task-tmp" cargo test --locked --manifest-path actors/system-authority/Cargo.toml --lib -- --test-threads=1'
    bash -eu -c 'mkdir -p target/task-tmp; TMPDIR="{{justfile_directory()}}/target/task-tmp" cargo test --locked --manifest-path actors/system-catalog/Cargo.toml --lib -- --test-threads=1'

# Check the public portable SDK documentation without relying on host features.
# This is an SDK intra-doc-link gate, not a whole-book or external-link audit.
agent-sdk-doc-check:
    bash -eu -c 'mkdir -p target/task-tmp; TMPDIR="{{justfile_directory()}}/target/task-tmp" RUSTDOCFLAGS="${RUSTDOCFLAGS:-} -D rustdoc::broken_intra_doc_links" cargo doc -p vos-agent-sdk --no-default-features --no-deps'

# Private host/store modules are absent without private-agent-store. Keep the
# feature explicit so successful zero-test runs cannot stand in for recovery.
agent-recovery-check:
    cargo test -p vos --features pvm,private-agent-store --lib agent::private_host::tests -- --test-threads=1
    cargo test -p vos --features pvm,private-agent-store --lib agent::private_store::tests -- --test-threads=1
    cargo test -p vos --features pvm,private-agent-store --lib agent::private_runtime::tests -- --test-threads=1
    cargo test -p vos --features pvm,private-agent-store --lib portable -- --test-threads=1

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
