# Root justfile for vos — build and test orchestration.

# Default: list available recipes
default:
    @just --list

# ── Build ───────────────────────────────────────────────────────────

# Build everything: crates, extensions, PVM actors, agents
build: build-crates build-extensions build-pvm

# Build the workspace (vos, vosx, etc.)
build-crates:
    cargo build

# Build native extension plugins (.so files)
build-extensions:
    cargo build -p echo-extension -p proxy-extension -p fetcher-extension

# Build WASM actors (wasm32-unknown-unknown target)
build-wasm:
    cd examples/wasm/echo && cargo build --target wasm32-unknown-unknown --release
    cd examples/wasm/fetcher && cargo build --target wasm32-unknown-unknown --release

# Build all PVM actors and agents (riscv64 targets, requires custom toolchain)
build-pvm:
    cd examples && just build

# ── Test ────────────────────────────────────────────────────────────

# Run all tests (workspace + integration)
test: build-extensions
    cargo test --all

# Run only extension tests
test-extensions: build-extensions
    cargo test -p vos extension -- --nocapture

# Smoke test the WASM actors in Node
test-wasm: build-wasm
    node examples/wasm/js/test.mjs
    node examples/wasm/js/test-fetch.mjs
    node examples/wasm/js/test-persist.mjs

# Run PVM-related integration tests (requires built PVM actors)
test-pvm: build-extensions
    cargo test -p vos --test elf_integration -- --nocapture

# Run a single test by name
test-one name: build-extensions
    cargo test -p vos {{name}} -- --nocapture

# Build just the crdt-counter actor (cycle-5 example)
build-crdt-counter:
    cd examples/actors/crdt-counter && cargo actor

# Build the space-registry actor — built-in PVM actor that
# lives under actors/ alongside the workspace crates. `cargo actor`
# is the alias defined in each actor's .cargo/config.toml that
# invokes `rustc --crate-type bin -Zbuild-std=…` against the
# riscv64em-javm target spec — produces the executable ELF the
# host bundles. Plain `cargo build --release` silently builds only
# the rlib + dropped cdylib, leaving the ELF stale.
build-registry:
    cd actors/space-registry && cargo +nightly actor

# Refresh the shipped registry blob at `vosx/blobs/space_registry.elf`.
# `cargo install vosx` from crates.io reads this file (the dev path
# `actors/space-registry/target/.../space_registry.elf` is only
# available in a working tree). Run after any change that affects
# the produced space-registry ELF before publishing.
refresh-bundled-registry: build-registry
    cp actors/space-registry/target/riscv64em-javm/release/space_registry.elf \
       vosx/blobs/space_registry.elf
    @echo "✓ refreshed vosx/blobs/space_registry.elf"

# Build the space-bridge actor — built-in PVM actor that
# every member space of a hyperspace runs as the cross-space
# gateway. Same toolchain as the registry.
build-bridge:
    cd actors/space-bridge && cargo +nightly actor


# Build the clerk-ledger actor — per-bank stateful agent
# wrapping cipher-clerk's confidential double-entry kernel.
build-clerk-ledger:
    cd actors/clerk-ledger && cargo +nightly actor


# Build the clerk-bridge actor — per-bank cross-clerk voucher
# ingress agent. Verifies + opens vouchers from peer banks,
# dedups by transfer triple, returns the recovered opening to
# the host operator (which then credits the local recipient via
# clerk-ledger).
build-clerk-bridge:
    cd actors/clerk-bridge && cargo +nightly actor


# Build the voucher-check PVM guest — the binary whose traced
# execution IS the witness for a Mode::External voucher proof.
# `start` runs cipher_clerk::voucher::proof::check; zkpvm proves
# the trace, a verifier checks the proof against the program
# commitment. Lives under examples/actors/ (not actors/) because
# it's a guest workload, not a service actor — no Local/Crdt
# replication, no Ref API consumers.
build-voucher-check:
    cd examples/actors/voucher-check && cargo +nightly build --release


# Live cross-node CRDT convergence demo. Spins up two networked
# VosNodes in-process, registers the crdt-counter actor on both
# under the same replication_id, drives one inc on each side,
# and asserts both replicas converge to count=2 (~1.4s
# end-to-end).
demo-crdt-sync: build-crdt-counter
    cargo test -p vos --features network --test elf_integration \
        crdt_counter_converges_across_nodes_live -- --nocapture

# Two-process CRDT demo using real `vosx space up` daemons.
# Each process gets its own isolated XDG state tree (so
# `~/.config/vosx/spaces.toml` doesn't collide between them)
# and reconciles the same crdt-counter agent from
# `examples/space-crdt-{a,b}.toml`. Both manifests' `on_start`
# fires one inc per replica; the EffectLogs hash to distinct
# DAG nodes (different `(origin, seq)` per replica), gossipsub
# carries them to the other side, soft-restart replays both
# logs, and `count=2` shows up on each side once convergence
# completes (~6s end-to-end).
demo-crdt-procs: build-crdt-counter build-crates
    #!/usr/bin/env bash
    set -euo pipefail
    A=/tmp/vosx-a; B=/tmp/vosx-b
    rm -rf $A $B
    mkdir -p $A/{data,config,cache} $B/{data,config,cache}

    echo "→ host A: create space..."
    XDG_DATA_HOME=$A/data XDG_CONFIG_HOME=$A/config XDG_CACHE_HOME=$A/cache \
      ./target/debug/vosx space new --name demo > /dev/null
    SPACE_ID=$(grep -E '^id = ' $A/config/vosx/spaces.toml | head -1 | cut -d'"' -f2)
    echo "  space_id=$SPACE_ID"

    echo "→ host A: starting daemon on :4811, reconciling space-crdt-a.toml..."
    XDG_DATA_HOME=$A/data XDG_CONFIG_HOME=$A/config XDG_CACHE_HOME=$A/cache \
    RUST_LOG=info ./target/debug/vosx space up demo \
        --manifest examples/space-crdt-a.toml \
        --listen /ip4/127.0.0.1/tcp/4811 \
        > /tmp/vosx-a.log 2>&1 &
    PID_A=$!

    # Wait for A's swarm to bind and write its endpoint, then
    # extract the peer-id so B can dial it.
    for _ in $(seq 1 50); do
        [ -f "$A/data/vosx/$SPACE_ID/.endpoint" ] && break
        sleep 0.1
    done
    PEER_A=$(grep peer_id "$A/data/vosx/$SPACE_ID/.endpoint" | cut -d'"' -f2)
    BOOTNODE="/ip4/127.0.0.1/tcp/4811/p2p/$PEER_A"
    echo "  bootnode=$BOOTNODE"

    echo "→ host B: join + start (dials A)..."
    XDG_DATA_HOME=$B/data XDG_CONFIG_HOME=$B/config XDG_CACHE_HOME=$B/cache \
      ./target/debug/vosx space join "$SPACE_ID@$BOOTNODE" --name demo > /dev/null
    XDG_DATA_HOME=$B/data XDG_CONFIG_HOME=$B/config XDG_CACHE_HOME=$B/cache \
    RUST_LOG=info ./target/debug/vosx space up demo \
        --manifest examples/space-crdt-b.toml \
        --connect "$BOOTNODE" \
        > /tmp/vosx-b.log 2>&1 &
    PID_B=$!

    sleep 6
    echo ""
    echo "── host A counter log ─────────────────────────────────────"
    grep "crdt-counter:" /tmp/vosx-a.log || echo "(no actor output)"
    echo ""
    echo "── host B counter log ─────────────────────────────────────"
    grep "crdt-counter:" /tmp/vosx-b.log || echo "(no actor output)"
    echo ""
    echo "→ shutting down..."
    kill $PID_A $PID_B 2>/dev/null || true
    wait $PID_A 2>/dev/null || true
    wait $PID_B 2>/dev/null || true
    echo "done. Full logs in /tmp/vosx-{a,b}.log"

# ── Run ─────────────────────────────────────────────────────────────

# Run a single PVM actor as a one-shot, no space, no networking.
run-actor name="greeter": build-pvm
    cargo run --bin vosx -- run examples/actors/{{name}}/target/riscv64em-javm/release/{{name}}.elf

# ── zkpvm verifier ──────────────────────────────────────────────────

# Host-side no_std build of the verifier surface.  Catches std-only imports
# leaking into the always-compiled path without needing the wasm toolchain.
check-zkpvm-no-std:
    cargo build -p zkpvm --no-default-features
    cargo build -p zkpvm-verifier

# WASM smoke build of zkpvm-verifier.  Currently blocked on an upstream javm
# fix: `pub const CODE_WINDOW_SIZE: usize = 1 << 32` in
# olanod/jar/grey/crates/javm/src/backing.rs overflows on 32-bit usize.
# Until that lands the recipe will fail at javm const-eval; the
# `check-no-std` recipe above is the host-side substitute.
wasm-verifier:
    rustup target add wasm32-unknown-unknown
    cargo build -p zkpvm-verifier --target wasm32-unknown-unknown

# Run the full zkpvm test suite (prover side).
test-zkpvm:
    cargo test -p zkpvm

# Run only the fast zkpvm tests.
test-zkpvm-fast:
    cargo test -p zkpvm --lib --test add64_e2e --test memory --test control_flow

# ── Maintenance ─────────────────────────────────────────────────────

# Remove build artifacts
clean:
    cargo clean
    cd examples && cargo clean 2>/dev/null || true

# Format all code
fmt:
    cargo fmt --all

# Lint with clippy
lint:
    cargo clippy --all-targets -- -D warnings

# Check everything compiles without building artifacts
check:
    cargo check --all-targets

# Run all checks the pre-commit + pre-push hooks run, in one go
verify:
    cargo fmt -- --check
    cargo clippy --workspace -- -D warnings -A clippy::too_many_arguments -A clippy::type_complexity -A clippy::result_unit_err -A clippy::manual_async_fn
    cargo test --workspace --lib
    just build-pvm

# Point git at the in-repo hooks under .githooks/ (idempotent)
install-hooks:
    git config core.hooksPath .githooks
    @echo "✓ git hooks installed (.githooks/pre-commit, .githooks/pre-push)"

# Verify vos-raft builds on representative no_std + alloc embedded
# targets. Catches regressions to the alloc-only code paths
# (anything accidentally pulling in std::collections, std::time,
# etc.) at CI time before a downstream Embassy / firmware user
# breaks. Requires the riscv32imc-unknown-none-elf and
# thumbv7em-none-eabihf rustup targets.
check-no-std:
    cargo build -p vos-raft --no-default-features --target thumbv7em-none-eabihf
    cargo build -p vos-raft --no-default-features --target riscv32imc-unknown-none-elf

# Run cargo-deny across the workspace (license / advisory / bans /
# sources). Requires `cargo install cargo-deny` once. Wire this into
# CI before any release that ships outside the trusted-internal
# bucket — without it, RustSec advisories on hyper / quinn / rustls /
# ring won't get caught.
deny:
    cargo deny --all-features check
