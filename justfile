# Root justfile for kunekt — build and test orchestration.

# Default: list available recipes
default:
    @just --list

# ── Build ───────────────────────────────────────────────────────────

# Build everything: crates, workers, PVM actors, agents
build: build-crates build-workers build-pvm

# Build the workspace (vos, vosx, etc.)
build-crates:
    cargo build

# Build native worker plugins (.so files)
build-workers:
    cargo build -p echo-worker -p proxy-worker -p fetcher-worker

# Build WASM actors (wasm32-unknown-unknown target)
build-wasm:
    cd examples/wasm/echo && cargo build --target wasm32-unknown-unknown --release
    cd examples/wasm/fetcher && cargo build --target wasm32-unknown-unknown --release

# Build all PVM actors and agents (riscv64 targets, requires custom toolchain)
build-pvm:
    cd examples && just build

# ── Test ────────────────────────────────────────────────────────────

# Run all tests (workspace + integration)
test: build-workers
    cargo test --all

# Run only worker tests
test-workers: build-workers
    cargo test -p vos worker -- --nocapture

# Smoke test the WASM actors in Node
test-wasm: build-wasm
    node examples/wasm/js/test.mjs
    node examples/wasm/js/test-fetch.mjs
    node examples/wasm/js/test-persist.mjs

# Run PVM-related integration tests (requires built PVM actors)
test-pvm: build-workers
    cargo test -p vos --test elf_integration -- --nocapture

# Run a single test by name
test-one name: build-workers
    cargo test -p vos {{name}} -- --nocapture

# Build just the crdt-counter actor (cycle-5 example)
build-crdt-counter:
    cd examples/actors/crdt-counter && cargo +nightly -Zjson-target-spec build --release

# Build the hyperspace registry actor (cycle-9, first-class — lives
# under actors/ rather than examples/)
build-registry:
    cd actors/registry && cargo +nightly -Zjson-target-spec build --release

# Live cross-node CRDT convergence demo. Spins up two networked
# VosNodes in-process, registers the crdt-counter actor on both
# under the same replication_id, drives one inc on each side,
# and asserts both replicas converge to count=2 (~1.4s
# end-to-end).
demo-crdt-sync: build-crdt-counter
    cargo test -p vos --features network --test elf_integration \
        crdt_counter_converges_across_nodes_live -- --nocapture

# Two-process CRDT demo using real `vosx start` instances. Each
# process owns its own data dir + libp2p identity; both run the
# crdt-counter actor under the same replication_id (auto-derived
# from blob+name). On startup each side fires `inc(tag=N)` with
# N differing per host so the two EffectLogs hash to distinct
# DAG nodes. Cycle-3 sync pulls each replica's node into the
# other's redb; cycle-4 soft restart replays both logs; the
# println in the actor reports `count=2` on each side once
# convergence completes.
demo-crdt-procs: build-crdt-counter build-crates
    #!/usr/bin/env bash
    set -euo pipefail
    rm -rf /tmp/vosx-a /tmp/vosx-b
    mkdir -p /tmp/vosx-a /tmp/vosx-b
    echo "→ starting host A (listens on :4811)..."
    RUST_LOG=info ./target/debug/vosx start examples/space-crdt-a.toml \
        --data-dir /tmp/vosx-a --listen /ip4/127.0.0.1/tcp/4811 \
        > /tmp/vosx-a.log 2>&1 &
    PID_A=$!
    sleep 1
    echo "→ starting host B (dials A)..."
    RUST_LOG=info ./target/debug/vosx start examples/space-crdt-b.toml \
        --data-dir /tmp/vosx-b --connect /ip4/127.0.0.1/tcp/4811 \
        > /tmp/vosx-b.log 2>&1 &
    PID_B=$!
    sleep 6
    echo ""
    echo "── host A inc log ─────────────────────────────────────────"
    grep "crdt-counter:" /tmp/vosx-a.log || echo "(no actor output)"
    echo ""
    echo "── host B inc log ─────────────────────────────────────────"
    grep "crdt-counter:" /tmp/vosx-b.log || echo "(no actor output)"
    echo ""
    echo "→ shutting down..."
    kill $PID_A $PID_B 2>/dev/null || true
    wait $PID_A 2>/dev/null || true
    wait $PID_B 2>/dev/null || true
    echo "done. Full logs in /tmp/vosx-{a,b}.log"

# ── Run ─────────────────────────────────────────────────────────────

# Run vosx with the example space manifest
run-manifest: build build-pvm
    cargo run --bin vosx -- start examples/space.toml --no-persist

# Run a single PVM actor
run-actor name="greeter": build-pvm
    cargo run --bin vosx -- run examples/actors/{{name}}/target/riscv64em-javm/release/{{name}}.elf

# Run a worker standalone
run-worker name="echo": build-workers
    cargo run --bin vosx -- node --worker target/debug/lib{{name}}_worker.so

# Run two workers together (proxy can ask echo)
run-workers: build-workers
    cargo run --bin vosx -- node \
        --worker target/debug/libecho_worker.so \
        --worker target/debug/libproxy_worker.so

# List metadata of actors in a manifest
list manifest="examples/space.toml": build-pvm
    cargo run --bin vosx -- list {{manifest}}

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
