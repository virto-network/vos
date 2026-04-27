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
