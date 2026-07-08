# Root justfile for vos — build and test orchestration.

# Run recipe bodies with nushell instead of sh.
set shell := ["nu", "-c"]

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
    cargo build -p echo-extension -p proxy-extension -p fetcher-extension -p byte-echo-extension -p tcp-echo-extension

# Build WASM actors (wasm32-unknown-unknown target)
build-wasm:
    cd examples/wasm/echo; cargo build --target wasm32-unknown-unknown --release
    cd examples/wasm/fetcher; cargo build --target wasm32-unknown-unknown --release

# Build all PVM actors and agents (riscv64 targets, requires custom toolchain)
build-pvm:
    cd examples; just build

# Build the on-chain settlement-verifier ELF for the JAM PVM (riscv64em-javm).
# Gates zkpvm's settle_run / settle_transpile tests (they skip if absent).
# Needs the pinned nightly + rust-src (build-std). Regenerate the embedded proof
# fixture first ONLY if the proof format changed:
#   cargo test -p zkpvm --test settle_fixture
build-settle:
    cd zkpvm/settlement-verifier && cargo build --release --target riscv64em-javm.json \
      -Zbuild-std=core,alloc,compiler_builtins \
      -Zbuild-std-features=compiler-builtins-mem \
      --features pvm-settle --bin settle

# Build the host-loaded artifacts the elf_integration e2e needs beyond the
# example PVM actors: the built-in actor ELFs (actors/*), the voucher-check
# guest, and the prover extension .so (debug for the default e2e, release for
# the opt-in real-STARK path). `test-pvm` depends on this, so a vos change can't
# leave a STALE ELF/.so behind — the recurring trap where a stale actor ELF
# surfaces as `register_remote Unreachable` and a stale voucher-check /
# prover .so as a `ProofInvalid`. (Run `just build-actors` by hand if you invoke
# `cargo test` directly instead of through `just test-pvm`.)
build-actors: build-registry build-bridge build-clerk-ledger build-clerk-bridge build-clerk-settle build-voucher-check
    cargo build -p prover-extension
    cargo build -p prover-extension --release

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

# Run the elf_integration e2e against FRESHLY-built artifacts. Depends on the
# full artifact set (workspace + extensions + example PVM actors + built-in
# actor ELFs + prover .so) so a vos change never runs the e2e against a stale
# ELF/.so. This is the safe way to run the e2e; prefer it over a bare
# `cargo test -p vos --test elf_integration`.
test-pvm: build-crates build-extensions build-pvm build-actors
    cargo test -p vos --test elf_integration -- --nocapture

# Run a single test by name
test-one name: build-extensions
    cargo test -p vos {{name}} -- --nocapture

# Build just the crdt-counter actor (cycle-5 example)
build-crdt-counter:
    cd examples/actors/crdt-counter; cargo actor

# Build the space-registry actor — built-in PVM actor that
# lives under actors/ alongside the workspace crates. `cargo actor`
# is the alias defined in each actor's .cargo/config.toml that
# invokes `rustc --crate-type bin -Zbuild-std=…` against the
# riscv64em-javm target spec — produces the executable ELF the
# host bundles. Plain `cargo build --release` silently builds only
# the rlib + dropped cdylib, leaving the ELF stale.
build-registry:
    cd actors/space-registry; cargo +nightly actor

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
    cd actors/space-bridge; cargo +nightly actor


# Build the clerk-ledger actor — per-bank stateful agent
# wrapping cipher-clerk's confidential double-entry kernel.
build-clerk-ledger:
    cd actors/clerk-ledger; cargo +nightly actor


# Build the clerk-bridge actor — per-bank cross-clerk voucher
# ingress agent. Verifies + opens vouchers from peer banks,
# dedups by transfer triple, returns the recovered opening to
# the host operator (which then credits the local recipient via
# clerk-ledger).
build-clerk-bridge:
    cd actors/clerk-bridge; cargo +nightly actor


# Build the clerk-settle actor — the settlement venue agent that
# runs on the third (venue) space. Registers banks, accepts signed
# net-flow claims, and reconciles a window's two claims (their
# Pedersen commitments must cancel). Same toolchain as the other
# clerk actors.
build-clerk-settle:
    cd actors/clerk-settle; cargo +nightly actor


# Build the voucher-check PVM guest — the binary whose traced
# execution IS the witness for a Mode::External voucher proof.
# `start` runs cipher_clerk::voucher::proof::check; zkpvm proves
# the trace, a verifier checks the proof against the program
# commitment. Lives under examples/actors/ (not actors/) because
# it's a guest workload, not a service actor — no Local/Crdt
# replication, no Ref API consumers.
build-voucher-check:
    cd examples/actors/voucher-check; cargo +nightly build --release


# Build the per-channel messaging actors — msg-log (crdt-mode
# ciphertext envelope log) + msg-ctl (sequenced MLS commit chain).
# Same toolchain as the registry.
build-msg-actors:
    cd actors/msg-log; cargo +nightly actor
    cd actors/msg-ctl; cargo +nightly actor
    cd actors/msg-directory; cargo +nightly actor

# Build the messenger PVM actor (the device-local E2EE edge): the
# deterministic no_std mls-rs riscv64 build whose ELF the `link_elf`
# transpile gate (cargo test -p vos --test messenger_transpile) checks.
build-messenger-actor:
    cd actors/messenger; cargo +nightly actor

# Build the chronos actor — the public clock + verifiable-randomness
# service plane (the generalized beacon). Standalone (not
# messaging-private); installed per space via manifest.
build-chronos:
    cd actors/chronos; cargo +nightly actor


# Live cross-node CRDT convergence demo. Spins up two networked
# VosNodes in-process, registers the crdt-counter actor on both
# under the same replication_id, drives one inc on each side,
# and asserts both replicas converge to count=2 (~1.4s
# end-to-end).
demo-crdt-sync: build-crdt-counter
    cargo test -p vos --features network --test elf_integration \
        crdt_counter_converges_across_nodes_live -- --nocapture

# Two-process CRDT demo: two real `vosx space up` daemons (isolated XDG trees)
# reconcile the same crdt-counter agent; one inc per replica gossips across and
# both converge to count=2 (~6s). Daemons run as nu jobs, torn down via try/catch.
demo-crdt-procs: build-crdt-counter build-crates
    #!/usr/bin/env nu
    def vx [e, a: list] { with-env $e { ^./target/debug/vosx ...$a } }
    def peerid [f] { open --raw $f | lines | where ($it | str contains "peer_id") | first | str replace -r "^.*peer_id = .([^\"]*).*$" "$1" }
    def xdg [d] { { XDG_DATA_HOME: $"($d)/data", XDG_CONFIG_HOME: $"($d)/config", XDG_CACHE_HOME: $"($d)/cache" } }
    def wait-bind [f] { for _ in 1..50 { if ($f | path exists) { break }; sleep 100ms } }

    let A = "/tmp/vosx-a"
    let B = "/tmp/vosx-b"
    let ea = (xdg $A)
    let eb = (xdg $B)
    rm -rf $A $B
    mkdir $"($A)/data" $"($A)/config" $"($A)/cache" $"($B)/data" $"($B)/config" $"($B)/cache"

    print "→ host A: create space..."
    vx $ea [space new --name demo] | ignore
    let space_id = (open --raw $"($A)/config/vosx/spaces.toml" | lines | where ($it | str starts-with "id = ") | first | str replace -r "^id = .(.*).$" "$1")
    print $"  space_id=($space_id)"

    print "→ host A: starting daemon on :4811..."
    let job_a = (job spawn { with-env ($ea | merge { RUST_LOG: "info" }) {
        ^./target/debug/vosx space up demo --manifest examples/space-crdt-a.toml --listen /ip4/127.0.0.1/tcp/4811 out+err> /tmp/vosx-a.log
    } })

    let ep_a = $"($A)/data/vosx/($space_id)/.endpoint"
    wait-bind $ep_a
    let bootnode = $"/ip4/127.0.0.1/tcp/4811/p2p/(peerid $ep_a)"
    print $"  bootnode=($bootnode)"

    print "→ host B: join + start (dials A)..."
    vx $eb [space join $"($space_id)@($bootnode)" --name demo] | ignore
    let job_b = (job spawn { with-env ($eb | merge { RUST_LOG: "info" }) {
        ^./target/debug/vosx space up demo --manifest examples/space-crdt-b.toml --connect $bootnode out+err> /tmp/vosx-b.log
    } })

    sleep 6sec
    print "\n── host A counter log ─────────────────────────────────────"
    try { ^grep "crdt-counter:" /tmp/vosx-a.log } catch { print "(no actor output)" }
    print "\n── host B counter log ─────────────────────────────────────"
    try { ^grep "crdt-counter:" /tmp/vosx-b.log } catch { print "(no actor output)" }
    print "\n→ shutting down..."
    try { job kill $job_a }
    try { job kill $job_b }
    print "done. Full logs in /tmp/vosx-{a,b}.log"

# Two-process E2EE messaging demo: alice (host A) creates the "general" channel,
# invites bob (host B), and they exchange messages through the replicated
# ciphertext log while every actor-visible byte stays MLS-encrypted (~20s).
# Daemons run as nu jobs, torn down via try/catch.
demo-msg-procs: build-msg-actors build-chronos build-messenger-actor build-crates
    #!/usr/bin/env nu
    def vx [e, a: list] { with-env $e { ^./target/debug/vosx ...$a } }
    def peerid [f] { open --raw $f | lines | where ($it | str contains "peer_id") | first | str replace -r "^.*peer_id = .([^\"]*).*$" "$1" }
    def xdg [d] { { XDG_DATA_HOME: $"($d)/data", XDG_CONFIG_HOME: $"($d)/config", XDG_CACHE_HOME: $"($d)/cache" } }
    def wait-bind [f] { for _ in 1..50 { if ($f | path exists) { break }; sleep 100ms } }

    let A = "/tmp/vosx-msg-a"
    let B = "/tmp/vosx-msg-b"
    let ea = (xdg $A)
    let eb = (xdg $B)
    rm -rf $A $B
    mkdir $"($A)/data" $"($A)/config" $"($A)/cache" $"($B)/data" $"($B)/config" $"($B)/cache"

    print "→ host A: create space..."
    vx $ea [space new --name msg-demo] | ignore
    let space_id = (open --raw $"($A)/config/vosx/spaces.toml" | lines | where ($it | str starts-with "id = ") | first | str replace -r "^id = .(.*).$" "$1")

    print "→ host A: starting daemon on :4821..."
    let job_a = (job spawn { with-env ($ea | merge { RUST_LOG: "info" }) {
        ^./target/debug/vosx space up msg-demo --manifest examples/space-msg-a.toml --listen /ip4/127.0.0.1/tcp/4821 out+err> /tmp/vosx-msg-a.log
    } })
    let ep_a = $"($A)/data/vosx/($space_id)/.endpoint"
    wait-bind $ep_a
    let bootnode = $"/ip4/127.0.0.1/tcp/4821/p2p/(peerid $ep_a)"

    print "→ host B: join + start (dials A)..."
    vx $eb [space join $"($space_id)@($bootnode)" --name msg-demo] | ignore
    let job_b = (job spawn { with-env ($eb | merge { RUST_LOG: "info" }) {
        ^./target/debug/vosx space up msg-demo --manifest examples/space-msg-b.toml --connect $bootnode out+err> /tmp/vosx-msg-b.log
    } })
    sleep 3sec

    print "→ alice: register + create channel..."
    vx $ea [messenger register --space msg-demo nickname=alice]
    vx $ea [messenger create --space msg-demo channel=general]
    print "→ alice: grant peers the member tier + enroll host B as a raft voter..."
    let peer_b = (vx $eb [whoami] | lines | where ($it | str starts-with "peer_id = ") | first | str replace -r "^peer_id = " "")
    vx $ea [space role msg-demo grant $peer_b read]
    let peer_b_node = (peerid $"($B)/data/vosx/($space_id)/.endpoint")
    vx $ea [space members msg-demo add-node $peer_b_node]
    # Forwarded raft writes carry the forwarding NODE's peer, so both
    # daemons' node peers need the member tier.
    vx $ea [space role msg-demo grant $peer_b_node read]
    vx $ea [space role msg-demo grant (peerid $ep_a) read]
    print "→ waiting for host B to join the raft groups..."
    for _ in 1..60 {
        let log = (try { open --raw /tmp/vosx-msg-b.log } catch { "" })
        if (($log | str contains "agent 'msg-directory' spawned at runtime") and ($log | str contains "agent 'msg-general-ctl' spawned at runtime")) { break }
        sleep 500ms
    }
    print "→ bob: register + join..."
    vx $eb [messenger register --space msg-demo nickname=bob]
    vx $eb [messenger join --space msg-demo channel=general]
    print "→ alice: invite bob + send..."
    vx $ea [messenger invite --space msg-demo channel=general member=bob]
    vx $ea [messenger send --space msg-demo channel=general "text=hello bob, this never leaves our devices in the clear"]
    sleep 5sec
    print "→ bob: reply..."
    vx $eb [messenger send --space msg-demo channel=general "text=hi alice, received over ciphertext-only replication"]
    sleep 5sec

    print "\n── alice's view ───────────────────────────────────────────"
    try { vx $ea [messenger history --space msg-demo channel=general limit=10] }
    print "── bob's view ─────────────────────────────────────────────"
    try { vx $eb [messenger history --space msg-demo channel=general limit=10] }
    print "→ shutting down..."
    try { job kill $job_a }
    try { job kill $job_b }
    print "done. Full logs in /tmp/vosx-msg-{a,b}.log"

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

# Run the proving benchmarks (measurement harness, NOT part of `cargo test`).
# Runs serially, so a large trace never contends for RAM with another. Pass a
# name substring to select specific benches (e.g. `just bench log16`).
bench filter="":
    cargo bench -p zkpvm --bench prove -- {{filter}}

# ── Maintenance ─────────────────────────────────────────────────────

# Remove build artifacts
clean:
    cargo clean
    try { cd examples; cargo clean } catch { }

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
