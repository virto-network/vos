# Kunekt

A protocol for decentralized, private, real-time collaboration.

## What it does

Kunekt lets groups of people work together on shared documents, chat, and data
without relying on a central server. Everything is encrypted so only group members
can read the content. Participants can be online, offline, or on flaky connections
and the system just works — everyone converges to the same state when they sync.

## How it works

A **space** is a private collaboration group. Inside a space, all shared content
is represented as **documents** — text, messages, settings, even the space structure
itself. Each document is a CRDT (a data structure that merges concurrent edits
without conflicts).

The protocol has three layers:

1. **Sync** — Changes propagate between peers using
   [Merkle-CRDTs](https://arxiv.org/abs/2004.00107). Each edit is recorded in a
   hash-linked DAG that acts as a logical clock. Peers exchange a single hash
   (root CID) to discover what's new and fetch only what they're missing. No leader
   election, no consensus, no coordination — any peer can sync with any other peer
   over any transport.

2. **Encryption** — All document content is encrypted using group ratchet keys
   (MLS/Megolm). Only space members can decrypt. Keys rotate automatically on
   membership changes. New members cannot read history from before they joined
   (forward secrecy). Anyone relaying or storing the data sees only opaque blobs.

3. **Persistence** — Encrypted DAG nodes can be stored on any available backend
   (a cloud relay, a DHT, a local database, a blockchain data-availability layer)
   to survive all peers going offline. The storage backend doesn't need to be
   trusted since it only ever sees encrypted, content-addressed data it cannot
   tamper with.

## Design goals

- **No servers** — peers connect directly, relay through untrusted infrastructure,
  or sync via any transport available
- **No coordination** — no leader, no consensus rounds, no single point of failure
- **Private by default** — end-to-end encrypted at the group level, storage and
  relay nodes see nothing
- **Offline-first** — full local editing, seamless merge on reconnect
- **Transport-agnostic** — works over WebRTC, libp2p, Bluetooth, USB, or anything
  that can carry bytes
- **Document-everything** — messages, files, config, access control are all
  documents (CRDTs) linked together

## Architecture

```
┌─────────────────────────────────────────────┐
│                   Space                      │
│                                              │
│  ┌──────────┐ ┌──────────┐ ┌──────────┐     │
│  │ Doc A    │ │ Doc B    │ │ Doc C    │ ... │
│  │ (CRDT)   │ │ (CRDT)   │ │ (CRDT)   │     │
│  └────┬─────┘ └────┬─────┘ └────┬─────┘     │
│       └─────────┬──┴────────────┘            │
│           Merkle-CRDT sync layer             │
│       ┌─────────┴──────────┐                 │
│       │  MLS group keys    │                 │
│       │  (encrypt/decrypt) │                 │
│       └─────────┬──────────┘                 │
└─────────────────┼───────────────────────────┘
                  │ encrypted DAG nodes
    ┌─────────────┼─────────────┐
    ↓             ↓             ↓
 Peer A        Peer B     Storage backend
 (local)      (direct)    (relay/DHT/DA)
```

## Building blocks

| Component | Purpose | Candidate |
|---|---|---|
| Document CRDTs | Conflict-free editing | [automerge](https://automerge.org) |
| Sync layer | Merkle-DAG clock + anti-entropy | [merkle-crdt](../merkle-crdt) |
| Group encryption | Forward-secret group keys | [OpenMLS](https://github.com/openmls/openmls) |
| Peer transport | Connecting browsers and devices | libp2p, WebRTC |
| Persistent storage | Survive all-offline | Any content-addressed store |

## Trying it out

This repo includes **VOS**, a working actor runtime, and `vosx`, the
operator-facing CLI. Actors are written as ordinary Rust, compiled
to a JAM-aligned PVM (RISC-V) target, and run inside a deterministic
host so two replicas of the same actor under the same `replication_id`
converge automatically.

`vosx` has two commands: `vosx run <elf>` for raw one-shot PVM
execution, and `vosx space *` for everything space-related. A space
is a per-collaboration root identified by a content-addressed
`space_id` (= `blake2b("vos-space-id/v1" || genesis_dag_root)`).

Quick start:

```bash
# Create a space. Generates per-space identity, runs the bundled
# space-registry briefly to commit a genesis CrdtEvent, derives
# space_id from the resulting DAG root.
vosx space new --name demo

# Run the daemon. Owns the redb, listens on libp2p (auto-port
# loopback by default; pass --listen for a routable addr).
# `--manifest` reconciles a TOML into the registry on startup
# (publishes blobs, installs agents, fires their `on_start`).
vosx space up demo --manifest examples/space-crdt-a.toml &

# Talk to it. `space call` is the floor primitive — any agent,
# any handler. `space publish/install/agents/etc.` are typed
# sugar on top.
vosx space call demo counter inc
vosx space agents demo
vosx space info demo                    # metadata + daemon liveness + RTT
vosx space export demo > snapshot.toml  # round-trip back to TOML
```

Two-process CRDT convergence demo (one shell):

```bash
just demo-crdt-procs   # creates + dials two daemons, both reach count=2
just demo-crdt-sync    # in-process variant, no separate processes
```

### Consistency modes

Each `[[agent]]` in a manifest picks a `consistency` mode:

| Mode | Replication | Read-from-any-replica | Writes block on |
|---|---|---|---|
| `ephemeral` | none, in-memory | n/a | nothing |
| `local` | redb on local disk | n/a | local fsync |
| `crdt` | merkle-CRDT, eventual | yes | local commit |
| `raft` | Raft consensus, strict | leader only (today) | quorum ack |

CRDT fits commutative state (counters, sets, LWW maps,
append-only logs) where reads-from-anywhere matter. Raft fits
strictly sequenced state where divergence corrupts (ledgers,
unique-name registries). Modes mix freely per-agent.

Raft requires a cluster membership list (every replica's
`node_prefix`). See `examples/space-raft.toml`.

```bash
cargo test --all -- --test-threads=1   # full integration suite
```

### Multi-node

```bash
# host A
vosx space new --name a
vosx space up a --manifest space-crdt-a.toml --listen /ip4/0.0.0.0/tcp/4811 &
vosx space info a            # prints the bootnode hint:
                             #   <space_id>@/ip4/.../tcp/4811/p2p/<peer-id>

# host B (paste the bootnode hint)
vosx space join "<bootnode-hint>" --name b
vosx space up b --manifest space-crdt-b.toml --connect /ip4/.../tcp/4811/p2p/<peer-id> &
```

The TOML manifest is a devhelper, not the runtime source of
truth — the registry is. `space export` re-derives a manifest
from the live registry; `space up --manifest` is idempotent
reconciliation.

### Writing an actor

```rust
use vos::prelude::*;

#[actor]
pub struct Counter { count: u64 }

#[messages]
impl Counter {
    fn new() -> Self { Counter { count: 0 } }

    #[msg]
    async fn inc(&mut self) { self.count += 1; }

    #[msg]
    async fn get(&self) -> u64 { self.count }
}
```

`#[actor]` emits the PVM `_start` / `accumulate` entry points.
`#[messages]` generates the per-handler message types and a
typed `CounterRef` for host-side calls:

```rust
use vos::node::{AgentConfig, VosNode};
use counter::CounterRef;

let mut node = VosNode::new();
let id = node.register(AgentConfig::new(blob));
let counter = CounterRef::at(id);
vos::block_on(counter.inc(&mut &node))?;
let n = vos::block_on(counter.get(&mut &node))?;
```

Compile with the `riscv64em-javm` target — see
`examples/actors/counter/.cargo/config.toml`.

### Development

Install the in-repo git hooks once after cloning:

```bash
just install-hooks
```

This points `core.hooksPath` at `.githooks/`. Pre-commit gates on
`cargo fmt --check`, `cargo clippy -D warnings`, and `vosx`'s unit
tests; pre-push runs the full workspace test suite and `just build-pvm`
(which also re-asserts the multi-target Cargo warning stays silenced).
Run everything by hand with `just verify`.
