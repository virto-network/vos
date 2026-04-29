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

This repo includes **VOS**, a working actor runtime that implements the
sync + persistence layers. Actors are written as ordinary Rust, compiled
to a JAM-aligned PVM (RISC-V) target, and run inside a deterministic
host so two replicas of the same actor under the same `replication_id`
converge automatically.

The `vosx` CLI is the operator-facing entry point. Recipes are in
`justfile`; run `just --list` to see them all. The fastest demos:

```bash
# Run the example space (scheduler + greeter + counter + fizzbuzz)
just run-manifest

# Live cross-node CRDT convergence demo. Two `vosx start` processes
# join the same hyperspace, each fires `inc()` on its local replica,
# both converge to count=2 within a couple of sync ticks.
just demo-crdt-procs

# In-process two-node convergence test (faster, no separate processes)
just demo-crdt-sync
```

The full integration suite (32 tests covering agent dispatch, CRDT
replication, registry sync, restart determinism, panic recovery, and
cold-bootstrap catch-up) runs with:

```bash
cargo test --all -- --test-threads=1
```

`vosx status [<manifest>] --connect <multiaddr>` joins a running
hyperspace as a transient peer and prints the local identity, connected
peers, and the registry's contents. `vosx invoke <name> <msg>
[--arg k=v]` sends a typed message to any actor by name.

### Writing an actor

Actors are normal Rust:

```rust
use vos::{actor, messages};
use vos::{print, println};  // guest println!, panic-propagating

#[actor]
pub struct Counter { count: u64 }

#[messages]
impl Counter {
    fn new() -> Self { Counter { count: 0 } }

    #[msg]
    async fn inc(&mut self, tag: u32) { self.count += 1; }

    #[msg]
    async fn get(&self) -> u64 { self.count }
}

vos::pvm_main!(Counter);  // emits PVM `_start` / `accumulate`
```

Compile with the riscv64em-javm target (see
`examples/actors/crdt-counter/.cargo/config.toml`), declare in a
manifest, and `vosx start space.toml`. Hosts get a typed
`CounterClient` for free via `#[messages]`:

```rust
use vos::node::{AgentConfig, VosNode};
use crdt_counter::CrdtCounterClient;

let mut node = VosNode::new();
let id = node.register(AgentConfig::new(blob));
let counter = CrdtCounterClient::at(&node, id);
counter.inc(1)?;
counter.inc(2)?;
assert_eq!(counter.get()?, 2);
```
