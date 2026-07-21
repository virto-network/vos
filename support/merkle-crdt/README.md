# merkle-crdt

Sync shared data between devices without a central server or leader.

## The problem

When multiple devices or users edit the same data (a document, a shopping list, a database),
someone needs to decide the order of changes. Traditional approaches elect a "leader" to
collect and order everyone's edits — but the leader is a bottleneck, requires reliable
connectivity, and if it goes down the whole system stalls.

## The solution

This crate implements [Merkle-CRDTs](https://arxiv.org/abs/2004.00107), which eliminate the
need for a leader entirely. Every participant keeps their own copy and edits freely — even
offline. When two participants reconnect, they sync by exchanging a single hash (a "root CID")
and fetching only what they're missing. When the payload itself has CRDT merge
semantics, replicas converge to the same state regardless of sync order,
timing, or network topology.

This works because of two ideas combined:

- **CRDTs** (Conflict-free Replicated Data Types) — data structures designed so that concurrent
  edits always merge cleanly without conflicts.
- **Merkle-DAGs** (hash-linked graphs) — every edit is hashed and linked to previous edits,
creating a content-authenticated history where you can efficiently find what's
new.

The hash-linked history acts as a logical clock that replaces version vectors
for causal synchronization. It does not make an arbitrary payload convergent:
`Payload::apply` must still implement a CRDT operation or a state join whose
result is independent of delivery order. Applications that need uniqueness,
overdraft prevention, or irreversible global ordering still need consensus or
a purpose-built conflict-free construction.

## Properties

- **No leader, no coordination** — every replica is equal, edits locally, syncs when convenient
- **Works over any transport** — TCP, UDP, Bluetooth, USB stick, carrier pigeon
- **Content-authenticated** — fetched nodes are rejected when their bytes do
  not match the advertised CID; an application validator must separately
  authenticate authors and payload policy
- **Efficient sync** — only missing pieces are transferred, shared history is skipped
- **`no_std`** — runs on embedded devices, WASM, or servers with zero required dependencies

## Quick example

```rust
use merkle_crdt::*;

// Define what an "edit" looks like
#[derive(Clone, Debug)]
struct AddItem(String);

impl Encode for AddItem {
    fn encode_to(&self, buf: &mut Vec<u8>) { self.0.encode_to(buf); }
}

impl Payload for AddItem {
    type State = std::collections::BTreeSet<String>;
    fn apply(state: &mut Self::State, op: &Self) { state.insert(op.0.clone()); }
}

// Two devices working independently
let mut phone: MerkleCrdt<MyHasher, AddItem, MemStore<_, _>> = MerkleCrdt::default();
let mut laptop: MerkleCrdt<MyHasher, AddItem, MemStore<_, _>> = MerkleCrdt::default();

phone.apply(AddItem("eggs".into())).unwrap();
laptop.apply(AddItem("milk".into())).unwrap();

// Later, they sync (in any order, any number of times)
for root in phone.roots().clone() { laptop.sync(&root, phone.store()).unwrap(); }
for root in laptop.roots().clone() { phone.sync(&root, laptop.store()).unwrap(); }

// Both have the same list: {"eggs", "milk"}
assert_eq!(phone.state(), laptop.state());
```

## Use cases

- **P2P collaboration** — real-time document editing without a central server
- **Offline-first apps** — edit while disconnected, sync seamlessly when back online
- **IoT networks** — sensor data from devices that connect intermittently
- **Distributed databases** — replicated key-value stores across data centers
- **Encrypted group sync** — combine with MLS/Megolm for private collaborative spaces

## Crate structure

| Trait / Type | Role |
|---|---|
| `Hasher` | Pluggable hash function (SHA-256, BLAKE3, etc.) |
| `Encode` | Deterministic serialization for content addressing |
| `Store` | Where nodes live (memory, disk, IPFS, network) |
| `Payload` | Your convergent CRDT operation or state join |
| `MerkleClock` | Low-level DAG clock — tracks roots, records events, merges |
| `MerkleCrdt` | High-level wrapper — clock + store + automatic state tracking |
| `sync::fetch_missing` | Anti-entropy algorithm — find and fetch what's missing |

## Based on

> H. Sanjuán, S. Pöyhtäri, P. Teixeira, I. Psaras.
> *"Merkle-CRDTs: Merkle-DAGs meet CRDTs"*, 2020.
> [arXiv:2004.00107](https://arxiv.org/abs/2004.00107)

License: MIT OR Apache-2.0
