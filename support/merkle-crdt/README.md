# merkle-crdt

Several replicas edit the same data, often offline, and must end up equal
with no server deciding who wins. This crate is a `no_std` replica for
operation-based Merkle-CRDTs, after Sanjuán et al. (below): it keeps the
edits as a DAG of signed nodes, the way git keeps commits, and applies each
to your data after the edits it follows; your CRDT makes every order of
concurrent edits end equal. The storage and the network are yours.

## When to use it

Use it when many writers edit one data set, offline or not, and nodes may
pass relays you do not trust and arrive in any order (within bounds, below).
Not for a single
writer (a log is simpler), nor where writers need one total order or a check
across them (balances, unique names: a log or consensus), nor for large blobs
(store them apart and put their hashes in the operations).

## How it works

```text
  alice   a0 <-- a1 <-- a2
                       /
  bob     b0 <-- b1 <-- b2          x <-- y : y names x as a parent
```

- A **node** is a batch of operations by one **author** (an ed25519 key).
  Its **CID** is the hash of its bytes; it names its **parents** by CID, the
  nodes its author had seen (alice wrote `a2` after seeing `b1`).
- The **heads** are the nodes no node names (`a2`, `b2`). A new node names
  the heads, so a node written after seeing both is the only head.
- An author's nodes form a numbered **chain**, each naming the one before.
  Two at one number are an **equivocation**: kept, and reported so your
  reads can filter that author.
- A `Replica` applies each node once, after all its parents, and **holds** a
  node whose parents have not arrived (`b2` before `b1`).
- What a node does to your data is your **`Apply`**, a CRDT over rows.
  Concurrent nodes (`a2`, `b2`) arrive in different orders at different
  replicas, so its result must not depend on the order.

## Compared with git

| | git | merkle-crdt |
|---|---|---|
| a unit | a commit: content-addressed, names its parents | a node: the same, holding operations instead of a snapshot |
| the tips | branch tips | heads, unnamed |
| concurrent work | a merge commit, conflicts resolved by hand | nothing to resolve: the CRDT gives one state for every order |
| who wrote it | an optional signature | every node signed and numbered in its author's chain; a fork of a chain is an equivocation |
| fetching | parents first, from one remote | from anyone, in any order within the held bounds: a node waits for its parents |
| the state | a snapshot checked out | applied node by node into a store, one atomic commit a batch |
| history | rewritable (rebase, force push) | only grows |

## Using it

1. Pick a `Hasher` for the CIDs; write an `Apply` over an `Event` and `Rows`.
2. Implement `Store` over your database (point reads, `load` at open, one
   atomic and durable `commit`), or take `MemStore` for tests.
3. `record` local operations; send `outbox()`'s bytes and mark them `pushed`.
4. `ingest` what arrives, in any batching, with its feed position; `wanted()`,
   `have()` and `cursor()` say what to fetch next.

```rust
use blake2::{Blake2b, Digest, digest::consts::U32};
use ed25519_dalek::SigningKey;
use merkle_crdt::{Event, Hasher, MemStore, Replica, Rows, Scope};

struct Blake2b256;
impl Hasher for Blake2b256 {
    type Output = [u8; 32];
    fn hash(data: &[u8]) -> [u8; 32] { Blake2b::<U32>::digest(data).into() }
}

// A grow-only set of strings, one row an element.
fn add(event: Event<'_, Blake2b256, String>, rows: &mut dyn Rows) {
    rows.write(event.ops.as_bytes(), Some(&[]));
}

let open = || Replica::<Blake2b256, String, _>::open(MemStore::new(), Scope([1; 16])).unwrap();
let (mut phone, mut laptop) = (open(), open());
// Offline, each records an operation.
phone.record(&SigningKey::from_bytes(&[1; 32]), "eggs".into(), &mut add).unwrap();
laptop.record(&SigningKey::from_bytes(&[2; 32]), "milk".into(), &mut add).unwrap();
// Online, each ingests the other's outbox.
let to_laptop = phone.outbox().unwrap().into_iter().map(|node| node.bytes);
laptop.ingest(to_laptop, None, &mut add).unwrap();
let to_phone = laptop.outbox().unwrap().into_iter().map(|node| node.bytes);
phone.ingest(to_phone, None, &mut add).unwrap();
assert_eq!(phone.store().rows(), laptop.store().rows());
assert_eq!(phone.heads(), laptop.heads());
```

## Guarantees and limits

It promises: each node applied once, after its parents; one atomic commit of
nodes and rows for each `ingest` or `record`; forged, malformed or
chain-breaking nodes refused with their descendants, alike everywhere;
equivocations kept and reported; bounded cost (64 parents a node, 4096 held).

It leaves to you: who may write (any key that signs is an author: check
authors before `ingest`); the transport; your CRDT's convergence (no
dependence on order, nor on which of two equivocating nodes is flagged;
never failing on a peer's content); and a history that only grows (no
compaction yet). Past the held bounds a node is dropped and must come again:
fetch a long gap oldest first, or deliver it in one batch (see `MAX_HELD`).

## The paper and the tests

After *Merkle-CRDTs: Merkle-DAGs meet CRDTs* (Sanjuán et al., 2020,
[arXiv:2004.00107](https://arxiv.org/abs/2004.00107)): its DAG of operations
applied in causal order, with nodes signed and numbered by their author
added, and fetching and announcing left to the caller. Its "children" are
the parents here, its "roots" the heads.

`cargo test -p merkle-crdt` checks the replica against a full replay over
random DAGs, orders, duplicates and batchings, within the held bounds and past
them; `cargo bench -p merkle-crdt --bench apply` times it on 1k to 1M operations.
