# Sync Layer: Merkle-CRDTs

The sync layer is responsible for propagating changes between peers without
any coordination. It is built on
[Merkle-CRDTs](https://arxiv.org/abs/2004.00107) — the combination of
CRDTs with Merkle-DAGs. This is the foundational layer of Kunekt: every
document, every chat message, every configuration change flows through it.

---

## 1. Merkle-CRDTs Explained

### What is a Merkle-DAG?

A Merkle-DAG (directed acyclic graph) is a data structure where each node
is identified by the cryptographic hash of its contents, and nodes reference
their predecessors by hash. This is the same principle behind Git commits
and IPFS blocks. Two properties follow directly:

- **Self-verifying.** Given a node's data, anyone can recompute its hash
  and confirm the data has not been tampered with.
- **Structural sharing.** If two peers independently produce the same
  content, the resulting nodes have the same hash. Identical subgraphs are
  automatically deduplicated.

### How CRDTs and Merkle-DAGs combine

A CRDT (Conflict-free Replicated Data Type) is a data structure whose
replicas can be updated independently and merged without conflicts.
Operation-based CRDTs model mutations as a stream of operations. Each
operation must eventually reach every replica; the order of arrival does
not matter as long as the CRDT's merge function is commutative, associative,
and idempotent.

A Merkle-CRDT embeds each CRDT operation as the payload of a Merkle-DAG
node. The DAG structure records causal history: when you create a node,
its children field points to the current DAG roots (the "heads"), capturing
everything you have seen so far. This produces a partial order of
operations that respects causality without requiring any centralized
sequencer.

### The DAG as a logical clock

In traditional distributed systems, version vectors or Lamport timestamps
track causality. Merkle-CRDTs replace these mechanisms entirely: the DAG
*is* the logical clock.

- The set of current root CIDs is equivalent to a version vector — it
  summarizes everything a peer has observed.
- Comparing two peers' root sets reveals whether they are in sync,
  whether one is ahead of the other, or whether they have diverged.
- No per-peer state needs to be maintained. A peer that has been offline
  for months can rejoin and sync by exchanging roots with anyone.

### Why merge is commutative, associative, and idempotent

Merging two Merkle-CRDTs is set union of their DAG nodes. Set union has
all three properties by definition:

- **Commutative:** `A ∪ B = B ∪ A` — it does not matter who syncs first.
- **Associative:** `(A ∪ B) ∪ C = A ∪ (B ∪ C)` — multi-peer sync can
  happen in any grouping.
- **Idempotent:** `A ∪ A = A` — receiving the same node twice is a no-op.

These guarantees mean there is no coordination needed between peers, no
leader election, no consensus protocol, and no ordering service. Any peer
can sync with any other peer in any order, and all peers converge.

---

## 2. DAG Node Structure

Each node in the DAG has a fixed structure:

```
DagNode {
    payload:  Payload,       // The CRDT operation (e.g., an Automerge change)
    children: Vec<Cid>,      // Hashes of the DAG roots at time of creation
}

CID = Hash(encode(node))    // Content address = hash of the serialized node
```

### Fields

**`payload`** contains the actual CRDT operation. It is opaque to the sync
layer — the `Payload` trait defines how to serialize and apply it. For a
collaborative text document, this might be an Automerge change. For a chat
channel, it might be an appended message. For a counter, it might be an
increment.

**`children`** contains the CIDs of all current root nodes at the time the
operation was recorded. This is what creates the causal links. A node with
two children means the author had seen (at least) two concurrent branches
and is implicitly merging them. A node with one child is a linear
continuation. A node with zero children is a genesis node.

### Encoding format

Nodes are serialized with a deterministic binary encoding:

1. Length-prefixed payload bytes
2. Children count (varint)
3. Children CIDs in order (each fixed-size for a given hash function)

Deterministic encoding is critical: two peers that independently construct
the same logical node must produce the same bytes, and therefore the same
CID. This is what makes deduplication and self-verification work.

### Hash function

The hash function is pluggable via the `Hasher` trait. The default is
Blake3, chosen for its speed (especially on modern CPUs with SIMD) and
its 256-bit output. SHA-256 is also supported for environments where
FIPS compliance or interoperability with existing systems matters.

The CID covers the full serialized node — both the payload and the
children list. This means:

- You cannot tamper with an operation without changing its CID.
- You cannot rewrite history by changing a node's parent links without
  changing its CID (and therefore breaking all references to it).
- Any node fetched from any source (peer, relay, DA layer) can be
  verified by recomputing its hash. The source is untrusted by default.

---

## 3. The Sync Protocol

Syncing two peers is a set reconciliation problem: each peer has a set of
DAG nodes, and the goal is for both to end up with the union. The protocol
works in five steps.

### Step-by-step

1. **Root exchange.** Peer A announces its current root CIDs — the "heads"
   of its DAG. These are the nodes with no parents (no other node lists
   them as children). The root set is the peer's version summary.

2. **Root comparison.** Peer B receives A's roots and compares them against
   its own root set. Three outcomes are possible:
   - **Identical roots:** Both peers are fully in sync. Done.
   - **A's roots are a subset of B's history:** A is behind. B has nothing
     to learn from A (though A still needs to pull from B).
   - **Disjoint or partially overlapping roots:** The peers have diverged.
     Both need to exchange missing nodes.

3. **DAG walking.** For each root CID that Peer B does not recognize, B
   requests the corresponding node from A. Upon receiving it, B inspects
   the node's children. For each child CID that B does not already have,
   B requests that node too. This continues recursively until B reaches
   nodes it already has — the divergence point.

4. **Node exchange.** All missing nodes discovered during the walk are
   transferred. In practice, the walk and the transfer happen together:
   each fetched node is immediately stored locally.

5. **Apply in causal order.** The missing nodes are applied to the local
   CRDT state in topological order — children before parents, oldest
   first. Topological sort of a DAG is straightforward and guarantees
   that when a node is applied, all operations it depends on have already
   been applied. The root set is then updated to reflect the merged DAG.

After both peers run this protocol (A pulls from B, B pulls from A), they
hold the same set of nodes and their CRDTs are in the same state.

### DAG walking in detail

Walking is a recursive fetch-by-CID process. Starting from an unknown
root, the peer fetches the node, reads its children, and for each child
calls `Store::contains(cid)`. If the store does not contain that CID, the
child is fetched and the process repeats. If the store already has the CID,
that branch is pruned — everything below it is already known.

This is efficient because the DAG converges quickly. Even if two peers have
thousands of nodes, they typically share most of the history. The walk only
traverses the divergent portion.

### Multiple concurrent roots (multi-head DAG)

It is normal and expected for a DAG to have multiple roots simultaneously.
This happens when two or more peers edit concurrently without syncing. Each
peer's edit creates a new node pointing to its own previous root, producing
two independent branches.

When these peers eventually sync, both branches become part of the merged
DAG. The root set contains all unmerged heads. The next edit by any peer
will list all current roots as its children, creating a single new root
that implicitly merges the branches.

The CRDT handles the semantic merge — the DAG only records that the merge
happened.

### Causal ordering via topological sort

Applying operations in arbitrary order would violate causality: an operation
might reference state that has not been created yet. Topological sort of
the DAG produces a valid causal ordering. Since the DAG is acyclic by
construction (you cannot reference a node that does not yet exist), a
topological ordering always exists.

The specific algorithm: process nodes in reverse DFS post-order from the
roots. This ensures that for any node N, all of N's children (the nodes
it depends on) are processed first.

### Idempotency

Because node identity is determined by content hash, receiving the same
node twice is inherently a no-op: `Store::contains(cid)` returns true,
and the node is skipped. This means:

- Retransmissions are safe.
- Overlapping syncs from multiple peers are safe.
- There is no need for deduplication logic beyond the content-addressed
  store.

---

## 4. Anti-Entropy Algorithm

The sync protocol described above is the anti-entropy mechanism. It
guarantees that any two peers that communicate will converge. The
specific algorithm in the `merkle-crdt` implementation works as follows.

### Entry point: root CID exchange

Every sync session begins with both peers exchanging their root CID sets.
This is a compact message — typically one to three CIDs (32 bytes each).
It is the only metadata that must be shared; everything else is derived
from the DAG walk.

### Traversal strategy

The implementation uses **depth-first traversal** when walking an unknown
branch. The reasoning:

- **Depth-first** reaches the divergence point (shared history) quickly,
  which lets the peer determine the full set of missing nodes with minimal
  round trips. Once the shared ancestor is found, the scope of the sync is
  known.
- **Breadth-first** would enumerate all nodes at each depth level before
  going deeper, which can result in more round trips before discovering
  shared nodes.

In practice, the walk is bounded: most syncs involve a small number of
missing nodes (the edits since the last sync). Full history syncs (new
peer joining) are the exception and are discussed under DAG growth.

### "Have you seen this CID?" checks

The core primitive is `Store::contains(cid) -> bool`. This is a local
check against the peer's own store. During the walk, every child CID of a
fetched node is tested:

- If the store contains it: stop walking this branch.
- If the store does not contain it: fetch the node, store it, and continue
  walking its children.

This is a purely local decision — the peer never asks the remote "do you
have this CID?" (which would leak information; see section 8).

### Termination condition

The walk terminates when every branch has been pruned by reaching a known
CID. At this point, all missing nodes have been fetched. The peer updates
its root set and the sync is complete.

For correctness: the walk always terminates because the DAG is finite and
acyclic. Every step either fetches a new node (finite, since the remote
DAG is finite) or prunes a branch (which cannot loop, since the graph is
acyclic).

---

## 5. Operation Batching

Recording every individual CRDT operation as a separate DAG node is
wasteful and leaks information. Batching addresses both problems.

### Why batch

- **Reduce DAG nodes.** Each node carries overhead: CID computation,
  encoding, encryption, storage, and sync metadata. A user typing at
  60 WPM produces 5 characters per second. Without batching, that is
  5 DAG nodes per second per user.
- **Hide per-keystroke timing.** Individual character inserts reveal
  typing cadence, which is a biometric fingerprint. Batching collapses
  a window of operations into a single node, obscuring timing.
- **Amortize encryption cost.** Each DAG node is independently encrypted
  (see [Encryption](./encryption.md)). Batching reduces the number of
  encryption operations.
- **Reduce sync overhead.** Fewer nodes means fewer CIDs to exchange,
  fewer `contains` checks, and faster DAG walks.

### How batching works

The peer buffers CRDT operations for a configurable interval before
recording them as a single DAG node. The batch interval depends on the
use case:

| Context | Interval | Rationale |
|---|---|---|
| Real-time collaborative editing | 100-500ms | Low latency, still hides individual keystrokes |
| Chat messaging | Per-message | Each message is already a discrete unit |
| Background sync / bulk import | 1-5s | Maximize batching, minimize overhead |
| Offline editing | Until reconnect | All offline edits become one batch |

A batch is a single DAG node whose payload contains multiple CRDT
operations, applied in order. From the sync layer's perspective, a batched
node is identical to a single-operation node — the `Payload` trait handles
the multiplexing internally.

### Tradeoffs

Longer batch intervals improve privacy and reduce overhead but increase
the latency before other peers see your edits. The right balance is
application-specific, which is why the interval is configurable rather
than hard-coded.

---

## 6. DAG Growth and Pruning

The DAG grows without bound. Every operation (or batch of operations)
appends a new node, and nodes are never modified. For a long-lived
document with heavy editing, the DAG can grow to millions of nodes. This
section describes strategies for managing that growth.

### The problem

- **Storage cost.** Every peer stores the full DAG locally.
- **Sync cost.** A new peer joining a space must download the entire DAG
  to reconstruct the CRDT state.
- **Memory pressure.** Materializing the CRDT state from a large DAG may
  require loading many nodes into memory.

### Strategy 1: Snapshot compaction

Periodically, a peer creates a **snapshot node** — a special DAG node
whose payload is the full materialized CRDT state rather than an
incremental operation. The snapshot node's children point to the current
roots, anchoring it in the DAG.

After a snapshot exists:

- New peers only need the snapshot node plus any subsequent nodes. They
  do not need to fetch or replay the pre-snapshot history.
- The sync protocol's DAG walk stops at the snapshot node (since the
  peer has it), just as it would stop at any known node.
- Nodes older than the snapshot can be garbage collected from local
  storage if the peer does not need the full history.

Snapshots are created by any peer, unilaterally. Because the snapshot
payload deterministically captures the CRDT state, any peer that creates
a snapshot at the same logical point produces the same content (and
therefore the same CID). No coordination is needed.

### Strategy 2: Depth-limited history

A simpler approach: configure each peer to keep only the last N layers
of the DAG. When a node is more than N layers deep (measured from the
current roots), it is eligible for pruning from local storage.

The CRDT state is not affected by pruning — it is maintained
independently of the DAG history. Pruning only affects the ability to
replay or audit past operations.

### Strategy 3: Checkpoint epochs

Tie pruning to MLS epoch changes. When a new MLS epoch starts (due to
a membership change), the peer creates a snapshot. Pre-epoch history
can then be pruned.

This aligns naturally with forward secrecy: old epoch content is already
inaccessible to new members (the old epoch's keys have been ratcheted
away). Pruning the DAG nodes from that epoch is consistent — the content
could not be decrypted anyway.

This strategy makes pruning a protocol-level event rather than an
implementation detail, which simplifies reasoning about what history
is available.

### Strategy 4: Lazy pruning

Do not proactively delete nodes. Instead:

- Configure a depth limit on the DAG walk during sync. When walking
  a branch, stop after N levels even if the divergence point has not
  been found.
- Relay nodes expire content based on age or size quotas. Old nodes
  age out of relay caches naturally.
- The local store may implement LRU eviction for DAG nodes older than
  a configurable threshold.

This is the least disruptive strategy: no special snapshot logic, no
coordination. The tradeoff is that it offers weaker guarantees — a
peer may fail to fully sync if the divergence point is deeper than the
depth limit.

### Pruning vs. auditability

Some spaces may want full history: legal compliance, audit trails,
dispute resolution. Others may want aggressive pruning for privacy
(less stored content means less to compromise). This is a per-space
configuration:

| Policy | Behavior |
|---|---|
| `full_history` | Never prune. All nodes kept indefinitely. |
| `snapshot_and_prune` | Snapshot every N epochs, prune pre-snapshot nodes. |
| `depth_limited` | Keep last N layers only. |
| `lazy` | No active pruning; rely on cache expiry. |

The choice is stored in the space's root document (itself a CRDT) and
can be changed by members with appropriate permissions.

---

## 7. Sync Over Unreliable Transports

Kunekt peers operate in the real world: connections drop, peers go
offline, relays restart, mobile devices lose signal mid-sync. The
sync protocol is designed to tolerate all of this.

### Partial sync and resumption

If a connection drops mid-sync, all nodes already received and stored
are kept. They are content-addressed and self-verifying — a partial
transfer is not corrupted, just incomplete.

To resume, the peer simply re-runs the sync protocol: exchange roots,
walk the DAG, skip nodes already in the store. The `Store::contains`
check ensures no redundant work. There is no session state to maintain
between sync attempts.

### Relay-mediated sync (store-and-forward)

Two peers do not need to be online simultaneously. The protocol supports
asynchronous sync via a relay:

1. Peer A edits a document and pushes new DAG nodes to a relay.
2. Hours later, Peer B comes online and syncs with the relay.
3. The relay serves A's nodes to B. B applies them locally.
4. B pushes its own nodes (if any) to the relay.
5. Later, A syncs with the relay and picks up B's nodes.

The relay is an untrusted storage backend — it holds encrypted blobs
identified by CID. It does not need to understand the DAG structure,
though it may optionally assist with DAG walking if the DAG metadata
(children CIDs) is stored in plaintext.

See [Persistence](./persistence.md) for details on storage tiers and
relay behavior.

### Multi-path sync

A peer can fetch different parts of the DAG from different sources:

- Recent nodes from a direct peer connection (low latency).
- Older nodes from a relay (always available).
- Archival nodes from a DA layer (durable, censorship-resistant).

Because every node is identified and verified by its CID, it does not
matter where a node came from. The peer computes the hash of the
received data and checks it against the expected CID. If it matches,
the node is valid. If it does not, the node is discarded and fetched
from another source.

This means sync is naturally parallelizable: a peer can issue fetch
requests to multiple sources simultaneously, assembling the complete
DAG from whichever source responds first for each node.

---

## 8. Sync Privacy Considerations

The sync protocol, even with encrypted payloads, reveals metadata.
This section summarizes the leaks; see [Privacy Analysis](./privacy-layers.md)
for countermeasures.

**Root CID broadcasts reveal activity timing.** When a peer announces
new roots, observers learn that the peer (or someone in the space) has
made edits. Countermeasure: batched sync on a fixed schedule, combined
with dummy announcements during idle periods.

**DAG structure reveals causal relationships.** The parent-child links
between nodes encode a partial order of events. An observer with access
to the DAG structure (e.g., an untrusted relay) can infer which edits
happened before others, which edits were concurrent, and roughly how
many participants are active. Countermeasure: encrypt the children list
inside the node payload, at the cost of relays being unable to assist
with DAG walking.

**CID queries reveal interest.** When a peer requests a specific CID
from a relay or another peer, the request reveals that the peer is
interested in that node (and by extension, the document and space it
belongs to). Countermeasure: Private Information Retrieval (PIR)
protocols, where the storage backend serves a node without learning
which CID was requested.

**Node count and sizes reveal activity levels.** Even without reading
payloads, the number and size of DAG nodes convey information about edit
frequency and content type. Countermeasure: uniform node padding and
dummy node injection.

---

## 9. Implementation

The `merkle-crdt` crate provides a generic, `no_std` implementation of
the Merkle-CRDT data structure and sync logic. It is parameterized over
the hash function, storage backend, CRDT payload, and encoding format.

### Core types

**`MerkleClock<S, H>`** is the DAG clock. It tracks the current set of
root CIDs and provides two fundamental operations:

- `record(payload) -> Cid` — creates a new DAG node with the given
  payload and the current roots as children. Stores it. Returns the new
  node's CID. The root set is updated to contain only the new CID.
- `merge(roots) -> Result<()>` — takes a set of root CIDs from another
  peer, walks the DAG to find missing nodes, fetches and stores them,
  and updates the local root set to the union of both peers' roots.

**`MerkleCrdt<P, S, H>`** wraps a `MerkleClock` with a CRDT state
tracker. It calls the `Payload` trait methods to apply operations to
the CRDT state as they are recorded or merged. This is the primary type
that application code interacts with.

**`Payload` trait** — user-implemented. Defines how to serialize,
deserialize, and apply a CRDT operation:

```rust
trait Payload {
    fn encode(&self, buf: &mut Vec<u8>);
    fn decode(buf: &[u8]) -> Self;
    fn apply(&self, state: &mut State);
}
```

**`Store` trait** — pluggable storage backend. Any type that can store
and retrieve byte blobs by CID:

```rust
trait Store {
    fn put(&mut self, cid: Cid, data: &[u8]) -> Result<()>;
    fn get(&self, cid: &Cid) -> Result<Option<Vec<u8>>>;
    fn contains(&self, cid: &Cid) -> bool;
}
```

Implementations include `MemStore` (in-memory, for testing), SQLite
(local persistence), and Nostr relay (remote store-and-forward via
Nostr events).

**`Hasher` trait** — pluggable hash function:

```rust
trait Hasher {
    type Output: AsRef<[u8]>;
    fn hash(data: &[u8]) -> Self::Output;
}
```

Default implementation: Blake3. Alternative: SHA-256.

**`Encode` trait** — defines the deterministic serialization of DAG
nodes. Separated from `Payload::encode` because the node envelope
(children list, framing) is handled by the crate, not user code.

### Concrete example

Recording an event and syncing two peers:

```rust
use merkle_crdt::{MerkleCrdt, MemStore, Blake3Hasher};

// Create two independent peers, each with their own store.
let mut peer_a = MerkleCrdt::<MyPayload, MemStore, Blake3Hasher>::new();
let mut peer_b = MerkleCrdt::<MyPayload, MemStore, Blake3Hasher>::new();

// Peer A records two operations.
let cid1 = peer_a.record(MyPayload::Insert { pos: 0, ch: 'H' });
let cid2 = peer_a.record(MyPayload::Insert { pos: 1, ch: 'i' });

// Peer A's DAG now has two nodes: cid1 (root) <- cid2 (new root).
// Peer A's root set: { cid2 }.

// Peer B records a concurrent operation.
let cid3 = peer_b.record(MyPayload::Insert { pos: 0, ch: '!' });

// Peer B's root set: { cid3 }.

// Sync: Peer B merges Peer A's roots.
peer_b.merge(peer_a.roots());
// Peer B now has nodes: cid1, cid2, cid3.
// Peer B's root set: { cid2, cid3 } — two concurrent heads.

// Sync the other direction.
peer_a.merge(peer_b.roots());
// Both peers now have identical DAGs and root sets: { cid2, cid3 }.

// The next operation by either peer will merge the two heads.
let cid4 = peer_a.record(MyPayload::Insert { pos: 2, ch: '?' });
// cid4's children: [cid2, cid3] — merges both branches.
// Peer A's root set: { cid4 }.
```

After the next sync, both peers will have `{ cid4 }` as their root set
and identical CRDT state.

### Integration in Kunekt

In Kunekt, each document in a space has its own `MerkleCrdt` instance:

- The `Payload` implementation delegates to the document's CRDT. For
  collaborative text, this is an Automerge change. For a chat channel,
  it is an appended message entry.
- The `Store` writes to the local database *and* to the encrypted
  network layer. When storing a node, it is first encrypted with the
  space's current MLS epoch key, then pushed to the configured storage
  backends (local DB, relay, DA layer).
- The `Hasher` is Blake3 by default.

The sync layer operates on plaintext locally — CRDT operations are
applied to the in-memory document state in the clear. Encryption
happens at the storage boundary: nodes are encrypted before leaving
the peer and decrypted upon arrival. See [Encryption](./encryption.md)
for the full key management lifecycle.
