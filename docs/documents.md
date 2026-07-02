# Document Layer: CRDTs & Spaces

Every piece of shared content in VOS is a document. Every document is
a CRDT backed by a Merkle-DAG. This chapter explains how spaces organize
documents, what CRDT types are available, how documents sync
independently, and how developers define new document types.

---

## Spaces

A space is the top-level unit of collaboration in VOS. It is the
container that ties together encryption, membership, moderation, and
content. A space owns:

- An **MLS group** defining membership and providing group encryption
  keys. All content within the space is encrypted under the current
  epoch key.
- A **membership Merkle tree** whose leaves are commitments to members'
  space-scoped secrets. This tree enables ZK membership proofs: a
  member can prove "I belong to this space" without revealing which
  leaf is theirs.
- A set of **documents**, each an independent CRDT with its own
  Merkle-DAG history.
- A **root document** — a special CRDT that describes the space itself.

The space is not a server, not a channel, not a database. It is a
self-contained unit of private collaboration that peers replicate among
themselves. There is no central authority managing it.

---

## The Root Document

Every space has exactly one root document. It is a CRDT (specifically
an LWW-Map at its core, with nested structures) that describes the
space's configuration and state. The root document contains:

| Field | Type | Purpose |
|---|---|---|
| `name` | LWW-Register | Human-readable space name |
| `description` | LWW-Register | Optional space description |
| `documents` | OR-Map | Registry of all documents in the space (ID → type + metadata) |
| `membership_root` | LWW-Register | Current root hash of the membership Merkle tree |
| `mls_state` | Append-only log | MLS Commit and Proposal messages (membership changes, key rotations) |
| `moderation_config` | LWW-Map | Moderation policy: reputation thresholds, rate limits, moderator list |
| `settings` | LWW-Map | General configuration: privacy level, sync interval, storage policy |
| `admission_policy` | LWW-Map | Requirements for joining: open, invite-only, credential-gated |

The root document is itself a CRDT, so it syncs like any other document
via Merkle-CRDT. Changes to space settings are CRDT operations on the
root document. This means governance proposals that modify settings
(see [Private Economy](./private-economy.md)) are just CRDT ops —
the governance system and the configuration system are unified.

MLS state lives in the root document as an append-only log. When a
member joins, leaves, or keys rotate, the resulting MLS Commit message
is recorded as a DAG node in the root document. Peers process these
Commits during sync to stay current with the group's key schedule.

---

## Document Types and Their CRDTs

Each document in a space has a CRDT type that determines its merge
semantics. The following types are supported or planned:

### Rich text — Automerge

The primary document type for collaborative editing. Automerge provides
a sequence CRDT with character-level conflict resolution, supporting
concurrent inserts, deletes, and formatting changes.

- **CRDT:** Automerge (sequence + map)
- **Use:** Collaborative documents, notes, wikis, code files
- **Merge semantics:** Concurrent inserts at the same position are
  ordered deterministically by actor ID. Concurrent formatting is
  resolved by last-writer-wins per character per attribute.
- **Integration:** Automerge changes are serialized and wrapped as
  Merkle-CRDT payloads (see "How Automerge Integrates" below).

### Chat channel — GSet (append-only log)

A grow-only set of messages. Messages are never deleted from the CRDT
(deletion is handled at the application layer via tombstone markers or
moderation callbacks). Each message is a DAG node.

- **CRDT:** GSet (grow-only set)
- **Use:** Messaging, threaded discussions, comment streams
- **Merge semantics:** Set union. Every message ever sent is included.
  Concurrent messages are ordered by the DAG's causal structure;
  causally unrelated messages are ordered by topological sort with
  CID as tiebreaker.
- **Application-level features:** Threads (message references a parent
  message ID), reactions (message references a target + emoji),
  read receipts (per-member LWW-Register tracking last-read CID).

### Space settings — LWW-Map

A last-writer-wins map for configuration key-value pairs. The most
recent write to any key wins. Used for the root document's settings
fields.

- **CRDT:** LWW-Map (last-writer-wins element map)
- **Use:** Configuration, preferences, metadata
- **Merge semantics:** For each key, the value with the highest
  timestamp wins. Timestamps are Lamport clocks derived from DAG
  depth, not wall clocks (wall clocks are unreliable in P2P systems).
- **Concurrency:** If two peers set the same key simultaneously, the
  one with the higher Lamport timestamp wins. Ties broken by CID.

### Membership tree — Custom Merkle tree CRDT

The membership Merkle tree is a specialized CRDT that maintains a
balanced binary tree of member commitment leaves. Adding a member
appends a leaf; removing a member replaces a leaf with a tombstone
(the tree is append-biased, not rebalanced on removal, to preserve
existing proof paths for as long as possible).

- **CRDT:** Custom Merkle tree with append-only leaves and tombstone
  removal
- **Use:** ZK membership proofs (see
  [Authorization](./authorization.md))
- **Merge semantics:** Leaf additions are merged by set union. Leaf
  tombstones are merged by taking the tombstoned state (removal wins
  over no-removal). The tree root is recomputed after merge.
- **Integration with MLS:** Each MLS Add produces a corresponding
  membership tree append. Each MLS Remove produces a tombstone. The
  two structures must stay in sync — the root document's MLS log and
  membership tree are updated atomically (as a single batched CRDT
  operation).

### Moderation log — Append-only log (bulletin board)

The moderation log is the zk-promises bulletin board. Moderators post
callbacks here; users scan it for callbacks targeting their tickets.
It is append-only — entries are never modified or deleted.

- **CRDT:** Append-only log (GSet of callback entries)
- **Use:** zk-promises callback delivery, reputation tracking, ban
  enforcement
- **Merge semantics:** Set union. Every callback ever issued is
  included. Order is determined by DAG causality.
- **Privacy:** Callbacks are posted against anonymous tickets. The
  log reveals which tickets were penalized but not which members
  hold those tickets. See [Authorization](./authorization.md).

### Task board — OR-Map

An observed-remove map of lists, where each list is an OR-Set of task
items. Tasks can be created, moved between lists, reordered within
lists, and deleted. Concurrent moves are resolved by last-writer-wins
on the task's list assignment.

- **CRDT:** OR-Map (observed-remove map) of OR-Sets
- **Use:** Kanban boards, project management, to-do lists
- **Merge semantics:** Concurrent add and remove of the same task:
  add wins (observed-remove semantics). Concurrent moves to different
  lists: last-writer-wins on the task's list field. Position within a
  list: fractional indexing (Logoot-style).

### Wallet / ledger — Counter with ZK proofs

A counter CRDT extended with ZK balance proofs. Each increment or
decrement is accompanied by a zero-knowledge proof that the resulting
balance is non-negative (preventing overdraft without revealing the
actual balance).

- **CRDT:** PN-Counter (positive-negative counter) with ZK range
  proof per operation
- **Use:** Private payment channels, token balances, resource
  allocation
- **Merge semantics:** Standard PN-Counter merge (sum of all
  increments minus sum of all decrements per actor). The ZK proof
  is verified on application — invalid proofs cause the operation
  to be rejected.
- **Settlement:** Periodically, the final state can be settled
  on-chain via a ZK proof of correct execution. See
  [Private Economy](./private-economy.md).

### Proposal + votes — Custom voting CRDT

A specialized CRDT for governance proposals. Contains the proposal
text, voting parameters, encrypted votes, and the tally.

- **CRDT:** Custom (proposal metadata as LWW-Map + votes as GSet of
  encrypted ballots + tally as computed value)
- **Use:** Governance decisions, polls, elections
- **Merge semantics:** Proposal metadata merges by LWW. Votes merge
  by set union. Duplicate votes from the same nullifier are rejected
  (enforced by the ZK proof's nullifier check). Tally is recomputed
  from the merged vote set.
- **Privacy:** Votes use homomorphic commitments. The tally is
  computed from commitments without decrypting individual votes. See
  [Private Economy](./private-economy.md).

---

## Per-Document Independent Sync

Documents within a space sync independently. A peer subscribes to
specific documents, not to the entire space. This has several
consequences:

**Selective subscription.** A member of a large space may subscribe only
to the `#general` chat and the `design-doc` text document, ignoring the
task board and other channels. The peer only fetches, stores, and syncs
DAG nodes for subscribed documents.

**Bandwidth efficiency.** A mobile device on a metered connection can
subscribe to lightweight documents (chat, settings) and defer heavy
documents (file attachments, full kanban boards) until on Wi-Fi.

**Privacy benefit.** The set of documents a peer subscribes to is not
broadcast. When using PIR for storage retrieval, the storage
backend does not learn which documents a peer is interested in. Without
PIR, the relay can observe fetch patterns per document — this is a
known metadata leak addressed in the
[Privacy Analysis](messaging.md#security).

**Root document exception.** Every peer must subscribe to the root
document. It contains MLS state, membership tree updates, and
moderation configuration — all essential for participating in the space
at all.

**Sync mechanics.** Each document has its own `MerkleCrdt` instance with
its own set of DAG roots. Syncing document A does not require syncing
document B. The anti-entropy algorithm runs per-document: the peer
sends its root CIDs for document A to another peer, and they exchange
missing nodes for that document only. See [Sync Layer](./sync.md).

---

## Document Lifecycle

### Create

A member creates a new document by adding an entry to the root
document's `documents` registry. The entry specifies the document's
ID (a random UUID or derived CID), CRDT type, and initial metadata
(name, access policy). The act of creation is a CRDT operation on the
root document — it syncs to all members via the normal Merkle-CRDT
path.

The creator then initializes the document's `MerkleCrdt` instance and
records the first DAG node (which may be empty or contain initial
content).

### Edit

Editing is the normal CRDT flow: the application produces a CRDT
operation, which is recorded as a DAG node, encrypted, and synced. See
[Sync Layer](./sync.md) and [Encryption](./messaging.md#group-encryption-mls).

### Archive

Archiving is a soft state change: the root document's `documents`
registry entry for the document is updated with an `archived: true`
flag. The document's DAG remains in storage. Peers stop syncing it
(unless they explicitly request archived documents). The document can
be un-archived by clearing the flag.

### Delete

Deletion is more complex in a content-addressed system. The document's
registry entry in the root document is tombstoned. Peers that hold the
document's DAG nodes may garbage-collect them — but this is best-effort.
Nodes already replicated to external storage backends cannot be forcibly
deleted from those backends.

In practice, deletion means: the document is removed from the registry,
peers stop syncing it, and local stores are free to reclaim the space.
The encrypted DAG nodes may persist on remote relays indefinitely, but
without the MLS epoch key they are indistinguishable from random data.
Forward secrecy provides the real deletion guarantee: once the epoch
key is rotated and old key material is discarded, the data is
cryptographically inaccessible even if the ciphertext persists.

---

## How Automerge Integrates

Automerge is the primary CRDT engine for rich documents. Its integration
with the Merkle-CRDT sync layer works as follows:

### Write path

```
User edit (e.g. insert text)
  → Automerge generates a Change (binary blob)
  → Change is serialized as the Payload for a Merkle-CRDT DAG node
  → MerkleCrdt::apply(payload) is called
  → The DAG node is created:
      - payload = serialized Automerge Change
      - children = current root CIDs
      - CID = hash(node)
  → The node is encrypted with the current MLS epoch key
  → The encrypted blob is stored locally and pushed to remote backends
```

### Read path

```
Sync receives an encrypted blob from a remote peer or backend
  → Decrypt with the appropriate MLS epoch key
  → Verify CID: hash(decrypted node) must match the claimed CID
  → Extract the Automerge Change from the payload
  → Apply the Change to the local Automerge document
  → The Automerge document state updates (UI reflects the change)
```

### Batching

For real-time editing, individual keystrokes are not sent as separate
DAG nodes. Instead, Automerge changes are batched over a configurable
interval (default: 100ms for real-time, 5s for background sync). A
single DAG node may contain multiple Automerge changes bundled together.
This reduces DAG growth, network overhead, and per-keystroke timing
leaks.

### Automerge state vs. DAG state

There is a subtle but important distinction: Automerge maintains its
own internal causal history (each Change references its dependencies).
The Merkle-DAG also encodes causal history (each node references its
parent CIDs). These two histories must be consistent but they are
not redundant — Automerge's history captures fine-grained character-
level causality, while the Merkle-DAG captures coarser operation-
level causality used for sync.

During sync, the Merkle-DAG determines which nodes are missing and
in what causal order to apply them. The Automerge Changes within those
nodes are then applied to the Automerge document in that same order.
If Automerge detects an internal dependency that has not been satisfied
(a Change references a predecessor Change not yet applied), the
application is deferred until the predecessor arrives — but in
practice, the topological sort of DAG nodes ensures this does not
happen.

---

## Custom CRDT Trait

VOS is not limited to built-in document types. Developers can define
custom CRDTs by implementing the `Payload` trait from the `merkle-crdt`
crate:

```rust
/// A CRDT payload that can be applied to produce state.
pub trait Payload: Encode + Decode {
    /// The state type this payload produces.
    type State;

    /// Apply this payload to the current state, producing a new state.
    fn apply(&self, state: &mut Self::State);

    /// Merge two states (used during anti-entropy sync when applying
    /// multiple payloads in causal order).
    fn merge(a: &Self::State, b: &Self::State) -> Self::State;
}
```

A custom CRDT is a struct that implements `Payload`. The `apply` method
defines how a single operation modifies state. The `merge` method
defines how two independently-evolved states are combined. As long as
`merge` is commutative, associative, and idempotent, the result is a
valid CRDT that syncs correctly through the Merkle-CRDT layer.

### Example: a custom rating CRDT

```rust
use vos::prelude::*;

#[derive(Encode, Decode)]
enum RatingOp {
    Rate { item_id: Id, score: u8 },  // score 1-5
    Retract { item_id: Id },
}

#[derive(Default)]
struct RatingState {
    ratings: HashMap<(ActorId, Id), u8>,  // (rater, item) → score
}

impl Payload for RatingOp {
    type State = RatingState;

    fn apply(&self, state: &mut RatingState) {
        match self {
            RatingOp::Rate { item_id, score } => {
                state.ratings.insert((self.actor(), *item_id), *score);
            }
            RatingOp::Retract { item_id } => {
                state.ratings.remove(&(self.actor(), *item_id));
            }
        }
    }

    fn merge(a: &RatingState, b: &RatingState) -> RatingState {
        // LWW per (actor, item) pair — relies on DAG causal order
        let mut merged = a.ratings.clone();
        for (k, v) in &b.ratings {
            merged.insert(*k, *v);
        }
        RatingState { ratings: merged }
    }
}
```

This custom CRDT can then be used as a document type in a space:

```rust
let space = node.create_space(SpaceConfig {
    documents: vec![
        DocTemplate::new::<RatingOp>("product-ratings"),
    ],
    ..Default::default()
})?;
```

A planned `#[derive(Crdt)]` macro will automate most of this
boilerplate for simple cases. See Development Roadmap.

---

## Document Access Control

In the current design, all members of a space can read all documents
in that space. Encryption is at the space level (MLS group key), not
at the document level. This is a deliberate simplification:

- **Simpler key management.** One MLS group per space, one key
  schedule, one epoch. Per-document keys would multiply the key
  management complexity.
- **Consistent membership.** If member A can read chat but not the
  task board, what does it mean for A to be a "member" of the space?
  Partial access creates confusing membership semantics.
- **Practical pattern.** For most use cases, if you trust someone
  enough to include them in an encrypted group, you trust them with
  all the group's documents. If a subset of documents needs
  restricted access, create a sub-space with its own MLS group and
  membership.

### Future: per-document access via sub-groups

For cases where fine-grained access control is genuinely needed
(e.g., a large organization where some documents are board-only), the
planned approach is nested sub-groups:

- A document can be associated with a sub-group: a smaller MLS group
  whose members are a subset of the space's members.
- The document's DAG nodes are encrypted under the sub-group's key,
  not the space key.
- Non-sub-group members can see that the document exists (it is listed
  in the root document) but cannot decrypt its contents.
- Sub-group membership changes are recorded in the root document (so
  all space members know the sub-group exists) but the sub-group's
  MLS state is stored in a separate document accessible only to
  sub-group members.

This is not yet implemented. The complexity cost is significant: each
sub-group adds its own MLS lifecycle, key rotation, and epoch
management. It will be evaluated based on real-world demand.

### Selective sync as soft access control

Even without per-document encryption, selective sync provides a
pragmatic form of access control. If a peer does not subscribe to a
document, it never fetches the DAG nodes. The data does not exist on
that peer's device. This is not a security boundary — the peer *could*
subscribe and decrypt if it wanted to — but it reduces attack surface
for device compromise: data you never fetched cannot be extracted from
your device.
