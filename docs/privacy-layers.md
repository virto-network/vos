# Privacy Analysis

Encrypted content is table stakes. The real leaks are in metadata,
timing, access patterns, and structural information. This document
maps every layer of the protocol, identifies what leaks, and
proposes countermeasures — these directly inform the
[development phases](./roadmap.md) and choice of
[building blocks](./building-blocks.md).

The goal: **any application built on Kunekt should be private by default
at every layer**, not just at the payload level.

---

## 1. Transport Layer — "Who talks to whom"

### What leaks

| Signal | What it reveals |
|---|---|
| IP addresses | Physical identity / location |
| Connection timing | When a user is active |
| Peer graph | Who syncs with whom |
| Traffic volume | How active a user/space is |
| Connection duration | Session patterns |

### Countermeasures

**Mix networks.** Route all sync traffic through a mix network (like
Nym or Loopix). Messages are batched, padded to uniform size, delayed
randomly, and routed through multiple mix nodes. An observer sees
uniform-looking traffic with no clear sender-receiver link.

**Onion routing.** Lighter than a full mix network. Wrap sync messages
in multiple encryption layers (like Tor). Each relay peels one layer
and forwards. The destination sees the message but not the origin.

**Noise padding.** Even without a mix net, peers can pad all messages
to fixed sizes and send cover traffic (empty encrypted DAG nodes) at
regular intervals. This hides when real edits happen.

**Peer-to-peer relay via untrusted intermediaries.** Peers don't
connect directly — they publish encrypted blobs to a shared pool
(relay, DHT, DA layer) and other peers pull from it. No direct
peer-to-peer connections means no peer graph to observe.

> **ZK opportunity:** A peer could prove "I am authorized to use this
> relay" without revealing which space or user they are. Anonymous
> relay authentication via ZK credentials.

---

## 2. Sync Layer — "What changed and when"

### What leaks

| Signal | What it reveals |
|---|---|
| DAG structure | Causal relationships between edits |
| Root CID broadcasts | Activity timing per document |
| Number of DAG nodes | Edit frequency |
| Node sizes | Type/size of operations |
| Sync request patterns | Which peers are behind / ahead |
| CID queries | What a peer is looking for |

### Countermeasures

**Encrypted DAG topology.** Currently, CIDs and parent-child links are
in plaintext (so untrusted relays can assist with traversal). Instead:
- Encrypt the children list inside the node payload
- Use a **Private Information Retrieval (PIR)** protocol to fetch nodes
  from storage without revealing which CIDs you're requesting
- Trade-off: relays can no longer help with DAG walking — peers must
  fetch nodes one at a time (or in batches with PIR)

**Uniform node sizes.** Pad all DAG nodes to a fixed size before
encryption. This hides whether an operation is a single character
insert or a large paste.

**Batched sync.** Instead of broadcasting a new root CID after every
edit, batch operations and sync periodically (e.g. every 5 seconds).
This hides per-keystroke timing.

**Dummy operations.** Periodically inject no-op DAG nodes (encrypted,
indistinguishable from real ones). Prevents traffic analysis from
revealing when a user is actively editing vs idle.

> **ZK opportunity: Private set reconciliation.** During sync, two
> peers need to discover which DAG nodes they're each missing. Currently
> this involves walking the DAG and checking CIDs. With ZK, peers could
> perform **private set intersection** — each proves "I have nodes with
> these properties" without revealing the actual CIDs. This prevents a
> malicious peer from learning what you have or don't have.

> **ZK opportunity: Proof of sync correctness.** A relay or DA layer
> could verify that a submitted DAG node is well-formed (valid CID,
> valid parent references) without seeing the plaintext. The submitter
> provides a ZK proof that the encrypted blob, when decrypted, would
> produce a node whose hash matches the claimed CID.

---

## 3. Encryption Layer — "Who is in the group"

### What leaks

| Signal | What it reveals |
|---|---|
| MLS group ID | Links all messages to one group |
| MLS Welcome messages | When new members join |
| MLS Commit messages | When membership changes |
| Key package uploads | A member's public key exists |
| Epoch numbers | How many membership changes occurred |
| Group size | Number of members |

### Countermeasures

**Anonymous group membership.** Instead of MLS where each member has a
known leaf in the ratchet tree, use a scheme where membership is proven
via ZK proof. A member proves "I know a secret that is committed in
this group's membership Merkle root" without revealing which member
they are.

**Unlinkable key rotation.** When keys rotate, the new key package
should not be linkable to the old one. Use re-randomizable keys
(similar to how zk-promises re-randomizes tickets).

**Hidden group size.** Pad the membership structure to hide the actual
number of members. A group of 5 looks identical to a group of 50.

> **ZK opportunity: Anonymous group credentials.** A user proves "I am
> a member of space X" without revealing their identity within the group.
> This is core to enabling anonymous posting, anonymous moderation
> (zk-promises), and anonymous transactions within a space.
>
> Construction: The space maintains a Merkle tree of member commitments.
> To act, a member proves in ZK:
> 1. "I know a secret `s` such that `Com(s)` is a leaf in the membership tree"
> 2. "My serial number `sn = PRF(s, nonce)` has not been used before" (prevents double-spending/actions)
> 3. Any predicate on their private state (reputation, rate limit, etc.)

---

## 4. Storage Layer — "What is accessed and when"

### What leaks

| Signal | What it reveals |
|---|---|
| Read patterns | Which CIDs a peer requests |
| Write patterns | When a peer stores new data |
| Access frequency | How active a space/document is |
| Storage location choice | Which backend a peer trusts |
| Data retention | How long data persists |

### Countermeasures

**Private Information Retrieval (PIR).** When fetching a DAG node from
a storage backend, the backend should not learn which CID was requested.
PIR protocols let a client fetch an item from a database without the
server knowing which item was fetched.

- **Computational PIR** — server does work proportional to DB size per
  query. Practical for moderate databases.
- **Multi-server PIR** — split the storage across non-colluding servers.
  Much faster, but requires trust assumption.

**Oblivious RAM (ORAM).** For local storage, if the device could be
compromised, ORAM hides access patterns even from someone observing
disk I/O.

**Write-only append.** For remote storage, only ever append — never
update or delete. This prevents the storage backend from learning about
the relationship between old and new versions.

> **ZK opportunity: Proof of storage.** A storage backend proves "I am
> faithfully storing your encrypted blob and have not tampered with it"
> using a proof of storage / proof of retrievability. The user doesn't
> have to trust the backend or fetch the data back to verify.

> **ZK opportunity: Private storage access control.** A user proves
> they have access to a storage bucket without revealing who they are
> or which space the data belongs to. The storage backend serves the
> data without knowing anything about the requester.

---

## 5. Identity Layer — "Who am I across spaces"

### What leaks

| Signal | What it reveals |
|---|---|
| Reused keys across spaces | Same person in multiple groups |
| Consistent behavior patterns | Stylometric identification |
| Timing correlation | Same person active in multiple spaces simultaneously |
| Device fingerprints | Hardware/software identity |

### Countermeasures

**Per-space identities.** Each space gets a fresh keypair. No
cryptographic linkage between identities across spaces.

**Anonymous credentials.** Use ZK-based credentials (like those in
zk-promises) to prove properties without revealing identity:
- "I am over 18" without revealing age or name
- "I have reputation > 100 in some space" without revealing which
- "I have not been banned from any space" without listing spaces

**Cross-space reputation portability.** A user proves "I have good
standing in at least 3 spaces" without revealing which spaces. This
enables trust bootstrapping without identity linkage.

> **ZK opportunity: Selective disclosure credentials.** Build on
> anonymous credentials (CL signatures, BBS+ signatures) to create
> a universal identity layer where users hold credentials and selectively
> disclose attributes via ZK proofs.
>
> Example: To join a new space, prove "I hold a valid KryptOS credential
> issued in the last year, I have not been banned from more than 2
> spaces, and my aggregate reputation is above threshold X." The space
> learns nothing else about you.

---

## 6. Application Layer — "What are users doing"

### What leaks

| Signal | What it reveals |
|---|---|
| Document types | What kind of app (chat, doc, kanban...) |
| Operation structure | CRDT operation shapes reveal app semantics |
| Interaction patterns | Turn-taking in chat, cursor movement |
| File sizes | Type of content (text vs image vs video) |
| Feature usage | Which app features a user engages with |

### Countermeasures

**Uniform operation encoding.** All CRDT operations, regardless of
document type, are serialized to a uniform envelope before encryption.
An observer can't distinguish a chat message from a code edit.

**Application-level padding.** Pad payloads to discrete size buckets
so that a chat message and a paragraph insert look the same.

**Batched multi-document operations.** When a user edits multiple
documents, bundle the operations into a single encrypted batch.
Prevents correlating "user edited doc A and doc B at the same time."

---

## 7. Transaction Layer — "Private value exchange"

Kunekt spaces aren't just for documents. If the protocol supports
private collaboration, it can also support private transactions:

**Private payments within spaces.** Members pay each other without
revealing amounts or parties to outsiders. Combine Kunekt's encrypted
channels with a shielded transaction protocol.

**Anonymous marketplace.** A space acts as a marketplace. Buyers and
sellers interact via anonymous credentials. ZK proofs verify payment
and delivery without revealing identities.

**Private voting / governance.** Space members vote on proposals.
ZK proofs ensure one-member-one-vote, tallies are correct, but
individual votes are secret.

> **ZK opportunity: Private state channels.** Two or more parties in a
> space run a private state channel for transactions. Each state update
> is a CRDT operation encrypted via MLS. Settlement proofs (ZK) can be
> posted to a chain without revealing the channel's content.

---

## How this maps to the roadmap

Each layer's countermeasures are addressed in a specific development
phase. Content encryption (Phase 1) and IP hiding (Phase 2) come
first. Anonymous identity (Phase 3) and full metadata protection
(Phase 4) follow. See [Development Phases](./roadmap.md) for details
and [Building Blocks](./building-blocks.md) for which existing
technologies implement each countermeasure.
