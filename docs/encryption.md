# Encryption: Group Ratchet Keys

All document content in Kunekt is end-to-end encrypted at the group level.
Only space members can decrypt. Storage backends, relay nodes, and network
observers see only opaque blobs.

This chapter covers *why* group encryption, *how* MLS works, and — most
critically — how a protocol designed for ordered delivery (MLS) is
reconciled with a protocol that has no ordering at all (Merkle-CRDTs).

---

## 1. Why Group Encryption

### The problem

A Kunekt space is a set of peers collaborating on shared documents. The
content must be readable only by current members. Anyone else — relay
operators, network observers, other Kunekt users — must see nothing
but opaque ciphertext.

### Why not pairwise encryption

The naive approach: each member encrypts each message to every other
member individually (like PGP or NIP-44 DMs). For a group of *n*
members, every operation produces *n - 1* ciphertexts. This is O(n)
per message in bandwidth, O(n^2) in aggregate state, and utterly
impractical for groups of even modest size. A 50-member space producing
100 edits/minute would generate 4,900 ciphertext copies per minute.

Worse, pairwise encryption has no notion of group membership change.
When a member is removed, every remaining member must stop encrypting
to that member — but there is no protocol-enforced mechanism to ensure
this happens. Key rotation requires N new key exchanges.

### Why a group ratchet

A group ratchet protocol gives every member the same symmetric key,
derived from a shared secret that ratchets forward on each membership
change. This provides:

- **O(1) ciphertext per message** — one encrypted payload, any member
  can decrypt.
- **Forward secrecy** — a compromised key cannot decrypt past messages.
  Old epoch secrets are deleted after ratcheting.
- **Post-compromise security** — after a key compromise, a single
  membership change (or periodic rotation) generates a fresh epoch
  secret that the attacker cannot derive, healing the group.
- **Efficient membership changes** — adding or removing a member costs
  O(log n) rather than O(n), thanks to the tree structure.

Kunekt uses **MLS (Messaging Layer Security, RFC 9420)** for group
key management. Each space is an MLS group.

---

## 2. MLS Primer

MLS is an IETF standard (RFC 9420) for group key agreement. This
section gives enough background for readers unfamiliar with the
protocol. For full details, see the RFC.

### Ratchet tree

MLS organizes group members as leaves of a binary tree. Each leaf holds
a member's public key. Interior nodes hold key pairs derived from their
children. The root of the tree is the shared group secret.

```
              [root]
             /      \
          [A,B]    [C,D]
          /   \    /   \
        (A)  (B) (C)  (D)    ← leaf nodes = members
```

When a leaf updates its key, only the nodes along the path from that
leaf to the root are recomputed — O(log n) operations.

### Epochs

Every membership change or key update produces a new **epoch**. An
epoch is a snapshot of the group state: the ratchet tree, the member
list, and a set of derived keys. Epochs are numbered sequentially:
0, 1, 2, ...

An MLS group begins at epoch 0 (creation). Each Commit that is
applied advances the epoch by one.

### Key schedule

Each epoch has an `epoch_secret` from which all keys for that epoch
are derived via a key derivation function (KDF):

```
epoch_secret
  ├── encryption_secret   → per-message symmetric keys
  ├── exporter_secret     → application-specific derived keys
  ├── authentication_secret
  ├── external_secret     → for external joins
  └── init_secret         → seeds the next epoch
```

Kunekt uses the `encryption_secret` to encrypt DAG node payloads and
the `exporter_secret` to derive application-specific keys (e.g., the
Nostr relay signing key).

### Proposals and Commits

MLS changes are made in two steps:

1. **Proposal** — a member proposes a change (Add, Remove, Update,
   ReInit, etc.). A Proposal does not change the group state by itself.
2. **Commit** — a member bundles one or more Proposals and applies
   them, producing a new epoch. The Commit contains the new ratchet
   tree information needed for all members to derive the new
   epoch secret.

Only a Commit advances the epoch. Multiple Proposals can be bundled
into a single Commit.

### Welcome messages

When a new member is added, the committer produces a **Welcome**
message alongside the Commit. The Welcome contains everything the
new member needs to initialize their view of the ratchet tree and
derive the current epoch secret. It is encrypted to the new member's
key package (their long-term or pre-published public key).

The flow:

```
1. New member publishes a KeyPackage (public key + capabilities)
2. Existing member creates a Proposal(Add) referencing that KeyPackage
3. Same or different member creates a Commit bundling the Add
4. Commit → broadcast to existing members
5. Welcome → sent to new member
6. Everyone is now in epoch N+1
```

---

## 3. MLS + Merkle-CRDT Reconciliation

This is the hardest integration problem in the Kunekt protocol.

MLS was designed for a world with a **Delivery Service** — a server
that sequences Commits so all members see them in the same order.
Merkle-CRDTs have no server, no ordering, no coordination. Two peers
can independently create operations and sync later in any order.

This section describes how these two models are reconciled.

### The ordering problem

MLS Commits **must** be applied in a total order. If member A and
member B both issue a Commit at epoch 5, the group cannot apply both —
each Commit produces a different epoch 6 with a different ratchet tree.
Applying A's Commit then B's (or vice versa) produces different group
states.

CRDTs, by design, do not require ordering. Two concurrent operations
merge deterministically regardless of the order they are received.

A naive approach — "just treat MLS Commits as CRDT operations" —
does not work. MLS Commits are not commutative.

### Solution: MLS operations as a causal log in the root document

MLS operations (Proposals, Commits, Welcomes) are stored as entries
in a **special ordered log** within the space's root document. This
log is itself a CRDT (an append-only Merkle-DAG), but its *interpretation*
imposes an order.

The key insight: the Merkle-DAG already provides **causal ordering**.
If node X is an ancestor of node Y, then X happened before Y. If
neither is an ancestor of the other, they are concurrent.

```
MLS log in the root document DAG:

     [epoch 0: init]
           │
     [epoch 1: Add(Bob)]     ← Commit by Alice
           │
     [epoch 2: Add(Carol)]   ← Commit by Bob
          / \
  [epoch 3a]  [epoch 3b]     ← concurrent Commits: FORK
         \  /
     [epoch 3: resolved]     ← deterministic winner
           │
     [epoch 4: ...]
```

### Commit conflict resolution

When two members simultaneously issue MLS Commits (e.g., Alice adds
Dave while Bob removes Eve), the Merkle-DAG records both as
concurrent nodes — a fork. Both are valid at the DAG level, but only
one can be applied to the MLS state.

**Resolution rule:** When a peer encounters concurrent Commits, it
applies a deterministic tiebreaker:

1. Compare the CIDs (content hashes) of the two Commit nodes.
2. The Commit with the **lexicographically lower CID** wins.
3. The losing Commit's Proposals are **re-proposed** in the next
   epoch as new Proposals, to be included in a future Commit.

Because CIDs are deterministic hashes, every peer that encounters the
same fork reaches the same resolution — no coordination needed.

```
Example:

  Epoch 5
    ├── Commit A (CID: bafy...3a) — Add(Dave)
    └── Commit B (CID: bafy...7f) — Remove(Eve)

  bafy...3a < bafy...7f  →  Commit A wins  →  epoch 6 includes Dave

  Commit B's Remove(Eve) is re-proposed as a Proposal in epoch 6.
  The next Commit (epoch 6 → 7) can include it.
```

This means a losing Commit's effect is **delayed, not lost**. The
membership change will happen, just one epoch later.

**Edge cases:**

- **Three-way or n-way forks:** Same rule applies recursively. Sort
  all concurrent Commits by CID, apply the lowest, re-propose the
  rest.
- **Conflicting Commits** (e.g., one adds X, another removes X):
  Both are re-proposed. The next committer sees both Proposals and
  resolves the conflict at the application level (e.g., removal takes
  precedence, or the space's policy decides).
- **Self-referential conflicts** (a Commit that removes the member
  who issued a concurrent Commit): The losing Commit is simply
  discarded — the member who issued it is no longer in the group and
  cannot re-propose.

### Epoch key derivation for DAG nodes

Each DAG node payload is encrypted with the symmetric key derived from
the MLS epoch that was current when the node was created. To enable
decryption, the epoch number is stored **in plaintext** alongside the
encrypted payload:

```
DAG node (as stored/transmitted):

┌──────────────────────────────────────────┐
│  CID: bafy...                            │  ← plaintext (hash of this node)
│  children: [bafy..., bafy...]            │  ← plaintext (DAG structure)
│  epoch: 7                                │  ← plaintext (which key to use)
│  encrypted_payload: 0x8a3f...            │  ← ciphertext (CRDT operation)
│  nonce: 0xb7c2...                        │  ← per-node random nonce
└──────────────────────────────────────────┘
```

A recipient decrypts by:

1. Reading the `epoch` field.
2. Looking up the symmetric key for that epoch from their local MLS
   state (or key cache — see section 6).
3. Decrypting `encrypted_payload` with that key and the `nonce`.

**Why expose the epoch number?** It reveals only *when* (in terms of
group membership generation) a node was created, not *what* it contains.
The alternative — trying every epoch key until one works — is
impractical for long-lived spaces with many epochs.

### Epoch transitions during offline editing

A core scenario: Alice goes offline and makes 50 edits. While she is
offline, Bob adds Carol to the space, advancing the epoch from 7 to 8.
Alice's 50 DAG nodes are encrypted with epoch 7 keys.

On reconnect:

1. Alice syncs the root document DAG, discovers the new Commit
   (epoch 7 → 8).
2. Alice processes the Commit, derives the new epoch 8 keys.
3. Alice's 50 locally-created nodes remain encrypted with epoch 7.
   She does **not** re-encrypt them — they are already in the DAG
   with epoch 7 CIDs.
4. Other members can still decrypt Alice's nodes because they retain
   epoch 7 keys in their local key cache.
5. Alice's new edits going forward use epoch 8 keys.

This means a space will always have some DAG nodes encrypted under
older epochs. This is expected and correct. Members retain old epoch
keys for decryption (see section 6: Encryption at Rest).

**Security implication:** Carol (added at epoch 8) does NOT have
epoch 7 keys. She cannot decrypt Alice's 50 offline edits directly.
She *can* see the CRDT state that results from applying all operations
(including Alice's), because the CRDT state is reconstructed by peers
who have the keys and shared via the CRDT's normal merge semantics.
See section 7 (Forward Secrecy Semantics in CRDTs) for a detailed
discussion.

---

## 4. What Gets Encrypted

### DAG node payloads: encrypted

Every CRDT operation payload — text insertions, metadata changes,
chat messages, votes — is encrypted before leaving the local peer.
The ciphertext is the only form that ever touches the network or
storage backends.

### CIDs and DAG structure: plaintext

The node's CID (content hash) and its list of children CIDs remain
in plaintext. This is a deliberate design choice:

- **Relay-assisted traversal:** Untrusted relays can serve DAG nodes
  by CID without being able to read their contents. A peer requests
  "give me node bafy...abc" and the relay can look it up — even though
  the relay cannot decrypt the payload.
- **Efficient sync:** The Merkle-CRDT sync protocol compares root CIDs
  and walks the DAG structure to find missing nodes. This must work
  without decryption, because the relay/transport layer does not have
  keys.
- **CIDs reveal nothing about content:** A CID is a hash of the
  *encrypted* payload plus structural metadata. It does not leak
  information about the plaintext. Two identical plaintext operations
  produce different CIDs (because of the random nonce in the
  encryption).

**What CIDs do leak:** An observer who sees the DAG structure learns
the *shape* of activity — how many operations, causal relationships
between them, branching and merging patterns. This is metadata, and
it is addressed by the uniform envelope and timing defenses described
in the Nostr integration chapter.

### MLS metadata: partially visible

Some MLS-related metadata is necessarily visible:

| Field | Visibility | Rationale |
|---|---|---|
| Epoch number on DAG nodes | Plaintext | Recipients need it to select the decryption key |
| MLS group ID | Plaintext (same as space ID) | Identifies the group for key lookup |
| MLS Commit/Welcome messages | Encrypted payloads in root doc | Their *existence* is visible (they are DAG nodes), their content is encrypted |
| Ratchet tree structure | Inside MLS messages (encrypted) | Not visible to non-members |
| Member count (from tree) | Inferable from Commit sizes | Partial leak — mitigated by padding |

**Tradeoff:** Exposing the epoch number is a small metadata leak
(observers learn when membership changes occurred) in exchange for
efficient decryption. Without it, decryption would require trial
decryption with every epoch key — O(epochs) per node.

### Uniform envelope format

All encrypted payloads are padded to fixed-size buckets before
transmission:

```
Bucket sizes: 256 B, 1 KB, 4 KB, 16 KB, 64 KB

Padding:
  plaintext (variable) → encrypt → pad to next bucket boundary
```

An observer cannot distinguish a 3-byte chat message from a 900-byte
document edit — both appear as 1 KB blobs. Combined with cover traffic
(dummy nodes that are also valid-looking 1 KB blobs), this defeats
size-based traffic analysis.

---

## 5. Key Lifecycle

### Space creation: epoch 0

The space creator initializes a new MLS group and becomes the sole
member. This is epoch 0. The creator's device generates:

- An MLS credential (identity key for this space)
- A KeyPackage (used if others need to add this member to sub-groups)
- The epoch 0 secret, from which all epoch 0 keys are derived

```
Creator's device:
  mls_group = MlsGroup::new(ciphersuite, credential)
  epoch_0_secret = mls_group.epoch_secret()
  encryption_key = KDF(epoch_0_secret, "encryption")
  nostr_sk = KDF(epoch_0_secret, "nostr-relay-signing")
```

### Member join: Welcome + Commit → epoch N+1

Adding a new member:

1. The new member publishes a **KeyPackage** (out-of-band or via a
   Nostr event).
2. An existing member creates a Proposal(Add) referencing the
   KeyPackage.
3. The same or another member creates a Commit including the Add
   proposal.
4. The Commit is recorded as a DAG node in the root document.
5. A Welcome message is also recorded (encrypted to the new member).
6. All existing members process the Commit and derive epoch N+1 keys.
7. The new member processes the Welcome and derives epoch N+1 keys.

**Forward secrecy:** The new member receives epoch N+1 keys but NOT
any prior epoch keys. They cannot decrypt DAG nodes from epochs
0 through N. They can see the *current CRDT state* (the result of
all operations), but not the individual historical operations. See
section 7.

### Member removal: Commit → epoch N+1

Removing a member:

1. An authorized member creates a Proposal(Remove) for the target.
2. A Commit including the Remove is recorded in the root document.
3. Remaining members process the Commit and derive epoch N+1 keys.
4. The removed member does not receive the Commit's UpdatePath —
   they cannot derive epoch N+1 keys.

**Post-compromise security:** Even if the removed member retained
epoch N keys, all future content is encrypted under epoch N+1 (and
beyond), which they cannot derive. The ratchet tree path from their
former leaf to the root has been re-keyed.

### Periodic rotation

MLS supports key updates without membership changes. Any member can
issue an Update proposal, which re-keys their leaf and the path to
the root. This provides:

- **Healing after undetected compromise:** If a member's device was
  compromised and later recovered, an Update re-establishes security.
- **Limiting window of exposure:** Even without known compromise,
  periodic rotation limits how much content a single key can decrypt.

Rotation frequency is configurable per space. Recommended defaults:

| Space sensitivity | Rotation interval |
|---|---|
| Standard | Every 24 hours or every 100 operations, whichever comes first |
| High security | Every 1 hour or every 20 operations |
| Low activity | On membership changes only |

### Key derivation for Nostr relay signing

The Nostr signing key for a space is derived deterministically from
the MLS epoch secret:

```
nostr_sk = KDF(mls_epoch_secret, "nostr-relay-signing")
nostr_pk = secp256k1_pubkey(nostr_sk)
```

Every member independently derives the same key. Any member can sign
Nostr events on behalf of the space. The key rotates automatically
with each epoch change, so removed members lose the ability to sign.

See Nostr Integration for a full discussion of signing
key options and their tradeoffs.

---

## 6. Encryption at Rest

### Local storage

A peer's local database contains:

- DAG nodes for all subscribed documents (encrypted payloads)
- MLS group state (ratchet tree, epoch secrets)
- Cached epoch keys for past epochs

All local storage is encrypted with a key derived from the device's
**root secret** — a high-entropy secret stored in the platform's
secure enclave (Keychain on macOS/iOS, Keystore on Android, Secret
Service on Linux) or derived from a user passphrase via Argon2.

```
root_secret (in secure enclave)
  └── local_storage_key = KDF(root_secret, "local-db-encryption")
        └── encrypts SQLite / sled database at rest
```

### Stored ciphertext = transmitted ciphertext

DAG nodes are stored on disk in the same encrypted form as they are
transmitted over the network. There is no decryption-then-re-encryption
step for storage. Benefits:

- **Simplicity:** One code path for encryption, one ciphertext format.
- **Verifiability:** The CID of a stored node matches the CID of the
  same node on other peers and on relays, because the ciphertext is
  identical.
- **Defense in depth:** If the local storage encryption is bypassed
  (e.g., the device is stolen but the secure enclave is intact), the
  attacker still sees only MLS-encrypted payloads, which require the
  MLS epoch keys to decrypt.

### Epoch key caching

Members must retain keys from past epochs to decrypt old DAG nodes.
A member who joins at epoch 5 and the space is now at epoch 12 has
keys for epochs 5 through 12. They may need any of these to decrypt
nodes created in those epochs.

Key cache policy:

- **Keep all epoch keys since join.** Epoch keys are small (32 bytes
  each). Even a space with 10,000 epoch changes accumulates only
  ~320 KB of key material.
- **Epoch keys are never transmitted.** They exist only in local
  storage, encrypted under the local storage key.
- **On device loss:** The member must be re-added to the space (a new
  KeyPackage, a new Welcome). They receive the current epoch key only.
  Old epoch keys are lost — old DAG nodes on the new device cannot be
  individually decrypted. The CRDT state (the result of all operations)
  is still available because other peers can share the materialized
  state.

---

## 7. Forward Secrecy Semantics in CRDTs

CRDTs and forward secrecy interact in a way that deserves careful
explanation, because the naive interpretation ("new members can't see
old content") is both true and misleading.

### The tension

CRDTs accumulate state. A CRDT's current value is the result of
applying ALL operations in its history, including operations from
before a new member joined. The Automerge document you see now
reflects every keystroke ever made.

Forward secrecy means: a new member can derive the current epoch key
but NOT prior epoch keys.

These two properties seem contradictory: the CRDT state is the *sum*
of all history, but the new member cannot decrypt the historical
operations.

### The resolution: state vs. history

Kunekt distinguishes between the **document state** (the current
value of the CRDT) and the **operation history** (the individual
DAG nodes that built that state).

- **Document state** = the current merged CRDT value. This is what
  users see — the current text, the current chat log, the current
  configuration. The state is reconstructed by applying operations
  and can be shared as a snapshot.
- **Operation history** = the individual DAG nodes with their
  encrypted CRDT operations. This is the edit log — who changed
  what and when (to the extent that CRDT operations carry that
  information).

A new member joining at epoch N+1:

1. **Can** see the current document state — other peers share the
   CRDT state through normal sync. The state itself is not encrypted
   per-epoch; it is the result of applying decrypted operations.
2. **Cannot** individually decrypt DAG nodes from epochs 0 through N.
   They cannot inspect the fine-grained edit history — which character
   was inserted when, which operation was concurrent with which other.
3. **Can** decrypt all DAG nodes from epoch N+1 onward.

### This is a design choice

This behavior is deliberate:

- **The document is the state, not the log.** Users care about the
  current document. The edit history is an implementation detail of
  CRDTs, not a user-facing feature.
- **Protecting history protects metadata.** Even if the document
  content is eventually shared via the CRDT state, the fine-grained
  *pattern* of edits (timing, frequency, which parts were edited,
  concurrent editing behavior) is sensitive metadata that forward
  secrecy protects.
- **Least privilege.** A new member should see what they need to
  participate going forward. Granting access to the full edit
  history exceeds that requirement.

### Opt-in history sharing

Some spaces may *want* new members to see full history — for example,
a knowledge base where the edit log is itself valuable. This is
supported as an explicit opt-in:

1. An existing member (or a quorum, per space policy) decides to
   share history.
2. Historical DAG nodes are re-encrypted under the current epoch key.
3. The re-encrypted nodes are published as new DAG entries,
   referencing the originals.
4. The new member can now decrypt the historical operations.

This is **not the default**. It requires an explicit space-level
policy setting and an active re-encryption step by an existing member
who holds the old epoch keys.

---

## 8. OpenMLS Integration Details

### Crate

Kunekt uses the [`openmls`](https://github.com/openmls/openmls) crate,
a Rust implementation of RFC 9420. OpenMLS is modular — it defines
traits for pluggable backends (crypto, key store, delivery).

### Configuration

| Parameter | Choice | Rationale |
|---|---|---|
| Ciphersuite | `MLS_128_DHKEMX25519_AES128GCM_SHA256_Ed25519` | X25519 for key agreement, AES-128-GCM for encryption, Ed25519 for signatures. Well-supported, efficient, no RSA baggage. |
| Credential type | `BasicCredential` (Phase 1-2), custom ZK credential (Phase 3+) | Basic credentials carry an opaque identity. ZK credentials will allow proving membership without revealing which member. |
| Protocol version | MLS 1.0 | Only version specified by RFC 9420. |

### Custom MLS backends

OpenMLS requires three backend components. Kunekt provides custom
implementations for each, backed by the Merkle-CRDT layer:

**KeyStore** — persists key material (KeyPackages, ratchet tree
state, epoch secrets).

```rust
/// KeyStore backed by local encrypted storage
impl OpenMlsKeyStore for KunektKeyStore {
    type Error = KeyStoreError;

    fn store<V: MlsEntity>(&self, k: &[u8], v: &V) -> Result<(), Self::Error> {
        // Serialize, encrypt with local_storage_key, write to local DB
    }

    fn read<V: MlsEntity>(&self, k: &[u8]) -> Option<V> {
        // Read from local DB, decrypt, deserialize
    }

    fn delete<V: MlsEntity>(&self, k: &[u8]) -> Result<(), Self::Error> {
        // Remove from local DB (e.g., after epoch key is superseded)
    }
}
```

**DeliveryService** — in standard MLS, this is a server that receives
Commits and distributes them to all members. In Kunekt, there is no
server. The Merkle-CRDT sync layer *is* the delivery service.

```rust
/// "Delivery" via Merkle-CRDT root document
///
/// MLS Commits and Welcomes are serialized as DAG node payloads
/// in the space's root document. When a peer syncs the root
/// document's DAG, it discovers new MLS messages and processes them.
impl MlsDelivery for CrdtDeliveryService {
    fn send_commit(&self, commit: MlsCommit) -> Result<(), DeliveryError> {
        // Serialize Commit as a root document CRDT operation
        // Record as a new DAG node in the root document's MerkleCrdt
        // Sync propagates it to other peers
    }

    fn send_welcome(&self, welcome: MlsWelcome, recipient: &KeyPackageRef)
        -> Result<(), DeliveryError>
    {
        // Serialize Welcome, store in root document DAG
        // The Welcome is encrypted to the recipient's KeyPackage,
        // so it is safe to store in the shared DAG
    }

    fn recv(&self) -> Vec<MlsMessage> {
        // Walk the root document DAG for new MLS-typed nodes
        // since last processed epoch
        // Apply conflict resolution (section 3) for concurrent Commits
    }
}
```

**CryptoProvider** — the cryptographic backend. Kunekt uses
OpenMLS's `openmls_rust_crypto` provider (based on the RustCrypto
crates) for a pure-Rust, `no_std`-compatible implementation.

### Processing flow

The full lifecycle of a DAG node from creation to decryption:

```
SENDER:
  1. Application produces a CRDT operation (e.g., Automerge change)
  2. Serialize the operation
  3. Look up current MLS epoch and derive encryption key
  4. Encrypt: ciphertext = AES-GCM(encryption_key, nonce, plaintext)
  5. Build DAG node: { children, epoch, ciphertext, nonce }
  6. Compute CID = Hash(node)
  7. Record in local MerkleCrdt (plaintext state updated locally)
  8. Transmit encrypted node to relays / peers

RECIPIENT:
  1. Receive DAG node (via sync)
  2. Verify CID matches content (self-verifying)
  3. Read epoch number from node
  4. Look up epoch key from local MLS state / key cache
  5. Decrypt: plaintext = AES-GCM-Open(key, nonce, ciphertext)
  6. Deserialize CRDT operation
  7. Apply to local CRDT state
```

### Error handling

| Scenario | Behavior |
|---|---|
| Unknown epoch (node from future epoch) | Buffer the node. Process pending MLS Commits first to advance local epoch. Retry decryption. |
| Missing epoch key (node from before join) | Cannot decrypt. Discard the individual operation. CRDT state is still obtained via state sync with peers who have the key. |
| Corrupted ciphertext | CID verification fails (hash mismatch). Node is rejected. |
| MLS Commit from removed member | Commit is invalid per MLS rules. Ignored. |
| Concurrent Commits (fork) | Deterministic conflict resolution (section 3). Losing Commit's proposals re-queued. |

---

## Summary

The encryption layer sits between the sync layer (Merkle-CRDTs) and
the storage/transport layer. It ensures that:

1. All content is encrypted with group keys — only space members
   can read it.
2. Keys rotate on every membership change — forward secrecy and
   post-compromise security are maintained.
3. MLS's ordering requirements are satisfied by the Merkle-DAG's
   causal ordering plus deterministic conflict resolution — no
   central server needed.
4. Metadata exposure is minimized — epoch numbers are visible,
   but payload content, DAG node sizes (after padding), and member
   identities are protected.
5. Old content remains decryptable by members who were present
   during those epochs, while new members see the CRDT state
   without accessing the operation-level history.

For how encrypted DAG nodes are stored on Nostr relays, see
Nostr Integration. For the anonymity layer that
protects metadata beyond encryption, see
[Privacy Layers](threat-model.md).
