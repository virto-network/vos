# User Journey: From First Launch to Private Everything

> This document traces two parallel journeys — an **end-user** and an
> **app developer** — through every interaction with Kunekt. Each step
> reveals required features, protocol components, and where ZK
> technology is essential.
>
> Kunekt is the full implementation of
> [KryptOS RFP#000](https://codeberg.org/kusama-zk/RFPs/src/branch/main/rfp/000-privacy-os.md):
> the SDK, the private data store, and the private communications
> protocol — unified under one system.

---

## Phase 0: Installation & Identity Bootstrap

### End-user: "I just installed this app"

```
User installs a Kunekt-based app (chat, docs, marketplace, whatever).
There is no sign-up form. No email. No phone number. No username.
```

**What happens underneath:**

1. **Local key generation.** The device generates a root secret key.
   Everything derives from this: per-space keys, anonymous credentials,
   storage encryption keys. The root key never leaves the device.

2. **Device credential.** A self-issued anonymous credential is created.
   It contains no identifying information — just a commitment to the
   root secret. This is the user's "passport" to the Kunekt network.

3. **Network bootstrap.** The app discovers relay nodes / mix entry
   points via a hardcoded list, a DHT, or a blockchain registry.
   Connection is established through the anonymity layer — the relay
   does not learn the user's IP (onion routing or mix network).

4. **Local store initialization.** An encrypted local database is
   created (key derived from root secret + device PIN/biometric).
   All future state lives here.

**Features revealed:**
- `F-IDENTITY-001` Key derivation framework (root → per-space → per-session)
- `F-IDENTITY-002` Self-issued anonymous credentials (no registration authority)
- `F-TRANSPORT-001` Anonymity network bootstrap (mix/onion node discovery)
- `F-STORAGE-001` Encrypted local store

**ZK intersection:**
- The device credential is a ZK-compatible commitment. The user will
  later prove properties about it (age, membership, reputation) without
  revealing it.

---

### Developer: "I want to build a private app"

```rust
// The entire SDK is one dependency
use kunekt::prelude::*;

// Initialize — handles key generation, store, network bootstrap
let node = Kunekt::init(Config::default()).await?;
```

**SDK requirements:**
- `S-SDK-001` Single crate, single import, privacy by default
- `S-SDK-002` Config allows tuning privacy/performance tradeoffs
  (e.g. `PrivacyLevel::Maximum` uses mix network + PIR,
  `PrivacyLevel::Fast` uses direct connections + standard fetch)
- `S-SDK-003` Async runtime agnostic (tokio, smol, WASM)
- `S-SDK-004` `no_std` core with `std` convenience layer

---

## Phase 1: Creating a Space

### End-user: "I want a private group for my team"

```
User taps "Create Space". Gives it a name (local-only, never sent
to anyone unencrypted). Gets a shareable invite link/QR code.
```

**What happens underneath:**

1. **Space document creation.** A root document (CRDT) is created
   describing the space: name, settings, document list. This is
   the first node in the space's Merkle-DAG.

2. **MLS group initialization.** An MLS group is created with the
   user as the sole member. Epoch 0 keys are derived.

3. **Anonymous credential for space.** A space-scoped credential is
   derived from the root secret. This credential commits to a
   fresh space-specific secret — unlinkable to the root identity
   or to credentials in other spaces.

4. **Membership Merkle tree.** A Merkle tree is initialized with the
   creator's credential commitment as the first leaf. This tree
   will be used for ZK membership proofs.

5. **Invite token generation.** An invite is a signed capability:
   "the bearer may join space X." It contains the space's public
   parameters (MLS group info, membership tree root, relay hints)
   encrypted under a one-time key. The invite link contains this
   key.

6. **Storage allocation.** The space's encrypted DAG nodes are
   pushed to chosen backend(s) — local, relay, DA layer.

**Features revealed:**
- `F-SPACE-001` Space creation with root CRDT document
- `F-SPACE-002` MLS group lifecycle management
- `F-SPACE-003` Space-scoped anonymous credentials
- `F-SPACE-004` ZK membership tree
- `F-SPACE-005` Invite token generation (capability-based)
- `F-STORAGE-002` Multi-backend encrypted storage

**ZK intersection:**
- Membership tree enables ZK membership proofs for all future actions
- Invite tokens could carry ZK proofs of the inviter's authority
  ("I am an admin of this space" without revealing which admin)

---

### Developer: "I want to create a custom space type"

```rust
// Define what documents a space contains
let space = node.create_space(SpaceConfig {
    name: "Project Alpha",
    documents: vec![
        DocTemplate::new::<ChatCrdt>("general"),
        DocTemplate::new::<TextCrdt>("design-doc"),
        DocTemplate::new::<KanbanCrdt>("tasks"),
    ],
    // Moderation: anonymous with zk-promises
    moderation: Moderation::Anonymous {
        reputation_threshold: 10,
        rate_limit: RateLimit::leaky_bucket(100, Duration::from_secs(60)),
    },
    // Storage: replicate to relay + DA layer
    storage: StoragePolicy::replicate(vec![
        Backend::Relay("wss://relay.example.com"),
        Backend::DaLayer("polkadot-da"),
    ]),
    privacy: PrivacyLevel::Maximum,
})?;

let invite = space.create_invite(InvitePolicy::SingleUse)?;
println!("Share this: {}", invite.to_link());
```

**SDK requirements:**
- `S-SDK-010` Custom CRDT document types via trait
- `S-SDK-011` Pluggable moderation policies
- `S-SDK-012` Pluggable storage backends
- `S-SDK-013` Invite generation with policy (single-use, multi-use, expiring)

---

## Phase 2: Joining a Space

### End-user: "Someone shared a link with me"

```
User receives an invite link. Taps it. The app opens.
They're in the space immediately. No approval flow.
```

**What happens underneath:**

1. **Invite decryption.** The app extracts the one-time key from the
   link, decrypts the invite to get space parameters.

2. **Credential derivation.** A fresh space-scoped credential is
   derived. No linkage to the user's other spaces.

3. **MLS join.** The user creates an MLS KeyPackage and submits it
   (via the anonymity layer) to an existing member or relay. An
   existing member issues an MLS Welcome message. The new member
   now has epoch keys and can decrypt current content.

4. **Membership tree update.** The new member's credential commitment
   is added to the membership Merkle tree. All members update their
   local copy (this is itself a CRDT operation on the space root
   document).

5. **Initial sync.** The new member fetches the document DAGs from
   storage backends. Walks from current roots, fetches all nodes,
   decrypts, applies CRDT operations. The full current state
   materializes locally.

6. **Forward secrecy boundary.** The new member cannot decrypt DAG
   nodes from before their MLS epoch. They see the current state
   (which is the result of all operations) but not the history of
   who edited what. This is a feature, not a limitation.

**Features revealed:**
- `F-JOIN-001` Invite redemption flow
- `F-JOIN-002` MLS Welcome / KeyPackage exchange
- `F-JOIN-003` Membership tree update (CRDT)
- `F-JOIN-004` Cold sync (full DAG fetch for new joiners)
- `F-JOIN-005` Forward secrecy enforcement (no pre-join history)

**ZK intersection:**
- Join can require a ZK proof: "I hold a valid credential meeting
  the space's entry requirements" (e.g. minimum reputation from
  other spaces, not banned from more than N spaces)
- The membership tree update is the foundation for all anonymous
  actions in the space

---

## Phase 3: Real-Time Collaboration

### End-user: "We're editing a document together"

```
Three users have the same doc open. Alice types a sentence. Bob fixes
a typo in paragraph 2. Carol adds a comment. Everyone sees everything
converge in real-time. Nobody knows who typed what (if the space uses
anonymous mode).
```

**What happens underneath (per keystroke/operation):**

1. **CRDT operation.** The app's CRDT (e.g. Automerge) generates an
   operation: `Insert('a', pos=42)`.

2. **Merkle-DAG recording.** The operation is recorded as a DAG node
   in the document's Merkle-Clock. The node's children are the
   current roots. A new CID is computed.

3. **Encryption.** The serialized DAG node is encrypted with the
   current MLS epoch key. Padded to a uniform size.

4. **Broadcast.** The encrypted blob + CID are sent to connected
   peers and/or pushed to storage backends. Sent through the
   anonymity layer (mix network or onion routing).

5. **Reception.** Other peers receive the blob, decrypt, verify
   CID, apply the CRDT operation to their local state. The UI
   updates.

6. **Batching optimization.** For real-time typing, operations are
   batched (e.g. every 100ms) into a single DAG node. This reduces
   overhead and hides per-keystroke timing.

**Features revealed:**
- `F-COLLAB-001` Real-time CRDT sync
- `F-COLLAB-002` Operation batching (configurable interval)
- `F-COLLAB-003` Uniform-size encrypted envelopes
- `F-COLLAB-004` Anonymous broadcast (sender unlinkable to operation)
- `F-COLLAB-005` Presence awareness (optional, privacy-degrading)

**ZK intersection:**
- In anonymous mode, each batch of operations carries a ZK proof:
  "I am a member of this space AND my rate limit allows this AND I
  am not banned." This is the zk-promises `ShowAuthorized` proof.
- Other members verify the proof but learn nothing about which
  member authored the operations.
- **Critical tradeoff:** generating this proof takes ~300-700ms.
  For real-time editing, amortize over batches (one proof per
  5-second batch) or use a session token: prove once at session
  start, then use a short-lived token for the session.

---

## Phase 4: Offline Editing & Reconnection

### End-user: "I edited on the plane, now I'm back online"

```
User edited the document while offline for 3 hours. They come back
online. Their changes merge automatically. No conflicts, no manual
resolution. Other people's changes from the same period also appear.
```

**What happens underneath:**

1. **Offline edits.** All operations were recorded locally in the
   Merkle-DAG. The local clock advanced, new roots were created.
   Everything is stored encrypted in the local database.

2. **Reconnection.** The peer re-establishes connections through the
   anonymity layer. Discovers current root CIDs from other peers
   or storage backends.

3. **Bidirectional sync.** The Merkle-CRDT anti-entropy algorithm
   runs:
   - Fetch remote roots → walk DAGs → find missing nodes → fetch →
     apply in causal order
   - Push local roots → remote peers do the same

4. **MLS catch-up.** If MLS epoch changed while offline (members
   joined/left), the peer processes queued MLS Commit messages
   to get current keys.

5. **Callback scan (if anonymous mode).** If zk-promises is active,
   the peer scans the callback bulletin board for any callbacks
   issued while offline. Processes them (reputation changes, etc.)
   before resuming.

**Features revealed:**
- `F-OFFLINE-001` Full offline editing capability
- `F-OFFLINE-002` Automatic conflict-free merge on reconnect
- `F-OFFLINE-003` MLS epoch catch-up
- `F-OFFLINE-004` zk-promises callback catch-up

---

## Phase 5: Moderation & Accountability

### End-user: "Someone is spamming — I want to report them"

```
A moderator flags a post. The poster's reputation decreases. If it
drops below threshold, they can no longer post. The moderator never
learns who the poster is. The poster cannot ignore the penalty.
```

**What happens underneath:**

1. **Report.** The moderator selects a post (which is a DAG node
   with an attached anonymous credential proof).

2. **Callback issuance.** The moderator issues a zk-promises
   callback against the post's ticket: `Call(tik, "reduce_rep(10)")`.
   This is posted to the moderation bulletin board (a CRDT
   document in the space).

3. **Callback delivery.** The bulletin board syncs to all members
   via Merkle-CRDT.

4. **Callback processing.** The anonymous poster (and only they)
   recognizes their ticket in the bulletin. During their next
   `ScanOne`, they process the callback: their local zk-object
   updates (reputation -= 10). They produce a ZK proof that the
   update was applied correctly.

5. **Enforcement.** On the poster's next action, their ZK proof
   must show the updated (lower) reputation. If below threshold,
   the proof fails and the action is rejected by other members.

6. **Banning.** If reputation reaches 0, the callback sets a ban
   flag. The user can no longer produce a valid `ShowAuthorized`
   proof. They're effectively removed without anyone knowing who
   was banned.

**Features revealed:**
- `F-MOD-001` Anonymous reporting
- `F-MOD-002` Callback-based reputation system (zk-promises)
- `F-MOD-003` Bulletin board as CRDT document
- `F-MOD-004` Rate limiting via ZK-proven leaky bucket
- `F-MOD-005` Anonymous banning

**ZK intersection:**
- This entire flow is ZK. Every step involves a zero-knowledge proof.
- The bulletin board is the critical shared state — it must be
  available and consistent. In a fully P2P setting, it's a CRDT
  synced via Merkle-CRDT. For stronger guarantees, anchor it to a
  chain.

---

## Phase 6: Cross-Space Interactions

### End-user: "I want to join a new space but I have no reputation there"

```
User has been active in Space A for months with good reputation. They
want to join Space B which requires minimum reputation to post. They
prove their standing without revealing which space it comes from or
who they are in Space A.
```

**What happens underneath:**

1. **Reputation attestation.** The user's zk-object in Space A
   includes their reputation score. They create a ZK proof:
   "I hold a valid credential in *some* space where my reputation
   is above 50." The proof reveals nothing about Space A.

2. **Cross-space credential.** Using a credential scheme that supports
   selective disclosure (BBS+ signatures), the user presents:
   - Proof of reputation threshold
   - Proof they have not been banned from more than N spaces
   - Proof their account is older than T days
   All without revealing which spaces, which account, or any
   linkable identifier.

3. **Space B admission.** Space B's admission policy verifies the
   proofs. The user is added to Space B's membership tree with a
   completely fresh credential. No link to Space A.

**Features revealed:**
- `F-CROSS-001` Cross-space reputation portability (ZK)
- `F-CROSS-002` Selective disclosure credentials (BBS+/CL)
- `F-CROSS-003` Configurable admission policies
- `F-CROSS-004` Unlinkable multi-space identity

**ZK intersection:**
- This is pure ZK. Without it, you either link identities (privacy
  failure) or start from zero in every space (usability failure).
- The credential scheme (BBS+, CL signatures, or a custom scheme
  over the zk-promises framework) is a core protocol component.

---

## Phase 7: Private Data Store

### End-user: "I want to store files that only I can access"

```
User stores personal files — medical records, financial documents,
photos. They're encrypted and distributed. No single storage
provider can read them or even know they exist. The user can share
specific files with specific spaces by granting access.
```

**What happens underneath:**

1. **File as document.** A file is a single-writer CRDT document
   (just the user). It has its own Merkle-DAG (versions = edits).

2. **Encryption.** Encrypted with a key derived from the user's
   root secret + file ID. Not tied to any MLS group.

3. **Erasure coding + distribution.** The encrypted file is split
   into fragments via erasure coding (e.g. k-of-n: any k fragments
   can reconstruct, n are stored). Fragments are distributed across
   multiple storage backends.

4. **PIR retrieval.** When the user fetches their own file, they
   use PIR so the storage backend doesn't learn which fragments
   were requested.

5. **Selective sharing.** To share a file with a space, the user
   re-encrypts the file key under the space's MLS group key and
   publishes the re-encrypted key as a DAG node in the space.
   Members can now decrypt the file. Revoking access = rotating
   the file key and not re-sharing.

**Features revealed:**
- `F-STORE-001` Personal encrypted file storage
- `F-STORE-002` Erasure coding for redundancy
- `F-STORE-003` PIR for private retrieval
- `F-STORE-004` Selective sharing via proxy re-encryption
- `F-STORE-005` Access revocation

**ZK intersection:**
- Proof of storage: user periodically challenges backends to prove
  they still hold the fragments, without downloading them.
- Proof of access: when sharing, prove "I am the owner of this file"
  without revealing which file or which user.

---

## Phase 8: Private Transactions

### End-user: "I want to pay someone in the space"

```
User sends a payment to another space member. The amount, sender,
and receiver are hidden from everyone else. The receiver can verify
they received the correct amount.
```

**What happens underneath:**

1. **Payment channel.** A private state channel exists between the
   two parties (or is created on-demand). The channel state is a
   CRDT tracking balances.

2. **Transfer operation.** A CRDT operation: `Transfer(amount)`.
   Encrypted, recorded in a DAG node.

3. **ZK balance proof.** The sender produces a ZK proof: "After
   this transfer, my balance is non-negative." This prevents
   double-spending without revealing the actual balance.

4. **Settlement.** Periodically (or on channel close), the final
   state is settled on-chain via a ZK proof: "The final balances
   are the result of correctly applying all operations from the
   initial state." The chain sees only the proof + final encrypted
   state.

**Features revealed:**
- `F-TX-001` Private payment channels
- `F-TX-002` ZK balance proofs
- `F-TX-003` On-chain settlement with ZK
- `F-TX-004` Multi-party payment splitting

---

## Phase 9: Private Governance

### End-user: "Our space needs to vote on a proposal"

```
A proposal is raised. Members vote yes/no. The tally is computed
and published. No one knows how any individual voted. Everyone can
verify the tally is correct.
```

**What happens underneath:**

1. **Proposal document.** A new CRDT document is created for the
   proposal. Contains the proposal text and voting parameters
   (quorum, deadline, options).

2. **Vote casting.** Each member creates a DAG node containing their
   encrypted vote + a ZK proof:
   - "I am a member of this space" (membership tree proof)
   - "I have not already voted on this proposal" (nullifier)
   - "My vote is one of the valid options" (well-formedness)

3. **Tally.** Votes use homomorphic commitments. Anyone can compute
   the tally from the commitments without decrypting individual
   votes. A ZK proof verifies the tally is correct.

4. **Result.** The tally and proof are recorded as a DAG node.
   Everyone can verify. The proposal's effect (if passed) is
   applied to the space root document.

**Features revealed:**
- `F-GOV-001` Anonymous voting with ZK
- `F-GOV-002` Homomorphic tally
- `F-GOV-003` Verifiable results
- `F-GOV-004` Configurable governance policies (quorum, supermajority, etc.)

---

## Phase 10: Developer Experience

### Developer: "I want to build a private marketplace"

```rust
use kunekt::prelude::*;

#[derive(Crdt, Encode)]
struct Listing {
    title: String,
    price: Amount,
    seller: AnonCredential,  // anonymous seller identity
}

#[derive(Crdt, Encode)]
struct Marketplace {
    listings: GrowSet<Listing>,
    escrow: PaymentChannel,
}

let app = Kunekt::init(Config {
    privacy: PrivacyLevel::Maximum,
    storage: StoragePolicy::erasure_coded(3, 5, backends),
    ..Default::default()
}).await?;

// Create marketplace space
let market = app.create_space::<Marketplace>(SpaceConfig {
    admission: Admission::open(),
    moderation: Moderation::Anonymous {
        reputation_threshold: 5,
        ..Default::default()
    },
    ..Default::default()
})?;

// List an item — anonymous, ZK-proven authorized
market.apply(MarketOp::List(Listing {
    title: "Vintage keyboard".into(),
    price: Amount::new(50, Currency::DOT),
    seller: app.anonymous_credential(&market)?,
}))?;

// Buy — private payment via escrow
let listing = market.state().listings.get(id)?;
market.apply(MarketOp::Buy {
    listing: id,
    payment: app.pay(&listing.seller, listing.price).await?,
})?;
```

**SDK requirements:**
- `S-SDK-020` Derive macro for custom CRDT types
- `S-SDK-021` Built-in payment channel primitives
- `S-SDK-022` Anonymous credential helpers
- `S-SDK-023` Marketplace/escrow patterns as library components
- `S-SDK-024` Everything compiles to WASM for browser apps

---

## What this journey reveals

The feature IDs (`F-IDENTITY-001`, `F-COLLAB-001`, etc.) and SDK
requirements (`S-SDK-001`, etc.) scattered through this document
form a concrete backlog. See [Development Phases](./roadmap.md) for
the build order, and [Building Blocks](./building-blocks.md) for
which existing technology implements each piece.
