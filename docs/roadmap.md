# Development Phases

Each phase produces a usable system. Later phases add deeper privacy
and richer capabilities. A developer can ship a product on Phase 1
and upgrade as later phases land.

---

## Phase 1 — Foundation

> **Goal:** Two peers can sync encrypted documents without a server.
>
> **Builds on:** merkle-crdt (done), OpenMLS, basic Nostr relays

### What gets built

**Merkle-CRDT core** ✅ Done
- `MerkleClock`, `MerkleCrdt`, `Store`, `Hasher`, `Payload`, `Encode` traits
- Anti-entropy sync algorithm with topological sort
- `MemStore` reference implementation
- Generic, `no_std`, pluggable

**MLS integration**
- Wrap OpenMLS for per-space group key management
- Encrypt DAG node payloads with MLS epoch key before storage
- Decrypt on fetch, verify CID after decryption
- MLS Commits/Welcomes stored as CRDT operations in space root doc
- Key rotation on membership changes

**Space lifecycle**
- Create space → initializes MLS group + root document
- Join space → MLS Welcome + initial DAG sync
- Leave space → MLS removal + key rotation
- Per-space keypairs (no cross-space linkage at the key level)

**Basic storage**
- Local encrypted store (SQLite or sled, key derived from root secret)
- Nostr relay as remote store (Level 1: dumb blob storage)
  - DAG nodes → Nostr events (kind 30078)
  - CID in `d` tag for retrieval
  - Space signing key derived from MLS epoch secret
- `Store` trait implementations for both

**Invite system**
- Capability-based invite tokens
- Contains encrypted space parameters (MLS group info, relay hints)
- Single-use and multi-use variants

### Existing tech leveraged
| Component | Technology | Maturity |
|---|---|---|
| Sync | merkle-crdt (ours) | Done |
| Encryption | OpenMLS | Stable, RFC 9420 |
| Storage | Nostr relays (NIP-78) | Thousands deployed |
| Local DB | SQLite / sled | Production-grade |

### Result
A working encrypted P2P collaboration system. Two people can create
a space, join it, edit shared data, and sync — with content encrypted
and stored on Nostr relays. Privacy is content-level only (metadata
is not yet protected).

---

## Phase 2 — Usable Collaboration

> **Goal:** Real-time multi-user editing with offline support, usable
> by app developers.
>
> **Builds on:** Phase 1 + Automerge, Tor, Nostr discovery

### What gets built

**Document CRDT integration**
- Automerge as a `Payload` implementation for rich text/JSON documents
- Adapter: Automerge changes ↔ Merkle-CRDT DAG nodes
- Additional CRDT types: GSet, LWW-Register, Counter, OR-Map
- Per-document independent sync (subscribe to some docs, not all)

**Real-time sync**
- Operation batching (configurable: 100ms for real-time, 5s for background)
- Root CID gossip via Nostr subscriptions (NIP-78 events)
- Notification (lightweight, Nostr pubsub) separated from data
  transfer (heavier, DAG node fetch)

**Offline editing & reconnect**
- Full local operation while disconnected
- Automatic bidirectional merge on reconnect (anti-entropy)
- MLS epoch catch-up for missed membership changes
- Conflict-free by construction (CRDT guarantee)

**Nostr Level 2 integration**
- Relay discovery via NIP-65 relay lists
- Invite sharing via Nostr events
- Space announcements for public/discoverable spaces
- Multi-relay redundancy (publish to N, fetch from any)

**Network privacy (basic)**
- All relay connections routed through Tor
- Relays see Tor exit node IP, not user's real IP
- Optional direct peer connections for low-latency (privacy tradeoff)

**SDK foundation**
- Async API (`async fn` everywhere, runtime-agnostic)
- WASM compilation target (for browser apps)
- `Kunekt::init()`, `create_space()`, `join_space()`, `apply()`, `sync()`
- Event/callback system for UI integration

### Existing tech leveraged
| Component | Technology | Maturity |
|---|---|---|
| Rich CRDTs | Automerge | Production (Ink & Switch) |
| Network anonymity | Tor (arti crate) | Mature |
| Discovery | Nostr NIP-65 | Widely supported |
| Async runtime | tokio / wasm-bindgen | Production-grade |

### Result
A developer can build a real collaborative app (chat, docs, kanban).
Users edit in real-time, work offline, and reconnect seamlessly.
Content is encrypted, IPs are hidden behind Tor. Moderation is
admin-based (remove member from MLS group).

---

## Phase 3 — Anonymous Mode

> **Goal:** Members can act anonymously within a space. Moderation
> works without knowing who anyone is.
>
> **Builds on:** Phase 2 + zk-promises, ZK proofs (Groth16/Arkworks),
> BBS+ signatures

### What gets built

**Anonymous credentials**
- Per-space ZK-compatible credential (commitment to space-specific secret)
- Membership Merkle tree: each member's commitment is a leaf
- Membership tree stored as CRDT in space root doc
- ZK membership proof: "I am a member" without revealing which one

**zk-promises integration**
- zk-objects: each member holds private state (reputation, rate-limit
  counter, ban status)
- ShowAuthorized proof: "I can post — not banned, within rate limit,
  reputation above threshold" (~700ms, done once per session or per
  batch)
- Callbacks: moderator issues penalty against a post's ticket, user
  must process it before next action
- Bulletin board: a CRDT document in the space, synced via Merkle-CRDT

**Anonymous session tokens**
- Prove authorization once at session start → receive a short-lived
  session token (validity: minutes to hours, configurable)
- Token authorizes operations without re-proving each time
- Tradeoff: weaker anonymity within a session (operations from one
  token are linkable) but practical for real-time editing
- Session token is a blinded credential — relay and peers can verify
  validity but can't link to the membership proof

**Cross-space reputation**
- BBS+ or CL signatures for selective disclosure
- Prove "I have reputation > X in at least N spaces" without
  revealing which spaces, which scores, or any linkable identity
- Used for space admission policies ("must have good standing
  somewhere to join")

**Nostr privacy hardening**
- Opaque tags: `HMAC(epoch_tag_key, CID)` — relay filters efficiently,
  learns nothing, tags change every epoch
- Blind-signed ephemeral Nostr keys: space blind-signs members'
  throwaway keypairs, relay can't link to members or count them
- Uniform event sizes: pad all events to fixed buckets

### Existing tech leveraged
| Component | Technology | Maturity |
|---|---|---|
| ZK proofs | Groth16 via Arkworks | Production (Zcash, etc.) |
| Anonymous moderation | zk-promises | Research impl (Rust) |
| Selective disclosure | BBS+ signatures | W3C draft, multiple impls |
| Blind signatures | Schnorr blind sigs | Well-studied |

### Result
A space can operate in anonymous mode. Members post, edit, and
interact without anyone — including moderators and other members —
knowing who they are. Moderation works via zk-promises: reputation,
rate limiting, banning — all enforced cryptographically, all
anonymous. Cross-space reputation lets trusted newcomers join
without starting from zero.

---

## Phase 4 — Private Infrastructure

> **Goal:** Metadata protection at every layer. Even the infrastructure
> can't learn anything useful about users.
>
> **Builds on:** Phase 3 + Nym mix network, PIR, erasure coding

### What gets built

**Mix network integration**
- High-sensitivity operations (credential proofs, key rotations,
  governance votes) routed through Nym mix network
- Real-time edits stay on Tor (latency tradeoff)
- Cover traffic: constant-rate dummy messages maintain baseline
  traffic even when no real activity happens

**Private Information Retrieval (PIR)**
- Fetch DAG nodes from storage without the backend learning which
  CIDs were requested
- Computational PIR for moderate-size stores
- Multi-server PIR (across non-colluding relays) for better performance
- Fallback: bulk download + client-side filter for simpler deployments

**Erasure-coded distributed storage**
- Files split into k-of-n fragments via erasure coding
- Fragments distributed across multiple backends
- Any k fragments reconstruct the original
- No single backend holds enough to reconstruct (even if it could
  decrypt, which it can't)

**Proof of storage**
- Periodic challenges to storage backends: "prove you still hold my
  data" without downloading it
- ZK proof of retrievability — backend proves faithfulness

**Selective sharing via proxy re-encryption**
- Share a personal file with a space by re-encrypting its key under
  the space's MLS group key
- Revoke by rotating the file key and not re-sharing
- No need to re-encrypt the file itself (only the key changes)

**Uniform envelopes**
- All operations (chat, edit, vote, payment, dummy) serialized to
  identical-looking encrypted envelopes
- Size-bucketed padding (1KB, 4KB, 16KB)
- Application-level semantics completely hidden from transport and
  storage layers

### Existing tech leveraged
| Component | Technology | Maturity |
|---|---|---|
| Mix network | Nym | Mainnet, Rust SDK |
| PIR | SealPIR / SimplePIR | Research, practical for moderate DBs |
| Erasure coding | reed-solomon-simd | Production-grade |
| Proxy re-encryption | recrypt / umbral | Multiple implementations |

### Result
Full metadata protection. A global observer watching all relays, all
network traffic, and all storage backends learns almost nothing:
constant-rate encrypted blobs of uniform size flowing through mix
nodes from anonymous sources. The infrastructure is fully untrusted.

---

## Phase 5 — Private Economy

> **Goal:** Private transactions, governance, and marketplace
> primitives built on the private collaboration foundation.
>
> **Builds on:** Phase 4 + ZK balance proofs, homomorphic commitments

### What gets built

**Private payment channels**
- State channel between space members backed by a CRDT
- Transfer operations are CRDT ops encrypted via MLS
- ZK balance proof: "my balance is non-negative after this transfer"
- On-chain settlement via ZK proof of final state correctness

**Anonymous voting / governance**
- Proposal as a CRDT document
- Vote = DAG node with encrypted vote + ZK proof:
  - Membership proof (I'm a member)
  - Nullifier (I haven't voted already)
  - Well-formedness (my vote is a valid option)
- Homomorphic tally: compute result from commitments without
  decrypting individual votes
- Verifiable result: ZK proof that tally is correct

**Marketplace primitives**
- Anonymous listings (seller anonymous via ZK credential)
- Escrow via shared payment channel
- Reputation portable across marketplaces (cross-space credentials)
- Dispute resolution via governance (anonymous voting)

### Existing tech leveraged
| Component | Technology | Maturity |
|---|---|---|
| Payment channels | State channels (various) | Production (Lightning, etc.) |
| ZK balance proofs | Pedersen commitments + range proofs | Well-studied |
| Homomorphic tally | ElGamal / Pedersen | Standard |
| Anonymous voting | Many schemes (Helios, etc.) | Research + practical |

### Result
The private collaboration system extends to economic activity.
People can transact, vote, and trade within spaces — all with the
same privacy guarantees as collaboration. The space becomes a
self-governing private micro-economy.

---

## Phase 6 — Full Privacy OS

> **Goal:** Developer-friendly SDK, ecosystem readiness, future-proofing.
>
> **Builds on:** All previous phases

### What gets built

**SDK polish**
- `#[derive(Crdt)]` macro for custom document types
- High-level API: `space.create_document::<MyCrdt>()`
- Privacy level as a config knob, not a code change
- Comprehensive WASM support (browser-native apps)
- Built-in document templates (chat, text, kanban, gallery)

**Recursive ZK for DAG verification**
- Each DAG node carries an incrementally-updated proof that the
  entire history is valid (Nova/SuperNova recursive SNARKs)
- New peer verifies the full document by checking one proof
- No need to walk the entire DAG for verification

**Post-quantum readiness**
- Migration path from elliptic-curve ZK to lattice-based / hash-based
  alternatives as they mature
- Hybrid mode: both classical and post-quantum proofs during transition
- Hash-based signatures for long-term data authenticity

**Third-party ecosystem**
- Plugin architecture for custom storage backends, transports,
  CRDT types, moderation policies, credential schemes
- App registry (itself a Kunekt space) for discovering applications
- Interoperability standards for cross-implementation compatibility

### Existing tech leveraged
| Component | Technology | Maturity |
|---|---|---|
| Recursive proofs | Nova / SuperNova | Research, advancing fast |
| Proc macros | Rust proc_macro | Stable |
| Post-quantum ZK | Lattice-based (emerging) | Early research |

### Result
A complete privacy operating system. Developers build private
applications by writing business logic — the protocol handles
everything else. Users interact with a private internet where
communication, storage, transactions, and governance are all
private by default.

---

## Phase Summary

```
Phase   Delivers                       Key Tech Added        Privacy Level
─────────────────────────────────────────────────────────────────────────
  1     Encrypted P2P sync             merkle-crdt, OpenMLS  Content encrypted
                                       Nostr relays

  2     Real-time collaboration        Automerge, Tor        + IP hidden
        Offline-first                  Nostr discovery

  3     Anonymous mode                 ZK proofs, zk-promises + Identity hidden
        Anonymous moderation           BBS+ credentials       + Actions unlinkable

  4     Metadata protection            Nym mix net, PIR      + Access patterns hidden
        Private storage                Erasure coding         + Timing hidden

  5     Private economy                ZK balance proofs     + Transactions private
        Governance                     Homomorphic tally      + Votes secret

  6     Full privacy OS                Recursive ZK, SDK     + Future-proof
        Developer ecosystem            Post-quantum           + Ecosystem ready
```

---

## What comes from us vs what we integrate

**We build:**
- The integration layer (how all pieces fit together)
- The `merkle-crdt` sync core
- The space/document/membership lifecycle
- The SDK API surface
- Anonymous session tokens
- The Nostr ↔ Kunekt adapter (Store implementation + privacy hardening)
- Glue between MLS and Merkle-CRDT (Commits as CRDT ops)
- Glue between zk-promises and MLS (anonymous credentials for group membership)

**We integrate (not rebuild):**
- Automerge (CRDT logic)
- OpenMLS (group key agreement)
- Arkworks / Groth16 (ZK proof system)
- zk-promises (anonymous accountability framework)
- Nostr relays (storage + transport infrastructure)
- Tor / arti (onion routing)
- Nym (mix network)
- Reed-Solomon (erasure coding)
- BBS+ signatures (selective disclosure)

The principle: **write glue, not crypto.** Every cryptographic primitive
we use should be an existing, audited, proven implementation. Our
contribution is making them work together seamlessly.
