# Building Blocks: Existing Technologies

Kunekt composes existing, proven technologies rather than reinventing
them. This document describes each building block, what it gives us,
its limitations, and how it fits into the protocol.

---

## Merkle-CRDTs — Leaderless Sync

> Paper: [arXiv:2004.00107](https://arxiv.org/abs/2004.00107)
> Implementation: [`merkle-crdt`](../README.md) (our crate)

**What it gives us:**
- Every peer edits independently, syncs when convenient
- Sync requires exchanging a single hash (root CID)
- Only missing data is transferred (efficient anti-entropy)
- No leader election, no consensus, no coordination
- Works over any transport that can carry bytes
- Self-verifying: data fetched from untrusted sources is validated by hash

**Limitations:**
- The DAG grows unboundedly (needs pruning/compaction strategy)
- Causal ordering is guaranteed but not total ordering
- No built-in encryption or access control

**How Kunekt uses it:**
Each document in a space has its own `MerkleCrdt` instance. The
Merkle-DAG is the foundation — every other layer (encryption, storage,
anonymity) wraps around it.

**Status:** Implemented. The `merkle-crdt` crate is `no_std`, generic
over hash function, storage backend, and CRDT payload.

---

## Automerge — Document CRDTs

> Website: [automerge.org](https://automerge.org)
> Crate: `automerge`

**What it gives us:**
- Conflict-free editing for JSON-like documents
- Rich text, lists, maps, counters
- Mature Rust implementation with WASM support
- Proven in production (Ink & Switch, many others)
- Handles complex merge scenarios (concurrent text editing, etc.)

**Limitations:**
- Its own sync protocol assumes a different transport model
- Large document histories can be expensive to store/transmit
- Not designed for anonymous/encrypted environments

**How Kunekt uses it:**
Automerge provides the CRDT logic inside each document. Kunekt replaces
Automerge's built-in sync with Merkle-CRDT sync. An Automerge change
becomes the `Payload` of a Merkle-DAG node:

```
Automerge change → serialize → MerkleCrdt::apply(payload) → DAG node
```

Automerge handles "what does this edit mean." Merkle-CRDT handles
"how does this edit reach other peers." This separation lets us swap
CRDT implementations per document type (Automerge for text, a simple
GSet for tags, a counter for votes, etc.).

**Integration stage:** Phase 2

---

## OpenMLS — Group Encryption

> Spec: [RFC 9420 (MLS)](https://www.rfc-editor.org/rfc/rfc9420.html)
> Crate: [openmls](https://github.com/openmls/openmls)

**What it gives us:**
- IETF-standard group key agreement
- Forward secrecy: compromised keys don't expose past messages
- Post-compromise security: key rotation heals after compromise
- Efficient key rotation on membership changes
- Scales to large groups (tree-based key schedule)

**Limitations:**
- Requires a Delivery Service to order certain messages (Commits)
- Group membership is visible to the Delivery Service
- Key packages contain long-term identity keys
- Not designed for anonymous membership

**How Kunekt uses it:**
OpenMLS manages per-space encryption keys. Every DAG node payload is
encrypted with the current MLS epoch key before leaving the peer.

Key adaptation for Kunekt:
- **Delivery Service = Merkle-CRDT.** MLS Commits and Welcomes are
  themselves CRDT operations stored in the space's root document DAG.
  No separate delivery service needed.
- **Anonymous membership (Phase 3).** Replace MLS identity keys with
  ZK-compatible commitments. A member proves they hold a valid leaf
  in the ratchet tree without revealing which leaf.

**Integration stage:** Phase 1

---

## Nostr Relays — Deployed Infrastructure

> Protocol: [nostr.com](https://nostr.com)
> NIPs: [github.com/nostr-protocol/nips](https://github.com/nostr-protocol/nips)

**What it gives us:**
- Thousands of deployed relay servers worldwide
- Simple WebSocket protocol (works in browsers)
- Content-addressed-ish storage (events have IDs)
- Subscription/filter mechanism for real-time updates
- Relay redundancy (publish to many, fetch from any)
- Existing social discovery layer (profiles, follows, relay hints)

**Limitations:**
- Events are signed by a pubkey (identity always attached)
- Tags are plaintext (metadata exposure)
- Relays see connection IPs, timing, subscription patterns
- No native support for encrypted/opaque filtering
- Event size limits (~64KB on most relays)

**How Kunekt uses it:**
Nostr relays are one storage/transport backend. A Merkle-DAG node maps
to a Nostr event (kind 30078, application-specific data). The relay
stores and retrieves encrypted blobs by CID tag.

Key adaptations for privacy:
- **MLS-derived signing key (Phase 1-2):** the space derives its Nostr
  signing key from the MLS epoch secret. Every member can sign. Key
  rotates on membership change.
- **Opaque tags:** tag values are HMAC(epoch_key, CID) — relay can
  filter efficiently but tags are meaningless and change every epoch.
- **Blind-signed ephemeral keys (Phase 3+):** members get blind-signed
  throwaway Nostr keypairs. Relay can't link keys to members.
- **Tor/mix network connections:** relay never sees real IPs.

See [Nostr Integration](./nostr.md) for full analysis.

**Integration stage:** Phase 1 (dumb storage), Phase 2 (discovery + gossip)

---

## Nym / Tor — Network Anonymity

> Nym: [nymtech.net](https://nymtech.net)
> Tor: [torproject.org](https://www.torproject.org)

**What they give us:**
- **Tor:** onion routing hides IP addresses. Mature, widely deployed.
  Reasonable latency (~200-500ms). Vulnerable to traffic analysis by
  global observers.
- **Nym:** mix network adds timing obfuscation on top of routing
  anonymity. Messages are batched, padded, delayed, and mixed.
  Resistant to traffic analysis. Higher latency (~1-5s).

**Limitations:**
- Tor: vulnerable to correlation attacks (entry + exit observation)
- Nym: higher latency, smaller network, still maturing
- Both: add latency that conflicts with real-time collaboration

**How Kunekt uses them:**
All connections to relays and other peers are routed through the
anonymity layer. The relay/peer sees a Tor exit node or Nym gateway,
not the user's IP.

Key design decision — **tiered latency:**
- **Real-time edits (Phase 2):** Tor (lower latency, acceptable for
  batched CRDT ops every 100-500ms)
- **High-sensitivity operations (Phase 4):** Nym mix network for
  credential proofs, key rotations, membership changes, governance
  votes — operations where timing correlation is most dangerous
- **Cover traffic:** constant-rate dummy messages through the
  anonymity layer to hide when real activity happens

**Integration stage:** Phase 2 (Tor), Phase 4 (Nym/mix network)

---

## Zero-Knowledge Proofs — The Connective Tissue

> Systems: Groth16, PLONK, Nova/SuperNova, Jolt
> Frameworks: [Arkworks](https://arkworks.rs), circom, Halo2

**What they give us:**
- Prove any statement without revealing the witness
- Anonymous credentials: "I am a member" without revealing which
- Private state: "my reputation is above 50" without revealing it
- Verifiable computation: "I correctly applied these operations"
  without revealing the operations

**Limitations:**
- Proof generation is expensive (100ms-10s depending on circuit)
- Circuit design requires specialized expertise
- Groth16 requires trusted setup (per-circuit)
- PLONK/Nova are universal but larger proofs or more verification time
- Not yet practical for per-keystroke operations

**How Kunekt uses ZK at each phase:**

| Phase | ZK Application | Technique | Proves |
|---|---|---|---|
| Phase 3 | Space membership | Merkle proof in ZK | "I am a member" (not which one) |
| Phase 3 | Anonymous posting | zk-promises ShowAuthorized | "I can post: not banned, within rate limit" |
| Phase 3 | Anonymous moderation | zk-promises Callbacks | Reputation/ban applied correctly |
| Phase 3 | Cross-space reputation | BBS+ selective disclosure | "I have rep > X in some space" |
| Phase 4 | Storage access control | ZK credential proof | "I may access this bucket" |
| Phase 5 | Private transactions | ZK balance proof | "My balance is non-negative after transfer" |
| Phase 5 | Anonymous voting | ZK vote + nullifier | "I voted exactly once, validly" |
| Phase 6 | DAG history verification | Recursive SNARKs (Nova) | "All operations in this DAG are valid" |

**ZK framework choice:**
- Phase 3: Groth16 via Arkworks (proven, fast verification, the
  zk-promises reference implementation already uses it)
- Phase 5+: evaluate Nova/SuperNova for recursive proofs, and
  newer systems (Jolt, SP1) for WASM-friendly client-side proving
- Long-term: post-quantum migration path (lattice-based ZK systems
  as they mature)

**Integration stage:** Phase 3 (core), expanding through Phase 6

---

## zk-promises — Anonymous Accountability

> Paper: [ePrint 2024/1260](https://eprint.iacr.org/2024/1260)
> Implementation: [github.com/moshih/zk-promises](https://github.com/moshih/zk-promises)

**What it gives us:**
- Users hold private state objects (reputation, rate limits, ban status)
- Actions are authorized via ZK proof of state properties
- Moderators issue callbacks that modify user state (reduce reputation,
  ban) without knowing which user
- Users must process callbacks before their next action (can't ignore)
- Bulletin board (append-only log) is the only shared state

**Limitations:**
- Proof generation ~300-900ms (not per-keystroke)
- Requires a consistent bulletin board visible to all members
- Users must periodically scan for callbacks (offline accumulation)
- Groth16 trusted setup
- Arkworks dependency is heavy (not `no_std`)

**How Kunekt uses it:**
zk-promises provides the anonymous moderation layer. It sits at the
authorization gate — users prove they're allowed to act before their
operations enter the Merkle-CRDT sync layer.

The bulletin board is a special CRDT document in the space, synced via
Merkle-CRDT like everything else. For stronger consistency, it can be
anchored to a blockchain.

See [Anonymous Moderation](./zk-promises.md) for full analysis.

**Integration stage:** Phase 3

---

## Content Addressing (CID) — Self-Verifying Data

> Used by: IPFS, libp2p, and many content-addressed systems

**What it gives us:**
- Data identity = hash of content (tamper-proof)
- Fetch from anyone, verify by recomputing the hash
- Natural deduplication (same content = same CID)
- Location-independent (CID doesn't say where, just what)

**Limitations:**
- Immutable by design (updating = new CID)
- Hash function choice is a long-term commitment
- CIDs leak content identity (two peers requesting the same CID
  are interested in the same data)

**How Kunekt uses it:**
Every Merkle-DAG node is content-addressed. The `merkle-crdt` crate
computes CIDs as `Hash(len(payload) || payload || num_children || children)`.
This is the foundation for self-verifying sync — nodes fetched from
untrusted relays or storage backends are validated by CID.

**Status:** Implemented in `merkle-crdt`.

---

## Summary: Technology × Layer × Phase

```
                    Phase 1      Phase 2       Phase 3        Phase 4       Phase 5-6
                    Foundation   Collaboration Anonymous      Private       Private
                                               Mode           Infra        Economy
────────────────────────────────────────────────────────────────────────────────────
Sync               merkle-crdt  +Automerge    ···            ···           +recursive ZK
                    ✅ done      integration                                DAG verify

Encryption         OpenMLS      ···           +ZK membership  ···          ···
                                               credentials

Storage            local DB     +Nostr relays  ···           +PIR          ···
                                +multi-backend               +erasure code

Transport          direct       +Tor          ···            +Nym/mix net  ···
                   WebSocket                                 +cover traffic

Identity           per-space    ···           +anon creds    ···           +cross-space
                   keypairs                   +zk-promises                  portable rep

Application        basic CRDT   +batching     +uniform       +padded       +payments
                   ops          +offline       envelopes     envelopes     +voting
                                                                           +governance

SDK                core types   +async API    +credential    +privacy      +derive macros
                                +WASM          helpers        level config +marketplace
────────────────────────────────────────────────────────────────────────────────────
```
