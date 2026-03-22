# Nostr Integration

> How Nostr fits into Kunekt's architecture — and where the two
> protocols complement vs conflict.

## Nostr in 30 seconds

Nostr is a protocol where clients publish signed JSON events to relays.
Relays store and forward events. Identity is a keypair. The protocol
is deliberately simple: no consensus, no blockchain, no P2P — just
clients and dumb relay servers.

Key properties:
- Events are signed, timestamped, tagged JSON blobs
- Relays are interchangeable — use many, trust none
- Identity = secp256k1 keypair (same as Bitcoin)
- No group encryption, no CRDTs, no conflict resolution
- Massive deployed infrastructure (thousands of relays, millions of users)

## Where Nostr fits in Kunekt

```
Kunekt stack                    Nostr role
──────────────────────────────────────────────
Application (CRDTs, docs)       —
ZK layer (credentials, proofs)  —
Encryption (MLS group keys)     —
Sync (Merkle-CRDT)              —
Storage / Relay                 ← Nostr relays here
Transport                       ← Nostr WebSocket transport here
Discovery                       ← Nostr social graph here
```

### 1. Nostr relays as a storage backend

Kunekt needs places to store encrypted DAG nodes so peers can fetch
them asynchronously. Nostr relays are exactly this — dumb servers
that store blobs and serve them on request.

A Kunekt DAG node maps to a Nostr event:

```
Nostr event (kind = 30078 or custom)
├── pubkey: space relay key (or ephemeral key for anonymity)
├── content: encrypted DAG node (opaque base64 blob)
├── tags:
│   ├── ["d", "<CID hex>"]           ← content address
│   ├── ["space", "<space-id>"]      ← for relay filtering
│   └── ["parent", "<parent CID>"]   ← optional, for DAG traversal
└── sig: signature
```

This gives Kunekt instant access to the entire Nostr relay network
without deploying any custom infrastructure.

**Trade-offs:**
- Nostr events require a signature (pubkey visible). For anonymous
  mode, use an ephemeral relay-specific key per space — unlinkable
  to the user's identity. The relay sees a pubkey but can't link it
  to a person.
- Nostr relays may filter/reject events they don't understand.
  Using standardized replaceable event kinds (NIP-78: application-
  specific data) helps.
- Nostr events have size limits (~64KB per event on most relays).
  Large DAG nodes need chunking.

### 2. Nostr as a discovery layer

How do peers find each other? How does a new member discover which
relays hold a space's data? Nostr's social graph and relay hint
system solve this:

- **Space announcement:** A space publishes its relay hints and
  public parameters as a Nostr event (e.g. NIP-78 or a custom kind).
  Members subscribe to this event to discover relay endpoints.
- **Invite links via Nostr:** Instead of out-of-band invite URLs,
  share a Nostr event containing encrypted invite parameters. The
  recipient's Nostr client can hand off to their Kunekt-capable app.
- **Relay list synchronization:** Members publish their preferred
  relay lists (NIP-65). Kunekt uses this to know where to push/pull
  DAG nodes for best connectivity.

### 3. Nostr for root CID gossip

During real-time collaboration, peers need to announce new root CIDs
so others know to sync. Nostr's subscription model (REQ filters) is
a natural pubsub channel:

- Each space has a "sync" event kind
- When a peer records a new DAG node, it publishes a Nostr event
  with the new root CID
- Other peers subscribed to that space's filter receive it instantly
  via WebSocket
- They then fetch the actual DAG nodes (from the same or different
  relays)

This separates **notification** (lightweight, via Nostr pubsub) from
**data transfer** (heavier, via DAG node fetch).

### 4. Bridge to Nostr social features

Nostr already has a social layer — profiles, follows, DMs, communities
(NIP-72). Kunekt can bridge to this:

- **Profile link:** A Kunekt user can optionally link their Nostr
  identity (for public-facing social features) while keeping their
  Kunekt space identities anonymous. The link is one-directional
  and voluntary.
- **Public spaces as Nostr communities:** A non-anonymous Kunekt
  space could expose its content as Nostr events, making it
  readable by standard Nostr clients. The CRDT state is rendered
  to a Nostr-compatible event stream.
- **DMs as Kunekt spaces:** Nostr DMs (NIP-44) are 1:1 encrypted.
  A Kunekt 2-person space provides richer semantics (shared
  documents, history, offline merge) while using Nostr relays for
  transport.

---

## Where they conflict

| Concern | Nostr | Kunekt | Tension |
|---|---|---|---|
| Identity model | Pubkey on every event | Anonymous by default | Nostr events always have a pubkey — need ephemeral keys for anonymity |
| Event structure | Signed JSON, immutable | Encrypted DAG nodes, mutable state via CRDTs | Kunekt content is opaque to Nostr; relays can't index/filter by content |
| Metadata | Tags are plaintext | Minimal metadata exposure | Space IDs and CIDs in tags are visible to relays |
| Relay trust | Relays see plaintext events | Relays see only encrypted blobs | OK for Kunekt — relays are untrusted storage |
| Sync model | Timestamp-based filters | DAG-based anti-entropy | Nostr can't do efficient Merkle-CRDT sync natively — it's just storage |
| Group comms | No native group encryption | MLS group keys | Nostr communities are public; Kunekt spaces are private by default |

### The shared space key problem

The naive idea: "the space has one Nostr keypair, all members sign
with it." But who holds that key? If one member holds it, they're
a gatekeeper — centralization. If you distribute it, how?

**Option A: MLS-derived signing key (simplest, recommended for Phase 1)**

MLS already gives every current member a shared epoch secret. Derive
the Nostr signing key deterministically from it:

```
nostr_sk = KDF(mls_epoch_secret, "nostr-relay-signing")
```

Every member independently derives the same key. Any member can sign
events. No coordination needed to post.

Properties:
- ✅ No single keyholder — every member can sign
- ✅ Key rotates automatically when MLS epoch changes (member join/leave)
- ✅ Removed members lose the key (new epoch, new derived key)
- ✅ Fully offline — no interaction needed to sign
- ⚠️ Any member can impersonate the space — but this is fine.
  The Nostr signature only authorizes *relay storage*, not content
  authenticity. Content integrity is verified at the Merkle-CRDT
  layer (CID verification) and authorization at the ZK layer.
- ⚠️ A malicious member could spam the relay with garbage events
  signed by the space key. Mitigation: the relay can rate-limit
  per pubkey, and other members ignore events with invalid CIDs.

**Option B: Threshold Schnorr signatures (stronger, Phase 3+)**

t-of-n threshold Schnorr (e.g. FROST) over secp256k1. The space has
a public key, but no single member holds the corresponding secret.
Any t members can cooperatively produce a valid signature.

Properties:
- ✅ No single member can sign alone — stronger abuse resistance
- ❌ Requires t members to be online simultaneously to sign
- ❌ Conflicts with offline-first — can't post if fewer than t peers
  are reachable
- ❌ Adds a coordination round per event (defeats the "no coordination"
  property)

Verdict: too heavy for general use. Could be useful for high-stakes
operations (e.g. signing a space's public announcement or a governance
result) but not for routine DAG node publishing.

**Option C: Per-member ephemeral keys (no shared key at all)**

Each member generates a fresh throwaway Nostr keypair per space
(or per session). Events from the same space come from different
pubkeys. No shared key needed.

Properties:
- ✅ No key management complexity
- ✅ Fully offline, no coordination
- ✅ A compromised member only exposes their own ephemeral key
- ⚠️ Relay sees N distinct pubkeys → learns group size
- ⚠️ Can correlate events from the same member within a session

Mitigation for group size leakage: rotate keys frequently (per-batch)
and add dummy pubkeys posting cover traffic.

**Option D: Blind-signed ephemeral keys (best anonymity, Phase 3+)**

The space (via MLS group action) blind-signs members' ephemeral
Nostr pubkeys. A member generates a fresh keypair, gets it
blind-signed by the group, then presents the signature to the relay
as proof of authorization. The relay verifies the space authorized
this pubkey but can't link it to a specific member.

```
Member → generates (ek_pub, ek_sk)
Member → blinds ek_pub → sends to group
Group  → blind-signs → returns blind signature
Member → unblinds → has signature on ek_pub
Member → presents (ek_pub, sig) to relay
Relay  → verifies sig against space pubkey → accepts events from ek_pub
```

Properties:
- ✅ Relay can't link ephemeral keys to members
- ✅ Relay can't count members (keys rotate, overlap is invisible)
- ✅ Space controls authorization without knowing who gets which key
- ⚠️ Blind signing requires an MLS group operation (but can batch —
  sign N keys at once during epoch change)
- ⚠️ More complex cryptography

**Recommendation:**
- Phase 1-2: Option A (MLS-derived key). Simple, works offline,
  good enough when relays are semi-trusted storage.
- Phase 3+: Option D (blind-signed ephemeral keys) for anonymous
  mode. Option C as a simpler fallback when blind signing isn't
  available.

### Metadata leakage: what Nostr relays learn and how to fight it

This is the real concern. Even with encrypted content, Nostr relays
observe significant metadata. Here's the full threat model:

**What the relay sees:**

| Data point | What it reveals | Severity |
|---|---|---|
| Pubkey on events | Which space (or member) is posting | High |
| Event timestamps | When activity happens | High |
| Event sizes | Type of operation (chat msg vs large edit) | Medium |
| Tags (CIDs, parent CIDs) | DAG structure, causal relationships | High |
| IP addresses of posters | Physical location of members | Critical |
| IP addresses of subscribers | Who is reading which space | Critical |
| Subscription filters | Which CIDs/tags a client wants | High |
| Event count per pubkey | Activity volume | Medium |

**Layer 1: Opaque deterministic tags (relay can filter, learns nothing)**

Instead of putting raw CIDs in tags, derive opaque tag values that
only space members can reconstruct:

```
tag_value = HMAC(epoch_tag_key, CID)
where epoch_tag_key = KDF(mls_epoch_secret, "nostr-tag-key")
```

A member wanting to fetch CID `abc123` computes
`HMAC(epoch_tag_key, "abc123")` and sends that as the REQ filter.
The relay matches it exactly — efficient server-side filtering —
but the tag value is meaningless to the relay.

When the epoch changes, all tag values change. The relay can't
correlate events across epochs.

Limitations: the relay can still count events per epoch, observe
timing, and see which opaque tags are queried together.

**Layer 2: Uniform envelopes**

All events from a space are padded to one of a few fixed size
buckets (e.g. 1KB, 4KB, 16KB). The relay can't distinguish a
chat message from a document edit from a cover traffic dummy.

**Layer 3: Timing defenses**

- **Batched posting:** Don't publish events immediately. Buffer
  operations and publish at fixed intervals (every 5s, 30s,
  configurable per space). This hides per-operation timing.
- **Jitter:** Add random delay (0-2s) to each batch. Prevents
  fingerprinting by exact timing.
- **Cover traffic:** Periodically publish dummy events
  (indistinguishable from real ones). This maintains constant
  event rate even when no real activity happens.

**Layer 4: Network anonymity**

IP address is the most critical leak. Mitigations:

- **Tor:** Route all relay connections through Tor. The relay sees
  a Tor exit node, not the member's IP. Practical today.
- **Mix network (Nym):** Stronger than Tor — adds timing
  obfuscation on top of routing anonymity. Higher latency.
- **Relay hopping:** Don't always connect to the same relay.
  Spread reads and writes across many relays. No single relay
  sees the full picture.
- **Proxy relays:** A Kunekt-aware proxy that aggregates traffic
  from many users/spaces before forwarding to public Nostr relays.
  The public relay sees the proxy's IP and can't distinguish
  individual users.

**Layer 5: Read privacy**

Subscribing to events is as revealing as posting them. The relay
learns what a client is interested in.

- **Bulk download:** Instead of filtering by specific tags,
  download all events from the space's pubkey (or all events in a
  time range) and filter client-side. Wasteful but reveals nothing
  about what you specifically need.
- **Multi-relay split:** Subscribe to different tag ranges on
  different relays. No single relay sees your full interest set.
- **PIR (future):** If a relay supports Private Information
  Retrieval, the client can fetch specific events without the
  relay knowing which ones. This requires relay-side support
  (not standard Nostr today).

**Putting it together: privacy levels for Nostr integration**

```
Level       Technique stack                        Relay learns
──────────────────────────────────────────────────────────────
Minimal     Raw tags + direct connection           Everything
            (good for public/semi-public spaces)

Standard    Opaque tags + uniform sizes +          Event count,
            batched posting + Tor                  timing (blurred),
            (default for private spaces)           nothing about
                                                   content or members

Maximum     Opaque tags + uniform sizes +          Almost nothing:
            cover traffic + mix network +          constant-rate
            bulk download + relay hopping          opaque blobs from
            (for high-risk spaces)                 an anonymous source
```

### What we can't fix (Nostr's structural limits)

Some metadata leaks are inherent to the Nostr relay model:

1. **Relays must store data.** A malicious relay can retain events
   forever, even after "deletion." Content-addressed encrypted blobs
   mitigate this (the relay has ciphertext it can't read), but the
   metadata accumulates.

2. **Relays can correlate connections.** Even with Tor, a relay
   running traffic analysis over long periods might correlate
   subscription patterns. Mix networks help but add latency.

3. **Relay collusion.** If multiple relays collude, they can combine
   their views. Using many relays helps only if they don't cooperate.

4. **No plausible deniability.** A relay knows *something* is being
   stored. It can't be denied that a space exists (though the relay
   doesn't know it's a "space" — just opaque events).

**Acceptance:** Nostr relays are an *opportunistic* transport — use
them for their convenience and deployed infrastructure, but don't
rely on them for privacy guarantees. The privacy guarantees come
from Kunekt's own layers (encryption, ZK, anonymity network).
Nostr relays are untrusted storage that we make as little use of
their metadata exposure as possible.

---

## Integration levels

Kunekt can integrate Nostr at different depths:

### Level 1: Nostr relays as dumb storage (minimal integration)
- Kunekt treats Nostr relays as key-value stores
- `put(CID, encrypted_blob)` → publish Nostr event
- `get(CID)` → REQ with tag filter
- No awareness of Nostr social features
- Works today with existing relays

### Level 2: Nostr as transport + discovery (medium integration)
- Root CID gossip via Nostr subscriptions
- Relay hints via NIP-65
- Invite sharing via Nostr events
- Space announcements as Nostr events
- Still anonymous internally

### Level 3: Nostr social bridge (deep integration)
- Optional Nostr identity linkage
- Public spaces readable by Nostr clients
- Kunekt-enhanced DMs replacing NIP-44
- Cross-protocol social graph
- Privacy is opt-out for public-facing features

### Recommendation: Start at Level 1, grow to Level 2

Level 1 is trivial to implement and gives Kunekt access to thousands
of deployed relays immediately. Level 2 adds real utility (discovery,
gossip) without compromising privacy. Level 3 is optional and only
makes sense for spaces that choose to be public.

---

## Implementation sketch

```rust
/// Nostr relay as a Kunekt storage backend
impl<H: Hasher, P: Payload> Store<H, P> for NostrRelayStore {
    type Error = RelayError;

    fn get(&self, cid: &Cid<H>) -> Result<Option<DagNode<H, P>>, Self::Error> {
        // REQ ["REQ", sub_id, {"#d": [cid_hex], "kinds": [30078]}]
        // Deserialize from Nostr event content field
    }

    fn put(&mut self, cid: Cid<H>, node: DagNode<H, P>) -> Result<(), Self::Error> {
        // Serialize node, create Nostr event kind 30078
        // Tag with ["d", cid_hex]
        // Sign with space relay key
        // Publish to relay
    }

    fn contains(&self, cid: &Cid<H>) -> Result<bool, Self::Error> {
        // REQ with COUNT (NIP-45) or just try to fetch
    }
}
```

The entire Nostr integration is a `Store` implementation. The rest
of Kunekt (CRDTs, sync, encryption, ZK) is completely unaware that
Nostr exists underneath. This is the power of the layered design.
