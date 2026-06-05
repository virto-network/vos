# The Privacy Gap

Encryption is necessary but not sufficient. Every existing system that
claims to protect privacy solves part of the problem and leaves the
rest exposed. This chapter examines what falls through the cracks —
and why VOS exists to close them.

---

## 1. The Metadata Problem

End-to-end encryption protects the content of a message. It does not
protect the fact that a message was sent, who sent it, who received it,
when, how often, how large it was, or from where.

This information — metadata — is often more revealing than content.

**What metadata exposes:**

| Metadata type | What it reveals |
|---|---|
| Sender / recipient | Social graph, group membership |
| Timing | Activity patterns, time zones, habits |
| Frequency | Relationship intensity |
| Message size | Content type (text, image, file) |
| IP address | Physical location |
| Device fingerprint | Hardware, OS, cross-service linkage |
| Group membership changes | Who joined/left and when |

**Real-world consequences.** Metadata exploitation is not theoretical.
Former NSA and CIA director Michael Hayden stated plainly: *"We kill
people based on metadata."* The NSA's bulk telephony metadata program,
revealed in 2013, collected call records — who called whom, when, and
for how long — for millions of people who were never suspected of any
crime. No content was needed.

Stanford researchers demonstrated in 2014 that phone metadata alone
can infer medical conditions, firearm ownership, participation in
specific organizations, and religious affiliation — all without
accessing a single conversation.

The lesson: **encrypting content while leaving metadata exposed is
like sealing a letter in an envelope but writing the contents on the
outside.**

**Why better encryption is not the answer.** Metadata protection
requires a fundamentally different architecture, not stronger ciphers.
Content encryption operates on payloads. Metadata leaks happen at
every other layer: the transport (IP addresses, timing), the sync
protocol (who syncs with whom, how often), the key management system
(group size, membership changes), the storage backend (access patterns,
which objects are fetched), and the identity system (linkable keys
across contexts).

Protecting metadata means redesigning each of these layers — and
designing them together so that no gap between layers creates a new
leak.

---

## 2. Existing Systems Compared

Several systems have made genuine progress on parts of the privacy
problem. Each deserves credit for what it does well. None solves the
whole problem.

### Signal

Signal set the standard for usable end-to-end encrypted messaging.
The Signal Protocol (Double Ratchet + X3DH) provides forward secrecy
and post-compromise security for pairwise conversations, and the
Sender Keys variant handles groups.

**What it does well:**
- Best-in-class pairwise E2E encryption, widely audited
- Sealed Sender reduces metadata on message delivery
- Simple, polished user experience

**Where it falls short:**
- Centralized servers (Signal Foundation) mediate all message delivery
- Phone number required as identity — links to real-world identity
- Servers observe who is communicating, when, and group membership
- No CRDT-based sync — not designed for collaborative documents
- No offline-first architecture beyond message queuing
- No anonymous identity or ZK credentials
- No group anonymity — all members are known to Signal servers
- Closed federation — only Signal's servers participate

### Matrix / Element

Matrix is a federated protocol for encrypted communication. Element is
the primary client. The architecture distributes trust across
homeservers rather than centralizing it.

**What it does well:**
- Open federation — anyone can run a homeserver
- E2E encryption via Megolm (opt-in per room, default in DMs)
- Rich feature set: rooms, threads, VoIP, bridges to other networks
- Active open-source ecosystem

**Where it falls short:**
- Homeservers see extensive metadata: room membership, message timing,
  sender/recipient pairs, room topics, read receipts
- Megolm provides weaker forward secrecy than MLS — a compromised
  session key exposes all messages in that session
- No anonymous identity — Matrix IDs are `@user:server`, tied to a
  homeserver
- No ZK credentials or anonymous moderation
- Federation is complex to operate and introduces metadata sharing
  between homeservers
- No CRDT-based conflict-free editing — relies on event ordering
- DAG-based event graph but without the anti-entropy properties of
  Merkle-CRDTs

### Briar

Briar is a peer-to-peer messenger designed for activists and
journalists. It routes traffic through Tor, requires no servers, and
can sync over Wi-Fi, Bluetooth, or SD cards.

**What it does well:**
- True peer-to-peer: no servers, no homeservers, no relays
- All traffic routed through Tor by default
- Works over local networks (Wi-Fi, Bluetooth) when the internet is
  unavailable
- Designed for hostile environments (protest, censorship)

**Where it falls short:**
- No group CRDTs — limited to messaging (forums, blogs, private chat)
- No cross-device sync — identity is locked to a single device
- No anonymous moderation or ZK credentials
- Limited scalability — P2P mesh grows expensive with group size
- No collaborative document editing
- Tor alone is vulnerable to traffic correlation by well-resourced
  adversaries

### Session

Session is a decentralized messenger built on the Oxen network
(a service node infrastructure). It does not require a phone number
or email — identity is a public key.

**What it does well:**
- No phone number or email required — public key identity
- Decentralized message routing via Oxen service nodes
- Onion routing for sender anonymity
- Open source

**Where it falls short:**
- Limited CRDT support — not designed for collaborative data
- Onion routing but not a mix network — timing correlation attacks
  remain possible
- No ZK credentials or anonymous moderation
- Group encryption uses Sender Keys, not MLS — weaker forward secrecy
  properties
- Dependency on Oxen network (token-incentivized nodes) introduces
  economic attack surface
- No offline-first architecture with conflict-free sync

### Nostr

Nostr is a simple protocol for decentralized social networking. Users
publish signed events to relays. Relays are "dumb" — they store and
forward events without understanding them.

**What it does well:**
- Radically simple protocol — easy to implement clients and relays
- Censorship-resistant: publish to many relays, readers fetch from any
- Thousands of relays deployed worldwide
- No registration, no phone number — just a keypair
- Active ecosystem of clients and relay implementations

**Where it falls short:**
- No encryption by default — events are public and signed with the
  author's pubkey
- NIP-44 adds encrypted DMs but no group encryption
- Public key identity attached to every event — no anonymity
- Relays see IP addresses, timing, subscription patterns, event
  metadata
- No CRDTs — events are immutable, not mergeable
- No anonymous credentials, no ZK proofs
- Tags are plaintext metadata

### IPFS / OrbitDB

IPFS provides content-addressed storage. OrbitDB builds CRDT databases
on top of IPFS and libp2p. Together they offer a decentralized data
layer with conflict-free replication.

**What it does well:**
- Content addressing — data is self-verifying and location-independent
- OrbitDB provides CRDT-based databases (log, feed, key-value, counter)
- Decentralized storage and retrieval via DHT
- Data deduplication by hash

**Where it falls short:**
- No encryption layer — data is stored and transmitted in plaintext
  by default
- No group key management — applications must build their own
- DHT queries expose access patterns (who is looking for what)
- Peer connections reveal the social/interest graph
- No anonymity — libp2p peer IDs are persistent identifiers
- No ZK credentials or anonymous access control
- OrbitDB CRDT support is narrower than Automerge

### Veilid

Veilid is a privacy-focused application framework built on a custom
DHT. It aims to provide a general-purpose private networking layer.

**What it does well:**
- Privacy as a core design goal from the start
- Custom DHT with privacy-preserving routing
- Designed as a general framework, not just messaging
- Open source, backed by the Cult of the Dead Cow

**Where it falls short:**
- Early stage — API and protocol are still stabilizing
- No group CRDTs or conflict-free collaborative editing
- No ZK credentials or anonymous moderation
- No MLS or equivalent group key management standard
- Limited ecosystem and deployments so far
- Privacy properties not yet formally analyzed or audited

---

## 3. The Integration Gap

Each system above solves a real problem:

- Signal proved that usable E2E encryption is possible at scale
- Matrix proved that federated encrypted communication can work
- Briar proved that serverless P2P messaging over Tor is viable
- Nostr proved that dumb relays and simple protocols enable censorship
  resistance
- IPFS proved that content-addressed decentralized storage works
- Veilid is exploring privacy-first DHT design

But privacy leaks happen **between** layers, not within them.

A system with excellent encryption but centralized delivery leaks
metadata to the delivery server. A system with anonymous transport
but persistent identity links all traffic to one pubkey. A system
with CRDTs but no encryption exposes every operation to storage
providers. A system with ZK proofs but no sync protocol cannot support
real-time collaboration.

No existing system combines:

| Capability | Why it matters |
|---|---|
| Conflict-free sync (CRDTs) | Offline-first, leaderless collaboration |
| Group key management (MLS) | Forward secrecy, post-compromise security for groups |
| Metadata protection | Transport anonymity, access pattern hiding |
| Anonymous identity | Unlinkable actions, per-context pseudonyms |
| ZK credentials | Prove properties without revealing identity |
| Decentralized storage | No single point of failure or surveillance |

These are not independent features that can be bolted together after
the fact. They must be **co-designed** so that each layer's privacy
guarantees hold when composed with the others.

Consider: if the CRDT sync layer reveals DAG structure to an
untrusted relay, and the encryption layer protects payloads but not
structure, then the relay can infer editing patterns, authorship
timing, and collaboration intensity — even though every payload is
encrypted. The gap between the sync layer and the encryption layer
is where the leak happens.

This is VOS's thesis: **sync, encryption, anonymity, credentials,
and storage must be designed together as a single coherent stack.**
Privacy is not a feature you add on top. It is an architectural
property that either holds across all layers or fails.

---

## 4. Summary Table

| | Signal | Matrix | Briar | Session | Nostr | IPFS/OrbitDB | Veilid | **VOS** |
|---|---|---|---|---|---|---|---|---|
| **E2E encryption** | Yes | Yes (Megolm) | Yes | Yes | Partial (NIP-44) | No | Yes | Yes (MLS) |
| **Metadata protection** | Partial | No | Partial (Tor) | Partial | No | No | Partial | Yes |
| **Offline-first** | No | Partial | Yes | No | Yes (relays) | Yes | Yes | Yes |
| **CRDTs** | No | No | No | No | No | Yes (OrbitDB) | No | Yes (Merkle-CRDTs) |
| **Anonymous identity** | No | No | No | Partial | No | No | Partial | Yes (per-space) |
| **ZK credentials** | No | No | No | No | No | No | No | Yes (zk-promises) |
| **Decentralized** | No | Federated | Yes (P2P) | Yes | Yes | Yes | Yes | Yes |
| **Open standard** | Partial | Yes | Yes | Yes | Yes | Yes | Yes | Yes |
| **Group anonymity** | No | No | No | No | No | No | No | Yes |
| **Forward secrecy** | Yes | Partial | Yes | Partial | No | No | TBD | Yes (MLS) |
| **Post-compromise security** | Yes | Partial | Yes | No | No | No | TBD | Yes (MLS) |

No row in this table is unique to VOS. Other systems achieve
individual properties — often better than a first version of VOS
will. What no other system achieves is every row simultaneously,
designed as an integrated whole.

That is the gap VOS aims to fill.
