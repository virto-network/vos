# Glossary

Key terms used throughout the VOS protocol documentation,
listed alphabetically. Each entry includes a brief definition and the
VOS layer(s) where it is relevant.

---

**Anti-entropy** — A synchronization protocol where peers compare their
state and exchange missing data to converge. In VOS, anti-entropy
operates on the Merkle-DAG: peers exchange root CIDs, walk the DAG to
discover missing nodes, and fetch them. *Sync layer.*

**Automerge** — An open-source CRDT library for rich collaborative
data structures (text, JSON, tables). VOS uses Automerge as the
primary CRDT engine for rich text documents. Automerge changes are
serialized as Merkle-CRDT payloads. *Document layer.*

**BBS+ signatures** — A signature scheme that supports selective
disclosure: the signer signs a set of attributes, and the holder later
proves possession of the signature while revealing only a chosen subset
of attributes. Used in VOS for cross-space reputation credentials.
*Authorization layer, Identity.*

**Bulletin board** — An append-only log that serves as the shared state
for the zk-promises protocol. In VOS, implemented as a moderation
log document (a CRDT synced via Merkle-CRDT). Moderators post callbacks
here; users scan it for penalties targeting their tickets.
*Authorization layer.*

**Callback** — A moderator-issued penalty in the zk-promises protocol.
A callback targets a ticket attached to an anonymous post and specifies
an action (reduce reputation, ban, warn). The post's author must
process the callback before their next action. *Authorization layer.*

**CID (Content Identifier)** — A self-describing hash of a piece of
content. In VOS, every DAG node has a CID computed from its
contents. CIDs are location-independent: the same content always
produces the same CID regardless of where it is stored. *Sync layer,
Storage layer.*

**Commitment** — A cryptographic primitive that lets a party commit to
a value without revealing it, and later prove properties about the
committed value. VOS uses Pedersen commitments (`C = g^v * h^r`) for
membership credentials, balance proofs, and zk-object state.
*Authorization layer, Document layer.*

**Cover traffic** — Dummy messages indistinguishable from real ones,
sent at regular intervals to hide when genuine activity occurs. Prevents
traffic analysis from revealing activity patterns. *Transport layer.*

**CRDT (Conflict-free Replicated Data Type)** — A data structure that
can be replicated across peers and updated independently, with
concurrent updates merging automatically without conflicts. Every
VOS document is a CRDT. *Document layer.*

**DAG (Directed Acyclic Graph)** — A graph where edges have direction
and no cycles exist. In VOS, each document's edit history is stored
as a Merkle-DAG: each node points to its causal predecessors via their
CIDs. *Sync layer.*

**Data availability (DA) layer** — A system that guarantees published
data can be retrieved by anyone who needs it. Can be a blockchain or a
specialized data availability network. Used in VOS as an optional
storage backend with stronger availability guarantees than standalone
relays. *Storage layer.*

**Epoch** — A period during which a set of encryption keys is valid.
In MLS, a new epoch begins each time the group membership changes
(member joins, leaves, or keys rotate). Content encrypted under one
epoch's keys cannot be decrypted with another epoch's keys.
*Encryption layer.*

**Erasure coding** — A technique that splits data into `n` fragments
such that any `k` fragments (where `k < n`) can reconstruct the
original. Provides redundancy: data survives the loss of up to `n - k`
fragments. Used in VOS for distributed storage across multiple
backends. *Storage layer.*

**Forward secrecy** — A security property ensuring that compromise of
current keys does not reveal past communications. In MLS, forward
secrecy means a new member cannot decrypt messages sent before they
joined. *Encryption layer.*

**Groth16** — A zero-knowledge proof system that produces very small
proofs (~128 bytes) with fast verification (~3ms). Requires a trusted
setup per circuit. Used in the zk-promises reference implementation.
Can be replaced with a universal-setup system like PLONK.
*Authorization layer.*

**Homomorphic** — A property of an encryption or commitment scheme
where operations on ciphertexts correspond to operations on
plaintexts. For example, adding two ElGamal ciphertexts produces the
encryption of the sum of the plaintexts. Used in VOS for
anonymous voting tallies and balance conservation proofs.
*Document layer (voting, payments).*

**IPFS (InterPlanetary File System)** — A content-addressed distributed
file system. VOS does not depend on IPFS directly but shares the
same content-addressing model (CIDs). IPFS could serve as a storage
backend via the `Store` trait. *Storage layer.*

**KeyPackage** — An MLS data structure containing a member's public
keys and capabilities, used to add them to a group. In VOS, a
joining member submits a KeyPackage to receive a Welcome message and
join the space's MLS group. *Encryption layer.*

**Leaky bucket** — A rate-limiting algorithm where a bucket of tokens
drains at a fixed rate and is replenished over time. In VOS,
members prove in ZK that their rate-limit bucket is non-empty,
preventing spam without revealing activity history.
*Authorization layer.*

**MLS (Messaging Layer Security)** — An IETF standard (RFC 9420) for
group key agreement. Provides forward secrecy, post-compromise
security, and efficient key rotation for groups. VOS uses MLS to
manage encryption keys for each space. *Encryption layer.*

**Merkle-CRDT** — The combination of a CRDT with a Merkle-DAG. CRDT
operations are recorded as nodes in a hash-linked DAG. Sync reduces
to exchanging DAG nodes. Merge is set union — commutative, associative,
idempotent. The core replication mechanism of VOS. *Sync layer.*

**Merkle tree** — A binary tree where each leaf contains a hash of
data and each internal node contains the hash of its children. Enables
efficient proofs that a leaf is included in the tree by providing a
logarithmic-size path from leaf to root. Used in VOS for membership
proofs. *Authorization layer, Document layer.*

**Mix network** — An anonymity network where messages are batched,
padded, delayed, and routed through multiple mix nodes. Provides
stronger metadata protection than onion routing because messages are
mixed (shuffled) at each hop. Nym is a mix network. *Transport layer.*

**Nym** — A mix network implementation providing network-level privacy.
Messages are split into Sphinx packets, routed through three mix nodes
with random delays, and reassembled at the destination. Used in VOS
for high-sensitivity operations (credential proofs, governance votes).
*Transport layer.*

**Nullifier** — A deterministic value derived from a secret and a
context that prevents double-actions. If two operations produce the
same nullifier, one is a duplicate. The nullifier reveals nothing about
the secret. Used in voting (one-member-one-vote) and selective
double-action prevention. *Authorization layer.*

**Nostr** — A simple, open protocol for decentralized social networking
based on signed events relayed through WebSocket servers. Considered as a
possible untrusted storage/relay backend for encrypted DAG nodes, but not
part of the current design (VOS replicates over libp2p). *Storage layer.*

**ORAM (Oblivious RAM)** — A technique that hides access patterns from
the storage medium. Every read or write is indistinguishable from any
other, preventing the storage backend from learning which data is being
accessed. *Storage layer.*

**Onion routing** — An anonymity technique where messages are wrapped
in multiple encryption layers. Each relay peels one layer and forwards
the message. The destination sees the message but not the origin. Tor
uses onion routing. *Transport layer.*

**OpenMLS** — A Rust implementation of the MLS protocol (RFC 9420).
Handles group creation, key schedules, ratchet trees, proposals, and
commits. VOS wraps OpenMLS for per-space group key management.
*Encryption layer.*

**PIR (Private Information Retrieval)** — A protocol that lets a client
fetch an item from a database without the server learning which item
was requested. Used in VOS to fetch DAG nodes from storage backends
without revealing access patterns. *Storage layer.*

**PLONK** — A universal zero-knowledge proof system (no per-circuit
trusted setup). Slower proof generation than Groth16 but avoids the
trusted setup requirement. A candidate replacement for Groth16 in the
zk-promises layer. *Authorization layer.*

**Payload** — The `Payload` trait in the `merkle-crdt` crate. Defines
the CRDT logic for a document type: how operations are applied to state
and how states are merged. Developers implement this trait to create
custom document types. *Sync layer, Document layer.*

**Peer** — Any device participating in a VOS space. Peers are
equal — there is no leader or primary replica. Each peer keeps a local
encrypted copy of subscribed documents and syncs with other peers.
*Sync layer.*

**Post-compromise security** — A security property ensuring that after
a key compromise, the system recovers security through key rotation.
In MLS, removing a compromised member and advancing the epoch restores
confidentiality for subsequent messages. *Encryption layer.*

**Proposal (MLS)** — An MLS message that suggests a group change (add
member, remove member, update keys). A proposal must be committed by a
group member to take effect. In VOS, MLS proposals are recorded as
CRDT operations in the space's root document. *Encryption layer.*

**Proxy re-encryption** — A technique where a proxy transforms a
ciphertext encrypted under key A into a ciphertext encrypted under
key B, without the proxy learning the plaintext. Used in VOS for
selective file sharing: re-encrypt a file's key under a space's MLS
group key. *Storage layer, Encryption layer.*

**Ratchet tree** — The tree structure in MLS that manages per-member
key material. Each member is a leaf. Internal nodes hold shared
secrets used for key agreement. The tree enables efficient key
rotation: updating one leaf requires updating only the path to the
root (logarithmic in group size). *Encryption layer.*

**Relay** — A server that stores and forwards encrypted data. In
VOS, untrusted relays may serve as storage backends for encrypted DAG
nodes. Relays are untrusted: they see only opaque blobs and cannot
read, correlate, or attribute content. *Storage layer.*

**Root CID** — The CID of the most recent DAG node(s) in a document's
Merkle-DAG. The root CID represents the latest known state. Sharing
root CIDs between peers is the first step of anti-entropy sync.
*Sync layer.*

**Root secret** — The master secret key generated on a user's device
at first launch. All other cryptographic material (per-space keys,
credentials, storage encryption keys) derives from it. The root
secret never leaves the device and is never used directly for any
protocol operation. *Identity.*

**Selective disclosure** — The ability to reveal only specific
attributes from a credential while hiding the rest. Implemented via
BBS+ signatures or similar schemes. Enables proofs like "my reputation
is above 50" without revealing the exact score or which space issued
the credential. *Authorization layer, Identity.*

**Session token** — A short-lived blinded credential derived from a
ShowAuthorized proof. Authorizes operations within a session without
requiring a new ZK proof for each batch. Operations within a session
are linkable to each other but not to the member's identity.
*Authorization layer.*

**Space** — The top-level unit of collaboration in VOS. A space
owns an MLS group, a membership Merkle tree, a set of documents,
and a root document describing the space's configuration. All content
within a space is end-to-end encrypted. *Document layer, Encryption
layer.*

**Store trait** — The `Store` trait in the `merkle-crdt` crate.
Defines how DAG nodes are persisted and retrieved. Implementations
exist for in-memory storage, SQLite, and Nostr relays. Developers
can implement custom backends. *Storage layer.*

**Ticket (zk-promises)** — A pseudorandom value attached to an
anonymous action. Derived deterministically from the member's secret
and a nonce: `tik = PRF(s, nonce)`. Moderators issue callbacks
against tickets. The ticket is unlinkable to the member's identity.
*Authorization layer.*

**Topological sort** — An ordering of DAG nodes such that every node
appears after all of its predecessors (children in Merkle-DAG
terminology). Used during sync to apply CRDT operations in causal
order. *Sync layer.*

**Tor** — An onion routing network for anonymous communication.
VOS routes relay connections through Tor (via the `arti` Rust
crate) to hide users' IP addresses. Provides lower latency than a
mix network but weaker metadata protection. *Transport layer.*

**Welcome (MLS)** — An MLS message sent to a new member when they join
a group. Contains the group's current state (ratchet tree, epoch, group
context) encrypted under the new member's KeyPackage. The new member
uses it to derive current epoch keys. *Encryption layer.*

**zk-object** — A private state vector held by a member in the
zk-promises framework. Contains reputation score, rate-limit counter,
ban flag, and nonce. The member proves properties about the zk-object
in zero-knowledge without revealing its contents.
*Authorization layer.*

**zk-promises** — A framework for anonymous actions with accountable
consequences. Users act anonymously while maintaining provable private
state (reputation, rate limits, bans). Moderators penalize actions via
callbacks without learning who they are penalizing. Based on the
[ePrint 2024/1260](https://eprint.iacr.org/2024/1260) paper.
*Authorization layer.*

**Zero-knowledge proof** — A cryptographic proof that a statement is
true without revealing any information beyond the truth of the
statement. Used throughout VOS for membership proofs, authorization,
balance proofs, vote validity, credential verification, and more.
*Authorization layer, Document layer, Identity.*
