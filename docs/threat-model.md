# Threat Model & Design Principles

This chapter defines what Kunekt protects against, what it does not,
and the assumptions underlying those guarantees. Every security claim
in the rest of this book traces back to the adversary model and trust
assumptions described here.

---

## 1. Design Principles

These principles are inherited from the
[KryptOS Privacy OS](https://codeberg.org/kusama-zk/RFPs/src/branch/main/rfp/000-privacy-os.md)
philosophy and govern every design decision in the protocol.

### Privacy as default

Protection applies automatically. Encryption, anonymity, and metadata
protection are on by default. Users may choose to *reduce* privacy for
convenience (e.g. linking a public Nostr identity to a space), but the
default posture is maximum protection. An application built on Kunekt
is private without the developer doing anything special.

This is not a philosophical preference — it is a design constraint.
Systems where privacy is opt-in fail in practice because most users
never opt in, and those who do stand out. When everyone is private,
no one stands out.

### Cryptographic verification over institutional trust

No component in the stack is trusted to behave correctly. Relays,
storage backends, other peers, even moderators — all are verified
mathematically rather than trusted socially.

- Content integrity is verified by CID (hash the data, compare).
- Group membership is verified by MLS key schedule or ZK proof.
- Moderation actions are verified by zk-promises proofs.
- Storage faithfulness is verified by proof of retrievability.

If a component cannot prove its claim, it is rejected. There is no
"trusted server" anywhere in the architecture.

### System integration

Components function as cohesive layers, not isolated tools. Sync,
encryption, anonymity, storage, and credentials are designed together
so there are no gaps between them.

A gap between layers is where metadata leaks. If encryption and
transport are designed separately, the encryption layer may assume
the transport hides IP addresses — but it does not. If the sync layer
and the storage layer are designed separately, access patterns leak
through the storage API. Kunekt's layered architecture
([Architecture](./architecture.md)) explicitly defines what each layer
hides from the one below and what it expects from the one above.

### Developer accessibility

Building a private application should not require cryptography
expertise. The SDK abstracts the complexity: a developer calls
`create_space()`, `apply()`, `sync()`. The protocol handles key
management, anonymous credentials, DAG replication, and relay
communication internally.

This principle has a direct security implication: if privacy is hard
to use correctly, developers will use it incorrectly. The API must
make the secure path the easy path.

### Open standards

All protocols, specifications, and code are open and community-driven.
Kunekt builds on IETF standards (MLS, RFC 9420), published research
(Merkle-CRDTs, zk-promises), and open-source implementations
(OpenMLS, Arkworks, Automerge). No vendor lock-in, no proprietary
components, no security through obscurity.

---

## 2. Adversary Model

Each adversary type is defined by its *position* (where in the
system it sits), its *capabilities* (what it can do), and its
*goals* (what it wants to learn or disrupt).

### 2.1 Passive network observer

| Property | Description |
|---|---|
| **Position** | On the network path between peers and relays |
| **Capabilities** | Observes all traffic on its links: source/destination IPs, packet sizes, timing, frequency. Cannot modify or inject traffic. |
| **Goals** | Learn who talks to whom, when, how often, and infer what they are doing. |

**Example:** An ISP, a Wi-Fi access point operator, or an entity
tapping a network link.

**What Kunekt does:** Content is encrypted (MLS), so the observer
sees only ciphertext. Connections are routed through Tor (Phase 2)
or a mix network (Phase 4), hiding the true endpoints. Uniform
envelope sizes and batched posting (Phase 4) resist traffic analysis.

**Residual risk:** Timing correlation between a user coming online
and activity appearing on a relay is possible with Tor. Mix networks
with cover traffic (Phase 4) address this.

### 2.2 Malicious relay operator

| Property | Description |
|---|---|
| **Position** | Controls one or more Nostr relays used by a space |
| **Capabilities** | Logs all events stored and fetched. Correlates pubkeys, tags, timestamps, IP addresses (if not using Tor), and subscription filters. Can selectively drop, delay, or refuse events. |
| **Goals** | Deanonymize users, learn group membership and activity, censor content. |

**Example:** A Nostr relay operator with a logging infrastructure,
or a relay coerced by a legal order.

**What Kunekt does:**
- Content is opaque ciphertext — the relay cannot read it.
- Tags are HMAC-derived (Phase 3), meaningless to the relay, and
  rotate every MLS epoch.
- Signing keys are MLS-derived (Phase 1-2) or blind-signed
  ephemeral keys (Phase 3+), preventing member identification.
- Connections arrive over Tor/mix network, hiding IPs.
- Users publish to multiple relays; no single relay sees everything.

**Residual risk:** A relay can deny service (drop events). Mitigation:
replicate across multiple independent relays; availability requires at
least one honest relay (see Trust Assumptions).

### 2.3 Colluding relays

| Property | Description |
|---|---|
| **Position** | Multiple relay operators sharing data |
| **Capabilities** | Combines views from all participating relays. Can correlate events, timing, and subscription patterns across relays. Stronger traffic analysis than a single relay. |
| **Goals** | Build a more complete picture of user activity than any single relay could. |

**What Kunekt does:** The same defenses as against a single relay
apply, but the threat is amplified. Key additional defenses:
- Opaque tags change every epoch, preventing cross-epoch correlation
  even if relays share data.
- Blind-signed ephemeral keys (Phase 3+) are unlinkable across
  relays — a user can use a different key on each relay.
- Cover traffic makes it hard to distinguish real from dummy events
  even with a combined view.

**Residual risk:** If all relays a user publishes to collude, they can
combine timing and volume to estimate activity patterns. The mix
network layer (Phase 4) is the primary defense: the relays never see
the true sender.

### 2.4 Compromised group member

| Property | Description |
|---|---|
| **Position** | A legitimate member of a space who turns adversarial |
| **Capabilities** | Holds current MLS epoch keys — can decrypt all content in the space for the current epoch. Can record all plaintext they observe. Can attempt to link anonymous posts to members via side channels (timing, writing style, behavior patterns). |
| **Goals** | Identify anonymous members, leak decrypted content, attribute anonymous posts. |

**What Kunekt does:**
- Per-space identities prevent the compromised member from linking
  a target's identity across spaces.
- zk-promises anonymity: even a member who can decrypt content
  cannot link a post to a specific member — the ZK proof reveals
  nothing about the poster's identity within the group.
- Forward secrecy: content from before the compromised member
  joined is encrypted under earlier MLS epochs they do not have.
- Post-compromise security: once the compromised member is removed,
  MLS rotates keys and future content is inaccessible to them.

**Residual risk:** A compromised member can record all plaintext
they observe while a member. This is fundamental — any member who
can read content can copy it. Kunekt cannot prevent screenshot-level
leaks. Additionally, stylometric analysis of decrypted content may
allow a sophisticated member to attribute anonymous posts (see
Section 5).

### 2.5 Expelled member

| Property | Description |
|---|---|
| **Position** | Was a legitimate member, now removed from the MLS group |
| **Capabilities** | Holds old MLS epoch keys (for epochs they participated in). May still have network access to relays. May attempt to rejoin under a new identity. |
| **Goals** | Read content posted after their removal, rejoin the space, disrupt operations. |

**What Kunekt does:**
- **Post-compromise security (MLS):** Upon removal, the MLS group
  performs a Commit that updates the key schedule. The expelled member
  does not have the new epoch secret and cannot derive future keys.
  All content encrypted under the new epoch is unreadable to them.
- **Membership tree update:** The expelled member's commitment is
  removed from the membership Merkle tree. They can no longer produce
  a valid ZK membership proof.
- **Relay access control:** With blind-signed ephemeral keys
  (Phase 3+), the expelled member cannot obtain new authorized
  relay keys after removal.

**Residual risk:** The expelled member retains old epoch keys and
can decrypt any content from their membership period. This is by
design — they were a legitimate member during that time. Kunekt
guarantees forward secrecy (new members cannot read old content)
and post-compromise security (expelled members cannot read new
content), but does not retroactively revoke access to content
already decrypted.

Rejoining under a new identity is possible if the space's admission
policy does not prevent it. Cross-space ban detection (Phase 3) can
mitigate this: "prove you have not been banned from more than N
spaces."

### 2.6 Global passive adversary

| Property | Description |
|---|---|
| **Position** | Observes all network links simultaneously |
| **Capabilities** | Sees all traffic entering and leaving every relay, every Tor node, every mix node. Can perform timing correlation across the entire network. Cannot break cryptographic primitives. |
| **Goals** | Deanonymize users via traffic analysis, map the social graph, identify which users participate in which spaces. |

**Example:** A nation-state signals intelligence agency.

**What Kunekt does:**
- **Tor** provides routing anonymity but is vulnerable to a GPA
  that observes both the entry and exit of a circuit (correlation
  attack). Tor does *not* claim resistance to a GPA.
- **Mix network (Nym, Phase 4)** provides stronger protection:
  messages are batched, delayed, and mixed across multiple nodes.
  A GPA must break the mixing function, not just correlate timing.
- **Cover traffic** maintains a constant traffic rate, making it
  harder to correlate silent periods with user inactivity.
- **Uniform envelopes** prevent classification of traffic by content
  type or operation size.

**Residual risk:** A GPA with sufficient resources and time can
potentially perform statistical attacks against mix networks,
especially if the anonymity set is small. This is an inherent
limitation of any online communication system. Kunekt's defense
degrades gracefully: even under a GPA, the adversary learns *at
most* communication patterns — never content (which remains
encrypted under MLS).

### 2.7 Malicious storage backend

| Property | Description |
|---|---|
| **Position** | Operates a storage service (local disk, cloud, DA layer) |
| **Capabilities** | Stores data but attempts to learn access patterns — which CIDs are read/written, how often, by whom. May selectively deny service or tamper with stored data. |
| **Goals** | Correlate users to data, build access profiles, deny service to targeted users. |

**What Kunekt does:**
- All stored data is encrypted — the backend sees opaque blobs.
- CIDs are content hashes that reveal nothing about content
  semantics.
- **PIR (Phase 4):** Private Information Retrieval prevents the
  backend from learning which CIDs are fetched.
- **Erasure coding (Phase 4):** Data is split across multiple
  backends — no single backend holds enough to reconstruct.
- **Proof of retrievability (Phase 4):** The backend must prove it
  faithfully stores data without the user downloading it to check.
- CID integrity verification: data fetched from any backend is
  verified by recomputing the hash.

**Residual risk:** A backend can deny service. Replication across
multiple backends mitigates this. Write patterns (when new data
appears) are visible unless the user posts through a mix network
with cover traffic.

---

## 3. Trust Assumptions

Kunekt's security guarantees depend on the following assumptions.
If any assumption is violated, the corresponding guarantees may
not hold.

### What we trust

| Assumption | What it means | If violated |
|---|---|---|
| **Cryptographic primitives are sound** | SHA-256 is collision-resistant. AES-256 is semantically secure. Groth16/PLONK proofs are zero-knowledge and sound. MLS key schedule is secure (RFC 9420). Elliptic curve discrete log is hard. | Content may be decrypted. Proofs may be forged. The entire security model collapses. |
| **Local device integrity** | The user's device has not been compromised. The root secret stored on the device is accessible only to the Kunekt application. | Attacker obtains the root secret and can derive all per-space keys, decrypt all content, and impersonate the user in all spaces. See Section 5. |
| **At least one honest relay is available** | For any given space, at least one of the configured relays is reachable and will faithfully store and serve events. | Liveness degrades: the space cannot sync if all relays are down or censoring. Privacy is not affected — relays are never trusted for confidentiality. |
| **Anonymity network assumptions hold** | Tor: no single entity observes both entry and exit of a circuit. Nym: the mixing function provides the claimed anonymity set, and mix nodes do not all collude. | Routing anonymity is weakened or broken. Content remains encrypted, but the adversary may learn who communicates with whom. |
| **CRDT convergence** | The CRDT operations used (Automerge, GSet, LWW-Map, etc.) are mathematically convergent: all peers applying the same set of operations in any order arrive at the same state. | Peers diverge. This is a correctness property, not a security property, but divergence could be exploited to cause confusion. |

### What we do not trust

| Component | Why not | How we verify instead |
|---|---|---|
| **Relays** | Relays see metadata, can log, can censor. | Encrypt content before it reaches the relay. Use opaque tags. Connect via Tor/mix network. Replicate across multiple relays. |
| **Storage backends** | Backends can observe access patterns and deny service. | Encrypt all stored data. Use PIR for reads (Phase 4). Erasure-code across backends. Verify integrity by CID. |
| **Other group members (for your identity)** | A member who can decrypt content might try to identify anonymous posters. | Per-space identities. zk-promises anonymity (ZK proofs reveal nothing about the poster). No cross-space linkage at the cryptographic level. |
| **Moderators** | Moderators issue penalties but must not learn who they penalize. | zk-promises callbacks target tickets, not identities. The moderator never learns which member holds the ticket. |
| **The network** | The network is assumed to be adversary-controlled. | End-to-end encryption (MLS). Anonymity routing (Tor/Nym). Cover traffic. Uniform envelopes. |

---

## 4. Security Goals

Each goal is mapped to the adversaries it defends against and the
protocol mechanisms that provide the defense.

### Confidentiality

> Content is readable only by current group members.

| Adversary | Defense |
|---|---|
| Passive network observer | MLS encryption: all DAG node payloads are ciphertext |
| Malicious relay operator | Relay stores only encrypted blobs; cannot decrypt without MLS epoch key |
| Expelled member | Post-compromise security: MLS key rotation on removal |
| Malicious storage backend | All stored data is encrypted; backend has no keys |

**Mechanism:** OpenMLS group ratchet. Every DAG node payload is
encrypted with the current MLS epoch key before leaving the local
peer. See [Encryption](./encryption.md).

### Integrity

> Tampered data is detected and rejected.

| Adversary | Defense |
|---|---|
| Malicious relay operator | CID verification: `hash(data) == claimed CID` |
| Malicious storage backend | Same CID verification on every fetch |
| Compromised group member | DAG structure is append-only; tampering requires producing a valid hash, which requires knowing the content |

**Mechanism:** Content addressing. Every Merkle-DAG node's identity
is its content hash. Any modification changes the hash and is
immediately detectable. See [Sync](./sync.md).

### Anonymity

> Actions cannot be linked to a real-world identity.

| Adversary | Defense |
|---|---|
| Passive network observer | Tor/Nym hides IP address |
| Malicious relay operator | Ephemeral signing keys; opaque tags; no persistent identity |
| Compromised group member | zk-promises: ZK proof of authorization reveals nothing about which member is acting |
| Global passive adversary | Mix network with cover traffic (Phase 4) |

**Mechanism:** Per-space keypairs (no cross-space linkage), anonymous
routing (Tor/Nym), zk-promises anonymous credentials (Phase 3). See
[Privacy Analysis](threat-model.md).

### Unlinkability

> Actions across different spaces cannot be correlated to the same person.

| Adversary | Defense |
|---|---|
| Colluding relays | Different ephemeral keys per space; no shared identifier |
| Compromised group member in one space | Per-space credentials derived independently; no cryptographic link to other spaces |
| Global passive adversary | Mix network prevents correlating traffic to different relays |

**Mechanism:** Per-space identity derivation from the root secret.
Each space gets a fresh keypair and credential commitment. The
derivation is deterministic (the user can regenerate it) but
unlinkable without knowing the root secret.

### Forward secrecy

> Past content remains safe if current keys are compromised.

| Adversary | Defense |
|---|---|
| Compromised group member (current) | MLS ratchet: each epoch uses a different key derived from a one-way key schedule. Compromising the current epoch key does not reveal past epoch keys. |
| Expelled member | They hold old keys (for their membership period), but this is expected — they were legitimate members. New members joining *after* an epoch cannot derive keys for epochs before they joined. |

**Mechanism:** MLS key schedule (RFC 9420). The ratchet tree
provides forward secrecy by design. See [Encryption](./encryption.md).

### Post-compromise security

> Future content is safe after a compromise is detected and keys are rotated.

| Adversary | Defense |
|---|---|
| Expelled member | MLS Commit on removal rotates the key schedule. The expelled member cannot derive new epoch keys. |
| Compromised group member (detected) | Remove the compromised member from MLS → key rotation → future content is encrypted under a key the adversary does not have. |

**Mechanism:** MLS membership change triggers a Commit that updates
the ratchet tree. The new epoch secret is derived from values the
removed/compromised member does not possess.

### Availability

> The system continues to function if at least one peer or relay is reachable.

| Adversary | Defense |
|---|---|
| Malicious relay operator (censoring) | Multi-relay replication: if one relay drops events, others serve them |
| Malicious storage backend (denying service) | Erasure coding across multiple backends (Phase 4); local copy always available |
| Network disruption | Offline-first: peers continue editing locally and sync when connectivity returns |

**Mechanism:** Merkle-CRDT sync requires only one reachable peer or
relay to exchange data. CRDTs converge regardless of sync order or
timing. Local storage ensures the user's own data is always
accessible.

### Accountability without identity

> Bad actors can be penalized without being identified.

| Adversary | Defense against misuse |
|---|---|
| Spammer / abuser | zk-promises: rate limiting and reputation enforced via ZK proof; exceeding limits makes further action impossible |
| Moderator abuse | Callbacks are public on the bulletin board; the community can audit that callbacks are justified (the post is visible, the penalty is visible, only the poster's identity is hidden) |

**Mechanism:** zk-promises framework (Phase 3). Users hold private
state (reputation, rate-limit counter, ban flag). Moderators issue
callbacks against anonymous tickets. Users must process callbacks
before their next action. See [Anonymous Moderation](./zk-promises.md).

---

## 5. What We Explicitly Do Not Protect Against

Honest security engineering requires stating limitations clearly.
The following threats are outside Kunekt's defense perimeter.

### Compromised local device

If the user's device is compromised (malware, physical seizure, root
access by an attacker), the root secret is exposed. The attacker can
derive all per-space keys, decrypt all locally-stored content, and
impersonate the user.

**Why we accept this:** Securing the local device is the
responsibility of the operating system and the user. No application-
layer protocol can protect against an adversary with root access to
the device. This is the standard assumption in all end-to-end
encryption systems (Signal, MLS, etc.).

**Mitigation (outside protocol scope):** Hardware-backed key storage
(TPM, Secure Enclave), full-disk encryption, device PINs/biometrics.

### Stylometric analysis

An adversary who can read decrypted content (e.g. a compromised group
member) may use writing style, vocabulary, grammar patterns, or
behavioral traits to deanonymize anonymous posts.

**Why we accept this:** Stylometric deanonymization operates on
semantic content, which is outside the protocol's scope. Kunekt
guarantees that the *protocol* reveals nothing about the poster's
identity. It cannot guarantee that the *content itself* does not
reveal it.

**Mitigation (application-level):** LLM-based style normalization
tools, standardized templates, or collaborative editing where
multiple people contribute to the same text.

### Coercion and rubber-hose attacks

An adversary who can compel a user to reveal their root secret (via
legal order, physical threat, or social pressure) bypasses all
cryptographic protections.

**Why we accept this:** No cryptographic protocol can resist an
adversary who can compel cooperation. This is a physical security
problem.

**Mitigation (outside protocol scope):** Plausible deniability
(duress keys that reveal a decoy space) is a potential future
feature but is not part of the current design.

### Application-level bugs

A bug in a Kunekt-based application might leak sensitive information
through side channels: logging plaintext to disk, displaying content
in notifications, including metadata in error reports, or misusing
the SDK API.

**Why we accept this:** Kunekt provides a private-by-default SDK, but
cannot control how applications use it. The SDK is designed to make
the secure path easy, but cannot prevent all misuse.

**Mitigation:** SDK design (secure defaults, no footguns in the API),
security audits of applications, clear documentation of what
developers must not do.

### Quantum computers

Kunekt's current cryptographic primitives (elliptic curve Diffie-
Hellman in MLS, secp256k1 for Nostr signatures, Groth16/PLONK for
ZK proofs) are vulnerable to quantum computers running Shor's
algorithm.

**Why we accept this for now:** Practically relevant quantum computers
do not yet exist. Post-quantum alternatives for group key agreement
and zero-knowledge proofs are actively researched but not yet mature
enough for production use.

**Mitigation:** Phase 6 includes post-quantum migration: hybrid mode
(classical + post-quantum proofs during transition), hash-based
signatures for long-term data authenticity, and migration to lattice-
based ZK systems as they mature. See Development Phases.

### Denial of service by all relays

If every relay a space uses simultaneously drops or refuses events,
the space cannot sync between peers that are not directly connected.
Local editing continues but multi-peer collaboration stalls.

**Why we accept this:** Guaranteeing availability against a powerful
adversary that controls all infrastructure is fundamentally impossible
without trusted components. Kunekt mitigates by encouraging relay
diversity and supporting multiple storage backends.

---

## 6. Summary: Adversary vs. Goal Matrix

The following table summarizes which security goals hold against
each adversary. Checkmarks indicate the goal is achieved; dashes
indicate it is not applicable; question marks indicate partial or
conditional protection.

```
                          Confid.  Integr.  Anon.  Unlink.  Fwd.Sec  PCS   Avail.  Acct.
                          ──────   ──────   ─────  ──────   ───────  ───   ──────  ─────
Passive observer            ✓        ✓       ✓      ✓        ✓       ✓      ✓       —
Malicious relay             ✓        ✓       ✓      ✓        ✓       ✓      ?¹      —
Colluding relays            ✓        ✓       ✓      ✓        ✓       ✓      ?¹      —
Compromised member          —²       ✓       ✓³     ✓        ✓       ✓      ✓       ✓
Expelled member             ✓        ✓       ✓      ✓        —⁴      ✓      ✓       —
Global passive adversary    ✓        ✓       ?⁵     ?⁵       ✓       ✓      ✓       —
Malicious storage           ✓        ✓       ✓      ✓        ✓       ✓      ?¹      —
Compromised device          ✗        ✗       ✗      ✗        ✗       ✗      ✓       ✗
```

**Notes:**

1. Availability depends on at least one honest relay/backend being
   reachable. If the adversary controls all of them, availability
   is lost.
2. A current member can read current content by definition — they
   hold the epoch key. Confidentiality against current members is
   not a goal.
3. Anonymity within the group requires Phase 3 (zk-promises). Before
   Phase 3, members are pseudonymous (per-space keypair), not fully
   anonymous.
4. Expelled members retain keys for their membership period. Forward
   secrecy protects content from *before* they joined, not content
   during their membership.
5. Protection against a global passive adversary is conditional on
   the anonymity network (Tor: partial; Nym mix network with cover
   traffic: stronger). Full resistance requires Phase 4.
