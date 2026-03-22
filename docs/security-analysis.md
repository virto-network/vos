# Security Analysis & Open Questions

This chapter assesses Kunekt's security properties honestly: what the
protocol achieves, what it does not, and what remains unresolved. Every
claim is tied to the specific mechanism that provides it, and every
limitation is stated plainly with its implications.

For the threat model and adversary definitions, see
[Threat Model & Design Principles](./threat-model.md). This chapter
builds on that foundation by evaluating the protocol's actual security
posture.

---

## 1. Security Properties Achieved

Each property states a claim, identifies the mechanism that provides
it, and notes the conditions under which it holds.

### Content confidentiality

**Claim:** Only current members of a space can read document content.

**Mechanism:** MLS (RFC 9420) group ratchet. Every DAG node payload is
encrypted with the symmetric key derived from the current MLS epoch
secret before leaving the local peer. The epoch key is known only to
members who have processed the relevant MLS Commit or Welcome message.

**Conditions:** Holds as long as (a) the MLS key schedule is secure
(standard assumption for RFC 9420), (b) AES-128-GCM is semantically
secure, and (c) no current member leaks plaintext. Condition (c) is
fundamental — any member who can read content can copy it. The protocol
cannot prevent screenshot-level exfiltration.

See [Encryption](./encryption.md), sections 1 and 4.

### Data integrity

**Claim:** Tampered data is detected and rejected by any peer.

**Mechanism:** Content addressing. Every Merkle-DAG node's identity is
the cryptographic hash (Blake3 or SHA-256) of its serialized contents.
A peer that receives a node recomputes the hash and compares it to the
claimed CID. Any modification — to the payload, the children list, or
the framing — produces a different hash and is rejected.

**Conditions:** Holds as long as the hash function is collision-resistant.
For Blake3-256 and SHA-256, this is a standard assumption.

See [Sync](./sync.md), section 2.

### Forward secrecy

**Claim:** Compromising a member's current epoch key does not expose
content from previous epochs.

**Mechanism:** MLS key schedule. Each epoch derives its keys from a
one-way key derivation function. The `init_secret` from epoch N seeds
epoch N+1, but epoch N+1's secret cannot be reversed to recover epoch
N's keys. Old epoch secrets are deleted from device memory after
ratcheting.

**Conditions:** Holds as long as (a) the KDF is one-way (HKDF-SHA256,
standard assumption), (b) old epoch keys are deleted from device
storage after ratcheting, and (c) the device is not compromised while
old keys are still in memory.

**Nuance for CRDTs:** Forward secrecy protects the *operation history*
(individual DAG nodes from past epochs), not the *CRDT state*. The
current state reflects all past operations and is available to any
current member. A new member joining at epoch N cannot decrypt DAG
nodes from epochs 0 through N-1, but can see the materialized document
state that resulted from those operations. This is deliberate — see
[Encryption](./encryption.md), section 7 for the full discussion.

### Post-compromise security

**Claim:** After a compromised member is removed and keys are rotated,
the attacker cannot read new content.

**Mechanism:** MLS Commit on member removal. The ratchet tree path from
the removed member's leaf to the root is re-keyed. The new epoch secret
is derived from values the removed member does not possess (the
UpdatePath encrypted to remaining members only).

**Conditions:** Holds as long as (a) the MLS ratchet tree update is
secure (standard assumption for RFC 9420), and (b) at least one
remaining member is honest and processes the removal Commit.

### Anonymity within group

**Claim:** In anonymous mode (Phase 3), members perform actions without
revealing which member they are, even to other members and moderators.

**Mechanism:** zk-promises `ShowAuthorized` proof. The member proves in
zero knowledge: "I know a secret committed in this space's membership
Merkle tree, my reputation is above threshold, I am not banned, and my
rate limit is not exhausted." The proof reveals none of these values —
only that the statement is true.

**Conditions:** Holds as long as (a) the Groth16 proof system is
zero-knowledge and sound, (b) the membership Merkle tree is correctly
maintained, and (c) side channels (timing, writing style, behavioral
patterns) do not leak identity. Condition (c) is outside the protocol's
control — see Section 2 and the [threat model](./threat-model.md),
section 5.

### Unlinkability across spaces

**Claim:** A user's identity in Space A cannot be cryptographically
linked to their identity in Space B.

**Mechanism:** Per-space key derivation. Each space gets a fresh keypair
derived from the root secret with the space identifier as context:
`space_secret = HKDF(root_secret, "kunekt/space/" || space_id)`.
There is no shared public key, credential, or identifier across spaces.

**Conditions:** Holds as long as (a) the HKDF derivation is secure
(the space secret reveals nothing about the root secret or other space
secrets), and (b) the user does not voluntarily link identities through
application-level behavior (e.g., sharing the same username in
multiple spaces).

See [Identity](./identity.md), section 1.

### Accountability without identity

**Claim:** Bad actors can be penalized (reputation reduced, rate-limited,
banned) without anyone learning who they are.

**Mechanism:** zk-promises callbacks. A moderator issues a callback
against an anonymous post's ticket. The callback is published to the
bulletin board (a CRDT document). The poster — and only the poster —
recognizes their ticket during their next `ScanOne` pass. They must
process the callback (update their private zk-object state) before
producing their next valid `ShowAuthorized` proof. If they fail to
process it, their proof is invalid and their next action is rejected.

**Conditions:** Holds as long as (a) the bulletin board is available
and consistent (all members see the same callbacks), (b) the zk-promises
cryptographic construction is sound, and (c) the user eventually comes
online to process the callback.

See [Anonymous Moderation](./zk-promises.md).

### Censorship resistance

**Claim:** No single entity can prevent content from being stored and
replicated.

**Mechanism:** Multiple independent storage backends (Nostr relays,
local databases, DA layers), content-addressed data (any source can
serve any node), and offline-first design (peers retain local copies).
A peer publishes to multiple relays. A single relay refusing events
does not prevent other relays from serving them. Even if all remote
storage is unavailable, local editing continues and syncs when any
peer or relay becomes reachable.

**Conditions:** Holds as long as at least one relay or peer is reachable
and honest. If an adversary controls all relays a space uses
simultaneously, remote sync stalls (though local operation continues).

---

## 2. Known Limitations

These are not bugs — they are constraints inherent to the design, known
tradeoffs, or areas where the current implementation accepts a weaker
guarantee in exchange for practicality.

### MLS ordering requirement

**Problem:** MLS Commits must be applied in a total order. If two
members simultaneously issue a Commit at the same epoch, the group
cannot apply both — each produces a different next epoch with a
different ratchet tree. CRDTs, by design, do not provide total ordering.

**Current solution:** Deterministic conflict resolution based on CID
comparison. When concurrent Commits are detected in the Merkle-DAG
(a fork), the Commit with the lexicographically lower CID wins. The
losing Commit's Proposals are re-proposed in the next epoch. Because
CIDs are deterministic hashes, every peer reaches the same resolution
independently.

**Risk:** This resolution strategy is a protocol-level design that has
not been formally verified. While it is deterministic and has been
reasoned about carefully (see [Encryption](./encryption.md), section 3),
subtle edge cases may exist — particularly around n-way forks, rapid
concurrent Commits, or interactions between MLS group state and CRDT
convergence. Formal verification of this mechanism is a priority for
the first security audit.

### Trusted setup (Groth16)

**Problem:** The zk-promises framework uses Groth16 proofs, which
require a per-circuit trusted setup ceremony. The setup produces a
structured reference string (SRS) that must be generated honestly. If
the setup is compromised (the toxic waste is not destroyed), an
attacker can forge proofs — they could bypass reputation checks, ignore
rate limits, or evade bans.

**Impact:** Soundness of the anonymous moderation system. A forged
`ShowAuthorized` proof would allow unauthorized actions. A forged
callback-processing proof would allow ignoring moderation penalties.

**Mitigation:** Use multi-party computation (MPC) for the setup
ceremony, where soundness holds as long as at least one participant is
honest. Long-term, migrate to a universal setup system (PLONK, Marlin)
that eliminates the per-circuit trusted setup entirely. This migration
is planned but not yet scheduled.

### Bulletin board availability

**Problem:** The zk-promises protocol requires the bulletin board to be
available and consistent. If the bulletin board is partitioned (some
members see different versions), moderation enforcement becomes
inconsistent — a user might produce a valid proof on one partition that
would be invalid on another.

**Current implementation:** The bulletin board is a CRDT document in the
space, synced via Merkle-CRDT like everything else. CRDTs guarantee
eventual consistency, so partitions are temporary. However, during a
partition, a user on one side might act without having processed a
callback that exists on the other side. When the partition heals and the
bulletin boards merge, the inconsistency is resolved — but the
unauthorized action has already occurred.

**Impact:** Moderation enforcement may lag during network partitions.
In practice, this means a penalized user might get a few extra actions
through before the penalty takes effect. The CRDT merge will eventually
make the penalty visible everywhere.

**Mitigation for high-stakes spaces:** Anchor the bulletin board to a
blockchain or DA layer with stronger consistency guarantees. This
trades latency for consistency.

### Timing side channels

**Problem:** Even with batching and uniform envelope sizes, a
sufficiently powerful adversary observing all network links may
correlate activity patterns. A user who is active in Space A and
Space B at correlated times might be linkable across spaces through
timing analysis, despite per-space key isolation.

**Current defenses (by phase):**
- Phase 2: Tor hides IP addresses but does not prevent timing
  correlation by a global passive adversary.
- Phase 4: Nym mix network with cover traffic. Messages are batched,
  delayed, and mixed. Cover traffic maintains a constant rate even
  during idle periods.

**Residual risk:** Cover traffic reduces but does not eliminate timing
leakage. The tradeoff is bandwidth: more cover traffic means better
anonymity but higher bandwidth cost. The optimal rate depends on the
anonymity set size and the adversary's resources — this is an active
research area with no definitive answer.

### Client-side proof generation cost

**Problem:** ZK proof generation (Groth16 via Arkworks) is
CPU-intensive. The `ShowAuthorized` proof takes approximately 300-900ms
on modern desktop hardware (native Rust). In WASM (browser), this
increases to approximately 1.5-3.5 seconds due to WASM runtime
overhead and the lack of SIMD optimization in most WASM environments.

**Impact:** Per-operation proofs are impractical. The protocol uses
session tokens (prove once at session start, then use a short-lived
token) to amortize the cost. This weakens anonymity within a session
— operations from the same session token are linkable to each other
(though not to a specific member).

**Future direction:** Newer proof systems designed for client-side
efficiency (Jolt, SP1, Binius) may reduce proving time to under 100ms,
making per-batch proofs practical. This is being evaluated but no
commitment has been made.

Low-power devices (phones, IoT) are disproportionately affected. The
`no_std` core of `merkle-crdt` runs on constrained devices, but the ZK
layer (Arkworks, `std`-only) does not. Devices without ZK capability
must delegate proof generation to a more powerful peer or skip anonymous
mode entirely.

### Key recovery is hard

**Problem:** There is no server holding a copy of the user's keys. If
all devices holding the root secret are lost and no recovery method was
set up, the user permanently loses access to every space, all stored
data, and all accumulated reputation.

**Current approach:** The SDK supports four recovery methods (social
recovery via Shamir's Secret Sharing, encrypted cloud backup, hardware
security key, mnemonic phrase) and prompts users to set up recovery
during onboarding. See [Identity](./identity.md), section 3.

**Residual risk:** Recovery requires proactive setup. Users who dismiss
the recovery prompt and later lose their device have no recourse.
Unlike centralized services, there is no "account recovery" department
to contact. This is an inherent tradeoff of decentralized identity and
must be communicated clearly to users.

### Quantum vulnerability

**Problem:** All current cryptographic primitives used by Kunekt are
vulnerable to quantum computers:

| Primitive | Used by | Quantum attack |
|---|---|---|
| ECDH (X25519) | MLS key agreement | Shor's algorithm |
| Ed25519 | MLS signatures, Nostr signing | Shor's algorithm |
| secp256k1 | Nostr event signing | Shor's algorithm |
| Groth16 (pairing-based) | zk-promises proofs | Quantum speedup for discrete log |
| BBS+ (pairing-based) | Cross-space credentials | Shor's algorithm |

**Impact:** A quantum computer capable of running Shor's algorithm at
sufficient scale could break key agreement (decrypting all content),
forge signatures (impersonating any member), and forge ZK proofs
(bypassing all anonymous moderation).

**Current status:** Practically relevant quantum computers do not exist
as of this writing. Post-quantum alternatives for group key agreement
(ML-KEM) are standardized (NIST FIPS 203), but post-quantum ZK proof
systems and pairing-based credential schemes are still in early research.

**Planned mitigation:** Phase 6 includes a post-quantum migration path:
hybrid mode (classical + post-quantum proofs during transition) and
hash-based signatures for long-term data authenticity. The migration
path for ZK proofs is less clear — lattice-based ZK systems are
actively researched but not yet mature enough for production.

**Harvest-now-decrypt-later risk:** An adversary recording encrypted
traffic today could decrypt it in the future with a quantum computer.
MLS forward secrecy limits the window (each epoch's key is independent),
but all content from a given epoch is vulnerable if the epoch key is
recovered via quantum attack on the ECDH exchange.

---

## 3. Open Research Questions

These are questions that do not have known solutions and require
further research, experimentation, or advances in the field.

### Can MLS work without any ordering requirement?

MLS (RFC 9420) was designed with an ordering service (Delivery Service)
in mind. Kunekt's CID-based conflict resolution provides a
deterministic tiebreaker for concurrent Commits, but this is a
pragmatic workaround, not a fundamental solution. Active research
directions include:

- **Decentralized MLS (dMLS):** Academic work on removing the ordering
  requirement from MLS entirely, replacing sequential epochs with a
  DAG-based epoch structure. This aligns naturally with Merkle-CRDTs
  but is not yet standardized.
- **TreeKEM variants:** Modified tree ratchet schemes that tolerate
  concurrent updates without conflict. Some proposals exist in the
  literature but have not been implemented at scale.
- **CRDT-native group encryption:** Designing a group key agreement
  protocol from scratch for CRDT environments, where concurrent
  key updates are commutative by construction. This is speculative
  but would eliminate the MLS ordering problem entirely.

### Can zk-promises proof generation be fast enough for per-operation proofs?

Current proving time (~700ms native, ~3s WASM) forces the use of
session tokens, which weaken per-operation anonymity. Reducing proving
time to under 50ms would allow per-batch proofs (one proof per 100ms
edit batch), significantly improving anonymity guarantees.

Promising directions:
- **Jolt:** A zkVM that achieves fast prover times by leveraging
  lookup arguments. Could reduce the circuit-specific overhead of
  zk-promises.
- **SP1:** A zkVM targeting developer experience and prover
  efficiency, with explicit WASM support.
- **Hardware acceleration:** GPU-based or FPGA-based proof generation
  for native clients.
- **Incremental proving:** Reuse parts of the previous proof when the
  zk-object state changes by only one field (e.g., reputation
  decremented by 10). This could reduce subsequent proofs to a small
  delta computation.

### Is there a practical PIR scheme for Nostr relay-scale databases?

Private Information Retrieval would allow peers to fetch DAG nodes from
relays without the relay learning which CIDs were requested. Current
PIR schemes face a fundamental tension:

- **Single-server computational PIR:** The server must perform work
  proportional to the entire database size per query. For a relay with
  millions of events, this is seconds per query — impractical for
  real-time sync.
- **Multi-server PIR:** Fast, but requires multiple non-colluding
  servers. This weakens the trust model (the servers must not share
  data).
- **SimplePIR and derivatives:** Recent schemes reduce server
  computation significantly, but still require substantial client-side
  preprocessing. Feasibility at Nostr relay scale (millions of events,
  hundreds of concurrent clients) has not been demonstrated.

An alternative approach: **keyword PIR** or **batch PIR** tailored to
the access pattern (fetching DAG nodes by CID, which is essentially
a key-value lookup). This is a more constrained problem than general
PIR and may admit more efficient solutions.

### Can recursive SNARKs practically verify entire DAG histories?

Phase 6 envisions using recursive proofs (Nova, SuperNova) so that
each DAG node carries an incrementally updated proof that the entire
history is valid. A new peer would verify one proof instead of walking
the entire DAG.

Open questions:
- **Proof accumulation overhead:** Each new DAG node must fold in the
  previous proof. What is the per-node overhead? If it exceeds the
  batching interval (100ms), recursive proofs are impractical for
  real-time collaboration.
- **Circuit complexity:** The recursive circuit must verify both the
  CRDT operation validity and the previous proof. For complex CRDT
  types (Automerge), the circuit size may be prohibitive.
- **Concurrent branches:** Nova assumes a sequential chain of proofs.
  A Merkle-DAG has concurrent branches. Merging two branches requires
  combining two independent proof chains, which is not natively
  supported by Nova's folding scheme. SuperNova or other multi-circuit
  folding schemes may help.

### How to prevent credential accumulation attacks?

Cross-space reputation (Phase 3) allows users to prove "I have good
standing in N spaces." An attacker with N Sybil identities could
accumulate credentials across manufactured spaces and present
convincing aggregate proofs.

The fundamental challenge: preventing Sybil attacks without a
centralized identity oracle is an open problem. Kunekt's planned
mitigations (rate-limited credential issuance, social vouching, optional
proof-of-personhood) raise the cost of attacks but do not eliminate
them. The question of what level of Sybil resistance is "good enough"
for practical anonymous reputation systems remains unresolved.

See [Identity](./identity.md), section 4 for the current approach.

### What is the optimal cover traffic rate?

Cover traffic (constant-rate dummy messages) is the primary defense
against timing analysis by a global passive adversary. Too little
cover traffic and real activity stands out. Too much and bandwidth
costs become prohibitive.

The optimal rate depends on:
- The anonymity set size (how many users are sending cover traffic).
- The adversary's observation capability (fraction of network links
  monitored).
- The application's activity pattern (bursty vs. continuous).
- The user's bandwidth constraints (mobile vs. desktop).

This is fundamentally a game-theoretic problem. There is no single
"correct" rate. Practical systems typically choose conservative
defaults and allow users to adjust, but the interaction between
individual user settings and collective anonymity is not well
understood.

---

## 4. Comparison of Security Properties

The following table compares Kunekt's security properties against
established secure communication systems. Each cell indicates whether
the property is achieved (Yes), not achieved (No), partially achieved
(Partial), or not applicable (N/A).

```
Property                    Kunekt          Signal       Matrix (E2EE)   Briar
                            (Phase 3+)
──────────────────────────────────────────────────────────────────────────────
Content confidentiality     Yes             Yes          Yes             Yes
  Mechanism                 MLS group key   Signal       Megolm session  Per-contact
                                            Protocol     keys            channel keys

Data integrity              Yes             Yes          Yes             Yes
  Mechanism                 CID (hash)      MAC          MAC/signature   MAC

Forward secrecy             Yes             Yes          Partial¹        Yes
  Mechanism                 MLS epoch       Double       Megolm limited  Bramble
                            ratchet         ratchet      ratchet         transport

Post-compromise security    Yes             Yes          Partial²        Yes
  Mechanism                 MLS removal +   Ratchet      Re-establish    New channel
                            key rotation    reset        session         on compromise

Group encryption            Yes (O(log n))  No³          Yes (O(n))      No⁴
  Mechanism                 MLS ratchet     Pairwise     Megolm (sender  Pairwise
                            tree            for groups   key per member)

Anonymity within group      Yes⁵            No           No              N/A⁶
  Mechanism                 zk-promises     Members      Members         1:1 only
                            ZK proofs       identified   identified

Unlinkability across        Yes             No           No              Partial⁷
  groups/spaces             Per-space keys  One identity One identity    Per-contact
                                                                         identity

Metadata protection         Yes (Phase 4)   Partial⁸     No⁹             Yes¹⁰
  Mechanism                 Tor/Nym +       Sealed       Server sees     Tor + no
                            cover traffic   sender       metadata        server

Decentralization            Yes             No¹¹         Partial¹²       Yes
  Mechanism                 P2P + relays    Signal       Federated       P2P
                            (no trust)      servers      servers

Offline editing             Yes             No¹³         No¹³            Yes¹⁴
  Mechanism                 CRDTs merge     Queue until  Queue until     Queue until
                            conflict-free   online       online          sync

Anonymous moderation        Yes⁵            No           No              No
  Mechanism                 zk-promises     N/A          Admin-based     N/A
                            callbacks
```

**Notes:**

1. Matrix Megolm has limited forward secrecy. Session keys are shared
   with new members, weakening FS guarantees within a session.
2. Matrix post-compromise security requires manual session
   re-establishment. Automatic healing is weaker than MLS.
3. Signal uses pairwise encryption for groups (sender keys), which is
   O(n) per message in terms of key distribution.
4. Briar supports only 1:1 contacts and small forums, not general
   group encryption.
5. Requires Phase 3 (zk-promises integration). Prior to Phase 3,
   members are pseudonymous (per-space keypair), not fully anonymous.
6. Briar is 1:1 only; group anonymity is not applicable.
7. Briar uses per-contact identities (different identity per contact),
   providing partial unlinkability.
8. Signal protects sender identity via sealed sender, but the Signal
   server still sees recipient, timing, and message sizes.
9. Matrix homeservers see full metadata: who sends to whom, when,
   room membership, and message sizes.
10. Briar uses Tor for all connections and does not rely on servers,
    providing strong metadata protection.
11. Signal requires Signal servers for message delivery and user
    registration (phone number).
12. Matrix is federated (users choose a server) but servers are
    trusted for availability and see metadata.
13. Signal and Matrix queue messages until the recipient is online;
    they do not support offline *editing* of shared state.
14. Briar supports offline operation and syncs when peers reconnect,
    but does not have CRDT-based conflict resolution.

---

## 5. Audit Roadmap

Security audits are planned in phases that align with the development
roadmap. Each audit phase targets the most critical code paths for
the corresponding protocol phase.

### Audit Phase 1: Core data path

**Scope:** The path from CRDT operation to encrypted, stored DAG node
and back.

**Components:**
- `merkle-crdt` crate: DAG construction, CID computation, sync
  protocol, topological sort, anti-entropy algorithm.
- MLS integration: OpenMLS configuration, epoch key derivation,
  encryption/decryption of DAG node payloads.
- MLS + Merkle-CRDT reconciliation: concurrent Commit resolution
  (CID-based tiebreaker), epoch transition during offline editing,
  key caching.
- Local storage encryption: key derivation from root secret, database
  encryption at rest.

**Priority:** This is the highest-priority audit. Every byte of user
data flows through this path. A bug here could break confidentiality
or integrity for all users.

**Timing:** Before the first production release (end of Phase 1
development).

### Audit Phase 2: Nostr adapter and transport

**Scope:** The interface between Kunekt and external infrastructure.

**Components:**
- Nostr relay adapter: event construction, tag computation
  (HMAC-based opaque tags), subscription filters, event retrieval.
- Nostr signing key derivation: MLS epoch secret to Nostr keypair.
- Tor integration (arti): connection management, circuit reuse
  policy, error handling.
- Relay discovery and selection logic.
- Multi-relay replication and consistency.

**Priority:** High. The Nostr adapter is the primary attack surface
for relay-based adversaries. Incorrect tag computation, signing key
handling, or subscription patterns could leak metadata.

**Timing:** Before Phase 2 production release.

### Audit Phase 3: ZK circuits and anonymous credentials

**Scope:** The zero-knowledge proof layer.

**Components:**
- zk-promises integration: `ShowAuthorized` circuit, callback
  processing circuit, bulletin board interaction.
- Membership Merkle tree: construction, update (as CRDT operation),
  ZK membership proof circuit.
- Anonymous session tokens: issuance, verification, expiry, linkability
  properties.
- Cross-space credential proofs: BBS+ selective disclosure integration,
  anonymity set estimation.
- Groth16 trusted setup: ceremony design, toxic waste handling.

**Priority:** High. ZK circuits are notoriously difficult to get right.
A bug in the `ShowAuthorized` circuit could allow unauthorized actions
(soundness failure) or leak member identity (zero-knowledge failure).
Both are catastrophic.

**Timing:** Before Phase 3 production release.

### Ongoing: Dependency audits

Kunekt integrates several large external dependencies that must be
monitored continuously:

| Dependency | What to monitor |
|---|---|
| OpenMLS | CVEs, protocol compliance, ratchet tree correctness |
| Arkworks | Proof system soundness, field arithmetic bugs |
| arti (Tor) | Circuit security, DNS leaks, timing side channels |
| Automerge | CRDT convergence correctness, serialization bugs |
| RustCrypto crates | Constant-time implementation, side channels |

**Process:** Subscribe to security advisories for each dependency.
Pin versions in `Cargo.lock`. Evaluate each update for security
implications before upgrading. Run `cargo audit` in CI.

### Bug bounty program

After the first production release, establish a bug bounty program
covering:
- Confidentiality breaks (decrypting content without group membership)
- Integrity breaks (forging a valid CID for tampered data)
- Anonymity breaks (identifying an anonymous poster from protocol
  data alone — not from content analysis)
- Soundness breaks (forging a ZK proof that verifies)
- Key recovery (deriving epoch keys without being a group member)

Bounty amounts should reflect severity. A confidentiality or soundness
break is critical. A metadata leak is important but less severe. The
program should explicitly exclude side channels that require physical
access to the device (covered by the "compromised device" exclusion in
the threat model).
