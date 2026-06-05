# Identity: Multi-Device, Recovery & Cross-Space

VOS has no accounts, no usernames, no registration authority. A
user's identity is a root secret key generated on their device. Every
other credential, membership, and capability derives from it. This
design eliminates central points of trust but raises hard questions:
what happens when a user has multiple devices? What happens when a
device is lost? How does reputation travel across spaces without
linking identities?

This chapter addresses those questions.

---

## 1. Identity Architecture

### Derivation hierarchy

All cryptographic material derives from a single root secret through a
deterministic key derivation tree:

```
root_secret
 |
 +-- device_credential (ZK-compatible commitment to root_secret)
 |
 +-- space_secret[space_id]          (per-space, via KDF)
 |    |
 |    +-- mls_identity_key           (leaf in the MLS ratchet tree)
 |    +-- zk_object_secret           (private state for zk-promises)
 |    +-- credential_commitment      (leaf in the membership Merkle tree)
 |    +-- session_key[epoch]         (per-MLS-epoch encryption key)
 |
 +-- storage_key                     (local database encryption)
 +-- backup_key                      (encrypted backup derivation)
```

Derivation uses a KDF (e.g. HKDF-SHA256) with domain separation:
`space_secret = HKDF(root_secret, "vos/space/" || space_id)`. The
root secret is never used directly for any protocol operation — it
exists only to derive children.

### Why per-space isolation matters

Each space gets a fresh keypair derived from the root secret with the
space identifier as context. There is no cryptographic link between a
user's identity in Space A and Space B. An observer who compromises
both spaces sees two unrelated members.

This unlinkability is not a side effect — it is a core design goal.
Without it, an adversary who joins multiple spaces could correlate
members across them, build social graphs, and de-anonymize users
through intersection attacks. Per-space derivation prevents this
at the cryptographic level.

Unlinkability comes with a cost: reputation and trust do not transfer
automatically. A user with excellent standing in one space starts from
zero in another. Section 4 addresses this with selective disclosure
credentials that bridge the gap without breaking isolation.

### Device credential as ZK-compatible commitment

At identity bootstrap (first launch), the device computes a Pedersen
commitment to the root secret: `C = g^s * h^r` where `s` is the root
secret and `r` is a random blinding factor. This commitment is the
user's device credential.

The commitment is ZK-friendly by design. It can be used as a leaf in
Merkle trees and proven about in zero-knowledge circuits without
revealing `s`. Every per-space credential is derived from this
commitment, so the same ZK infrastructure works at every level:
proving space membership, proving reputation properties, proving
cross-space attributes — all reduce to proving knowledge of a secret
committed under a known group element.

---

## 2. Multi-Device Support

### The problem

The root secret lives on one device. Users have phones, laptops,
tablets, and expect all of them to participate in the same spaces with
the same identity. VOS has no server to mediate this. The protocol
must support multi-device use without introducing a central
coordinator or breaking the per-space unlinkability guarantees.

Three approaches are viable. They differ in security model, user
experience, and implementation complexity.

### Option A: Device linking via shared secret

The simplest approach. The user's first device holds the root secret.
To add a second device:

1. **Pairing.** The first device displays a QR code (or short code)
   containing the root secret encrypted under an ephemeral key. The
   new device scans it and obtains the root secret.

2. **Independent derivation.** Both devices now hold the same root
   secret. Each derives the same per-space keys deterministically —
   but each device gets its own MLS leaf in each space (identified by
   a device index appended to the derivation path).

3. **Device sync space.** A private space is created automatically,
   containing only the user's own devices as members. This space
   synchronizes device metadata: which spaces the user has joined,
   pending invites, credential updates, MLS epoch state. It uses the
   same Merkle-CRDT sync and MLS encryption as any other space.

4. **Per-space registration.** When a new device joins a space for the
   first time, an existing device of the same user issues an MLS Add
   proposal for the new device's leaf. The space sees a new MLS leaf
   but — if the space uses anonymous mode — cannot distinguish whether
   it belongs to a new user or an existing user's additional device.

**Tradeoffs:**

- The root secret is copied between devices. If the QR code is
  intercepted, the attacker gains full access. The transfer must
  happen over a secure local channel (camera scan, NFC tap, or local
  network with verified key exchange).
- Both devices can act independently. There is no "primary" device.
  If one device is compromised, the attacker has the root secret and
  can derive all per-space keys.
- Simple to implement. No threshold cryptography, no cross-signing
  infrastructure.

### Option B: Threshold secret sharing (Shamir)

The root secret is split into `n` shares using Shamir's Secret
Sharing. Any `k` of the `n` shares can reconstruct the root secret;
fewer than `k` shares reveal nothing about it.

1. **Initial split.** On first setup, the root secret is split into
   shares. Each device the user owns receives one share. Additional
   shares can be stored with trusted contacts or on backup media.

2. **Reconstruction.** To derive per-space keys, a device needs the
   root secret. It contacts `k-1` other devices (over the device sync
   space or local network), collects their shares, reconstructs the
   root secret in memory, derives the needed keys, and discards the
   reconstructed secret.

3. **Share refresh.** Shares can be periodically refreshed (proactive
   secret sharing) without changing the root secret. This limits the
   window of exposure if a share leaks.

**Tradeoffs:**

- More resilient: losing one device does not compromise the root
  secret (as long as fewer than `k` devices are compromised).
- More complex: every key derivation requires a threshold
  reconstruction ceremony. In practice, the device would reconstruct
  once per session and cache derived keys in memory.
- Latency: reconstruction requires communication with other devices.
  Not viable if only one device is available.
- The `k` threshold is a critical parameter. `k=1` degenerates to
  Option A. `k=n` means losing any device is catastrophic. A
  reasonable default is `k=2, n=3` (two devices + one backup share).

### Option C: Device-specific keys + cross-certification

Each device generates its own independent root secret. Devices are
linked by cross-signing each other's credentials.

1. **Independent secrets.** Each device has `root_secret_A`,
   `root_secret_B`, etc. Each derives its own per-space keys. There
   is no single shared root.

2. **Cross-certification.** When device B is added, device A signs a
   statement: "Device B's credential `C_B` belongs to the same user
   as my credential `C_A`." Device B signs the reciprocal statement.
   These cross-certificates are stored in the device sync space.

3. **Space membership.** Each device joins each space independently
   with its own derived keys. The space sees separate members. In
   non-anonymous spaces, the cross-certificates can be presented to
   prove "these two members are the same user." In anonymous spaces,
   a ZK proof can demonstrate "I hold a credential that is
   cross-certified by at least one other credential in this
   membership tree" — proving multi-device ownership without revealing
   which members are linked.

**Tradeoffs:**

- No single secret to steal. Compromising device A does not
  compromise device B.
- The space sees multiple members rather than one member with
  multiple devices. This affects member counts, rate limits (does the
  user get one rate-limit budget or two?), and voting (must ensure
  one-person-one-vote, not one-device-one-vote).
- Cross-certification creates a linkability risk: if the
  cross-certificates leak, an adversary learns which space members
  belong to the same user. The certificates must be stored only in
  the private device sync space, never disclosed to space peers.
- More complex ZK circuits. Proving "my two leaves belong to the same
  user without revealing which leaves" requires careful circuit
  design.

### Recommendation

**Option A for the initial implementation.** It is the simplest to
build, the easiest for users to understand ("scan this QR to link your
phone"), and fits naturally into VOS's existing architecture — the
device sync space is just another VOS space.

The device sync space serves as a private coordination channel:

- Synchronize the list of joined spaces and their current MLS epochs.
- Relay MLS Welcome messages so a new device can catch up on all
  spaces.
- Store encrypted backups of per-space state for faster device onboarding.
- Coordinate key rotation: if one device rotates a space key, others
  learn about it through the device sync space before they next connect
  to that space.

Option C should be revisited when the ZK infrastructure matures
(later), as it offers better security isolation between devices. A
hybrid approach is also possible: use Option A for the root secret but
give each device its own MLS signing key (derived from the shared root
with a device-specific path), so that MLS can distinguish devices for
forward secrecy purposes even though they share a root.

---

## 3. Key Recovery

### The problem

There is no server holding a copy of the user's keys. There is no
"forgot password" email. If the device holding the root secret is
lost, destroyed, or stolen, the user loses access to every space, all
stored data, and all accumulated reputation — unless recovery
mechanisms are in place before the loss occurs.

Recovery is not optional. It must be set up proactively (before the
device is lost) and it must not compromise the security model.

### Method 1: Social recovery

The user selects `n` trusted contacts and splits an encrypted backup
of the root secret into `n` shares using Shamir's Secret Sharing. Each
contact receives one share. To recover, the user contacts `k` of them
and collects their shares.

**Setup flow:**

1. The user selects recovery contacts from their existing spaces.
2. The root secret (or a backup encryption key derived from it) is
   split into `n` shares with threshold `k`.
3. Each share is encrypted under the recipient's space-scoped public
   key and delivered through the relevant space's encrypted channel.
4. The user's device stores metadata about which contacts hold shares
   (but not the shares themselves) in the device sync space.

**Recovery flow:**

1. The user installs on a new device. The device generates a temporary
   keypair.
2. The user contacts `k` recovery contacts through an out-of-band
   channel (phone call, in-person meeting, another messaging app).
3. Each contact's VOS app retrieves the stored share and sends it
   to the new device (encrypted under the temporary public key).
4. The new device reconstructs the root secret and resumes normal
   operation.

**Properties:**

- No single contact can recover the secret alone (threshold `k > 1`).
- Each share reveals nothing about the root secret individually
  (information-theoretic security of Shamir's scheme).
- Contacts do not need to know each other or coordinate. The user
  contacts them independently.
- The user must remember who their recovery contacts are. Storing this
  list in the device sync space creates a chicken-and-egg problem if
  all devices are lost — the user must remember at least some contacts
  from memory or external records.

**Risk:** Social engineering. An attacker who impersonates the user to
`k` contacts can recover the secret. Mitigation: require contacts to
verify the user's identity through a pre-agreed challenge (a shared
secret phrase, a video call, in-person verification).

### Method 2: Encrypted cloud backup

The root secret (or a derived backup key) is encrypted under a
user-chosen passphrase and stored on a relay, DA layer, or
conventional cloud storage.

```
backup_blob = Encrypt(KDF(passphrase, salt), root_secret || metadata)
```

The backup blob is pushed to one or more storage backends. The user
needs only the passphrase to recover on a new device.

**Properties:**

- Simple user experience: "remember this passphrase."
- The passphrase becomes the security boundary. If it is weak, an
  attacker who obtains the backup blob can brute-force it. Use a
  memory-hard KDF (Argon2id) with aggressive parameters.
- The storage backend sees an opaque blob. It cannot determine whether
  it is a VOS backup or random data (assuming uniform-size blobs).

**Risk:** Passphrase reuse, weak passphrases, phishing. This method
shifts trust from the protocol to the user's passphrase discipline. It
should be offered as an option, not as the default.

### Method 3: Hardware security key

The root secret is backed up to a hardware token (YubiKey, Ledger,
Trezor, or a generic FIDO2 device).

- The hardware token stores the root secret (or a backup encryption
  key) in tamper-resistant hardware.
- Recovery: plug in the token, authenticate (PIN or biometric), extract
  the backup key.
- The token can also serve as a second factor for the device sync
  space.

**Properties:**

- Strong security: the backup is physically isolated.
- Risk of physical loss of the token itself. Mitigate by combining
  with another recovery method.

### Method 4: Mnemonic phrase (paper backup)

The root secret is encoded as a BIP-39-style mnemonic phrase (12 or 24
words). The user writes it down and stores it securely (safe, safety
deposit box, engraved metal plate).

```
root_secret → 256 bits → BIP-39 encoding → 24 words
```

**Properties:**

- No electronic dependency. Survives device failure, cloud outages,
  and network partitions.
- Physical security risk: anyone who reads the phrase has full access.
- Users frequently store mnemonics insecurely (photos, notes apps,
  email drafts). Education and UX nudges are important.

### Recommendation

Support all four methods. Present them as layers of a recovery
strategy, not as mutually exclusive choices:

1. **Social recovery as the default.** Set up during onboarding with a
   guided flow: "Choose 3 trusted contacts. Any 2 can help you
   recover." This provides the best balance of security and usability
   for non-technical users.
2. **Mnemonic phrase as the fallback.** Displayed once during setup,
   with a strong prompt to write it down physically. This is the
   recovery of last resort when social contacts are unavailable.
3. **Hardware token and cloud backup as optional upgrades.** Power
   users who want belt-and-suspenders can add these.

The recovery setup should happen during the first session, not as a
dismissible prompt. The protocol cannot enforce this, but the SDK
should surface it prominently and the reference apps should require
completing at least one recovery method before allowing space creation.

---

## 4. Cross-Space Identity

Per-space isolation means credentials do not transfer. A user with
months of reputation in Space A is a stranger in Space B. Cross-space
identity is the mechanism for selectively bridging this gap without
breaking unlinkability.

### BBS+ selective disclosure

[BBS+ signatures](https://identity.foundation/bbs-signature/draft-irtf-cfrg-bbs-signatures.html)
allow a credential issuer to sign a set of attributes, and the
credential holder to later prove possession of the signature while
revealing only a chosen subset of attributes. The verifier learns
nothing about the hidden attributes.

**Application to VOS:**

A space can issue BBS+ credentials to its members attesting to their
properties: membership duration, reputation score, roles held, actions
completed. The user holds these credentials locally.

When joining a new space, the user presents a ZK proof derived from
one or more BBS+ credentials:

- "I hold a valid credential from *some* space where my reputation
  exceeds 50." (The proof does not reveal which space.)
- "I have been a member of at least one space for more than 90 days."
- "I hold a moderator-role credential from some space."

The new space verifies the proof and admits the user. No link is
created to the issuing space.

### Credential accumulation

Users collect attestations from multiple spaces over time. These can
be combined into aggregate proofs:

- "I hold valid credentials from at least 3 different spaces, each
  with reputation above 30."
- "My total accumulated reputation across all my spaces exceeds 200."

Aggregate proofs use techniques from the anonymous credentials
literature: proving properties over committed values without revealing
the values. The zk-promises framework's private state objects (which
already support ZK proofs over hidden numeric state) can be extended
to support cross-space aggregation by introducing a "meta-object" that
commits to the user's credential set.

### The unlinkability challenge

Selective disclosure has a subtle fingerprinting risk. Consider the
proof: "I have reputation above 50 in at least 3 spaces." If only one
user in the network meets this criterion, the proof itself identifies
them — even though it reveals no specific space or identity.

More generally, any sufficiently specific predicate becomes a
quasi-identifier. The rarer the proven property, the smaller the
anonymity set.

**Mitigations:**

- **Coarse predicates.** Prove "reputation above 10" rather than
  "reputation equals 73." Prove "member of at least 1 space" rather
  than "member of exactly 4 spaces." Bucket thresholds reduce
  distinguishability.
- **Minimum anonymity set checks.** Before generating a proof, the
  user's client estimates the anonymity set size for the predicate
  being proven. If the set is too small (below a configurable
  threshold, e.g. 20 users), the client warns the user or refuses to
  generate the proof.
- **Proof expiration.** Cross-space proofs carry a short validity
  window (e.g. 24 hours). The user generates fresh proofs
  periodically. A proof presented today cannot be correlated with a
  proof presented last week, because the re-randomization ensures they
  are unlinkable.
- **Decoy credentials.** The protocol could issue dummy credentials to
  pad the anonymity set, but this adds complexity and must be done
  carefully to avoid introducing other attacks.

### Sybil resistance across spaces

If one person can create many independent identities (each with its
own root secret), they can accumulate credentials fraudulently: create
10 identities, build reputation in 10 different spaces, and present
an aggregate proof claiming broad trust.

This is the fundamental Sybil problem, and there is no purely
cryptographic solution without some form of identity binding.

**Approaches within VOS's design:**

- **Proof of personhood.** Require a proof-of-personhood credential
  (e.g. from a ceremony like Worldcoin's Orb or Idena's FLIP test)
  as a prerequisite for cross-space credential proofs. The
  proof-of-personhood check ensures one credential set per person
  without revealing which person. This is effective but introduces a
  dependency on an external identity oracle.

- **Stake-based identity.** Require a user to lock a stake (tokens,
  bond) when generating cross-space credentials. The stake is
  slashable if Sybil behavior is detected. Detection is hard in the
  anonymous setting, but some heuristics apply: if the same
  proof-of-personhood credential is used to back two different
  cross-space proofs within the same space, that is a detectable
  double-spend (using nullifiers, as in zk-promises).

- **Social vouching.** Cross-space credential proofs require
  co-signatures from existing members of the target space. A user
  joining Space B must be vouched for by an existing member of Space
  B who has seen the cross-space proof. This does not prevent Sybils
  but raises the cost — the attacker must socially integrate into
  each space, not just create throwaway identities.

- **Rate limiting credential issuance.** Spaces issue BBS+
  credentials at a limited rate (e.g. one reputation attestation per
  month of active participation). An attacker running 10 Sybil
  identities must invest 10 months of genuine participation across
  them, making the attack expensive rather than impossible.

No single approach eliminates the Sybil problem. The recommendation
is to layer these mechanisms: rate-limited credential issuance as the
baseline, social vouching for high-trust spaces, and optional
proof-of-personhood for spaces that require stronger guarantees.

---

## 5. Identity Lifecycle

An identity in VOS is not a static key — it is a living entity that
evolves as devices are added, lost, and replaced. Understanding the
full lifecycle is essential for building correct recovery and migration
flows.

### Creation

```
Install app
  → generate root_secret
  → compute device_credential = Commit(root_secret)
  → initialize local encrypted store
  → set up device sync space (single-member space)
  → prompt recovery setup (social recovery, mnemonic, or both)
```

At this point the user exists but has joined no spaces. The device
sync space is the user's first and most private space — it will
never have external members.

### Active use

```
Create or join spaces
  → derive space_secret[space_id] for each space
  → join MLS group (one leaf per device per space)
  → add credential_commitment to space membership tree
  → begin sync, collaboration, reputation accumulation
```

Each space is independent. The user's activity in one space is
invisible to other spaces.

### Device addition

```
New device scans QR / enters pairing code
  → receives root_secret (Option A) or generates own root + cross-cert (Option C)
  → joins device sync space
  → syncs list of joined spaces from device sync space
  → for each space:
      → derive space_secret[space_id]
      → existing device issues MLS Add for new device's leaf
      → new device receives MLS Welcome, obtains current epoch keys
      → new device begins sync (fetches current DAG state)
```

The new device catches up to current state but cannot decrypt
pre-join history (MLS forward secrecy). This is acceptable — the
current CRDT state reflects the result of all past operations.

### Device loss

```
Device is lost / stolen / destroyed
  → remaining devices detect absence (no sync heartbeat in device sync space)
  → for each space the lost device was a member of:
      → an active device issues MLS Remove for the lost device's leaf
      → MLS epoch advances, keys rotate
      → the lost device can no longer decrypt new content (post-compromise security)
  → the lost device's share of any threshold secrets is marked stale
  → if the lost device held the only copy of root_secret:
      → trigger recovery (Section 3)
```

**Timing matters.** The sooner the lost device's MLS leaves are
removed, the shorter the window during which a thief with the device
could read new messages. Remaining devices should issue Remove
proposals as soon as loss is detected. In the worst case (single
device, total loss), recovery must happen before the user can rejoin
any space.

### Recovery

```
New device installed
  → recover root_secret via social recovery / mnemonic / hardware token / cloud backup
  → regenerate device_credential
  → rejoin device sync space (if another device exists, it issues MLS Add;
    if no other device exists, the user re-initializes the device sync space
    from backup state)
  → for each previously joined space:
      → derive space_secret[space_id]
      → an existing member (or the user's other device) issues MLS Add
      → the space's membership tree is updated with the new device's commitment
      → old membership commitment (from the lost device) is revoked
```

If all devices were lost and recovery is from a mnemonic or social
shares, the user has no device sync space to bootstrap from. They must
re-derive space secrets from the root secret and re-announce
themselves to each space. This requires remembering (or having stored
externally) which spaces they belonged to. The recovery setup flow
should include backing up the space list alongside the root secret.

### Credential migration

When a device is replaced (loss + recovery, or voluntary upgrade):

- The old device's per-space credentials (MLS leaves, membership tree
  commitments) are revoked.
- The new device's credentials are added.
- ZK-promises state (reputation, rate limits) is bound to the root
  secret, not the device. Since the recovered device has the same root
  secret, the user's zk-object state is preserved — they do not lose
  reputation. However, they must prove continuity: "my new credential
  commitment is derived from the same root secret as my old one"
  without revealing the root secret. This is a ZK proof of credential
  equivalence, provable because both commitments derive from the same
  secret via a known derivation path.

If the root secret itself changes (e.g., the user rotates it after a
suspected compromise), reputation migration requires the old root
secret to sign a transfer statement to the new one. If the old secret
is fully compromised (attacker has it), the user must accept that the
attacker could also claim the reputation. In this case, the safer
option is to start fresh — accept the reputation loss to avoid the
attacker impersonating the user's historical identity.

---

## Open Questions

Several aspects of identity management remain unresolved and require
further research or implementation experience:

- **Device sync space bootstrapping.** If all devices are lost, how
  does the recovered device discover and rejoin the device sync space?
  The space identifier could be derived deterministically from the
  root secret, but the space's MLS state is lost. The device may need
  to re-initialize the space entirely.

- **Concurrent device operations.** If two devices simultaneously
  issue MLS proposals in the same space (e.g., both try to add a
  third device), the MLS protocol requires ordering. Since VOS
  uses CRDTs for the delivery service, the ordering semantics of
  concurrent MLS Commits need careful handling.

- **Anonymity set size estimation.** For cross-space credential
  proofs, how does the client estimate the anonymity set? It would
  need statistics about the credential distribution across the
  network, which itself is private information. Heuristic estimates
  (based on space sizes and typical reputation distributions) may be
  the only viable approach.

- **Recovery contact rotation.** If a recovery contact leaves the
  user's social circle or loses their device, the user should update
  their recovery shares. This requires re-splitting and
  re-distributing, which is straightforward but must be surfaced in
  the UX.

- **Post-quantum migration.** The current design relies on elliptic
  curve commitments and pairings (for BBS+). A post-quantum migration
  path (lattice-based commitments, hash-based signatures for
  cross-certification) should be designed before the cryptographic
  primitives are locked in.
