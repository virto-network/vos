# Authorization Layer: Anonymous Credentials

The authorization layer sits between the application and the sync
layer. Before an operation enters the Merkle-CRDT DAG, it must pass
through an authorization gate: the user proves they are allowed to
act. In non-anonymous spaces, this is trivial (MLS membership is
sufficient). In anonymous spaces, authorization is a zero-knowledge
proof — the user proves membership, reputation, rate-limit compliance,
and ban status without revealing their identity.

This chapter covers the full authorization model: zk-promises for
anonymous moderation, session tokens for amortizing proof cost,
anonymous membership proofs, and moderator roles.

---

## The Authorization Gate

Every operation in a VOS space passes through an authorization
check before it is accepted by peers:

```
Application produces CRDT operation
  → Authorization gate: "Is this operation allowed?"
  → If yes: operation enters MerkleCrdt::apply() → DAG node → encrypt → sync
  → If no: operation is rejected locally (never enters the DAG)
```

In a **non-anonymous space**, authorization checks are straightforward:

- The operation is signed with the member's MLS identity key.
- Peers verify the signature against the MLS ratchet tree.
- If the signature is valid, the member is authorized.
- Moderation is explicit: an admin removes a member from the MLS
  group, revoking their keys.

In an **anonymous space**, authorization is a ZK proof:

- The operation carries a zero-knowledge proof of authorization.
- Peers verify the proof. If valid, the operation is accepted.
- No peer learns which member authored the operation.
- Moderation operates through the zk-promises framework: reputation,
  rate limits, and bans are enforced cryptographically, not
  administratively.

The authorization gate is the same interface in both modes. The
difference is what constitutes "proof of authorization" — a
signature or a ZK proof. This lets spaces switch between modes (or
use a hybrid) without changing the sync, encryption, or storage
layers.

---

## zk-promises Deep Dive

> Based on: *"zk-promises: Making Zero-Knowledge Objects Accept the
> Real World"*
> ([ePrint 2024/1260](https://eprint.iacr.org/2024/1260))

zk-promises provides **anonymous actions with accountable
consequences**. A user acts anonymously while provably maintaining
private state (reputation, rate limits, ban status). Moderators can
penalize actions without learning who performed them.

### zk-objects

Each member of an anonymous space holds a **zk-object** — a private
state vector containing:

| Field | Type | Purpose |
|---|---|---|
| `reputation` | integer | Accumulated trust score |
| `rate_counter` | integer | Tokens consumed in current window |
| `rate_window` | timestamp | Start of current rate-limit window |
| `ban_flag` | boolean | Whether the member is banned |
| `nonce` | integer | Monotonically increasing, prevents replay |

The zk-object lives only on the member's device. It is never
transmitted. Instead, the member proves properties about it using
zero-knowledge proofs:

- "My reputation is above the space's threshold"
- "My rate counter is below the space's limit"
- "My ban flag is false"
- "My nonce is greater than the last nonce I used"

These proofs are generated using a SNARK (currently Groth16 via
Arkworks; replaceable with PLONK or a newer system). The proof
reveals nothing about the actual values — only that the stated
predicates hold.

### ShowAuthorized Proof Flow

The core protocol operation is `ShowAuthorized`: the member proves
they are authorized to act.

```
1. Member holds zk-object with current state:
   { reputation: 85, rate_counter: 3, ban_flag: false, nonce: 42 }

2. Member constructs a ZK proof π:
   - "I know a secret s such that Com(s) is a leaf in the membership tree"
     (proves membership without revealing which leaf)
   - "My reputation ≥ space.min_reputation"
   - "My rate_counter < space.rate_limit"
   - "My ban_flag == false"
   - "My nonce > last_nonce" (prevents reuse of old proofs)

3. Member updates zk-object:
   - rate_counter += 1 (or += batch_size)
   - nonce += 1
   - Computes new commitment: Com'(new_state)

4. Member produces a ticket tik = PRF(s, nonce)
   - tik is unlinkable to the member's identity
   - tik is deterministic: if the member tries to reuse a nonce,
     the same tik is produced (enabling double-action detection)

5. Output: (π, Com', tik)
   - π is verified by peers (valid proof → operation accepted)
   - Com' is posted to the bulletin board (updated state commitment)
   - tik is attached to the operation (moderators can issue callbacks
     against it later)
```

Proof generation takes approximately 300-700ms on a modern device
(Groth16 over BN254). This is too slow for every keystroke but
acceptable for session-start or per-batch authorization.

### Callbacks

A callback is a moderator's response to an action. It modifies the
actor's zk-object without revealing who the actor is.

```
1. Moderator observes a problematic post (DAG node with ticket tik_x)

2. Moderator issues a callback:
   Callback = (tik_x, action)
   where action ∈ { reduce_rep(amount), ban, warn, ... }

3. Callback is posted to the bulletin board (moderation log document)

4. The bulletin board syncs to all members via Merkle-CRDT

5. The original poster (and only they) recognizes tik_x as their
   ticket. They process the callback:
   - If action = reduce_rep(10): reputation -= 10
   - If action = ban: ban_flag = true
   - Update zk-object, compute new commitment

6. On the poster's next ShowAuthorized, the proof must reflect the
   updated state. If they skip processing the callback, their proof
   will fail verification (the commitment chain will be inconsistent).
```

The moderator never learns which member owns `tik_x`. The member
cannot ignore the callback — the protocol enforces processing before
the next action.

### Bulletin Board

The bulletin board is an append-only log that serves as the shared
state for the zk-promises protocol. In VOS, it is implemented as
a **moderation log document** — a CRDT within the space, synced via
Merkle-CRDT like any other document.

The bulletin board contains:

- **Commitment updates:** Each member's latest state commitment
  (Com'). These are anonymized — peers cannot link commitments to
  members.
- **Callbacks:** Moderator-issued penalties, each targeting a ticket.
- **Epoch markers:** Periodic checkpoints for garbage collection.

Alternative implementations:

- **Blockchain DA layer.** Provides stronger availability and ordering
  guarantees. Useful for high-stakes spaces (governance, financial).
- **Dedicated relay.** Trusted for integrity (append-only, ordered)
  but not for confidentiality. Simpler than a blockchain anchor.

The CRDT-based bulletin board is the default. It works in fully P2P
settings with no external dependencies. The tradeoff is weaker
availability guarantees: if no peer holding the bulletin board is
online, new sessions cannot start (because the member cannot verify
that no callbacks are pending).

### ScanOne Operation

Before producing a new `ShowAuthorized` proof, a member must scan the
bulletin board for callbacks targeting their tickets. The scan
operation is called `ScanOne`:

```
1. Member retrieves all new entries from the bulletin board since
   their last scan.

2. For each callback entry (tik, action):
   - Compute: does tik match any ticket I have issued?
   - Match check: tik_mine = PRF(s, nonce_i) for each nonce_i
     in [last_scanned_nonce .. current_nonce]
   - If match: process the callback (update zk-object)

3. Produce proof that all matching callbacks have been processed:
   - "My current state commitment is the result of correctly
     applying all callbacks targeting my tickets"

4. Update last_scanned_nonce.
```

The scan is a local operation. The member downloads the bulletin board
entries (they are part of a synced CRDT document — the member already
has them if they are syncing the space) and checks each callback
against their own secret. No one else can determine which callbacks
the member found.

**Performance note:** Scanning is linear in the number of new bulletin
board entries since the last scan. For an active space with many
callbacks, this could become slow. Mitigation: epoch-based
partitioning of the bulletin board, where members only need to scan
entries from their most recent epoch.

---

## Session Tokens

Generating a ZK proof for every batch of operations is expensive.
Session tokens amortize this cost: prove once, use for a session.

### Construction

A session token is a **blinded credential** derived from the
`ShowAuthorized` proof:

```
1. Member generates ShowAuthorized proof π at session start
   (~300-700ms, one-time cost)

2. From π, derive a session token:
   token = BlindSign(session_key, π, validity_period)
   - session_key is an ephemeral key generated for this session
   - validity_period defines how long the token is usable

3. For each subsequent operation within the session:
   - Attach token instead of a full ZK proof
   - Peers verify the token (signature check, ~1ms)
   - If valid and not expired, the operation is accepted
```

The blinding ensures that the session token cannot be linked back to
the `ShowAuthorized` proof or the membership proof. Peers can verify
the token is valid (issued by a legitimate `ShowAuthorized` flow)
without learning which member issued it.

### Validity Period

Session tokens have a configurable validity period:

- **Short sessions (minutes).** Higher privacy: shorter linkability
  window. Higher cost: more frequent proof generation. Suitable for
  sensitive operations (governance, financial).
- **Long sessions (hours).** Lower privacy: longer linkability window.
  Lower cost: proof generated once per work session. Suitable for
  collaborative editing where real-time performance matters.

The space's moderation configuration specifies the maximum allowed
session duration. Members can choose shorter sessions for stronger
privacy.

### Linkability Tradeoff

Operations within a single session are **linkable to each other**.
An observer can determine that the same session token produced
operations A, B, and C. They cannot determine which member holds that
token, but they can build a behavioral profile for the session: typing
speed, editing patterns, active hours.

This is a deliberate tradeoff. Per-operation proofs (no session token)
provide full unlinkability but at 300-700ms per batch, real-time
collaboration is impractical. Session tokens make anonymous real-time
editing viable at the cost of intra-session linkability.

For maximum privacy, a member can:
- Use short sessions (rotate tokens frequently)
- Pad operations with dummy edits to obscure patterns
- Vary their session duration randomly

---

## Rate Limiting

Rate limiting prevents abuse (spam, flooding) without revealing
identity. It is enforced via the zk-object's `rate_counter` field.

### Leaky Bucket Model

The rate limit uses a leaky bucket model proven in ZK:

```
Rate limit parameters (set in space moderation config):
  - capacity: maximum tokens in the bucket (e.g. 100)
  - refill_rate: tokens added per time unit (e.g. 10 per minute)

On ShowAuthorized:
  1. Compute elapsed time since last action
  2. Refill bucket: tokens = min(capacity, tokens + elapsed * refill_rate)
  3. Consume tokens: tokens -= cost_of_operation
  4. Prove in ZK: tokens ≥ 0 (bucket is not empty)
```

The proof reveals only that the bucket is non-negative. It does not
reveal the actual token count, the elapsed time, or the refill
computation. This prevents timing analysis from learning how active
the member has been.

### Per-Session vs. Per-Batch

Rate limiting is checked at session boundaries or at batch boundaries,
not per individual CRDT operation:

- **Per-session:** The `ShowAuthorized` proof at session start consumes
  tokens for the entire session. The member declares "I intend to
  perform up to N operations" and proves their bucket can sustain it.
  Simpler but less granular.
- **Per-batch:** Each batch of operations (e.g., every 5 seconds of
  editing) consumes tokens. More granular control at the cost of more
  frequent proof generation. In practice, batches use session tokens,
  so the per-batch token consumption is recorded locally and proven
  at the next session renewal.

---

## Anonymous Membership Proofs

The foundation of all anonymous authorization is the membership proof:
"I am a member of this space" without revealing which member.

### Membership Merkle Tree

The space maintains a Merkle tree whose leaves are commitments to
members' space-scoped secrets:

```
Membership tree:
         root
        /    \
      h01    h23
      / \    / \
    L0  L1  L2  L3

Each leaf Li = Com(si) = g^si * h^ri
  where si is member i's space-scoped secret
  and ri is a random blinding factor
```

The tree is stored as a CRDT in the space's root document. All members
have the current tree. The root hash is a compact summary of the
entire membership.

### ZK Membership Proof

To prove membership, a member constructs a ZK proof:

```
Public inputs: membership_tree_root
Private inputs: secret s, blinding r, Merkle path from Com(s) to root

Proof statement:
  1. Com(s) = g^s * h^r                    (I know the opening of a commitment)
  2. MerklePath(Com(s), root) is valid      (that commitment is a leaf in the tree)
  3. Com(s) is not tombstoned               (the leaf has not been removed)
```

This proof is approximately 128 bytes (Groth16) and verifies in ~3ms.
It is included as part of the `ShowAuthorized` proof — membership is
a prerequisite for any anonymous action.

### Nullifiers

For operations where double-action must be prevented (e.g., voting),
the proof includes a **nullifier**:

```
nullifier = PRF(s, action_context)
  where action_context = hash(proposal_id || "vote")
```

The nullifier is deterministic: the same member voting on the same
proposal always produces the same nullifier. If two operations carry
the same nullifier, one is a double-action and is rejected. The
nullifier reveals nothing about the member's identity — it is derived
from the secret `s` which is never disclosed.

For operations where double-action is fine (e.g., posting messages),
no nullifier is needed. The ticket from zk-promises serves a different
purpose: it enables targeted callbacks, not double-action prevention.

---

## Moderator Roles

Anonymous moderation requires moderators who can issue callbacks but
cannot identify the users they are penalizing.

### Appointment

Moderators are appointed through one of several mechanisms, configured
per space:

- **Creator-designated.** The space creator appoints initial
  moderators. Simple, suitable for small spaces. The creator knows
  the moderators' identities (they were appointed by name or invite).
- **Governance vote.** Members vote to elect moderators. The vote
  uses the anonymous voting CRDT (see
  [Private Economy](./private-economy.md)). Moderators are known by
  their role credential, not their identity — an elected moderator
  holds a ZK proof "I won the moderator election" without revealing
  who they are.
- **Rotating.** Moderator duty rotates among members. Each epoch, a
  deterministic selection (based on the epoch number and the
  membership tree) assigns moderator privileges to a subset of
  members. The selection is verifiable by all members but the
  selected members prove their role in ZK.
- **Reputation-based.** Members above a reputation threshold
  automatically gain moderator privileges. Proven in ZK: "my
  reputation > moderator_threshold." No appointment needed.

### Moderator Capabilities

A moderator can:
- Issue callbacks against tickets (reduce reputation, warn, ban)
- Propose content removal (the content remains in the DAG but is
  flagged in the moderation log — peers can choose to hide it)
- Adjust rate limit parameters via governance proposals

A moderator cannot:
- Identify who posted what
- Decrypt content that other members posted (they see the same
  encrypted content as everyone else)
- Unilaterally change space settings (settings changes go through
  the root document's CRDT, subject to governance rules)

### Moderator Abuse Prevention

The moderation system includes safeguards against moderator abuse:

**Rate-limited callbacks.** Moderators can issue at most N callbacks
per epoch. This is enforced by the moderator's own zk-object: issuing
a callback consumes moderator rate-limit tokens, proven in ZK.

**Callback justification.** Each callback references the target post's
CID. Other members can inspect the post and the callback to judge
whether the penalty was warranted. While the moderator's identity
may be hidden, the moderation action is publicly auditable.

**Appeals.** A penalized member can contest a callback by posting an
appeal to the moderation log. The appeal is itself an anonymous
action. If the space uses governance voting, appeals can be resolved
by community vote.

**Super-moderator oversight.** For spaces that need it, a
super-moderator role (appointed by governance vote, held by multiple
members via threshold) can reverse callbacks. This is a governance
mechanism, not a cryptographic one — the reversal is a new callback
that restores the penalized member's reputation.

**Transparency log.** All moderation actions are recorded in the
moderation log (the bulletin board). Any member can audit the history
of callbacks and verify that moderators are acting within their
rate limits.

---

## Integration with MLS

Anonymous credentials and MLS group membership serve complementary
purposes. MLS provides encryption keys; anonymous credentials provide
authorization proofs. They must work together:

### Dual membership structures

Each space maintains two parallel membership structures:

1. **MLS ratchet tree.** Determines who has the decryption keys. Each
   member has a known leaf (identified by their MLS identity key).
   This structure is inherently non-anonymous — MLS needs to know
   which keys belong to which leaves for key agreement to work.

2. **Membership Merkle tree.** Determines who can prove membership
   anonymously. Each member has a committed leaf (identified by a
   commitment to their space secret). This structure is designed for
   ZK proofs.

Both structures must stay in sync: adding a member means adding both
an MLS leaf and a Merkle tree leaf. Removing a member means removing
both.

### The anonymity gap

MLS is not anonymous. When a member encrypts a message, the MLS
protocol identifies the sender (for key derivation and forward secrecy
purposes). This creates a tension with anonymous posting.

The resolution: **decouple encryption from authorship**.

- The MLS group key encrypts the DAG node payload. Any member can
  encrypt using the shared group key — this does not identify the
  sender.
- The operation's authorship is proven via the ZK proof (attached to
  the DAG node). The proof says "a valid member authored this" without
  saying which one.
- For MLS to function, the DAG node must be encrypted by *some*
  member's sender key. In anonymous mode, a privacy-preserving scheme
  is used: the member derives a sender key from the shared group
  secret + a random nonce, rather than from their personal MLS leaf
  key. All members can decrypt (they know the group secret) but
  cannot attribute the message to a specific leaf.

This is a meaningful departure from standard MLS usage and requires
careful security analysis. The key question is whether it weakens
MLS's post-compromise security guarantees. The current assessment is
that it does not, because the group secret is rotated on every
membership change regardless of which leaf was the sender. See
[Encryption](./encryption.md) for the full MLS integration.

### Joining anonymously

When a new member joins a space:

1. They submit an MLS KeyPackage (this is not anonymous — the MLS
   protocol sees the new leaf).
2. An existing member issues an MLS Welcome.
3. The new member's credential commitment is added to the membership
   Merkle tree.

Steps 1 and 2 are inherently non-anonymous within the MLS protocol.
However, they are anonymous to the outside world: the KeyPackage is
submitted through the anonymity network (Tor/Nym), and the Welcome
is delivered through encrypted channels. The relay and network
observers do not learn who joined. Within the space, members see a
new MLS leaf but — if the joiner used a fresh, unlinkable KeyPackage
— they cannot link it to any identity outside the space.

The membership Merkle tree leaf (step 3) is fully anonymous: it is a
commitment that reveals nothing about the member.
