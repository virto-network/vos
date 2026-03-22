# Private Economy: Payments, Voting, Governance

Kunekt spaces are not limited to documents and chat. The same
infrastructure — encrypted CRDTs, anonymous credentials, ZK proofs —
extends to economic activity: payments, voting, governance, and
marketplace interactions. This chapter covers how these systems work,
what cryptographic primitives they use, and what remains open.

These capabilities correspond to Phases 5-6 of the
[Development Roadmap](./roadmap.md) and Phases 8-9 of the
[User Journey](./user-journey.md).

---

## Private Payment Channels

A private payment channel is a bilateral (or multilateral) ledger
maintained as a CRDT within a Kunekt space. Transfers are CRDT
operations encrypted under MLS. Balances are hidden behind
cryptographic commitments. Settlement happens on-chain via ZK proofs.

### State Channels Backed by CRDTs

A payment channel between two members is a document in the space.
Its CRDT is a PN-Counter extended with ZK balance proofs (see
[Document Layer](./documents.md)). The channel state tracks:

- **Balances:** Each party's current balance, represented as a
  Pedersen commitment `C = g^v * h^r` where `v` is the balance and
  `r` is a random blinding factor.
- **Transaction log:** An append-only sequence of transfers, each
  a DAG node in the channel's Merkle-DAG.
- **Nonce:** Monotonically increasing, prevents replay of old states.

The channel is opened by an on-chain funding transaction that locks
collateral. Once funded, all transfers happen off-chain as CRDT
operations — fast, private, and free of transaction fees.

### Transfer Operations as CRDT Ops

A transfer is a CRDT operation recorded as a DAG node:

```
Transfer {
    from_delta: PedersenCommitment,   // commitment to -amount
    to_delta: PedersenCommitment,     // commitment to +amount
    proof: ZKProof,                   // see below
    nonce: u64,
}
```

The operation is encrypted with the MLS epoch key before entering
the DAG. Only channel participants (and other space members, if the
channel is a shared document) can decrypt it.

### ZK Balance Proofs

Each transfer carries a ZK proof demonstrating:

1. **Conservation:** The sum of deltas is zero. The transferred
   amount leaving one balance equals the amount entering the other.
   Proven via the homomorphic property of Pedersen commitments:
   `from_delta + to_delta = Com(0)`.

2. **Non-negativity:** The sender's resulting balance is non-negative.
   This is a range proof: `v_sender - amount ≥ 0`. Implemented via
   Bulletproofs or a SNARK range circuit.

3. **Authorization:** The sender is authorized to operate the channel
   (membership proof + session token or ShowAuthorized proof).

The proof reveals nothing about the actual balances or transfer
amounts. An observer (even another space member with decryption access)
sees only commitments and a valid proof.

**Pedersen commitments** are the foundation:

```
Balance commitment: C = g^v * h^r
  - v: balance value (hidden)
  - r: random blinding factor (hidden)
  - g, h: public generators (nothing-up-my-sleeve points)

Homomorphic property: C1 + C2 = g^(v1+v2) * h^(r1+r2)
  → can verify sum relationships without opening commitments
```

### On-Chain Settlement

When the channel is closed (or periodically for checkpointing), the
final state is settled on-chain:

```
1. Both parties sign the final state (latest nonce + balance
   commitments).

2. A ZK proof is generated:
   "Starting from the on-chain funding amounts, applying the
    sequence of transfers recorded in the Merkle-DAG produces
    the claimed final balance commitments."

3. The proof + final commitments are submitted on-chain.

4. The chain verifies the proof (~3ms for Groth16) and releases
   funds according to the final balances.
```

The chain sees only the initial funding, the final balances (as
commitments), and a proof of correct execution. It learns nothing
about the number of transfers, their amounts, or their timing.

### Dispute Resolution

If one party disappears or submits a stale state:

- Either party can submit a state with a higher nonce to the chain.
- The chain accepts the state with the highest nonce that has a valid
  ZK proof.
- A challenge period allows the counterparty to submit a later state.
- After the challenge period, funds are released.

This follows the standard state channel dispute pattern, adapted to
use ZK proofs instead of plaintext state.

---

## Anonymous Voting

Voting enables space members to make collective decisions without
revealing individual votes. The vote uses the same ZK and CRDT
infrastructure as the rest of the protocol.

### Proposal as CRDT Document

A proposal is a new document in the space. Its CRDT contains:

| Field | Type | Content |
|---|---|---|
| `text` | LWW-Register | Proposal description |
| `options` | LWW-Register | Valid vote choices (e.g., yes/no/abstain) |
| `quorum` | LWW-Register | Minimum participation required |
| `deadline` | LWW-Register | Voting end time (or end epoch) |
| `votes` | GSet | Set of encrypted vote DAG nodes |
| `tally` | LWW-Register | Computed result (set after deadline) |

The proposal is created by a member (or by governance automation)
as a CRDT operation on the space's root document (adding the proposal
document to the document registry), then populated with the proposal
content.

### Vote = DAG Node with ZK Proof

Each vote is a DAG node in the proposal document. It contains:

```
Vote {
    encrypted_choice: ElGamalCiphertext,  // encrypted vote value
    membership_proof: ZKProof,            // "I am a member"
    nullifier: Bytes,                     // prevents double-voting
    well_formedness_proof: ZKProof,       // "my vote is a valid option"
}
```

The ZK proofs establish:

1. **Membership:** "I know a secret `s` such that `Com(s)` is a leaf
   in the membership Merkle tree." Same proof used for all anonymous
   actions.

2. **Nullifier:** `nullifier = PRF(s, proposal_id)`. Deterministic
   per member per proposal. If two votes carry the same nullifier,
   one is a double-vote and is rejected. The nullifier reveals nothing
   about which member cast it.

3. **Well-formedness:** "My encrypted vote encodes one of the valid
   options." This prevents a voter from submitting a garbage value
   that would corrupt the tally. Proven via a disjunctive ZK proof:
   "my plaintext is 0 OR my plaintext is 1" (for a yes/no vote).

### Homomorphic Tally

Votes are encrypted using a homomorphic encryption scheme (ElGamal
or Pedersen):

```
ElGamal encryption of vote v ∈ {0, 1}:
  ciphertext = (g^r, pk^r * g^v)
  where pk is the tally public key, r is random

Homomorphic property:
  Sum of ciphertexts = encryption of sum of votes
  Σ ciphertext_i = (g^(Σr_i), pk^(Σr_i) * g^(Σv_i))
```

After the voting deadline, the tally is computed by multiplying all
ciphertexts together. The result is an encryption of the sum of all
votes. To decrypt the sum, a designated tally authority (or a
threshold group of members) uses the tally secret key.

**Threshold decryption** distributes trust: the tally secret key is
split among `k` of `n` tally authorities. No single authority can
decrypt the tally alone, and no authority learns individual votes.
The threshold decryption produces a ZK proof that the decrypted tally
is correct relative to the encrypted votes.

### Verifiable Results

The final tally is accompanied by a ZK proof:

- "The tally value `T` is the correct decryption of the product of
  all vote ciphertexts in the proposal's vote set."
- Any member can verify this proof against the public vote set
  (the ciphertexts are in the DAG) and the tally public key.
- If the proof verifies, the result is trustworthy even if the tally
  authorities are not.

The tally and proof are recorded as a DAG node in the proposal
document. The result is part of the space's permanent, verifiable
history.

---

## Governance Framework

Governance is the mechanism by which space members collectively modify
the space's configuration and policies. It builds on anonymous voting
and operates through the root document's CRDT.

### Configurable Policies

Each space defines its governance parameters in the root document's
settings:

| Policy | Description | Example values |
|---|---|---|
| `quorum` | Minimum voter participation | 50% of members, 10 members |
| `threshold` | Votes needed to pass | Simple majority, 2/3 supermajority |
| `delegation` | Whether vote delegation is allowed | Enabled/disabled |
| `proposal_bond` | Stake required to create a proposal | 0 (free), 10 tokens |
| `voting_period` | Duration of voting window | 48 hours, 1 week |
| `execution_delay` | Time between passing and execution | 24 hours |

These parameters are themselves subject to governance: changing them
requires a proposal that passes under the current rules.

### Proposals That Modify Space Settings

A governance proposal specifies a set of CRDT operations to be applied
to the root document if the proposal passes:

```
Proposal {
    description: "Increase rate limit from 100 to 200 ops/minute",
    operations: vec![
        RootDocOp::SetSetting("rate_limit.capacity", 200),
    ],
    voting_params: VotingParams {
        quorum: Quorum::Percentage(50),
        threshold: Threshold::SuperMajority,
        deadline: Epoch::current() + Duration::days(3),
    },
}
```

The proposal document is created. Members vote. After the deadline:

1. If quorum is met and the threshold is reached, the proposal passes.
2. The execution delay begins (a timelock allowing members to review
   and potentially veto).
3. After the delay, the specified CRDT operations are applied to the
   root document.
4. The root document's new state syncs to all members.

### Timelock and Execution

The execution delay serves two purposes:

- **Veto window.** If members realize a proposal is harmful after it
  passes (e.g., due to low participation), they can raise a counter-
  proposal or emergency veto during the delay.
- **Preparation.** Members (and their clients) have time to prepare
  for the change. For example, if the rate limit is changing, clients
  can adjust their batching behavior before the new limit takes
  effect.

Emergency proposals (e.g., banning a severe abuser) can be configured
with a shorter or zero delay, but this requires a higher threshold
(e.g., unanimous among moderators).

### Delegation

Vote delegation allows a member to delegate their vote to another
member. The delegatee votes on the delegator's behalf. Delegation is:

- **Anonymous.** The delegation is recorded as a ZK proof: "I am
  delegating my vote to the member with commitment `C_delegatee`."
  Neither the delegator's nor the delegatee's identity is revealed.
- **Revocable.** The delegator can revoke at any time by casting
  their own vote (which supersedes the delegation for that proposal).
- **Transitive or non-transitive.** Configurable per space. Transitive
  delegation (liquid democracy) allows chains of delegation but
  requires cycle detection.

---

## Marketplace Primitives

Kunekt spaces can function as anonymous marketplaces. The building
blocks — anonymous credentials, private payments, and governance —
combine to support buying, selling, and dispute resolution.

### Anonymous Listings

A seller lists an item by creating a CRDT operation in the marketplace
document:

```
Listing {
    id: random_id,
    title: "Vintage keyboard",
    description: "...",
    price: Amount::new(50, Currency::DOT),
    seller_credential: AnonCredentialProof,
}
```

The `seller_credential` is a ZK proof demonstrating:
- The seller is a member of the space.
- The seller has sufficient reputation (above the marketplace's
  minimum seller threshold).
- The seller has not been banned.

The listing does not reveal which member is the seller. The buyer
communicates with the seller through the space's anonymous channels.

### Escrow via Shared Payment Channels

A purchase uses a shared payment channel as escrow:

```
1. Buyer opens a payment channel with the escrow document,
   funding it with the purchase price.

2. Seller ships the item (or delivers the digital good).

3. Buyer confirms receipt → escrow releases funds to seller.

4. If dispute: funds are held until governance vote resolves it.
```

The escrow is a CRDT document: a three-party payment channel between
buyer, seller, and an escrow authority (which can be a governance-
elected role or a threshold group). All operations are encrypted and
anonymous.

### Reputation Portability

A seller's reputation in one marketplace can be proven in another:

- The seller holds BBS+ credentials attesting to their transaction
  history (number of successful sales, dispute rate, average rating).
- When listing in a new marketplace, they present a ZK proof:
  "I have completed at least 20 successful sales across one or more
  marketplaces with a dispute rate below 5%."
- The proof reveals nothing about which marketplaces, which
  transactions, or which identity.

See [Identity: Cross-Space](./identity.md) for the full credential
portability mechanism.

### Dispute Resolution

Disputes are resolved by governance vote:

1. Either party opens a dispute by creating a proposal document in
   the space.
2. The dispute document contains the relevant transaction evidence
   (encrypted, visible only to space members).
3. Members vote on the resolution (release funds to buyer, release to
   seller, split).
4. The vote result triggers the escrow settlement.

Dispute resolution is anonymous: voters do not know who the buyer or
seller is (only the transaction evidence). The buyer and seller do
not know who voted.

---

## Economic Sustainability

Kunekt is a protocol, not a company. The infrastructure — relays,
storage backends, mix network nodes — must be sustained by someone.
This is an open design question with no single settled answer. We
present the options honestly.

### Who Pays for Infrastructure?

In the current design, space members bear the cost:

- **Self-hosting.** Members run their own Nostr relays and storage
  nodes. Zero cost to the network but requires technical capability.
- **Relay subscriptions.** Members pay relay operators for storage
  and bandwidth. Nostr already has paid relay models (NIP-42
  authentication, subscription tiers).
- **On-chain settlement fees.** Payment channel settlement incurs
  blockchain transaction fees. These are borne by the channel
  participants.

### Relay Operator Incentives

Relay operators need a reason to run infrastructure:

- **Paid tiers.** Relays charge for storage above a free quota.
  Members pay in cryptocurrency. The relay does not know what the
  stored data is (encrypted blobs) but it knows how much storage
  a subscriber uses.
- **Privacy-preserving payments.** Using ZK credentials, a member
  can pay a relay without revealing which space or user the storage
  is for. The relay sees "valid payment credential" and allocates
  storage. See [Nostr Integration](./nostr.md) for relay privacy
  hardening.
- **Relay-as-a-service.** Organizations run relays for their own
  spaces and optionally offer capacity to others. Similar to email
  server hosting.

### Storage Market

A decentralized storage market would let members publish storage
requests ("I need 1GB for 1 year") and storage providers bid on them:

- Providers post offers (price, capacity, availability guarantees).
- Members select providers and store erasure-coded fragments across
  multiple providers (see
  [Storage Layer](./persistence.md)).
- Proof-of-storage challenges verify that providers are faithfully
  storing data.
- Payment is via payment channels settled on-chain.

This is a potential Phase 6+ feature. The design is speculative and
depends on the maturity of proof-of-storage systems and the
existence of a suitable settlement chain.

### What We Do Not Know

Several economic questions remain open:

- **Free-riding.** How do you prevent members from consuming relay
  resources without paying? Authentication tokens help, but pricing
  models are unsettled.
- **Sustainability without tokens.** Can the infrastructure sustain
  itself without a native token? Relay subscriptions denominated in
  existing cryptocurrencies may suffice, but a native token could
  align incentives more directly.
- **Pricing privacy.** If a relay charges per-byte, it learns
  something about usage patterns. Fixed-price tiers (pay for a
  bucket, not per byte) provide better privacy at the cost of
  economic inefficiency.
- **Governance of shared infrastructure.** If multiple spaces share
  a relay, who decides the relay's policies? A governance framework
  for shared infrastructure is needed but not yet designed.

These questions will be revisited as the protocol matures and real
usage patterns emerge.
