# Bank federation: heterogeneous banks over a shared settlement protocol

Status: DIRECTION (Wave 1 landing). Captures the target shape of the
cross-bank federation and why the pieces are factored the way they are, so
that later work — operator privacy, public/BFT banks, the settlement venue —
slots in without a redesign. Companions: `succinct-merkle-witness.md` (the
transition proof), `proving-time.md` (making it fast).

## The one idea: banks are private, the protocol is shared

Different institutions will run very different banks — a regulated bank on a
private Raft cluster, a public bank that is itself a blockchain, a
privacy-first bank that hides balances even from its own operator. The
federation does **not** try to make them agree on an internal model. It makes
them agree on a **wire**: the voucher + on-chain settlement protocol.

- A bank's **internal model** — its consensus (Raft / BFT / chain), its
  storage, whether the operator can see balances — stays private to that bank.
- What crosses the boundary is a **voucher** attesting a conservation-of-value
  transition, backed by a signature and/or a zk proof.
- The **settlement-verifier is the cross-type trust bridge**: two banks that do
  not trust each other's internals both prove to the same settlement layer,
  which runs the inter-vault zero-sum check. Neither inspects the other.

This is already true in the code: cipher-clerk's voucher wire is documented as
working identically "whether C1 is a regulated bank running L0 (clerk sees
everything internally) or a fully-shielded wallet" (`cipher-clerk`
`src/voucher/mod.rs`). Heterogeneous banks are therefore a *forward-compatible
addition*, not a retrofit.

## Bank types, in waves

| Wave | Bank type | Consensus | Operator sees balances? | Proof mode |
|------|-----------|-----------|-------------------------|------------|
| **1 (now)** | Regulated / private | **Raft** across the operator's own nodes | **Yes** (trusted clerk) | `Mode::Signature`, or the `Mode::External` real-STARK path |
| 2+ (future) | Public / on-chain | **BFT** (the bank *is* a blockchain) | — | proof-verified on-chain |
| 2+ (future) | Privacy-first | any | **No** — operator-blind | **client-side** proving |

Wave 1 is intentionally the *trusted-clerk, operator-visible* configuration.
It is enough to stand up a real multi-bank deployment among mutually-known
operators, and every later type reuses the same voucher/settlement wire.

## Wave 1 — what ships

1. **Ledger as `Raft`, not `Local`.** A bank wants high availability for its
   users, so the ledger replicates across the operator's own nodes. `Raft` is
   tier-2 on the shareability lattice (below), so it is *not* node-confined and
   answers the network by design — which means it needs **no**
   `network_reachable` opt-out. Replication is scoped to the operator's
   enrolled nodes via `AgentConfig.members` + `NODE_ROLE_VOTER` voter
   enrollment. (Note the monotone locality **seal**: a `Local` agent can't be
   widened to `Raft` later — register it `Raft` from the start.)

2. **Role-gate the ledger's read handlers.** A `Raft` ledger answers *any*
   peer, gated only by each handler's own `#[msg(role)]`. Today
   `account`/`state_root`/`transfer`/`*_count` are bare `#[msg]`, so a `Raft`
   ledger would expose commitments **and metadata** (which accounts exist,
   counts, the transfer graph) to arbitrary peers. Values stay hidden
   (Pedersen), but that metadata should not leak — gate the reads to the
   bank's own members. **The privacy boundary for a `Raft` ledger lives in the
   ACLs, not the confinement tier.**

3. **`network_reachable` manifest wiring (④) — for the bridges.** The
   cross-bank `clerk-bridge` and cross-space `space-bridge` are `Ephemeral`
   (stateless gateways, no private data) and *must* answer the network. They
   stay confined-by-default and need the `network_reachable` opt-out threaded
   from the manifest → the author-signed `AgentRow` (mirrored in
   `vos/src/registry_canon.rs`, fail-closed drift guard) → `agent_config_from_row`.
   This is needed regardless of the ledger being `Raft`.

4. **Cross-bank goes through the bridge, never a direct ledger read.** The
   voucher settlement flow never reads a peer's ledger: bank A reads its *own*
   ledger to issue, ships the voucher to bank B's **bridge**, and the bridge
   credits bank B's *own* ledger locally. So a `Raft` ledger answering the
   network is for *intra-operator* traffic (HA + the bank's own users); the
   bridge is the only *inter-operator* surface.

Trust model for Wave 1: mutually-known operators. Vouchers settle on
`Mode::Signature` (the issuer vouches with its clerk key) or the
`Mode::External` real-STARK proof — the receiver-side prior-state **anchor** is
not yet wired, which is acceptable while peers are pre-shared and trusted.

## Why confinement works the way it does

Network reachability is derived from the **shareability lattice**
(`Consistency::is_node_confined`): `Ephemeral`(0) and `Local`(1) are
*node-confined* — their state never leaves the device — while `Crdt`/`Raft`(2)
replicate off-node and legitimately answer the network. A confined agent is
reachable only by this device's own operator; every other peer is refused (the
messenger's MLS keys, CSPRNG seed and decrypted plaintext are the load-bearing
reason the gate exists).

The subtlety: *state shareability* and *network reachability* are correlated
but not identical. The messenger is confined-state **and** network-private
(aligned). But the `Ephemeral` bridges hold nothing private yet must answer the
network, and a `Raft` ledger answers the network yet has a private read
surface. `AgentConfig.network_reachable` is the per-actor patch that decouples
the two axes; the finer long-term boundary is **per-handler visibility** (a
`network_visible` flag mirroring the existing `exposed_to_cli` per-`#[msg]`
flag), so consistency goes back to meaning only *state* shareability. Not
needed for Wave 1, but the shape to grow into.

## The heterogeneity gate: the F2 anchor + on-chain settlement

Wave 1 among trusted operators is fine on signatures/proof. Admitting banks you
do **not** already trust needs the real solvency backstop, in two coupled
pieces:

- **Receiver-side prior-state anchor** (application layer) — **LANDED**. Each
  `PeerEntry` carries `last_root_after: Option<[u8; 32]>`; once the bridge
  accepts a voucher from a peer, that peer's next voucher must declare
  `state_root_before == last_root_after`, forcing a single linear voucher chain
  per peer. The first voucher is unanchored — the true anchor is settlement.
  Placed as a distinct check **after** the external-proof dispatch and the dedup
  check (NOT folded into `verify(Some(..))`), so a bad proof still reports
  `ProofInvalid` and a replay still reports `VoucherReplayed`; only a fresh,
  correctly-signed, non-chaining voucher collapses to `VoucherInvalid`. The
  cursor advances only on acceptance and is preserved across a key-rotation
  re-register (the chain tracks the peer's ledger, not its signing key).
  **Limits (carry forward):** (a) it stores a *claimed* `root_after` — in
  Signature-mode nothing proves the roots reflect real ledger state (only an
  External proof or on-chain settlement does); (b) it fails **closed** — a peer
  whose ledger advances off this channel (a voucher to a different receiver, or
  any non-vouchered transfer) declares an unseen `state_root_before` and is
  rejected, and since rejections don't advance the cursor the channel can wedge
  until settlement. There is no wedge-recovery in Wave 1 by design; the
  sanctioned recovery is the Wave-2 on-chain settlement anchor.
- **On-chain settlement-verifier** (the real backstop): each bank proves its
  vault delta on-chain and the chain runs the inter-vault zero-sum
  reconciliation (`zkpvm/settlement-verifier`, Poseidon2-M31; `build-settle`
  exists). This is what makes cross-*type* settlement sound — the shared layer a
  Raft/operator-visible bank and a BFT/operator-blind bank both prove to.

Design the settlement seam in Wave 1; build it when Wave 2 arrives.

## Operator-blind (Wave 2): the privacy upgrade, deferred

As implemented, cipher-clerk is a **trusted-clerk** model: balances/amounts are
Pedersen commitments (hiding to outside observers and the chain), but the
operator's node holds the openings and `apply_batch` *mandatorily* reveals each
entry's cleartext `(value, blinding)` to run its range / non-negativity checks
(`kernel/apply.rs`, `kernel/verify.rs`). Operator-blind is neither implemented
nor designed for the account ledger — privacy is engineered against peer
clerks, the chain, and public observers, not the operating clerk. (One doc,
`l1-amounts.md`, overstates this — "only the recipient holds them" describes the
viewing-key *envelope*, an extra sealed copy, not a removal of the operator's
need for openings.)

Making a bank operator-blind is a real architectural extension of the *same* zk
stack, not a config flag:

1. **Move proving client-side** — the user's wallet holds the openings and
   generates the transition proof; the operator only verifies it and applies the
   homomorphic commitment update, never seeing `(value, blinding)`.
2. **Replace operator-side reveal with a client range proof** — the blocker is
   `reveal_and_check`, which needs the opening; the client proves
   `0 ≤ value < 2^n` in zk so the operator verifies without it.
3. Ledger storage is unchanged (commitments only); the *validation path* is
   what moves.

So operator-blindness is the client-side-proving evolution of the
voucher-check / succinct-witness machinery. The current operator-side
`Mode::External` prover is the stepping stone.

## Non-goals (now)

- Operator-blind / client-side proving (Wave 2).
- Public / BFT banks (Wave 2) — only the shared voucher+settlement wire matters
  for interop; their internals are out of scope here.
- Recursive aggregation (see `proving-time.md` §6) — orthogonal proving-cost
  work that would also retire the per-segment commitment allowlist.
- Per-handler `network_visible` — the finer confinement model; the per-actor
  `network_reachable` bool suffices for Wave 1.
