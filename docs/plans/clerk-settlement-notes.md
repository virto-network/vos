# Workstream C — clerk/settlement tracking notes

Working notes for the clerk-settlement branch (federation-showcase.md
Track S: G6 → S1 → S2 → S4 → S5 → S6). Not a design doc — a running
record of decisions and deferred work whose rationale doesn't belong in
code comments.

## G6 — Raft caller-identity gate (RESOLVED: node-peer grants are the pattern)

**Question.** A `clerk-ledger` runs `Consistency::Raft` across a bank's
nodes; its money-path mutators are `#[msg(role = Operator)]`. When such a
mutator reaches the Raft leader from another node — either a follower's
in-process agent auto-forwarding a refused write
(`agent_forward_to_raft_leader`, `vos/src/node.rs`) or any cross-node
invoke — the leader attributes the caller to the **forwarding/peer node's
PeerId**. The in-process `Caller::System` / `Caller::Actor` identity that
bypasses role gates is *lost* the moment the invoke leaves the node. So:
does the existing node-peer grant path satisfy the Operator gate, or is a
new mechanism (a System-relayed forward) required?

**Answer: node-peer grants work; no new mechanism.** The leader resolves
the caller's space role from its **local** space-registry
(`lookup_caller_role` → `peer_role`). Granting the voter node's own PeerId
`AUTH_ROLE_ADMIN` (space `Admin`, which the `CLERK_LEDGER_SPACE_ROLE_MAP`
maps to `ClerkLedgerRole::Operator`) makes the forwarded/cross-node write
pass. `AUTH_ROLE_DEVELOPER` would also map to `Operator`; `Member` would
not. This is the "chronos lesson" already documented at
`vos/src/node.rs`'s `agent_forward_to_raft_leader`.

Proven by `raft_clerk_ledger_operator_gate_under_leader_forward`
(`vos/tests/elf_integration.rs`): ungranted node peer → `Forbidden`;
granted node peer → `bootstrap`/`create_account`/`apply_transfer` commit
through the leader and both replicas converge on one state root; a
follower restart re-converges.

**Consequences this shapes:**

- **Manifests (S5).** `clerk-ledger` is `consistency = "raft"`. The
  space-registry that resolves the grant must be **CRDT-replicated across
  the bank's nodes** so the grant is present on whichever node holds
  leadership. (The grant is anchored on one node and converges; the test
  asserts convergence on both replicas before driving the gated writes.)
- **Grant script (E/S7).** Grant **every voter node's own peer**
  `Admin` on the bank's space — not only the operator's CLI peer. A write
  that lands on / forwards through a node authenticates as *that node's*
  peer.
- **clerk-settle (S1).** `register_bank` / `settle_window` are
  Operator-gated on a Raft venue and inherit the same rule. The demo
  targets the venue **leader** directly for these (via `raft-status`), but
  the venue's node peers must still be granted `Admin` so a co-located
  agent's forward (or a leadership flip mid-call) doesn't strand the write.
  `submit_claim` stays an OPEN handler (auth = the bank's claim signature),
  so it is unaffected.

## Handler arg typing (G25/G26) — DONE (rebased onto master)

The branch was **rebased onto master `353743c8`** (which carries stream D:
G28 `7fc261dc`, G25 `cb65822c`, G26 `18dc34d1`, G27a `2762905b`) — clean, no
conflicts. The handlers I added are now **born typed** with G26 `[u8; N]`
args and the `try_array` decoding dropped:

- `clerk-settle`: `register_bank(name: Vec<u8>, clerk_pubkey: [u8; 32])`;
  `submit_claim(claim: Vec<u8>, voucher_count, rk_set_hash: [u8; 32])`
  (`claim` stays opaque — a foreign `SettlementClaim` wire form);
  `claim_diagnostics(claimant: [u8; 32], peer: [u8; 32], …)`. Bank names stay
  `Vec<u8>` (opaque). `ClaimReport` was already a typed rkyv return.
- `clerk-bridge`: `anchor_reset(peer_name: Vec<u8>, root: [u8; 32])`.

`store.rs` free fns + unit tests + the e2e Ref call sites were updated to
match (e.g. `pk.to_vec()` → `pk`). A wrong-length pubkey is now a
compile-time invariant of the typed arg, so the old `BadInput`-on-bad-length
paths/tests were dropped.

**Not retyped (out of workstream-C scope):** the pre-existing clerk-ledger /
clerk-bridge handlers (`bootstrap`, `create_account`, `register_peer`,
`submit_voucher`, …) stay `Vec<u8>` — retyping them is the broader E-A
"retype the clerk handlers" cleanup that touches the two-bank e2e's many
existing call sites; a follow-up, not this branch.

## Progress

- **G6** — done, committed. Raft caller-identity gate proven.
- **S1** — done. `actors/clerk-settle` crate (venue actor): `register_bank`
  (Operator), `submit_claim` (open, claim-signature-authed), `settle_window`
  (Operator) → `cipher_clerk::settlement::reconcile`; claim store
  replace-until-settled + freeze-on-settle with a version byte; watch-view
  reads. 8 in-crate unit tests + `raft_clerk_settle_bilateral_settlement`
  e2e (venue Raft ×2, Operator handlers via leader-forward + node-peer
  grant, open `submit_claim` via follower, bilateral zero-sum settle,
  replication convergence). cipher-clerk `settlement` feature enabled for
  this crate only.
- **S2** — done. clerk-bridge receiver-term accumulation: per-`(peer,
  currency, window)` negated sum of accepted vouchers' `amount_commit`,
  folded at the same accept points as the F2 anchor (both `submit_voucher`
  and `redeem_voucher`); `window_rotate(peer)` (Operator) + `current_window`
  + `window_net(peer, currency, window)` reads. Currency = fixed
  `DEMO_CURRENCY = 840` (register_peer's ABI kept stable — a per-peer
  currency param is the multi-currency forward step). Point arithmetic uses
  only `Amount::to_point`/`from_point` (no `curve25519` direct dep, no
  `settlement` feature on the bridge). The normative worked example is
  `window::tests::worked_example_two_bank_net_flows_cancel`; the two-bank
  e2e now asserts `window_net` == negated accepted commit end-to-end.
  clerk-bridge gained a roles module (Operator gate) for `window_rotate`
  (and S4's `anchor_reset`).

  **Currency decision:** the accumulator key carries currency from the
  start, but `register_peer` stays 3-arg (`peer_name, clerk_pubkey,
  node_prefix`) — the demo is single-currency, and its two existing callers
  (the two-bank e2e) stay untouched. Revisit if multi-currency federation
  is added: add `currency: u32` to `register_peer` → `PeerEntry`.
- **S4** — done. `anchor_reset(peer, root)` (Operator) on clerk-bridge:
  re-anchors `last_root_after` to a settled window's closing root, the
  sanctioned recovery for the F2 fail-closed wedge. Two-bank e2e now proves
  wedge → recovery: a non-chaining voucher is `VoucherInvalid`, then
  `anchor_reset` re-anchors and the same voucher chains (`Ok`).
- **S5** — done. Example manifests `examples/space-bank-a.toml`,
  `space-bank-b.toml`, `space-venue.toml` (bank: clerk-ledger `raft` +
  clerk-bridge `local`+`network_reachable`; venue: clerk-settle `raft`;
  shared `hyperspace = "bank-federation"`). `space-clerk-demo.toml` updated
  to the same postures (closes bank-federation.md item 1 in-repo).
  `bank-federation.md` corrected: the "Ephemeral bridges" wording now
  distinguishes the stateless `space-bridge` (`Ephemeral`) from the stateful
  `clerk-bridge` (`Local`); item 1 marked DONE; the F2 anchor marked wired;
  the wedge-recovery paragraph now points to settlement + `anchor_reset`.
- **S6** — done. `multi_node_three_space_settlement_capstone`: five
  in-process nodes (venue ×2 clerk-settle Raft, bank-A ×2 with a bridge on
  a1, bank-B ×1) sharing one hyperspace registry. Asserts: hyperspace
  resolution from bank-A's SECOND node; BIDIRECTIONAL vouchers (A→B and B→A,
  each bridge folding the accepted commit into its receiver term); window
  rotate → quiesce → both drivers derive `issuer ⊕ receiver` claims → the
  two net-flow commitments cancel → `settle_window` records the window and
  replicates to both venue nodes; `anchor_reset` unwedges a deliberately
  wedged channel. Uses `submit_voucher` (verify + accumulate) — no
  clerk-ledger needed for the settlement demonstration — and drives the
  venue's Operator handlers locally on the leader as `Caller::System` (the
  leader-forward + grant path is already proven by G6/S1), so S6 needs no
  per-space registries or grants, only the shared hyperspace registry.

## S6 finding — submit_claim follower routing (shapes the S3 driver)

The plan framed `submit_claim` "arriving at the venue follower → leader-
forward on the open handler". The actual behavior is more nuanced and the
driver must account for it:

- A `submit_claim` that would **short-circuit before the write**
  (`UnknownBank` / `BadInput` / `SignatureInvalid` / `AlreadySettled`) can
  return a status from a **follower** — no commit is needed, so the reply
  comes back normally.
- A `submit_claim` that **would commit** (valid claim, banks registered),
  sent to a follower, is **refused**: the follower's raft agent drops the
  write and the inbound libp2p `dispatch_invoke` does NOT auto-forward
  (leader-forward only fires on the agent/extension *outbound* paths, per
  G6). It surfaces to the caller as an error.

So the driver must **target the venue leader** for `submit_claim` (resolve
`clerk-settle` via the hyperspace, then pick the leader via `raft-status`),
exactly as it already must for the Operator-gated `register_bank` /
`settle_window`. There is no free follower→leader forward for the open
write on the direct cross-space path.

## Track S complete

G6 · S1 · S2 · S4 · S5 · S6 all landed on branch `clerk-settlement` (one
commit per item). Not pushed (awaiting review). Deferred: clerk handler
retyping when stream D's G25 reaches master (see the retype TODO above).

## S5 finding — auto replication_id is NOT space-scoped (trap for S7 / bloque)

`vosx`'s `auto_replication_id(agent_name, program_hash)`
(`vosx/src/commands/space/common.rs`, called from `reconcile.rs`) hashes
only `(name, blob)` — no `space_id`. So two DIFFERENT spaces that name an
agent identically with the same ELF and leave `replication_id = "auto"`
collide into ONE replication group. For the federation (bank-a and bank-b
both name their ledger `clerk-ledger`), that would merge the two banks'
Raft ledgers. The reference bank manifests therefore **pin a distinct
`replication_id` per bank**; the operational bloque manifests must do the
same (or use per-bank agent names). The venue is unaffected (single venue,
distinct `clerk-settle` name). Worth considering folding `space_id` into
`auto_replication_id` in `vosx` (workstream F), which would make `"auto"`
safe across spaces.

## S4 close-protocol conventions (for the S3 driver / S9 runbook)

These are driver/script conventions the bridge code enables; they live in
the bloque repo's driver + runbook (workstream E), recorded here so the
handler contract they rely on is explicit.

- **Quiesce barrier.** `reconcile` demands *identical* voucher sets on both
  sides of a byte-identical window, and it is a bare `Err` with no
  partial/dispute path — one in-flight voucher at close fails *both*
  windows. So the close script must: stop issuing → assert every issued
  `redemption_key` (both directions) appears in the counterpart bridge's
  dedup set (`redeemed_count` + the per-triple check) → `window_rotate`
  both directions → derive claims from the just-closed window's
  `window_net` + the driver's issuer accumulator.
- **Divergence diagnostics.** Commitments are opaque, so a bare
  `NetFlowMismatch` is undebuggable. The `voucher_count` + `rk_set_hash`
  submitted alongside each claim (`clerk-settle::claim_diagnostics`)
  localize a mismatch without opening any commitment: count differs ⇒
  in-flight/missed voucher; count equal but hash differs ⇒ set divergence.
  Recovery is resubmission of a corrected claim (the venue's claim store is
  replace-until-settled), then re-`settle_window`.
- **Wedge recovery.** After a recorded settlement, `anchor_reset(peer,
  settled_closing_root)` on *both* banks' bridges re-opens the voucher
  channels for the next window.

## Adversarial review 2026-07-08 (pre-merge) — fixed here + carried forward

A 4-lens adversarial review ran before merge. One money-path blocker was
**fixed on this branch**; the rest are DoS/griefing or test-coverage that
cannot produce a *wrong* settlement (the venue's `settle_window`
cancellation check is the monetary gate) and are recorded here.

**FIXED — commit-binding (was a silent receiver-loss route).**
`submit_voucher` opened the envelope and credited its value, and folded
`amount_commit` into the settlement receiver term, but never checked the
two agree — the issuer signs both independently. A malicious issuer could
seal value 100 while committing to 10 (receiver credits 100, window settles
10), or ship a non-canonical `amount_commit` the receiver term folds as the
identity (window settles clean while the receiver is out the credited
value). Fixed by a fail-closed
`Amount::commit(value, &blinding) == voucher.amount_commit` check on the
submit accept path (byte equality also forces `amount_commit` canonical),
mirrored by a `to_point().is_some()` guard on `redeem_voucher`. Regression:
`elf_integration.rs` two-bank e2e (mismatched-envelope voucher →
`VoucherInvalid`, dedup + receiver term untouched). This makes
`window::sub_commit`'s `None` arms unreachable defense-in-depth (comment
corrected).

**Carried forward — Wave-1 limits (no wrong-settlement risk; documented,
not code-blocking):**

- **Claim store has no freshness/supersession.** `submit_claim` is open and
  claims carry no nonce/sequence, so a wire observer can resubmit a bank's
  *earlier* signed claim to roll back a corrected one
  (`store.rs` replace-until-settled overwrites unconditionally). It cannot
  forge a claim (signature is checked against the registered claimant
  pubkey) and cannot produce a wrong settlement (cancellation still gates
  `settle_window`), but it can get a window settled+frozen on a stale voucher
  set. **Close-protocol rule:** re-verify `claim_diagnostics` immediately
  before `settle_window`. **Wave-2:** carry a monotonic per-(claimant, pair,
  currency, window) sequence inside the signed claim and reject
  non-increasing replacements.
- **Claim store is grow-only.** `(currency, window)` are attacker-chosen
  fields inside the signed claim; a registered bank can push unbounded
  distinct-keyed rows. **Wave-2:** cap rows per pair, or reject
  `currency != DEMO_CURRENCY` / windows outside a band of the venue's
  current window.
- **Diagnostics are unauthenticated.** `voucher_count` / `rk_set_hash` ride
  *outside* the signed claim — an operator-triage hint only, spoofable by the
  submitter. Never gate an automated decision on them.
- **rkyv fail-to-fresh on upgrade.** This branch adds fields to the
  clerk-bridge state (`PeerEntry.window`, `ClerkBridge.window_nets`) and the
  new clerk-settle actor. An existing bridge's archived state fails
  `try_decode` and resets to `new()` (the accepted node_prefix precedent) —
  wiping `local_ledger_id`, the peers table, the F2 anchor, and the dedup
  set. **Operational rule:** stand bridges up fresh when deploying this
  branch (or re-bootstrap → re-register peers → `anchor_reset`).

**Carried forward — test-coverage fast-follow (add with the S3 driver / S6
hardening; the properties hold, the guards just aren't pinned):**

- Cross-node **Operator-gate enforcement** on `anchor_reset` / `window_rotate`
  is never asserted (every test drives them as local `Caller::System`, which
  bypasses the gate). Add: an ungranted cross-node peer → `Forbidden` for
  each (one assert each, using the existing mesh).
- The **`redeem_voucher`-path receiver-term fold** (the production
  money-moving ingress) has no `window_net` assertion — only the
  `submit_voucher` path is checked. Add a `window_net` assertion after a
  redeem so deleting that fold fails a test.
- No **non-Ok clerk-settle Status** crosses the wire in any e2e (all venue
  assertions compare against `Ok` = 0). Add one wire-level negative
  (`UnknownBank` before registration, or `AlreadySettled` after settling) so
  an rkyv discriminant drift is caught.
- The **issuer ⊕ receiver → `reconcile`** composition is proven only by the
  ELF-gated e2es; the native `window` test uses a hand-rolled `add/is_zero`.
  Add a native clerk-settle test that composes accumulate_neg-derived terms,
  signs both claims, and drives `store::settle_window` so a sign regression
  fails plain `cargo test`.
