# Succinct Merkle witness for the conservation-of-value proof

Status: PLAN (not started). Prereq landed: the full-snapshot transition now
proves end-to-end as a bounded-memory segment chain (branch
`voucher-state-transition`). This plan replaces the **full-ledger** witness with
a **touched-leaves + Merkle-paths** witness so proving cost scales with the
batch, not the ledger.

## Why

`TransitionWitness` carries the issuer's entire `VecLedger`, and
`verify_transition` re-hashes the whole ledger twice (`root()` before + after,
via `composite_state_root` over *all* accounts/transfers) plus re-runs the
kernel. Even a 2-account batch traces to **5.3M PVM steps** and needs ~75 min as
an 11-segment chain. The cost is `O(ledger size)` — every leaf is re-hashed —
which is the real blocker for anything past a pilot ledger.

A succinct witness carries only:
- the **touched leaves** (accounts the batch reads/writes, the referenced
  transfers, the journal), each with its **128-sibling SMT authentication path**
  against `root_before`, and
- the **unrooted bookkeeping** the kernel checks (`external_ids`,
  `voided_transfers`, `pending_statuses`) — see Soundness.

The guest verifies the paths reconstruct `root_before`, re-runs the *same*
kernel against a sparse ledger view, and recomputes `root_after` from the
updated leaves + cached siblings. Witness size and trace length both drop to
**`O(touched · log N)`**, independent of total ledger size. Expected payoff: a
typical batch proves in **one shot** (no segmentation / `verify_chain`), turning
~75 min into seconds–minutes.

The public interface is unchanged: the proof still binds
`public_bytes(&voucher::Public)` (`domain || issuer || amount_commit ||
root_before || root_after`, 125 B) into the Phase-Z0 io-hash; the verifier still
composes `verify_standalone ∧ public_io_hash == compute_io_hash`. Only the
*witness* and `verify_transition`'s internals change. `kernel/proof.rs` already
anticipates this ("swap to per-touched-leaf Merkle witnesses without changing
`Public` shape").

## What exists vs. what's missing

Exists (cipher-clerk):
- `SparseMerkleTree` (depth 128, 16-byte keys): `insert/remove/get/root`,
  `prove(key) -> SmtProof{key, leaf, siblings: Vec<[u8;32]>}`,
  `SmtProof::verify(root) -> bool` (recomputes root from leaf + siblings by
  key-bit path). `merkle.rs`.
- `composite_state_root(accounts, transfers, journal)` =
  `smt_node_hash(smt_node_hash(accounts_root, transfers_root), journals_root)`;
  `build_empty_chain()` for empty subtrees; domain-tagged leaf/node hashes.
  `state_root.rs`.
- Kernel reads **only by explicit id** (binary-search `get_account`/
  `get_transfer`; no full scans), so a sparse ledger view is drop-in. The
  `LedgerState` trait is the seam. `apply_batch_refine` already returns a
  `StateDelta{accounts, transfers, external_ids, voided_transfers, journals,
  pending_statuses}` — exactly the touched-write set.
- Unused scaffolding signalling intent: `state.rs` `MerklePath{leaf, siblings,
  directions}` and `Oracle::merkle_path`/`next_blinding` stubs.

Missing (the build):
1. **Sparse multiproof primitive** — recompute one consistent root from N
   touched leaves + their shared siblings (single-leaf `SmtProof` doesn't
   compose). This is the core algorithm.
2. **`SparseLedger`** — a `LedgerState` impl backed by proven leaves that
   **panics on any unproven read** (so a prover can't dodge an overdraft check
   by omitting an account).
3. **`SuccinctTransitionWitness`** + `verify_transition_succinct`.
4. **Host witness builder** — extract proofs for the touched keys from the
   producer's `SparseMerkleTree`-backed ledger.
5. (Soundness prerequisite) root-commit `external_ids`/`voided_transfers`/
   `pending_statuses`.

## Core primitive: sparse Merkle multiproof

Single-leaf `SmtProof::verify` recomputes the root from `(leaf, 128 siblings)`.
For a batch the leaves share ancestors, so we need one consistent reconstruction:

```
struct BatchProof {
    // touched (key, leaf_hash) for one sub-SMT (accounts | transfers | journal)
    leaves: Vec<([u8;16], [u8;32])>,
    // the minimal frontier of sibling hashes needed to fill the rest of the tree,
    // keyed by their position so shared nodes are stored once
    nodes:  BTreeMap<NodePos, [u8;32]>,   // NodePos = (depth_from_leaf, path_prefix)
}
impl BatchProof {
    // bottom-up recompute: at each node, hash the two children when both are
    // present (a touched subtree or a frontier node); otherwise fall back to
    // the empty-subtree hash. Returns the sub-SMT root.
    fn root(&self, leaf_override: &Map<key,[u8;32]>, empty: &[[u8;32];129]) -> [u8;32];
}
```

- `verify`: `root(no overrides) == sub_root_before`.
- `root_after`: `root(updated leaf hashes)` — same `nodes` frontier, new leaves.
- Build one `BatchProof` per sub-SMT (accounts, transfers, journal), then
  `composite = node(node(accts, xfers), journals)` before and after.
- Soundness of the frontier: consistency is forced by the reconstruction
  hashing to `sub_root_before`; a wrong/extra sibling changes the root and
  fails. Account **creation** = a touched leaf whose proven value is
  `SMT_EMPTY_LEAF` (non-inclusion), updated to the new account leaf.

This can live in cipher-clerk `merkle.rs`/`state_root.rs` and is pure host-side
Rust the guest re-runs — keep it allocation-light and `no_std`-friendly (the
guest is PVM).

## Phases

### Phase 0 — root-commit the unrooted bookkeeping (soundness prerequisite)
`composite_state_root` commits accounts + transfers + journal only. The kernel
*also* checks `external_id_seen` (idempotency), `transfer_voided` (no double
void), and `pending_status` (lifecycle) — none root-bound. **This is a
pre-existing gap** (the full-snapshot witness lets the prover supply those sets
freely), but a succinct witness makes it unavoidable to confront because those
sets must be carried explicitly. Fix: extend the composite root to
`node(node(node(accts, xfers), journals), node(node(ext_ids, voided), pending))`
(three more sub-SMTs, presence-only leaves). Bumps the state-root format; update
`composite_state_root`, `VecLedger::root`, and any pinned roots. This makes both
the full-snapshot and succinct paths sound and is independently valuable for the
"real money" hardening track. *Decision point: do Phase 0 first, or ship the
succinct path with the same trust assumption as today and harden later.*

### Phase 1 — cipher-clerk: succinct verify (host-testable, no zkVM)
- 1a. `BatchProof` + sparse multiproof root/verify/update (the primitive above) +
  unit tests against `SparseMerkleTree` on random ledgers (round-trip:
  `batch_proof.root() == tree.root()`; update matches a full rebuild).
- 1b. `SparseLedger`: `LedgerState` over the verified touched leaves; `get_*`
  returns the proven leaf or **panics** for any id not in the witness;
  `put_*` accumulates into a `StateDelta` (reuse the existing one).
- 1c. `SuccinctTransitionWitness{ accounts/transfers/journal BatchProofs,
  ext_ids/voided/pending sets (+ their proofs if Phase 0), oracle, events,
  batch_seed_timestamp }` (rkyv-archivable, `no_std`).
- 1d. `verify_transition_succinct(&self, root_before, root_after)`: verify all
  BatchProofs against `root_before`; build `SparseLedger`; run
  `apply_batch_refine`; assert every `status == Created`; apply the delta to the
  proven leaves; recompute and assert `root_after`. Mirror
  `verify_transition`'s assertions exactly.
- 1e. Host witness builder `SuccinctTransitionWitness::from_full(&VecLedger,
  events, oracle, ts)`: run the batch once to discover touched keys (the
  `StateDelta` + the read set), build a `SparseMerkleTree`, extract a `BatchProof`
  per sub-SMT. A **differential test** is the key gate: for many random batches,
  `verify_transition_succinct` accepts exactly when `verify_transition` does, and
  rejects the same forgeries (overstated `root_after`, fabricated balance,
  omitted account, double-void, replayed external id, create-on-occupied-slot).

### Phase 2 — guest: voucher-check runs the succinct witness
- Decode `SuccinctTransitionWitness` from `__VOS_WITNESS` (rkyv), call
  `verify_transition_succinct`, keep `has_debit_commit` + the identical
  `bind_io_bytes(public_bytes, &[1])` io-binding. The 16 KiB buffer now holds a
  small proof set instead of the full ledger.
- Build the voucher-check ELF (path-independent; re-pin
  `VOUCHER_CHECK_COMMITMENT` if the program bytes change).

### Phase 3 — prover/host: build the succinct witness
- `prover` extension builds `SuccinctTransitionWitness` (from the producer's
  ledger) and injects it; the clerk-bridge / federation path is unchanged
  (same `Public`, same commitment, same verify composition).

### Phase 4 — validate + measure
- `measure_transition_trace` on the succinct guest: confirm steps drop from
  ~5.3M to `O(touched · log N)` and are **independent of ledger size** (prove a
  10-account and a 10k-account ledger with the same 1-debit batch; step counts
  should match within noise).
- If the trace fits one proof: prove with `prove`/`prove_mobile` directly —
  segmentation/`verify_chain` become unnecessary for typical batches (keep them
  for pathologically large batches).
- Re-run the federation e2e (`clerk_ledger_two_bank_federation`) end-to-end:
  real STARK over the succinct witness, CAS-shipped, accepted through the
  clerk-bridge. Rebuild the prover `.so` first (stale-cdylib gotcha).

## Soundness checklist (guest must enforce; tests must attack)
- Every leaf the kernel reads is proven against `root_before`; `SparseLedger`
  panics on any unproven read (no silent `None`). Forgery: omit an account to
  skip its overdraft check → panic.
- Account creation proves the slot was **empty** in `root_before`
  (`leaf == SMT_EMPTY_LEAF`, full 128-sibling path). Forgery: create on an
  occupied slot.
- `root_after` recomputed from updated leaves + the *same* frontier == bound
  `state_root_after`. Forgery: overstate `root_after` / fabricate a balance.
- Idempotency / double-void / pending-lifecycle: the `external_ids`,
  `voided_transfers`, `pending_statuses` the kernel checks must come from
  `root_before` (Phase 0) — otherwise the prover supplies them freely (today's
  trust assumption; document loudly if Phase 0 is deferred).
- Linked-chain atomicity, every-event-`Created`, sorted-by-id ordering,
  timestamp-postdating: re-executed identically by running the real kernel; do
  not reimplement.

## Risks / unknowns
- **Multiproof correctness** is the crux: bit-indexing (MSB-first, depth
  127..0), empty-subtree fallback, and shared-node consistency must match
  `composite_state_root` byte-for-byte. Differential tests vs. the full tree are
  the safety net.
- **Per-leaf 128-blake2b cost**: for a batch touching many leaves the proof
  verification (≈ touched × 128 blake2b) could rival re-hashing a *small*
  ledger — succinctness wins decisively only once the ledger is large. Measure;
  the structure still removes the `O(ledger)` term.
- **`no_std` in the guest**: the multiproof + `SparseLedger` run inside PVM —
  keep them allocation-light and dependency-free.
- **Phase 0 format bump** invalidates any pinned/persisted roots; sequence it
  with the federation ledger.
- **rkyv layout stability** for the new witness type — round-trip tests +
  field-order comments.

## Rough effort
Phase 1 (cipher-clerk, all host-testable, no zkVM in the loop) is the bulk and
the de-risking — the multiproof + `SparseLedger` + the differential test gate.
Phases 2–4 are mechanical given Phase 1 (the kernel and io-binding are reused
unchanged). Phase 0 is a contained but format-breaking change; decide up front
whether it gates or parallels.
