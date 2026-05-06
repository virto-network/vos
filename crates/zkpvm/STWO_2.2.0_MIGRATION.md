# Stwo `0790eba` → v2.x migration — BLOCKED upstream

## TL;DR
**Stwo's v2.x release line moved `MerkleChannel` impls exclusively into the new `vcs_lifted` "lifted protocol", and the lifted protocol does not yet support AIRs with constraint degree ≥ 2.** All our chips have `LOG_CONSTRAINT_DEGREE_BOUND ≥ 1` (constraint degree ≥ 2), so v2.0.0+ cannot prove our chips today. Stwo's own Poseidon test is `#[ignore]`'d in their tree for the same reason.

We stay on `rev = "0790eba"` until the lifted protocol gains higher-degree-AIR support.

## Smoking gun
```
$ cargo test --release poseidon # in stwo's own examples crate at v2.2.0
test poseidon::tests::test_simd_poseidon_prove ...
  ignored, AIRs with constraint degree >= 2 are not supported yet in the lifted protocol.
```

## Confirmed details
- **`v2.0.0`** (commit `980180a`) — non-lifted `vcs::blake2_merkle::Blake2sMerkleChannelGeneric` does NOT impl `MerkleChannel`. Only the lifted variant in `vcs_lifted::blake2_merkle` impls it. Same restriction.
- **`v2.2.0`** (commit `289c20de`) — same as v2.0.0 plus more parallel/perf wins, but same lifted-only `MerkleChannel`.
- Tested locally: bumping to either tag, fixing renames (path-only `vcs::` → `vcs_lifted::`, `FriConfig::new` 4th arg, `PcsConfig.lifting_log_size`, `set_store_polynomials_coefficients`), then running our existing tests: every prove path returns `ConstraintsNotSatisfied` from the OODS sanity check at end of `prove_impl`. The cause is the lifted protocol's restriction (verified by Poseidon's `#[ignore]`).

## What stays usable
- `0790eba` is our pin. Full Phase-2 tap-and-pay PROVES + VERIFIES at ~3.85 s. Step 9–19 work intact.

## Watch list (when this unblocks)
- Stwo PR / issue: "lifted protocol: support AIRs with constraint degree >= 2".  Once that lands in a release, the migration becomes straightforward (path-only renames + the `set_store_polynomials_coefficients` toggle).
- Perf cluster we'd inherit from v2.2.0 once unblocked: parallel FFT (#1304), parallel `denominator_inverses` (#1305), parallel OOD (#1306), `BaseColumnPool` (#1342), FRI jumps SIMD (#1340), `fold_circle_into_line` parallelisation (#1389/#1392/#1393), subdomain quotients (#1372/#1373).

## Honest takeaway
Phase A's "we don't touch `Trace` directly so we should be fine" was wrong. The blocker is at the *protocol* level — the channel/merkle layer that the prover and verifier both rely on — not at the chip-trace layer we have direct control over. Phase A should have caught this; the agent's recon noted the lifted-Merkle infrastructure was added but didn't connect that the impls had also been *removed* from the non-lifted path, leaving no fallback.

Migration estimate revised from "3–5 working days" to **"blocked indefinitely until upstream lands degree-≥2 support in the lifted protocol"**. No code changes from us can work around this without forking Stwo.

## Decision
1. ✅ Stay on `0790eba` for now.
2. ✅ Phase 0 commit landed (Step 9–19 baseline preserved on `master` of cipher-clerk and `zkvm` branch of kunekt).
3. ❌ Phases B–E aborted; renames reverted.
4. ⏳ Re-evaluate when Stwo's lifted protocol gains the missing capability.

---

## Update — direct chip-rewrite path explored (2026-05-06)

User preference: pursue migration regardless of cost rather than wait
for upstream. Re-bumped to v2.2.0 + path renames + `set_store_polynomials_coefficients`
again ("Phase G" succeeded, `cargo check` clean).

Tried the cheap experiment first: lower `LOG_CONSTRAINT_DEGREE_BOUND`
on all five high-bound chips to `1` to see if any are over-declared
margins (constraints actually fitting in degree 2). They are not —
`prove_fibonacci_actor` still fails with `ConstraintsNotSatisfied`.
The framework enforces actual algebraic degree, not the declared bound.

This confirms the real workaround is constraint-by-constraint
refactoring with helper columns. Pattern for any degree-3+ constraint
`a · b · c · linear = 0`:
```
  ab = a · b           // helper column
  ab - a · b = 0       // degree 2 ✓
  abc = ab · c         // helper column
  abc - ab · c = 0     // degree 2 ✓
  abc · linear = 0     // degree 2 ✓
```

### Honest scope re-estimate per chip

| Chip | Bound | Constraint count | Helper-column rewrite scope |
|---|---|---|---|
| `Blake2bChip` | 2 | 41 | ~50 helpers, ~1 week |
| `MulChip` | 2 | 16 | ~30 helpers, ~3–5 days |
| `CpuChip` | 2 | 123 | ~150–300 helpers, ~2 weeks |
| `DivRemChip` | 3 | 17 | sign-correction chains, ~1 week |
| `RistrettoChip` | 3 | 35 | schoolbook ~thousands of helpers OR rewrite via lookups, ~3+ weeks |

Total realistic: **6–8 person-weeks** of focused chip-AIR refactoring work.

### Risk: column inflation may cancel perf cluster gains

Every helper column adds a base-field column to the trace. v2.2.0's
perf cluster (parallel FFT, FRI jumps, BaseColumnPool, subdomain
quotients) is expected to deliver ~10–30% on the SIMD path. A
2× column-count blow-up plausibly cancels that. We won't know
until measured post-rewrite.

### Why this is hard to finish in a single session

The rewrite isn't mechanical — each constraint needs to be analyzed
in context, helper columns sized correctly, witness fill code updated
to match (the host-side trace generation must populate the helper
columns with the right values), and verifier-side reconstruction
verified. Doing this for one chip and measuring is ~1 week of careful
work. Doing all five is a project, not a step.

### Status as of this writing
- Pin restored to `0790eba`. Phase-2 tap-and-pay still PROVES + VERIFIES
  at ~3.85 s on the original baseline.
- All Phase G/H/I exploratory changes reverted.
- Migration remains the right *eventual* move; pursuing it requires a
  dedicated 6–8 week phase with proper instrumentation (per-chip
  constraint-degree audit before refactor, before/after column counts,
  before/after prove times). Not feasible inside this conversation.

---

## Recon refresh — 2026-05-06 (start of dedicated migration phase)

User has committed to the migration regardless of upstream movement.
Re-checked the upstream picture before resuming Phase G.

### Upstream still blocked
- **Stwo HEAD (`e1286720`, Apr 30 2026)**: Poseidon test still
  `#[ignore = "AIRs with constraint degree >= 2 are not supported yet
  in the lifted protocol."]` (`crates/examples/src/poseidon/mod.rs:489,534`).
  The block hasn't moved.
- No PR or branch in flight on the upstream repo addressing degree-≥2
  in the lifted protocol (searched issues + PRs for "constraint degree",
  "lifted", "degree >= 2"; nothing relevant).
- The draft issue at `STWO_UPSTREAM_ISSUE_DRAFT.md` was **not filed**.
  Filing it now wouldn't change the migration scope materially — we'd
  still need the chip rewrites — but it would set up a watch signal
  for the eventual fix.

### Newer release than v2.2.0?
- **No.** v2.2.0 (`289c20de`, tag dated by PR #1376) is still the latest tag.
- 18 commits exist between v2.2.0 and HEAD `e1286720`. Notable ones we
  inherit by pinning to HEAD instead of the v2.2.0 tag:
  - **#1389** `Parallelize fold_circle_into_line`
  - **#1392** `Parallelize fold_circle_evaluation_into_line`
  - **#1393** `Optimize fold_circle_evaluation_into_line with alpha decomposition`
  - **#1390** `Add column slice types and parallel chunk methods`
  - **#1395** `Add Keccak256MerkleChannel for Solidity-friendly Fiat-Shamir`
    (separate channel; doesn't help our degree problem but useful future option)
  - **#1398** `Add SIMD-parallel Keccak-f[1600] permutation primitive`
  - **#1384/#1385** new error types `InvalidLiftingLogSizeError`,
    `InvalidCanonicCosetLogSize` — minor API touch on `FriConfig`/`PcsConfig`
- **#1388** is a *revert* of `FrameworkComponent::is_enabled` (#1308) —
  if any of our chips picked up `is_enabled`, we'll need to drop it.

### Decision
- **Pin target: HEAD `e1286720`** (not the v2.2.0 tag). Captures the
  post-v2.2.0 FRI fold parallelization for free, same blocker either way.
- Issue draft stays unfiled for now. Optionally file once Phase G is
  committed and we can link to a concrete reproducer in our tree.

### Phase G additions vs. the original plan
On top of the original Phase-G items (path renames, `lifting_log_size`,
`set_store_polynomials_coefficients`, `FriConfig::new` 4th arg,
`LOG_N_LANES` import gating):
- Audit any usage of `FrameworkComponent::is_enabled` — if present,
  remove (reverted upstream).
- Watch for `InvalidLiftingLogSizeError` / `InvalidCanonicCosetLogSize`
  on the verifier side; convert wherever we currently wrap raw `String`
  errors from those constructors.

### Phase H findings (2026-05-06)

Confirmed the upstream block applies on the new pin via a small ALU
prove test (`prove_add64`):

- **Library unit tests pass:** 29/29 in `chips::ristretto::*` — the
  pure witness-level math runs unchanged.
- **Any prove path fails with `ConstraintsNotSatisfied`** — every
  `prove` call goes through `CpuChip` (bound = 2), so even the
  smallest 64-bit ADD prover trips the lifted-protocol degree
  restriction. Same failure mode as the prior Phase H attempt at
  v2.2.0; the v2.x→HEAD delta is irrelevant to the block.

New finding vs the original Phase-G plan:
- **`set_store_polynomials_coefficients()` is now MANDATORY**, not
  optional. Without it the prover panics at
  `component_prover.rs:77` with "The polynomial's coefficients are
  not stored" before constraint checking starts. The default
  barycentric-weights path in `prove_values` no longer covers our
  shape at HEAD — a column whose coeffs aren't stored hits
  `get_evaluation_on_domain` directly. Costs some memory but is
  the only supported path.

Phase H complete. Phase I (chip rewrites) is the next step.

---

## Phase I — scope corrected after Blake2bChip audit (2026-05-06)

A constraint-by-constraint degree audit of `Blake2bChip` lives in
`STWO_PHASE_I_BLAKE2B.md`.  Headline:

- **~236 helper columns** for Blake2bChip alone, vs. the original "~50"
  estimate.  Discrepancy is the per-loop multiplier the original
  estimate missed: `add_constraints` has 40 `eval.add_constraint`
  call sites but they sit inside `for i in 0..8` / `for k in 0..16`
  loops emitting ~830–1000 individual algebraic constraints.
- **Realistic effort: 2–3 person-weeks for Blake2bChip** (not "~1 week").
- **Five-chip total likely 10–14 weeks**, not 6–8.
- **Column inflation ~85% for Blake2bChip alone** — plausibly cancels
  or exceeds the v2.x perf cluster's expected 10–30% gain on the
  Blake2b leg.  Whether the migration is net-positive on prove time
  is no longer the conservative bet it appeared to be in the original
  scope.

### Stopping point for this session
Phase G (pin bump + path renames) and Phase H (block confirmed) are
landed.  Phase I audit + helper-column design for Blake2bChip is in
`STWO_PHASE_I_BLAKE2B.md`.  Code changes to chip files are deferred to
a future session with multi-week scope — starting them now risks
witness/constraint-mismatch landmines that pass chip tests while
silently breaking verifier soundness.

### Strategic re-check before continuing
With the corrected scope, the build-vs-wait calculus shifts.  Two
paths the user should weigh before sinking the next 2–3 weeks into
Blake2bChip-1:

1. **Keep building**: chip rewrites in the order from
   `STWO_PHASE_I_BLAKE2B.md`.  10–14 weeks total; final benchmark
   could be neutral or negative on prove time.  Wins regardless on
   "future Stwo upgrades unblocked."
2. **Stay on `0790eba` and pressure upstream**: file the issue draft
   (`STWO_UPSTREAM_ISSUE_DRAFT.md`), check upstream every 2–4 weeks.
   If Stwo lands degree-≥2 in the lifted protocol (no current ETA but
   not architectural — they ignored Poseidon for the same reason),
   the migration drops back to "1 week of path renames".  Worst case:
   we're stuck at 3.85 s a while longer, which is already a real
   shipped milestone.

This is a strategic call for the user, not a technical one.
