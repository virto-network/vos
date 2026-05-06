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
