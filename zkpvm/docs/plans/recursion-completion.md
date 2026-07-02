# zkpvm → completion plan (sessionized)

**Source of truth for the road from "per-child verifier sound" to "shippable."**
Drive it by clearing the session and saying *"continue session N"* — each session
below is self-contained with a START-HERE, a gate, and an estimate. Read the
matching memory ([[project_recursion_completion_plan]]) + [[project_recursion_build]]
for build history.

---

## TL;DR — current state & decisions

**Two products share one verifier.** TRACK A (prove a *light* voucher transition as ONE
STARK segment, verify it directly on-chain) is **DONE + shippable** — measured RAM/prove-time,
and the verify runs on the JAM PVM. TRACK B (fold *many* segments of a long/federation
computation into ONE constant-size aggregate, verified cheaply on-chain) is where the open
question lives.

**Track B, native FRI-STARK recursion is DEAD (measured).** Verifying a base segment is
Θ(n_queries × committed_columns), and the base is WIDE (~15,775 columns), so both the in-AIR
self-verify and the LIFT (verifier-as-guest) approaches blow up: a single join is ~600–750M
instructions (~2000× over one provable segment) plus a ~69 GiB memory wall; K-splitting
diverges. Root cause = the base width under a non-homomorphic (Merkle/FRI) commitment.

**The path forward (choose the aggregation primitive):**
- **SOTA escape = SUM-CHECK / GKR + Jagged PCS** (SP1-Hypercube-style, production+audited) —
  a sum-check verifier is WIDTH-INDEPENDENT, which structurally removes the wall. Cost: a
  multi-quarter BASE re-architecture (FRI → sum-check), M31 + transparency retained.
- **Near-term fallback = Option A (STARK→SNARK pairing wrap)** — AMBER-feasible today
  (lookup-Plonkish per-child wrap + recursive-narrow aggregation + a final Groth16 for the
  O(1) on-chain verify, measured 51.8M cyc on the PVM), but heavy, edge-of-machine, and it
  forfeits post-quantum at the wrap.
- **Rejected: folding** (Nexus, this project's origin, already retreated from it to this exact
  Stwo/M31 stack); **rejected: a narrow app-specific AIR** (the zkVM is general-purpose).

**Two forks gate the choice (product decisions):** (1) is **post-quantum** required? — if so the
pairing wrap is a stopgap and the destination is transparent sum-check. (2) does Track B even need
an aggregation TREE, or does a **streaming prover** (Jolt-style, no recursion, bounded RAM) fit
VOS's refine/accumulate execution model? Both point toward a sum-check/streaming base.

**Usable today regardless:** the general-purpose base prover, per-segment (`verify_standalone`)
and chain (`verify_chain`) verification, and the Track-A on-chain verify path all work. The
detailed session log below records how each conclusion was measured; the in-AIR recursion
machinery that produced them is preserved in tag `voucher-recursion-archive`.

---

## The goal, restated (2026-06-24, after the user's mobile-proving clarification)

Two end-products share ONE verifier but have DIFFERENT proving stories:

- **TRACK A — light circuits proven on constrained hardware.** A *small* program (a
  light voucher state transition = ONE segment, a few-thousand steps) must be
  **provable on relatively constrained hardware — DO NOT assume lots of RAM.** Its
  proof is verified **directly on-chain** (JAM PVM / Substrate). **Recursion is NOT
  involved** — one segment, one proof, verify it. This is a complete product on its
  own.
- **TRACK B — heavy / federation aggregation.** A *large* program spans many segments
  (the capstone = 76). Proving each segment + folding 76→1 stays **server-side**
  (heavy is fine there). The phone only ever **verifies the constant-size aggregate**.

"Mobile/cheap" therefore means two measurable things, and **we have measured
NEITHER**:
1. **prove-light-cheap** — peak RAM to prove ONE light segment (Track A only).
2. **verify-cheap** — proof size + verify cycles/RAM of a single segment proof (both
   tracks) on the real target (JAM PVM).

**Everything to date proved the verifier-AIR is sound + tractable (the recursion
make-or-break). That retired the big TECHNICAL risk, but it did not measure the
GOAL.** The plan front-loads those two measurements, then attacks whichever dimension
they expose.

### Durable constraint (do not regress)
- The leaf prover is `SimdBackend` trace-gen → `for_commit` → **`to_cpu` transplant**
  under `--features poseidon2-channel` (Poseidon2-M31 commit is CpuBackend-only,
  `prove.rs:784`); it forfeits SIMD on the commit. **MEASURED (S1): the transplant
  does NOT meaningfully raise peak RAM — peak RSS matches the Blake2s/SimdBackend path
  to within ~0.5% at every segment size (1.3 GiB light, 5.3 GiB @100k). Its cost is
  ~24× prove TIME (a ~serial scalar commit), not memory.** ⇒ **SimdBackend-Poseidon2
  commit ("P5-perf") is the prove-TIME / phone-feasibility lever for Track A, NOT a
  RAM lever** (the original "doubles peak RAM" premise is refuted — see Session 1
  RESULTS).
- On-chain verify wants the **Poseidon2-M31** stack (M31-algebraic Merkle paths are
  what make in-PVM verify cheap; a Blake2s STARK is not). So a Track-A light proof
  must be Poseidon2, which today means CpuBackend. This couples Track A to P5-perf.
- The per-segment RAM knob already exists: `segment_bounds(total, max_steps)`
  (`segment.rs:41`) + `SEG_STEPS`. Smaller `max_steps` ⇒ smaller per-segment trace ⇒
  less RAM. The capstone OOMs at 500k-step segments (~37 GiB), runs at 100k (~17 GiB)
  — so the knob works; Track A just needs it tuned + measured for a phone budget.

---

## Status snapshot (what's done / open)

| Phase | What | Status |
|---|---|---|
| P0–P3 | verifier-AIR verifies ONE segment in-AIR; log_size ≤ 19 holds | ✅ |
| P4 | fixed-point join (2 *synthetic* children of its own shape) | ✅ |
| P5.0–5.2 | Poseidon2-M31 swap; OODS embed; per-child vs a REAL segment | ✅ |
| P5.3 | per-child verifier + DEEP anchor + **q0-binding (F1/F2 sound)** | ✅ proven |
| **MEASURE** | verify cost (size/cycles/RAM) + light-leaf prove RAM | ✅ **S1 done — see Session 1 RESULTS** |
| Track A | prove a light segment under a mobile RAM cap | ✅ RAM met (~1.3 GiB ≪ 4 GiB); prove **TIME** cut 4× (S2) |
| P5-perf | SimdBackend Poseidon2 prove (whole prove vectorized) + row-parallel merkle leaf hash | ✅ **S2 landed** (`0df715f5`): light prove 20.9s→5.6s. SIMD-packed permute ATTEMPTED+REVERTED (overhead-bound, slower — S2 part 2). Further light-prove speedup ⇒ (c) lighter-than-canonical shape (fewer than 9951 cols) |
| P5.3 width | q0 Layer-2 producer 248 bit-cols → 1 word/row | ✅ **S3 `046607a9`** (main 264→73). But this is NOT the RAM lever — real driver = OODS `coeff` preproc (6112 cols) + DEEP lane (1672); "60→24 via qpos" mis-attributed |
| RAM: coeff | shrink the OODS `coeff` preproc table (the #1 RAM driver) | ✅ **S3b** (LOCAL): `OPS_S 4→1` (embed is merkle-bound at log 17 → free row headroom) ⇒ preproc **6777→1630**, coeff **6112→992 (6.2×)**, main 4400→4228. air_satisfied + q0_tampers GREEN; **`child_full_measure` honest prove+verify now peaks 14.6 GiB (was ~24, OOM'd) — RAM saving ground-truthed, deep-mask prove validated.** Next: DEEP lane (1672) |
| RAM: DEEP lane | shrink the DEEP `lane[418]` scatter-add accumulators | ✅ **S3c** (LOCAL): denom-fold `L[b][qi]`(418)→`S[qi]`(38) — fold `Σ_b denom_inv_b·inc_b` on leaf rows; per-query point LATCHED + bound late at evalfin (latch held ⇒ early==late). main **4228→2784** (−1444). **`measure` 14.6→11.1 GiB.** air_satisfied + q0_tampers GREEN (F1/F2 + new per-slot forgery bite). 3-agent reviewed |
| Priority 2 (d.1/d.3) + P3 | shifted z_b binding, claimed-sum boundary, routing one-hots | ✅ **S4 (LOCAL)**: **d.1** `af8ad37` — each batch-≥1 OODS point `z_b = z_0 + P_δb` (P_δb = `z_b−z_0` = segment-invariant base-field circle point, the mask-offset+periodicity shift); pin latched `z_b` to OODS-bound `z_0` rotated by the const (deg 1). **d.3** `0a4c43e` — pin the DEEP logup `claimed_sum` to the CONSTANT 0 at all 5 feed points (the literal `is_last·cumsum==0` is VACUOUS: `finalize_last` mean-subtracts cumsum_shift ⇒ last coset row always 0); stwo's zero-shift recurrence then rejects any nonzero balance in-AIR; verify-side check retired. **P3** `f2f56d6` — booleanity+partition+gated label-tie on `deep_eis`↔`deep_ebatch` + qsel one-hot self-cert (route/mslot are scalars, excluded). air_satisfied GREEN + q0_tampers (F1/F2/per-slot + new d.1 z_b + P3 ebatch tampers BITE); d.3 tested PROVE-path (`child_full_d3_boundary`, verify⇒Err) since a logup-balance failure aborts the AssertEvaluator LogupAtRow Drop. **d.2 (v↔mix_felts) = LANDED + `child_full_measure` GREEN** (see the d.2 row below). Priority 2 fully closed |
| Priority 2 (d.2) | bind sampled values `v ↔ mix_felts(sampled_values)` | ✅ **S4 d.2 LANDED (LOCAL)**: step (a) plumbing `b1deddc` + steps (b/c/d). `SampledValRelation(5)=[flat_idx,v0..v3]` (base-field limbs) folded into the EXISTING d.3-pinned-0 logup (DEEP∧QPos∧sampled, ONE `finalize_last`, no new component/mix). **Shape (B)** — disjoint slots `N_SV_LOGUP=NLEAF+2=48`→24 cols: CONSUMER = the embed leaf lanes (mult −1, tuple `[leaf_idx, leaf_value]`), PRODUCER = the 2 QM31/RATE-8 absorb-run rows (mult = per-value USE-COUNT). Gating in the MULTIPLICITY (preproc 0 off-region) ⇒ every entry deg 2, leaf/absorbed values read RAW. Self-cert `sv_is_absorb·(1−is_absorb)==0` pins the producer run rows to genuine absorb rows (LOAD-BEARING: forces the channel to bind `absorbed` to the transcript there — else a prover relabels a run row + forges `v`). Run located between OODS-t squeeze[1] and DEEP squeeze[2]; +96 preproc (1631→1727). GATES: `air_satisfied` GREEN (honest combined balance incl. sampled == 0; deg ≤2 validated) + `q0_tampers` GREEN (F1/F2/d.1/P3 still bite) + **`child_full_d2_boundary`** PROVE-path GREEN (q0_tamper 7=producer over-count, 8=dropped consumer leaf ⇒ verify Err; each prove ran full → confirms the +24-col pipeline). **`child_full_measure` GREEN** (honest prove+verify, degree ≤ 2, peak RSS **11.5 GiB** = +0.6 over the S3c ~11.1 baseline, no OOM). Adversarial soundness review clean (no gaps: multiset binding tight, self-cert load-bearing, every recon-used leaf bound). **Priority 2 (d.1/d.2/d.3/P3) fully CLOSED.** |
| P5.4 | join two REAL 31-component children | ✅ **S5a LANDED (LOCAL, `tests/recursion_child_full.rs`)**: the make-or-break — TWO `ChildFullEval` components prove+verify in ONE artifact (`prove_and_verify_two`: one channel, ONE shared preprocessed pool committed once, the 3 relations drawn once post-main, per-component `gen_deep_interaction`, two INDEPENDENT pinned-zero DEEP balances, hand-built verifier tree sizes that avoid the `concat_cols` shared-preproc double-list). **`recursion_two_child_plumbing` GREEN @ log 17, peak RSS 19.9 GiB**; THREE tamper FAMILIES on the 2nd child each reject under joining — main-trace transcript binding, the interaction-tree DEEP logup BALANCE (`trace_q0(5)`), the FRI fold chain (`fri_tamper`) ⇒ the 2nd component's distinct constraint families all bite (the tampered-child negative is self-validating: an unconstrained / mis-mapped 2nd component would make the tamper invisible). Real children via `two_canonical_children` (7-step Add64+Trap `split_at(3)` → 2× `prove_canonical`; both comb-free ⇒ both `C_0`; equal log 17 ⇒ shared preproc). **`recursion_two_child_join_contract` GREEN**: the HOST-side join contract over two REAL DISTINCT children — the 4-bound-field seam (`registers/pc/timestamp/memory_root`; `memory_commitment` excluded as unbound; a per-field reject negative for each), `{C_0,C_1}` allowlist membership (same-program ⇒ C_0==C_1; out-of-allowlist rejected), aggregate-PI inputs (distinct chained entering/exit boundaries + exit io-hash). NO re-pin. Adversarially reviewed (18-agent workflow): the two-component plumbing GREEN is confirmed MEANINGFUL; a HIGH tautological-M4 contract-test defect + over-claiming prose were fixed. **DEFERRED to the next increment:** binding the join contract IN-AIR over the two-component proof (seam/allowlist as constraints, not host checks) needs per-child preprocessed-column namespacing (DISTINCT children can't share the static `preproc_ids()` pool — the contract test feeds distinct children host-only; the plumbing test feeds identical children to the prover); a real distinct-program 2nd allowlist slot; and a memory-writing program to make per-endpoint `memory_root`/io-hash discriminating. |
| P5.5 | tree driver: fold 76 → 1 aggregate + verify_aggregate; re-prove 76 | ❌ |
| P6 | aggregate / single segment verified on JAM PVM; gas/size | ⚠️ **verify EXECUTES on JAM PVM (~1.1M cycles after the transpiler bump `acbeb9b6`), S6 pt1-3**: settle.elf decodes an embedded proof + runs the full Poseidon2-M31 verify. Root cause of the remaining abort = grey-transpiler bug PINPOINTED (`translate_store` Case 1 truncate w/o address_map + no dead-after guard). **UPDATE — S6 FINISH LINE LANDED `2f986e2b`/`bf1a8df1`**: the grey-transpiler `slli rd,x0,n` bug fixed (jar `ec9debbe`, pin bumped off the path-patch); the Poseidon2-M31 settlement verify now **ACCEPTS on JAM PVM (~10.7M cycles, build→link→transpile→EXECUTE→ACCEPT)** ⇒ Track-A light-verify path CLOSED. Remaining P6 = feed a REAL segment / the **aggregate** proof + record final on-chain gas+size (Track B; gated on Session 5) |

---

## Sessions

> Ordering principle: **measure the goal first (cheap, decisive), then build only what
> the numbers demand.** Track A (mobile light proving) is independent of the recursion
> track and can ship first.

### Session 1 — MEASURE THE FINISH LINE  *(no new infra; pure measurement; ~1 session)*
**Goal:** turn the two unmeasured goal-metrics into numbers that decide everything.
**START HERE:**
1. **Verify cost.** Take one real `prove_canonical` segment proof. Run
   `recursion-verifier::verify_segment` and measure: serialized **proof size (bytes)**,
   native **verify wall-time**. Then push it to the **real target**: build
   `recursion-verifier` for `riscv64em-javm` (PVM) — chase the `portable_atomic`/`Arc`
   blocker (the messenger's single-core route; see P4.3 notes) far enough to either
   (a) run it under the JAVM and count cycles, or (b) precisely characterize the
   residual blocker + measure wasm32 as a proxy.
2. **Light-leaf prove RAM.** For a genuinely light program (the `canonical_segment`
   test program, or a ~few-k-step voucher transition) measure **peak RSS** of
   `prove_canonical` under `--features poseidon2-channel` (CpuBackend+to_cpu) AND, as a
   ceiling, the production SimdBackend/Blake2s path. Sweep `SEG_STEPS` to get the
   RAM-vs-segment-size curve.
**GATE / deliverable:** a numbers table — `verify = {bytes, ms, cycles?}`,
`light-leaf prove = {GiB at SEG_STEPS=…}`. Write it into this doc + memory. Decide:
is Track A already under a phone budget (skip Session 2) or not?
**EST:** light. Highest leverage in the whole plan.

### Session 1 — RESULTS  *(2026-06-24)*  ✅
Measured on a 22-core x86_64 desktop (`target-cpu=native`, 62 GiB). Harness =
`zkpvm/verifier/tests/measure_finish_line.rs`: `STEPS=N` proves an N-step Add64 chain
as ONE canonical 31-component segment (so `STEPS` directly knobs single-segment size),
reporting peak `VmHWM`, bincode proof size, and min-of-5 native verify. Re-runnable —
use it to re-measure after P5-perf. Run both with and without `--features
poseidon2-channel`.

**Verify cost** (MOBILE config: blowup 4, 38 queries, pow 20) — flat across segment
size (FRI-config-determined; +~100 KiB from log 14→19):

| stack | proof size (bincode) | native verify |
|---|---|---|
| **Poseidon2-M31** (on-chain target stack) | **~2.9–3.0 MiB** | **~80–88 ms** |
| Blake2s/Simd (production reference) | ~2.9–3.0 MiB | ~35–40 ms |

⚠ the native ms is NOT the on-chain cost: native M31 software hashing is ~2.2× slower
than Blake2s, but **in-PVM** the M31-algebraic path is the cheap one. The real
on-chain CYCLE count needs the PVM run (S6, blocked — see build note).

**Light-leaf prove — peak RAM + time** (Poseidon2-M31 = CpuBackend + to_cpu, the real
Track-A stack):

| steps | max_log | peak RSS | prove @22-core | prove @1-core |
|---|---|---|---|---|
| 7 (canonical floor) | 14 | **1.25 GiB** | 24.2 s | 32.9 s |
| 1 000 | 14 | 1.28 GiB | 23.3 s | 32.2 s |
| 10 000 | 15 | 1.63 GiB | 35.3 s | — |
| 50 000 | 18 | 3.31 GiB | 60.4 s | — |
| 100 000 (= federation seg) | 19 | 5.28 GiB | 107 s | — |

Blake2s/Simd reference RSS is within ~0.5% at every row (1.26 / 5.29 GiB) but proves
~24× faster (1.0 s / 4.0 s). The scalar Poseidon2 commit barely parallelizes (24 s
@22-core → 33 s @1-core) — it is ~serial today.

CAVEAT: the Add64 chain populates CpuChip/memory/register chips and leaves
Ristretto/Blake2b/SMT at their canonical floors (all 31 forced present). A real light
voucher transition additionally populates those → somewhat higher RAM/steps, but the
floor (1.3 GiB) and the verify cost (config-determined) are representative.

**Verify-target build (task 2):**
- `wasm32-unknown-unknown`: **GREEN** (rlib, ~18 s) — Substrate-pallet fallback venue.
- `riscv64em-javm` (PVM): fixed a target-spec schema drift first
  (`target-pointer-width` must be a JSON *string* under nightly-2025-05-09), then
  reaches the KNOWN wall, confirmed current: **`max-atomic-width: 0` ⇒ no
  `core::sync::atomic::*` / `alloc::sync::Arc`**. Blockers: `foldhash` (hashbrown),
  `tracing-core` (+Arc), `lock_api`, `crossbeam-utils` (needs std). Unblock =
  `portable_atomic` routing + gate out tracing/crossbeam (S6). ALSO: the crate's round
  constants are placeholder `1234` — must sync to zkpvm's Grain-LFSR before it can
  verify a real proof (extra S6 prereq for a true cycle count). No PVM cycle number
  this session (best-effort (b): characterized).

**DECISION:**
- **Track A RAM: PASS with margin.** A few-k-step light segment proves at ~1.3 GiB —
  ≪ a 4 GiB phone budget, under even 2 GiB. **Session 2 is NOT needed to hit a RAM
  cap.** RAM only reaches ~5.3 GiB at log 19 (100k = federation/Track-B segment,
  server-side).
- **The to_cpu-doubling premise is REFUTED.** P5-perf is the prove-**TIME** lever, not
  a RAM lever.
- **The real Track-A constraint is prove TIME**: ~33 s single-core for a light segment
  on this desktop ⇒ minutes on a phone; bottleneck = the ~serial scalar Poseidon2
  commit. **Session 2 is re-scoped (below): goal = prove TIME (phone feasibility), core
  task = P5-perf.** Next decisive number = real phone-class prove time + P5-perf's
  speedup.

### Session 2 — TRACK A: MOBILE LIGHT PROVING  *(re-scoped by S1 → prove TIME, not RAM)*
**Goal (re-scoped 2026-06-24 by Session 1):** RAM is already met (~1.3 GiB for a light
segment ≪ 4 GiB). The binding constraint is prove **TIME** — a light Poseidon2-M31
prove is ~33 s single-core here (⇒ minutes on a phone), bottlenecked on the ~serial
scalar Poseidon2 commit. Goal: bring a light light-segment prove to a phone-feasible
time while it still verifies on-chain.
**Original goal (RAM cap) — retained for reference:** a light voucher transition proves
under a stated mobile RAM cap (e.g. ≤ 4 GiB) and still verifies on-chain.
**START HERE (re-ordered by S1 — TIME, not RAM):** (a) **SimdBackend-Poseidon2 commit
(P5-perf)** — THE lever: the scalar commit is ~serial and ~24× the SimdBackend time;
SIMD-vectorising it (and letting it scale across cores) is what brings a light prove
from ~33 s → toward the Blake2s ~1–4 s. (b) measure a real phone-class (or
further-reduced single-core) prove time to set the actual target. (c) only if still
too slow: trim work per light segment (the canonical proof forces all 31 chips —
consider a lighter-than-canonical shape for Track-A single segments, soundness budget
permitting). RAM is already met, so `max_steps`/streaming (the old (a)/(c)) are
deprioritised. Keep n_queries=38 floor.
**GATE:** a light transition proves in a phone-feasible time + `verify_segment` accepts
it + (if PVM ran) the on-chain verify still passes. **Track A ships here.**
**EST:** medium; gated by how far P5-perf must go.

### Session 2 — RESULTS (part 1, P5-perf landed)  *(2026-06-24)*  ✅ commit `0df715f5`
**What landed:** `SimdBackend` now satisfies `BackendForChannel<P2MerkleChannel>` (four
orphan-legal impls in `poseidon2/mod.rs::simd_backend` — `ColumnOps<P2Hash>`,
`MerkleOpsLifted<P2MerkleHasher>`, `GrindOps<Poseidon2M31Channel>`, the marker), so
`ProverBackend` under `poseidon2-channel` flipped `CpuBackend → SimdBackend` and the
WHOLE prove (FRI, quotients, twiddles) re-vectorized; `for_commit` is identity again.
The leaf hash has no SIMD form, so `MerkleOpsLifted::build_leaves` moves columns to CPU
and runs a **row-parallel** reimplementation of stwo's serial `CpuBackend` leaf loop.
Roots are bit-identical (canonical round-trip + verify×5 pass). Added a `ZKPVM_PROFILE`
env gate to surface `prove`'s phase breakdown.

**Measured** (22-core desktop, `STEPS=7` light canonical segment, `--features
poseidon2-channel`; `measure_finish_line`):

| threads | S1 (CpuBackend) | S2 (SimdBackend + parallel leaf) |
|---|---|---|
| cap-10 (default) | — | **5.6 s** |
| 4 | — | 8.3 s |
| 1 (phone proxy) | 33 s (S1 @1-core) | 21 s |

`poseidon2_canonical_segment` round-trip 24.3 s → 5.9 s. Verify (~80–84 ms) + proof
size (~3.0 MiB) + RAM (~1.7 GiB, still ≪ 4 GiB) unchanged. **Phase breakdown** (cap-10):
`main_commit` **59% (3.37 s)** — the 9951-column merkle leaf hash now dominates;
`interaction_commit` 16%, `stark_prove`(FRI) 17%, rest <10%.

**DECISION / where the GOAL stands:** the 4× cut moves Track A from "minutes on a phone"
to single-digit seconds on a desktop; the **1-core (phone single-thread) case is 21 s**.

### Session 2 — RESULTS (part 2, SIMD-packed permute ATTEMPTED → REVERTED)  *(2026-06-24)*  ❌ negative result, not committed
**Hypothesis:** pack 16 leaves per `PackedM31` permute to cut the per-core hash (the
single-thread/phone axis parallelism can't touch). Fully implemented + PROVEN CORRECT:
`permute_generic<F>` (the permutation is already field-generic), a packed `build_leaves`
that hashes each output leaf independently via a telescoped lift index
`g(idx)=((idx>>(out_log−log_c+1))<<1)|(idx&1)` (so all 16 lanes share one absorb/permute
schedule), with a lane-for-lane `packed_permute_matches_scalar` unit test and a
`build_leaves` SIMD-vs-CPU equality test across uniform / mixed-size / final-lift /
sub-pack shapes — all green, roots bit-identical.
**But it was SLOWER**, so reverted: @1-core 21 s → **23.9 s**, @cap-10 5.6 s → **7.0 s**;
`main_commit` 3.37 s → 3.75 s, `interaction_commit` 0.92 s → 1.74 s.
**Why (measured):** scalar = 20.4M permutes @~165 ns; packed = 1.27M permutes @~2950 ns
(~18×). The permute arithmetic was NOT the dominant cost — the **per-column
gather/transpose + buffer churn** (≈10.2M `[BaseField;16]`-gather + `from_array`-reduce +
`Vec` push/drain for the main trace alone) dominates and outweighs the 16×-fewer permutes.
Naive packing is overhead-bound, not permute-bound. To win it would need an efficient
**block transpose** (bulk 16×16 column×leaf load, contiguous, no per-element reduce) —
substantial, uncertain payoff. **Conclusion: don't pursue naive packing.**
**The next lever to evaluate is (c) a LIGHTER-THAN-CANONICAL Track-A shape** (see part 3).

### Session 2 — RESULTS (part 3, (c) natural-shape PROBE)  *(2026-06-24)*  ⚠ informative, needs a real-voucher benchmark
**Key realization:** Track A is verified DIRECTLY on-chain and does NOT recurse, so it does
NOT need the canonical 31-chip shape or the `{C_0,C_1}` allowlist (those exist only so
recursion's verifier-AIR can verify any child). `prove`/`prove_mobile` already use
`active_components` (only the chips the trace touches, at natural sizes); the verifier
reconstructs the same active set via `active_components_verifier`. So **the Track-A path
should be `prove_mobile`, not `prove_canonical`** — S1/S2 measured `prove_canonical` (the
Track-B-representative shape), which OVERSTATES Track A's cost. Added a `SHAPE=natural`
knob to `measure_finish_line` (the natural-shape Track-A proof ROUND-TRIPS / verifies
standalone).

**Measured** (STEPS=7, cap-10, `--features poseidon2-channel`):

| | canonical (Track B) | natural (Track A) |
|---|---|---|
| n_components | 31 | 15 |
| main_cols | 9951 | 4169 |
| proof size | ~3.0 MiB | **~1.19 MiB** (2.5× smaller) |
| verify | ~81 ms | **~35 ms** (2.3× faster) |
| prove | 5.6 s | 12.0 s (FRI 0.99→5.13 s) |

**Natural shape is a clear WIN on the on-chain axis (proof size + verify — the costs that
actually land on-chain), but prove is SLOWER (natural's FRI is ~5× canonical's — unexplained,
an open puzzle; if fixable, natural would be the clean Track-A winner: fast prove + small
proof + fast verify).**

**THE LIGHT-PROVE FLOOR IS STRUCTURAL** (added a `MEM_KIB` knob to settle it). Sweeping
`STEPS` and `MEM_KIB`:
- `MEM_KIB` 4096 → 256 → 64: **no change** to `max_log` (14) or prove time. So the floor is
  NOT the memory (the earlier "memory-dominated" guess was WRONG).
- `STEPS` 7 → 1000: prove ~constant (canonical ~4.7–5.6 s). `STEPS` 100 000: `max_log` jumps
  to 19, prove ~19 s, RSS ~6.5 GiB.
⇒ A light program sits at a **fixed `log 14` floor set by the always-present fixed-size
lookup tables/chips** (range/bitwise/Poseidon2-constant tables), NOT by the program or its
memory. **Shrinking an already-light program does NOT lower prove time** — so "(c) lighter
shape" is a DEAD END for prove TIME (and natural shape is actually *slower* to prove). The
program only drives cost once it *exceeds* the floor (`STEPS≥~100k` → `log≥19`, Track-B
territory). Reducing the light floor below ~5 s would need an **AIR-level change to the
fixed-table sizes** (deep), or accepting it.

**NET (S2 fully explored):** part 1's row-parallel SimdBackend leaf hash is the banked
prove-TIME win (4×) and it lands a light prove **at its structural floor** (~4.7–5.6 s
canonical, cap-10; ~8–12 s phone-class). Three further levers were probed and characterized:
(2) SIMD-packed permute — overhead-bound, slower, reverted; (3a) natural-shape (c) — helps
proof size (2.5×) + verify (2.3×) but prove is slower and capped by the same floor; (3b)
program/memory size — does NOT move the light floor. **For PROVE TIME, the floor is now the
wall; the open levers are deep (shrink the fixed lookup tables) or a security-budget trade
(fewer FRI queries / smaller blowup).** For the ON-CHAIN axis, route Track A through
`prove_mobile` (natural shape, verifies standalone) for the smaller/faster-verify proof now.
A real light-voucher-transition benchmark is still worth building to confirm these numbers
on a representative chip mix (and to chase the natural-FRI-5× puzzle).

### Session 3 — RECURSION WIDTH CUT  *(DONE 2026-06-25, `046607a9`; premise corrected)*
**Original goal:** drop the q0-binding Layer-2 producer from **248 bit-cols → ~38**
(spread the 8-word authentication to 1 word/row with `out[0..8]` latched across 8 rows),
believed to pull `child_full_measure` from ~60 GiB back toward ~24 GiB.

**WHAT LANDED (`046607a9`, LOCAL not pushed):** the QPos Layer-2 producer is restructured
exactly as planned — each query-draw squeeze's `N_QPOS=8` output words are LATCHED across
the trace (the `deep_z`/`deep_alpha` hold idiom; pinned to the live perm output on the
squeeze row via a per-squeeze one-hot) and re-decomposed ONE word per row over an
`NSQ·N_QPOS = 40`-row band in the padding region after evalfin. A band row selects its word
via a `(squeeze,word)` one-hot and binds `rec_all == selected latch` (ungated, degree 2);
canonicity + the position logup (slot 0 live, other 7 zeroed so the interaction tree is
UNCHANGED — `gen_deep_interaction` untouched) + the evalfin consumer are preserved. The band
rides EXISTING padding rows ⇒ **0 rows added, log_size stays 17.** Only proven small-offset
idioms are used: the tempting `carry_lo`-at-fixed-negative-offset trick (0 latch columns) is
UNSAFE because stwo's prover (`offset_bit_reversed_circle_domain_index`) applies large mask
offsets via a half-coset `rem_euclid(half_size)` that diverges from the verifier's full-domain
shift for offsets bigger than ~±2.
**Net: q0 Layer-2 main columns 264 → 73 (−191).** `child_full_air_satisfied` GREEN (46.75s);
`child_full_q0_tampers` (F1 fold-bit, F2 eval-point) still BITE (69.87s). Correct + sound.

**THE PREMISE WAS MIS-ATTRIBUTED — the QPos cut is NOT the RAM lever.** Measuring the TRUE
committed column counts (`child_full_air_satisfied` now prints them; the prior `983` label
undercounted DEEP + q0) at log 17:
- **preproc = 6777 cols**, of which the OODS `coeff` table = `OPS_S·2·WIN·4 = 4·2·191·4 =`
  **6112 cols (90% of preproc, ~54% of ALL committed)** [`WIN = NLEAF 80 + OPS_S·N_OFF 100 +
  N_LATCHED 11 = 191`].
- **main = 4400 cols**, dominated by the DEEP `lane[418]·4 = 1672` (38% of main); QPos is now
  **73** (was 264).
- total committed ≈ **11,200 cols**. The QPos cut removed **191 = 1.7% of committed ≈ ~0.4 GiB
  of LDE** (log 17, blowup 4, 2 MiB/col). The plan's "remove 248 qpos cols → 60→24 GiB"
  (−36 GiB) is **arithmetically impossible from 191 columns** — the "60 GiB" was wrong/stale
  (the test's own `#[ignore]` string says ~20–25 GiB, consistent with ~11,200 cols).
**REAL RAM DRIVERS = the OODS `coeff` preproc table (6112 cols, ~12 GiB LDE) + the DEEP lane
(1672 main, ~3.3 GiB).** The QPos producer was never it.

**RETARGET (next RAM session — own session, deep AIR work): shrink the OODS `coeff` preproc
table.** SCOPED 2026-06-25: it is `OPS_S·2·WIN·4` columns (`prog` in eval, ~L1677-1696; filled
gen_trace ~L3367-3398) encoding, PER EMBED ROW `i`, the linear combination that rebuilds each
OODS-quotient lane from a `WIN=191`-wide value window — **NOT broadcast constants**:
`coeff[win_index(pos)][i] += c` over each OODS record's `rec.terms` (`lay.slot_oa[i][l]` /
`slot_ob[i][l]`). So they vary per row and can't be constant-folded. `WIN = NLEAF 80 +
OPS_S·N_OFF 100 (N_OFF=DR+1=25) + N_LATCHED 11`. Two reduction levers, both deep:
(1) **sparse encoding** — each `rec.terms` is short, so the dense `WIN`-wide coeff vector is mostly
zero; replace it with a logup/sparse `(pos, coeff)` representation instead of `WIN` dense
full-height columns; (2) **shrink `WIN`** (cut `DR`/`NLEAF`/`N_LATCHED` — the per-OODS-record read
window). Second lever overall = the DEEP `lane[418]·4 = 1672` main block. **Start this as a FRESH
session** (it's a real OODS-gadget redesign, far larger than S3). **DEFERRED:** the heavy
`child_full_measure` peak-RSS run (only ~20 GiB free on this box vs ~24–40 GiB needed; expected
QPos delta ~0.4 GiB) — run it to ground-truth the absolute RAM when memory frees.

### Session 3b — OODS `coeff` PREPROC-TABLE REDUCTION  *(DONE 2026-06-25, LOCAL; the S3-RETARGET RAM lever)*
**Goal (from S3 RETARGET):** shrink the OODS `coeff` preproc table (6112 of 6777 preproc M31
cols, the #1 RAM driver, ~12 GiB LDE).

**SCOPE — sparse-encode vs shrink-WIN, decided by measurement (`oods_coeff_sparsity_probe`,
temporary probe, real segment):**
- The coeff grid is **1.23 % dense (81× sparse)**, avg **2.36 terms/recon**, max-pos used 190.
  But raw sparsity does NOT map to a column cut: the AIR reads a FIXED window (mask offsets are
  structural, not data-driven) and selects via preprocessed coeffs, so the committed COLUMN
  count is `2·OPS_S·WIN·4` regardless of per-cell zeros. A "logup/sparse `(pos,coeff)`" gather
  (plan lever 1) has **no clean per-row AIR form** — a weighted gather `Σ c·W[p]` from a
  data-driven `p` needs either a WIN-wide one-hot (= dense again) or a Lasso-style sparse-dense
  sumcheck (not a per-row constraint). Its only AIR-realizable form is **dropping all-zero
  columns** (irregular live-set): the probe shows only **679 of 1528** coeff QM31 columns are
  ever nonzero → floor ~596 used at OPS_S=1. Fiddlier; deferred.
- **The column-reducing lever is shrink-WIN (lever 2), and the dominant knob is `OPS_S`.** The
  slot block of WIN is `2·OPS_S²·N_OFF·4`; since `N_OFF≈DR+1` grows only ~linearly as `OPS_S`
  shrinks (the read-back deepens), the product scales DOWN with smaller `OPS_S`. And the embed
  is **merkle-bound at log 17** (uses ~6251 of 131072 rows) — so spending row headroom by
  lowering `OPS_S` is free of any log-size cost. (OPS_S,T) sweep, dense right-sized coeff M31:
  `OPS_S=4,T=16` → 5536; `OPS_S=2,T=24` → 2384 (dr 33); **`OPS_S=1,T=24` → 992 (dr 66, n_rows
  24114).**

**WHAT LANDED:** the four embed layout consts `OPS_S 4→1, T_PER_MAC 16→24, DR 24→66, NLEAF
80→46` (all derived downstream — eval `prog`/window/recon, gen_trace fill, `preproc_ids` all
scale off the consts; one localized change). **Deep slot reads (offset up to −66) are SOUND by
causality:** `layout_colocate` emits every producer on a row ≤ its consumer (`off = crow −
srow(s) ≤ crow`), so a recon's coeff is **0 wherever a mask read would wrap to an unproduced
row** — the wrap value is always ×0, in BOTH the assert and prove paths. (This is exactly why
the pre-existing −24 slot reads prove cleanly while the S3 `carry_lo`-at-negative-offset trick
did NOT: that trick CONSUMED the wrapped value directly with no coeff to zero it; the
`rem_euclid(half_size)` prover/verifier divergence only bites an un-zeroed wrap read.)

**RESULT (real segment, log 17):**
- **preproc 6777 → 1630 M31 cols** (−5147; the coeff table itself **6112 → 992, 6.2×**).
- **main 4400 → 4228 M31 cols** (−172; the embed leaf/lane main also shrinks with `OPS_S`).
- **≈ 10.4 GiB LDE saved** (5319 cols × ~2 MiB/col @ log17 blowup4). **GROUND-TRUTHED:
  `child_full_measure` honest prove+verify now peaks at 14.6 GiB** (`VmHWM` 14966 MiB), down
  from the pre-reduction ~24 GiB that OOM'd this box — confirms the saving on REAL peak RSS, not
  just column arithmetic, and `child_full_measure` is now runnable here.
- `child_full_air_satisfied` **GREEN** (20.27 s); `child_full_q0_tampers` (F1 fold-bit, F2
  evalfin deep_px) **still BITE** (36.86 s) — the DEEP↔FRI anchor stays load-bearing. Soundness
  unchanged: only the LAYOUT moved (same recons/coeffs/products, pinned preproc); F1/F2 live in
  the separate DEEP/FRI block. **Deep-mask (−66) PROVE path validated end-to-end: the
  `child_full_measure` honest prove+verify SUCCEEDS** (the causality-zeroing holds in the prover,
  as argued). (The measure's 2nd prove — the FRI-fold tamper-reject — was cut off by a 25-min
  wall, not a failure; its FRI logic is untouched by this layout change.)

**FOLLOW-UPS:** (a) irregular live-set drop (992 → ~596) for a further ~0.8 GiB; (b) the DEEP
`lane[418]·4 = 1672` main block (now the largest single block) — the next RAM lever; (c) the
preproc-root change means the W0 `{C_0,C_1}` allowlist must be re-pinned when the real
recursion re-proves (S5b). **DEFERRED still:** the heavy `child_full_measure` peak-RSS run to
ground-truth the absolute RAM (run it now that ~13–14 GiB fits the box).

### Session 3c — DEEP LANE REDUCTION (denom-fold 418→38)  *(DONE 2026-06-25, LOCAL; the 2nd RAM lever)*
**Goal:** shrink the DEEP `lane[418]·4 = 1672` main block (was the largest single block,
~3.3 GiB LDE) — the per-(batch,query) scatter-add accumulators `L[b][qi]`.

**RESULT (real segment, log 17):** `main 4228 → 2784 M31 cols` (−1444: `deep_lane` 1672 →
`deep_s` 152 + 76 latched-point cols; preproc unchanged). **`child_full_measure` honest
prove+verify peaks 11.1 GiB (`VmHWM` 11366 MiB), down from 14.6 GiB** — the ~3 GiB saving
ground-truthed on real RSS (fewer cols shrink the transient/quotient buffers too, beating the
column estimate). `child_full_air_satisfied` GREEN; `child_full_q0_tampers` GREEN — **F1, F2,
AND the new per-slot point-binding forgery (`q0_tamper==3`: forge one query's `px_lat[q]`) each
BITE.** The honest prove succeeding confirms the fold is degree 2 (qsel is a degree-0 preproc
selector ⇒ `qsel·(inc_b·denom_inv_b)` stays degree 2 — the reviewers' degree-3 worry assumed
qsel was degree 1; no pre-witness needed). Built in two gated steps: (1) additive latched-point
+ per-slot binding (validated the bind-late mechanism, main 4228→4304), (2) the fold + lane
removal (main 4304→2784). (As in S3b, `measure`'s 2nd prove — the FRI-fold tamper-reject — hit
the 25-min wall; not a failure, the honest prove is the result and `q0_tampers` F1 covers the FRI
fold-bit tamper at the assert level.) **Cumulative with S3b: the full per-child verifier `measure`
is now ~11.1 GiB (was ~24 GiB pre-S3b).** Design 3-agent-reviewed before building (the per-slot
binding was the make-or-break the review caught).

**WHY IT'S NOT AN S3b-STYLE TWEAK (scoped 2026-06-25):** the lanes are a running accumulator
held from the first merkle leaf row to the evalfin at the end, i.e. they **span the merkle
binding region** — there is NO free row-headroom (the opposite of the coeff embed), and every
(b,qi) is live (every query hits batch 0 + its extra batches). So the only lever is a
**structural redesign of the accumulation**, in the F1/F2-critical DEEP↔FRI region.

**DESIGN — denom-fold (drop the ×NB batch dimension at accumulation):**
`eval[qi] = Σ_b denom_inv[b][qi]·(L[b][qi] − py·A[b] − B[b])`
`        = [ Σ_{rows r serving qi} Σ_b denom_inv[b][qi]·inc_b(r) ] − Σ_b denom_inv[b][qi]·(py·A[b]+B[b])`
`        = S[qi] − const[qi]`.
Accumulate **one** lane `S[qi]` per query (NB×fewer: 418→38) by folding `Σ_b denom_inv[b][qi]·inc_b`
on each leaf row instead of carrying NB separate sums. `const[qi]` stays at the evalfin row (as
now). `S[qi]_next = qsel_qi·(Σ_b denom_inv[b][qi]·inc_b) + lane_cont·S[qi]_prev` — degree 2
(qsel preproc × [denom_inv main × inc_b main]).

**THE OBSTACLE + RESOLUTION (the make-or-break):** folding needs `denom_inv[b][qi]` (hence the
query point `p_qi`) DURING the leaf accumulation, but `p_qi`'s soundness binding to
`query_positions[qi]` completes at the merkle CLIMB (later) — a forward reference; and the
points are indexed by SORTED query order (`deep_qi`) while the FS draws are an unordered set, so
there is no clean early binding either. **Resolution: latch the point, bind it late.** Witness
`(px_qi, py_qi)` per sorted-query as LATCHED columns (held constant, `not_last`); use them in the
leaf-row fold (early); BIND them at the evalfin row (after the climb) to the climb-derived point
via the existing F2 pos-chain. Held-constant ⇒ the value used early == the value verified late,
so a wrong fold point is rejected. F1 unchanged; F2 becomes `latched p_qi == climb-derived`.

**COLUMN ACCOUNTING:** −418 lanes (1672 M31) + 38 `S[qi]` (152 M31) + 76 latched-point BaseField
cols (`px_qi,py_qi` × 38); the NB denom witnesses (`deep_dre/dim/dire/diim`, 44 cols) and the
pos-chain are REUSED (now also nonzero on leaf rows, no new cols). Net ≈ **−1444 M31 ≈ −2.9 GiB**
⇒ `child_full_measure` 14.6 → ~11.7 GiB. The DEEP logup / `gen_deep_interaction` is UNTOUCHED
(the lanes are pure main accumulators read only at evalfin).

**GATE:** `child_full_air_satisfied` GREEN + `child_full_q0_tampers` (F1/F2) still BITE +
`child_full_measure` peak RSS. **RISK:** F2 re-points to the latch; the leaf-row `deep_px/deep_py`
now carry the leaf's qi point (was qi_p slot-0) — must not break F1's fold-parity binding.

**REVIEW CORRECTIONS (3 independent agents, 2026-06-25 — fold these in BEFORE building):**
1. **CRITICAL — per-slot late binding, not single `qi_p`.** The fold scatters lane `qi = f.deep_qi`
   (≠ the row's `qi_p`), so ALL 38 latched points must each be pinned at THEIR evalfin row via a
   one-hot: `Σ_qi efsel[qi]·(px_lat[qi] − derived_for_qi) == 0` (mirror `deep_eval_lat`). Binding
   only `qi_p` leaves 37/38 points free ⇒ a prover forges `denom_inv`+`eval[qi]` for all but one
   query. This is the make-or-break.
2. **F1 IS untouched (confirmed): trace-leaf consumer rows (`deep_valid`, set only in `mk_resolve`)
   are DISJOINT from FRI-fold rows (`deep_fl_qi`, only in `fri_resolve`).** BUT F2's `deep_px==derived`
   pin AND the denom constraints are UNGATED (every row) — so on consumer rows `deep_posbit/poschain`
   AND `deep_dre/dim/dire/diim` must be repointed to the leaf's qi IN LOCKSTEP (the fill already does
   `derive_pos_point`/`deep_denom_cm31` per-row, so this is mechanical; silent-break if posbit is left
   at the slot-0 default). So "only F2 repointed" is right for F1 but the repoint is per-row, not just
   at evalfin.
3. **Degree:** `qsel·(Σ_b denom_inv[b]·inc_b)` is degree 3 unless `denom_inv·inc_b` is pre-witnessed
   into a column per batch — add that intermediate witness to keep the fold degree 2.
4. **`const[qi]` must read the SAME latched `py[qi]`** the fold used (else the `py·A[b]` factoring is
   inconsistent).
5. **Add a consumer-row `deep_px` tamper** to `child_full_q0_tampers` — the current F2 test only probes
   the evalfin row and would NOT catch a wrong-point fold on a leaf row.
Consensus: denom-fold is the right (and minimal) structural change; reorder→11 was REJECTED (shatters
the merkle sponge→climb `hash_link`/`cap_fwd` chain). Implementation note: a clean way to satisfy 1+2 is
to set consumer-row `deep_px/deep_py = Σ_q qsel_q·px_lat[q]` (a new ungated read-constraint), so F2's
per-row pin transitively forces the consumer posbit to match the (evalfin-bound) latch.

### Session 4 — RECURSION SOUNDNESS FINISH  *(Priority 2/3; ~1–2 sessions)*
**Goal:** close the last DEEP-anchor gaps on the slimmer post-S3 AIR. From
`recursion-c-hardening.md`: (d.1) batch-≥1 `z_b = oods·g^δ_b` derived in-AIR; (d.2)
`v ↔ mix_felts(sampled_values)` (the heavy one — may be its own session); (d.3) in-AIR
`is_last·last_cumsum == 0` claimed_sum boundary; Priority 3 `is_query_draw·(1−is_squeeze)`
self-cert + F3 selector self-cert.
**GATE:** each via `child_full_air_satisfied` then `child_full_measure`; new negative
tests bite. Per-child verifier is then FULLY sound.
**EST:** d.1+d.3+P3 = one session; d.2 likely its own.

#### S4 — d.1 / d.3 / P3 LANDED  *(2026-06-25, voucher-state-transition, LOCAL — 3 commits)*  ✅
6-agent map+adversarial-review workflow first (`wcmbv0ehr`), then implemented + gated each in order.
- **d.1 (`af8ad37`) — shifted z_b binding (degree 1).** Each batch-≥1 OODS sample point is
  `z_b = z_0 + P_δb`, where `P_δb = z_b − z_0` is a SEGMENT-INVARIANT BASE-FIELD circle point
  (stwo `constraint-framework/component.rs:225-229`: mask points = `oods + trace_step·offset`,
  base-field; plus the FRI periodicity shift, also base-field). Pin the latched `z_b` to the
  OODS-bound `z_0` rotated by the constant `(a_b,b_b)`: `z_b.x = z0.x·a_b − z0.y·b_b`,
  `z_b.y = z0.x·b_b + z0.y·a_b` (QM31·M31). `deep_rot` passed via the component (like cx/cy/
  pos_consts), host-derived from the honest batch points + asserted base-field. `q0_tamper==4`
  perturbs a derived z_1 ⇒ rotation pin bites.
- **d.3 (`0a4c43e`) — self-certifying claimed-sum boundary.** THE PLAN'S LITERAL `is_last·
  last_cumsum==0` IS VACUOUS: stwo's `finalize_last` (prover/logup.rs:129-133) subtracts
  `cumsum_shift = claimed_sum/n` from every entry BEFORE the inclusive prefix sum, so the last
  coset row of the cumsum column is identically 0 for ANY claimed_sum — a boundary read certifies
  nothing. The REAL self-cert = **PIN the component logup `claimed_sum` to the constant 0** (was
  the prover-reported `deep_claimed`) at all 5 feed points (prove component, both channel mixes,
  both assert-path args). stwo's last-batch recurrence uses `cumsum_shift = claimed_sum/n`; pinned
  to 0 it's the genuine running sum over the `[-1,0]` wrap ⇒ any nonzero balance fails the
  recurrence at OODS ⇒ verify Err. Verify-side `deep_claimed != 0` check RETIRED. **GOTCHA (cost me
  a gate run): a logup-balance tamper CANNOT be tested on the ASSERT path** — when the logup
  recurrence constraint fails INSIDE `finalize_logup_in_pairs`, the `LogupAtRow` is non-finalized,
  its `Drop` double-panics ("LogupAtRow was not finalized") → SIGABRT, which `catch_unwind` cannot
  catch. (Tampers 1–4/P3 are fine: they fail constraints BEFORE any `add_to_relation`, so the
  LogupAtRow is still `dummy()`/finalized.) ⇒ d.3's tamper (`q0_tamper==5`, inflate producer
  entry-0 mult in BOTH `deep_mslot[0]` AND `deep_logup.num[0]`) is tested on the PROVE path:
  new `child_full_d3_boundary` asserts `prove_and_verify(trace_q0(5)).is_err()` (verify cleanly
  rejects — no LogupAtRow). Removed the host `assert_eq!` fail-fast from `prove_and_verify` so the
  prove path demonstrates the IN-AIR rejection (verify Err), not a host panic; honest balance==0
  asserted in `child_full_air_satisfied`.
- **P3 (`f2f56d6`) — routing one-hot self-cert (defense-in-depth, deg ≤ 2).** Booleanity +
  at-most-one partition + GATED label-tie pinning `deep_eis[e]`↔`deep_ebatch[e]`; `valid_e =
  Σ_b eis[e][b]` is data-dependent (0 on absent/producer rows, 1 on a live consumer) so the
  label-tie is vacuous when 0. `qsel` gets booleanity+partition. `route`/`mslot` are SCALAR value
  columns (NOT one-hots) ⇒ excluded (the prompt's "do the same for route/mslot" was a
  mis-spec). Preproc cols ⇒ tautological on honest preproc; meaningful only against a malicious
  preproc (the W0 `{C_0,C_1}` allowlist already pins it). `q0_tamper==6` corrupts a LIVE entry's
  `deep_ebatch` LABEL (NOT the `eis` one-hot — else the pre-existing `incx` pin bites first); the
  P3 label-tie, declared BEFORE the leaf↔c logup, bites first.
- **GATE per step:** `child_full_air_satisfied` GREEN + the new tamper rejected + `child_full_q0_tampers`
  (F1/F2/per-slot + d.1 + P3 all bite). d.3 added `child_full_d3_boundary` (PROVE path). **Still
  pending: `child_full_measure` (degree gate + peak RSS) — run after d.2.**

#### S4 d.2 — bind sampled values to `mix_felts(sampled_values)`  *(LANDED 2026-06-26, LOCAL)*  ✅
**AS-BUILT (delta vs the DESIGN below):** implemented exactly as designed via **shape (B)** — disjoint
logup slots `N_SV_LOGUP = NLEAF + N_SV_PROD = 48` (→24 paired interaction cols), NOT shared
value-pin columns. Consumer slots `0..NLEAF` read the existing embed `leaves` limbs directly
(one entry/lane, mult −1); producer slots `NLEAF..48` read the existing channel `absorbed[0..4]`/
`[4..8]` directly (mult = preproc use-count). **Zero new MAIN columns** — only the ±mult/flat
preproc (1631→1727, +96) + one self-cert. Gating is in the MULTIPLICITY (preproc 0 off-region) so
every entry is degree 2 with the values read RAW (no `is_*·value` tuple terms that would hit deg 3).
The region is located at trace-build time between squeeze[1] (OODS get_random_point) and squeeze[2]
(DEEP random_coeff); odd-tail/unreferenced sampled values ride at mult 0 (balance-neutral). Self-cert
`sv_is_absorb·(1−is_absorb)==0` pins the producer run rows to genuine `is_absorb` channel rows so
`absorbed` is transcript-bound there. Folded into `gen_deep_interaction` (one `LogupTraceGenerator`,
one `finalize_last`) → rides the existing d.3 pinned-zero claimed_sum; no new component/draw-mix.
Drawn `deep → qpos → sampled` on both prover + verifier channels. New `child_full_d2_boundary`
(prove-path, `q0_tamper` 7/8). The original mapped design follows verbatim.

#### S4 d.2 DESIGN — bind sampled values to `mix_felts(sampled_values)`  *(scoped 2026-06-25, 2 agents)*
**Why:** the embed "leaves" = the OODS sampled values `v`, read RAW in the recon window but
currently **host-provided/unbound** — a prover can supply any `v`. Bind them to the transcript's
`mix_felts(sampled_values.flatten_cols())` absorb (~8500 of the 8584 transcript perms; already
replayed in the channel block, so the absorbed values live in the existing `absorbed[0..8]` cols).
**Mechanism — a logup, mirroring the DEEP leaf↔c logup** (NOT the cs-chunk one-hot approach — that
needs ~8500 indicators; doesn't scale):
- **Relation** `SampledValRelation(1 + SECURE_EXTENSION_DEGREE = 5)`: tuple `[flat_idx, v0..v3]`.
  `flat_idx` = position in `sampled_values.flatten_cols()` (tree-major → col → offset; deterministic).
- **Producer** = the sampled-values absorb rows. Each RATE-8 Absorb row carries 2 QM31 values:
  emit `(+mult_k, [2k, absorbed[0..4]])` and `(+mult_{k+1}, [2k+1, absorbed[4..8]])`. `mult` = the
  per-value USE-COUNT (how many embed leaves read that value) — a PREPROCESSED multiplicity (the use
  count varies per value, unlike the DEEP producer's fixed +N_QUERIES). Region selector
  `is_sv_absorb` (preproc) gates the producer; the base flat index per row is preproc. **Locate the
  region by scanning `records[prefix_len..]` for the FIRST `mix_felts` Absorb run** (it sits between
  the OODS `get_random_point` squeeze and the DEEP `random_coeff` squeeze; NOT prefix-relative like
  `cs_chunk_row`).
- **Consumer** = the embed leaf rows. Each valid leaf lane emits `(−1, [flat_idx_of_leaf, leaf_value])`.
- **Balance:** `claimed_sum == 0` (pinned, like `deep_claimed`) ⇒ {leaf values} ⊆ {absorbed values}
  at matching indices ⇒ the recon's `v` ARE the transcript-absorbed sampled values.
**THE BLOCKER (plumbing):** each leaf's `flat_idx` is computed in `oods_auto.rs::StreamBackend::next_mask`
(~L1366-1378, the `(tree,interaction,col,offset)` coordinate) then DISCARDED — `StreamNode::Mask`
(~L1251) + `WOp2::Leaf` (~L1687) are unit variants. Must plumb the flat index through, ADDITIVELY
(parallel `Vec`s, NO enum-signature changes — `recursion_common` is SHARED by oods_auto_*/recursion_*
tests, must not break them): `node_idx` in StreamBackend (set in next_mask) → `w_idx` in
TwoStreamBuilder (set in `reconstruct` when emitting a Leaf) → `leaf_idx[row][lane]` in
`layout_colocate` (parallel to `leaf_val`). The test then tags the consumer logup with `leaf_idx`.
**IMPL ORDER:** (1) plumb the index additively + build-check ALL recursion tests compile (the
shared-file risk); (2) producer (region scan + base-idx/mult preproc + emit) + consumer (leaf
logup) + a `gen_sampled_interaction` (mirror `gen_deep_interaction`) + relation draw + `mix_felts(claimed)`
+ commit; (3) preproc cols. **GATE:** `child_full_air_satisfied` + `q0_tampers` (F1/F2 bite) + a NEW
tamper (perturb a leaf / sampled value ⇒ rejected). Keep deg ≤ 2; EF·F not F·EF. **Build the use-count
multiplicity from the capture** (count leaf references per flat_idx). Watch: a sampled value read by
ZERO leaves still appears in the absorb (mult 0 producer entry — fine) — the logup binds the USED
subset; that's the soundness-relevant set (A/B only touch used values).

### Session 5 — REAL 2-CHILD JOIN + AGGREGATE  *(P5.4 + P5.5; LIKELY SPLITS 5a/5b)*
**5a — real join (P5.4):** the per-child verifier verifies TWO REAL 31-component
children of its own shape + the SegmentState seam + the {C_0,C_1} allowlist. First
real recursion step. GATE: proves+verifies; broken seam / out-of-allowlist rejected.
**5b — aggregate (P5.5):** tree driver folds 76 segments → 1 aggregate; `verify_aggregate`
≡ `verify_chain_standalone_allowlist` + io-binding. Requires re-proving all 76 segments
under Poseidon2-M31 + re-pinning {C_0,C_1} (the federation re-prove — needs S3's width
cut to be affordable). GATE: the full 76→1 aggregate proves once + verifies; the
aggregate's public inputs match the chain's.
**EST:** the fat one; plan 2 sessions.

#### Session 5a START-HERE  *(scoped 2026-06-26 — 6-agent workflow `w8q1s1py7`; anchors are guidance, re-verify line numbers at execution)*

#### Session 5a (P5.4) START-HERE — the first REAL recursion node: two real children + seam + allowlist

**Branch:** `voucher-state-transition` · **feature:** `--features poseidon2-channel` · **repo root:** `/home/daniel/src/virto/vos/zkpvm`

**One-line goal:** Prove+verify ONE artifact that fully verifies TWO REAL 31-component canonical segments, binds the seam (`child0.final == child1.initial`) and the `{C_0,C_1}` allowlist over each child's transcript-bound commitment. GATE: honest accepts; broken seam OR out-of-allowlist child rejects.

---

##### 1. Architecture decision — TWO `ChildFullEval` components in ONE proof (NOT a new 2-child AIR)

**Recommend: instantiate `ChildFullEval` (`tests/recursion_child_full.rs:1647`) TWICE as two `FrameworkComponent`s in one proof — `prove(&[&c0, &c1], …)` / `verify(&[&c0, &c1], …)` — with the seam, allowlist, and aggregate public inputs bound as a HOST check over the two children's AIR-bound `BoundaryAir` public-input surface (plus a cheap in-AIR per-child allowlist-membership constraint).**

Justification, from the maps:
- **The prove/verify API already takes a slice** (`recursion_child_full.rs:4985` `prove(&[&component], …)`, `:5006` `verify(&[&component as &dyn Component], …)`). Stwo natively supports N components per proof. This is the *minimal* real change: `ChildFullEval`'s ~3500-line `evaluate` body (`:1688`) is **reused verbatim**, instantiated twice — no rewrite.
- **Each child's `BoundaryAir` is ALREADY an AIR-enforced public-input surface.** The step-4b recompute (`:2143-2201`) constrains `recompute(init_regs, final_regs, pc, ts, init_root, final_root) == transcript-bound claimed_sums` (`:2175/2185/2196/2201`). So a host check over `proof.{initial,final}_state` is a check over *genuinely verified* quantities — strictly stronger than P4's synthetic in-AIR seam (which equates `build_seam()` constants tied to no real proof, `fixed_point_join.rs:424-437`).
- **The alternative (a new single interleaved 2-child AIR, P4 `JoinEval` style)** requires re-parameterizing `ChildFullEval::evaluate` over a per-child column offset and laying both children + their Merkle/FRI/DEEP regions on one grid with per-child `is_child_start`/`chain_ok` anchors (`fixed_point_join.rs:316-326`). That is the ONLY way to get a true *in-AIR cross-child seam constraint* (stwo constraints are per-component; you cannot constrain across two separate components). It is a substantially larger lift and is **the shape-closure / fixed-point step, not 5a** (see §7). 5a's GATE only requires accept/reject behavior, which the two-component + host-binding path delivers.

**Minimal real change vs P4's synthetic join:** keep P4's *breadth contract* (two children, seam equality, allowlist membership, aggregate PI) but (a) children become two real `prove_canonical` segments, (b) seam/allowlist bind to the children's transcript-bound `BoundaryAir`/`root_lat` instead of `build_seam()`/`commitments[1]` placeholders, (c) the verifier is run as two real `ChildFullEval` components, not one synthetic `JoinEval`.

---

##### 2. The seam binding — host check over two AIR-bound `BoundaryAir`s

**Fields to equate (the 4 BOUND fields only):** `registers[13]`, `pc`, `timestamp`, `memory_root[32]`. **NOT** `memory_commitment` — it is unbound/vestigial (`src/proof.rs:137`); the in-AIR/host-over-bound-inputs seam is sound on the 4 bound fields, where `memory_root` carries RAM continuity. (Host `verify_chain` at `src/verify.rs:44` compares full-struct incl. `memory_commitment`; equating only the 4 bound fields is the correct trustless subset.)

**Where:** HOST check over the two verified children's public inputs —
```
assert child0.final_state.{registers,pc,timestamp,memory_root}
    == child1.initial_state.{registers,pc,timestamp,memory_root}
```
mirroring `verifier/src/lib.rs:507-514`. The surface is `Proof.{initial,final}_state` (`src/proof.rs:175,177`), exposed in each child as `BoundaryAir` (`recursion_child_full.rs:1586`), populated at `:4620-4634`, and pinned to that child's claimed_sums by the in-AIR recompute (`:2175/2185/2196/2201`). Because each side of the equality is AIR-bound to its own child's STARK, a broken seam means at least one child's real boundary differs from the asserted value → the host equality fails (and if you instead tried to force a single shared constant into both evals, one child's recompute≠claimed_sum → its `verify` fails). This is exactly the soundness `state_tamper` already exercises single-child (`:5608-5616`).

*(Optional in-AIR upgrade, deferrable to the interleaved-AIR step:* a true cross-child seam constraint requires the single-component layout of §1's rejected alternative — out of 5a scope.)*

---

##### 3. Allowlist enforcement + the re-pin question

**RE-PIN: NO — do not re-pin `{C_0,C_1}` before 5a.** From Map 4 §3: `{C_0,C_1}` pin the **verified SEGMENT's** commitment = `commitments[0]` of a real `prove_canonical` voucher-check segment (preprocessed-tree root = program identity, `src/program_id.rs:54`). The d.1/d.2/d.3/P3 preproc growth (1631→1727 cols) is in the **verifier AIR** (`recursion_child_full.rs`), whose own preproc root is pinned by the *outer* allowlist (a P5.5 concern), **distinct** from `{C_0,C_1}`. The verified segment's chips are untouched. No re-pin. (The baked M31 `{C_0,C_1}` live in the *vos tree* `prover/src/lib.rs:504-519`, not here — see §4 for deriving them at test time.)

**Enforcement:** Each child's `commitments[0]` is already latched + transcript-bound in-AIR via `root_lat`/`rl[0]` (`recursion_child_full.rs:2211-2222`: `is_root_absorb[t]·(absorbed[j]−rl[j][0])` and `is_root_t[t]·(dc_root[j]−rl[j][0])`, for `t=0` = preprocessed root). Two enforcement options:
- **Start HOST** (cheapest): `assert proof.stark_proof.commitments[0] ∈ {C_0,C_1}` per child, mirroring `verifier/src/lib.rs:517-525`.
- **Lift IN-AIR per child** (recommended, cheap — `rl[0]` is already in-AIR): add the `JoinEval` membership idiom (`fixed_point_join.rs:352-361`) right after the root-latch block: `rl[0][j][0] == sel·C1[j] + (1−sel)·C0[j]`, `sel` boolean. This is a *per-child* constraint (fits inside `ChildFullEval` or a thin wrapper), no cross-child coupling — and makes the allowlist self-certifying, matching the d.1/d.2/d.3/P3 self-cert direction. Point it at `commitments[0]` (preprocessed), **not** P4's `commitments[1]` main-root placeholder (`fixed_point_join.rs:699`).

---

##### 4. Real children — the cheapest chaining pair

**Reuse `prove_two_segment_chain` (`tests/chain_standalone.rs:28-82`) with `prove()` → `prove_canonical()`.** It already takes the 7-step Add64+Trap program, `split_at(3)` into `[0..3)`/`[3..7)`, and produces two SideNotes whose boundary states chain (`:79-80` asserts `proof1.final_state == proof2.initial_state`). The step-slicing produces genuine chaining boundary states for free.

Recipe (`two_canonical_children()`):
1. Copy `chain_standalone.rs:28-82`, swap both `prove(&mut snX)` → `prove_canonical(&mut snX, &[])` (`src/prove.rs:573`).
2. Assert `p0.final_state == p1.initial_state` (chains by construction).
3. Both halves are comb-free (Add64 only, no Ristretto) → **both have `commitments[0] == C_0`**. Derive `C_0 = commitment_bytes(p0.stark_proof.commitments[0])` (`src/recursion_pcs.rs:56`) at test time; set the test allowlist `{C_0, C_1_dummy}`. This is the cheapest chaining pair: two identical-shape canonical segments → identical verifier `log_size` → **shared preprocessed pool, no namespacing** (critical for §1's two-component plumbing).

*Exercising `C_1` (the comb shape) requires a Ristretto-op segment — much heavier; defer to a follow-up. Both-`C_0` is sufficient to gate "in-allowlist accepts, out-of-allowlist rejects".*

---

##### 5. Ordered edit list + IMPL ORDER (build-checkable steps)

New file: **`tests/recursion_two_child.rs`** (model on `recursion_child_full.rs`'s harness). Reuse `canonical_segment` shape, `build_inputs()` (`:4525`), `ChildInputs` (`:4503`), `ChildFullEval` (`:1647`), `preproc_ids()` (`:646`), `prove_and_verify` (`:4919`).

| # | Step | Anchor | Build-check |
|---|---|---|---|
| **M0** | `two_canonical_children()` — copy `chain_standalone.rs:28-82`, `prove()`→`prove_canonical()`; assert chain + both `commitments[0]==C_0` | `chain_standalone.rs:28`, `src/prove.rs:573` | compiles; chain asserts pass |
| **M0b** | Build two `ChildInputs` via `build_inputs()` twice; **assert `ci0.log_size == ci1.log_size`** (shared-preproc precondition) | `recursion_child_full.rs:4525`, `:4716` | assert holds → green-light two-component path |
| **M1 (MAKE-OR-BREAK)** | Generalize `prove_and_verify` (`:4919`) to TWO components: ONE channel, ONE `TraceLocationAllocator::new_with_preprocessed_columns(&preproc_ids())`, draw the 3 relations ONCE post-main (`:4938-4940`), gen DEEP/QPos/sampled interaction for BOTH (`gen_deep_interaction` `:4835` called twice), build `c0,c1: FrameworkComponent<ChildFullEval>`, `prove(&[&c0,&c1], …)`, `verify(&[&c0,&c1], …)` | `:4927-5008`, `:4985`, `:5006` | **two real children prove+verify, no seam/allowlist yet** |
| **M2** | Host seam check (the 4 bound fields) | mirror `verifier/src/lib.rs:507` | accepts honest pair |
| **M3** | Allowlist: host `commitments[0] ∈ {C_0,C_1}` per child; THEN lift in-AIR membership at `rl[0]` (`:2211-2222`) using `fixed_point_join.rs:352-361` idiom | `verifier/src/lib.rs:517`, `fixed_point_join.rs:352` | accepts; tamper rejects |
| **M4** | Aggregate PI: assert `left.initial_state.memory_root == expected_initial_root`, `right.final_state.memory_root == final_memory_root`, `right.registers[9..13] == io_hash` (`Proof::public_io_hash` `src/proof.rs:216`) | `fixed_point_join.rs:387-402` | bound |
| **M5** | `recursion_two_child_gate` + negatives (§6) | mirror `child_full_gate` `:5535` | GATE green |

**Land order:** M0 → M0b → **M1** (everything hinges here) → M2/M3/M4 (incremental, independent) → M5.

---

##### 6. The GATE — `recursion_two_child_gate` (mirror `child_full_gate:5535`)

**Positive:** two real chaining canonical children (M0) → two `ChildFullEval` components → `prove(&[&c0,&c1])` → `verify` returns `Ok`; host seam passes; each `commitments[0] ∈ {C_0,C_1}`; aggregate PI bound. `assert ok`.

**Negative — broken seam:** feed two NON-chaining real segments (e.g. seg0 from program A + seg1 from program B, or skip the middle segment of a 3-cut). Host seam `child0.final != child1.initial` → `Err` (and if forced shared-constant, one child's `verify` fails). `assert is_err()`. (Mirrors `state_tamper` `:5608`.)

**Negative — out-of-allowlist child:** tamper a child's `rl[0]`/`commitments[0]` so it ∉ `{C_0,C_1}` (or set allowlist that excludes it) → in-AIR membership constraint fails (or host check rejects). `assert is_err()`. (Mirrors `root_tamper` at `:3232`.)

*(Optional, mirror `child_full_gate`'s 10-bool tamper vector: also re-run one base child-proof tamper to confirm the depth body still rejects under two-component proving.)*

**Measure** (per the P5.4 plan `docs/plans/recursion-p5.md:1339-1351`): record the 2-component `log_size`, prove-time, peak RSS in the gate output.

---

##### 7. RISKS / open questions — resolve EARLY

1. **Shape closure is NOT in 5a (scope guard).** The two-component output proof is **not** the same shape as a child (a child is one 31-component segment; the output is a 2×verifier-component artifact). 5a does NOT close the recursion fixed point — `recursion-design.md:206-208` leaves the single-uniform-join-AIR vs lift-AIR decision open. Do not let "make it re-verifiable as a child" creep into 5a; that is the later interleaved-AIR step. State this in the gate header.
2. **Shared-preproc requires equal child `log_size` (M0b is the gate).** Two canonical segments of the SAME program share `log_size` and preprocessed columns → no `preproc_ids()` namespace collision (`recursion_child_full.rs:646`, the collision risk Map 1 §D flags). If M0b's assert fails (children differ in size), you'd need per-child namespaced preproc IDs — a real lift. Mitigation: both children comb-free, same program (§4). **Verify M0b before writing M1.**
3. **Two claimed-sum balances + pinned-zero DEEP (d.3).** Each component carries its own `claimed_sums` balancing to 0 and its own pinned-zero `cumsum_shift` logup (`:4983`). M1 must gen the DEEP/QPos/sampled interaction for BOTH components and commit one interaction tree covering both. Risk the per-component pinned-zero balance needs the interaction laid out per-component — confirm `gen_deep_interaction` (`:4835`) composes for two. If not, this is the most likely M1 surgery point.
4. **Memory is the binding constraint.** The gate runs THREE heavy proves: 2× `prove_canonical` (the children, each a full 31-component STARK) + 1× the 2-component verifier prove (~2× single-child width → `log ~18`, projected ~20-25 GiB vs single-child ~11.5 GiB at `:5671`). Keep children tiny (7-step Add64, `split_at(3)`). Run the gate `--test-threads=1`, own process, BIG STACK (canonical/2-child verify needs it — W0 memo). Add a `SEG`-style env knob if RSS bites.
5. **`{C_0,C_1}` derivation at test time** (no re-pin, §3): derive `C_0` from a real segment's `commitments[0]` via `commitment_bytes` (`recursion_pcs.rs:56`); don't hardcode the vos-tree baked M31 literals. `C_1` can be a distinct dummy for the allowlist's second slot.

---

##### 8. Estimate + split

**One session if M1 plumbing "just works"** (the slice API is already there); **spills to a second session** only if Risk #3 (two-component interaction/balance) needs surgery in `gen_deep_interaction`/`prove_and_verify`.

**Sub-split:**
- **Milestone 1 (MAKE-OR-BREAK, do first):** M0 + M0b + M1 — *two real `ChildFullEval` components prove+verify in one artifact, no seam/allowlist*. This proves the multi-component plumbing (shared channel + shared preproc + two balances). Everything after is incremental host/AIR glue.
- **Milestone 2:** M2+M3+M4+M5 — seam + allowlist + aggregate PI + gate + negatives.

If M1 is green by mid-session, 5a lands in one session. If M1 fights the two-balance interaction, stop, land M1 as its own commit, and take M2–M5 next session.

**START HERE:** open `tests/recursion_child_full.rs:4919` (`prove_and_verify` — the harness to fork) and `:4525` (`build_inputs` — call twice) side-by-side with `tests/chain_standalone.rs:28` (`prove_two_segment_chain` — the child producer to fork) and `tests/fixed_point_join.rs:339-402` (the seam/allowlist/aggregate idioms to lift onto the real `BoundaryAir`/`rl[0]`).

### Session 5c — SHAPE-CLOSURE (recursion fixed point)  *(DESIGNED 2026-06-26 — 14-agent workflow `wernuy93h`: 4 ground maps → 3-approach judge panel → synthesis → 3-lens adversarial review; L–XL, multi-session)*

**Why this exists:** S5a's two-component artifact is a PERMANENT dead-end for an in-AIR cross-child seam — stwo has NO global Σ-claimed_sums (constraint-framework `component.rs:259` evaluates each component against its OWN `self.claimed_sum`, verified at rev e1286720), so a true cross-child seam can ONLY live inside ONE interleaved `FrameworkComponent`. "Shape-closure" = the verifier's OUTPUT proof is re-ingestable AS A CHILD by the SAME verifier (depth>1: verify 2 segments→a level-1 proof; verify 2 level-1 proofs→level-2; …). Today they match on only 2 axes (FRI config 38q/blowup2/pow20; 4 commitment trees) and diverge on every shape axis that matters (num_components 31 vs 1/2; claimed_sums 31-real vs pinned-0; preproc 31-chip-program vs the ~1727-col `preproc_ids()` pool; boundary = a `SegmentState` read from proof vs constants baked in `BoundaryAir`; artifact type `zkpvm::Proof` vs bare stwo `StarkProof`).

**ARCHITECTURE (judge verdict: UNIFORM, 2-of-3 with uniform tied-top on the 3rd).** UNIFORM single interleaved join-AIR as the end-state (the only construction where ingest-descriptor==emit-descriptor by construction at every interior level), reached MEASURE-FIRST via minimal-delta's ROW-interleave (child0 rows `[0,n)`, child1 `[n,2n)`, n=2^17→log 18) so the ~3500-line per-row `ChildFullEval` body is reused VERBATIM; converge to COLUMN-interleave (log 17, the `prove_and_verify_two` shape) only if the self-ref measurement needs the bit. Two AIRs, RISC-Zero binary tree (76 leaves→depth-7 root): a JOIN-AIR (interleaves two children + real seam) + a thin LEAF-ADAPTER (today's `ChildFullEval` repackaged to emit the join's child-shape S). LIFT Form B (compile the landed S6 verify-only-stwo verifier as a `join_verify` PVM guest + a Poseidon2-M31 hash-children accelerator chip ⇒ the join becomes a NORMAL 31-chip segment `build_inputs_from` already ingests) is the COMPRESSION FALLBACK iff the self-ref log blows the ceiling.

**VALIDATED BACKBONE (reviewer-confirmed against code):** (1) the seam can ONLY be one interleaved component (no global Σcs). (2) the **deg-3 `air_inv` trap is REAL** (`recursion_child_full.rs:1571-1582`: `inv*combine` is deg-2 ONLY because the boundary `tuple` is a BaseField CONSTANT; witnessing it makes `lift(t)` deg-1 → `inv*combine` deg-3, breaking the ≤2 budget at `:1685`) — the flatten fix (witness a `combine` column; `combine-(Σpow[i]·lift(t)-z)==0` deg-2; `inv*combine-1==0` deg-2) is mandatory and applies ~29×/child. (3) registers + memory_root ARE injectively pinned; the seam binds the 4 BOUND fields {registers[13],pc,timestamp,memory_root}, EXCLUDING vestigial `memory_commitment`. (4) the `C_J=hash(preproc incl C_J)` infeasible-fixed-point is correctly dodged via a witnessed PUBLIC-INPUT-HASH allowlist re-checked by the OUTER (JAM) verifier.

**SESSION SPLIT (incremental, each landable; make-or-break = CL.4):**
- **CL.1** ✅ **LANDED** (CL.1a `22257c4` memory-root + deg-3 flatten; CL.1b `abc1dc0` registers/pc/timestamp = CL.1 complete): all 4 seam fields are now WITNESSED held-constant columns. `air_inv_witnessed` flattens the deg-3 trap (witness a `combine` column ⇒ both `combine−(Σpow·lift(t)−z)==0` and `inv·combine−1==0` are deg-2); the 29 boundary `air_inv` calls read witnessed value-limb columns (init/final regs, pc, ts, root) with constant tuple slots (reg index/is_write/ts=0) lifted; the `reg_b/reg_c/prod−cons/mem == cs_ef[pos]` bindings are unchanged ⇒ each witnessed field stays pinned to the child's STARK. +412 base cols over baseline (2784→3196). `child_full_measure` honest prove+verify GREEN @ log 17, **degree ≤ 2, peak 12.5 GiB**; FRI-tamper rejects; new light `child_full_state_tamper_light` confirms a witnessed-memory-root tamper rejects (binding non-vacuous). DEFERRED to later CLs: per-limb byte range-checks (logup binding suffices; needed for the SegmentState read-out at CL.3); pc/ts injective binding via in-AIR boundary-mix replay (lands with the seam at CL.2).
- **CL.2** (M/L) — ✅ **COMPLETE (CL.2a–CL.2e LANDED)**: the real recursion node — two DISTINCT chaining children in ONE interleaved component with a true in-AIR cross-child seam, an in-AIR `{C_0,C_1}` program allowlist, and pc/ts boundary-mix binding — **proves+verifies @ log 18, peak RSS ~30.4 GiB** (`recursion_pair_gate`). Done:
  - **CL.2a-step1 `bc478558`** — interleave plumbing: ONE interleaved `ChildFullEval` proves+verifies two IDENTICAL base segments @ log 18 (the `interleaved`-flag selector rebind switches all ~30 hold sites; `storage_index` stitch; `prove_and_verify_pair`). RAM: log-18 OOM'd at ~23 GiB free, passed at ~34 (the flagged RAM concern, surfaced at CL.2a).
  - **CL.2a-step2 `ca8367ef`** — per-child logup MID-PIN (TWO anchors: `is_global_last·cumsum==0` fixes the free additive constant C, then `is_child0_last·cumsum==0`; the single-anchor version was caught UNSOUND). Inlined manual in-pairs finalize (byte-identical for single-child) to read the running cumsum. `recursion_pair_imbalanced_rejected` (light) confirms ±X cross-child cancellation is rejected (CONTROL/ISOLATION/NEGATIVE).
  - **CL.2b `29ede560`** — real cross-child SEAM (148 `is_child0_last`-gated deg-2 conjuncts, child0.final==child1.init) over DISTINCT chaining children. The two FRI fixes the empirical probe pinpointed: PREREQ-2 deg-2 `carry_step` gate (the FRI carry-latch was a forward cyclic accumulator crossing the boundary); PREREQ-1 per-child witnessed `fri_last_layer_const` (a per-proof host constant). `recursion_pair_distinct_plumbing` heavy GREEN @ log 18; `child_full_measure` (single) still GREEN @ 12.8 GiB (PREREQ-1+2 behaviour-preserving); seam bites cross-child (`recursion_pair_identical_seam_rejected` GREEN), not vacuous.
  - **CL.2c `911e1943`** — in-AIR `{C_0,C_1}` program-commitment allowlist at the tree-0 root latch (`rl[0]` = the preprocessed-trace commitment = program identity). At each child's commit-absorb row `is_root_absorb[0]` gates the held root into membership `member = sel·c1 + (1−sel)·c0` (`sel` = per-child preproc boolean `MEMBER_SEL`, appended LAST, read LAST); since `rl[0] == absorbed[j]` there, it pins the ACTUAL transcript-absorbed program commitment, not a free host root. `ChildFullEval` gains `allowlist`/`c0`/`c1` (host-known flags like `seam`); single-child byte-identical (`allowlist=false`, no MEMBER_SEL use; main 3204 / preproc 1727 unchanged). `c0 = commitments[0].0` (M31 `Hash8`, NOT `commitment_bytes()`), `c1` a distinct dummy slot (real distinct C_1 program DEFERRED). 1 booleanity + 8 membership conjuncts, each deg 2. New negative `recursion_pair_out_of_allowlist_rejected` (accepted vs correct slot, rejected when perturbed, BOTH sel=0/sel=1). `recursion_pair_distinct_plumbing` heavy GREEN @ log 18 (degree ≤ 2 confirmed in a real prove, ~26.5 min). Designed + 3-lens-reviewed via workflow `wbyh7s2lt` (caught: use `.0` not `commitment_bytes`; `MEMBER_SEL` must be PREPROC read-last to avoid main-cursor desync).
  - **CL.2d `c11d4d59`** — in-AIR boundary-mix replay binds the seam pc/timestamp (review gap #3). The child proof's boundary mix (`prove.rs:806-869`: 13+13 regs, init/final pc+ts, 8 root words, each `mix_u64`) is replayed in-AIR: 4 per-child `is_bnd_mix` preproc selectors (init_pc/init_ts/final_pc/final_ts) fire on each child's `mix_u64` Absorb row (`root_absorb_row[1]+1+offset`); there the witnessed CL.1b pc/ts limb-COMBINATION (recompose `Σ byte·256^i`, which in M31 == `reduce(value)`, deg-1) is bound to `absorbed[0]=lo32`/`absorbed[1]=hi32` (FS/FRI-forced). 12 deg-2 conjuncts; reuses existing `is_absorb`/`absorbed[]`/held limbs (NO new cols, NO src/ edits, NO format bump). Binding strength = mod-P limb-combination (NOT per-byte/injective): pc EXACT (pc<P), `final_ts` redundant (register_closing pins it), `init_ts` low-word mod-P — sufficient for gap #3's pc-discontinuity splice. `bnd_mix` flag (host-known like `seam`); single-child byte-identical. Aggregate-PI consolidated host-side (`seam_ok_bound` + `JoinAggregatePI`/`aggregate_pi`: entering=child0.init, exit=child1.final, exit_io_hash; CL.3-forward). Negative `recursion_pair_pc_ts_forgery_rejected` = a prog-combine-kernel forgery (δ on init_ts s.t. `Σ δ_i·α1^i==0` keeps `program_boundary` satisfied) ACCEPTED with bnd_mix OFF but REJECTED with bnd_mix ON — the fix bites for the right reason. Heavy degree gate GREEN @ log 18 (deg ≤ 2 in a real prove, bnd_mix=true). Designed + 3-lens-reviewed via workflow `wd2w7pctc`. (Folded G1: `recursion_pair_out_of_allowlist_rejected` MEMBER_SEL-targeting switched to by-id before the 4 new selectors were appended.)
  - **CL.2e `073d11be`** — consolidated `recursion_pair_gate` (the authoritative CL.2 leaf-join gate; **RENAMED from `recursion_pair_distinct_plumbing`**, which it subsumes): POSITIVE heavy prove+verify @ log 18 (seam + allowlist + bnd_mix ALL enforced) + light in-AIR out-of-allowlist reject + the **LEAF-JOIN COST MEASURE: log_size 18, peak RSS ~30.4 GiB (31120 MiB)**. The dedicated negatives stay (each isolates ONE mechanism): seam-bite `recursion_pair_identical_seam_rejected`, pc/ts forgery `recursion_pair_pc_ts_forgery_rejected`, mid-pin imbalance `recursion_pair_imbalanced_rejected`, per-field broken-seam + host allowlist + aggregate-PI `recursion_two_child_join_contract`. **FINDING:** a clean in-AIR per-field seam ISOLATION test is NOT constructible (every boundary field is co-used by the seam AND the owning child's own boundary/held-constancy ⇒ any single-field tamper trips both) — the per-field split is done host-side in the join contract. **NOTE on the ~30.4 GiB:** this is the log-18 ROW-interleave; if CL.4's self-ref needs headroom, COLUMN-interleave (stays log 17) is the documented convergence (≈ halves the domain).
- **CL.2 DEFERRED + labeled (carry into CL.3+):** FS-binding `fri_last_layer_const` (witnessed prover-chosen, parallels the unfinished single-child FRI binding); the memory_root seam conjunct is vacuous on the Add64 toy + the exit io-hash is `[0;32]` (a memory-writing child makes per-endpoint memory_root/io-hash discriminating); a REAL distinct C_1 program slot (today `c1` is a dummy ⇒ the allowlist `sel=1` path is exercised only in the negative test).
- **CL.3** ✅ **LANDED `aa0d0e7a`**: `build_join_proof` repackages the join's bare `StarkProof` (otherwise discarded after `prove_and_verify_pair` verifies it) into a child-shaped `zkpvm::Proof` — `num_components=1`, `claimed_sums=[0]`, aggregate boundary `initial_state`=child0.init / `final_state`=child1.final, tagged by `JOIN_COMPONENT_MASK = 1<<31` (a reserved non-chip sentinel bit in `component_mask`; base segments use bits 0..30) with NO format_version bump (a join is still Poseidon2-M31 v9 crypto). `join_proof_roundtrip` GREEN (12 s): shape intact + byte-identical bincode round-trip, using a real base-child `StarkProof` stand-in (repackaging+serde are content-independent) with genuine entering/exit states from two chaining children. The REAL pair `StarkProof` flows through `build_join_proof` in CL.4. (NB: the host-side `initial/final_state` come from the child proofs; the in-AIR SegmentState read-out from witnessed cols is a CL.4/CL.5 concern.)
- **CL.4** (XL — split 4a generalize extract/reconstruct/drive off `BASE_COMPONENTS`; 4b parameterize POS_LOG/dbl_steps/N_FRI_LAYERS by join log; 4c self-ref embed + depth-2 self-ingest): `build_join_inputs_from`+`extract_join_recursion_data`; prove a level-1 join, ingest AS A CHILD of level-2, verify. **DECISION GATE: print the level-2 self-ref OODS log_size — ≤19 closes natively (→CL.5); >19 → CL.F.** `shape_closure_depth2`.
  - ✅ **MAKE-OR-BREAK PASSED — SPIKE LANDED `4ee07e0a` (`cl4_laynrows_spike`, NO heavy prove, ~34 s): the shape-closure fixed point CLOSES NATIVELY at log ~17. No LIFT fallback, no server-class RAM.** Measured the ONE unmeasured swing term, `lay.n_rows` = the OODS-recon op-count of the interleaved join's OWN `ChildFullEval::evaluate`. **Mechanism VALIDATED:** a `MaskShapeProbe` records `evaluate`'s per-tree mask-read shape → a dummy mask of that shape drives a `StreamBackend` → `schedule_two_stream`+`layout_colocate` give n_rows; on the 31 base chips this reproduces `build_inputs`'s real-OODS `lay.n_rows` to the unit (**24114 == 24114**, matching the production `child_full_air_satisfied` print). **The design's "6251" base ref was STALE** (pre-Phase-A log-14 base); **24114 is the current base**. **RESULT: join `lay.n_rows` = 9017** (0.37× the current base — the verifier AIR is LEANER than the Phase-A-grown 31-chip machine, the OPPOSITE of the review's worst-case worry); 2× = 18034 ≪ the log-17 threshold (65536). The binding level-2 term is the merkle/deep/records SUM (~85k for two join children, < the base's 110k since the join is ~3× narrower at ~5105 cols) → `next_pow2` = **2^17**. Even the pessimistic "join as wide as base" bound = 2^18 ≤ 19 (still native). Join `evaluate` reads preproc 1733 / main 3204 / interaction 160 — preproc/main EXACTLY match the registered counts (independent shape check). **Also landed STEP 0: `prove_and_verify_pair` now RETURNS the verified `StarkProof`** (was discarded) — the `build_join_proof` seam for CL.5. **TWO CONCRETE CL.5 ACTIONS surfaced:** (i) join `max_leaf_in_row` = **48 > NLEAF=46** ⇒ `layout_colocate`'s guard (`oods_auto.rs:2450`) trips for the join verifier — bump `NLEAF`≥48 (slightly wider); (ii) a TYPE SEAM — the pair prove uses the `recursion_common`-mirror `P2MerkleHasher` (via that channel) while `build_join_proof` (CL.3) takes `zkpvm::poseidon2::P2MerkleHasher`; reconcile before feeding the real pair StarkProof through `build_join_proof`. **REMAINING in CL.4 = Tier-B (the EXACT level-2 number via the real `reconstruct_join_oods`/`build_join_inputs_from`, the 4a/4b build) + Tier-C (the depth-2 confirmation prove `shape_closure_depth2`, ~30.4 GiB peak — the leaf children dominate). The native-vs-LIFT DECISION is already made (native); Tier-B/C refine + validate end-to-end.**
  - ✅ **TIER-B LANDED 2026-06-29 (`cl4_tierb_exact_quartet`, NO heavy prove, ~32 s): the EXACT level-2 self-ref quartet — `level2_log = 17` (NATIVE, ≤18), ~2.7× headroom to 2^18.** Design + 12-agent adversarial-review workflow `w65y796sm` (4 maps → 3 designs → synth → 3 lenses → finalize); **the architecture is TEST-SIDE, SHAPE-ONLY (no join prove, no src edit, no NLEAF bump, no type-seam touch)** — every quartet term is a value-independent COUNT computed from the join AIR's shape and VALIDATED EXACTLY against the live `build_inputs_from` BASE reference via **5 cross-checks (all match to the unit):** #1 lay.n_rows 24114, #2 mk_fills 83562 (widths [452,9951,5364,8]), #3 deep.terms 17929 (stwo periodicity rule — a 2-offset column → 3 deep entries; 1077 2-offset cols), #4 records 8584 (FS-transcript op-replay), #5 the join's ACTUAL `Components::mask_points` path reproduces #3/#4 (proves mask_points is un-inflated ⇒ `periodicity_terms` applies exactly once — guards a silent `deep_terms` double-count). **JOIN quartet:** records 3390 + mk_fills 36632 + deep.terms 7951 + 38 = single_sum **48011** → single_log 16; `level2_log = next_pow2(max(2·48011, 2·9017)) = 2^17 = 17`. New helpers (all in `recursion_child_full.rs`): `derive_lifting`/`mk_fills_count`/`periodicity_terms`/`replay_transcript_records`+`TranscriptDesc`/`base_mech_lay_n_rows`/`join_lay_n_rows`/`build_join_quartet`. **THREE SPEC CORRECTIONS (code-confirmed, all in the workflow output):** (a) **lifting = 20, mlbd = 18, n_fri = 18 — NOT the design's 19/~17** (`composition_log_degree_bound = log_n_rows+1 = 19`, then `lifting = (19−COMPOSITION_LOG_SPLIT)+log_blowup = 20`; runtime-derived via `derive_lifting`, never hardcoded — an off-by-one corrupts the q0 pos-chain). (b) **NLEAF must NOT be bumped for the measurement** — it is STRUCTURAL at ~15 base/level-1 AIR sites (`N_SV_LOGUP`/`WIN`/embed widths), so a global bump re-shapes the base ⇒ {C_0,C_1} re-pin; `layout_escalate` reads the true `max_leaf_in_row=48` past the guard (`n_rows` is nleaf-independent, `oods_auto.rs:2409`). The NLEAF bump belongs to **CL.5/Tier-C** (the real prove), done carefully. (c) **`{POS_LOG,N_FRI_LAYERS,N_CS,NLEAF}` CANNOT become runtime struct fields** (they size fixed arrays) — level-2 values are carried via the additive `TranscriptDesc` + runtime-derived lifting; and the src descriptor-enum-in-ONE-place is infeasible (src can't name the test `ChildFullEval`/3 relations; base vs join FS-transcripts diverge at 5 points) ⇒ realized test-side. **F4 (spike fix):** `cl4_laynrows_spike`'s old `2·lay≤65536` heuristic tested ONLY lay.n_rows (coincidentally right); the verdict is governed by the ADDITIVE sum (dominated by mk_fills, since join tree heights = lifting = 20) — the spike is rewired to the exact `build_join_quartet`. **F3 caveat:** lay.n_rows=9017 is a level-1 PROXY (the `pos_consts`/`N_POSCHAIN` chain is POS_LOG=16-sized) that under-counts the level-2 pos-chain — irrelevant (~5× below the additive sum). **Tier-C scaffold (documented, NOT built):** const-generic `ChildFullEval<NLEAF,POS_LOG>` so level-1 (46/16) and level-2 (≥48/20) coexist; `prove_pair_native` to cross the `recursion_common`↔`zkpvm::poseidon2` `P2MerkleHasher` type seam; the real `build_join_inputs_from` over ONE heavy log-18 prove for the depth-2 self-ingest.
  - **DESIGNED 2026-06-28 (9-agent workflow `we1emqaz8`: 4 ground → 3-proposal scored judge panel → synth → adversarial review). RECOMMENDATION = Proposal A (MODE-GATED single AIR), row-interleave, native closure PREDICTED (~log 17, ≤19), NO server RAM. Full output: the `we1emqaz8` task file. (NB: Tier-B above SUPERSEDES this note's "lifting=19/N_FRI~17" and "bump NLEAF≥48" — see corrections (a)/(b).)**
    - **THE FORK RESOLVED (gap #2): ONE parameterized `ChildFullEval` verifies BOTH base and join children** by driving extract/reconstruct/embed off the child's actual `(num_components, log_sizes, claimed_sums)` AS DATA. `evaluate` is data-driven over the embedded OODS records (NOT hardwired to 31), so the fork is mostly a HOST-side generalization. Column-interleave REJECTED (the self-ref log is decommit-WIDTH-driven not domain-driven; col-interleave is ~1.66× WIDER ⇒ worse, and forfeits the CL.2b in-AIR seam). LIFT Form B = documented >19 fallback only (the S6 transpiler trap is FIXED+pushed, jar `ec9debbe`; ~10.7M cycles/node ⇒ strictly contingent).
    - **CONVERGENCE = ONE measurement: `lay.n_rows(level-2)`** = the OODS-recon op-count (#macs+#products, `oods_auto.rs:2394-2409`) of `ChildFullEval`'s OWN ~3500-line `evaluate` body (vs the base 31-chip machine's 6251). The OTHER three log terms (`records`, `mk_fills`, `deep.terms`) PROVABLY CONTRACT — a join child is ~5099 cols, ~3× narrower than a base segment (~15775), ENGINEERED by the landed S3b coeff cut 6112→992 + S3c DEEP-lane 1672→228. **Review thresholds (lay·2 vs the contracted interleaved sum ~84k):** op_count ≤ ~65k (≤10.5× base) → level-2 log **17** (~16 GiB); 65k–262k (10.5–42×) → log 18 (~32 GiB, still ≤19); >262k (>42×) → log ≥19 → fallback. Likely `evaluate` ~2–4× a base machine ⇒ ~12–25k ⇒ **log 17**. **Level-2 is the WORST CASE** (it verifies the WIDEST join child it ever sees — the leaf-join; width contracts thereafter) ⇒ "level-2 ≤ 19 ⇒ fixed point ≤ 19" is a real bound. PIN the fixed point P with an arithmetic L5358 sweep over P∈{16,17,18} (smallest P with output(P)≤P).
    - **CHEAPEST MEASUREMENT = NO heavy prove.** The gate `log_size` (`recursion_child_full.rs:5358`) is a host-side `max(records + mk_fills + deep.terms + N_QUERIES, lay.n_rows).next_power_of_two()` — all built during input RECONSTRUCTION, never a prove. **FIRST INCREMENT (review-adjusted — the `lay.n_rows` spike, NOT the rec's Tier-A arithmetic which OMITS the swing term):** (0, 5 min) make `prove_and_verify_pair` (L6414) RETURN the verified `StarkProof` (it currently discards it) so `build_join_proof` repackages the real one; (1) instantiate the level-1 join's own `ChildFullEval` (held ~L6451), drive its `evaluate` through the StreamBackend capture exactly as `drive_multi` does (`|_,_,e| FrameworkEval::evaluate(&inner,e)` — the 4c arm ONLY, no 4a/4b), print `layout_colocate(...).n_rows` + `max_leaf_in_row`; (2) ASSERT `max_leaf_in_row ≤ NLEAF=46` (`L3440` guard — a denser join inner may co-locate >46 leaves/row ⇒ NLEAF must grow ⇒ wider verifier — a concrete early trip). Near-zero RAM, no prove. Then 4a/4b/4c Tier-B reads the EXACT quartet off `build_join_inputs_from`.
    - **4b off-by-one (review): the join at trace-log 18 has lifting = composition_log_degree_bound = 18+1 (deg-2) = 19, NOT 20** ⇒ `POS_LOG` 16→**19**, mlbd=18, dbl_steps=17, `N_FRI_LAYERS` 14→~17. DERIVE from `data.lifting_log_size` at runtime (an off-by-one silently corrupts the q0 pos-chain `N_POSBIT`/`N_POSCHAIN`). Make `{POS_LOG, N_FRI_LAYERS, N_CS, boundary_on}` PER-INSTANTIATION fields (the level-2 verifier runs `{19,~17,1,false}` while the inner level-1 it drives symbolically runs `{16,14,31,true}` — both coexist in one prove).
    - **RAM (review-refined): the measurement never proves (~0 RAM).** Tier-C depth-2 prove peak is bounded by producing the two level-1 join children FIRST (each a ~30.4 GiB leaf-join prove) ⇒ sequential peak **~30.4 GiB**, fits the 62 GiB box. Server-class needed ONLY at self-ref log ≥19.
    - **`C_J = hash(preproc incl C_J)` infeasible fixed point CONFIRMED DODGED:** the allowlist `{c0,c1}` are WITNESSED host-known flags (CL.2c), NOT baked into preproc ⇒ C_J is allowlist-independent ⇒ no circularity. Residual (CL.5): `c1` is a DUMMY today; the self-ref needs `c1=C_J` — a bootstrap-ordering step (finalize join preproc → compute C_J → set the witness), feasible because the allowlist is a witness not a constant.
  - ✅ **TIER-C COMPLETE 2026-06-30 (`8033b650`) — SEMANTIC depth-2 shape-closure GREEN (the recursion make-or-break, with the FAITHFUL inner — not merely structural).** The depth-2 L2 verifier trace BUILDS+VERIFIES at log 17 via the REAL `build_join_inputs_from` over a real J1 prove; make-or-break RE-CONFIRMED with real pieces (R8: records 3390 + mk_fills 36632 + deep 7951 + 38 = single_sum 48011 → level2_log **17 NATIVE**). Machinery (all `recursion_child_full.rs`): const-generic OCTET `ChildFullEval<POS_LOG,NLEAF,N_CS,N_FRI_LAYERS,NB,N_DENSE,OPS_S,N_OFF>` (`ChildEval=<16,46,31,14,11,0,1,67>` base byte-identical `0xdb2ec0205bbe9fca`; `JoinEval=<20,48,1,18,68,4,1,250>`); folded dedicated-wide-slot DEEP layout for J1's 4 dense embed-stream-lane cols (67 entries each, `N_DENSE_ENTRY=67` decoupled from `N_OFF`); embed window `N_OFF` per-instantiation (250, dr=249 fits); `prove_pair_native` (crosses the `recursion_common`↔`zkpvm::poseidon2` `P2MerkleHasher` type seam); **faithful `reconstruct_j1_inner`** (field-for-field replica of J1's committed component — consts threaded from `base_pair`, relations from J1's FS transcript) so the L2 GENUINELY verifies J1's composition closure (#652 un-gated). **THE LAYOUT CASCADE (all resolved, each MEASURED before proving):** the const-generic generalization surfaced base-vs-join divergences one at a time — quintet → N_DENSE (folded DEEP) → OPS_S (measured+REJECTED) → N_OFF/DR (embed-recon stream depth dr=249 ≫ base 66). PATTERN = the self-referential verifier needs LARGER layout params than the base 31-chip machine (KEY GAP #1 realized); all width/depth, level2_log=17 holds. Workflows: `ww35mxus8`/`wkl2iwchj`/`w57tme57t`. **BLOCKER RESOLVED (`8033b650`): the `shape_closure_depth2_air_satisfied` itertools `zip_eq` panic was a per-tree MAIN column-count mismatch.** `extract_join_recursion_data` sized its recon component from a dummy `shape_only_j1_inner()` that hardcoded `dbl_steps:17` (the LEVEL-2 verifier's mlbd−1); but J1 verifies BASE children ⇒ it was PROVED with `dbl_steps=13` (base mlbd−1: POS_LOG_BASE=16, log_blowup=2 ⇒ mlbd=14), and `ChildFullEval::evaluate` reads `8·dbl_steps` MAIN cols via two `0..dbl_steps` `read4_0` loops ⇒ the recon OVER-committed MAIN by `8·(17−13)=32` cols ⇒ the per-tree decommit zip_eq (stwo `vcs_lifted/verifier.rs:126`, `queried_values.iter().zip_eq(column_log_sizes)`) length-mismatched BEFORE #652. (The earlier "L6189-6191/refactor-side-effect/not-statically-diagnosable" read was wrong — it IS statically diagnosable: the panic is a per-tree column count, and `dbl_steps` is a value-DEPENDENT size, contra the deleted comment's claim.) FIX = thread J1's real `J1InnerConsts` into `extract_join_recursion_data` + size the recon from `j1.clone()` (dbl_steps=13 ⇒ shape-IDENTICAL to the proved J1 component; the faithful `build_join_inputs_from` recon already used the real consts — only the extract sizing path used the bad dummy), delete `shape_only_j1_inner`, add a defensive per-tree column-count assert (clear message vs cryptic itertools panic). 4-agent adversarial review GREEN (root-cause-confirmed / fix-complete / no-regression; flagged a future-drift note: the `ChildEval` alias matches J1's monomorphization only because `OPS_S_JOIN==OPS_S_BASE==1` ∧ `N_OFF_BASE==67` coincide — the new assert guards it). **VALIDATING PROVE GREEN (`shape_closure_depth2_air_satisfied`, 1651s, ~30 GiB):** no panic; R8 `single_sum=48011`; `level2_log=17`; the un-gated #652 (`is_final·r_l==0`) closes ⇒ L2 GENUINELY verifies J1's composition over canonical base children (faithful depth-2). Base byte-identity unchanged (`0xdb2ec0205bbe9fca`); cheap Tier-C gates green. **CL.4 (the recursion make-or-break) is DONE — native closure at log 17 with the faithful #652. NEXT = CL.5.** **The branch is MASSIVE (Tier-C ≈ +2400 lines) and needs a dedicated REVIEW pass before merge.**
- **CL.5** (XL — the `(M)` was an undercount) — SCOPED + DESIGNED 2026-06-30 (workflow `w8bdzq3pq`: 4 ground maps → design synth → 3-lens adversarial review, verdict **has-gaps ×3** which CAUGHT a fundamental scoping inversion). **ARCHITECTURE DECIDED: a BOUNDED, depth-INDEPENDENT 3-slot allowlist `{C_0 (base segment), C_adapter (leaf-normalizer), C_J (canonical interior join)}`.** A literal single tree-wide `C_J` is STRUCTURALLY IMPOSSIBLE (leaves embed a 31-chip base segment ⇒ `C_adapter`; interiors embed `JoinEval` ⇒ `C_J`; different preproc ⇒ ≥2 commitments). An unbounded per-level allowlist doesn't close (the OUTER published set would grow up the depth-7 tree). The only sound middle = canonicalize every interior join to ONE `C_J` (via `prove_join_canonical` fixed-log + fixed-octet padding) + a leaf-adapter that normalizes base leaves into the join's child-shape S so interiors only ever embed shape-S (= themselves).
  - **THE REVIEW'S LOAD-BEARING CORRECTION (all 3 lenses): the leaf-adapter is a PREREQUISITE, not a deferrable follow-on.** The make-or-break novelty is the SELF-REF fixed point `JoinEval`-verifies-`JoinEval` (interior verifies interior ⇒ one constant `C_J`). A real self-ref prove needs a real `JoinEval`-SHAPED child — you cannot fabricate the `#652`/OODS/FRI values (soundness forbids) — and its ONLY source is the leaf-adapter (base→shape-S) or another canonical join (which regresses to leaves = base segments, NOT shape-S). **CL.4 Tier-C measured/proved `JoinEval`-verifies-`ChildEval`** (`reconstruct_j1_inner` returns a `ChildEval`) — that is the LEAF relationship (interior-verifies-leaf), NOT the fixed point; it demonstrates ZERO level-to-level `C_J` invariance. So "CL.5d over the cached J1" = "Tier-C with `allowlist=on`", not the self-ref.
  - **CL.5a IS A FIXED-POINT *SOLVE*, not a one-shot measure** (review): the self-ref inner's `dbl_steps`(=mlbd−1)/`POS_LOG`/N_FRI depend on `L_canon`, and `L_canon = next_pow2` of a sum over a verifier whose MAIN width is `8·dbl_steps` (the EXACT feedback that caused the `8033b650` zip_eq blocker). Must ITERATE octet/`L_canon` to a stable fixed point and prove `single_log(L) ≤ L` has a native solution; the self-ref inner is HEAVIER than Tier-C's `ChildEval` inner (N_OFF 67→250, N_DENSE 0→4) so 17→18 (and the ~30 GiB→OOM RAM jump) is a LIVE unmeasured risk. Gate = fixed-point convergence, NOT the optimistic "≤18".
  - **CIRCULARITY is NOT yet proven** (review): the dodge (c0/c1 are witnessed constants → composition tree, not preproc) is right for the OUTER allowlist constraint, but the self-ref embeds an INNER verifier whose `c1=C_J`, and the `const_id`/`coeff_id` PREPROC columns bake the embedded inner AIR's coefficients into tree-0. Whether the inner's `c1` lands in those preproc columns (⇒ `C_J=F(C_J)` regress) is UNVERIFIED. REQUIRED cheap gate (host): derive `C_J` twice — inner-c1=[0;8] vs inner-c1=[nonzero] — require `commitments[0].0` BYTE-IDENTICAL; if they differ, CL.5 is blocked at the foundation.
  - **SOUNDNESS scope-cut (state plainly): the in-AIR allowlist with a prover-chosen `c1` WITNESS is NOT self-binding** — a prover picks `c1` to match a forged child. The real binding is ENTIRELY deferred to the OUTER verifier hardcoding canonical `c0/c1` + re-running OODS/FRI. And the production verifier CANNOT ingest a join today: `verify_chain_standalone_allowlist` (verifier/src/lib.rs:481) → `verify_standalone` drives off `component_mask` over chip bits and REQUIRES a boundary-binding chip + `popcount==num_components`; a join mask `1<<31` selects zero chips. So CL.5 lands a TEST-SIDE standalone-verify mirror, NOT "internalizing `verify_chain_standalone_allowlist`" in production (a separate, soundness-critical, UNSCOPED src lift). The I/O boundary (loop B / SegmentState in-AIR read-out) stays HOST-read from child proofs at every interior node AND the adapter leaf — "program-identity loop A closes" must always be paired with "I/O loop B is a host-trust gap."
  - **INCREMENT SEQUENCE** (front-loaded; ~2-3 heavy proves in the full path): **CL.5a** self-ref shape spike (HOST-ONLY: fixed-point convergence solve `single_log(L)≤L` for `JoinEval`-verifies-`JoinEval` + circularity double-derive + octet self-consistency for BOTH child kinds + FRI-RAM estimate; GATE = native convergence ⇒ Path A reachable, else CL.F) → **CL.5b** `C_J` host derivation (`join_program_commitment` = commit ONLY the canonical preproc tree, byte-deterministic; freeze the MEMBER_SEL pattern into it) → **CL.5c** allowlist self-ref LIGHT (`assert_constraints`, perturbed-c1 reject — but review caveat: a TRUE self-ref light gate needs a real shape-S child, so this only de-risks once the adapter exists) → **CL.5h LEAF-ADAPTER** normalizer-prove (HEAVY; base→shape-S; yields `C_adapter`; PREREQUISITE of every real self-ref prove, pull EARLY) → **CL.5d** `prove_join_canonical` (HEAVY: first real canonical-join StarkProof — Tier-C only `assert_constraints`'d, a join StarkProof has NEVER been FRI-proved — padded to `L_canon`, `allowlist=true`, `c1=C_J`; GATE `commitments[0].0 == C_J`, deg≤2 in a REAL prove) → **CL.5e** test-side standalone allowlist-verify of a join (membership + verifier-supplied `c0/c1` + real verify) → **CL.5f** `shape_closure_e2e` depth-2 (the landing gate; child→canonical join→re-ingest→standalone allowlist-verify pinning `C_J`). **CL.5g** depth-3 = STRETCH, gated by its OWN measure-first log spike, recommended OUT (depth-2 already demonstrates the fixed point).
  - **MIXED-PROGRAM TREE NODES** (review, deferred but flagged): `MEMBER_SEL` is a committed preproc column ⇒ the per-child sel pattern is baked into `C_J`; a real 76-leaf unbalanced tree has heterogeneous interior nodes (adapter-child + join-child) ⇒ a uniform `sel` cannot be both `C_adapter` and `C_J`. Resolve via tree-shape canonicalization (pad to a perfect binary tree of uniform shape-S children) OR a per-position frozen sel pattern — must be fixed BEFORE `C_J` is computed. Not depth-2 blocking; load-bearing for tree-wide verification.
  - **DECISIONS TAKEN (user, 2026-06-30):** start with the cheap make-or-break spike (CL.5a) FIRST before any heavy prove. Keep the existing 2-slot in-AIR `{c0,c1}` machinery (depth-independence from canonicalization, not slot-widening). Depth-3 OUT this session.
  - **CL.5a SELF-REF SHAPE SPIKE — RAN 2026-06-30 (`cl5a_selfref_shape_spike`, host-only, ~30s; NO prove). TWO foundational gates resolved; the full octet fixed-point is the precise remaining unknown.** Mechanism: `join_quartet_from_inner` made octet-GENERIC (`quartet_from_inner_g`, behavior-preserving thin wrapper — the leaf cross-check `single_sum=48011` PASSES) so the quartet can be measured for a `JoinEval`-shaped child. **(1) CONVERGENCE (one iteration) GREEN:** verifying a `JoinEval` child (the self-ref, vs Tier-C's `ChildEval`/leaf child) costs `single_sum ≈ 82–85k` (widths `[4671,5184,700]` vs leaf `[1733,3204,160]` — ~1.7× wider; preproc 2.7×, interaction 4.4×) ⇒ `level2_log = 18` for ALL `L∈16..19` ⇒ `L_canon = 18`, NATIVE (≤19, no CL.F LIFT). The self-ref costs EXACTLY **+1 OODS log vs the leaf** (leaf 17 → self-ref 18 = the canonical J1 log); zero contraction below 18; ~1.55× headroom before spilling to 19. **(2) CIRCULARITY DODGED (code-confirmed, not just argued):** `self.c0`/`self.c1` are read ONLY in `evaluate` (L2980-81, as an `add_constraint` ⇒ composition tree), NEVER in trace/preproc generation ⇒ the canonical preproc commitment `C_J` is `c1`-INDEPENDENT ⇒ `C_J=hash(preproc incl C_J)` cannot arise; and `c1` enters via `add_constraint` (not a `next_trace_mask`) so it doesn't leak into the OUTER's recon layout/preproc either. The (1) number was ONE iteration (a `JoinEval` child under the FIXED `JoinEval` octet), NOT the self-hosting fixed point — and the fixed-point iteration REVERSED it.
  - **CL.5a OCTET FIXED-POINT ITERATION — RAN + ADVERSARIALLY VERIFIED 2026-06-30 (`cl5a_octet_fixed_point`, host-only, ~30s, NO prove): RED — the self-hosting octet DIVERGES ⇒ Path A (native in-AIR uniform self-ref) is DEAD ⇒ CL.F LIFT is REQUIRED for Track B (76→1).** The octet-solve (NLEAF=max_leaf, N_OFF=dr+1 via `layout_escalate`, NB=distinct OODS mask points) generalized to derive O_{k+1} = the octet of a verifier of an O_k child; CROSS-CHECK anchors it EXACTLY (solve(`ChildEval`) → the known JoinEval octet `<20,48,1,18,68,4,1,250>` + widths `[4671,5184,700]` + single_sum 84432 — the leaf rung is real-prove-anchored via Tier-C). **The ladder: O0 (JoinEval) ΣW=10555/ss=84432/level2_log=18 → O1 ΣW=24266/ss=179911/log=19 → O2 ΣW=53876/ss=386082/log=20.** `N_OFF` 250→660→1440 and `NB` 68→251→661 roughly DOUBLE each level; the width map is **W(C) ≈ 2.3·C** (each verifier ~2× wider than its child), `level2_log` climbs 18→19→20 MONOTONICALLY — no native fixed point. **MECHANISM (textbook non-succinctness of in-AIR STARK self-verify — succinct in trace LENGTH, LINEAR in trace WIDTH):** the dominant `single_sum` term `mk_fills` (the merkle/FRI decommit) is strictly ∝ the child's committed width ΣW, and the deep-recon read-back window `N_OFF=dr+1` (coeff ≈ 8·N_OFF) + DEEP-batch count `NB` (one-hot ≈ 24·NB) feed back ADDITIVELY into the verifier's OWN width ⇒ unavoidable >1 multiplier. **3-lens adversarial review (`w5d9h0oc0`, re-ran the test LIVE) = UNANIMOUS: divergence TRUSTWORTHY + CONSERVATIVE** (every fidelity imperfection found — `octet_child` carries seam/allowlist/bnd_mix OFF; `N_DENSE_ENTRY` pinned 67 — UNDER-states width ⇒ true divergence ≥ measured 2.3×). **`OPS_S=1` is the LEANEST layout** (the deep-recon fold is a serial mac-chain ⇒ `dr` is chain-length-bound, OPS_S-independent; OPS_S≥2 blows `max_leaf` past 48 + adds OPS_S² coeff width; column-interleave is ~1.66× WIDER) ⇒ NO layout converges. **Bounded-depth does NOT escape** (width explodes 2.3^k; depth-7 root ≈ 340× leaf ⇒ TB-scale RAM). Matches production recursion theory (Plonky2/RISC Zero/SP1 all use a FIXED verifier-AS-PROGRAM, never a verifier-AIR-of-the-verified-AIR). **Residual (non-blocking): only the LEAF rung has a real prove behind it; O1/O2 are self-consistency-checked extrapolations of the same (under-counting) machinery — conservative lower bound, optional de-risk = an OPS_S re-sweep at dr~1440.**
  - **⇒ TRACK-B ARCHITECTURE PIVOT: Path A (the uniform interleaved in-AIR self-ref, the judge-panel's primary) is RETIRED; CL.F (LIFT Form B) is the path** (the review's gap-#2 vindicated — "some LIFT is STRUCTURALLY required, not just a >log19 fallback"). **CL.4's landed depth-2 in-AIR prove is SUPERSEDED as the shipping aggregation mechanism but RETAINS value as (a) the validated measurement ORACLE (its anchored cross-check is exactly what makes this RED verdict trustworthy) and (b) the semantic reference SPEC for the `join_verify` guest (the seam / SegmentState boundary read-out / aggregate-PI / {c0,c1} allowlist logic the depth-2 demonstrated must all be replicated INSIDE the guest); CL.3 `build_join_proof` repackaging + the CL.5h leaf-adapter concept carry over.** **Track A (single light segment, on-chain, NO recursion) is UNAFFECTED and remains DONE.** **CL.F SCOPE (XL, the big remaining Track-B piece) = four sub-parts:** (a) a Poseidon2-M31 **hash-children accelerator chip** (new 31-chip-family member) so hash-children is one chip-op, keeping each per-join `join_verify` segment a tractable FIXED size; (b) compile the landed `recursion-verifier` (verify-only-stwo; jar `ec9debbe` already TRANSPILES + EXECUTES the full Poseidon2-M31 verify on JAM PVM, ~10.7M cycles) as a `join_verify` PVM guest; (c) wire `build_inputs_from` to ingest the `join_verify` segment as a NORMAL 31-chip segment ⇒ `C_J` = the verifier-PROGRAM commitment (CONSTANT, recursion closes); (d) close the SegmentState I/O loop-B host-trust gap. Per-node cost FIXED (~10.7M-cycle segment) × 75 interior nodes for 76 leaves — BOUNDED + PARALLELIZABLE (exactly the property the divergent in-AIR map lacks). This REPLACES the old `shape_closure_e2e` / CL.5b-h in-AIR plan. Full design = `w8bdzq3pq`; spike = `af8265b66c6a55e2a`; divergence-review = `w5d9h0oc0`.
- **CL.F MAKE-OR-BREAK — RAN + MEASURED 2026-06-30 (host counts + PVM microbench + cost-model workflow `ww938sy1u` 8-agent / 3-lens review): RED — the Poseidon2-M31 accelerator is NECESSARY-BUT-INSUFFICIENT; a single `join_verify` segment is INTRACTABLE by 1.5–2 orders of magnitude; Track-B native FRI-recursion (in-AIR AND LIFT) is WALLED by the base WIDTH.** Measured anchors (trustworthy): **N_perm = 88,600 permutes / real 31-chip child verify** (host count; 3-way cross-validated — independent workflow run 87,668, in-AIR mk_fills 83,562; width-driven, ~FLAT in log_size; dominated by Merkle leaf-hashing of the 15,775-col commitment, trees [452,9951,5364,8]); **cyc_per_perm = 15,808 PVM cycles** (microbench, clean slope, ~47-cyc fixed); BoolEval (toy log5/1col) verify = **89.7 % hashing**, residual floor 1.10M cycles (validated: the wide-bool residual harness reproduces 1.10M exactly at (W=1,L=5)). **THE LOCKED FLOOR (verdict is robust to all residual uncertainty):** STARK verify cost is Θ(n_queries × committed_columns) for the DEEP/OODS-quotient eval (`fri_answers`/`accumulate_row_quotients`, stwo `pcs/quotients.rs`) — for each query, sum over every opened (column,offset) value, the soundness-critical "combine all opened values" step. It is FIELD ARITHMETIC, so the Poseidon2 hash-accelerator does NOT touch it. **DEEP terms/child = 38 × 17,929 ≈ 681k irreducible QM31 mul-adds; a join (2 children) FLOOR @ an unphysical 10 instr/term = 13.6M instr = 34× over the single-segment log-21 budget** (~400k retired instr; C_reg≈5.2 from the 100k→log19 calibration; production 19q only halves to ~17×). Realistic (~30–90 instr/QM31-combine) ⇒ join ≈ 36M…800M cycles ⇒ **log 25–30**. **WITHOUT accel: ~1.4B cyc/child ⇒ log 31** (the plan's "~10.7M-cycle segment" was the TOY BoolEval fixture, NOT a real child — disproven). **K-SPLIT DOES NOT RESCUE IT** (unanimous 3-reviewer correction of the synth's false-optimistic "closes with a fixed ~340–790 per-node constant"): if one `join_verify` needs K>1 segments, its proof is a K-segment chain ⇒ the parent must verify ALL K (a STARK chain is only sound if every segment is verified) ⇒ parent trace ~K× ⇒ segment-count compounds ~K^depth over the depth-7 tree — the SAME divergence that retired the in-AIR path (CL.5a), relocated from trace-WIDTH (2.3×/level) to SEGMENT-COUNT (~K×/level). ⇒ the single-segment condition `I_with ≤ I_seg` IS the closure prerequisite, and it FAILS. **ROOT CAUSE (unifying): the base segment is WIDE (15,775 committed columns; 31-chip VM). Verify cost ∝ width (Θ(queries×width) DEEP-quotient + Θ(width) leaf-hash). BOTH recursion strategies die from this ONE cause** — in-AIR compounds width 2.3×/level; LIFT's per-node verify is Θ(width×queries) ⇒ K-chain diverges. **ROBUST conclusions reviewers say TRUST:** (1) without-accel hopeless; (2) Poseidon2 accel NECESSARY; (3) a single Poseidon2-accelerated `join_verify` is NOT single-segment, robust across ~1.5 orders of magnitude of residual uncertainty (residual = DEEP-quotient, column-driven, binding floor). Reviewer UNDERCOUNTS all make it WORSE: the only existing precompile template (RistrettoEcallChip, 1 byte/row) ⇒ accel chip = 96·N_perm ≈ 17M rows ⇒ log24 unless a packed-logup layout (unbuilt) is achieved; `peak_log` must be MAX over ALL chips incl. the accel chip + interaction-tree + the Phase-A memory-Merkle chips; residual omits deserialize (~3 MiB postcard) + queried_values gather (~2.34 MiB) + OODS composition re-eval (re-run all 31 chips' evaluate), all accelerator-immune. **GOLD-STANDARD PVM MEASUREMENT (user-requested; RAN 2026-06-30) — confirms RED by ~3 orders of magnitude, on TWO independent walls.** Done on the EXISTING settle infra (parametrize the BoolEval fixture to `FIXTURE_WIDTH` cols × `FIXTURE_LOG`; regen → `just build-settle` → run on JAM PVM; host-count N_perm via the gated permute counter; a LEAN bare-`Interpreter` step-count runner since `TracingPvm` host-OOMs above ~150M cycles). **CORRECTION: there is NO transpiler deserialize bug** — the prior agent's "miscompile fires for any non-trivial proof" was MISDIAGNOSED bump-allocator OOM. A log-12 1-col verify ACCEPTS on PVM (55.3M cyc); a 256-col verify ACCEPTS (83.0M cyc) once the arena is raised 192MiB→1GiB. ⇒ **Track-A on-chain verify is NOT blocked** (size the arena to the proof; only the 31-component reconstruction guest remains unbuilt — engineering, not a wall). **WALL 1 — instructions:** residual = cycles − N_perm·15,808 scales LINEARLY in committed width, residual ≈ 5.5M + **23,215·W** (R²≈0.999; ≈498 cyc per column×query DEEP-quotient combine — physical), base(L)≈5.63M+850k·(L−12). Extrapolated to a real child (15,775 cols, L17): residual_real ≈ **303–376M cycles/child** ⇒ join (2 children) ≈ **606–752M retired instr** vs the single-segment budget ~400k ⇒ **~1,500–1,900× over (~3.2 orders of magnitude); required join segment log ≈ 32 vs the log-21 ceiling.** This is ~5–10× WORSE than the analytic floor above (real per-combine ≈498 cyc, not the floor's 10–90). **WALL 2 (NEW, independent) — memory:** the verify's PEAK live set scales ≈**2.18 MiB/column** ⇒ a real child ≈34 GiB, a join ≈**69 GiB**, vs the PVM's ~2 GiB PC-relative-reloc-bounded arena. Demonstrated concretely: **W=1024 (peak ~2.2 GiB) already cannot allocate on the PVM** (0xDEAD at the arena cap) — the join literally cannot hold its working set. Both walls are conservative LOWER bounds (WideBoolEval's simple single-mask constraints under-count the real OODS re-eval). Data points (L=12, pool allocator): (W1: N3195, 56.1M cyc, resid 5.63M), (W256: N4542, 83.0M, 11.19M), (W512: N5861, 110.1M, 17.50M); never-free cross-check (≈zero alloc overhead): per-col residual 18,658. Verdict RED is now anchored FOUR ways: combinatorial floor, 3-reviewer consensus, the instruction wall (~2000×), and the memory wall (~69 GiB). **⇒ STRATEGIC FORK (the user must decide — see [[project_recursion_completion_plan]]): native FRI-STARK recursion cannot give Track B a constant-size 76→1 aggregate; the recursion must verify a NARROW proof. Options: (A) SNARK WRAPPER (Groth16/Plonk/Halo2 — constant-size cheap-verifier wrap each base proof, then aggregate; re-opens the Groth16 question the memo deferred); (B) FOLDING (Nova/ProtoStar/HyperNova — O(1) per-step IVC); (C) cheaper PCS (KZG/multilinear, O(1)-O(log) opening verify — kills FRI's Θ(queries×columns) DEEP step); (D) non-recursive Track B (drop the single-aggregate goal).** **Track A (single light voucher segment, on-chain, NO recursion) is UNAFFECTED and remains DONE** (only the heavy federation 76→1 aggregation hits the wall). The CL.* recursion line (252 commits) validated a great deal but the FINAL Track-B aggregation needs a different primitive. Workflows: cost-model+review `ww938sy1u`. Throwaway measurement instrumentation reverted (preserved in scratchpad); NO src change landed — this is a DOC/measurement verdict commit (like CL.5a's RED).
- **CL.F** (conditional, XL — SUPERSEDED by the make-or-break RED above): LIFT Form B (Poseidon2-M31 accelerator chip + `join_verify` guest) does NOT close on its own; gated on the strategic-fork decision.

### Track-B PIVOT — aggregation primitive  *(SCOPED 2026-06-30 — 8-agent design+3-lens-review workflow `wwvhf7443`; user chose "scope the primitive pivot")*
**RECOMMENDATION (synth + UNANIMOUS 3-reviewer endorsement of the DIRECTION, verdict "has-gaps" ×3 = sound-but-tighten):** **Option A — a STARK→SNARK WRAP producing a CONSTANT-SIZE PAIRING proof for the Track-B 76→1 aggregation ONLY.** Keep the 31-chip M31 Circle-STARK for all 76 base segments AND for Track A unchanged (one base prover, M31 speed + transparency preserved there). **The decisive structural finding (homomorphism criterion):** the measured wall is Θ(n_queries × committed_columns) because the FRI/Merkle commitment is NON-homomorphic — you cannot linearly-combine 15,775 Merkle roots, so soundness forces revealing+combining every column at every query. ONLY a HOMOMORPHIC commitment (pairing/KZG/Pedersen) collapses the 15,775 column commitments into ONE (a single server-side MSM, no per-query factor) + one O(1) opening. ⇒ **(C) "cheaper PCS" splits: C2 (KZG/homomorphic) = Option A under another name (escaping forces leaving M31 ⇒ a pairing wrap); C1 (transparent FRI-family: WHIR/STIR/Basefold/Binius/Brakedown) KEEPS the wall — only shaves constants (~10× vs the ~2000× gap) AND stays polylog-not-constant ⇒ DEAD for this deliverable.** (B) folding is dominated: its final on-chain artifact still funnels through a pairing decider (same verify cost) while adding cycle-curve+decider machinery; and B(ii) (rebuild the VM as a Nova step circuit) discards the 31-chip base prover (violates "one base prover, Track A unchanged"). **The escape is REAL and structurally distinct from the dead native recursion:** the Θ(width×queries) cost RELOCATES into the SERVER-SIDE wrap circuit (~1e8–1e9 constraints/child, paid ONCE per leaf, embarrassingly parallel, charter-permits-heavy), the certificate SHRINKS to constant-size at the wrap boundary, and verifying a constant-size SNARK in the next layer is O(1) — it does NOT compound up the depth-7 tree (unlike K-split). Flip the durable "no Groth16" memo — SCOPED to "pairing-SNARK is the Track-B aggregation wrapper; base + Track A stay STARK" — but ONLY after the gate below is GREEN. JAM-PVM final verify = ~3–4 Miller loops + final-exp + a public-input MSM = O(1) in the 76, O(1) RAM (the deliverable bar: ~hundreds of bytes vs 3 MiB/segment, cheaper than verifying ONE raw STARK segment ~1.7B cyc).
**THE REVIEWERS' LOAD-BEARING REFINEMENTS (fold in BEFORE any prover investment):**
1. **THREE walls, not one — and the named spike tests the EASIEST.** W1 = final pairing-verify cheap on JAM PVM (industry runs Groth16 verify everywhere ⇒ lowest risk). **W2 = build ONE child's STARK-verify relation as a BN254/BLS12-381 circuit at feasible constraint count — the BESPOKE circle-STARK-over-M31 + Poseidon2-M31-Merkle gadget, NO off-the-shelf template (SP1/RISC0 wrap BabyBear/Goldilocks NON-circle FRI) — the REAL "secretly-doesn't-close" unknown, dominated by re-hashing the 88,600 Poseidon2 permutes IN-circuit (~2e8–1e9 constraints).** W3 = aggregate 76 wrapped→1 (itself a SNARK recursion: in-circuit pairings / cycle-of-curves). **W2 is equally cheap (host-only constraint count) and MUST run in PARALLEL with W1, not gated behind it.**
2. **The "narrow thing" axis was DROPPED — and it may be CHEAPER + lower-risk.** The fix-required line was "verify a NARROW thing OR cheap opening"; the analysis pursued only cheap-opening (→ pairing). **(D2) a custom NARROW VOUCHER-transition AIR (hundreds, not 15,775 columns) ⇒ native TRANSPARENT FRI recursion CLOSES** — NO trusted setup, NO field change, NO PQ loss, NO pairing-on-PVM gate, reuses the WHOLE M31/Poseidon2/FRI stack + the Track-A on-chain verifier. The honest blocker = generality (the PVM proves arbitrary actors at 15,775 cols) vs Track B being VOUCHER-SPECIFIC. **PROBE D2 FIRST (~3–5 days host-only): measure the minimal voucher-transition AIR width.** If narrow, it moots Option A's entire trusted-setup + bespoke-prover cost.
3. **The RED-fallback (a pairing-accelerator chip) is ILLUSORY on-chain** — the final verify runs on JAM's FIXED PVM as guest code; you CANNOT add precompiles to JAM's verifier VM (the accel-chip escape only works on the team's OWN prover-side zkVM). ⇒ **W1 is a HARD BINARY gate: enumerate JAM's host-function surface for bigint/pairing FIRST; if none and W1 RED, the pairing family is OUT for on-chain** (fall to D2 or non-constant Track B).
4. **Curve + reuse reality:** the in-tree vendored arkworks/blst is **BLS12-381** (JAM's own curve; ~1.5–2× heavier than BN254 — 381-bit/6-limb), and **blst is HOST-ONLY C (won't cross-compile to riscv64em-javm guest)** ⇒ W1 must port NEW pure-Rust no_std no-atomics pairing into the guest (several days, real toolchain risk; the settle HARNESS reuses, the pairing CODE does not). Pin the curve before W1; measure BOTH Groth16 AND Plonk-KZG (the trust-acceptable Plonk universal-SRS is the MORE expensive verify — if IT busts the budget you're forced into per-circuit Groth16 ceremonies = a governance call for a money system).
5. **Recursive NARROW aggregation is PRIMARY, not one-shot-76** (which SUMS to a 1e10–1e11-constraint monolith no prover holds, SOTA ~2^24–2^28). **DROP the "pre-compress a la SP1/RISC0" fallback language — that IS STARK recursion = the dead path (circular).** Commit to wrap-each-child → aggregate-narrow.
6. **PQ forfeiture is UNPRICED** (A's pairing verify is NOT post-quantum; FRI is — a real regression for long-lived on-chain money the rubric never tallied against A) and **soundness-faithfulness of the STARK-verifier-in-circuit is CO-PRIMARY** (a Groth16 sound about the WRONG statement = total silent loss) ⇒ a differential host-vs-circuit equivalence harness GATES W2/S4/S5.
**RE-SCOPED MEASURE-FIRST RE-PLAN (each landable; gates before any heavy build — the discipline that settled CL.F):**
- **TB.0 — D2 PROBE (do FIRST, ~3–5 days, host-only):** measure the minimal voucher-transition AIR width (which chips a real voucher transition actually activates vs the canonical 31). If narrow ⇒ native transparent recursion may close ⇒ re-evaluate vs Option A (could avoid the whole pairing path). GATE: voucher AIR width.
- **TB.1 — W1 PAIRING-VERIFY-ON-JAM-PVM SPIKE — ✅ DONE 2026-06-30: GREEN (directly measured + independently reproduced).** Host-fn surface confirmed: the JAVM `Ecalli` exits to `HostCall(u32)` (embedder-dispatched), the JAM verifier VM has NO pairing/bigint builtin and is FIXED (no chip escape) ⇒ a pairing verify is PURE GUEST software. **Buildability (the feared toolchain risk): CLEAN — arkworks 0.5 (`ark-bls12-381`/`ark-bn254`/`ark-ec`/`ark-ff`/`ark-groth16`, all `default-features=false`) built for `riscv64em-javm` on the FIRST try, NO new atomic shims** (the existing `pvm_atomic_shim` + `-Zbuild-std` compiler-builtins covered it; `ark-ec` gates `ahash` on `target_has_atomic` w/o getrandom; `ark-ff-asm` emits x86 asm only ⇒ portable path on riscv). Measured on the settle harness + lean step-count runner: **Tier-1 microbench cyc/pairing = 23.03M (BLS12-381) / 10.56M (BN254)** (slope N=20→120, ~27-cyc fixed overhead). **Tier-2 DIRECT Groth16 verify (real ark-groth16 proof+vk, a·b=c, 1 public input, accepted a0=0xACCE): BLS12-381 = 51.8M cyc / 0.15 MiB peak (62 % of the 83M envelope, 0.007 % of the 2 GiB arena); BN254 = 26.7M cyc / 0.11 MiB.** (Groth16 verify ≈ a 3-pair Miller loop + 1 final-exp + 40 KB PVK decompress ≈ 2.25 pairings; O(1) RAM.) **VERDICT: a constant-size pairing-SNARK final verify is VIABLE on JAM's fixed VM as pure guest software, with ~38 % headroom on the in-tree BLS12-381 curve — no precompile/chip escape required.** ⇒ Option A's HARD BINARY GATE is GREEN; the verify-side wall is cleared. Caveats: measured with 1 public input — keep the real circuit at a SINGLE HASHED PI (else the G1 MSM grows); Plonk-KZG verify (universal-SRS, the trust-acceptable option) is HEAVIER than Groth16 and was NOT measured — measure it before the trust-vs-cost call. **W1 GREEN is necessary-not-sufficient: the REAL unknowns are W2 (the server-side wrap-circuit constraint count + the bespoke circle-STARK-over-M31 + Poseidon2-M31-Merkle gadget) and the D2 alternative (TB.0).** Harnesses preserved in scratchpad (`tb1-arkworks-cargo.patch`, `pairing_bench.rs`, `groth16_verify.rs`, `tb1_bench_run.rs`); throwaway, reverted to a clean tree.
- **TB.2 — W2 SINGLE-CHILD VERIFY-CIRCUIT CONSTRAINT COUNT — ✅ DONE 2026-07-01: AMBER (buildable only as lookup-Plonkish + recursive-narrow; one child at the single-machine EDGE).** MEASURED exactly via an arkworks-R1CS scratch crate (`ark_relations` `ConstraintSystem` over BN254 `Fr`, `cs.num_constraints()`): **M31 mul+reduce = 65** (1 `mul_equals` a·b=q·p+r + two 31-bit range checks @32 each; adds + mul-by-const are FREE linear combos — only the range checks cost), pow5 = 195, ext/int-MDS reduce = 41/50. **C_perm = 44,138 R1CS-conservative** (27,690 S-box intrinsic lower bound) **vs ~1,982–3,186 lookup-Plonkish** (range check ~3–5 rows not ~31). **child_constraints (88,600 permutes ~90% + DEEP 681k×9 M31 ~9% + FRI <1%): R1CS ≈ 4.35e9 vs lookup ≈ 1.96e8–3.16e8.** **VERDICT vs the single-machine Groth16 ceiling ~2^28≈2.68e8:** one-shot-76 INFEASIBLE both ways (R1CS 1231× / lookup ~60× over) ⇒ **recursive-narrow aggregation MANDATORY** (reviewers vindicated); **single child R1CS/Groth16-prove DOES NOT FIT (16.2× over)** ⇒ a pure-Groth16 wrap is un-buildable for even ONE child; **single child lookup-Plonkish FITS but BORDERLINE (0.73×–1.19× the ceiling, ZERO margin at the realistic 3,186/perm).** ⇒ **Option A is buildable ONLY as: lookup-based Plonkish (halo2/Plonky3-KZG-over-BN254 with a range-check lookup argument) per-child wrap (~3e8 rows, ~tens-of-GB SRS, ~minutes–1h each, ×76 PARALLEL) → cheap recursive SNARK→SNARK narrow aggregation (2:1 fan-in) → a FINAL Groth16 compression for the O(1) on-chain verify** (TB.1's 51.8M-cyc Groth16 verify applies to that LAST step; note the per-child/aggregation layers use Plonk-KZG, whose verify is heavier than Groth16 — only the final compressed proof is Groth16). NOTE the tension with TB.1: Groth16 has the cheapest VERIFY (TB.1 green) but can't fit the PROVE; lookup-Plonkish fits the prove ⇒ the standard SP1/RISC0 pattern (Plonkish/recursion for the heavy part, final Groth16 wrap for the cheap on-chain verify). **RISKS:** (1) the lookup figure is an ESTIMATE not a measured halo2 circuit — at realistic 3,186/perm a child is 1.19× the ceiling (slightly OVER) ⇒ a halo2 range-check benchmark must DE-RISK before committing (the next measurement). (2) **Soundness-faithfulness is the DOMINANT risk** — NO off-the-shelf wrap template (SP1/RISC0/Plonky3 wrap BabyBear/Goldilocks NON-circle FRI + different hashes; none port to circle-STARK-over-M31 + Poseidon2-M31-Merkle/FRI/OODS); the in-circuit verifier must reproduce the stwo transcript/FRI-fold/DEEP-OODS BIT-FOR-BIT or it's a silent soundness hole. (3) RAM is the binding prover constraint, at the single-machine edge ⇒ argues for SMALLER base segments (→ strengthens the TB.0/D2 narrow-AIR case) or 2:1 recursion. Scratch crate in scratchpad (`tb2/`); repo tree untouched. **NET: Option A is FEASIBLE but heavy + edge-of-machine + soundness-critical-bespoke ⇒ the cheap TB.0/D2 probe (narrow voucher AIR ⇒ native transparent recursion, avoiding ALL of this) is now even higher-value.**
- **TB.3 — freeze the wrap STATEMENT** (re-express the in-tree soundness machinery as PI layout + constraints: 4-field seam pc/registers[13]/timestamp/memory_root + mid-pin, {C_0,C_1} allowlist, entering-image anchor, aggregate-PI endpoints; SINGLE hashed PI). **TB.4 — single-child wrap** (first real wrapped proof verified on PVM; + the differential equivalence harness). **TB.5 — aggregate 76→1 via recursive-narrow-aggregation** (bind seam/allowlist/anchor/PI across ALL 76 — the K-chain soundness rule). **TB.6 — flip the "no Groth16" memo** (scoped), citing the measured gate.
**SALVAGE of the 252-commit recursion line: ~80% retired** (CL.2–CL.5 native-FRI-recursion machinery unused by a SNARK wrap) — but the **boundary-binding soundness DESIGN (4-field seam, {C_0,C_1} allowlist, entering-image anchor, aggregate-PI) is REUSED as the wrap STATEMENT's spec + public inputs**, and `verify_standalone`/the settle PVM harness carry over. Workflow: `wwvhf7443` (note: the A-deep-dive + B-deep-dive ground agents failed on output-schema; the homomorphism criterion + the 3 reviews carried the conclusion — a fuller A/B re-run is optional, not blocking). FULL detail = the `wwvhf7443` task file.

### Track-B SOTA SURVEY — the option we were missing: SUM-CHECK/GKR  *(2026-07-01, 9-agent web-grounded research + 3-lens review `wds1nuvts`; user asked "what's SOTA, better options we're missing?")*
**THE REAL MISS = the general-purpose zkVM field pivoted OFF wide univariate FRI onto SUM-CHECK / MULTILINEAR proving to escape EXACTLY this width wall — now IN PRODUCTION + AUDITED (SP1 Hypercube = LogUp-GKR + Jagged PCS, live on Ethereum mainnet 2026, ~5× faster).** WHY it's the structural cure (not a relocation): **a sum-check/GKR verifier is WIDTH-INDEPENDENT — O(log width), not Θ(15,775 cols)** (FRI forces revealing+recombining every column at every query; sum-check does not), and **Jagged PCS (eprint 2025/917) commits the ENTIRE variable-height multi-table trace as ONE multilinear** instead of 15,775 separately-committed columns (its authors name the exact failure: "large overhead in verification costs, especially in hash-based systems" from committing columns separately). ⇒ **"FRI recursion is dead" is true of FRI, NOT of STARKs; sum-check STARKs over M31 are alive/fast/audited.** This is the one mechanism that removes the ROOT CAUSE, and it's the option the Track-B analysis never weighed (folding + transparent-FRI-family were ruled out; a sum-check RE-ARITHMETIZATION was not). **COST: a BASE re-architecture, not a bolt-on** — the recursion must verify the base, so you can't fix recursion without making the BASE cheap-to-verify (FRI→sum-check/Jagged). Two flavors: (a) port Jagged-PCS + LogUp-GKR onto the circle-M31/QM31 base (keeps Poseidon2-M31 + the boundary-binding soundness DESIGN; research-grade port, no audited circle-M31 template yet), or (b) adopt SP1/Ceno's stack wholesale (discards circle-M31, buys audited tooling). Multi-quarter either way. **NOT the answer (3-lens review, verdict recommendation-broken ×2, caught the workflow synth re-proposing a DEAD path):** (1) a "native narrow M31 recursion AIR" IS the CL.1–CL.5a line — already MEASURED to DIVERGE 2.3×/level in WIDTH (CL.5a octet, log 18→19→20 monotonic; in-AIR STARK self-verify is succinct in LENGTH, LINEAR in WIDTH); the workflow's "never measured / Starkware-1min→3s-proves-1000×-cheaper" was WRONG (Starkware's is a NARROW closed Cairo circuit; its ~1000× is a LENGTH effect that doesn't touch the width divergence) — the proposed "measure first-lift row-count ≤2^24" spike is non-decisive (first-lift already log 17; the killer is multi-LEVEL width growth, already RED at CL.5a). (2) DO NOT FOLD — Nexus (this project's ORIGIN) ran a full Nova/HyperNova folding zkVM, hit the pains (Merkle-trie memory, non-native Grumpkin, KZG setup), and in MARCH 2025 RETREATED to a transparent Stwo-over-M31 STARK + wrap-SNARK = CONVERGED onto this project's current stack; folding's cheap decider is the SAME pairing SNARK anyway (only edge = fast incremental prove, at the cost of discarding everything). **CORRECTIONS to the workflow synth (from review):** Option A is NOT "infeasible regardless of setup" — TB.2 measured it AMBER-FEASIBLE (the SP1/RISC0 pattern), the shippable general-purpose fallback; the terminal wrap is SHARED by every option + SOLVED (TB.1: use FIXED-FUNNEL Groth16/BLS12-381 = the only MEASURED pure-guest verify at 51.8M cyc; fflonk is a GATED upgrade — Substrate does pairings via HOST functions that DON'T exist on JAM's fixed guest, unverified there; BN254's 26.7M = ~100-bit post-exTNFS = a security downgrade for money). **TWO FIRST-ORDER FORKS the review surfaced (user's call):** (i) **POST-QUANTUM** — every pairing terminal forfeits PQ (the FRI base has it); if PQ is a hard requirement for a long-lived voucher/settlement system, the entire cheap-pairing-terminal premise collapses + re-ranks everything (the transparent alternative WHIR is ~5.65M-gas-class / ~7-20× Groth16, blows the ~83M-cyc envelope). (ii) **DO YOU NEED THE AGGREGATION TREE?** — STREAMING PROVERS (Jolt Twist & Shout 2025) prove arbitrarily long executions in <2 GB RAM WITHOUT recursion; if the only Track-B driver is LONG PROGRAMS (not parallel-proving throughput or a mandated single on-chain proof), a streaming prover sidesteps the tree + the K^depth divergence + the memory wall entirely — CONFIRM THE DRIVER before committing to a tree. **RESEARCH-WATCH (not build-now):** ARC (2024/1731) / WARP (2025/753) group-free accumulation of the FRI/RS proximity claim = the most reuse-preserving research bet (keeps the M31 base, swaps only the aggregation layer; paper-stage, no zkVM-scale impl); STIR/WHIR cut FRI queries (linear shave of the wall, not a close); and track Nexus×Stwo aggregation (same base, solving the same problem now). **NET: the SOTA escape from the width wall for a GENERAL zkVM is sum-check/GKR (multi-quarter base re-arch); Option A stays the near-term shippable fallback; the two forks (PQ, streaming-vs-tree) should be answered before committing.** Full detail = the `wds1nuvts` task file.

**KEY GAPS the adversarial panel raised (verdict "has-gaps" ×3 — fold these in BEFORE building):**
1. **The make-or-break is the CONVERGENCE number, and it's UNMEASURED + on a different shape than CL.2.** CL.2 over BASE segments measures the LEAF level (inner AIR = the 31-chip machine); the fixed point needs the INTERIOR join verifying JOIN-shaped children (inner AIR = `ChildPairEval` itself, the self-ref embed at CL.4). The "99.5% hash-dominated, flat cost" stability claim was measured for `ChildFullEval` verifying a 31-chip MACHINE, NOT a join verifying a JOIN proof. The binding cost is per-query decommit WIDTH (columns opened), and the interior join may be WIDER than a base segment → divergence (L'>L) is possible. **Measure level-2 vs level-1 delta early (a spike before sinking CL.5); report `deep.terms.len()` + `lay.n_rows`, not just log_size.**
2. **Some LIFT/normalization is STRUCTURALLY REQUIRED, not just a >log19 fallback.** base=31-component, join=1-component; one fixed-mask component cannot verify both. So the interior join consumes leaf-adapter children at level-1 and join children at level-2+ = TWO inner AIRs. PRIMARY DECISION (resolve before CL.2): a single MODE-GATED AIR carrying both constraint sets, vs a RISC-Zero-style LIFT-NORMALIZER mapping base segments into the join's shape so the interior only ever embeds ONE inner AIR (itself). The "uniform primary / lift contingent" framing is partly inverted.
3. **Seam pc/timestamp are NOT injectively bound to the child's STARK** (registers + memory_root ARE). `program_boundary` is a SINGLE difference-of-inverses over un-range-checked limbs at one claimed-sum slot `pos[2]`; a prover can forge a common `(pc,ts)` into both children (splice pc-discontinuous executions) — `ChildFullEval` does NOT replay the boundary mix, so nothing else pins pc/ts. **DECISION: (a) replay the boundary mix in-AIR (`is_bnd_mix` selectors binding witnessed boundary cols to the transcript — cleanest, makes the mix load-bearing, no format bump); (b) restructure `program_boundary` into two injective terms (base-machine change + PROOF_FORMAT_VERSION bump); or (c) drop pc/ts from the seam/security claim (document unbound like `memory_commitment`).** Plus range-check the witnessed boundary limbs.
4. Per-child logup balance must be INDIVIDUALLY pinned (the +X/-X cross-child cancellation passes a global Σcs==0): the mid-pin is mandatory and is INCOMPATIBLE with column-interleave; two-cumsum-in-one-component is unproven on this stack (fallback: two interaction-column sets + a hand-rolled second finalize).

**OPEN DECISIONS (surface before the dependent step):** interleave start (row vs column); the PRIMARY architectural fork (mode-gated vs lift-normalizer, gap #2); seam field set + pc/ts binding (gap #3); the CL.4 fallback threshold (log 19 hard ceiling vs a log-20 server-side interior acceptable for Track B); CL.F strategic-pivot pre-approval; file placement (`ChildPairEval` inside the ~6000-line `recursion_child_full.rs` to reuse private helpers, split later). FULL workflow output: `wernuy93h` task file.

**START HERE (CL.1 DONE → CL.2):** build ONE `ChildPairEval` `FrameworkComponent` over two BASE segments, ROW-interleaved (child0 rows `[0,n)`, child1 `[n,2n)`, n=2^17 → log 18), reusing the per-row `ChildFullEval` body. The boundary is already witnessed (CL.1), so the seam is `is_child0_last·(child0.final_col[k] − child1.init_col[k]) == 0` over the 4 fields (deg-1, both AIR-bound). Add 3 selectors (`not_child_last`/`is_child0_last`/`is_global_last`), the `not_last→not_child_last` swap (~15 sites, per-site negatives), the per-child channel re-anchor + digest-chain break at the n−1→n boundary (`fixed_point_join.rs:316-326`), fold both DEEP balances into ONE pinned-zero claimed_sum with the `is_child0_last·cumsum==0` mid-pin, the in-AIR allowlist at `rl[0]`, and aggregate-PI. Gate `recursion_pair_gate` (accept; per-field broken-seam reject; out-of-allowlist reject; tamper reject) and PRINT the leaf-join log/RSS. Then strengthen pc/ts binding via in-AIR boundary-mix replay (the gap #3 decision). Heaviest open unknown remains CL.4's self-ref OODS log (the convergence gate).

**CL.2 interleave mechanics — GROUNDED 2026-06-26 against `fixed_point_join.rs` JoinEval (the synthetic prior-art) + the live `ChildFullEval`.** Substrate = ONE `FrameworkComponent` over a DOUBLED domain (log 17→18), block layout: child0 = logical rows `[0, 2^17)`, child1 = `[2^17, 2^18)`; each logical row `r` writes to storage `storage_index(r, 18)` (JoinEval gen builds in logical order, indexes storage — no inverse needed; the real version stitches two log-17 child traces by reading each col at `storage_index(r,17)` and writing `storage_index(c·2^17+r, 18)`, for main + interaction + preproc). KEY SIMPLIFICATION: `ChildFullEval::evaluate` uses `not_last` (~30 sites) + `not_last_tr` (digest chain) + `ch_is_first` (digest=0 anchor) — all read by ID at the top, so interleaved mode just REBINDS those three variables to per-child preproc columns (`not_child_last` = 1 except each child's last row; a per-child `not_last_tr`; `is_child_start` = 1 at each child's row 0) ⇒ all 30 sites switch with no per-site edits. New selectors: `is_child0_last` (row 2^17−1) for the seam, `is_global_last` (row 2^18−1). The digest chain breaks per-child via the `not_last_tr`/chain rebind (JoinEval's `chain_ok`). SEAM (CL.2b) = `is_child0_last·(final_*[0] − init_*[1]) == 0` over the 4 WITNESSED CL.1 boundary cols, comparing child0.final (held in `[0,2^17)`) at row 2^17−1 to child1.init (held in `[2^17,·)`) at row 2^17 via a `[0,1]` mask — no separate seam columns needed. TWO-BALANCE: the single interaction cumsum runs across both halves; honest combined = 0 (the existing d.3 pin) suffices for the PLUMBING de-risk (CL.2a), but SOUNDNESS needs the per-child mid-pin `is_child0_last·cumsum == 0` (prevents +X/−X cross-child cancellation, reviewer gap #4) — row-interleave-specific (incompatible with column-interleave). Per-child PREPROC NAMESPACING is a NON-issue here (unlike the S5a two-component path): one component holds per-half preproc values positionally in the same column ids. **CL.2a-step1** (make-or-break, identical children, no seam/mid-pin): stitch + rebind + prove ONE component at log 18 + a light `recursion_pair_air_satisfied` oracle. Then CL.2a-step2 (mid-pin + +X/−X negative) → CL.2b (seam + genuine non-chaining negative) → CL.2c (allowlist) → CL.2d (aggregate-PI + boundary-mix replay) → CL.2e (`recursion_pair_gate`).

### Session 6 — SETTLEMENT (P6)  *(~1–2 sessions)*
**Goal:** verify the aggregate (Track B) AND a single light segment (Track A) on JAM
PVM / Substrate; wire the settlement path; record final **on-chain gas + proof size**.

**S6 PART 1 — `recursion-verifier` PVM BUILD UNBLOCKED**  *(2026-06-24, `93dd6463`, LOCAL)*  ✅
The S1 wall (`max-atomic-width:0` → no atomics) is RETIRED — `recursion-verifier` now
compiles for `riscv64em-javm` (`librecursion_verifier.rlib`), wasm32 still green. Two
changes (smaller than the S1 guess — tracing-subscriber/rand/blst/rayon were NOT in the
verify build):
1. **stwo's only std-only verify-graph dep is `dashmap`** (→ crossbeam-utils + lock_api),
   used ONLY under the already-`#[cfg(feature="prover")]`-gated `pub mod prover`. A
   vendored stwo (rev e1286720) under `recursion-verifier/vendor/` makes `dashmap` optional
   + prover-gated (ONE Cargo.toml change; wired via `[patch]`). default-features=false ⇒ it
   leaves the graph. (No verifier *logic* touched.)
2. **Atomics:** JAM PVM is RV64EM with NO `a` ext (JAVM decodes no lr/sc/amo), so native
   `+a` compiles but won't run. Target now sets **`max-atomic-width:64` WITHOUT `+a`** ⇒ the
   residual `core::sync::atomic` loads (foldhash seed, tracing-core callsites) lower to
   `__atomic_*` LIBCALLS, not instructions. Build references only `__atomic_load_{1,8}`,
   provided as single-core plain-load shims (`pvm_atomic_shim`, gated `target_os="none"`
   riscv64). This is the runtime-correct single-core route.

**S6 PART 2 — real constants + settlement ELF**  *(2026-06-24, `a8bdd291`, LOCAL)*  ✅ (a)+(b) done
(a) **Settlement ELF LINKS.** A `#![no_main]` `settle` bin (feature `pvm-settle`; bump
allocator + panic handler + `_start` pinning `verify_segment`'s symbol graph) links into a
complete PVM ELF — `settle.elf`, RISC-V RVE, statically linked, **zero undefined symbols**.
The full link surfaced the rest of the atomic-libcall set beyond loads
(`__atomic_store_{1,8}` + `__atomic_compare_exchange_{1,8}` — foldhash seed CAS + tracing-core
stores), now all single-core shims. (b) **Round constants SYNCED** — the placeholder `1234`
arrays in `recursion-verifier/src/lib.rs` replaced with the prover's canonical Grain-LFSR
(128 external + 14 internal, verbatim from `poseidon2/mod.rs`); must stay byte-identical.

**`settle.elf` TRANSPILES CLEAN to JAM PVM bytecode** (`03ec564a`): `grey_transpiler::link_elf`
succeeds (399 KB ELF → 17 MB PVM blob), the bytecode-level proof that every instruction is
JAVM-executable — the `max-atomic-width:64`-without-`+a` + single-core `__atomic` shim route
leaked NO atomic instructions. So the verifier is PVM-runnable at every level short of
execution (build → link → transpile all green, real constants). Test:
`zkpvm/tests/settle_transpile.rs`.

**S6 PART 3 — the verify EXECUTES on JAM PVM**  *(2026-06-24, `23cf39d8`+`88994e47`, LOCAL)*  ⚠ runs, one trap to chase
The settlement verify now RUNS on the PVM, not just builds. `settle.elf`
`include_bytes!`es a postcard `StarkProof<P2MerkleHasher>` fixture (a trivial boolean AIR,
produced + roundtrip-validated host-side by `tests/settle_fixture.rs`), `_start` calls
`verify_settlement_proof` (postcard decode → rebuild component + `CommitmentSchemeVerifier`
→ `verify`), and the tracing interpreter executes **~504,356 cycles of real verify** (FRI +
Merkle decommit + OODS) — `tests/settle_run.rs`. Driver + dummy-serde `P2MerkleHasher` live
in `recursion-verifier` (build host + PVM); atomic shims extended (store/cas/exchange/
fetch_or/fetch_and). **KNOWN GAP:** the run halts on a DETERMINISTIC mid-verify trap — NOT
allocator-bound (192 MiB ≡ 512 MiB arena → identical stop cycle), so it's an in-verify
panic/abort (host-vs-PVM numeric/codegen divergence or a grey-transpiler instruction quirk),
not OOM. Reaching the clean ACCEPT + the final cycle/gas number is the last step. (Host
roundtrip already proves verify logic + wire format: honest accept / tampered reject.)

**TRAP DIAGNOSED (2026-06-24) → grey-transpiler MISCOMPILATION** (a corrupted value /
control-flow deep in the verify), NOT a crypto/logic/runtime fault. Ruled out by
instrumentation: NOT OOM (192 MiB ≡ 512 MiB arena → identical stop cycle); NOT a Rust panic
(`#[panic_handler]` never reached); NOT alloc-failure (bump-overflow branch never taken);
NOT stack overflow (sp moves only 8 bytes from its `0x10000` reset). The run aborts via a
`JumpInd` at blob pc ≈`0x23f5` into the trap trampoline, registers holding garbage
`0xFFFFFFFF_xxxx`. This is the documented grey-transpiler bug class
([[project_messaging_pvm_transpiler_bug]]: CALL_PLT branch-target leak + peephole
load-imm/ALU mis-fusion — fixes existed uncommitted in jar.git; unclear if in the pinned rev
`6075cec`).
**UPDATE 2026-06-24 — step (1) DONE + remaining bug PINPOINTED.** The pinned rev `6075cec`
WAS missing the 3 grey-transpiler fixes (CALL_PLT, load_imm+ALU, load_imm+load), which land
linearly after it at `c91e83c1` (jar master, superset incl. the SLT fix). Bumped zkpvm's
grey-transpiler `6075cec → c91e83c1` (commit `acbeb9b6`) → the verify's stop moved from
~5.0e5 → **~1.1e6 cycles** (confirms the cause), but it STILL aborts on a **LATENT bug of the
same class**. PINPOINTED by reading the source: `grey-transpiler/src/riscv.rs`
`translate_store` Case 1 (≈L680) truncates the fused `load_imm` WITHOUT (a) the
`address_map.insert(addr, undo_pos)` the fixed `translate_load` does (≈L614-616) — so a
branch targeting the store lands mid-instruction — AND (b) any dead-after guard (a store does
NOT overwrite its base `rs1`, so the base constant can still be live; `translate_load` only
fuses when `rd==rs1` ⇒ base dead). Same class in `translate_branch` (no address_map update)
and `peephole_fuse_load_imm_memory` (lib.rs:352, unconditional truncate).
**BISECTION ROUND 2 (2026-06-24) — RULED OUT the obvious latent sites; the remaining bug is
a DIFFERENT main-pass miscompilation.** Via a local-path `[patch]` of zkpvm → an edited jar,
tested each candidate against `settle_run` (stop cycle is a stable fingerprint, ~1.121e6):
- Added the `address_map.insert(addr, undo_pos)` fix to `translate_store` Case 1 + both
  `translate_branch` truncate sites (threaded `addr`, mirroring the fixed `translate_load`) →
  **NO change** (same stop cycle). So our trap is NOT a branch-target-mid-instruction at a
  fused store/branch.
- Disabled all three post-pass peepholes (`fuse_load_imm_alu` / `_memory` /
  `eliminate_dead_load_imm`) → **NO change** (1.121e6±36). NOT a post-pass peephole.
- Disabled `translate_store` Case 1 fusion entirely (the dead-after hypothesis) → **NO
  change**. NOT the store dead-after.
- Re-classified the post-bump trap: still a DIRECT abort (panic-handler NOT reached, alloc-
  overflow NOT hit, not my `halt`) ⇒ corrupted control-flow/value from some OTHER instruction
  lowering in the main translate pass.
**(The `translate_store`/`translate_branch` `address_map` fixes are still CORRECT for the
documented latent bug — worth landing in jar — they just aren't THIS trap.)**
**FINISH FROM HERE:** this now needs the principled tool the messenger used (see
[[project_messaging_pvm_transpiler_bug]]): a **block-level differential trace** — run the same
PVM blob and record `(block_pc, reg-hash)` per basic block, comparing a KNOWN-GOOD reference
against the actual, to find the FIRST divergence, then read the codegen for the RISC-V op at
that source addr. (For a transpiler bug there's no interpreter-vs-JIT oracle — both run the
same bad bytecode — so the reference must come from a correct RISC-V execution of the same
program, e.g. qemu-riscv or a host run of the same logic, mapped via the ELF reloc/jump table.)
The driver + embedded proof + run harness + the c91e83c1 bump are DONE; only this one
main-pass transpiler bug remains for the clean accept + final cycle/gas.

### S6 part 4 — DONE 2026-06-24: transpiler bug found + fixed → settlement verify ACCEPTS on PVM 🏁
**THE FINISH LINE IS REACHED.** Root cause: grey-transpiler's `translate_op_imm` left the
shift funct3 (1=SLLI, 5=SRLI/SRAI) in the `rs1==0` catch-all `_ => {}`, falling through to the
register path — and PVM has no zero register (x0 maps to reg 0 = **RA**), so `slli rd, x0, n`
shifted RA instead of 0. (`translate_op_imm_32` addiw/slliw/srliw/sraiw had **no** x0 handling
at all — same latent class.) Rust's stable `slice::sort` (driftsort) merge emits `slli a2, x0, 3`
as a **zeroing idiom**; the merge-cursor base became `RA<<3` instead of 0, mis-sorting `&usize`
slices → FRI query positions (`Queries::new` BTreeSet dedup) came out **under-deduplicated**
(38 raw → 37 instead of 28) → the lifted-Merkle verifier's `col_iter.next().unwrap()` panicked.
**FIX:** jar `grey/crates/grey-transpiler/src/riscv.rs` — both op-imm paths now materialize the
x0-source result directly (shifts → 0, addiw → sext32(imm)); 2 regression tests added; jar 50/50
green. **Landed cleanly (2026-06-25):** jar branch merged FF to **master** and pushed to origin
(`olanod/jar`) at **ec9debbe**; zkpvm's grey-transpiler pin bumped `c91e83c1 → ec9debbe` and the
temporary path-[patch] removed (vos `e41d6de3`). settle_run re-validated ACCEPTING via the GIT
pin (no local jar checkout, identical 10,677,169 cycles).
**RESULT (`zkpvm/tests/settle_run.rs`, clean ELF):** the Poseidon2-M31 settlement verify
**ACCEPTS** the honest fixture on the JAM PVM (a0 = φ7 = 0xACCE) in **10,677,169 cycles** — the
representative on-chain cost of an M31-algebraic settlement verify (build → link → transpile →
EXECUTE → ACCEPT). Was previously a deterministic abort at ~1.12M cycles.
**HOW IT WAS FOUND (durable method — reuse for the next transpiler bug):** (1) instrumented
panic handler surfaced the panic site via registers (link-time vaddrs don't survive `link_elf`;
runtime register values do); (2) a host build of the *same* verify (recursion-verifier is
host-buildable) ACCEPTED → confirmed PVM-execution-fidelity bug, not logic; (3) reduced to a
7.7k-cycle standalone repro (`std sort(&usize) n=24`); (4) **qemu-riscv64** ran the bare-metal
ELF to the `unimp` as a CORRECT reference (all sorts → 0 inversions); (5) a control-flow-edge
differential in **PVM-offset space** (qemu vs the tracer, aligned via a `GREY_DUMP_MAP` of
`address_map`, peepholes off so offsets stay exact) pinned the first divergent branch, then a
backward data-flow trace of the corrupted register reached `slli a2, x0, 3`. (Diff scripts +
method live in this session's transcript; the bridge/debug hooks were reverted before landing.)

**Fully closed (2026-06-25):** jar pushed (`olanod/jar` master ec9debbe) + zkpvm pin bumped off
the path-[patch]. (Optional next, separate from this Track-A finish line: a 500k-segment recursion
proof / Track B aggregate — S3→S5.)

---

### S6 part 4 — ORIGINAL SCOPE (now done; kept for the method) *(self-contained)*
**Goal:** localize the ONE grey-transpiler instruction-lowering bug that aborts the verify at
~1.121e6 PVM cycles (a direct abort = corrupted control-flow/value), fix it in jar, then
`settle_run` reaches the clean ACCEPT → record the FINAL cycle count + proof size = the S6
on-chain settlement-verify cost (the finish line). NO interp-vs-JIT oracle exists (both run
the same bad bytecode), so a reference must come from a correct RISC-V/host execution.

**Phase 0 — cheap phase-narrowing (do FIRST; no tracing; ~1 hr).** Regenerate the fixture
(`settle_fixture.rs`) with varied params + matching `recursion-verifier` consts, re-run
`settle_run`, watch the abort cycle:
- `n_queries` 38→1 (and `mobile_config` blowup 2→4): if the abort cycle SCALES with queries ⇒
  bug is in the per-query FRI-fold / Merkle-decommit path; if FIXED ⇒ OODS / composition /
  quotient eval.
- `FIXTURE_LOG` 5→4/6: does the abort scale with trace size? FRI-fold vs one-shot op.
- A different trivial AIR (2 cols / different constraint): if the abort is unchanged ⇒ bug is
  in shared FRI/Merkle code, not AIR-specific.
  ⇒ brackets the buggy PHASE before any instrumentation.

**Phase 1 — Rust-level checkpoint differential (the main tool).** The host build of the SAME
verify is the oracle (recursion-verifier builds for host; host run is correct). Instrument the
vendored stwo verify (`recursion-verifier/vendor/stwo/crates/stwo/src/core/verifier.rs` +
`core/fri.rs`) with a `checkpoint(id, hash)` folding a u64 checksum of key intermediates (OODS
point, each FRI layer's folded eval, claimed sums, decommitted leaf values) into a global
`static mut CK: [u64; N]`. Host run → the full checkpoint sequence. PVM run (aborts ~1.121e6)
→ read `CK` from `tracing.pvm.flat_mem` after the run (CK's addr from `nm settle.elf`; RW
vaddr ≈ flat_mem offset — verified: the 192 MiB arena mapped 1:1, seeded sp = data top
0xc05a000). The LAST PVM checkpoint matching host + the FIRST diverging one localize the bug
to one stwo op; add finer checkpoints inside it until it's one loop/expression. (Alt to the
flat_mem read: emit each checkpoint as a marker instruction with the checksum in a reg and
filter the step trace.)

**Phase 2 — instruction-level pin.** For the localized Rust expression: `objdump` the ELF
function (its RISC-V), map RISC-V vaddr → PVM pc via the transpiler's `address_map`/jump_table,
and diff the RISC-V semantics vs the PVM lowering for those instructions. (Block-level
`(block_pc, reg-hash)` PVM-vs-reference trace — per [[project_messaging_pvm_transpiler_bug]] —
is the heavier alternative; reference = qemu-riscv64 IF it supports rv64e/+e, else a full-rv64
build of the verify mapped across.)

**Phase 3 — fix + validate + land.** Patch the lowering in jar (local-path `[patch]` zkpvm →
`/home/daniel/src/jar/jar/grey/crates/grey-transpiler`; edit; `cargo test -p zkpvm --test
settle_run`). GATE: `settle_run` reaches ACCEPT (verify Ok → `halt(0xACCE)`), record final
cycle/gas + proof size. Then land in jar (+ the correct store/branch `address_map` fixes from
round 2), bump zkpvm's grey-transpiler pin off the local path.

**Durable facts to carry:** trap = direct abort (NOT panic/alloc/OOM/stack), stable at
~1.121e6 cycles, post `6075cec→c91e83c1` bump; RULED OUT (round 2): store/branch address_map,
all 3 post-pass peepholes, store-Case-1 dead-after fusion. Host roundtrip (`settle_fixture`)
proves verify logic + wire format are CORRECT (honest accept / tampered reject) ⇒ purely a
PVM-execution-fidelity bug. settle.elf build cmd in `recursion-verifier/.cargo/config.toml`.

**(historical START HERE — superseded by the above):** today's
`settle` `_start` only `black_box`-pins `verify_segment` — it does NOT call it. To run a real
verify + count cycles:
1. **Promote a `FrameworkEval` + verify driver into `recursion-verifier`** (it has the verify
   *primitives* — permute/hasher/channel/`eval_permutation`/`verify_segment` — but NOT a
   `FrameworkEval`, component constructor, or the commitment-scheme driver; those live in the
   tests against `recursion_common`, e.g. `recursion_q0_perm.rs`: build
   `CommitmentSchemeVerifier::<P2MerkleChannel>`, `commit(commitments[i], &sizes[i], channel)`
   per tree, draw, then `verify_segment`).
2. **Embed a serialized proof** — generate a `P2MerkleHasher` permutation-AIR proof host-side
   (the recursion building block) + its `sizes`/config, bincode-serialize, `include_bytes!`
   into the `settle` bin (add a no_std deser — bincode/ciborium). (Track A's raw-segment
   verify needs the FULL 31-chip AIRs, which this crate does NOT carry — that is a separate,
   heavier port; the permutation-AIR proof exercises the same expensive verify machinery
   — FRI verify + Poseidon2 Merkle decommit + OODS — so it yields a representative cycle
   cost for the on-chain M31-algebraic verify.)
3. `_start` deserializes → builds component + commitment scheme → calls `verify_segment` →
   halts accept/reject. **Run the transpiled blob on JAVM** (`grey_transpiler::link_elf` +
   the `Interpreter` / `zkpvm::actor::trace_blob`), **record cycles/gas**. Validate constants
   end-to-end (honest ACCEPT / tampered REJECT). (Native verify is ~35–88 ms / ~1.2–3 MiB —
   native ms is NOT the on-chain cost; cycles need the PVM run.)
**GATE:** the verify runs on JAVM with a recorded cycle/gas count, honest-accept/tampered-reject.
**This is the finish line.**

---

## Dependency graph (so re-ordering is safe)
- **S1 gates everything** (decides if S2 is needed, sizes S6).
- **Track A = S1 → S2 → (S6 single-segment verify).** Independent of S3–S5; can ship first.
- **Track B = S3 → S4 → S5 → S6 aggregate.** S3 (width) is a hard prereq for the S5b
  federation re-prove being affordable.
- **P5-perf (SimdBackend Poseidon2 commit)** appears in S2 (Track A RAM) AND speeds S5
  (federation re-prove) — do it once in S2, reuse.

## How to drive
Clear, then: *"continue session N"* (or *"continue session 1"* to start). I read this
doc + [[project_recursion_completion_plan]], do the START-HERE, gate it, commit, and
update the status table here + memory. If a session's measurements change the plan, I
adjust this doc and say so.
