# Spike 6a: the real wrap masked under variant (c), measured

Date 2026-10-18. Throwaway code, evidence for the slice-6 plan.

Tags: **[measured]** in this spike; **[est]** my arithmetic; **[read]** read in source; **[doc]** a figure from the design docs, not re-measured.

## 0. Answers

1. **(c) works on the real wrap, on the pin.** The wrap circuit (p2/qm31/h8 at 2^14/2^15/2^11, paired logup, degree 3), masked as (c) specifies, proves and verifies:
   - on the Blake2b-256 channel, at fold step 3 with affine DEEP batching;
   - at blowup 32 / 24 queries (shape A, 6b's recommendation, spike format number 39);
   - and at blowup 64 / 20 queries (shape B, number 40).

   It was run on the one-segment test kernel, on `areas` (3 segments) and on the window kernel (26 segments). The wrap's shape does not depend on the kernel (`LOG_SIZES` is fixed at [14, 15, 11]), so the three wraps cost the same.
2. **Budget gate: passed with room.**
   - Memory to prove: **3.45 GiB** of heap (3,531 MiB), against the 24 GiB gate.
   - JAM gas to verify: **115.8–118.7M** on the JAM-only host, against the 200M gate.
3. **Against the models:**
   - Gas, bytes and Wasm land on or below them.
   - Prover memory is ×1.41, as 6b's proxy predicted.
   - **Prover time is ×2.6–2.9, not (c)'s ×1.6** (§3). Blake2b-256 Merkle hashing over a leaf layer twice as large dominates the wrap's prover; in the toy, column LDE dominated.
4. **Format 32 is untouched.** The fixture stale test regenerates the leaf, fold and wrap fixtures and the statement fixtures (H_fold, program ids, wrap 28) byte for byte. It **passes** on the spike branch.
5. **Every tamper is refused by an error; no verifier panic was hit.** That covers 14 tamper cases, two salt-count mismatches, cross-format proofs, unbalanced blinding and two invalid witnesses.
6. **R1 runs on the real wrap in 16–39 ms.** It sees 80 revealed rows against h = 256 at q = 24, and 68 at q = 20. It never failed on about 30 transcripts. With h = 64 it refuses, as it should.
7. **R3 under affine batching needs a prover check (design change).**
   - The FRI mask's four base columns get four independent QM31 coefficients.
   - The mask hides the FRI layers iff those coefficients are M31-independent. That fails with probability about 2^-31, against 2^-62 under powers.
   - So the prototype's powers-based argument does not carry over.
   - Built: a prover-side 4×4 rank check with retry. It never fired.
   - The alternative is an 8-column FRI mask, where failure is about 2^-155 with no check.
8. **Surprise: shape A's preprocessed root is format 28's, byte for byte.** Columns extended to n+1 and evaluated at blowup 32 are the same evaluations as format 28's at n+6. The wrap's `PREPROCESSED_ROOT` constant does not change at shape A; shape B's does.

## 1. What was built (local branches, never pushed)

**Stwo fork:** `~/src/virto/stwo-s6-mask`, branch `spike/s6-mask` from `ab294189` (`vos/wrap`).
- The prototype was cherry-picked cleanly: `11623be`, `6558ec3`, `d1379bc`, `bb7439e`, `0c649c3`.
- `7379502`: the prototype's salts set to 8 columns (248 bits).
- `1c06864`: its tests name the `deep_batching` field the pin's `PcsConfig` carries; they did not compile on the pin.
- 15/15 prototype tests pass on the pin.
- No soundness-critical fork file is touched. The vos code uses only the fork's public API.

**VOS:** `/home/daniel/src/virto/vos/.worktrees/s6-mask`, branch `spike/s6-mask` from `vos-core` `31b7938e`. The `stwo` deps point by path at the fork worktree.
- `c95b46c9`: the masked AIR variant, prover, verifier and tests.
- `5227bf6c`: the kernel runs, R1/R3 over 20 verified transcripts, the no-re-LDE check, timing.

| file | what |
|---|---|
| `pvm/proof/recair-air/src/{p2,qm31,h8}.rs` | Each `evaluate` split into `body()` plus `finalize_logup_in_pairs()`. Behaviour-preserving: the fixtures prove it. |
| `pvm/proof/recair-air/src/masked.rs` (new, no_std) | `MASKED_LOG_CONSTRAINT_EXPANSION = 2`; `BlindRelation` (`relation!(_, 1)`); `MaskedEval<B>` (body, then 4 blinding main columns, then one fraction `combine_ef(b)/combine_B(1)`, then finalize); `MaskedComponents`; `MaskedComponent` (bounds +1); `committed_log_sizes`; `sample_points` (returns `Option`, no panics); `composition_point` (π(z)); `composition_oods_eval`. Wrap-only: leaf and fold never reference it. |
| `pvm/proof/recair/src/masked.rs` (new) | The prover. Port of `MaskLayout`; parallel `mask_columns`; `commit_salted` (8 salt columns at the lifting height); `prove()` with retry; R1 `revealed_functionals_independent`; R3 `fri_mask_coefficients_independent`; `preprocessed_root`. |
| `pvm/proof/recair/src/trace.rs` | `interaction_with(.., extra)`: one extra fraction a row a component (the blinding). `interaction()` calls it with `None`, so its output is unchanged. |
| `pvm/proof/final-verifier/src/masked.rs` (new, **no_std**) | Builds for thumbv7em, for wasm32 with no nightly features, and for riscv64em. `MaskedFormat` (R6 pins: number, config, interaction PoW, `log_mask_rows`, `salt_columns`); `MASKED_B32` (39) and `MASKED_B64` (40); `verify_masked` on `CommitmentSchemeVerifier::{commit, verify_values}` and the components' public API, never `core::verifier::verify` (DIVERGENCE-004); `verify_any` dispatches on the format. |
| Wasm blob, `final-verify.elf` | `verify` calls `verify_any`, so the existing harnesses measure masked proofs unchanged. |
| tests | `recair/tests/recursion/masked.rs`: costs, tampering, R1/R3, JAM. `recair/tests/circuit/gates.rs`: the masked degree audit. `pvm/proof/tests/common/mod.rs`: `wrap_root` also proves, verifies and JAM-verifies the masked wrap, so `the_predicate_wraps` and `the_window_wraps` measure it. |

**The masked transcript.**
1. The header, at the masked format's number and configuration.
2. The preprocessed root: columns extended to n+1, unsalted.
3. The main root: each component's columns, then its 4 blinding columns, all `f + v_H·r`, then 8 salt columns.
4. The 24 words; the interaction PoW (8 bits).
5. The `Gate` relation; then the **blinding relation**.
6. The blinded claimed sums; the interaction root (masked, 8 salts).
7. The composition coefficient.
8. The **composition tree**: the whole composition (4 columns at m+2 = 17, **never split**); the FRI mask R (4 uniform columns at 17); 8 salts.
9. The OODS point z. Trace masks are sampled at AIR level m+1 = 16; the composition at **π(z)**; R at z.
10. `prove_values`, whose affine DEEP coefficients are drawn after every commitment and sample.

**The blinding values.** `b_c` is nonzero on one row only: r0, r1 and −(r0+r1). Each `claimed_c = true_c + r_c/(1−z_B)`.

**Interaction columns** (masked): p2 has 12 (6 fractions still make 3 pairs), qm31 12 (+4), h8 16 (+4). The main tree has 373 columns plus 8 salts.

## 2. Measurements

**Conditions.** The machine was shared with another spike's builds, at load averages 5–17 over the runs. Every run was one at a time under `systemd-run … MemoryMax=20G`, at `nice 10`.
- **Gas, Wasm instructions, bytes and heap are load-independent.**
- **Wall times are not.** I give the best and the range, and process CPU seconds from `/proc/self/stat`.

| | format 28 (unmasked) | **masked A** (blowup 32, 24 queries) | ×A | masked B (blowup 64, 20 queries) | ×B |
|---|---|---|---|---|---|
| prove, wall, best (range) [measured] | 3.88 s (3.88–8.83) | **11.57 s** (11.57–28.3; areas 14.46, window 12.52) | ×2.6–3.0 | 18.56 s (18.6–45.7) | ×4–5 |
| prove, CPU seconds [measured] | 34.6–42.9 | 100–134 | ×2.4–3.2 | 134–207 | ×4–5 |
| prove, heap peak [measured] | 2,498 MiB | **3,531 MiB (3.45 GiB)** | ×1.41 | 6,978 MiB | ×2.79 |
| proof bytes (postcard) [measured] | 122,528 (window 124,564) | **159,760–162,762** (window 162,760) | ×1.30–1.33 | 142,002–143,818 | ×1.16–1.17 |
| JAM-only host, total gas [measured] | 95.38M (areas 94.48M, window 96.64M) | **115.78M** (areas 117.58M, window 118.73M) | ×1.21–1.24 | 107.62M | ×1.13 |
| … decode / verify [measured] | 15.69M / 79.62M | 19.88M / 95.81M | ×1.27 / ×1.20 | 17.99M / 89.55M | |
| JAM heap peak / high water [measured] | 338 / 892 KiB | 368 / 966 KiB | | 359 / 950 KiB | |
| Wasm, PVF semantics, retired instructions [measured] | 38.02M (2.45 ms) | **45.18M** (2.95 ms) | ×1.19 | 41.98M (2.77 ms) | ×1.10 |
| Wasm, client semantics [measured] | 37.50M | **44.57M** | ×1.19 | 41.40M | ×1.10 |
| native verify, median of 10 [measured, noisy] | 7.0–25 ms | 8.5–31 ms | about ×1.2 | 7–29 ms | |
| R1 + R3 rank checks [measured] | — | 22–39 ms | | 16–20 ms | |

**About the build.**
- The verifier is linked with both formats: the Wasm blob is 339,670 B and the JAM program 538,683 B (ELF 869,592).
- **538,683 B is over JAM's 512 KiB `Limits::program` (524,288 B)** for an actor-hosted verifier. Format 28 alone was 494 KB [doc].
  - A production venue that links only the masked path will be about 494 KB plus the masked path's code. **Measure it.**
  - This adds to C.9's case for a dedicated JAM service.
- **Metering:** the JAM-only host's javm meters GP v0.8.0 **per basic block**: a pipeline simulation with cost `max(cycles − 3, 1)` a block (`pvm/runtime/src/gas_cost.rs:1-9`) [read]. These are the GP 0.8.0 (PR #508) semantics.

**Against the gate and the models.**

| | gate | model | measured (A) |
|---|---|---|---|
| prove memory | ≤ 24 GiB | 3.8–4.3 GiB [est, context M2.7]; 3.4–3.9 GiB [6b proxy]; 3.5–7.8 [doc] | **3.45 GiB** |
| prove time | — | 9–12 s [est] | **11.6–15 s best/typical** (×2.6–2.9) |
| verify gas | ≤ 200M | 117–119M [doc model]; 132–135M [est from 96.4M × 1.37–1.40]; 101M verify + decode [6b] | **115.8–118.7M** (verify 95.8M + decode 19.9M) |
| bytes | — | 150–174 KB [est]; 164–170 KB [doc]; about 160 KB [6b] | **160–163 KB** |
| Wasm instructions | — | 46–54M [est, M3.5] | **45.2M** (PVF) |

- The toy's ×1.37–1.40 overestimated verify. The real ratio is ×1.20 verify and ×1.27 decode. Spike 4a's ×1.21 structural proxy was right.
- `MAX_HANDLER_GAS = 100M` is exceeded: 118.7M. That confirms D.5's dedicated service.

## 3. Where the prover time goes

The best run of shape A, load about 8–9, `VOS_SPIKE_TIMING=1` [measured]:

| phase | masked A | note |
|---|---|---|
| mask the main columns (interpolate, `f + v_H·r`) | 0.04–0.05 s | negligible |
| main tree commit | 4.6 s | evaluate 0.3 s, **salts 0.8 s, Merkle 3.5 s** at 2^22 leaves × 381 columns |
| interaction trace and its masking | 0.07 + 0.04 s | |
| interaction tree commit | 1.6 s | salts 0.8 s, Merkle 0.8 s |
| composition, evaluate and commit | 1.7 s | salts 0.8 s, Merkle 0.8 s (2^22 × 16) |
| `prove_values` (OODS, DEEP, FRI, decommit) | 1.8–3.1 s | lifting 2^22, one more FRI layer |
| R1 + R3 | 0.025 s | |

Format 28 in the same runs: the main commit 0.5–2.0 s and Stwo's prove 0.4–1.2 s.

**Why ×2.6 rather than ×1.6** [measured plus argued].
- (c) puts the lifting at m+2+B′ = 22, one level above format 28's 21.
- Every non-preprocessed tree's leaf layer therefore doubles, because the lifted Merkle hashes every column at the leaf layer. The verifier also requires non-preprocessed trees at the lifting height.
- With Blake2b-256 in software, that hashing dominates the wrap's prover. The toy was dominated by column LDE, which (c) does not grow.
- This is inherent to (c) on Stwo's lifted PCS, not to the salts.

**The lever.**
- The salts cost about 0.8 s a tree, about 2.4 s in all.
- That is the spike's generation: an iterator into `BaseColumn` at 2^22 entries × 8 columns × 3 trees. Bulk RNG bytes did not change it, so the cost is the collect.
- Writing packed SIMD columns directly should take this to about 0.1 s [est], and A to about 9–10 s.

**Shape B** doubles every column's LDE as well: ×2.8 memory, ×4–5 time. Its only gain is ×1.10 Wasm and ×1.13 gas. **Shape A is confirmed.**

## 4. Premise checks on the wrap

- **Degree audit** [measured, `spike_the_masked_degree_audit_passes`]: every constraint is ≤ 3.
  - Masked p2: 303 constraints, degrees [0, 0, 143, 160].
  - qm31: 4 constraints, [0, 1, 0, 3].
  - h8: 8 constraints, [0, 1, 1, 6].
  - The blinding pair is degree 1 where it is alone (its denominator is constant).
  - h = 256 ≤ 2N/3 for every component (h8: N = 2048), so the masked cubic quotient fits 4N.
  - The prover's `h ≤ N/4` assertion holds (h8: 512).
- **No re-LDE** [measured]: `EvaluationMode::infer` on the masked components gives `SubDomain { log_expansion: 4 }` at A and `SubDomain { log_expansion: 5 }` at B. The composition reads the committed evaluations' subdomains.
- **Lifted-Merkle ordering on salted trees** [measured]: the preprocessed tree sits at m+1+B′ = 21, one level below the lifting (22). Every masked proof therefore goes through `prepare_preprocessed_query_positions` and the sorted auth paths (upstream 8c816ee in the pin). About 30 masked proofs verified, 20 of them in a loop, with no `RootMismatch`. The salted trees sit at the lifting height.
- **The composition is never split** [read, measured]. The prover commits `into_coordinate_polys()` whole at m+2 = 17. The verifier commits 4 + 4 + 8 columns at 17 and never calls `core::verifier::verify`, so `COMPOSITION_LOG_SPLIT` is unused (Haböck–Al Kindi's split-half randomization is not needed).
- **R and the blinding columns precede the DEEP coefficients** [read]. The blinding is in the main tree, committed before even the `Gate` challenges. R is in the composition tree, before z and before `prove_values` mixes the samples and draws the affine coefficients.
- **The DEEP point** [read]: the trace masks are at z, stepped at level m+1; the composition at **π(z)**; R at z.
- **Openings per masked polynomial** (the coordinator's item 5) [read]. A column with offsets O is opened at its |O| OODS points, its query decommitments, and the composition's shifted reads, which (c)'s R1 counts at q per offset.
  - Stwo's periodicity sample for two-sample columns repeats the OODS value at a point the lift maps to the same point: no new functional.
  - The composition's own opening at π(z) is determined by the trace samples (DEEP-ALI), so it is no new opening either.
- **The trace randomness budget** (item 3): we use h = 256.
  - (c)'s count is 2(4|O| + q(|O|+1)) = 160 at q = 24 and |O| = 2, against Haböck–Al Kindi's 2(4·n_F + q) = 64. Ours is larger because (c)'s quotient lifts one level below the masked columns: the shifted composition reads never coincide with the decommitment.
  - R1 measured 80 revealed rows.

**Tamper** [measured, `spike_masked_wrap_refuses_tampering`]. Each case is refused with an error; none panics.

| tampered | refused with |
|---|---|
| OODS sample of a main column, of an interaction column; a composition sample; two blinded sums with their total kept | OodsNotMatching (0x13) |
| a queried main value; a queried salt (main, composition) | Merkle RootMismatch (0x12) |
| the FRI mask's sample | ProofOfWork (0x15): the transcript moves |
| one blinded claimed sum | Logup (0x9) |
| a salt column dropped | QueriedValuesShapeMismatch (0x12) |
| a sample dropped; R's samples dropped; the verifier pinning 7 or 9 salts | Shape (0x6), before any Stwo call |
| the interaction PoW | 0x8 |
| the format number; a masked proof to the format-28 verifier; a format-28 proof to the masked verifier | Format (0x4) |
| a prover with unbalanced blinding (soundness gate 8) | Logup |
| an invalid witness, prover check skipped | a qm31 limb: Logup; a broken S-box (no relation): OodsNotMatching |
| either invalid witness, prover check on | refused by the prover |

Each Wasm and JAM run also refuses a tampered byte (Merkle).

## 5. R1, and R3 re-derived under affine batching

**R1** is ported unchanged. It builds the matrix of the randomizer's revealed functionals per column class (level, quotient lift, offset set): 4 rows an OODS point, the decommitments, and the composition's shifted reads. It asks for full row rank over M31.
- On the wrap there are about six classes; the largest has 80 rows at A (68 at B) against h = 256.
- It takes 16–39 ms and never failed in about 30 transcripts.
- With h = 64 the prover refuses (`RankDeficient`), though trivially, by `rows > h`.

**R3, re-derived.**
- With R's four base columns `R_k` uniform and committed before the coefficients, the batch contribution is `Σ_k c_k·T_k`, with `T_k` ranging over the M31 quotient code.
- Its image is `span_M31(c_0..c_3) ⊗ code`. It is the whole QM31 code, which makes every FRI-layer value simulatable from first-layer values, iff `c_0..c_3` are M31-linearly independent.
  - **Under powers** (the prototype's setting) they are `γ^j..γ^{j+3}`: dependent iff γ ∈ CM31, probability about 2^-62.
  - **Under affine batching** (format 28's and A's) they are four independent uniform QM31s, viewed as a 4×4 M31 matrix: singular with probability about 1/p ≈ **2^-31**. That is not negligible for statistical ZK.
- **The prototype's test does not apply:** it assumed γ's powers.
- **Built:** `fri_mask_coefficients_independent` replays `prove_values`'s draw (clone the channel, mix the samples, `DeepCoefficients::draw`), takes R's four coefficients by DEEP-value order, and checks the 4×4 rank. On failure the prover re-randomizes. It never fired.
- The FRI layers' own functionals (8 fold-3 siblings a query a layer, plus a 2^6 last layer, a few hundred) are far below the code's dimension (about 2^19), so they are independent given that span condition [argued]. They do not count against h; that is the coordinator's item 2.
- The coordinator's "R with coefficient 1" is not available under Stwo's batching: only the first DEEP value (a preprocessed column) gets 1. The rank check, or **an 8-column R** (failure about p^-5 ≈ 2^-155, no check needed, 4 more columns), is the equivalent. Recommended: the check, plus 8 columns if Fable prefers a check-free argument.

**R4 (hedged randomness) is a stub.** `StdRng::from_entropy()` per attempt, with per-column seeds from it. There is no witness digest and no test-only seam.

## 6. Panic paths

**Hit: none,** in the verifier, the Wasm blob or the JAM program, over every case above.

**Seen by reading.**
- **Verifier.**
  - `verify_values` uses `zip_eq` over trees against decommitments and queried values, and `trees.last().unwrap()`. These are safe only because `check_shape` pins exactly 4 of each first.
  - `eval_composition_polynomial_at_point` indexes the samples by trace locations. It is safe only after the spike's shape check of the samples against the sample points.
  - The queried-value widths are checked inside `MerkleVerifierLifted::verify` (`QueriedValuesShapeMismatch`, ca20894) before `fri_answers` reads them.
  - Production should still pre-check the per-tree widths (57/381/48/16) with the masked format's pins (R6).
- **Prover.**
  - `MaskLayout::new` asserts `h ≤ N/4` and asserts on the layout.
  - The sample points' `expect`, `assert_eq!(composition.log_size(), …)`.
  - Stwo's `eval_at_point` unwraps the weights map when a sampled column has no stored coefficients. That would panic if a salt column were ever given a sample point; the salts are `Poly::new(None, …)`.
  - `mask_columns`' `expect("a layout a size")`.
  - All of these become errors in production.
- **Harness.** The Wasm runner's "min of runs" once reported 70,585 instructions for its first file under client semantics, a perf-counter glitch. Take medians, or skip the first run.

## 7. Production work left (M2.1–M2.5), as steps a faster agent can take

1. **Format entry** (M2.4):
   - a new number, `masked: true`, shape A;
   - R6 pins: h = 256, 8 salts a tree, 4 (or 8) R columns, AIR level m+1, composition point π(z), log sizes [14, 15, 11];
   - the security tool's (c) terms, from 6b's branch `1b76b028`.
2. **recair-air:**
   - keep the `body()` split, which is behaviour-preserving (the fixtures prove it);
   - promote `masked.rs`: `MaskedEval`, `BlindRelation`, `MaskedComponent`, `committed_log_sizes`, `sample_points`;
   - add a static check that only `MaskedEval` uses `BlindRelation`;
   - the masked degree audit (done) as a gate.
3. **recair prover:**
   - promote `masked.rs`, with errors in place of the asserts and expects;
   - hedged RNG: ChaCha20 seeded from `H(OS ‖ witness digest)`, with a test-only injectable seam;
   - salts written straight into packed columns;
   - R1 and R3 with bounded retry;
   - wire into `wrap::prove` for the masked format, beside 28 or replacing it;
   - pin the masked constants. At A, `PREPROCESSED_ROOT` equals 28's; pin it anyway, with its own test.
4. **final-verifier:**
   - promote `masked.rs`: no_std already, builds on stable wasm32;
   - extend `check_shape` to the masked trees' widths and the composition tree's 16 columns;
   - multi-format dispatch driven by the accepted set, not `verify_any`'s hardcoding;
   - the fixed-layout decode and the message-level Blake2b hook stay separate M2.5 items;
   - fuzz targets on masked bytes.
5. **vos-statement** (M2.6): accepted format set; transition cases; fixtures judged by verdict (or by the RNG seam); regenerate.
6. **Harnesses:** Wasm blob and `final-verify.elf` link the production verifier. Re-measure the JAM program size against 512 KiB.
7. **Gates (M2.7):**
   - keep this spike's 14 tamper cases plus gate 8;
   - leakage tests not built: simulator, witness-pair χ², a hidden-state byte search over every carrier, fresh and replayed RNG, the claimed-sum control;
   - a Fable review of the masked transcript.

**Size.** The spike's core is about 1,100 lines, most of which survive. I estimate 2–3 weeks for steps 1–6 [est], plus the leakage gates and the review.

## 8. What should change in the design (proving.md §5, A.4, recursion-air §7)

1. **Replace (c)'s prover factor for the wrap.**
   - Use ×2.6–2.9 wall and ×2.4–3.2 CPU, about 12–15 s (9–10 s with fast salts [est]).
   - Memory ×1.41: 3.45 GiB, not "3.5–7.8 GiB".
   - Verify ×1.20 (Wasm ×1.19, gas ×1.21–1.24), bytes ×1.31. The ×1.37–1.40 toy ratios should go.
   - Gas measured at 115.8–118.7M: the 132–135M [est] in the context was pessimistic.
2. **R3's statement under affine batching:**
   - the condition is per coefficient, failing at about 2^-31;
   - it needs a prover-side rank check with retry (built), or an 8-column FRI mask;
   - §5 item 3 should say which.
3. **A.4 and M2.5:** at shape A the wrap's preprocessed root (the circuit commitment) does not change, so "new `PREPROCESSED_ROOT`" is moot for A; B would change it. `LOG_SIZES` are unchanged either way.
4. **R2 as built:**
   - one blinding QM31 a component, on one row;
   - a dedicated `BlindRelation` drawn right after `Gate`;
   - p2's interaction width unchanged; qm31 and h8 each +4 columns.
   - The boundary re-cut is trivial for the wrap: the public sum is the words and `u`.
5. **Shape A over B is confirmed by measurement.**
6. **The JAM program cap:** a verifier linking both formats is 538 KB, over 512 KiB. That is one more reason for a dedicated JAM service and a masked-only venue build.
