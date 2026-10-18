# Spike 6b: the security tool learns variant (c); candidate masked final formats

Date 2026-10-18. Branch `spike/s6-bits` in `/home/daniel/src/virto/vos/.worktrees/s6-bits`, cut from `vos-core` `31b7938e`. One local commit, `1b76b028`, not pushed.

Paths: `P` = `pvm/proof/`, `R` = `docs/design/research/slice-5/`. The raw table is in `spike6b-table.log`, next to this file.

Tags:
- **[tool]**: computed by the extended `security.rs`;
- **[proxy]**: computed by the cost proxies in the new test file;
- **[argued]**: my derivation;
- **[read]**: read in the cited source.

## 0. Answers

1. **Which terms (c) changes.** All six of the tool's terms keep their formulas. (c) changes the levels they are evaluated at, and adds one factor to the DEEP term:
   - FRI tests dimension `k = 4N`, whole, at the masked format's own rate;
   - the masked trace's degree bound is `2N`, so `d = 3` in the DEEP term;
   - the DEEP point is `π(z)`, so the DEEP term doubles.
   
   Nothing else moves: the query phase, the affine-batching form, -011's fold rounds, ALI, logup, the salts and the interaction PoW.
2. **The binding term at blowup 64 changes.** For format 28 it is the query term, 82.60 at `m = 4`. Under (c) it is the DEEP batching term `ε_lin(k)`: `k` and `n` both grow ×4, which costs 2 bits on it.
   - (c) at format 28's own parameters counts 146 / 81.74 [tool].
   - The DEEP and ALI terms have 15–26 bits of slack. The half-circle factor is immaterial.
3. **Recommended: shape A.**
   - Parameters: blowup 32 (log 5), 24 queries, PoW 26, interaction PoW 8, fold step 3, last layer 2^6, affine batching, Blake2b-256.
   - Counts: **146 / 82 (82.70)** [tool]. 23 queries is the least that clears 80 (80.84).
   - Against format 28 [proxy]:
     - verify ×1.26, about 101M verify gas plus decode;
     - proof bytes ×1.31, about 160 KB;
     - prover memory ×1.40, about 3.4–3.9 GiB.
   
   **The alternative: shape B.** Blowup 64 and format 28's other parameters, at 146 / 81 (81.74):
   - verify ×1.14 and bytes ×1.16;
   - but prover memory ×2.8, about 6.6–7 GiB, and every column's LDE doubles.
4. **Masking makes DIVERGENCE-012 matter more.** With batching by powers, (c) is capped at 76.15 at blowup 32 and 73.65 at blowup 64.
   - Without the affine count, the masked wrap needs blowup 8 with 43 queries, or a batching-phase PoW of at least 4 bits (blowup 32) or 7 bits (blowup 64).
5. **The unmasked counts are unchanged.** Every registry format still counts what is pinned, format 28 at 146 / 82.60, and the segment and leaf formats likewise. The tests pin this, and all 96 lib tests pass.

## 1. (c)'s effect on each term

**Notation.**
- `N = 2^m` is the tallest component's row count. The wrap has `m = 15` (`p2`, `qm31`, `h8` at 2^14, 2^15, 2^11).
- `B'` is the masked format's own `log_blowup`, which is FRI's: `ρ = 2^-B'`.
- "Trading one blowup bit" against format 28 means `B' = 5`. Each column's own LDE, `(n_c+1)+5`, is then the same size as format 28's `n_c+6`.
- **Format 28 as built:** the composition bound is `2N` (`LOG_CONSTRAINT_EXPANSION = 1`), split once (`COMPOSITION_LOG_SPLIT = 1`, DIVERGENCE-004). So FRI tests `k = N = 2^15` at lifting 2^21 [read: `SB/crates/stwo/src/core/verifier.rs:17,51`; `P/src/proof/preflight.rs:349-380`; `D/recursion-air.md:465-467`].
- **Under (c)** (`R/spike2-masking.md` §3b):
  - the constraint bound is `4N` (`LOG_CONSTRAINT_EXPANSION = 2`);
  - the composition is committed whole at level `m+2`;
  - the masked columns `f' = f + v_H·r` sit at bound `2N` (level `m+1`), lifted one doubling more than the quotients;
  - the lifting is `m+2+B'`;
  - the AIR is evaluated at level `m+1`, and the composition is sampled at `π(z)`.

### Terms that change

| term | (c)'s effect, and why |
|---|---|
| **Query phase** `2^-pow·(1−γ)^q`, `γ = 1−√ρ−η` (BCIKS20 / BCHKS25 Johnson regime, soundcalc `_get_query_phase_error`) | **The formula is unchanged; `ρ` is the masked format's rate.** At `B' = 5` a query is worth about 2.5 bits, against 3 at blowup 64. The masks are the prover's choice, made before any query challenge: FRI tests the committed `f'` like any codeword. The FRI mask `R` is one more batched function (`masking-review.md` §1.4). |
| **DEEP batching**, affine: `ε_lin(k)` (BCIKS20 Thm 1.6 as soundcalc counts it; `ε_lin` from BCHKS25 Thm 4.2, DIVERGENCE-012) | **Same form, at `k = 2^(m+2)` and `n = k/ρ = 2^(m+2+B')`.** Against format 28's `k = 2^15`, `n = 2^21`: at `B' = 6`, `n` grows ×4, which is −2 bits (83.74 → 81.74 at `m = 4`); at `B' = 5`, `n` grows ×2, but `1/(ρ√ρ)` falls 2^1.5, a net +0.5 bit. The affine error does not depend on how many functions the batch holds, so the masked columns' quotients, `T_R` and the blinding columns' quotients cost nothing here. Its premise is every function fixed before the coefficients: `R` must be committed, and the samples mixed, before they are drawn (`R/spike2-masking.md` §2.4; the fork draws the affine coefficients after the sampled values). By powers, the term is `(B_s − 1)·ε_lin(k)`, and `B_s` grows by 40 (20 blinding columns × 2; the whole composition's 4 and `R`'s 4 replace the split composition's 8). |
| **FRI folds** `(2^f − 1)·ε_lin(k/F_i)` (soundcalc `_get_commit_phase_error`; DIVERGENCE-011) | **Same mechanism, at `log k = m+2 = 17`:** rounds `[3,3,3,2]` to a 2^6 last layer, one more round than format 28's `[3,3,3]`. -011's first round (the circle fold plus `fold_step − 1` line folds before the first commitment) is untouched by masking. It stays 0.19 bits above the batching term, so it never binds first. |
| **DEEP** `L·(d(k+c−1) + (k−1))/(\|F\| − k − D)` (Thm 8 of eprint 2022/1216, soundcalc `circuits/deep_ali.py`) | **Three changes:**<br>1. `k` becomes the masked trace bound `2N`. FRI enforces it exactly: a masked column is lifted once more than the quotients.<br>2. `d = 2^(l_C − l_k) + 1 = 3`, from `l_C = m+2` and `l_k = m+1`. That is the exact bound for a cubic constraint over degree-`2N` columns (`3·2N = 4N + 2N`), so `d·k = 6N` against format 28's `3N` as built (`5N` at its reference).<br>3. **New factor `2^j`, `j = 1`:** the identity is checked with the composition at `π(z)`. `π` is 2-to-1, so the point is uniform on half the circle; equivalently, the identity's degree in `z` doubles. Either way the error at most doubles (`R/spike2-masking.md:785-786` "half the circle, so its error at most doubles" [argued]). This is the `composition_point_doublings` field.<br>`c` stays 2: `|O| ≤ 2`, and the composition and `R` are sampled once each. Net: about ×4 against format 28 as built, 97.0–97.7 bits [tool], never binding. |
| **ALI** `L·C/\|F\|` | **Same form.** `C` grows by R2's blinding constraints (about 2). `L` is the list size at `ρ`. The ALI combination by powers of `α` is unchanged with the composition at `4N`. 107.7–108.9 bits. |
| **logup** `N·S/\|F\|·2^-ipow` | **Same form.** `N` grows by the blinding fractions (one a row a component: +2^14 + 2^15 + 2^11). `S` stays 5. The blinding relation's pole argument (`R/spike2-masking.md` §2.2: Schwartz–Zippel in the challenges [from memory]) is a fraction count inside this term. 111.6 bits; at interaction PoW 0, 103.6. **Interaction PoW never binds the wrap.** Masking the interaction columns after the challenges adds no prover freedom the verifier checks (`masking-review.md` §2.5). |

### What adds no term

- **Salt columns:** 8 M31 per tree, on 3 trees. They are never sampled and enter no quotient. Binding is Blake2b-256 collision resistance (128-bit generic), which the tool does not model, for format 28 either.
- **Hedged randomness (R4) and R1's re-randomize-and-retry.** They change only what the honest prover samples. A cheating prover's attempts are already counted per Fiat–Shamir query.
- **The randomizer size `h`:**
  - it is a completeness and hiding parameter;
  - `h = (2(4|O| + q(|O|+1)))`, rounded up to a power of two, is 256 for every candidate (`q ≤ 40`);
  - it is within `h8`'s `N/4 = 512`;
  - and `≤ 2N/3`, the bound under which a cubic constraint fits.
- **Conjectured bits:** `pow + q·B'`, the same formula at the masked rate.

### Multi-point precondition

`k + c < √ρ·n`, that is `2^17 + 2 < 2^(17 + B'/2)`. It holds for every `B' ≥ 1`.

## 2. What the tool now does (`spike/s6-bits`, `1b76b028`)

**In `P/src/security.rs`:**
- A new field, `SecurityShape::composition_point_doublings` (`j`). The DEEP term is multiplied by `2^j`, and `Analysis::new` refuses `j > log_degree_bound`. It is 0 in every existing shape: `format.rs`'s references and `framework_access::security_shape`.
- `SecurityShape::variant_c(self)`. From the tallest component's `m = log_trace_length` it sets:
  - `log_degree_bound = m+2`;
  - `log_trace_length = m+1`;
  - `log_composition_degree_bound = m+2`;
  - `j = 1`.
  
  It keeps the sampled values (the whole composition's 4 plus `R`'s 4 replace the split composition's 8).
- Module docs for the masked count.
- A `#[cfg(test)] term_bits` that returns each term at the binding `m`.

**In `P/src/format.rs`:** `MASKED_WRAP_REFERENCE`, which is `WRAP_REFERENCE.variant_c()` plus R2's blinding:
- 12 main and 8 interaction columns (`p2`'s lone fraction is filled; `qm31` and `h8` each gain a pair column);
- +2 constraints;
- the fractions 6, 5 and 7 a row.

**In `P/src/format_masked_tests.rs`** (new; run with `--nocapture` to print the tables):
- `the_unmasked_counts_do_not_move`: every registry format reproduces its pinned bits with `j = 0`, and format 28 is 82.60–82.61.
- `each_term_of_c_at_format_28s_parameters` and `the_terms_side_by_side`: section 3's per-term table.
- `the_masked_wrap_candidates`: the grid, with shapes A (146 / 82, 82.69–82.70; least 23 queries) and B (146 / 81, 81.73–81.74; least 19) pinned.
- `the_interaction_pow_does_not_bind`.
- `the_masked_wrap_needs_affine_batching`.
- `the_proxies_reproduce_format_28`.

**Results** (`cargo test -p vos-pvm-proof --no-default-features --lib -j 6`):
- 96 passed;
- the existing `format::tests` (pins 28 = 146/82, 30 = 106/62, 32 = 108/63, 35 = 104/62, 36 = 96/57, 37 = 106/62) unchanged;
- `the_wrap_needs_affine_batching` unchanged.

**The cost proxies,** relative to format 28, in the test file:
- **Verify:** spike 4a's mechanistic gas fit (`R/spike4a-final-gas.md` §7), `−4.2M + 59.3k·C_s + 2,171·q·C_o + 17,183·P + 9,376·F`:
  - `C_s` the sampled columns, `C_o` the opened ones with the salts;
  - `P` the path hashes over 4 trees plus the FRI layers;
  - `F` the FRI values folded.
- **Bytes:** opened values, plus 32 B a path hash, FRI siblings, OODS samples and the last layer.
- **Memory:** 4 B a committed evaluation, plus the tree nodes and the FRI layers.

**Calibration on format 28:**
- verify 82.3M, against 80.3M measured;
- 117.7 KB, against 122–125 KB;
- 2.36 GiB, against 2.44–2.5 GiB heap.

The memory proxy leaves out the constraint-evaluation transient. On spike 2's toy it reads (c) at about ×1.26, where ×1.56 was measured.

## 3. Candidates

### Per-term bits

Each term at the `m` the count is taken at [tool]:

| shape | m | query | batching | fold | ALI | DEEP | logup | count |
|---|---|---|---|---|---|---|---|---|
| 28, reference shape (k 2^16) | 4 | **82.60** | 82.74 | 82.93 | 107.71 | 98.42 | 111.90 | 82.60 |
| 28 as built (k 2^15) | 4 | **82.60** | 83.74 | 83.93 | 107.71 | 99.00 | 111.90 | 82.60 |
| (c) b64 q20, `j = 0` | 4 | 82.60 | **81.74** | 81.93 | 107.70 | 98.00 | 111.60 | 81.74 |
| (c) b64 q20 (B) | 4 | 82.60 | **81.74** | 81.93 | 107.70 | 97.00 | 111.60 | 81.74 |
| (c) b32 q24 (A) | 5 | 82.70 | 82.79 | 82.98 | 108.38 | 97.68 | 111.60 | 82.70 |
| (c) b32 q24, one level up | 4 | 81.92 | 83.24 | 83.43 | 108.71 | 97.00 | 111.90 | 81.92 |
| (c) b16 q30 | 7 | 83.01 | 83.05 | 83.24 | 108.89 | 98.19 | 111.60 | 83.01 |

### The least queries for ≥ 100 / ≥ 80

At interaction PoW 8. Interaction PoW 0 gives identical rows. Ratios are the proxy's, against format 28. The full grid, every last layer 2^4–2^8, is in `spike6b-table.log`.

| log blowup | fold | last | PoW | q | counts | verify | bytes | memory |
|---|---|---|---|---|---|---|---|---|
| 4 | 3 | 2^6 | 26 | 28 | 138/80 (80.03) | ×1.36 | ×1.44 | ×0.70 |
| 4 | 3 | 2^8 | 28 | 27 | 136/80 (80.10) | ×1.28 | ×1.36 | ×0.70 |
| 5 | 3 | 2^6 | 20 | 25 | 145/80 (80.01) | ×1.29 | ×1.36 | ×1.40 |
| 5 | 3 | 2^6 | 24 | 24 | 144/81 (81.23) | ×1.26 | ×1.31 | ×1.40 |
| 5 | 3 | 2^6 | 26 | **23** | 141/80 (80.84) | ×1.22 | ×1.26 | ×1.40 |
| 5 | 3 | 2^6 | 28 | 22 | 138/80 (80.55) | ×1.18 | ×1.21 | ×1.40 |
| 5 | 2 | 2^6 | 26 | 23 | 141/80 (80.84) | ×1.32 | ×1.39 | ×1.44 |
| 5 | 3 | 2^8 | 26 | 23 | 141/80 (80.84) | ×1.17 | ×1.23 | ×1.40 |
| 6 | 3 | 2^6 | 26 | **19** | 140/80 (80.29) | ×1.10 | ×1.11 | ×2.79 |
| 6 | 3 | 2^6 | 28 | 19 | 142/81 (81.74) | ×1.10 | ×1.11 | ×2.79 |
| 6 | 2 | 2^6 | 26 | 19 | 140/80 (80.29) | ×1.19 | ×1.23 | ×2.88 |

**What the grid shows:**
- **Fold step 3 beats 2 at equal bits.** The fold term never binds, and fold 2 costs +8–10% verify.
- **PoW above 26 saves about one query a 2 bits,** at 4× the grind.
- **A last layer of 2^8 saves 4–5% of verify** in the fit. The fit has no term for evaluating the last layer at each query, so measure before taking it.

### Recommended

**A: blowup 32 (log 5), 24 queries, PoW 26, interaction PoW 8, fold step 3, last layer 2^6, affine, Blake2b-256.**
- **Counts: 146 / 82 (82.70).** Its margin over 80 is 2.7 bits, the same kind as format 28's 82.6 over its least of 19; the least here is 23 queries.
- **The verifier pays:**
  - ×1.26 in the proxy: about 101M verify gas against 80.3M, plus about 21M postcard decode, so about 122M in all;
  - the fixed-layout decode (M2.5) removes most of the decode;
  - this is under the context's [est] of 132–135M, which applied the toy's ×1.37–1.40;
  - Wasm about 48M instructions (×1.25 on 38.2M).
- **Bytes:** ×1.31, about 160 KB scaled from the measured 123.8 KB, within `MAX_PROOF_BYTES = 256 KiB`.
- **The prover pays:**
  - each column's own LDE is unchanged (2^(n+6));
  - the lifted trees double (lifting 2^22);
  - the composition's evaluation domain is `4N`;
  - the salts and `R` are new;
  - the proxy gives memory ×1.40, about 3.4 GiB, and spike 2's measured toy ratio ×1.56 gives about 3.9 GiB;
  - time ×1.6 on the toy (constraint evaluation doubles), so about 9–11 s;
  - the grind is format 28's.

**B (the alternative): blowup 64, 20 queries, PoW 26, interaction PoW 8, fold 3, last 2^6.**
- **Counts: 146 / 81 (81.74).** The least is 19 queries.
- **The verifier pays** ×1.14 (about 91M verify, about 110M with the decode) and ×1.16 in bytes (about 143 KB).
- **The prover pays:** every column's LDE doubles (2^(n+7)), the lifting is 2^23, the proxy gives memory ×2.79 (6.6–7 GiB) and time about ×2.5–3.
- **Pick B only if verify gas, not prover memory, binds.** On Kreivo (Wasm about 40M) neither binds. On JAM (a 100M handler cap; context C.9) neither fits as an actor anyway.

**Not recommended, but worth recording: blowup 16, 30 queries (146 / 83).**
- Its prover is *lighter* than format 28's: ×0.70 memory.
- Its verify is ×1.43.
- It is useful only if the wrap must ever be proved on a constrained host.

## 4. What rests on unreviewed citations or divergences, and what a reviewer must check

1. **DIVERGENCE-012, affine batching.** It is load-bearing for the masked format at blowup 32 and 64. The masked wrap's binding term at blowup 64 *is* this term.
   - **Check:** the citation (BCIKS20 Thm 1.6, read as soundcalc `2af5e7df` does) and the `ε_lin` instantiation (BCHKS25 Thm 4.2, `m ≥ 3`, `m' = m+½`).
   - **Check:** that its premise holds in the masked transcript. Every batched function, the masked columns' quotients, `T_R` and the blinding columns among them, must be committed and their samples mixed before the affine coefficients are drawn.
   - **Check:** that the masked verifier takes the batching from the format, never from the proof.
   - **If it falls:** batching by powers caps (c) at 76.15 (blowup 32) and 73.65 (blowup 64) [tool]. The fallbacks are blowup 8 with 43 queries (about 2× verify), or a batching-phase PoW of 4 bits or more (blowup 32) or 7 bits or more (blowup 64).
2. **DIVERGENCE-011, the first FRI round folds by `2^fold_step`.**
   - The fold term sits 0.19 bits above the batching term in A.
   - Under a model that counts the circle fold as its own round, the fold term would move by about 0.8 bits and bind first. A would then be about 82.2, still ≥ 80.
   - **Check** the tool's round list `[3,3,3,2]` at `log k = 17` against the fork's `FriVerifier::commit`.
3. **The DEEP term's three (c) inputs** are my derivation, after spike 2's [argued] §3b, not a cited theorem: `k = 2N`, `d = 3`, and the `2^j` factor for `π(z)`.
   - **Check** that Thm 8 of eprint 2022/1216 applies with the AIR evaluated at level `m+1`, the composition at `π(z)`, and lifted columns of mixed degree.
   - Low stakes: the term has about 15 bits of slack, so even a ×2^10 error does not move the count.
4. **The lifted protocol.** The tool treats the lifted batch as one RS code of dimension `2^(m+2)`, with each masked column's `2N` bound enforced by one extra doubling of its lift.
   - Format 28 already rests on this (columns at 2^11 to 2^15). The papers in the fork's canon (Circle STARKs, the Stwo whitepaper) do not analyze the lifted Merkle and FRI variant.
   - It is an upstream assumption the external audit should name.
5. **DIVERGENCE-004, the hardcoded composition split.** This is a code item for M2.5, not a citation.
   - The masked verifier must take its security shape from its own layout: `k = 4N`, whole, and `j = 1`.
   - It must not use `framework_access::air_layout` and `derive_protocol_degree_shape`, which subtract `COMPOSITION_LOG_SPLIT`. Those would count `k = 2N` and overstate the batching term by about 1 bit.
6. **R2's blinding soundness** (a Schwartz–Zippel pole argument, [from memory] in spike 2). The tool counts it only as extra logup fractions, 111.6 bits. It needs the gate soundness-8 test and a written argument.
7. **The reference-shape convention.**
   - `WRAP_REFERENCE` counts format 28 one level above the built wrap (`k` 2^16 against 2^15). The count is unchanged, because the query term binds at `m = 4`.
   - `MASKED_WRAP_REFERENCE` is at (c)'s true levels. At the same one-level pessimism, A would count 81.92.
   - The blinding counts (12 + 8 columns, +2 constraints) are a design estimate until R2 is built.
   - **Recompute the shape** from the built masked components, as `the_reference_shapes_are_the_segment_airs` does for segments.
8. **The integer-`m` quantization.** Counts are taken at the best integer multiplicity `m ≥ 3`. Small parameter moves jump the count (for example A at 23 queries is 80.84, at 24 is 82.70). The reviewer should accept or reject integer `m`, as soundcalc does.
9. **The conjectured count** at the masked rate inherits the refuted up-to-capacity conjecture's caveat. A's 146 equals format 28's, so the salvaged-form margin is unchanged.
10. **The cost figures are proxies, not measurements.**
    - Verify uses a Blake2s-fitted gas model of at most 400 columns.
    - Memory omits the constraint-evaluation transient.
    - Context C.1's spike (the real wrap masked) must measure A, and B if wanted, before the format is pinned.
