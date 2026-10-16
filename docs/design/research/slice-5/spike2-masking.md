# Slice 5, spike 2: zero-knowledge masking for the VOS prover

Research date 2026-10-15. Paths:

- `ST` = `~/src/virto/stwo`, the owner's Stwo fork. Local branch
  `zk-masking-spike`, cut from `no-std-pvf-gating` (`4f417dd`, which contains
  vos-core's pin `e1286720`). Commits `539f419`, `c9835e2`, `661267a`,
  `92ecb7e`, and `ec451ad` (the follow-up for Fable's review: variant (c) and
  the prover's rank check). Never pushed.
- `UP` = `/home/daniel/.claude/jobs/8e1fc21e/tmp/s5/proving-src`, a clone of
  `starkware-libs/proving` at `916aefb5` (2026-10-15).
- `P3` = `/home/daniel/.claude/jobs/8e1fc21e/tmp/s5/plonky3-src`, a clone of
  Plonky3 at `f983316` (2026-10-13), read as the checked reference for a
  hiding FRI PCS.
- `VC` = `/home/daniel/src/virto/vos/.worktrees/vos-core`, and `P` =
  `VC/pvm/proof` (read only).
- `BENCH` = `/home/daniel/.claude/jobs/8e1fc21e/tmp/s5/spike2-bench/`, the raw
  benchmark output.

Tags:
- **[measured]**: measured in this spike;
- **[read]**: read in the source, cited by file:line;
- **[argued]**: my derivation, following the cited standard construction;
- **[from memory]**: a paper I could not fetch. eprint answers the sandbox
  with HTTP 403. Plonky3's implementation, which cites these papers, is the
  checked proxy.

## 0. The answers

1. **Upstream has no ZK mode for an arbitrary AIR. Moving there does not give
   vos-core masking.**
   - The Stwo core in `starkware-libs/proving` is, as far as hiding goes, what
     we pin. 46 commits to `crates/stwo` and `crates/constraint-framework`
     since `e1286720`, none about hiding.
   - ZK exists only in the Starknet "privacy" recursion pipeline. A non-ZK
     Cairo proof is verified inside a `stwo-circuits` circuit, and that
     circuit's proof gets `n_queries + 10` random *valid* gates per circuit
     component. The gates are seeded from the inner proof's trace root, so the
     randomness is a function of the witness.
   - It has no salted Merkle leaves, no masked composition and no FRI mask.
   - Using it would mean a toolchain and API port, plus a verifier circuit for
     the PVM AIR and a recursion step per segment. It would still leave three
     of the four mechanisms to build ourselves.
2. **The design (section 2)** is the standard ZK-STARK recipe, fitted to Stwo's
   circle and lifted machinery:
   - randomize every main and interaction column as `f + v_H·r`;
   - salt every non-preprocessed Merkle leaf;
   - commit the composition whole, not split;
   - add a random codeword to the FRI batch;
   - blind each component's logup claimed sum;
   - publish no segment state beyond the io-hash and constants.

   It changes no constraint and no soundness-critical Stwo file. It runs on
   the pinned Stwo's public API.
3. **The number.**
   - The masking slack does not fit the padding rows. `f + v_H·r` has degree
     `N + h`, so every masked column, and every preprocessed column beside it,
     moves to committed degree bound `2N`. **Every component's committed
     height doubles; its row count and AIR do not.**
   - Three ways to pay for it, measured against the unmasked baseline on one
     wide-Fibonacci component (100 columns, 2^16 and 2^18 rows; single-thread
     CPU, minimum of interleaved runs on a quiet machine, grinding excluded;
     section 3 and section 3b):

     | variant | prover CPU | peak memory | proof size | verify | constraint degree |
     |---|---|---|---|---|---|
     | **(a)** same blowup, composition `2N` | ×2.0–2.2 | ×2.0–2.1 | +5–11% STD, +14–18% MOB | ×1.05–1.13 | ≤ 2: 18 chips unpair their logup |
     | **(b)** one blowup bit traded, composition `2N` | ×1.1 STD, ×1.2 MOB | ×1.1 / ×1.2 | +25–35% / +73–82% | ×1.3 / ×1.7–1.8 | ≤ 2: same unpairing |
     | **(c)** one blowup bit traded, composition `4N`, lifting at `m+2` | ×1.6 STD, ×1.6–1.7 MOB | ×1.6 / ×1.6–1.7 | +35–40% / +103–110% | ×1.4 / ×1.9–2.0 | **≤ 3 (≤ 4 at `h ≤ N/4`): no unpairing** |

   - **Masking under (a) or (b) needs every constraint at degree ≤ 2.** A cubic
     constraint's quotient overflows the composition bound `2N` once the trace
     is masked (measured: refused with a random randomizer, accepted with a
     zero one).
     - 18 of vos-core's 32 chips use `finalize_logup_in_pairs`, which is cubic.
       They include CPU, both BLAKE2b chips, MEMORY_PAGE, MEMORY_MERKLE and
       REGISTER_MEMORY.
     - Under (a) or (b) they must take one fraction per interaction column,
       which roughly doubles their interaction columns: an estimated +30–45%
       committed bytes, **and the same +30–45% on the per-query opened values
       that dominate a 15.8k-column proof** (estimate).
   - **Variant (c)** (Fable's R8) keeps cubic constraints: the composition
     bound is `4N`, which measured accepts the plonk component's cubic gate and
     paired logup. It costs ×1.6 instead of (a)'s ×2. It needs no unpairing,
     and its proof size is (b)'s plus one FRI layer.
   - **Projected for vos-core.** The chain window is MOBILE, about 5.2 GiB and
     4 s today.
     - (a) with unpairing: about ×2.6–2.9.
     - (c): about ×1.6–1.7, pending how heavy constraint evaluation is for the
       real chips, since (c) doubles the evaluation domain.
     - Proof and verify: (a) with unpairing is about ×1.35–1.6 over today; (c)
       at blowup 8 / 26 queries is about ×1.37. That is about the same, so (a)
       does not buy a smaller published proof once unpairing is counted.
4. **Toolchain and dependencies: masking forces none.**
   - The prototype builds on `nightly-2025-07-14`, with the fork's
     dependencies and lockfile unchanged.
   - The toolchain can move on its own: upstream's `02e5ae3e` ("Make the repo
     compile with Rust 1.94 nightly") applies cleanly to the fork.
5. **Test plan:** section 5. It covers:
   - soundness gates for every masked component;
   - the simulator's precondition as a rank test on real transcripts (built);
   - a simulator and witness-pair indistinguishability tests;
   - hidden-state checks and fresh randomness.

**Recommendation: mask in our pinned Stwo fork, in vos-core's prover over the
fork's public API. Do not move upstream.**
- **Published proofs: variant (c) at blowup 8 with 26 queries.**
  - Its soundness is (b)-STANDARD's, which Fable judged fine.
  - It needs no 18-chip unpairing.
  - The prover costs about ×1.6.
  - Proof and verify cost about as much as (a) with unpairing.
- Fall back to (a) with unpairing only if 5.3 measures the real chips'
  constraint evaluation dominating (c)'s cost.
- **Phones: (c) at blowup 2 with 76 queries,** for proofs that stay inside a
  space.
  - Memory is about ×1.6–1.7, against about ×2.6–2.9 for (a) with unpairing,
    which breaks a 3 GB envelope sooner.
  - Blowup 2 carries (b)'s caveat: no slack beyond the up-to-capacity
    conjecture. Do not publish settlement proofs at that rate.
- **The first build items of 5.3** are the constraint-degree audit (≤ 3 under
  (c)) and the prover's rank check (R1). R1 is now built in the prototype and
  costs 0.2–17 ms per column class.

## 1. Upstream: `starkware-libs/proving`

**What it is [read].**
- The successor monorepo of Stwo, stwo-cairo, stwo-circuits, proving-utils and
  stwo-air-infra (`UP/Cargo.toml:1-56`).
- Version 2.4.0, edition 2024 (`UP/Cargo.toml:57-58`), toolchain
  `nightly-2026-01-15` (`UP/rust-toolchain.toml:5`).
- It contains our pin `e1286720`.
  `git log e1286720..HEAD -- crates/stwo crates/constraint-framework` lists 46
  commits (153 files, +2921/−3531), none about hiding. They include:
  - an OODS proof-of-work (`f0bf0195`), which changes the proof format;
  - `pow_bits` moved into `FriConfig` (`e836666e`);
  - a non-optional `lifting_log_size` (`960b2529`, `447486eb`, `6f7ab7c6`);
  - removal of `PcsConfig::default` (`38c01830`);
  - `mix_root` renamed `mix_hash` (`dd8ffa12`);
  - the channel's config mixing moved (`f3ec23b3`, `98f027bb`);
  - rand 0.9 (`36561ca5`).

**Stwo itself has no ZK [read].**
- `UP/crates/stwo/src/prover/mod.rs:68` still splits the composition at mid,
  unmasked.
- The Merkle hashers take no salt. `git grep -i 'salt\|hiding\|blind'` over
  `crates/stwo` finds only the paper summary's line "Optimized non-ZK variant
  ... is not zero-knowledge" (`UP/.agents/papers/llm/Circle_STARKs.llm.md:142`).

**Where ZK exists: the privacy recursion [read].**
- `add_zk_blinding` (`UP/crates/circuit_common/src/finalize.rs:160-177`)
  appends, per blinding unit, one random-input valid gate to each circuit
  component (`:85-158`): `qm31_ops` (`x + 0 = x`), `eq` (`x == x`),
  `triple_xor`, `m31_to_u32` and `blake_g_gate`.
- The amount is `n_queries + NON_QUERY_INFO_LEAK`
  (`UP/crates/privacy_circuit_verify/src/lib.rs:194`;
  `UP/crates/leaf_prover/src/prove_leaf.rs:151-153`).
  - `NON_QUERY_INFO_LEAK = 10` covers "2 OODS queries (4 each since their
    answers are in QM31) + 2 M31s extra for safety"
    (`UP/crates/cairo_verifier/src/verify.rs:71-74`; `38d36327`, 2026-08-31;
    introduced in `bebe8d8c`).
- **The randomness is ChaCha20 seeded from the inner Cairo proof's trace root**
  (`verify.rs:165-167`). The privacy prover sets `channel_salt: 0`
  (`UP/crates/privacy_prove/src/consts.rs:25`).
  - The blinding is therefore a deterministic function of the witness.
  - A low-entropy witness can be guessed, its inner proof recomputed and the
    blinding stripped **[argued]**.
- **What it lacks against the recipe below [read + argued]:**
  - salts;
  - masking of the composition halves;
  - a random codeword in the FRI batch.

  Its budget counts only per-column functionals. Plonky3's hiding FRI, by
  contrast, requires all of the following (`P3/fri/src/hiding_pcs.rs:65-85`):
  - `N >= 2 * (num_queries + Challenge::DIMENSION * points)` random rows;
  - "At least `Challenge::DIMENSION` random codewords ... to mask
    extension-field batching";
  - quotient chunks randomized per §4.2 of eprint 2024/1037 (`:471-560`);
  - a salted `MerkleTreeHidingMmcs`
    (`P3/merkle-tree/src/hiding_mmcs.rs:21-33`).
- **Plans [read]:** no roadmap file and no commit plans a ZK mode for the Stwo
  core. The privacy work is Starknet client-side proving (SNIP-36, `699fa16e`)
  through the Cairo-to-circuit recursion.

**Is a move there viable for vos-core? Not as a way to get masking.**
- The port alone is substantial:
  - a toolchain bump to `nightly-2026-01-15` and edition 2024;
  - the API churn above, across 32 components and the no_std verifier;
  - a proof-format change (the OODS PoW);
  - re-pinning every program commitment.
- Upstream's ZK would also require a `stwo-circuits` verifier circuit for the
  PVM AIR. These are code-generated per AIR by stwo-air-infra, for Cairo.
- Every segment would then need a recursion step over the ~15.8k-column
  verifier. As a PVM guest, vos-core measured that verifier at 600–750M
  instructions with a 69 GiB wall
  (`P/docs/design/recursion-decision.md:24-29`). A circuit verifier is
  cheaper, but it is still a full recursion layer.
- The result would still lack three of the four mechanisms.
- The toolchain does not need the move (section 4).

## 2. The design

**Notation.**
- Component `c` has `N_c = 2^{n_c}` rows on `H_c = CanonicCoset(n_c)`, with
  vanishing polynomial `v_H`.
- `m = max n_c` is the AIR level; `B` is the log blowup; `q` is the FRI query
  count; `h` is the randomizer size per column.
- STANDARD = blowup 16, 19 queries; MOBILE = blowup 4, 38 queries; both with 20
  PoW bits (`P/src/prove.rs:107-176`). The chain path proves with MOBILE
  (`P/src/prove.rs:640-647`).

**Goal.**
- Honest-verifier zero knowledge of the published proof in the random-oracle
  model: the Fiat–Shamir transcript can be simulated from the public inputs.
- Soundness exactly as today.
- The prover runs inside the space's trust domain (core model §11.4) and
  needs only fresh, OS-seeded randomness.

### 2.1 Randomized trace polynomials

**The construction [argued].**
- Every column of tree 1 (main) and tree 2 (interaction) of every component
  is committed as `f' = f + v_H·r`, with `r` uniform in the size-`h` circle
  FFT space.
- `f' = f` on `H`, so every constraint, transition and logup cumulative sum is
  unchanged where the AIR checks them.
- Off `H`, any set of at most `h` linearly independent evaluations of `f'` is
  uniform and independent of `f`.
- This is the randomized-trace step of Ben-Sasson et al. ("Scalable zero
  knowledge with no trusted setup"), whose masking 2024/1037 calls essential
  [from memory]. It is also the Circle STARKs paper's main protocol, whose
  "optimized non-ZK variant" drops it
  (`ST/.agents/papers/llm/Circle_STARKs.llm.md:142`).
- Stwo's LDE domain `CanonicCoset(n+B)` and `H` are disjoint (point orders
  `2^{n+B+1}` and `2^{n+1}`), so no query lands on `H`.

**Where the slack goes [measured].**
- In the circle FFT basis, the canonic coset's `v_H` is `π^{n−1}(x)`
  (`ST/crates/stwo/src/core/constraints.rs:12-31`; the shift is zero for a
  canonic coset).
- That is exactly the basis element the size-`2N` basis adds
  (`ST/crates/stwo/src/prover/poly/circle/poly.rs:12-21`). So `v_H·b_j =
  b_{N+j}`: the mask is `h` random coefficients on `h` upper-half basis
  elements, and `f'` needs degree bound `2N`.
- `MaskLayout::new` asserts that a literal `v_H·r`, computed by evaluation and
  interpolation, has exactly `h` nonzero coefficients.
- **Gotcha:** the SIMD backend stores coefficients in a different order above
  its cached-FFT size `2^16`
  (`ST/crates/stwo/src/prover/backend/simd/fft/mod.rs:14`).
  - Appending coefficients is a correct extension up to `2^15→2^16` and wrong
    from `2^16→2^17`. This was measured; the first version of the prototype
    failed exactly at `2^16`.
  - The layout must be read off the backend, as `MaskLayout` does, or the
    mask computed in evaluation form.

**The composition fits only for degree ≤ 2 [measured, argued].**
- Every vos-core chip uses `LOG_CONSTRAINT_DEGREE_BOUND = 1`
  (`P/src/framework/traits/builtin.rs:30`), so the composition bound is `2N`.
- `f'` has total degree about `(N + h)/2`. A degree-`d` constraint quotient
  therefore has total degree about `(d−1)N/2 + d·h/2`.
  - For `d = 2` that is `N/2 + h`, which fits iff `h ≤ N/4`. The prototype
    asserts this. Measured: `h = N/2` fails and `N/4` passes.
  - For `d = 3` it is `N + 3h/2`, which never fits.
  - Unmasked cubic constraints just fit (`N`), which is why Stwo allows them
    under bound `2N`.
- Test `masked_degree_three_constraints_do_not_fit_the_composition_bound`:
  the plonk component (cubic gate `op·a·b`, paired logup), masked, is refused.
  The same pipeline with a zero randomizer proves.
- The alternatives cost more:
  - raising those components to `LOG_CONSTRAINT_DEGREE_BOUND = 2` puts the
    composition at level `m+2`, which breaks the lifting below unless the
    masked columns go to `n+2` (4× LDE);
  - splitting the composition leaves halves that cannot be randomized (2.3).
- **So, at composition bound `2N`, masked components need every constraint at
  degree ≤ 2.** Variant (c) (section 3b) raises the bound to `4N` and keeps
  cubic constraints, at the prover cost measured there.
  - In vos-core, 18 chips call `finalize_logup_in_pairs`, whose constraint
    `(ΔS + shift)·d₀·d₁ = n₀d₁ + n₁d₀` is cubic
    (`ST/crates/constraint-framework/src/lib.rs:193-259`): bitwise,
    blake2b/boundary, blake2b, compare, cpu, divrem, memory_merkle,
    memory_page, mul, program_boundary, register_memory, ristretto and its six
    comb/ecall chips.
  - They must use `finalize_logup` (one fraction per column, degree 2), or an
    auxiliary product column, which costs the same.
  - Their interaction columns roughly double. The interaction tree was 1.95
    GiB against main's 4.22 GiB at production floors before the C2 diet, and
    "Logup pairing itself is fine (two lone tails)"
    (`P/docs/plans/roadmap.md:173-176`).
  - That is an estimated +30–45% committed bytes; measure it in 5.3.
  - Non-logup cubic constraints must be found too: the framework's
    `ExprEvaluator` reports constraint degrees. Split them with an auxiliary
    column.
  - The roadmap's "batch-4 logup" (`roadmap.md:200`, degree 5) is ruled out
    under masking.

**How many random coefficients (`h`) [argued, measured].** For a column with
mask offsets `O`, the proof reveals these base-field functionals:
- `4·|O|` from the OODS samples (QM31 values);
- `q` from the trace decommitment, one position per query
  (`ST/crates/stwo/src/prover/vcs_lifted/prover.rs:108-115`);
- `q·(|O|−1)` from the whole composition's openings, which read `f'` at
  `x·g^o` (2.3).

Stwo's periodicity sample for two-sample columns repeats a value
(`ST/crates/stwo/src/core/pcs/quotients.rs:313-326`).

That gives `|O|(q + 4)` in total, and with the 2× margin of 2024/1037 §4.2 as
Plonky3 applies it (`P3/fri/src/hiding_pcs.rs:65-79`), `h ≥ 2|O|(q + 4)`.

In vos-core `|O| ≤ 2`: the `#[mask_next_row]` columns (143 uses in
`P/src/chips`) and the logup cumulative column with offsets `[-1, 0]`
(`ST/crates/constraint-framework/src/lib.rs:233-235`). So:

| shape | queries | `h` | smallest component (`h ≤ N/4`) |
|---|---|---|---|
| STANDARD | 19 | 128 | 512 rows |
| MOBILE | 38 | 256 | 1024 rows |
| (b) STANDARD | 26 | 128 | 512 rows |
| (b) MOBILE | 76 | 512 | 2048 rows |

Smaller components, the boundary chips and the 256-entry tables, are padded up
to that floor. It is a small fixed cost.

The rank tests (section 5, leakage 1) confirm on real and random transcripts
that these revealed functionals are independent. The sizes tested are:
- one offset at `q = 19, 26`;
- two offsets at `q = 19, 38, 76`.

A query's shifted read can coincide with another query's position. That is
the same value revealed twice, so it is one functional.

**Preprocessed columns [measured].**
- They are public and get no randomizer, but they must be committed at
  `n_c + 1` like their component's masked columns.
- Stwo evaluates each column at
  `point.repeated_double(lifting − column_log_size)`
  (`ST/crates/stwo/src/prover/pcs/mod.rs:197-205`), so a preprocessed column
  left at `n_c` is lifted one doubling too far.
- Test `masked_logup_component_verifies_with_preprocessed_at_the_masked_level`
  verifies at `n+1` and is refused at `n`.
- The program id (the preprocessed root, `P/src/program_id.rs:1-34`)
  therefore changes once, with the masked format version.

**Multi-component lifting [measured].**
- Lifting moves to `m + 1`, so the AIR must be evaluated at level `m`, not at
  `lifting − B`: mask points stepped by `g_m`, and `v_m(z)`.
- A masked column of component `c` is then evaluated at
  `π^{m−n_c}(z·g_m^o) = π^{m−n_c}(z)·g_{n_c}^o`, the lifted semantics.
- Test `masked_components_of_different_sizes_lift_consistently` (2^11 and 2^9
  rows) passes at both rates.

### 2.2 Lookup (logup) columns and their sums

**Interaction columns are masked like main columns.**
- The cumulative constraint holds on `H` because `S' = S` there. The claimed
  sum, `shift = claimed/N` (`ST/crates/constraint-framework/src/logup.rs:32-35`),
  is unchanged, and so is logup's soundness.
- Measured: the masked logup component verifies with the unmasked claimed sum.
  Its cumulative column is sampled at two points.
- Paired fractions must be unpaired (2.1).

**The per-component claimed sums leak [measured].**
- They are public (`P/src/proof.rs:296`), and the lookup elements are public
  coins, so a witness guess can be checked by recomputing a sum.
- The same test shows the right guess reproduces the claimed sum and a changed
  column does not.
- vos-core also uses them as the public-input carrier: the verifier recomputes
  the boundary chips' sums from the public registers, pc, timestamp and memory
  roots (`P/src/boundary_binding.rs:116-160`) and checks `Σ claimed = 0`
  (`P/verifier/src/lib.rs:621-625`).

**Fix: blind each claimed sum [argued].**
- Each component gets four main columns `b_c` (one QM31 numerator) and one
  extra fraction per row, `b_c(x)/combine(BLIND)`, on a relation id nothing
  else uses. vos-core's `add_to_relation_with` already takes multi-column
  secure numerators (`P/src/lookups/logup_trace_builder.rs:96-120`).
- The prover samples the `b_c` uniformly with `Σ_c Σ_x b_c(x) = 0`. Then
  `claimed_c = true_c + B_c/(z − BLIND)` is uniform for all but one
  component, and the last is fixed by the public total.
- **Soundness:** the `b_c` are committed before the lookup challenges. The
  global check is a rational-function identity in the challenges, so the pole
  at `BLIND` forces `Σ B_c = 0` except with probability about
  `deg/|QM31|` (Schwartz–Zippel, as in the logup lemma [from memory]).
  Blinding therefore cannot absorb an unbalanced multiset of any real
  relation.
- Cost: about 4 columns per component, roughly 128 of ~15.8k.

**The boundary binding is re-cut.**
- Public boundary values enter one verifier-computed public logup sum: the
  entry and halt pc, the io-hash words φ9..12, and constants.
- Private values stay inside the trace: the other registers, the timestamp and
  the memory roots.
- The check becomes `Σ_c claimed_c + public_sum = 0`.

### 2.3 The composition polynomial: commit it whole

- Stwo splits the composition (bound `2N`) into `Q = Q_L + π^{m−1}(x)·Q_R`,
  halves of bound `N` (`ST/crates/stwo/src/prover/mod.rs:73-79`;
  `ST/crates/stwo/src/core/proof.rs:27-56`).
- The halves are global linear functionals of `Q`, outside the trace
  randomizer's reach. 2024/1037's abstract calls the quotient decomposition "a
  source for mistakes, both in literature as well as in software
  implementations".
- The split admits no randomization inside bound `N`. It is unique, and the
  §4.2 chunk masking `Q_L' = Q_L + π·s`, `Q_R' = Q_R − s` (Plonky3's
  `get_quotient_ldes`) needs halves of degree `N + h`.
- **Under 2.1 the split buys nothing,** because lifting is already at `m + 1`.
  Commit `Q` whole at `m + 1`: 4 columns instead of 8 half-size ones, the same
  field elements.
- Each opening `Q(x) = Σ α^i C_i(f'(x·g^o))/v_H(x)` is then local in masked
  values that `h` covers, so no separate randomizer is needed.
- **Soundness:** the DEEP-ALI identity is the same check
  (`Components::eval_composition_polynomial_at_point`, unchanged), and FRI
  bounds `Q` at `2N` exactly as it bounds the halves today.

### 2.4 The FRI batch: a random codeword

- FRI's inner layers, fold siblings and last layer reveal about
  `q × layers × 2^fold + 2^last` functionals of the batched DEEP quotient:
  hundreds.
- The randomness 2.1 puts into the batch spans only `h` dimensions, because
  `Σ_i γ^i v_H r_i` shares one `v_H`. Unmasked, the FRI layers would leak
  global combinations of the trace **[argued]**.
- **Fix:**
  - A uniform secure polynomial `R` of bound `2^{m+1}` (4 base columns) is
    committed in the composition tree, before the DEEP coefficient.
  - It is sampled at `z`, so its quotient `T = (R − R(z))/v_z` enters the
    batch. `T` is uniform and independent of `R(z)`.
  - When the coefficient's powers are M31-independent (probability about
    `1 − 2^−62`), the batch is uniform in the FRI code, and every FRI value can
    be simulated from the first-layer values at the queries.
  - This is Plonky3's `num_random_codewords ≥ Challenge::DIMENSION`
    (`P3/fri/src/hiding_pcs.rs:83-85, 247-262`).
- **Soundness:** `R` is fixed before the batching coefficient, so batched-FRI
  soundness (correlated agreement) covers `{quotients} ∪ {T}` unchanged.
- Cost: 4 columns.

### 2.5 Hiding commitments: salted leaves

**Which trees.**
- Every non-preprocessed tree: main, interaction and composition.
- The FRI layers optionally; their content is already uniform under 2.4.

**The salt.**
- Each leaf hashes its values plus a fresh 4-word salt (about 124 bits),
  revealed only for opened leaves.
- This is the standard IOP-to-argument hiding compilation
  (Ben-Sasson–Chiesa–Spooner 2016 [from memory]). Plonky3's
  `MerkleTreeHidingMmcs` sizes its salt so that "`SALT_ELEMS` ... is at least
  the target security parameter" (`P3/merkle-tree/src/hiding_mmcs.rs:23-33`).
- Without salts, an unopened sibling's hash lets an adversary test a guess of
  that leaf. The randomizer leaves only a few free dimensions per leaf (`h`
  minus what is revealed), so the salt is what makes the argument clean
  **[argued]**.

**The preprocessed tree is not salted.**
- It is public, and its root is the program identity
  (`P/src/program_id.rs:1-34`). A salt would make the id non-deterministic.
- So no private data may live in a preprocessed column. Kernel arguments,
  witness rows and the salt page belong in main-trace memory.

**In the prototype and in production.**
- The prototype salts with raw random columns that are never sampled
  (`commit_salted`). That is a salted leaf in effect, and needs no Stwo
  change.
- Moving the salt into `MerkleHasherLifted` touches a SECURITY-CRITICAL module
  of the fork. It would need the fork's supervised process (`ST/CLAUDE.md`,
  "Supervised"; `ST/AGENTS.md`).
- **Soundness:** binding is collision resistance, unchanged.
- Cost: about +4 words of hashing per leaf, nothing next to ~15.8k columns;
  `16 B × q × trees` of proof, under 2 KB.

### 2.6 What the FRI queries reveal

At a query `x` the proof opens:
- `f'(x)`;
- the opened leaves' salts;
- public preprocessed values;
- `Q(x)` (local, 2.3);
- `R(x)` (uniform).

Under 2.4 the layers are masked. A simulator samples these values uniformly,
computes `Q(x)` and the first-layer value, and runs FRI on a random codeword.
Salts make the sibling hashes random in the random-oracle model, and proof of
work and query positions are public coins **[argued]**.

### 2.7 Segment states the published format must hide

Today `Proof` publishes the following (`P/src/proof.rs:268-314`), all mixed
into Fiat–Shamir (`P/verifier/src/lib.rs:595-615`) and bound through the
boundary claimed sums:
- `claimed_sums`, `log_sizes`, `num_components`, `component_mask`,
  `pcs_config`;
- `initial_state` and `final_state`, each with `pc`, `timestamp`,
  `registers[13]`, `memory_commitment` and `memory_root`.

| field | ZK status | treatment |
|---|---|---|
| `registers` except φ9..12 | private | removed from the format; boundary binding re-cut (2.2) |
| φ9..12 | public (io-hash) | a public logup term |
| `timestamp` | private: the step count says how busy the run was | removed; the shape class pins a maximum |
| `pc` | entry and halt are program constants | public constants only |
| `memory_root`, initial and final | private: binds the arguments and witness | not published for a single-segment kernel; a salted commitment where a chain must link |
| `memory_commitment` (blake3 of the flat image, "unbound/vestigial", `proof.rs:274`) | a plain deterministic hash of private memory | **drop** |
| `claimed_sums` | private per component | blinded (2.2) |
| `log_sizes`, `num_components`, `component_mask`, `pcs_config` | public by shape class | fixed per kernel id |

**The salt page.**
- The salt page (the plan's random page in the initial image) makes a
  page-Merkle root a hiding commitment in the random-oracle model.
- It is needed exactly where a root is published:
  - a single-segment kernel publishes none;
  - a chain links segments by equality of salted boundary commitments
    (`final_i == initial_{i+1}`), with the registers spilled into the image or
    committed beside the root.
- The trace itself does not need it: 2.1 hides every in-trace value, the roots
  in `MEMORY_ROOT_BOUNDARY` included.

**For 5.1.**
- With private initial memory, a kernel's initial root cannot be the
  verifier's anchor, as it is in `verify_chain_standalone`
  (`P/verifier/src/lib.rs:737, 854`).
- The program binding must rest on the preprocessed program image
  (`PROGRAM_MEMORY`, inside the program id) plus the io-hash.
- The AIR must constrain the initial image's program pages to the
  preprocessed ones and leave the data pages free.

### 2.8 Why not blinding rows in the padding (upstream's approach)

**What each chip would need.**
- Either valid random rows, which CPU, memory and the tables cannot produce
  without changing the execution;
- or a preprocessed selector that disables every constraint on `h` rows. The
  selector raises degree by 1, which is cubic for today's quadratics and so
  overflows under masking. It also needs a boundary-anchored logup with a free
  cumulative column on the blinding rows, a new variant of `logup.rs`
  (SOUNDNESS-CRITICAL).

**Where the padding is.**
- The fixed tables are full: the 256-entry byte tables, and
  `BITWISE_AND_BYTE` at 2^16.
- CPU is full at `2^k`-step cuts. An 8k window has CPU at `L = 13`
  (`P/docs/plans/roadmap.md:116-125`).

**What it still needs.**
- Salts and the FRI mask.
- A composition fix: the split halves cannot be randomized within bound `N`,
  and committing the composition whole lifts everything by one level anyway.

**Verdict:** 32 chip rewrites and a new logup, to save the doubling only where
a chip happens to have slack. Variant (b) already keeps the commitment domains
at their unmasked size.

## 3. The number: the one-component prototype

**Code.**
- `ST/crates/examples/src/zk_masking/mod.rs`: `MaskLayout`, `mask_trace`,
  `commit_salted`, `MaskedComponent`, `prove_zk` and `verify_zk`.
- `ST/crates/examples/src/zk_masking/tests.rs`: 12 tests, all passing.
- `ST/crates/examples/examples/zk_masking_bench.rs`.
- Clippy (the fork's flags) and rustfmt are clean.

**The bench.**
- The AIR is wide Fibonacci (`ST/crates/examples/src/wide_fibonacci/mod.rs:77-101`):
  `N = 2^n` rows, 100 columns, 98 degree-2 constraints.
- Main columns masked with `h` sized for two-offset columns; main and
  composition trees salted; composition whole; a 4-column FRI mask.
- Blake2s Merkle channel and stored coefficients, as in vos-core.

**Trace heights.**
- Rows stay `2^n`.
- The committed degree bound goes from `2^n` to `2^(n+1)`.
- The LDE goes from `2^(n+B)` to `2^(n+1+B)` under (a), and stays at
  `2^(n+B)` under (b).

**Proof size and peak RSS [measured].**
- Deterministic; one process per variant, 20 PoW bits (`BENCH/runs.txt`).
- `h` here used Plonky3's one-point formula (64 to 256); `h` affects neither
  size nor time measurably.

| rows | variant | blowup / queries | LDE | proof bytes | ×base | peak RSS MiB | ×base |
|---|---|---|---|---|---|---|---|
| 2^16 | base | 16 / 19 | 2^20 | 102,400 | 1 | 761 | 1 |
| 2^16 | (a) zk-a | 16 / 19 | 2^21 | 108,416 | 1.06 | 1,583 | 2.08 |
| 2^16 | (b) zk-b | 8 / 26 | 2^20 | 128,304 | 1.25 | 823 | 1.08 |
| 2^16 | base-mobile | 4 / 38 | 2^18 | 134,992 | 1 | 215 | 1 |
| 2^16 | (a) zk-a-mobile | 4 / 38 | 2^19 | 150,432 | 1.11 | 451 | 2.10 |
| 2^16 | (b) zk-b-mobile | 2 / 76 | 2^18 | 239,344 | 1.77 | 258 | 1.20 |
| 2^18 | base | 16 / 19 | 2^22 | 119,088 | 1 | 3,042 | 1 |
| 2^18 | (a) zk-a | 16 / 19 | 2^23 | 127,648 | 1.07 | 6,287 | 2.07 |
| 2^18 | (b) zk-b | 8 / 26 | 2^22 | 150,896 | 1.27 | 3,271 | 1.08 |
| 2^18 | base-mobile | 4 / 38 | 2^20 | 165,424 | 1 | 863 | 1 |
| 2^18 | (a) zk-a-mobile | 4 / 38 | 2^21 | 192,464 | 1.16 | 1,752 | 2.03 |
| 2^18 | (b) zk-b-mobile | 2 / 76 | 2^20 | 298,496 | 1.80 | 1,004 | 1.16 |

**Prover CPU [measured].**
- Commit plus prove, trace generation excluded, grinding off (the same in
  every variant).
- One thread, minimum over interleaved runs (5 at 2^16, 3 at 2^18), on a quiet
  machine (load about 2; `BENCH/suite.txt`).
- Runs taken during another spike's load were up to 8× slower and erratic
  (`BENCH/cpu1.txt`), so they are not used.

| rows | base | (a) zk-a | (b) zk-b | base-mobile | (a) zk-a-mobile | (b) zk-b-mobile |
|---|---|---|---|---|---|---|
| 2^16 | 2.04 s | 4.27 s (×2.09) | 2.21 s (×1.08) | 0.60 s | 1.23 s (×2.05) | 0.73 s (×1.22) |
| 2^18 | 9.60 s | 20.98 s (×2.19) | 10.39 s (×1.08) | 2.79 s | 5.54 s (×1.99) | 3.29 s (×1.18) |

**Wall clock with 10 threads** (vos-core's cap) at 2^18 (`BENCH/suite-10threads.txt`):

| base | (a) zk-a | (b) zk-b | base-mobile | (a) zk-a-mobile | (b) zk-b-mobile |
|---|---|---|---|---|---|
| 2.67 s | 6.47 s (×2.42) | 3.17 s (×1.19) | 0.65 s | 1.54 s (×2.37) | 0.96 s (×1.47) |

The ratios are above the CPU ones because the prototype's masking scatter,
layout probe and salt generation are single-threaded. A production version
parallelizes them, so the CPU ratios are the fair measure of the work.

**Reading it for vos-core [argued from the measured ratios].**
- The doubling falls on committed bytes, and BLAKE2B_BOUNDARY is 88.8% of
  them in a chain window (`P/docs/plans/roadmap.md:116-125`).
- **Variant (a) on the MOBILE chain window** (about 5.2 GiB and 4 s,
  `roadmap.md:15-19`): ×2 for masking times about ×1.3–1.45 for unpairing
  gives about 13.5–15 GiB and 10–12 s. That is inside the 24 GiB placement.
- **Variant (b) on MOBILE:**
  - about ×1.3–1.45 in memory, at blowup 2 with 76 queries, a shape the roadmap
    calls "at the soundness margin" (`roadmap.md:110`);
  - about 1.8× the proof.
- **Proof and verify work do not double under either variant:**
  - (a) adds one Merkle and FRI layer plus the composition, salt and mask
    columns: +6–16%;
  - (b) adds queries: +27% STANDARD, +80% MOBILE.
- So spike 1's "twice the margin" is conservative. It needs about ×1.2 under
  (a), ×1.3 under (b)-STANDARD and ×1.8 under (b)-MOBILE.

## 3b. Variant (c) and the prover's rank check (after Fable's review)

Fable's review (`masking-review.md`, R8) pointed out that the note dismissed a
composition bound of `4N` only at the same blowup. This section measures it.

### What (c) is

- **Constraint bound.** Every component's constraint bound is `log_size + 2`
  (prototype: `ExpandedEval`; in vos-core, `LOG_CONSTRAINT_DEGREE_BOUND = 2`).
  The composition is committed whole at bound `4N`, at level `m + 2`.
- **Masked columns.** As in (a) and (b) they sit at `log_size + 1`, but with
  log blowup `B − 1`, so each column's own LDE is base-sized, as in (b).
- **Lifting.** The lifting sits at the composition's level, so every tree's
  leaf layer is `2^{m+1+B}`, as in (a).
- **FRI.** It runs at rate `2^{−(B−1)}` with (b)'s query counts: 26 at blowup
  8 for 98 conjectured bits, 76 at blowup 2 for 96.
- **Lifting semantics [argued, measured].**
  - The masked columns are lifted once more than the quotients (`π^{M−n−1}`
    against `π^{M−n−2}`). The AIR is therefore evaluated at level `m + 1`:
    mask points stepped by `g_{m+1}`, and `v_{m+1}(z) = v_n(π(z))`.
  - The composition is sampled at `π(z)` instead of `z`.
  - `composition_point` in `mod.rs` derives this from the components. For (a)
    and (b) it reduces to `z`.
  - DEEP-ALI's point is then uniform on the doubling image, half the circle,
    so its error at most doubles.
- **Degree [argued, measured].**
  - The masked cubic quotient has `x`-degree up to `N + 3h/2 − 1`, which fits
    `2N − 1` iff `h ≤ 2N/3`. Quartic needs `h ≤ N/4`.
  - The prototype's `h ≤ N/4` covers both.
- **Budget.**
  - The quotient's reads at a query `x` sit at `π^{M−n−2}(x)·g^o`. They never
    coincide with the column's own decommitment at `π^{M−n−1}(x)`, so every
    offset costs `q`.
  - That gives `h ≥ 2(4|O| + q(|O|+1))`: 256 for two-offset columns at 26
    queries, 512 at 76 (`ZkParams::for_queries_expanded`).

### Tests [measured]

- `variant_c_verifies_at_both_rates_and_refuses_tampering`: wide Fibonacci,
  2^11 rows, blowup 8 with 26 queries and blowup 2 with 76 queries. It
  verifies, and a changed OODS sample is refused.
- `variant_c_accepts_cubic_constraints_and_paired_logup`: the plonk component
  verifies masked at both rates. It has a cubic gate `op·a·b` and
  `finalize_logup_in_pairs`, which is cubic too. At bound `2N` the same
  component is refused (`masked_degree_three_constraints_do_not_fit_the_composition_bound`).

### A pinned-Stwo defect found on the way

**What happens.**
- Under (c) the preprocessed tree sits one level below the lifting. The pinned
  lifted Merkle verifier assumes increasing query positions
  (`ST/crates/stwo/src/core/vcs_lifted/verifier.rs:113-147`: it dedups only
  adjacent positions and pairs siblings in order).
- `prepare_preprocessed_query_positions` maps lifting positions into a shorter
  tree non-monotonically (`ST/crates/stwo/src/core/pcs/utils.rs:196-214`).
- So a valid proof can be refused. This happened: `RootMismatch` on the plonk
  test's seed. With a non-adjacent duplicate, the verifier would panic at the
  root `try_into().unwrap()` instead.
- It cannot accept a false proof. A misordered or duplicated position only
  breaks the root computation.

**Upstream and workarounds.**
- Upstream fixed it after our pin: `74951f79`, "Sort queries before computing
  auth paths", 2026-06-17.
- **Workaround in the test:** `PcsConfig::lifting_log_size = Some(lifting)`,
  which keeps every tree at the lifting height.
- **For 5.3:** either the same pin, or cherry-picking `74951f79`.
  `vcs_lifted` is SECURITY-CRITICAL in the fork, so the cherry-pick goes
  through its supervised process.

**Today's exposure.**
- vos-core today runs this path whenever its preprocessed tree is shorter
  than the largest trace column.
- In the measured chain shape it is not, because PROGRAM_MEMORY (preprocessed,
  `L = 18`) is the largest. Small kernels' shapes should be checked.

### Measurements [measured]

**Setup.**
- One wide-Fibonacci component: 100 columns, degree 2, the same AIR in every
  variant. For (c) it is wrapped to bound `log_size + 2`.
- Randomizer sized for two-offset columns.

**How measured.**
- Peak RSS and proof bytes: one process per variant, 20 PoW bits
  (`BENCH/runs-c.txt`). Proof bytes vary about ±5% between transcripts,
  through query dedup.
- Prover CPU: single thread, grinding off, minimum over interleaved runs (5
  at 2^16, 3 at 2^18), load 1–5 (`BENCH/suite-c.txt`).
- Verify: single thread, minimum of 30 (`BENCH/verify-c.txt`).

**Ratios against each shape's unmasked baseline** (STANDARD: blowup 16 / 19
queries; MOBILE: blowup 4 / 38):

| rows | variant | blowup / q | LDE / lifting | prover CPU | peak RSS | proof bytes | verify |
|---|---|---|---|---|---|---|---|
| 2^16 | base | 16 / 19 | 2^20 / 2^20 | 2.03 s | 759 MiB | 102,400 | 0.73 ms |
| 2^16 | (a) | 16 / 19 | 2^21 / 2^21 | ×2.10 | ×2.07 | ×1.05 | ×1.05 |
| 2^16 | (b) | 8 / 26 | 2^20 / 2^20 | ×1.10 | ×1.08 | ×1.25 | ×1.29 |
| 2^16 | **(c)** | 8 / 26 | 2^20 / 2^21 | **×1.58** | **×1.57** | **×1.35** | **×1.39** |
| 2^16 | base-mobile | 4 / 38 | 2^18 / 2^18 | 0.61 s | 213 MiB | 134,992 | 1.08 ms |
| 2^16 | (a)-mobile | 4 / 38 | 2^19 / 2^19 | ×2.02 | ×2.06 | ×1.14 | ×1.06 |
| 2^16 | (b)-mobile | 2 / 76 | 2^18 / 2^18 | ×1.23 | ×1.18 | ×1.73 | ×1.72 |
| 2^16 | **(c)-mobile** | 2 / 76 | 2^18 / 2^19 | **×1.70** | **×1.68** | **×2.03** | **×1.86** |
| 2^18 | base | 16 / 19 | 2^22 / 2^22 | 8.86 s | 3,033 MiB | 119,088 | 0.87 ms |
| 2^18 | (a) | 16 / 19 | 2^23 / 2^23 | ×2.16 | ×2.07 | ×1.11 | ×1.10 |
| 2^18 | (b) | 8 / 26 | 2^22 / 2^22 | ×1.09 | ×1.08 | ×1.35 | ×1.33 |
| 2^18 | **(c)** | 8 / 26 | 2^22 / 2^23 | **×1.60** | **×1.56** | **×1.40** | **×1.37** |
| 2^18 | base-mobile | 4 / 38 | 2^20 / 2^20 | 2.57 s | 849 MiB | 165,424 | 1.31 ms |
| 2^18 | (a)-mobile | 4 / 38 | 2^21 / 2^21 | ×1.97 | ×2.05 | ×1.18 | ×1.13 |
| 2^18 | (b)-mobile | 2 / 76 | 2^20 / 2^20 | ×1.16 | ×1.17 | ×1.82 | ×1.82 |
| 2^18 | **(c)-mobile** | 2 / 76 | 2^20 / 2^21 | **×1.64** | **×1.62** | **×2.10** | **×1.98** |

**Where (c)'s cost goes** (2^18, STANDARD, CPU at the minimum):
- the commit phase is ×1.23 over base (5.6 s → 6.9 s): the lifted leaf layer
  doubles, and the column LDEs do not;
- the prove phase is ×2.24 (3.3 s → 7.4 s): the constraint-evaluation domain
  doubles to `4N`, and so do the composition commitment and the first FRI
  layer.

So on vos-core, (c)'s factor depends on how much of a window's time is
constraint evaluation. That is not measured here; 5.3 must measure it.

**(c) against (a) or (b) with unpairing, projected for vos-core
[argued from the ratios].**
- (a) and (b) need the 18 paired chips unpaired. That adds an estimated
  +30–45% committed bytes, and the same fraction of opened values per query,
  which dominate a 15.8k-column proof.
- (a) with unpairing:
  - prover about ×2.6–2.9;
  - proof and verify about ×1.35–1.6 (its own +5–18% times the extra
    interaction columns).
- (b) with unpairing:
  - prover about ×1.4–1.7, at (b)'s rate;
  - proof and verify about ×1.7–1.9 at STANDARD.
- (c):
  - prover about ×1.6–1.7;
  - proof and verify about ×1.37–1.40 at blowup 8.
- So (c) is cheaper to prove than (a) with unpairing. Its proof and verify
  cost about as much. It needs no AIR rewrite.

### (c)'s soundness [argued]

**FRI.**
- (c) runs FRI at exactly (b)'s rate and query count, so it carries (b)'s
  caveat and no other.
- At blowup 8 with 26 queries:
  - rate 1/8;
  - 78 conjectured bits plus PoW;
  - 39 Johnson-provable bits, against today's 38.

  Fable judged this shape fine.
- At blowup 2 with 76 queries the caveat is the one Fable gave for (b): rate
  1/2 leaves no slack beyond the up-to-capacity conjecture. It is
  Johnson-neutral and matches upstream's Cairo parameters, but should not be
  used for settlement proofs.

**What (c) adds.**
- The composition bound is `4N`: the DEEP-ALI error doubles, from about
  `2^-103` to `2^-102`.
- The DEEP point is `π(z)`: its uniform set halves, so the error doubles
  again. Both are negligible.
- Lifting at `m + 2` adds one FRI layer.
- The constraint degree may be 3, or 4 at `h ≤ N/4`. That is a completeness
  limit on the honest prover, not a soundness one (Fable §2.3).
- `ExprEvaluator`'s static gate becomes "≤ 3" instead of "≤ 2".

### R1: the prover-side rank check [measured]

**What is built.**
- `revealed_functionals_independent` runs inside `prove_zk_ex` after
  `prove_values`. It reads the OODS point and the sampled query positions
  (`aux.unsorted_query_locations`).
- For every class of masked columns, keyed by level, quotient lift and offset
  set, it builds the matrix of revealed base-field functionals over the `h`
  randomizer coefficients:
  - the OODS samples, four rows each;
  - the decommitments;
  - the composition's reads at every query and offset, with coinciding points
    counted once.
- It asks for full row rank over M31. The prover returns
  `ZkProveError::RankDeficient`, and the caller re-randomizes and proves
  again.

**Tests.**
- All 15 prototype tests run with the check on.
- `the_prover_refuses_a_transcript_its_randomizer_cannot_hide` makes it fire
  (`h = 16` against 23 revealed values).

**Cost per proof here (one column class):**

| shape | rank check |
|---|---|
| (a) STANDARD | 0.16–0.20 ms |
| (b) STANDARD | 0.2–0.3 ms |
| (c) STANDARD | 0.9–1.4 ms |
| (a) MOBILE | 0.6–1.4 ms |
| (b) MOBILE | 2.9–5.5 ms |
| (c) MOBILE | 8.7–17 ms |

- The cost scales with `h × rows²`.
- vos-core has a few dozen classes, two-offset ones with more rows: about
  0.05 s at (a) STANDARD up to about 0.5–1 s at (c) MOBILE, single-threaded.
  That is under 10% of a window even before parallelizing over classes.
- In every transcript run in this spike, several hundred, the check never
  failed with the budgeted `h`. A retry, at the cost of one more prove, is
  expected never in practice.
- **Production placement:** the check could run right after the query
  positions are drawn, before the decommitment, but that saves little.

## 4. Toolchain and dependency moves

**Masking forces none.**
- The prototype builds and passes on `nightly-2025-07-14`, with `ST/Cargo.lock`
  unchanged.
- It uses rand 0.8's `StdRng`; `rand_chacha` and `getrandom` are already in the
  lock. Production wants an OS-seeded CSPRNG (ChaCha20 from `OsRng`), which
  needs no new crate.

**No soundness-critical Stwo file changes.** Every API the prototype uses is
public:
- `CommitmentSchemeProver::commit_tree`, the fields of `CommitmentTreeProver`,
  `MerkleProverLifted::commit`, `PolyOps::evaluate_polynomials`;
- `ComponentProvers::compute_composition_polynomial`;
- `Components::{mask_points, eval_composition_polynomial_at_point,
  composition_log_degree_bound}`;
- `CommitmentSchemeVerifier::{commit, verify_values}`.

So masking can live in vos-core's prover and verifier (`P/src/prove.rs`,
`P/verifier/src/lib.rs`) over the pinned Stwo. `verify_zk` uses only no_std
core APIs, so the no_std verifier and the Poseidon2 settlement verifier (fork
rev `6df2fb30`) can take the same logic.

**The toolchain moves on its own, if wanted.**
- Upstream's `02e5ae3e` replaces the removed slice `array_chunks` with
  `as_chunks`, fixes `into_remainder`, and bumps to `nightly-2026-01-15`.
- It applies cleanly to the fork: `git apply --check --exclude='.github/*'`
  passes. The patch is at `BENCH/02e5ae3e-rust194.patch` (23 files,
  +147/−63).
- vos-core's own crates may need their own fixes on that nightly; not checked.

## 5. Test plan for 5.3 (masking)

The prototype tests named below are in `ST/crates/examples/src/zk_masking/tests.rs`.

### Soundness gates, for every masked component

1. **Degree audit first.**
   - Every constraint of every chip is degree ≤ 3 under (c), or ≤ 2 under (a)
     or (b): a static test over the framework's `ExprEvaluator` degrees.
   - Under (a) or (b), the 18 paired-logup chips are unpaired.
   - Prototype: `masked_degree_three_constraints_do_not_fit_the_composition_bound`,
     `variant_c_accepts_cubic_constraints_and_paired_logup`.
2. **Masked acceptance.**
   - Every positive test in `test-proof` and `test-bench-proof` passes masked,
     on both published channels (Blake2s 24-zk, Poseidon2 25-zk).
   - Every chip appears at least once, below and above `2^16` (the SIMD layout
     boundary).
   - Prototype: `masked_proof_verifies_at_both_rates` (2^8, 2^10, 2^16).
3. **Constraint tamper per chip.**
   - One broken constraint on one row of `H`: the first row, the last row and
     the wrap row.
   - The masked prover's OODS check refuses it, and a forced proof (check
     skipped) is refused by the verifier.
   - Re-run the existing gates masked: `ledger_readconsistency_gate`,
     `precompile_tamper`, and the boundary tampers.
   - Prototype: `invalid_witness_is_refused_by_prover_and_verifier`.
4. **The mask invariant per size.** `f'|_H = f`, and `(f' − f)/v_H` has
   exactly `h` coefficients. Prototype:
   `mask_agrees_with_the_trace_on_its_domain_across_fft_boundaries` (2^6 to
   2^17).
5. **The degree budget and the rank check (R1).**
   - The prover refuses `h > N/4`.
   - The prover checks, on its own transcript, that every masked column
     class's revealed functionals have full rank, and re-randomizes otherwise.
   - A static check: `h ≥ 2|O|(q + 4)` for every column, or
     `2(4|O| + q(|O|+1))` under (c).
   - Prototype: `query_budget_covers_every_revealed_functional`,
     `the_prover_refuses_a_transcript_its_randomizer_cannot_hide`.
6. **Lifting.**
   - Components of different sizes in one proof.
   - Preprocessed columns at `n+1` verify; at `n` they are refused.
   - Prototype: `masked_components_of_different_sizes_lift_consistently` and
     `masked_logup_component_verifies_with_preprocessed_at_the_masked_level`.
7. **Tampered masked proofs are refused.** Change any one of:
   - an OODS sample;
   - a queried trace value;
   - a salt (Merkle error);
   - the FRI mask's sample;
   - a composition sample;
   - a blinded claimed sum;
   - the number of salt or mask columns.

   Format versions keep masked and unmasked proofs apart. Prototype:
   `tampered_proofs_are_refused` and
   `the_unmasked_verifier_refuses_a_masked_proof`.
8. **Logup blinding soundness.**
   - A prover that unbalances a real relation (consumes a value no table has)
     and sets `Σ B_c` to cancel it at the drawn challenges is refused.
   - A static check that only the blinding relation uses its id.
9. **Structure.**
   - Wrong `log_sizes`, a missing tree, or a wrong sample count returns
     `InvalidStructure`, never a panic.
   - The prototype's `verify_zk` checks the sample shape but can still panic
     inside `verify_values` on a tree-width mismatch. Production must pre-check
     it.
10. **Security accounting.** `security_bits() ≥ 96` for each masked shape.

### Leakage tests

1. **The simulator's precondition, as a rank test.**
   - Replay the transcript, or draw points as Fiat–Shamir would.
   - Build each column class's matrix of revealed base-field functionals,
     restricted to `v_H·L_h`.
   - Assert full row rank over M31. Then the revealed values are uniform for
     every witness.
   - Prototype:
     - `revealed_trace_values_are_uniform_given_the_randomizer` (one offset,
       real transcripts);
     - `two_offset_columns_reveal_independent_functionals` (two offsets with
       the composition's shifted reads, at 19, 38 and 76 queries).
   - Extend to every column class of every chip, on both channels.
2. **A simulator.**
   - Public inputs only: sample the masked openings uniformly, compute `Q(x)`
     and the first-layer values, and run FRI on a random codeword.
   - Compare its output distribution with real proofs field by field
     (chi-square on bit buckets, KS on values), for two witnesses.
3. **Witness-pair indistinguishability.**
   - Pairs: a zero witness against a random one; two settlement amounts that
     differ by 1.
   - Compare every published field: OODS samples, queried values, salts,
     composition, FRI siblings and last layer, claimed sums. Use a
     Bonferroni-corrected chi-square.
   - Control: unmasked, the zero witness opens to all zeros.
   - Prototype: `openings_of_a_zero_witness_look_uniform_when_masked`.
4. **Hidden states.**
   - A serialized published proof contains none of: a plain hash of the
     private arguments, the step count, a memory root, `memory_commitment`, or
     a register other than φ9..12. Check with a byte search against the live
     run's values.
   - Two runs with different private arguments and the same output have
     identical public parts.
5. **Fresh randomness.**
   - Two proofs of one witness differ in every root and every claimed sum.
     This guards against upstream's witness-seeded blinding.
   - The randomness source is OS-seeded.
6. **The claimed-sum control.**
   - Unblinded, a right guess reproduces the sum; blinded, it does not.
   - Prototype: the end of
     `masked_logup_component_verifies_with_preprocessed_at_the_masked_level`.

### Measured in 5.3

- Prove time and peak memory per kernel, masked against unmasked, at the
  chosen variant.
- The unpairing cost on its own.
- Proof size.
- Spike 1 re-run masked.

## 6. Recommendation and open points

**Recommendation.**
- **Mask in the pinned fork,** in vos-core's prover over its public API. Do
  not move upstream.
  - Upstream offers no ZK for our AIR; its privacy ZK is a recursion wrap
    with a partial recipe and witness-seeded randomness.
  - The pinned Stwo exposes everything masking needs. Every tree is pinned to
    the lifting height, or upstream's `74951f79` is cherry-picked under
    supervision.
- **Published proofs: variant (c) at blowup 8 with 26 queries.**
  - Soundness as (b)-STANDARD, which Fable judged fine.
  - Cubic constraints stay, so there is no 18-chip unpairing.
  - Prover about ×1.6 measured, pending the real chips' constraint-evaluation
    share.
  - Proof and verify about ×1.4, about what (a) with unpairing would cost.
  - If 5.3 measures constraint evaluation dominating, fall back to (a) with
    unpairing: same proof, at prover about ×2.6–2.9.
- **Phones:** (c) at blowup 2 with 76 queries, for proofs that stay inside a
  space.
  - Memory about ×1.6–1.7.
  - Blowup 2 has no slack beyond the up-to-capacity conjecture, so phones'
    settlement proofs go at blowup 8 or are re-proved by a server.

**Open points, for 5.1 and 5.3.**
- **The constraint-degree gate:** ≤ 3 under (c), ≤ 2 under (a) or (b), as a
  static `ExprEvaluator` test (Fable R5).
- **Format decisions for 5.1:**
  - the boundary re-cut (2.2);
  - the program binding without a public initial root (2.7);
  - format pins for `h`, salts, mask columns, the AIR level and the composition
    point (Fable R6).
- **Built and tested in the prototype:**
  - trace masking, salts, the whole composition and the FRI mask;
  - multi-size lifting;
  - masked logup with preprocessed columns at the masked level;
  - variant (c) with cubic constraints;
  - the prover's rank check (R1).
- **Argued but not built:**
  - claimed-sum blinding and the boundary re-cut (R2);
  - the FRI-layer rank test (R3);
  - hedged randomness (R4).
- **The salt's form.** Salts inside `MerkleHasherLifted`, rather than as
  columns, need the fork's supervised process (`ST/CLAUDE.md`,
  `ST/AGENTS.md`). The column form needs none.
- **The test command** for the prototype is
  `cargo test -p stwo-examples --release --features parallel --lib zk_masking`.
  The crate has no `prover` feature.
- **The papers** could not be fetched. The §4.2 budget and chunk masking of
  2024/1037 are taken from Plonky3, which implements and cites them. Fable's
  review checked 2.1–2.4 from its own knowledge of the papers.
