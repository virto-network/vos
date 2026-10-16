# Review: zero-knowledge masking for the VOS prover (spike 2)

Reviewer: Fable, 2026-10-15. Read-only. Inputs: `spike2-masking.md`; the fork
branch `zk-masking-spike` (`539f419..92ecb7e`, `crates/examples/src/zk_masking/`);
`docs/design/slice-5-proving.md`; `pvm/proof`. The eprint papers are not
reachable from here either (both local "PDFs" under `tmp/s5/papers/` are 403
HTML pages), so the comparison with Haböck–Kindi (2024/1037), the Circle STARKs
paper (2024/278) and BCS 2016 is from my own knowledge of them, cross-checked
against the fork's paper digests (`ST/.agents/papers/llm/`) and the Stwo
source. I re-ran the prototype: 12/12 tests pass (`cargo test -p stwo-examples
--release zk_masking`, 3.4 s; the note's `--features prover` flag does not exist
on that crate).

## Verdict: **sound with changes**

- **Soundness** is not weakened by any of the six mechanisms. Variant (a)
  keeps the FRI rate and every error term within a factor 2 of today; variant
  (b) is Johnson-neutral (see §2.1). The DEEP-ALI check, the logup argument
  and FRI's correlated agreement are untouched; the prototype's masked
  verifier uses the stock `verify_values` and `eval_composition_polynomial_at_point`.
- **Zero-knowledge:** the construction is the standard randomized-trace +
  hiding-commitment + FRI-mask recipe, correctly fitted to the circle and to
  Stwo's lifted PCS. It is honest-verifier ZK of the IOP, hence NIZK in the
  **programmable** random-oracle model by the BCS compilation, **conditional
  on one precondition the note only tests empirically** (§1.1, the rank
  condition) and on two argued-but-unbuilt pieces (claimed-sum blinding, the
  boundary re-cut).
- The changes required before 5.3 are listed in §5. None is a redesign; two
  are gates that must become prover-side checks rather than tests on sample
  transcripts.

The rest of this note goes through the five questions in order.

---

## 1. Zero-knowledge

### 1.1 Masking degree: `f + v_H·r`

**The algebra on the circle is right.** For the canonic coset `H` of size
`N = 2^n`, `coset_vanishing` is `π^{n-1}(x)` with zero shift
(`core/constraints.rs:12-31`), which is exactly the basis element the size-2N
circle-FFT basis adds, so `v_H·L'_h` (randomizer in the size-`h` FFT space)
occupies `h` fixed coefficient slots of the size-2N basis, and `f' = f + v_H·r`
has `f'|_H = f` with `f' ∈ L'_{2N}`. `MaskLayout::new` probes the backend's
storage order rather than assuming it, which is the right fix for the SIMD
reorder above 2^16; the test covers 2^6..2^17.

**Domains.** `H` (odd multiples of `g_{n+1}`), the composition's evaluation
domain (odd multiples of `g_{n+2}`) and every LDE domain (odd multiples of
`g_{n+B+1}` or `g_{n+B+2}`) are pairwise disjoint, so no query ever lands on
`H`, and `v_H ≠ 0` at every revealed point. The lifted semantics
(`f'∘π^{m-n_c}` on the lifting domain, mask offset `o` → `+o·g_{n_c}`) compose
correctly with the mask because `π` commutes with the group law; the
two-size test and the logup-with-preprocessed test exercise exactly this.

**The count of revealed functionals is right.** Per base column with mask
offsets `O`:

- `4·|O|` M31 functionals from OODS (a QM31 sample of an M31 column is 4
  base functionals; the conjugate sample is determined, not extra);
- `q` from its own leaf at each query (one position per query in the lifted
  tree, `vcs_lifted/prover.rs:108-115`);
- `q·(|O|-1)` *through the whole composition's opening* `Q(x_q)`, which is a
  function of `f'(x_q·g^o)`;
- the "periodicity" sample Stwo adds for two-sample columns
  (`core/pcs/quotients.rs:313-326`) repeats the OODS value; it is a FRI
  constraint on the column, not a new revealed value. Correct in the note.
- The FRI inner layers, fold siblings and last layer are functionals of the
  batch, not of `f'`, and are covered by the FRI mask (§1.4). The PoW adds
  nothing.

So `|O|·(q+4)` is the necessary count. **The factor 2 is not a theorem.**
Haböck–Kindi count the revealed evaluations (FRI queries plus `k` base
functionals per extension-field opening) and ask for at least that many
random coefficients; Plonky3 doubles it and calls it "conservative"
(`hiding_pcs.rs:65-79`). Keep the 2× as headroom, but do not treat it as the
guarantee.

**The actual precondition is a rank condition, and on the circle it is not
automatic.** What the simulator needs is that the map
`r ↦ (revealed functionals of v_H·r)` from `L'_h` is *surjective*. For
univariate codes any `k ≤ h` distinct points impose independent conditions
(Vandermonde). On the circle, `L'_h` is a codimension-1 subspace of
`L_h = {total degree ≤ h/2}`, and evaluation of `L'_h` at `k ≤ h` distinct
points can be degenerate: `h = 2` fails at `(x,y),(−x,y)`; for general `h`
the vanishing polynomial of the *subgroup* `G_h` (and of rotations
`Q + D_h` with `x((h/2)·Q) = 0`) lies in `L'_h`, so `h` points of such a set
impose only `h−1` conditions. Query positions live on an LDE canonic coset,
which is disjoint from every `G_h`, and with `2k ≤ h` the bad configurations
are a measure-tiny algebraic set, so the prototype's rank tests pass as
expected. But a test on four seeds is evidence, not a proof. **Required
change (R1):** the production prover computes the `k × h` rank for every
column class on the actual transcript (it has the OODS point and the query
positions before it finalises; the matrix is at most 512 × 512 over M31,
microseconds) and, if deficient, re-randomises and re-proves. That makes the
precondition hold with probability 1 for every published proof, and the
simulator argument no longer depends on a "generic position" claim.

**`h ≤ N/4` and the degree-2 requirement.** The derivation is right and I
re-derived it: `f' = f_0(x) + y·f_1(x)` with `deg ≤ N/2 + h/2 − 1`; a product
of two such has `y`-free `x`-degree `≤ N + h`, so `C(f')/v_H` has `x`-degree
`≤ N/2 + h`, which is inside `L'_{2N}` (no `x^N` term) iff `h ≤ N/2 − 1`
(hence `N/4` at powers of two). Three factors give `N + 3h/2 − 1 > N − 1` for
every `h ≥ 1`, which is why unmasked cubic constraints fit `L'_{2N}` exactly
and masked ones never do. Note this is a *completeness* constraint on the
honest prover (its composition would not interpolate on the 2N domain), not a
soundness one.

### 1.2 Salted leaves

Four M31 words ≈ 124 bits per leaf, fresh per leaf and per column, hashed
into the leaf with the column values, revealed only when opened: this is the
BCS hiding Merkle tree. 124 bits is above the 96-bit target and matches
Plonky3's `SALT_ELEMS ≥ security parameter`. Binding is unchanged (collision
resistance). The column form (`commit_salted`) is equivalent to a salted
hasher because the lifted tree hashes every column of a leaf at the leaf
layer; it keeps the fork's SECURITY-CRITICAL `vcs_lifted` untouched, which I
prefer for 5.3.

Two remarks. (i) Masked leaves are already hiding by the mask entropy
(`W` columns × 31 bits), and composition/FRI leaves by `R`, so salts are
belt-and-braces; keep them, they make the BCS argument clean and cost ~2 KB.
(ii) Salts, like masks, are only as good as the RNG: see R4 (hedged
randomness).

### 1.3 Composition committed whole

Correct, and it is the right reading of Haböck–Kindi's warning about the
quotient decomposition. Stwo's split `Q = Q_L + π^{m-1}(x)·Q_R` is a
coefficient split: `Q_L(x)` and `Q_R(x)` are global linear functionals of
`Q`, i.e. of the whole trace, which no per-column randomizer covers; the
§4.2 chunk randomisation (`Q_L + v·s`, `Q_R − s`, Plonky3's
`get_quotient_ldes`) needs halves of bound `N + h`, which Stwo's halves do
not have. With lifting already at `m+1`, committing `Q` whole at bound
`2^{m+1}` costs nothing extra (same field elements, 4 columns instead of 8)
and makes `Q(x_q)` a *local* function of `f'(x_q·g^o)`, which `h` covers.
FRI bounds `Q` at `2^{m+1}` exactly as it bounds the halves today; the
DEEP-ALI identity is the same check. Sound.

### 1.4 FRI mask codeword

Necessary and sufficient as designed. Without it, the FRI inner layers reveal
hundreds of global functionals of the batch `Σγ^i T_i` whose randomness from
2.1 spans only `h` dimensions per column (one shared `v_H`). With `R`
uniform in `L'_{2^{m+1}}` (four base columns), sampled at `z` and committed
before the batching coefficient:

- `T_R = (R − I_R)/pv_z` is uniform on an affine space of dimension
  `4·(2^{m+1} − 4)` given `R(z)`; the FRI functionals (≈ `q·layers + 2^last`,
  a few hundred) are M31-linear in `R`, so they are uniform whenever the
  QM31-span condition on `γ^{j..j+3}` holds (fails with probability ≈ 2^-62,
  i.e. when `γ` lies in a proper subfield — detectable and re-randomisable).
  This is Plonky3's `≥ Challenge::DIMENSION` random codewords.
- The λ-term of Stwo's circle FRI (`f = g + λ·v`, `prover/fri.rs:70`) is
  identically zero for an honest batch of DEEP quotients (they live in
  `L_{2N-2} ⊂ L'_{2N}`), so it leaks nothing.
- Soundness: `R` is fixed before `γ`; correlated agreement covers
  `{T_i} ∪ {T_R}` unchanged; four more columns are negligible in the
  `d/|F|` terms.

**Change (R3):** the simulator precondition for the FRI layer functionals is
argued, not tested; the chi-square on last-layer values is weak evidence. Add
a rank test over `R`'s coefficients for the inner-layer siblings and last
layer on a real transcript, on both channels.

### 1.5 Claimed-sum blinding (argued only)

The design is sound and it is the right fix. Each component adds
`b_c(x)/combine_B(BLIND)` on a relation id used by nothing else, with `b_c`
in the main trace (committed before the lookup challenges) and
`Σ_c Σ_x b_c = 0`.

- **Hiding:** `claimed_c = true_c + B_c/(z_B − BLIND')` with `B_c` uniform
  for all but one component; the set of claimed sums reveals exactly
  `Σ_c claimed_c = −public_sum`, which is public anyway.
- **Soundness:** the global check is a rational identity in the challenges
  `(z_B, z_R, α_R…)`. The blinding term is the only one with a pole at
  `z_B = BLIND'`, so the identity forces `Σ_c B_c = 0` and `Σ_c true_c = 0`
  separately; clearing denominators gives a polynomial of degree ≈ (number
  of fractions), so the Schwartz–Zippel error is ≈ 2^20/2^124. A prover cannot
  use `B_c` to absorb an unbalanced real relation. This is exactly the logup
  lemma with one more relation; the multiplicities-mod-p caveat is
  unchanged (rows ≪ p).
- One blinding value per component suffices (one non-zero row); per-row
  `b_c` is fine but not needed. Either way the 4 base columns are masked
  like any main column.

**Required (R2):** build it, with gate §5 soundness-8 (unbalanced relation
plus compensating `Σ B_c`) and the static check that only the blinding
relation uses `BLIND`'s id.

### 1.6 The boundary re-cut

Sound in outline: the verifier computes `public_sum` from the public inputs
(entry/halt pc, io-hash words, constants) with the drawn lookup elements and
checks `Σ_c claimed_c + public_sum = 0`; private boundary values stay in-trace.
Today's `check_boundary_claimed_sums` (`boundary_binding.rs:116-168`)
recomputes *four* boundary chips' sums from `initial_state`/`final_state`
and the verifier mixes both states into FS (`verifier/src/lib.rs:595-615`);
all of that goes. The re-cut must make sure every relation entry the trace
produces for a now-private value is consumed in-trace (or not emitted) — a
dangling produced entry with no consumer is a soundness hole, a dangling
consumer is a completeness hole. 5.1 should write the table of (relation,
producer, consumer, public/private) per boundary chip.

### 1.7 The ZK model

HVZK of the IOP (randomized trace + whole composition + FRI mask + blinded
sums) ⇒ NIZK in the programmable ROM via BCS with salted leaves. The
simulator programs the oracle to fix the OODS point and query positions,
samples every masked opening uniformly (justified by R1), computes `Q(x_q)`
and the first-layer values, interpolates fake `f''` of bound 2N through the
simulated openings, samples `R` consistently, and runs real FRI. Statistical
distance: the 2^-62 γ-degeneracy only. Non-programmable-ROM ZK is not
achieved by any FRI-STARK of this shape; this is standard.

---

## 2. Soundness

### 2.1 Doubled degree bound and FRI parameters

- **Variant (a):** rate unchanged (`2N / 2N·2^B = 2^-B`), one more FRI layer,
  all `d/|F|` error terms at most 2×: ≈ 2^-103 instead of 2^-104. Security
  accounting `pow + q·log_blowup` is unchanged at 96. Sound as designed.
- **Variant (b):** rate halves; queries are raised so that
  `q·log_blowup` is preserved under the up-to-capacity conjecture
  (26·3 = 78 ≥ 19·4 = 76; 76·1 = 76 = 38·2). Under the *proven* Johnson
  regime each query gives `log2(1/√ρ) = log_blowup/2` bits, so (b) is
  **Johnson-neutral too**: 38 provable bits + 20 PoW = 58 in all four shapes.
  Upstream's Cairo prover ships `log_blowup 1, 70 queries, 26 PoW`
  (`UP/crates/prover/src/prover.rs:387-394`), so (b)-MOBILE's blowup 2 is
  within industry practice. The caveat is qualitative: at rate 1/2 the
  conjectured regime (`δ → 1/2`) and the proven one (`δ < 0.29`) leave no
  slack, and the strongest proximity-gap conjectures are under active
  scrutiny. I would not publish settlement proofs at blowup 2; (b)-STANDARD
  (blowup 8, 26 queries) is fine.
- The verifier's `MIN_CONJECTURED_SECURITY_BITS` floor accepts both (b)
  shapes (98 and 96); `PcsPolicy` pins must be re-cut for the chosen shape.

### 2.2 Extra query cost

No soundness effect; the only effect of more queries is more revealed
functionals, which the budget already scales with `q`.

### 2.3 Composition degree with masked columns

The verifier enforces bound `2^{m+1}` on `Q` and every column via FRI and
checks `Q(z)·v(z) = Σ α^i C_i(f'(z·g^o))` at a random `z`. If the identity
fails as polynomials the difference has total degree `≤ 3N` (cubic in
`f' ∈ L_{2N}`), hence `≤ 6N` zeros on the circle over QM31 (~2^124 points):
error `≤ 2^-100`. Soundness does not depend on what degree the *honest*
prover's `f'` has, so the masked bound is sound for any constraint degree;
the degree-2 rule is for completeness only (1.1).

The AIR level `m` must come from the pinned shape (the verifier's own
components), not from the tree height; the prototype does this
(`air_log_size(&components)`), production must keep it so.

### 2.4 Degree ≤ 2 and logup unpairing

`finalize_logup_in_pairs` is cubic (`constraint-framework/src/lib.rs:193-259`:
`diff·d0·d1 − (n0·d1 + n1·d0)`), the unpaired form `diff·d − n` is quadratic
when the tuple is degree ≤ 1 in trace columns and the multiplicity is degree
≤ 2 (blake2b's `r·l` numerators and ristretto's `real·(1−flag)` are fine;
the CPU rule "tuples degree ≤ 1", `chips/cpu/CONSTRAINTS.md:19`, must hold
for every chip). Unpairing is a behaviour-preserving change to the AIR with
no soundness effect; 19 chips use the paired form, 14 the unpaired. Gate:
`ExprEvaluator` degree ≤ 2 for every constraint of every chip, as a static
test.

**An alternative the note did not evaluate — variant (c).** The note rejects
`LOG_CONSTRAINT_DEGREE_BOUND = 2` because "the masked columns go to `n+2`
(4× LDE)" — that is only true at the same blowup. Put the lifting at `m+2`
with log blowup `B−1`: the commitment domain is `2^{m+1+B}`, the same as
variant (a); each column's own LDE is base-sized (as in (b)) and lifted by
repetition; FRI runs at rate `2^{-(B-1)}` with (b)'s query counts; the
composition fits cubic constraints masked (`N + 3h/2 − 1 ≤ 2N − 1` for
`h ≤ N/2`) and even quartic ones at `h ≤ N/4`. Cost: (a)'s Merkle and
composition size, (b)'s column LDE, (b)'s proof size, **no unpairing**
(saves the estimated +30–45 % interaction bytes and the 18-chip rewrite).
Soundness is identical to (b)'s analysis. It needs Stwo's framework to
accept `max_constraint_log_degree_bound = log_size + 2` under lifting
(the trait allows it; vos-core hard-codes 1). Measure (a)+unpairing against
(c) in 5.3 before committing to the unpairing.

### 2.5 Interaction columns masked after the challenges

No effect. The verifier only checks the logup constraints on `H`, where the
mask vanishes; off `H` the prover may commit any polynomial of bound 2N in
a non-ZK proof too. The randomizer being chosen after the challenges gives
the prover no new degree of freedom the verifier checks. The claimed-sum
shift `claimed/N` keeps `N = 2^{n_c}` (the row count), unchanged.

### 2.6 Preprocessed columns at the masked level

Required and correct: the lifted verifier evaluates a column declared at
`n_c` at `π^{lifting−n_c}(z)`, one doubling too many; the test refuses `n`
and accepts `n+1`. The polynomial is unchanged (an `extend`), but the lifted
tree's leaves are `p∘π^{L−n_c−1}` instead of `p∘π^{L−n_c}`, so the
preprocessed root (program id) changes under (a). (Under (b) the tree height
and the leaf values coincide with today's, so the program id may be
byte-identical; do not rely on it either way — re-pin.) The tree stays
unsalted and public; the invariant "no private or execution-dependent data in
a preprocessed column" must be a static check (the current program id
already depends on `log_sizes`, which the shape class pins).

### 2.7 Things I checked that are fine

- Columns with no sample points (salts) are decommitted but never enter the
  quotient; a salt tamper is a Merkle error (test).
- The FRI first layer is one batched column in the lifted PCS; siblings
  come from the first-layer tree, so the trace is opened once per query.
- `h` is a prover-side parameter; the verifier does not need it. Pin it in
  the format anyway, for auditability.

---

## 3. The published format: what else can leak

Dropping `initial_state`/`final_state` and `memory_commitment` from the
format and from FS is right and necessary. The remaining channels:

| channel | status | note |
|---|---|---|
| registers (except φ9..12), timestamp, pc | hidden | pc is a constant; the re-cut must not leave a public term for any of them |
| `claimed_sums` | hidden once blinded | today they are a deterministic function of the witness given the public coins: a guess oracle (the test shows it) |
| `memory_root`, initial/final | hidden if unpublished; hiding commitment if published | see salt page below |
| `memory_commitment` (blake3 of the flat image) | **drop** | plain hash of private data |
| io-hash φ9..12 | public by design | fine as long as its preimage (public args, output, roots read) is meant to be public; if any part is low-entropy and private, it needs a nonce in the preimage |
| program id, format, shape class | public by design | if a kernel has several shape classes, the class chosen leaks a coarse execution size |
| `log_sizes`, `component_mask`, `pcs_config` | fixed per kernel id | the prover must pad to the class unconditionally; an overflow must fail, not pick a bigger class silently |
| number of segments in a chain | **leaks** | step count at segment granularity (`2^k` steps per proof); the note hides the timestamp but not this |
| per-segment published roots in a chain | hiding commitments | equal roots across consecutive segments are by construction; but equal roots across *non-consecutive* ones would reveal "no memory change" — only publish what the linking needs, or verify the chain as one statement |
| proof size, FRI witness length | public coins only | distinct-query dedup depends on the transcript, not the witness |
| timing | side channel | prover wall time depends on real vs padded rows only weakly, but publication time and grinding jitter exist; batch or delay publication if it matters |
| preprocessed tree openings | public | program image, tables |
| other carriers | **audit** | `RefinePayload` (`src/refine/encode.rs`) and the JAM anchor chain carry memory roots today; the `Attest` record carries the salt; every carrier of a root or state must be re-cut, not just `Proof` |

**Is a salt page in the initial image enough to hide the initial root?**
Yes, under these conditions, all of which 5.1 must state:

1. the page is uniformly random with ≥ 128 bits of entropy, fresh per run
   (reuse across runs makes identical images linkable);
2. the hash (`page_merkle.rs`, blake2b-256 per page) is modelled as a random
   oracle; then the root `H(…, H(salt page), …)` hides every other page
   because any test of a guess needs the sibling subtree hash that depends on
   the salt;
3. **no node hash other than the published root is ever published**: page
   hashes, path nodes and subtree roots in the trace are masked (fine), but
   nothing else may emit them (CAS of page blobs, debug output, the refine
   payload);
4. the salt page is never overwritten or read out during the run and stays in
   the image through every published boundary root;
5. the program pages are bound to the preprocessed image by the AIR (5.1),
   since the verifier can no longer compare the initial root.

A single-segment kernel should publish no root at all; the io-hash and the
program id carry the statement.

---

## 4. Variant (a) or (b)

- **Published proofs (server, 24 GiB):** (a), as the note recommends: proof
  and verify +6–16 %, same FRI rate as today, provable and conjectured bits
  unchanged. Evaluate (c) first (§2.4): it may make the unpairing
  unnecessary at (b)'s proof size; if verify cost at the venue dominates,
  (a)+unpairing wins; if prover work and engineering risk dominate, (c).
- **Phones:** (b)-MOBILE is Johnson-neutral and matches upstream's Cairo
  parameters, so it is acceptable for proofs that stay inside a space; I
  would not use blowup 2 for settlement proofs. (b)-STANDARD (blowup 8,
  26 queries, +27 % proof) is the safer trade if memory binds.
- The prototype's wall-clock ratios (×2.4) overstate (a) because masking,
  layout probing and salt generation are single-threaded in the spike;
  parallelise them in 5.3 before measuring the chain window.

---

## 5. What must be true before 5.3 builds it

### Required changes

- **R1. Prover-side rank check** of the revealed-functional matrix per column
  class on the actual transcript, with re-randomise-and-retry on deficiency
  (§1.1). The simulator theorem rests on it.
- **R2. Build the claimed-sum blinding and the boundary re-cut** (§1.5,
  §1.6), with the relation table per boundary chip and the two gates below.
- **R3. Rank test for the FRI mask** over the inner-layer and last-layer
  functionals (§1.4); and detect the `γ` subfield degeneracy.
- **R4. Hedged randomness:** seed the mask/salt stream from
  `H(OS randomness ‖ witness digest)`. Pure OS randomness fails silently if
  RNG state is replayed (VM snapshot, forked process): two proofs with the
  same masks and different witnesses leak `f_1 − f_2` at every opening.
  Pure witness-derived randomness is upstream's mistake. Hedging is immune to
  both.
- **R5. Degree audit:** static `ExprEvaluator` test that every constraint of
  every chip is degree ≤ 2 and every relation tuple is degree ≤ 1 — unless
  variant (c) is adopted, in which case the bound is ≤ 3 (and ≤ 4 at
  `h ≤ N/4`).
- **R6. Format pins:** `salt_columns`, `FRI_MASK_COLUMNS`, `h`, the AIR level
  `m`, and the per-class `log_sizes` are format constants checked by the
  verifier (never read from the proof); structure errors are
  `InvalidStructure`, never panics (the prototype can still panic on a
  tree-width mismatch).
- **R7. Carrier audit** (§3): every struct that leaves the prover's trust
  domain is checked for roots, states, plain hashes of private memory.
- **R8. Measure (c) against (a)+unpairing** before the 18-chip rewrite.

### Soundness gates (the note's ten, with amendments)

The note's gates 1–10 are the right set. Amend: gate 5 becomes R1 (a prover
check, not only a static budget); gate 8 adds the static "only the blinding
relation uses `BLIND`" check and a test that a produced-but-unconsumed
private boundary entry is refused; gate 10 records both the conjectured
(≥ 96) and the Johnson-provable (≥ 58) bits per shape, so the venue decision
in 5.5 sees both.

### Leakage gates (the note's six, with amendments)

Keep all six. Amend: leakage 1 extends to the FRI mask (R3) and runs on both
channels at every class size; leakage 4 ("hidden states") greps every
carrier, not only `Proof`; leakage 5 ("fresh randomness") also asserts that
two proofs from a *replayed* RNG state and different witnesses differ in
every opening (that is what R4 buys); add leakage 7: the number of segments
and the shape class are documented as public, and a kernel whose run does
not fit its class fails rather than re-shapes.

### What I did not find

No soundness defect in the prototype code. No constraint, field, FRI or
channel file of the fork is touched; the masked verifier is the stock
verifier plus a structure check. The one wrong line in the note is the
`--features prover` test command; the examples crate has no such feature.
