# Review: the slice 5 planning set (proving.md d4, recursion-air.md, slice-5-proving.md d7)

Reviewer: Fable, 2026-10-16. Read-only. Checked against: `spike/s5-recair`
(`count.log`, `model.rs`, `rec.rs`, `main.rs`), the pinned Stwo `e1286720`
(`fri.rs`, `queries.rs`, `vcs_lifted/verifier.rs`, `pcs/quotients.rs`,
`constraint-framework/component.rs`), vos-core `pvm/proof` (`poseidon2/mod.rs`,
`verifier/src/lib.rs`, `proof.rs`, `boundary_binding.rs`, `framework_access.rs`,
`agent/wire/src/result.rs`), StarkWare `916aefb5` (`circuit_multiverifier`,
`stark_verifier/select_queries.rs`, `circuit_verifier/statement.rs`,
`circuits/context.rs`), Plonky3 `mersenne-31/src/poseidon2.rs`, spikes 4a/4b,
the audit and the masking review.

## Verdict: **sound design, one soundness gap in the fold, plan not yet brief-ready. One more revision, no redesign.**

The recursion AIR's design survives contact with the code: every structural
claim I could check against Stwo and vos-core holds (transcript order, the
global DEEP α-order that makes `h8`'s clean blocks exact, the single vanishing
inverse, the lifted leaf and FRI leaf layouts, the PoW and query draw). The
fixed-point claim is correct as a model statement and the fold has real
headroom. The wrap's 85M gas follows from spike 4a's fit within its stated
error. The gap: the fold does not check a fold-child's carried circuit-hash
word, so the wrap's pinned hash binds only the root's children (R1). The plan
is complete in order and gates but leaves out what the owner listed (Attest,
crate homes, fixtures, CI tiers, memory caps), carries stale cross-references,
and sums its M0 estimate wrong.

---

## 1. Soundness of the recursion AIR

- **Gate relation, signed multiplicities: sound.** The address is part of the
  tuple and preprocessed; by the logup lemma the sum vanishes iff each
  distinct tuple's multiplicities cancel (|Σm| < p trivially). One yield of
  −k per address and k uses of +1 force every use-value to equal the yield;
  tuples at different addresses cannot cancel. Yield-twice is static; the
  wiring is trusted through the circuit hash as StarkWare's is. "Equality is
  a use" and the inverse, bit, zero (`x+x=x`) and one (`u·x=u`, `u≠0` from the
  public term) idioms check. §1.1 has no written argument for R12's audit to
  audit: recommended.
- **p2 modes: faithful to the code.** The seven modes reproduce
  `update_leaf`/`finalize`, `hash_children` (state = left‖right), the
  channel's absorb (digest [0,8), chunk into [8,16), carried state on
  continuation chunks), the squeeze and both PoW permutations. Selectors are
  preprocessed; the −1 chain is a trace constraint. Padding rows still
  constrain `permute(0)`: trace generation must fill them (say so in 5.8).
- **qm31: sound**, degree 3. **h8: arithmetic**; its soundness is the
  differential test. The model's α-order (global across trees and columns,
  periodicity sample first) is exactly
  `build_samples_with_randomness_and_periodicity` at the pin, and the
  per-point `c_p` factoring is exact.
- **Degree ≤ 3, masking (c):** what the masking review admits for (c)
  (lines 284, 399–400); no degree pressure at blowup 64. Applies.
- **Circuit hash** binds wiring, padding and tree shape; the parent needs
  only the child's sampled preprocessed values. Fine. **Gate compiler:** the
  four tests are the right set; test 2 closes the recorder-vs-prover gap.
- **Transcript:** `verifier/src/lib.rs:561-615` is domain+config, log sizes,
  preprocessed root, main root, registers in/out, pc/ts in/out, memory roots,
  then `draw_all_lookup_elements` in active `BASE_COMPONENTS` order with
  first-use dedup by `TypeId`. Draft 4's A.1 says this; `recursion-air.md`
  §4.1 still says A.1 is wrong and omits the interaction PoW its own model
  counts (`model.rs` `+ 2 + 1`). R2.
- **Boundary public terms:** four chips' sums recomputed; ~800 rows is
  conservative. But the channel mixes `reduce(lo32), reduce(hi32)` of each
  u64, lossy; the circuit must derive those words from the chips' limb form.
  No encoding is specified anywhere. R3.
- **Lifted Merkle:** full sorted row per leaf, trees lifted to
  `config.lifting_log_size` (`pcs/verifier.rs:55`). Per-query full paths are
  independent of Stwo's deduplicated `hash_witness`, which the witness
  builder must expand (name the helper; recommended). Duplicate raw query
  positions are harmless in-circuit.
- **FRI fold step 3:** `fri.rs:107-200` and the packed 4-QM31 leaves match
  the model exactly. But no inner proof uses fold step 3 and the wrap's is
  verified natively: in-AIR fold step 3 verifies nothing in the design. R10.
- **Leaf flags and digests:** the halt condition is undefined in terms of the
  boundary state; the entry constants are not stated to be leaf constants; the
  leaf's program id must be a witness bound by the fold. R3, R1.
- **The fold's circuit set (the gap).** A fold checks each child's recomputed
  hash against the leaf set or its witness word W and copies W up; the wrap
  checks the root's W. That binds only the root's children: a true fold at
  depth 1 may carry `W₁ = H'`, verify an `H'` child emitting any preimage, and
  pass the root fold whose W is the true hash. The induction needs
  `child.word == W` for every fold child. R1.

## 2. The fixed point and the sizing

- **Row model vs `count.log`:** leaf 55,249/95,524/42,549 + `leaf_extra`
  (58, 800, 0) = 55,307/96,324/42,549 ✓; fold = 2 × 15,291/20,686/1,794 +
  37/108/0 ✓ = 47%/32%/5% ✓; COMPARE ✓. Per-term arithmetic checks: leaf perms
  `Σ⌈(n+1)/8⌉` = 21+638+282+2 = 943; paths 4×21; FRI `Σ(2+h)` over heights
  21..3 = 266; 4,734 channel permutations for 9,467 samples; 20 DEEP points =
  three offsets + 6 + 11 periodicity points (consistent with `mask_points`
  using the max-size step for every component).
- **"Converges at once" is sound** and nearly tautological: a fold's cost
  depends on the child's 458 columns and height, not on the inner width, so
  the leaf sets the shape and the fold fits with 53%/68%/95% headroom. The
  exposure is the leaf, where p2 is at 84% of 2^16; its terms are structural
  (exact given the layouts), so the risk is a layout surprise. R7 gates it
  early and cheaply.
- **56 vs 824 cells per column per query: plausible.** 44 is one eighth of a
  354-column row; 12 is `(1091×55 + 739×41)/7519`. StarkWare's 824 spends ~5
  of 8.46 QM31 rows on the query sort and ~80 Blake rows a compression over
  a 2^20 table. Nothing I looked for is missing: query decomposition, twiddles,
  periodicity, the single vanishing inverse (confirmed at `component.rs:254`),
  the composition split, next-row points. Estimated rather than derived: 4
  rows a bit, 7 a pair, 6 a point, 2d+16 for OODS, all inside the width-free
  5.5M of 33.2M cells. Time and memory are other provers' rates with the SIMD
  hasher assumed; fine as [projected].

## 3. The final wrap

Recomputed from spike 4a's mechanistic fit at C=458, q=18, layers [22,19,16,13]
(the model's `fri_layers` matches `FriVerifier::commit`, partial last fold
included): P ≈ 2,063, F = 576 → 81.7M ≈ the log's 81.1M; ×1.05 Blake2b in
software, ×0.79 through `0x400`. The fit is at ≤ 400 columns on a trivial AIR;
458 columns and 313 degree-3 constraints are a mild extrapolation, well under
the 150M gate. 122 KB, 2.2–4.9 GiB and 134/80 bits follow. "Last layer 1" for
inner proofs means `log_last_layer_degree_bound = 0`; write it that way.

## 4. Poseidon2

- **The reference arrangement with Plonky3's parameters is well-defined:**
  Plonky3 hard-codes `MERSENNE31_POSEIDON2_RC_16_{EXTERNAL_INITIAL,
  EXTERNAL_FINAL,INTERNAL}` (Grain) and `POSEIDON2_INTERNAL_MATRIX_DIAG_16_SHIFTS`;
  older revisions drew M31 constants from an RNG, so pin the revision (R11).
  The p2 component's shape survives: the final `M_E` is linear and the S-box
  count is 142 either way; `p2_check` is re-run.
- **The SIMD gate** (25M permutations in ≤ 0.5 s on 8 threads = 160 ns a
  permutation a thread) is reachable with AVX2 at ~8× over the measured
  scalar, not slack. Measurable and sharp.
- **The fallback** (a Blake2s gate) is named but unsized: a compression is a
  ~1,000-column row or ~80 narrow rows, and leaf hashing grows ~17× (4b
  §2.3), changing the padded shape and step 5's gate. Say so in 5.2 so a
  failed gate re-sizes before 5.8 (recommended).

## 5. The plan as an implementer's document

- **Specs per step:** 5.1–5.4, 5.8–5.11, 5.13 are brief-ready; 5.5 is not
  (R4); 5.12 and 5.14 not until A.3's encodings exist (R3); 5.15 not (R5, R6).
- **Dependencies:** right. Say explicitly that 5.8 needs 5.1's completeness
  fix (the recursion AIR's preprocessed tree at 2^17 sits below its lifting
  height 2^20: the exact bug), and that 5.9 can run beside 5.8.
- **Gates:** sharp except A.7's uniform ≤ 24 GiB (R6) and 5.11's reach (R7).
  **Estimates:** M1's step sum matches; M0's does not (R8). **Missing:** what
  the owner listed (R4–R6), the fork push (R9), stable Rust (R5), Plonky3 (R11).

## 6. Consistency

- Numbers agree across the three documents wherever both state them (458,
  33.2M, 0.16×, 2^16/2^17/2^16, 47/32/5, 85M/64M/117–119M, 122 KB, 134/80,
  17–24 weeks, 56–85 total).
- Stale: `recursion-air.md` §0.8, §1.3 ("§8's 160 columns"), §4.1 ("A.1 lists
  the boundary states before the trace root… A.2 orders by relations.rs") and
  §5 ("§3.3's fallback") describe draft 3; draft 4 took all four.
  `proving.md` §10 still names "a smaller segment class" as the leaf fallback.
- Names: `vos-recair` (5.8, §10) vs `vos-recair-air` (§8). A.5 describes an
  `Attest` that does not exist yet (R4). 5.9 attributes the multiplicity
  static checks to the compiler; they are the `Context`'s (5.8).

## 7. Late surprises not retired by an early gate

1. The fold's carry (R1): would surface only at the external audit.
2. The leaf's p2 rows (84%): retired by R7 weeks earlier than 5.12.
3. The JAM build cannot be "stable Rust" (R5): first brief that tries it.
4. Fork revision not pushed (R9): CI red at 5.1.
5. Register/root encodings (R3): discovered mid-5.12, and they touch the
   format (the state digest), so late discovery costs a format bump.
6. Heavy tests in `just check` (R6): a slow loop for every later step.

---

## Required changes

**R1. Close the fold's circuit-hash carry** (`recursion-air.md` §6;
`proving.md` §3.4, A.3). Every node's preimage carries one word W. A leaf
copies a witness word. A fold requires, per child: recomputed hash ∈ L ∪ {W}
**and** `child.word == W`. The wrap checks `root.word == H_fold`. Also state:
the leaf's program id is a witness; the fold recomputes the id from its
preimage, requires both children's carried id equal it, and a leaf child's
hash ∈ that preimage's leaf-circuit hashes. Add a refusal test to 5.13: a
fold whose child carries a foreign word.

**R2. Retire the stale corrections and add the interaction PoW**
(`recursion-air.md` §0.8, §1.3, §4.1, §5; `proving.md` §10). Replace "the
code does neither" with "A.1 follows the code"; insert the interaction PoW
nonce between the boundary states and the relation challenges in §4.1 (the
model counts it). In `proving.md` §10 replace "otherwise a smaller segment
class" with the real levers: `p2` at 2^17 (+70% cells), narrower chips, or
fold step 3 for inner proofs (p2 55.3k → 49.2k rows).

**R3. Pin the encodings and flag definitions** (`proving.md` A.3, §3.3;
`recursion-air.md` §4.1, §7). Give: the register limb form used by the
boundary chips' tuples and how the leaf derives the channel's
`reduce(lo32), reduce(hi32)` words from it; the memory root's word form in
the digest preimage and the mix (8 reduced 32-bit words today); the state
digest's exact preimage order; the halt flag as `pc_out == halt address`
(a leaf constant, also φ0 of the loader image); the entry pc, loader register
image and image root as leaf-circuit constants; the wrap's 24 public words
and their reserved addresses.

**R4. Specify the witness-input precompile's record** (`slice-5-proving.md`
5.5; `proving.md` A.5). Today `Attest { program, arguments, output }`
(`agent/wire/src/result.rs:351`). State the schema change (`witness_input:
Vec<u8>`, the exact byte stream in call order; `window`; later the proof
hash), the register ABI (destination, capacity, cursor; end of input;
deterministic short reads), the size cap, that `compute_io_hash` gains the
roots, that the `Derivation` gains the image root, and a tracer/agent cursor
parity test.

**R5. Name the crates' homes and fix "stable Rust"** (`slice-5-proving.md`
5.8, 5.14, 5.15; `proving.md` §3.6; `recursion-air.md` §8, R11). Proposed:
`pvm/proof/recair` (prover), `pvm/proof/recair-air` (bodies, no_std, no
prover dependency), `pvm/proof/final-verifier`, `pvm/proof/statement` (no vos
dependencies, so Kreivo can depend on it). Reconcile `vos-recair` /
`vos-recair-air`. `riscv64em-javm` needs build-std on the pinned nightly
(`rust-toolchain.toml`), so write "no nightly features in the source; stable
for x86 and wasm32; the JAM build on the pinned nightly with build-std".

**R6. Fixtures, CI tiers, memory caps** (`slice-5-proving.md` "How every
step runs", 5.11–5.16; `proving.md` A.6, A.7). State how fixtures are made
(a generator from the M0 pipeline, regenerated at each format bump, stored
under `pvm/proof/fixtures`, ~1.2 MB for A.6); a small test kernel (log ≤ 12)
for every structural recursion test in `just check`; the window kernel only
in `test-proof` under `systemd-run MemoryMax`; expected wall time per heavy
test (segment ≤ 8 s after 5.2, leaf/fold 1.2–2.6 s, wrap 4.4–9.5 s, the
16-segment window about 3–5 min); sharp caps: leaf/fold ≤ 4 GiB, wrap ≤ 8 GiB
unmasked, segment ≤ 24 GiB.

**R7. An early row-count gate** (`slice-5-proving.md` 5.11;
`recursion-air.md` §10 step 4). Add: "the window kernel's leaf topology
(`Context<NoValue>`, no proof) is built and counted: ≤ 2^16 / 2^17 / 2^16",
and pin `count.log`'s per-term counts, not only totals. COMPARE's leaf is 85%
width-free per-query work and does not exercise the kernel leaf's dominant
terms.

**R8. Fix the estimates** (`slice-5-proving.md` Estimates; `proving.md` §11).
5.1–5.6 sum to 5.8–9.2 weeks plus 5.7's 2–3 beside; state the two-track
assumption and the critical path (5.1 → 5.2 → 5.4/5.5 → 5.12) or widen M0 to
6–9. Reconcile M1's 17–24 with spike 4b §8's 20–28 (working tree) / 27–37
(production) in one sentence, or widen.

**R9. The fork push is a gate** (`slice-5-proving.md` Rules, 5.1, 5.14).
vos-core pinned to `olanod/stwo` at an unpushed revision cannot build in CI;
name the owner's push or approval as the closing gate of 5.1 and 5.14.

**R10. Drop in-AIR FRI fold step 3 from 5.10 and §10 step 3**, or mark it
optional. No inner proof uses it; keep it as the named p2 lever.

**R11. Pin Plonky3** (`slice-5-proving.md` 5.2). Name the constants
(`MERSENNE31_POSEIDON2_RC_16_*`, `POSEIDON2_INTERNAL_MATRIX_DIAG_16_SHIFTS`)
and the revision, and state the test vectors used.

## Recommended changes

- `recursion-air.md` §1.1: write the signed-multiplicity soundness argument
  (per-tuple cancellation, |Σm| < p, one yield per address, trusted wiring via
  the circuit hash) so R12's audit has a text to audit.
- §4.3: name the witness builder that expands Stwo's deduplicated
  `hash_witness` into full per-query paths and FRI siblings.
- §5 / `proving.md` §4: write "log last-layer degree bound 0" instead of
  "last layer 1".
- 5.2: size the Blake2s fallback's effect on the padded shape and on step 5's
  gate, so a failed gate re-plans before 5.8.
- 5.9 beside 5.8; move the multiplicity static checks to 5.8's text.
- 5.14's fork review: `MerkleVerifierLifted::verify` panics (`assert_eq!`) on
  prover-supplied values at duplicate positions; convert to an error while
  the Blake2b channel is reviewed.
- 5.13: add "a fold whose child carries a foreign word" and "a leaf carrying
  a wrong program id" to the refusals.
- A.3: note that a leaf's `(p, p)` is a free witness; continuity through the
  ts-bearing digest is what orders segments, and `first = 0` is checked only
  for the wrap's refusal.

---

## Draft 8 check (2026-10-16)

proving.md d5, recursion-air.md d2, slice-5-proving.md d8, re-read against
the code. **R1–R11 are addressed; one required addition (D1), two
recommended.** Nothing newly introduced is wrong.

| R | status | note |
|---|---|---|
| R1 fold carry | addressed | §3.4 / §6 / 5.13: `child.W == W` for every child, leaves copy a witness W, the wrap pins `root.W`; the leaf's program id is a witness, bound by the fold (recomputed id, both children carry it, leaf child's hash ∈ that preimage's L). Refusal tests added. The induction closes. |
| R2 stale text, interaction PoW | addressed | §4.1 lists the nonce as item 4 ("the model counts it"); §0.8 rewritten; §10's fallback row names p2 2^17 / narrower chips / inner fold step 3. |
| R3 encodings and flags | addressed, see D1 | A.3: boundary states as the chips' bytes (296, one run, 37 permutations), everything else 16-bit limbs, digest of 148 bytes, halt as `pc_out == PVM_HALT_ADDR`, entry constants, wrap words at 0–23. |
| R4 precompile record | addressed | `0x401` is free (`surface.rs:6`, `0x400..=0x47f`); 4 MiB is `cap::WORK_RESULT`; φ7/φ8 ABI, count in φ7, cursor parity, `Attest.witness_input`, Derivation gains the image root. |
| R5 crates, stable | addressed | homes under `pvm/proof/`, names reconciled, "no nightly feature in the source; JAM on the pinned nightly with build-std". |
| R6 fixtures, tiers, caps | addressed | A.6 generator and `pvm/proof/fixtures`; test tiers in the rules; A.7 caps 24/4/4/8 GiB with wall times. |
| R7 early row gate | addressed | 5.11 counts the kernel leaf's topology per term; §10 step 4 likewise. |
| R8 estimates | addressed | M0 6–9 on two tracks with the critical path; M1 reconciled with 4b §8; totals 25–36 and 57–87 add up. |
| R9 fork push | addressed | the owner's word recorded; closing gates in 5.1, 5.2, 5.14. |
| R10 in-AIR fold step 3 | addressed | dropped from 5.10 and step 3, kept as the named lever. |
| R11 Plonky3 pin | addressed | `f983316` exists in the clone; both named tests exist in `mersenne-31/src/poseidon2.rs` (lines 540, 588). |

**The four lead decisions, checked:**
- **Halt pc.** `PVM_HALT_ADDR = 2^32 − 2^16` (`pvm/runtime/src/lib.rs:88`);
  CpuChip today constrains `is_halt_* · (next_pc − pc) = 0`
  (`chips/cpu/mod.rs:2755, 2828`) and recognises halts as jumps to that
  address, so `next_pc = PVM_HALT_ADDR` at the halting step is a one-line
  constraint change plus `cpu_halt_gate.rs`; PROGRAM_BOUNDARY's
  `FinalNextPc` then carries it. No code offset reaches it. Sound; 5.5's
  tests cover both edges. Entry ts = 1 is right (`core/tracing.rs:240`,
  "0 is reserved for initial memory entries"); the initial register seeds
  sit at ts 0 (`expected_register_file_sum(.., 0, 1, ..)`), consistent.
- **Byte transcript.** The tuples are bytes throughout:
  `le_byte_limbs_u64/u32` for registers, ts and pc, and the memory-root
  tuple `(0, 0, root_in[32], root_out[32])` (`boundary_binding.rs:170-191`).
  296 bytes, 37 permutations, 148-byte digests at 19 permutations and a
  52-word preimage at 7: the arithmetic holds and §4.1/5.11 carry the +25
  p2 rows. Mixing bytes before the challenges is strictly better than
  today's lossy `reduce` words. **But "no byte needs a range check in the
  leaf" is argued nowhere, and it is not local:** the four boundary chips
  have no range checks of their own (they only emit and consume tuples).
  A touched register's limbs are bytes because the CPU/register-memory
  chips range-check them; an *untouched* register's seed is consumed by
  the closing read with the same limbs, so its bytes are whatever the
  entry carried, which continuity traces back to the first segment, where
  the entry flag compares against constant bytes. pc, the roots and
  φ9..12 at halt are range-checked by the chips that write them. So the
  claim holds through the chain, not per leaf. See D1.
- **Fold carry.** Correct as written (R1 above).
- **Leaf program-id binding.** Correct: a witness in the leaf, bound by
  the fold's recomputation and the `hash ∈ L` check, and L comes from the
  same preimage, so a leaf cannot carry an id whose preimage omits it.

**D1 (required, small).** `proving.md` A.3 (and `recursion-air.md` §4.1):
write the range-check argument above in one paragraph, naming the chips
that range-check touched values and the entry-flag-plus-continuity step
for untouched registers, so the audit has text; or, if the authors prefer
a local argument, decompose the 296 witness words to bytes in the leaf
(16 QM31 rows each, about 4.7k rows, 3.6% of `qm31`) and drop the claim.
Either is fine; the silent version is not.

**Recommended:**
- `proving.md` §3.3's parenthetical register image ("φ0 the halt address,
  φ1 the stack top, φ7 the argument base") could not be confirmed from
  the kernel loader here (`agent/default/src/machines.rs:156` puts
  `HALT_ADDRESS` in `frame[1]`); the brief for 5.12 should take the image
  from the loader, not from the sentence.
- PoW and interaction-PoW nonce limbs need no 16-bit range check (any M31
  4-tuple is a harder grind than a u64); say so in §4.2 so no one adds 256
  rows for it.

**Verdict: ready to implement once D1's paragraph is in.**
