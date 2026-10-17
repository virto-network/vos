# Slice 5: progress

The log of build step 5, against `slice-5-proving.md`. Every number is
tagged measured, model or projected.

## Step 5.2: the reference Poseidon2 and a SIMD hasher

**Gate: failed as first written** (`proving.md` §3.2), on the 8 threads
of an Intel Core Ultra 7 155H (AVX2, no AVX-512):
- a window-kernel segment proves on Poseidon2 in **1.75–1.85×** Blake2s's
  time, against 1.5× [measured];
- a leaf's commitment of 25M permutations takes **0.63 s**, against 0.5 s
  [measured, and projected from the permutation rate].

What dominates is the permutation itself: about 112M a segment, 95% in
leaves, take 58% of the Poseidon2 prove's cycles, and the packed
permutation runs at Plonky3's own speed on this machine.

### The decision: Poseidon2-M31 stays the segment channel

**The owner's, on 2026-10-16.** The gate becomes a segment's total cost,
its proving plus its leaf, against the Blake2s route's projection. Per
segment at the 32k cut:
- **Poseidon2:** about 5.6 s to prove [measured] plus a leaf of about
  1.5–3 s [projected]: about 7.1–8.6 s.
- **Blake2s:** about 3.1 s to prove [measured] plus a leaf with
  in-circuit Blake2s of about 4.5–6 s [projected]: about 7.6–9.1 s.
- **The Blake2s route would also** add a Blake2s gate to the recursion
  AIR and re-derive its padded shape and fixed point.
- **The fallback is dropped:** no Blake2s gate in the recursion AIR, and
  segments prove on Poseidon2-M31.

### The permutation

- **The reference arrangement** (`pvm/proof/src/poseidon2/mod.rs:318-355`,
  `permute_with` and `full_round`): the external matrix once, 4 full
  rounds, 14 partial rounds, 4 full rounds. A full round adds its
  constants, applies `x^5` to every word, then the external matrix; a
  partial round adds its constant to word 0, applies `x^5` to it, then
  the internal matrix. Before, each linear layer preceded its S-box layer
  and there was no first external matrix (Stwo's example order).
- **Plonky3's parameters at `f983316`:**
  - the external matrix `circ(2·M4, M4, M4, M4)` with Plonky3's
    `M4 = [[2,3,1,1],[1,2,3,1],[1,1,2,3],[3,1,1,2]]` (`apply_m4` and
    `apply_external_round_matrix`, `:250-296`); vos had HorizenLabs'
    `[[5,7,1,3],…]`;
  - the internal matrix `1 + diag(-2, 2^0, 2^1, …, 2^8, 2^10, 2^12, 2^13,
    2^14, 2^15, 2^16)` (`INTERNAL_DIAG_SHIFTS`, `INTERNAL_DIAGONAL`,
    `apply_internal_round_matrix`, `:229-310`); vos had
    `diag(2^1, …, 2^16)`;
  - the Grain round constants: unchanged, they were already Plonky3's
    `MERSENNE31_POSEIDON2_RC_16_EXTERNAL_INITIAL`, `_EXTERNAL_FINAL` and
    `_INTERNAL`, and `poseidon2_round_constants` still re-derives them.
- **The vectors, bit for bit** (`poseidon2::tests`):
  - `test_default_mersenne31_poseidon2_width_16`: input 0..15 under the
    reference constants;
  - `test_poseidon2_width_16_random`: Sage's vector under the constants
    `Xoroshiro128Plus` seed 1 draws (the generator and Plonky3's rejection
    sampling written out in the test), through `permute_with`;
  - the two matrices checked on unit vectors.
- **Modes unchanged:** the sponge (rate 8, capacity 8), the leaf and node
  layouts and the channel.
- **The settlement verifier** carries the same permutation. Its unused
  degree-2 permutation AIR fragment (`eval_permutation`) is deleted
  rather than rewritten untested; the recursion AIR's `p2` replaces it.
  On the PVM it accepts the regenerated fixture in **11,427,015
  instructions** [measured].

### The SIMD hasher

**Adapted, not depended on.** Plonky3 at `f983316` does not build on the
workspace's pinned nightly-2025-07-14 (`p3-util` uses `maybe_uninit_slice`,
stabilized later), and the pinned Stwo does not build on the nightlies
Plonky3 needs (`array_chunks` was removed), so the two cannot share a
toolchain. A dependency would also bring about fifteen crates into the
prover (`p3-field`, `-dft`, `-matrix`, `-mds`, `-poseidon1`, `-poseidon2`,
`-symmetric`, `-util`, `-maybe-rayon`, `rand` 0.10, `num-bigint` 0.5,
`itertools` 0.15, `paste`, `spin`, `tracing`) for the few functions used.

- **What was adapted** (`pvm/proof/src/poseidon2/packed/`, prover only):
  per instruction set, modular add and subtract, the fused round
  constant and `x^5` (`exp5`), and the rotations that multiply by the
  internal diagonal; the arrangement is written once over them. Headers
  name each source file at `f983316` and the change made;
  `LICENSE-PLONKY3-MIT` keeps the notice. The verifier stays on the
  scalar code, with no new dependency.
- **Sixteen lanes a call**, as one 512-bit, two 256-bit or four 128-bit
  registers a word, so independent lanes interleave. The instruction set
  is chosen at compile time by `target_feature`, as Stwo's `SimdBackend`
  chooses its own: AVX-512F, else AVX2, else NEON, else the scalar
  permutation lane by lane.
- **On `SimdBackend`** (`poseidon2/simd_backend.rs`): leaves (the lifted
  algorithm, sixteen sponges a block, finalized before the last lift),
  nodes and the grind. Roots and nonces equal `CpuBackend`'s; the grind
  returns the smallest nonce, as `CpuBackend`'s does.
- **A generic permutation over Stwo's `PackedM31`** was tried first:
  440 ns a permutation against Plonky3's 200 ns, both under a load
  average of about 24 [measured], so it was dropped.
- **Tests:** sixteen lanes equal the scalar permutation on 1,024 random
  states with `0`, `P` and `P - 1` among the words; leaves equal
  `CpuBackend`'s over lifted groups straddling a block and the sixteen-leaf
  boundary; nodes; the grind's nonce; a committed tree decommits,
  verifies, and refuses a changed value.
- **Where they ran:** AVX2 on this machine; the scalar fallback in a
  build without `target-cpu=native`; NEON under `qemu-aarch64`
  (`cargo test --target aarch64-unknown-linux-gnu`). The 11 Poseidon2
  tests pass on each. AVX-512F is compiled and linted
  (`-C target-feature=+avx512f`) but **not run**: this machine has no
  AVX-512. Its `exp5` reads sign bits with `vpcmpd` (F) where Plonky3 uses
  `vpmovd2m` (DQ).

### The gate's numbers

**Permutations** (`cargo bench --bench poseidon2`, load average 0.25)
[measured]:

| | 1 thread | 8 threads |
|---|---|---|
| scalar | 1.47 M/s | 7.05 M/s |
| packed (AVX2) | 10.78 M/s | 39.45 M/s |
| Plonky3's own packed, same machine (its own toolchain) | 11.7 M/s | 40.5 M/s |

- The 8 threads span the 155H's 6 P-cores (hyper-threaded) and its
  E-cores; 6, 12 and 16 threads reach 49, 44 and 51 M/s.
- **A leaf's commitment, 25M permutations:** 0.634 s projected from the
  rate, and **0.629 s** measured committing 176 columns of 2^20 rows
  (25.2M permutations) on `SimdBackend`. The same columns under Blake2s:
  0.118 s.

**A window-kernel segment** (spike 3's kernel, `n1000000-j2`, 32,768
steps and 8 pages, MOBILE, the full shape, since the `d165a7b6` seam is
not on `vos-core`), 5 segments, `RAYON_NUM_THREADS=8`, under
`systemd-run` at 16 GiB, load average 4.4–7.7 before the runs
[measured]:

| Channel | Prove, 5 segments | Per segment | Against Blake2s |
|---|---|---|---|
| Blake2s (format 24) | 14.94, 16.03, 16.19 s | 2.1–3.8 s | 1 |
| Poseidon2, this step | 27.01, 28.03, 29.91 s | 4.4–7.4 s | 1.75–1.85× |
| Poseidon2, before (spike 3's binary) | 102.98 s | 15.9–24.0 s | 6.4–6.9× |

- **What dominates** [measured]: per segment about 107M leaf
  permutations and 5.5M node permutations (77M and 1.6M for the
  868-step tail); the grind takes 16–36 ms. Under `perf`,
  `permute_x16` is 57.6% of the Poseidon2 prove's user cycles; Blake2s's
  compression is 20.0% of its prove's.
- The proofs verify standalone, 0.08 s a segment on Poseidon2 against
  0.026 s on Blake2s; proof sizes are unchanged (2.56–2.61 MB in
  bincode).

### Regenerated fixtures

- `pvm/proof/settlement-verifier/fixtures/bool_proof.postcard`, by
  `settle_fixture`.
- No other fixture or pinned constant depends on the permutation: the
  format 25 tests compute their commitments at run time, and the round
  constants did not change.

### Gates

- `just check`: green.
- `just test-proof`'s suites, under `systemd-run` at 16 GiB with
  `nice -n 10` and one test thread: green, the settlement verifier's PVM
  run included.
- Clippy with `-D warnings` for AVX-512F, the scalar fallback and
  aarch64 as well as the host.

## Step 5.3: the format registry, run-time selection and the security accounting

### The registry (`pvm/proof/src/format.rs`)

A proof's `format_version` names an entry; the entry fixes, at run time,
its channel, its parameters, its encodings and its floors.

| number | proofs | channel | log blowup, queries, PoW, fold step, last layer, interaction PoW | status | floors (conj. / proven) | counts at its reference shape [model] |
|---|---|---|---|---|---|---|
| 24 | segments, legacy | Blake2s | the proof's own (96 conjectured or more); MOBILE recorded | admitted | 96 / — | 96 / 57 |
| 26 | segments | Poseidon2-M31 | 2, 44, 20, 1, 0, 8 | admitted | 100 / 60 | 108 / 62 (62.69) |
| 27 | leaves and folds | Poseidon2-M31 | 2, 44, 20, 1, 0, 8 | reserved | 100 / 60 | 108 / 63 (63.37) |
| 28 | the final wrap, masked | Blake2b-256 | 6, 20, 26, 3, 6, 8; affine DEEP batching | reserved | 100 / 80 | 146 / **74** (74.71) as built |
| 29 | device proofs, masked | Blake2s-M31 | 1, 86, 20, 1, 0, 8 | reserved | 100 / 60 | 106 / 62 (62.05) |
| 30 | credential proofs, masked | Blake2s-M31 | 1, 86, 20, 1, 0, 8 | reserved | 100 / 60 | 106 / 62 (62.52) |

- **24 stays** while the refine bundles, the chain proofs, the canonical
  allowlists and their tests use it: the existing entry points (`prove`,
  `prove_mobile`, `prove_canonical`, `prove_chain`, …) still produce it, with
  its old transcript and its parameters under the 96-bit conjectured floor.
  **25 is not registered** (refused): 26 replaces it, and its tests
  (the canonical segment, the query replay, the codec) run on 26 or on both
  channels.
- **27 to 30 are entries only**, refused as "registered but not admitted":
  their AIRs come in M1 (27, 28) and with the phone work (29, 30), and no
  Blake2b-256 or Blake2s-M31 stack is built. Fold step 3 stays refused by the
  preflight, and 28 needs affine DEEP batching, which is not built.
- **Reference shapes:** 24 and 26, every chip of the segment AIR at 2^20 rows
  (14,102 sampled values, 6,650 constraints, at most 2.4·10^9 logup
  fractions, relations up to 265 limbs); 29, the same at 2^16; 27, the
  recursion AIR's padded shape (2^16 / 2^17 / 2^16, 458 columns counted at
  two samples, 313 constraints of degree 3); 28, the wrap's 2^14 / 2^15 /
  2^11; 30, `p2` alone at 2^14. A test recomputes 24's, 26's and 29's from
  the AIR.

### Run-time selection (`pvm/proof/src/pcs.rs`)

- The `poseidon2-channel` cargo feature and `recursion_pcs.rs` are gone.
  Prover, verifier, preflight replay, refine replay and codec are generic over
  `PcsStack` (implemented for `Blake2sMerkleChannel` and `P2MerkleChannel`);
  `with_stack!` picks the stack from the format's channel.
- `Proof.stark_proof` is a `StarkProofAny` (one variant a channel) and a
  commitment a `Commitment`; the verifier refuses a Stark proof on another
  channel than its format's before any other work.
- The lookup draws go through object-safe component methods, so they take a
  `ChannelRef` naming the concrete channel.
- **The prover is told the format:** `prove_format`,
  `prove_canonical_format`, `prove_chain_format`,
  `program_commitment_for_profile_format`. On a format the registry does not
  admit, or whose channel no stack implements, it returns
  `ProvingError::FormatNotAdmitted` (the crate's own `ProvingError`, which
  wraps Stwo's), or `None` from the two `Option` entry points.
- **One no_std verifier build reads both admitted formats**
  (`thumbv7em-none-eabihf`, wasm32); the packed Poseidon2 stays prover-only.
- The refine codec is version 2: it carries each child's interaction PoW
  nonce and decodes a child's hashes by its format's channel.

### The lossless encodings and the interaction PoW (formats 26–30)

- **The boundary states** enter the transcript as the boundary chips' bytes
  (`boundary_binding::boundary_state_bytes`), one M31 a byte, 296 in one
  absorb, in A.1's order (registers in, out, pc and ts in, out, roots in,
  out).
- **The Poseidon2-M31 channel is lossless for every format:** `mix_u64` and
  the PoW nonces take four 16-bit limbs, `mix_u32s` two a word; the
  `reduce(lo32), reduce(hi32)` encoding is gone, from the settlement
  verifier's copy of the channel too. Stwo's Blake2s channel hashes bytes and
  needed no change.
- **The interaction PoW** (A.1 item 4), 8 bits, is ground on `SimdBackend` after the
  boundary states and mixed before any relation challenge; the verifier, the
  prover-side verifier and the recursion seams check it
  (`proof::check_interaction_pow`), and the preflight replay starts from the
  channel after it. Format 24 has none and takes only the nonce 0.

### The bit counts (`pvm/proof/src/security.rs`)

- **Conjectured** = PoW + queries · log blowup.
- **Proven** = soundcalc's Johnson-bound count (`ethereum/soundcalc`
  `2af5e7df`): the least of the query phase (PoW + q · −log2(√ρ + η)), the
  DEEP batching ((B − 1) · ε_lin), each FRI fold ((f − 1) · ε_lin), ALI
  (L·C/|F|), DEEP (L·(d(k + c − 1) + k − 1)/(|F| − k − D)) and logup
  (N·S/|F| · 2^−interaction PoW), with ε_lin BCHKS25's Theorem 4.2 (eprint
  2025/2055) over QM31, maximized over the multiplicity m ≥ 3. Basic f64
  operations only, so every verifier counts alike.
- **The DEEP term's d** is the constraint degree, taken as
  2^(log composition bound − log k) + 1: Stwo's composition bound is
  2^l · 2^⌈log2(dᵢ − 1)⌉ for a component of 2^l rows, so every component's
  dᵢ · 2^l ≤ d · k. Exact for degree 2 and 3, larger otherwise, which only
  lowers the count. (The step's first cut took Stwo's d − 1.)
- **soundcalc's multi-point precondition,** k + c < (1 − θ)·n, is checked at
  θ's limit (1 − θ > √ρ for every m); a shape outside it is outside the
  analysis, and its proof is refused.
- **The verifier counts at each proof's own parameters and shape** and
  refuses one below either floor, then one whose parameters are not its
  format's. A 7-step program under 26 counts **108 / 63** [model], under 24
  **96 / 57**.
- **The inner count is set by the query term:** with PoW 20 its limit is
  20 + 44 = 64, and the count, 62.69, is where it meets the least other term
  at the best m. Less PoW moves that m, so it costs less than a bit a bit:
  at PoW 17 a segment still counts at least 60, at PoW 15 it does not.
- **The wrap:** blowup 64 with 18 queries or 20 counts 74.71 proven bits,
  however many queries: the batching term of powers-of-one DEEP batching,
  the batched values' count times ε_lin, grows with the blowup and binds.
  The entry carries the affine-batching plan's parameters (blowup 64, 20
  queries, PoW 26, fold step 3, last layer 6, interaction PoW 8) and is
  marked `DeepBatching::Affine`; the tool counts what is built, 74, and
  `check_format_security` reports it below its floor of 80. The ways to 80,
  for 5.14 [model, Fable's]: affine batching at blowup 64 and 19–20 queries
  (about 1.06× verify, a fork change for format 28 only, recommended); a
  6-bit batching-phase PoW at blowup 64 and 20 queries (1.11×); blowup 8
  with 41 queries (1.97×; the tool agrees on 41).

### Tests

- `format::tests`: the bit counts pinned per format, every format but the
  wrap clearing its floors; the unrounded counts the parameters were chosen
  by (62.69 for segments; 86 the least device query count clearing 62); the
  reference shapes recomputed from the AIR; the wrap's 74.71 at 18, 20 and
  256 queries, 41 at blowup 8, and the verifier's check saying it falls
  short; every number round-trips, only 24 and 26 admitted; a proof below
  either floor is refused.
- `security::tests`: the logarithm; the query term's limit; the multi-point
  precondition refuses a column sampled past it.
- `proof::transcript_tests` (`src/proof/transcript_tests.rs`): two boundary
  states apart by p in a 32-bit word, low or high, initial or final, draw
  different relation challenges (they collide under the retired encoding);
  the boundary run is the chips' bytes; the interaction PoW is checked.
- `verifier/tests/formats.rs` (on proofs): every admitted format proves,
  round-trips through bincode and postcard and verifies with and without the
  side note; a proof is refused under every other registered number and two
  unregistered ones; a wrong interaction nonce is refused, as a nonce on a
  format-24 proof; a format-26 proof below its conjectured floor (PoW 11),
  below its proven floor (PoW 15), or with other parameters, is refused; a
  `PcsPolicy` pins a format-26 proof (STANDARD refuses its blowup 4, MOBILE
  admits it), with and without the side note; the counts of a real proof; a
  canonical segment under 26 verifies and refuses a changed or
  non-canonical root.
- `refine_codec::tests` (`src/refine_codec/tests.rs`): a format-26 child
  round-trips with its nonce; the encoder refuses a child under a reserved
  number or on another channel; the decoder, on patched bytes, refuses a
  reserved or unregistered number, a 26 relabelled 24 (the transcript
  commitment binds the number), and a 24 relabelled 26 whose hashes are no
  M31 digests.
- `tests/recursion_seams.rs`: on a format-26 proof, the recorded transcript,
  the step-by-step extraction and the OODS reconstruction replay one
  transcript.
- The settlement verifier's `the_channel_copy_draws_as_the_provers`: its
  channel copy and `poseidon2::Poseidon2M31Channel` draw alike after the
  same u64s (values p apart included), u32s, felts, a root and PoW nonces,
  and accept the same nonces; `just test-proof` now runs its tests.
- `query_replay_tests` run on both channels.

### Folded from the reviews (code)

- **A policy pins every format:** `proof::check_shape_policy` runs on both
  verifiers' `*_with_pcs_policy` paths for every format; without a policy,
  format 24 keeps its 96-bit conjectured floor and the others their own
  floors. Before, a format-26 proof skipped a caller's policy.
- **The recursion seams are kept,** in `verify/recursion.rs`: 5.10's
  transcript-equality test and the leaf's per-piece tests ("on recorded
  data") are their M1 use. A smoke test on a format-26 proof covers them.
- **Module splits:** `proof/transcript.rs` (the FS domain, the statement
  header, the boundary mix, the interaction-PoW check, the format's security
  check) and `proof/transcript_tests.rs`; `refine_codec/tests.rs`;
  `prove.rs` 1,548 → 945 lines, with `prove/canonical.rs` (canonical shapes,
  profiles, program commitments, chain proving), `prove/debug.rs` (the
  `debug-internals` diagnostics) and `prove/profile.rs`.
- **`PcsStack`:** `stark_mut` replaces the tests' hand-rolled matches;
  `ProofHash::from_commitment` had no use and is gone;
  `StarkProofAny::proof_of_work` and `commitment_count` (no allocation).
- **`ProvingError::FormatNotAdmitted`** replaces `Target::of`'s assert, the
  prover's panic on an unbuilt channel and the replay binding's
  `ConstraintsNotSatisfied`.
- **One check each:** the preflight returns the format, so `proof_format`
  runs once a verify; the standalone verifier takes the Stark proof out once
  (`from_any`); `proof_security_bits` shares the standalone preflight and
  `proof::format_security_bits` with the verify path; the verifiers' second
  log-size cap, the preflight's own, is gone.
- **Stale comments** fixed in `format.rs`, `proof.rs`, the verifier's
  re-exports and `poseidon2/mod.rs`.

### Measured

- **A 7-step program, natural shape (16 chips, tallest 2^16), 8 threads**,
  three runs each [measured, load average 2–5]:

  | format | prove | proof (bincode) | verify | peak RSS | PoW nonce, interaction PoW nonce |
  |---|---|---|---|---|---|
  | 24 | 0.33–0.34 s | 882,506 B | 11.2–11.4 ms | 431–433 MiB | — |
  | 26 | 0.53–0.57 s | 994,850 B | 38.3–41.0 ms | 457–458 MiB | 776,923; 194 |

  At the first cut's parameters (39 queries, PoW 26, interaction PoW 24)
  format 26 proved in 3.5–11.5 s into 900,990 B and verified in 27–74 ms
  [measured, load average 5–17]. **Expected grind per proof** [model]:
  2^20 + 2^8 permutations, about 27 ms on 8 threads at 5.2's 39.45M/s,
  against 2^26 + 2^24 (84M, about 2.1 s) before; the five more queries add
  about 12% to the proof's bytes.
- **The settlement verifier on the PVM** accepts the regenerated fixture in
  **10,951,979 instructions** (27,306,959 gas) [measured], against
  11,427,015 before.

### Regenerated fixtures

- `pvm/proof/settlement-verifier/fixtures/bool_proof.postcard`, by
  `settle_fixture`: the PoW nonce now enters the channel as four limbs.
- No other fixture or pinned constant changed: the format-24 transcript is
  unchanged, and no format-26 commitment is pinned yet. **The wire layout of
  every `Proof` changed**, format 24's included: serde writes the
  `StarkProofAny` variant tag before the Stark proof and the
  `interaction_pow` field after it, so a bincode or postcard proof written
  before this step does not decode (the refine codec, version 2, likewise).
- The review fold changed no fixture: the settlement fixture's AIR and
  channel are untouched, and the new parameters reach only format 26, whose
  proofs the tests make fresh.

### Gates

- `just check`: green, 1,003 tests.
- `just test-proof`'s suites, under `systemd-run` at 16 GiB with
  `nice -n 10` and two test threads: green, 37 test binaries, the
  settlement verifier's PVM run and its own tests included (the verifier's
  suite, formats included, runs in `just check`).
- Clippy with `-D warnings` on the workspace and on the proof crates with
  `debug-internals`.

## Step 5.4: a shape per kernel

### The shape

- **Its chips come from the kernel's code** (`pvm/compiler/src/shape.rs`,
  computed by derive): each instruction's opcode selects the chips it uses,
  as the AIR's CPU classifies it (MUL for multiplies, left shifts and
  rotates; DIVREM for divisions, remainders and right shifts; BITWISE;
  COMPARE for set-less-than, cmov, min, max and branches; POPCOUNT;
  BITCOUNT; JUMP_TABLE for indirect jumps), and an `ecalli` those of the
  precompile it names (BLAKE2B for `0x400`, WITNESS_INPUT and COMPARE for
  `0x401`). The other 16 chips are in every shape (`chip_idx::ALWAYS`): the
  CPU, the ledgers and their boundaries, the program's memory and boundary,
  the page Merkle chips and the fixed tables. The seam `d165a7b6` counted
  every `ecalli` as BLAKE2b; derive now decodes the id. The prover's tests
  hold derive to the AIR opcode by opcode (`chip_idx::OPTIONAL` names the
  nine chips a trace may leave out).
- **Every derived kernel holds BLAKE2B, WITNESS_INPUT and COMPARE:** its
  prologue reads its arguments through `0x401`, and it hashes its io-hash
  through `0x400`. Its SDK code (decoding, the allocator) reaches MUL,
  DIVREM, BITWISE and JUMP_TABLE too. So the window kernel, the `kernels`
  actor's three kernels and any kernel the SDK derives have the same
  shape, **23 of 25 chips: every chip but POPCOUNT and BITCOUNT**. The
  audit's solvency predicate without BLAKE2B (4,538 columns) no longer
  exists.
- **Every log size is pinned per class.** A class is a cut, at most
  2^`log_steps` steps and `pages` touched pages a segment, and gives each
  chip of the shape a log size: the fixed tables' and boundaries' sizes,
  the program memory's and jump table's from the code, and for the chips a
  run fills a size the cut bounds or provisions (`capacity`). A segment
  lists the pages it touches and page 0, so the page chips are sized for
  `pages + 1`. Derive's classes, cheapest first:

  | class | steps | pages | CPU | BLAKE2B | BLAKE2B_BOUNDARY | MEMORY | MEMORY_PAGE | MEMORY_MERKLE | REGISTER_MEMORY | WITNESS_INPUT | ALU (4) | cells, window kernel [measured from its shape] |
  |---|---|---|---|---|---|---|---|---|---|---|---|---|
  | 0 | 2^12 | 8 | 12 | 11 | 16 | 17 | 9 | 8 | 14 | 16 | 12 | 122.0M |
  | 1 | 2^15 | 8 | 15 | 14 | 16 | 18 | 9 | 8 | 17 | 16 | 15 | 228.8M |
  | 2 | 2^12 | 24 | 12 | 11 | 18 | 18 | 10 | 9 | 14 | 16 | 12 | 411.4M |

  Class 2 holds a whole argument written in one step, a request's 64 KiB
  being 17 pages: the budgeted cut makes that step a segment of its own.
- **Every chip now pads.** CPU, MEMORY, MEMORY_MERKLE, REGISTER_MEMORY,
  WITNESS_INPUT, MUL, BITWISE, COMPARE and DIVREM took their natural size
  whatever the floor; each pads its main trace to a floor now, as the three
  canonical forcing chips did. Canonical proving passes its floors to the
  forcing set alone (`chip_idx::FORCING`), so its proofs are unchanged.
- **The prover** (`pvm/proof/src/prove/shaped.rs`): `prove_shaped` proves a
  segment over exactly a segment shape, and refuses (`ProvingError::Shape`)
  when a chip's rows need more than its size or a fixed chip's size is not
  the shape's. `prove_kernel` cuts a run by a class's budgets
  (`segment_bounds_budgeted`) and proves each window at the first class
  whose sizes hold its rows, halving a window none holds. A class is tried
  by proving at it: its traces are generated once, at the class's sizes,
  and an overflowing chip refuses the class before any commitment; a class
  of fewer steps than the window is skipped.
  `program_commitment_for_shape` computes a class's preprocessed root from
  the code alone (`kernel::kernel_side_note`): it is the root every segment
  of the class commits.
- **The verifier** (`vos-pvm-proof-verifier`): `verify_kernel_segment`
  checks a proof against its kernel's program (below): the format, the
  chips exactly the shape's (more or fewer refused, by name), the sizes
  exactly one class's, then `verify_standalone` against that class's root.
  The shape check is structural and comes before any cryptographic work.
  `verify_kernel_chain` verifies a whole run against the program and its
  entry (`KernelEntry::of` the kernel's blob, refused unless its hash and
  image root are the program's): the first segment at timestamp 1, at the
  entry pc, with the loader's registers and from the image root; each
  continuing the one before; the last ending at the halt pc; every
  structural check before any proof is verified. It takes the proofs by
  value, as verifying consumes them, and returns the final registers, the
  io-hash in φ9..φ12. A shape must hold `chip_idx::ALWAYS`, have one to
  four classes and size every chip from 2^4 to 2^24, or the program is
  refused.

### Dropping a chip, under the hardened AIR

Re-checked on the 25-chip AIR (`pvm/proof/src/shape.rs`):
- **A proof over a subset is a proof of the full AIR** in which each
  dropped chip's trace is its padding. Padding rows satisfy the chip's
  constraints and add nothing to any relation: every full-set canonical
  proof of a run that leaves a chip idle relies on it, and
  `a_full_set_proof_is_refused` proves one. So a witness of the subset's
  constraints and relations extends to the full set's, and a subset proves
  no statement the full set cannot.
- **Each optional chip answers requests whose multiplicities the committed
  code fixes:** the CPU's opcode flags and its host-call dispatch, which
  `ProgramMemory` binds per pc (the hardening's operand binding and the
  dispatch id), zero on padding rows. Without the chip a relation balances
  only if no row makes such a request; `a_run_needing_a_dropped_chip_does_not_verify`
  drops MUL from a run that multiplies, and the verifier refuses the logup
  sum. The tables' and the ALU chips' own requests to the always-present
  tables vanish with them.
- **The binding chips are never dropped:** `chip_idx::ALWAYS` holds the
  three boundary-binding chips, the memory root boundary, both ledgers, the
  program memory and boundary; a shape without one is refused, and the
  verifier's boundary binding still requires its own three.

### The `Derivation`

`Kernel` (`agent/wire/src/records.rs`) gains `shape: Shape { policy,
chips, classes: [SegmentClass { log_steps, pages, log_sizes }] }`,
computed by derive (`Derived::shapes`, one a kernel) and taken by
`Derivation::new`, so a node's install and a JAM builder's agree.
`policy` is the version of derive's classes and capacities
(`vos_pvm_compiler::shape::POLICY`, 1), so changing them derives other
`Derivation`s visibly. A class's sizes are a fixed `[u8; 25]` by chip (0
outside the shape), so a kernel's record decodes with one allocation. The
wire test pins the encoding: the policy and the mask as u32s, the
classes' count, each class's byte, u16 and 25 bytes; 96 bytes a kernel's
shape for derive's three classes. A kernel's record is no longer `Copy`.

The proof crate reads a record through one validating conversion,
`KernelShape::try_from(&records::Shape)` (the `wire` feature, on by
default), which every consumer and the tests share. It refuses a chip
past the AIR's 25, a nonzero size for a chip outside the mask, a missing
`ALWAYS` chip, more than `MAX_CLASSES` classes (4), and whatever
`KernelShape::check` refuses; sizes outside the mask being zero, a record
is of exactly one shape. The cap is what `DECODE_KERNEL` covers:
`the_start_reserves_cover_decoding_a_batch` decodes six installs of the
`wide` actor's 33 kernels at four classes each in 1.93M of 2.49M kept,
under its four-fifths bound [measured]; a fifth class would pass it.

**Found by the gate, and fixed:** a refine's start reserve
(`defaults::refine_start`, 20 gas a byte) did not cover decoding a batch
of installs: a kernel's record decodes at about 2.9k gas before the shape
and 8.2k with it [measured], 40–60 gas a byte, so a batch of six installs
of the `wide` actor's 33 kernels trapped already before this step
(measured with the shapes emptied: 0.57M spent of 0.45M kept), and `an_install_past_the_jam_limits_is_refused`
trapped with the shapes. `defaults::batch_start` adds `DECODE_KERNEL`
(8,000 gas) for each kernel a batch's installs name; every node, the JAM
builder's fit, its simulation and the reference runner give a refine
`batch_start`. `the_start_reserves_cover_decoding_a_batch` measures the
six installs: 1.65M of 2.38M kept. The reserve is a consensus constant,
which this step changed: `core-model.md` §8.5 says so.

### The program id (`pvm/proof/src/program_id.rs`)

- **Its preimage,** M31 words, every value in A.3's limbs (a u32 two
  16-bit limbs, a 32-byte hash 16, a byte or a log size one, a
  Poseidon2-M31 root its eight words): the domain `vos/program-id` and the
  version 2; `TRANSPILER_VERSION`; the `ProgramHash`; the shape (the mask,
  the classes' count, each class's steps, pages and log sizes); the segment
  format (31), which names the channel; each class's preprocessed root; the
  image root; the leaf-circuit slot, its version 0 and a count of 0, which
  5.12 fills.
- **The id** is the recursion AIR's `p2` leaf mode over the preimage (eight
  words a permutation into the rate, then a 1 and zeros), so a fold
  recomputes it with the rows it already has. A test recomputes it from the
  raw permutation; a golden vector pins it; a test moves each field and
  sees the id move.
- It is assembled from the install's record and the classes' roots
  (`program_commitment_for_shape`, 0.7–1.3 s for the window kernel's three
  classes [measured]). It is not yet in the `Derivation`: the roots need the
  prover, which an install does not run.

### Tests

- `pvm/proof/tests/kernel_shape.rs` (`just test-proof`), on the `kernels`
  actor's `digest`, which hashes its input as the window kernel does, and
  `areas`, which hashes only its io-hash, as a solvency predicate:
  - derive reads the AIR's chips, opcode by opcode, and the same order and
    always-present set;
  - each kernel's runs stay within the shape its install recorded;
  - both prove over their shapes, every segment at its first class, and
    their chains verify against their programs, each root its class's,
    and return the registers holding the run's io-hash;
  - a kernel's entry is its loader's (pc 0, timestamp 1, the layout's
    registers), and another blob is refused;
  - a chain not from the entry is refused: one proved from step 2, and
    one whose first state names another timestamp, pc or registers;
  - a chain not ending at the halt is refused: a run proved up to its last
    step verifies as a segment, not as the kernel's run;
  - a full-set proof of the same run verifies alone and is refused as the
    kernel's (0x60000 more chips);
  - a proof missing a chip is refused (a kernel that jumps over a count of
    set bits: proved without POPCOUNT, it verifies alone; as the kernel's it
    is refused, 0x20000 fewer; over its shape it verifies);
  - a proof at another log size (CPU one larger) is refused;
  - a run needing a dropped chip does not verify;
  - a segment past its class is refused by the prover, naming the chip.
- Unit tests: a proof is of exactly one class; a malformed shape is
  refused, more than four classes among it; a record converts to one
  shape, and each malformed record is refused; the program id's layout and golden vector, the leaf mode, every
  field moving it, and a malformed program refused.
- **The window kernel** (spike 3's settlement-window actor rebuilt on
  vos-core, `spikes/s5-shape/window` on branch `spike/s5-shape`, kept off
  the vos-core line, its cipher-clerk Ristretto calls
  served in software by its shim; derive prunes them from the kernel) runs
  live on the agent's reference model on the 8-journal window, re-traces
  from its attest to the same output, proves over its shape and verifies as
  a chain against its program; its full-set proofs are refused as the
  kernel's.

### Measured

The window kernel, 8 journals (`n1000000-j8`), format 31, 8 threads of an
Intel Core Ultra 7 155H shared with other agents' runs (load average
12–18) [measured]:
- **The run:** 404,091 steps, 687 kernel compressions, a 26,130-byte
  witness input; cut at class 1's budgets into 17 segments: the witness
  step's 151-step window and the last at class 0, the other 15 at class 1
  (the page budget closes four early: 10.6k–17.1k steps).
- **Proving:** 17 segments in 184–317 s; per 32k segment alone 7.1–18.6 s
  (the faster runs 7.1–9.3 s), class 0 segments 4.1–6.9 s; peak RSS
  6.4–7.0 GiB, under 14 GiB. Proofs 1.41–2.02 MB (postcard).
- **Columns:** the shape 8,024 (180 preprocessed, 4,880 main, 2,956
  interaction, 8 composition), the full set 8,039: **15 fewer (0.19%)**,
  POPCOUNT's and BITCOUNT's.
- **Verify gas on the JAM-only host** (`spikes/s5-shape/guest-verify` on
  branch `spike/s5-shape`, spike 1's guest and harness on the current
  verifier: vos-pvm's GP 0.8.0 instruction gas with PolkaJam's host-call
  prices):

  | segment | shape (23 chips, class sizes) | full set (25) | natural (22, unpinned) |
  |---|---|---|---|
  | 4 (32k, class 1) | 3.3465B | 3.3596B | 3.3439B |
  | 7 (32k, class 1) | 3.3510B | 3.3569B | 3.3375B |

  **The shape saves 0.18–0.39% against the full set.** Against an unpinned
  proof over the chips the segment uses, pinning costs 0.08–0.40% (padded
  ALU chips, WITNESS_INPUT present in every segment). A class 0 segment
  verifies in 3.28–3.33B: verify gas hardly follows rows. Native verify
  62–546 ms by load; the guest's peak live heap 6.3 MiB.
- **The gate:** exact-set acceptance holds (the refusals above, natively
  and in the tests). The saving is recorded: 0.2–0.4% of verify gas, not
  the 30% the plan's gate assumed. The audit's 38% was the Ristretto chips'
  (42% of the columns), which 5.5b removed; what a kernel's code leaves out
  of the hardened AIR is two small tables.

### Findings

- **The shape is now about identity and the leaf, not gas.** It pins every
  log size, which the leaf circuit needs as constants and the program id
  binds; its column saving is two tables'.
- **Pinning costs prover time:** each class pads the ALU chips to its step
  count (2^15 against 2^9–2^13 natural at the 32k cut) and WITNESS_INPUT
  to 2^16 in every segment. A narrower ALU capacity, or WITNESS_INPUT
  in the entry segment's class alone, would cut it; a window that
  overflows a narrower class is cut in half and proved twice, so the
  capacities here hold a step's worst case where it is cheap.
- **A segment lists one page past its cut:** the page Merkle boundary
  always lists page 0, so the page chips are sized for `pages + 1`.

### Gates

[measured, on this machine, each under `systemd-run` at 14 GiB with
`nice -n 10` and `CARGO_INCREMENTAL=0`]: `just check` green, 1,005 tests;
`just test-proof` green, 555 tests (`kernel_shape` 8, and 6 new unit
tests); `just clippy` clean. With the review folded, on vos-core: `just
check` green, 1,005 tests; `just test-proof` green, 577 tests
(`kernel_shape` 11); `just clippy` clean.

## Step 5.5: the witness-input precompile, the run's ends and the io-hash

### The witness input, `0x401`

- **Served alike everywhere:** `vos_pvm::precompile::WitnessInput` serves a
  call: φ7 the destination, φ8 the capacity, `min(capacity, remaining)`
  bytes written there and their count in φ7, 0 at the end. The testkit's
  model and the tracer serve through it; the agent serves through its own
  `Machine::witness_input`, on VOS and JAM alike (the agent serves its
  kernels on both). A call that cannot pay stops the kernel out of gas, one
  whose bytes cannot land traps it, and a handler's call of `0x401` is an
  id the agent does not serve (`WHAT`).
- **Its price** (decided here): 2,500 a call, an actor's `input`, plus 24 a
  byte, an actor's per-byte price, charged before the bytes are written;
  the agent takes `PRECOMPILE_SERVING` (27,000) from the batch's meter a
  call, as for every precompile. A kernel's 64 KiB of arguments cost
  1,575,364 gas [model].
- **The record:** `Attest { program, witness_input, output }`: the bytes the
  kernel read, in call order, at most 4 MiB. **Deviation from the plan:**
  it replaces `arguments` rather than joining it. The kernel now reads its
  arguments through the input, so the two would hold the same bytes, and a
  step's sixteen attests at both caps would pass the work result's 4 MiB
  (`cap::step_result` sizes an attest at its arguments and output: about
  3.42 MiB of 4 MiB today, 4.42 MiB with both) [model].
- **`derive`'s prologue** (`TRANSPILER_VERSION` 3, 29 instructions): it
  reads the input into 17 zero pages past the kernel's read-write data
  (room for a request's 64 KiB and a byte), calls until a call returns 0,
  traps if it filled them, calls the entry on the bytes, and returns to
  the halt address with the output in φ7/φ8 and the io-hash in φ9..φ12.
  The loader maps no arguments and leaves φ8 at 0. `derive` admits
  `0x401` (`is_kernel_call`).
- **The image root:** each `Derivation` kernel (`records::Kernel`) names
  `image_root`, the page tree's root over its initial memory with no
  arguments (`vos_pvm_program::image`), computed in `Derivation::new` at
  install, the VOS node's and the JAM builder's alike.

### The io-hash

`compute_io_hash(public_args, output, roots)` (`vos_pvm_precompiles::io`):
BLAKE2b-256 of `vos/io/v1`, then the three fields SCALE-encoded (a compact
length and the bytes; a compact count and each `RootRead` as kind, space,
LE window and root, 73 bytes). On the PVM it hashes through `0x400`. The
SDK's attestable entry computes it on its encoded output, with no public
arguments and no roots, and the prologue leaves it in φ9..φ12.

### The AIR binding

- **CpuChip:** `IsWitnessEcall` selects dispatch 101, committed in
  PROGRAM_MEMORY like `0x400`'s. Its row reads φ7 and φ8 at its timestamp
  (the register reads Ristretto's ids share), writes the count to φ7 alone
  (`ResultIsReg`, `ResultRegIdx` 7), a count below 2^24 at a destination
  below 2^32; `WitnessNonEmpty` (with an inverse) is set exactly when the
  count is not zero. Four new emissions: `(φ8, count, lt = 0)` twice to
  CompareChip, so the count is at most φ8, and `(ts, destination, count)`
  twice to the new relation `WitnessCall` when non-empty. Four columns.
- **`WitnessInputChip`** (index 13; `chip_idx::COUNT` 32 → 33, so the
  component mask is a `u64`): one row a byte, 22 columns, 8 lookups. A
  call's first row consumes its tuple; while bytes are left a row is
  followed by the call's next byte, at its timestamp, the next address (a
  carry chain with every byte range-checked, no wrap past 2^32) and one
  fewer left; the last has one left; a row that does not start a call
  follows one that goes on. Each row writes its byte to the memory ledger.
- **The register ledger sorts reads before writes** within a timestamp
  (key `2·ts + is_write`). Without it a prover could order the witness
  call's φ7 read after its write and read the count as the destination;
  the same freedom let a step reading and writing one register (an ALU op
  whose destination is a source) read its own result. A same-register gap
  of 2^27 steps is now the limit, past the 100M-step budget.
- **The halt:** a halting step's `next_pc` is `PVM_HALT_ADDR`, in the
  tracer, the Refine prover's observation and CpuChip's two halt
  selectors, so a segment's `pc_out` is the halt address exactly when it
  ends at a halt.

### Tests

- live ≡ traced (`pvm/proof/tests/witness_input.rs`): each of the
  `kernels` actor's three kernels, attested on the agent's model on 0, 4
  and 200 values, re-runs from its attest (`kernel::trace_kernel`) to the
  same output and to `compute_io_hash(&[], output, &[])`, reading its
  recorded input whole; the agent's own tests hold its attests equal to
  the model's on VOS and JAM;
- the cursors at every call: one reader program, pinned on both sides
  (`tracking.rs` for the agent, `witness_input.rs` for the tracer): three
  bytes, none, four, a short read of three, a read at the end, cursors
  0, 3, 3, 7, 10;
- a short read returns its count and a read at the end 0: there, and
  `vos_pvm`'s unit tests;
- writes outside the named range refused: a write moved one byte past or
  before its destination, a byte past or short of the count, and a count
  past its capacity each fail verification (the last passes once the
  compare emission is removed); the column-level gates
  (`witness_input_gate.rs`) for every CpuChip and WitnessInputChip
  constraint, and the ledger's read-after-write;
- an oversize input refused: past 4 MiB by `WitnessInput`, the tracer and
  the agent; past a request's bytes by the prologue, on every host;
- the initial root equals the install's, the derivation's and the first
  segment's proven `memory_root`;
- a halting run's last segment ends at the halt address, and a segment
  cut just before the halting step ends at that step's pc; the chain
  verifies.

### Numbers

- **The `kernels` actor's kernels, re-traced** [measured]: `named` 891
  steps whatever its input; `digest` 1,797, 2,537 and 20,394 steps on 0,
  4 and 200 values; `areas` 925, 1,697 and 31,094. Each reads its input
  in two calls, the second at the end; the prologue, the entry's decoding
  and the io-hash's one compression are in every count.
- **The witness input's AIR cost** [model]: a row of 22 columns a byte
  in WitnessInputChip, and four columns on the CPU; a kernel's 64 KiB of
  arguments is a 2^16-row chip.
- **The gates** [measured, on this machine]: `just check` green, 1,006
  tests; `just test-proof` under `systemd-run` at 16 GiB with `nice -n
  10` and two threads green, 527 tests in its first suite, 1,002 s in all.

### The operand binding

Fable's review of 5.5 found CpuChip bound no register index or
register-source flag to the instruction: a ThreeReg row could drop its
ValB read, take any ValB, and write the sum to φ9, an arbitrary io-hash.
The fix, and the holes of the same class it turned up:

- **The flag bag is 80 bits in 10 bytes** (`PROG_MEMORY_N_FLAGS`; the
  instruction tuple 32 → 36 limbs). Byte 6 is the instruction's register
  accesses (`reg_access::access_shape`: ValB from φA or φB or none, ValD
  from φB or the immediate, the result to φA or φD or none) with the
  remainder bit of a division and the two operand swaps; bytes 7–9 the
  compare, branch and bitwise sub-operations, which were bound only as
  sums (an `And` could be applied as an `Or`, a `MinU` as a `CmovIz`
  writing anything). CpuChip recomposes bytes 6–9 from their bits, each
  boolean, in its own constraints (no new lookups); the indices are
  `ValBRegIdx = RegB + ValBFromA·(RegA − RegB)`, `ValDRegIdx = RegB`,
  `ResultRegIdx = RegA + ResultToD·(RegD − RegA) + 7·IsWitnessEcall`. A
  conditional move's result bit is its move, a witness call's its count.
- **Every instruction's write is recorded** (`tracing::recorded_write`,
  shared with the Refine prover's observation), even of the value the
  register held, so `ResultIsReg` is fixed by the instruction.
- **An immediate operand is the instruction's:** `RegValD` is ValD's
  source, its register or the immediate, pinned to `ImmBytes`; ValD was
  free on every immediate instruction (`LoadImm φ4 = 42` could load
  anything). `LoadImmJump` moves its immediate and `LoadImmJumpInd`'s
  result is its `imm_x`; both results were free.
- **Shift amounts:** the identity `RegValD = ShiftAmount + modulus·q` was
  over M31 with an unchecked 8-byte q, so any amount satisfied it, and it
  was ungated on immediate shifts. It is now on the low byte, with q's
  bits (3 and 4 columns), over the integers; `IsShiftConstrained = IsShift`.
- **MemoryChip** sorts by `2·ts + is_write`, as the register ledger does,
  and its `IsWrite` and `IsPadding` are boolean.
- **Lookup tables keyed by main columns:** Range256, BitwiseAnd and
  PowerOfTwo read their entries from main columns a prover fills, not
  their committed preprocessed ones; any Range256 check was void. They now
  read the preprocessed columns; their main traces are multiplicities.
- **Smaller ones:** the register ledger's `IsPadding` is boolean; the
  jump table's padding rows (tuple `(0, 0)`) take no multiplicity
  (`IsEntry`); a MemoryPage page is real on all its 32 rows, so it always
  produces its leaf; derive and ProgramMemory refuse a static jump to the
  halt address; a witness call that writes no bytes may name any
  destination, as the live call does.

Each forgery is a gate that the old code accepted and the new refuses:
`operand_binding_gate.rs` (12), `memory_ledger_gate.rs` (2),
`jump_table_gate.rs` (1), and `witness_input.rs`'s zero-count call
(which failed to prove before).

### Findings, not fixed here

An audit of the other chips for the same class reported these; they are
the next fixes:

- **The register ledger's merged read slots** (`Ts1..Ts3`) are not
  ordered: a read can take a stale value by riding an earlier row.
- **Mul and DivRem carries** are not range-checked, nor the top carry
  pinned: a product or quotient can be wrong; DivRem's `|r| < |d|` chain
  uses unchecked carries.
- **BLAKE2b:** the write addresses are pinned on row 0 only, and the
  main chip's `IsReal` is not held across its 96 rows.
- ~~**Ristretto:** ids 110–114 compute nothing tied to memory, row roles
  and source rows in the comb chips are free, `IsFixedBase` is not
  checked against the base point.~~ Resolved by removal: the chips and
  the ids are gone (below).
- **Shifts right:** nothing distinguishes `ShloR` from `SharR` in the
  AIR (both prove either quotient).
- `ShloL/ShloR/SharRImmAlt` take their operands unswapped and do not
  prove (completeness only).

### The Ristretto chips removed

The owner's decision: the Ristretto and scalar chips were unsound (the
finding above), derive already refused a kernel using them, and slice 7's
generic bignum chip replaces them.

- **Gone:** the eight chips (`RistrettoChip`, `RistrettoEcallChip`, the
  comb table, its anchor, scalar boundary, fixed-base consumer, compress
  and compress-output chips), their eleven relations, CpuChip's five
  `Is{110..114}Ecall` selectors and their emissions, the tracer's handlers
  and records, the side note's streams, the segment cutter's and cursors'
  streams, the shim's `ristretto` feature (`Scalar`, `RistrettoPoint`) and
  `curve25519-dalek` from the prover and the shim.
- **The ids:** 110–114 are no precompile anywhere: the tracer does not
  serve them (`proof_precompile_dispatch_id` is 0), the runtime neither
  serves nor prices them, and derive refuses a kernel reaching one; a test
  pins each.
- **The AIR:** `chip_idx::COUNT` 33 → 25, `BITWISE_AND_BYTE` at 24, so the
  component mask is a `u32` again. A witness-input call keeps its φ7 and
  φ8 register reads, now in a block of their own.
- **The full width** [measured]: a full canonical segment (every chip,
  mask `0x1ffffff`) commits **7,556 columns**: 173 preprocessed, 5,107
  main, 2,268 interaction, 8 composition. It was 13,037 with the
  Ristretto chips, at 32 chips. The full shape now fits under a kernel
  leaf's ~9,300-column headroom [model].
- **Tests:** the Ristretto suites are deleted (`comb_value_sweep`,
  `ristretto_ts_gate`, the Ristretto parts of `precompiles` and
  `chip_isolated`); the dispatch gates and the host-call pc gates now run
  on BLAKE2b and the witness input; the segment fixture threads three
  BLAKE2b compressions across its windows.
- **Gates** [measured, on this machine]: `just check` green, 998 tests;
  `just test-proof` under `systemd-run` at 16 GiB with `nice -n 10` green,
  465 tests (the prover's library 132 → 91 unit tests); `just
  test-bench-proof` green; clippy clean on every feature set of `just
  clippy` that touches the prover.

## 5.5b hardening: ARITH

The arithmetic holes of the AIR audit (G3, and G1's X-DIVHI), closed on
`s5-hard-arith`. Each forgery is a permanent
gate in `pvm/proof/tests/arith_gate.rs`: an execution whose destination
register holds the forged value in every step from the forged one on, so
the register ledger and the closing state agree with it, proved by forged
chips that rewrite MulChip's, DivRemChip's and the CpuChip's division
columns (and move the lookup multiplicities with them) between trace
generation and commitment, then verified with the real chips. Before the
fix all eight proved and verified [measured]; after it each is refused.

| hole | forgery (arith_gate.rs) | before | after |
|---|---|---|---|
| G3-1 MulChip carries free | `mul64_carries_solved_in_m31_refused` (6·7 as 41), `shlo_l64_…` (1 << 3 as 0xDEAD_BEEF) | accepted | refused: logup sum not zero (non-byte carries) |
| G3-2 DivRem schoolbook free | `divu64_carries_solved_in_m31_refused` (100/7 as 13) | accepted | refused: logup sum not zero |
| G3-3 magnitude chains | `rems64_magnitude_carries_solved_in_m31_refused` (−100 rem 7 as −9, \|r\| claimed 0) | accepted | refused: constraints (boolean AbsR carries) |
| G3-3 signed correction carries free | `divs64_correction_carries_solved_in_m31_refused` (−100/7 as 0xDB6D…DB60 rem −4) | accepted | refused: logup sum not zero |
| G3-4 / X-DIVHI high half free | `shlo_r64_quotient_top_bits_refused` (0x1000 >> 12 as 1 + 2^52, all carries bytes) | accepted | refused: constraints (H = 0) |
| G3-4 SharR = ShloR | `shar_r64_sign_dropped_refused` (−1024 >> 3 as the logical shift) | accepted | refused: constraints (floor-division H) |
| new: 32-bit divisor magnitude | `divs32_negative_divisor_magnitude_refused` (100 / −7 as −13 rem 9, every chain over the integers) | accepted | refused: constraints (\|d\| of the sign-extended word) |

Controls, refused before and after: the honest filler's witness for a
forged product, the low bits of a shift quotient, and `13·7 + 9 = 100`
with `r ≥ d`; the harness proves an honest execution.

- **The fixes** (`chips/mul.rs`, `chips/divrem.rs`): Range256 on every
  byte and carry the chains read — MulChip 64 emissions a row (low and
  high products, `MulHigh`, the 32 schoolbook and 8 correction carries),
  DivRemChip 96 (quotient, remainder, high half, the 32 schoolbook and 8
  correction carries, `AbsD`, `AbsR`, the two compare chains' bytes) —
  and boolean `AbsDCarry`/`AbsRCarry`/`AbsCmpCarry`/`DivCmpCarry`. Every
  chain equation then stays below 2^25 and holds over the integers; the
  schoolbook's final carry is 0 because `q·d + r < 2^(2W)`. DivRemChip
  pins the schoolbook's high half `H`: `H = 0` on unsigned division and
  ShloR; `H ≡ sq·d + sd·q + sr − sb + k (mod 2^W)` on DivS/RemS, written
  with `−sb` as `sb·(2^W − 1)` so the carries stay in {0, 1, 2}; and
  `H ≡ sq·d − sb` on SharR (the same chain with `sd·q` dropped — a shift's
  `2^63` is unsigned — and `sr = 0` by `r < d`), which with `0 ≤ r < d`
  is floor division. These are the auditors' minimal fixes; the SharR
  high half, their `sb·(d − 1)`, is `sq·d − sb` through the signed chain
  (equal, as floor division gives `q` the sign of `b`), which reuses its
  columns.
- **The flag** (CPU, kept minimal): the DivRem tuple gains `is_shar_r`
  (41 limbs). It must be committed per opcode, and the 80 flag bits were
  all in use, so flag byte 0's bit 3 now commits `is_shar_r` in place of
  `is_mul_upper`, which its three variants (bytes 2–3, bound bit by bit)
  already imply. CpuChip gains the `IsSharR` column; the byte-0
  byte-to-bits tuple and the DivRem emission carry it. Program
  commitments of code with an arithmetic shift or a MulUpper change.
- **Completeness** (G3-5), each now a positive test in `phase2_alu.rs`:
  DivS/RemS `MIN / −1` at both widths — a boolean `DivOverflow` adds 1 to
  the correction, allowed only on a signed division by −1 (all-ones
  divisor word), where `|r| < 1` and the identity force `b = q = MIN`;
  `−256 / 256` (the offset chain); DivU32/RemU32/ShloR32 results with bit
  31 set (a 32-bit row's quotient and remainder are sign-extended words,
  the `r < d` decision read at byte 3); SharR32 of negative values
  (`r` taken mod 2^32); SharR by the top bit at both widths. Also found
  and fixed: a 32-bit remainder by zero of a value with bit 31 set
  (CpuChip bound the result's high word to the truncated dividend's
  zeros; `DbzActiveRem64H` now binds it on 64-bit rows only, the 32-bit
  sign extension covering the rest).
- **Found here, fixed** (beyond G3): a 32-bit signed division by a
  negative divisor took `|d|` over the 8 bytes of the zero-extended word,
  about 2^64, so `|r| < |d|` held for any remainder — a forgery surviving
  every G3 fix. The magnitude chain now reads the sign-extended word.
- **G3-6** (and G1's T-WEAK): `forge_two_reg_result`,
  `forge_three_reg_result` and alu_negative's direct forgeries carry the
  forged value through every later step (`forge_first_result`), so only
  the op's own constraints can refuse them; the chips' internal-witness
  forgeries are arith_gate's. All still refused.
- **Restructured:** DivRemChip computes its own row (`divrem::entry`,
  `witness`, `range_checked_bytes`); the CpuChip fill calls it instead of
  carrying ~300 lines of the chip's chains, and both chips' Range256
  multiplicities come from the chip's own list.
- **Width** [measured]: the full shape commits 7,846 columns (173
  preprocessed, 5,109 main, 2,556 interaction, 8 composition), from 7,556.
- **Gates** [measured, on this machine]: `just check` green, 998 tests;
  `just test-proof` under
  `systemd-run` at 14 GiB with `nice -n 10` green, 493 tests; `just
  test-bench-proof` green; `just clippy` clean.
- **Files outside the track's own**, each change isolated: `cpu/classify.rs`
  (`is_shar_r`, the byte-0 slot), `cpu/columns.rs` (`IsSharR`,
  `DbzActiveRem64H`), `cpu/mod.rs` and `cpu/interaction.rs` (the byte-0
  tuple's slot, the DivRem tuple's field, the remainder-by-zero binding),
  `cpu/trace_fill.rs` (the DivRem block replaced by `divrem::entry`, the
  multiplicity charges), `side_note.rs` (`DivRemEntry`), `proof.rs` and
  `refine/tests.rs` (the format), `tests/common/mod.rs`.

## 5.5b hardening: BLAKE

The AIR audit's BLAKE2b group (G4) and the memory group's items on the
BLAKE2b chip, the root boundary and the host verifier (G2). Each hole's
forgery is a permanent gate test; each was run on the unfixed tree first.

| hole | before | fix | gate test | after |
|---|---|---|---|---|
| G4-1 `IsReal` not held across a compression | ACCEPTED: a lone real row 95 writes a forged digest at a forged address and ts; a lone real row 0 consumes the call and drops the write | `IsReal` boolean, `ContinuityGate·(IsReal_next − IsReal) = 0` (`blake2b/mod.rs`, the IsReal anchor) | `blake2b_gate`: `a_lone_last_row_cannot_write`, `a_lone_first_row_cannot_drop_the_write` | REFUSED (continuity) |
| G4-1, found here: the trailing partial block | ACCEPTED: block 0 padding, call 0 placed in the 64-row tail, which has no row 95; the wrap to row 0 kept satisfied | `IsTail·IsReal = 0`, `IsTail` preprocessed (`r ≥ 96·⌊N/96⌋`) | `a_tail_block_cannot_consume_a_call` | REFUSED (`IsTail`) |
| G4-6 `IsReal = 2` | ACCEPTED | the booleanity above | `is_real_two_is_refused` | REFUSED |
| G4-2 / G2-3 write address pinned on row 0 only | ACCEPTED: row 95's `HWrAddrB2` moved 64 KiB | `HWrAddr` dropped; the writes use the `h` addresses, whose limb relations hold on every row (`blake2b/address.rs`) | `the_write_address_is_pinned_on_the_writing_row` | REFUSED (limb relation) |
| G4-3 addresses mod p | ACCEPTED: `h_ptr + p` read and written | byte-carry addresses (`address.rs`): limb 0 `ptr0 + i − 256·c_i`, `c_i` boolean, Range256; limbs 1..3 the pointer's or `(ptr >> 8) + 1`'s, chosen by `c_i`; the increment's limbs Range256, carries boolean, no carry out of limb 3 | `an_address_aliased_by_p_is_refused`, `a_range_wrapping_2_32_is_unprovable`, `ranges_carrying_across_limbs_are_accepted` | REFUSED (carry booleanity) |
| G4-8 dead code | — | `Blake2bStateLookupElements` and the main chip's `EmitMult` deleted | — | — |
| G4-7 tracer | the flat path read zeros out of range and recorded the access | `handle_blake2b_ecall` serves through `vos_pvm::precompile::execute` on flat and sparse memory alike (refused ⇒ Panic); the ledger builder uses `wrapping_add` | — | — |
| G2-4 root boundary `IsReal` | ACCEPTED (`IsReal = 2`) | `IsReal·(IsReal − 1) = 0` (`memory_root_boundary.rs`) | `memory_root_boundary_gate` | REFUSED |
| G2-7 host verify gated on a side-note flag | ACCEPTED end to end: a proof made without the boundary mix, its final φ9 forged, verified against a side note with `closing_chip_active` cleared | the production path (`boundary_positions` known) always mixes the boundary states and checks the claimed sums, and refuses `initial_state.timestamp < 1` (`verify.rs`) | `host_verify_boundary_gate` | REFUSED |
| G2-2 `IsPadding = 2` mints a write | closed by d418e727, untested; ACCEPTED with the booleanity removed (mutation run) | — | `memory_ledger_padding_gate` | REFUSED |

- **Deviation from the auditor's G4-3 fix.** A full carry chain with
  Range256 on all four limbs of 192 addresses is 768 lookups a row. Only
  limb 0 needs its own carry; limbs 1..3 take one of two values, the
  pointer's own limbs or those of `(ptr >> 8) + 1`, so one range-checked
  increment per pointer covers them: 198 lookups. Every limb is still a
  range-checked byte (or a pointer limb, which the CPU's call tuple
  supplies), every identity is over small integers, so each address is
  `ptr + i` exactly. G4-2's fix falls out: the write tuples read the `h`
  addresses on row 95, where their relations hold.
- **The width** [measured]: `Blake2bChip` is 44 preprocessed (+2), 1,744
  main (−247) and 1,344 interaction (+396) columns, so the full shape is
  7,707 columns (+151).
- **Completeness:** a pointer within 256 bytes of 2^32 (`ptr ≥
  0xFFFF_FF00`) has no satisfying increment even when its range does not
  wrap; the standard layout maps nothing above `0xFFFF_0000`.
- **Dependencies:** the addresses are canonical given canonical `HPtr`
  and `MPtr` bytes, which the CPU call tuple carries (the CPU group's
  register limbs).
- **Not here:** G4-4 and G4-5 (the CPU's 0x400 path) and G2-1 (page
  permissions) are track CPU's. The AIR changed, so the proof format
  needs a bump; that is left to the merge of the three tracks.
- **Gates** [measured, on this machine, under `systemd-run` at 14 GiB with
  `nice -n 10`, three tracks in parallel]: `just test-proof` green, 478
  tests (465 + the 13 new gates); `just test-bench-proof` green; `just
  check` green (`tree_crash` failed once under the parallel load and passed
  on rerun); clippy clean on every feature set of `just clippy` that
  touches the prover.

## 5.5b hardening: CPU

The CPU, register and memory-permission holes of the AIR audit (G1, G2-1,
G4-4, G4-5), each ported as a permanent gate, run first on the unfixed
AIR (ACCEPTED), then fixed (REFUSED).

### Page permissions: the design (G2-1)

Today the AIR proves a run on an all-RW machine: a store to a read-only
page, or any access to an unmapped page, faults on the PVM but proves.
A kernel's permissions are static (no host call changes them) and fixed by
its layout, which `derive` gives it: the read-only data, the read-write
data with its heap, and the stack, each a whole number of pages, the
argument window (empty for a kernel), and nothing else mapped.

The two candidates:

- **(a) A permission in the page leaf**, and a `(page, perm)` relation
  CpuChip consumes per memory row. It changes what an image root is (the
  program crate's `image_root`, `page_merkle`, every recorded root), adds
  per-row lookups to the widest chip, and leaves the BLAKE2b and witness
  writes, which are not CpuChip's, unchecked.
- **(b) The layout's regions as preprocessed constants**, each memory
  access proving its address lies in a permitted region. Per CPU row that
  is two 32-bit range comparisons, and the precompiles' accesses again.

Chosen: **(b), checked per page and enforced per ledger row**, which is
cheaper than either as stated and covers every producer:

1. **The regions are preprocessed.** MemoryPageChip carries four regions
   as constant preprocessed columns, in pages: read-only data and the
   argument window (readable), read-write data with its heap and the
   stack (writable). They enter the preprocessed commitment, which is the
   program's identity, so a proof's permissions are its program id's. A
   kernel's come from its layout (`trace_kernel`); a side note with no
   layout (the test machines) has one writable region over all pages.
2. **A listed page claims its permission and proves it.** Each page row
   selects at most one region and proves `lo ≤ page < hi` by two 20-bit
   decompositions. Claiming none (unmapped) needs no proof: it only
   forbids. A page claimed readable lies in a readable or writable region,
   one claimed writable in a writable region.
3. **The ledger carries the permission through each address.** The page's
   ts=0 write, which starts every address group of the ledger, carries its
   permission in the tuple's last field (`is_closing + 2·perm`; every other
   producer emits 0 there, and no other producer emits ts = 0). MemoryChip
   holds `Readable`/`Writable` constant along the group and enforces on
   every row after its start: a write needs `Writable`; on an unreadable
   page the start is followed directly by the closing read.

So every CPU load or store, BLAKE2b read or write and witness-input write
lands in a group whose page proved the permission it needs, with no new
lookup, no new relation, and no change to the image root. Cost: on
MemoryPageChip 8 preprocessed and 46 main columns (4 selectors, the two
bounds, 40 bits), on MemoryChip 4 main columns, no interaction columns.

Out of this binding: refine machine slices, whose inner machines change
their pages' permissions at run time (the `pages` host call); their side
notes ask for `MemoryLayout::writable()` explicitly, and refine's replay
binds their permissions. A layout per slice, or a permission that a page's
history carries, would be their in-AIR binding.

### The holes, each before and after

Every gate ran first on the unfixed AIR at 0dc9ba45: each forgery
ACCEPTED (the gate failed with `SOUNDNESS GAP`); after the fix, REFUSED.
A gate's forgery edits the honest trace as a forger would, consistent with
every constraint that does not bind the column it changes; a lookup's
refusal is checked against every chip's constraints and the whole trace's
logup balance (`harness::base_components`, debug-internals).

- **H-CARRY** (critical): Add/Sub carries were free field elements, so
  any result solved its byte equations. Now bits on every row.
  `cpu_soundness_gate::an_add_s_carries_are_bits` (Add64 100 + 7 → 999).
- **H-REGSLOT** (critical): the merged read slots `Ts1..Ts3` consumed any
  read, unordered. Gone: each ledger row consumes one access (27 columns
  and three emissions fewer). `register_ledger_gate::a_read_is_not_merged_into_another`
  ACCEPTED before; after, the forgery has no column to stand in.
- **H-REGPAD** (critical): padding switched the sortedness gadget off,
  and a run after it took a free `PrevValue`. A chain of same-register rows
  now starts at its register's ts = 0 write (`ChainStartH`), one per
  register; the auditor's suffix-padding rule plus write-first rule needs a
  preprocessed first-row column, this needs none and is MemoryChip's rule.
  `a_read_follows_its_register_s_writes` (a stale read of φ2 after a
  padding row).
- **H-PADEMIT** (critical): a padding row's flags were free, so it could
  emit register, memory, BLAKE2b and witness tuples; `IsPadding` was not a
  bit. Now `IsPadding` is a bit and a padding row's ten flag bytes are
  zero; the byte-to-bits lookups run on every row (multiplicity 1, the
  zero tuple counted per padding row), so every flag is pinned there, and
  the memory-width shape is ungated, zeroing the active bytes; the
  precompile selectors and the result write follow. Cheaper than gating
  each of the ~20 emission multiplicities, and it covers any later gate.
  `a_padding_row_emits_nothing` (φ2 := 100 at ts 1 from a padding row),
  `padding_is_a_bit` (Add64 with `IsPadding = 2`, its realness −1).
- **H-BREQ** (critical): equality was bound one way. `EqFlag` is now the
  operands' equality both ways on compare and branch rows: the sum of
  squared byte differences, below 2^20, and its inverse; BranchEq/BranchNe
  take it as their condition. A branch whose target is its fallthrough
  records `BranchTaken` as its condition, which the fill now honours
  (before, the step's "pc moved" bit stood there, which the strict
  Lt/Ge/Le/Gt constraints refused for a true condition).
  `an_equal_branch_eq_is_taken`, `an_equal_branch_ne_falls_through`,
  `equal_operands_are_equal` (BranchLeUImm 42 ≤ 42 not taken);
  `control_flow_negative` gains the auditor's end-to-end forgeries.
- **H-MINMAX** (high): MinS/MaxS results were free. One column,
  `MinMaxLtFlag` (the signed less-than on their rows, the unsigned
  otherwise), feeds the MinU/MaxU helpers, whose result constraints now
  cover the signed rows; the auditor's 16 helper columns are not needed.
  `a_signed_min_is_its_lesser_operand`, `a_signed_max_is_its_greater_operand`.
- **H-STIMM64** (high): an 8-byte immediate store's high word was free.
  `ImmYBytes` and ProgramMemory's `ImmYCanon` carry imm_y's fifth byte, its
  sign byte (the program-memory tuple 37 limbs), and MemValue[4..8] equals
  it. `a_store_immediate_s_high_word_is_the_instruction_s`.
- **H-TRAPPC** (high): a Trap's NextPc, a segment's final pc, was free.
  It stays at its pc. `a_trap_stays_at_its_pc` (a panic presented at the
  halt address).
- **H-NOOP** (medium): ProgramMemory served its zero tuple at non-start
  pcs. A preprocessed `IsInstruction` refuses them any multiplicity.
  `only_an_instruction_start_is_fetched`.
- **L-TSLIMB** (low): NextTimestamp's limbs are Range256-checked (8
  lookups per row, kept last). `a_timestamp_s_limbs_are_bytes` (the limb
  256, a withheld carry; checked against every chip and the logup balance).
- **L-PCCARRY** (low): PcCarry bits. `a_pc_carry_is_a_bit`.
- **L-PHI7, G4-5** (low): `Phi7Bool` tests the sum of φ10's bytes (zero
  exactly when the register is), not its field reduction; `Phi7Inv` one
  column. `cpu_completeness::a_compression_flag_of_the_modulus_proves`
  (φ10 = 2^31 − 1, unprovable before).
- **L-ISWRITE** (low): the register ledger's `IsWrite` is a bit.
- **G4-4** (medium): a BLAKE2b call's φ7/φ8 high bytes are zero.
  `a_compression_s_pointers_are_32_bit`.
- **G2-1** (high): the design above. `page_permission_gate::a_store_to_a_read_only_page_is_refused`
  (the auditor's: a store to a read-only and to an unmapped page, run on a
  writable one; ACCEPTED before, both REFUSED after, and the writable
  layout proves under another program identity),
  `a_page_lies_in_the_region_it_claims`, `a_read_of_a_read_only_page_proves`.

**Completeness:**

- **C-IMMALT**, fixed: the ImmAlt shifts swap their operands as RotR's
  does (`IsRotateRImmAlt` is now `IsImmAlt`, set on all eight).
  `cpu_completeness::imm_alt_{left,right}_shifts_prove` (the auditor's
  `5 << 3` refused before).
- Branches to their fallthrough, fixed (above):
  `branches_to_their_fallthrough_prove`.
- **C-DJUMP**, recorded: an invalid dynamic jump (odd, zero or past the
  table) panics on the machine but has no `(addr, target)` entry, so its
  step cannot be proven. A kernel ends at a halt (`trace_kernel` refuses
  any other exit), so no kernel proof needs it; proving it would need a
  terminal selector whose address provably lies outside the table (odd,
  or above `2·len`), a comparison against the table's length.
- The register ledger's 28-bit order delta still caps a register idle for
  2^27 steps (G1), as the memory ledger's does (G2-5).

**Vacuous negatives replaced:** `forge_two_reg_result` (bitmanip's
negatives) now carries the forged result through the run, so the ledger
accepts it and only the operation's constraints can refuse it; all 14 are
still refused. `forge_three_reg_result` (alu_negative) is track ARITH's.
The `padding_is_a_bit`, carry and branch gates edit exactly their column.

**Gates** [measured, on this machine, under `systemd-run` at 14 GiB with
`nice -n 10` and 6 jobs]: `just check` green, 998 tests; `just
test-proof` green, 493 tests; `just test-bench-proof` green; clippy clean
on the prover's feature sets of `just clippy`.

**Merge notes:** format 30/31 is also track ARITH's; the merged AIR takes
one bump. No new flag bit: `IsImmAlt` is the old `IsRotateRImmAlt` bit.
The byte-to-bits emissions' multiplicity (now 1) sits next to ARITH's
byte-0 slot; the DivRem emission block and trace_fill's DivRem section are
untouched.

## 5.5b: the tracks merged, and onto 5.3

The three hardening tracks merged into `s5-witness` (arith, then blake,
then cpu), and `s5-witness` into `vos-core` over step 5.3.

### The tracks

- **arith** fast-forwarded `s5-witness`; **blake** merged without a
  conflict.
- **cpu:** the format history (both tracks had written their own 30 and 31)
  became one entry for the three tracks' AIR; `tests/common/mod.rs` took
  arith's `forge_first_result`, the same forgery the cpu track inlined in
  `forge_two_reg_result`. The overlaps the tracks named merged cleanly and
  were checked by hand: flag byte 0's bit 3 commits `is_shar_r` (arith) in
  the byte-to-bits tuples, both the constraint and the interaction side,
  whose multiplicity is now 1 on every row (cpu), so a padding row's
  `IsSharR` is pinned to 0 like every flag; the DivRem tuple's 41 limbs
  (arith) are untouched by cpu; `IsImmAlt` (cpu) and `is_shar_r` (arith)
  are both set on SharRImmAlt.
- **Found by the merge:** blake's `memory_ledger_padding_gate` refills the
  memory ledger from explicit rows, and cpu's permission columns (`IsStart`,
  `Readable`, `Writable`, `PermissionH`) were left zero, so its honest
  control failed. The refill now derives them as MemoryChip does; the
  forgery is still refused (the `IsPadding` booleanity, and now also
  `IsStart`'s, as the minting row's `IsStart` is −1). The eval helper
  `combine_le_u64`, whose last callers blake and cpu each removed, is gone.
- After each merge, every gate test of the three tracks and of 5.5 ran
  green.

### Onto 5.3

- **Conflicts:** `prove.rs` and `verify.rs`, which 5.3 split into
  `prove/{canonical,debug,profile}.rs` and `verify/recursion.rs`: 5.3's
  layout kept, 5.5's edits ported into the moved code (the debug names
  list: `WitnessInput` in, the Ristretto chips out, `BitwiseAndByte` in;
  comments). `verify.rs`'s boundary block: 5.3's `mix_boundary_states`
  and interaction PoW, under blake's G2-7 rule: the production path
  (`boundary_positions` known) always mixes and checks the claimed sums,
  whatever `closing_chip_active` says, and refuses an initial timestamp
  below 1. `lookups/relations.rs`: the Ristretto relations gone, 5.3's
  `MAX_RELATION_WIDTH` kept over the relations left (`WitnessCall` in,
  the BLAKE2b state relation out; still 265). The Ristretto files 5.3
  touched are deleted; `poseidon2_canonical_segment.rs`, which 5.3 had
  replaced by `verifier/tests/formats.rs`, stays deleted. `justfile`: 5.3's
  recipes, with 5.5's `build-test-actors` before `test-proof`.
- **Ported to run-time selection:** the new gate tests drew lookup elements
  on `recursion_pcs::ProverChannel`; they draw on a `Blake2sChannel` through
  `ChannelRef`, and arith's forged-chip wrapper implements the erased
  traits' `ChannelRef` and `SimdBackend` signatures.

### The format numbers

5.5 and the tracks changed the segment AIR, so every format naming it
takes a new number, and the numbers that named the old one are retired
(`format::RETIRED`: refused as retired, never registered again). The
branches' own numbers (26 to 31) were never published and are gone.

| number | proofs | status | counts at its reference shape [model] |
|---|---|---|---|
| 28 | the final wrap (recursion AIR) | reserved, unchanged | 146 / 74 (74.71) |
| 30 | credential proofs (recursion AIR's `p2`) | reserved, unchanged | 106 / 62 (62.52) |
| 31 | segments, Poseidon2-M31 (was 26) | admitted | 108 / 62 (62.79) |
| 32 | leaves and folds (was 27) | reserved | 108 / 63 (63.37) |
| 33 | segments, Blake2s, legacy encodings (was 24); `PROOF_FORMAT_VERSION` | admitted | MOBILE: 96 / 57 (57.49) |
| 34 | device proofs (was 29) | reserved | 106 / 62 (62.13) |
| 24, 25, 26, 27, 29 | retired | refused | — |

- 5.3's parameters (2/44/20/1/0/8 inner, 1/86/20/1/0/8 device, the wrap's)
  and floors are unchanged, and each entry's rounded counts are too. The
  segment reference shape, recomputed from the AIR: 9,047 sampled values
  (was 14,102), 5,169 constraints (6,650), 1,553,989,632 logup fractions
  at 2^20 (2,445,279,232), 97,124,352 at 2^16; relations still up to 265
  limbs. 86 is still the least device query count that clears 62.

### The width

The full shape [measured] (every chip, mask `0x1ffffff`, from the AIR's
trace sizes, the method that gave 7,556 at 5.5): **8,039 columns**, 185
preprocessed, 4,882 main, 2,964 interaction, 8 composition; arith +290,
blake +151 and cpu +42 over 5.5's 7,556. It still fits a kernel leaf's
~9,300-column headroom [model].

### Gates

[measured, on this machine, each under `systemd-run` at 16 GiB with
`nice -n 10` and `CARGO_INCREMENTAL=0`]: `just check` green, 1,005 tests
(`tree_crash` among them, green); `just test-proof` green, 541 tests;
`just test-bench-proof` green; `just clippy` clean. Every gate test of 5.5
and the three tracks green on the merged tip: `arith_gate` 12,
`phase2_alu` 115, `blake2b_gate` 9, `memory_root_boundary_gate` 1,
`host_verify_boundary_gate` 1, `memory_ledger_padding_gate` 2,
`cpu_soundness_gate` 14, `register_ledger_gate` 3, `page_permission_gate`
3, `cpu_completeness` 6, `control_flow_negative` 25,
`operand_binding_gate` 12, `memory_ledger_gate` 2, `jump_table_gate` 1,
`witness_input` 13, `witness_input_gate` 11.

## Step 5.7: the items carried from slice 4

### Per-target limits (the owner's decision)

**Built:**
- **An agent runs on one target,** VOS or JAM (`cap::Target`): an
  agent runs on one host, so every instance installed into it takes its
  target. Its first install records it (`keys::target`); a later install
  naming another is refused, `Failure::Target` (13), and a JAM builder
  takes installs for JAM alone (`Error::Target`), as the agent refined
  from a witness does itself, its first install included, its refusal's
  detail JAM. `Admin::Install` and the
  `Installed` record name it; a workflow keeps it in its record (format
  5). The agent and the model hold every instance to the target's
  `cap::Limits` on every host, so a builder's simulation, the JAM refine
  and a VOS node replaying the batch agree. A refused install's detail
  is a `cap::Refused`, naming the limit and the figure, which the
  operator's CLI prints. An install now reads applied state, the
  agent's target: a host serving none traps on it, as on a request.
- **JAM's limits** (`cap::JAM`), each within VOS's (asserted):

  | | VOS | JAM |
  |---|---|---|
  | A step's writes | 256 KiB, rows by gas (about 3,125) | 16 KiB in at most 128 rows |
  | Messages, each's arguments | 16, 64 KiB | 8, 2 KiB |
  | Attests, each's arguments and output | 16, 64 KiB | 8, 2 KiB |
  | Pages a workflow's program may write | 4,096 | 256 |
  | Pages a step writes, pages held | 8 MiB, 576 | 256 KiB, 64 |
  | Checked at install: pages, program, kernels | — , 64 MiB, 1,024 | 256 (the whole heap), 512 KiB, 32 |
  | A kernel's gas | the caller's | the least of the caller's, its method's and 2,457,600 (4,096 compressions at 600) |

- **Derived from slice 4's budgets** (model, `vos_jam::gas::effects`): at
  VOS's caps a step's effects take up to about 1.40e9 gas of a package's
  own work, past PolkaJam's 1e9; at JAM's, 39.4M, 35.6 times fewer.
  `WORST_JAM_STEP`, a step restoring, storing and dropping every page a
  JAM workflow holds and ending it, with its effects at their limits, is
  839M of the 950M usable, asserted at compile time. The worst VOS
  ending with its effects is about 2.31e9.
- **`#[attestable(gas = N)]`** declares a kernel's gas. On JAM a kernel
  runs within the least of the caller's gas, the declared gas and
  2,457,600 (`Limits::kernel_gas`), what 4,096 compressions, each served
  in software (`PRECOMPILE_SERVING`), pay for; one declaring none takes
  2,457,600, and one declaring more is refused at install, by the agent
  (`Refused::KernelGas`) and, naming the method, by `vos_jam`'s
  derivation. The least holds even were an attesting instance's target
  another than the step's.
- **An attest is served apart** from the inlined frame a nested call
  takes a level (`Invocation::attest`, `#[inline(never)]`): computing its
  kernel's gas inline grew that frame past what 63 levels of the agent's
  stack hold.
- **One page price everywhere,** unchanged: the limits cap a step and
  never price it.
- **The JAM testnet** installs its actors for JAM, the shop built with
  the default heap (`lean`). So do the paired JAM tests, now for JAM
  throughout; those that drove VOS's caps on JAM drive JAM's: the
  budget lowered by four steps of 120 distinct puts, the ending at 56 of
  JAM's 64 pages beside 32 such steps (7 fit), the segments by 64
  computations of 48 pages, and an upgrade to the shop with a 640 KiB
  heap (`compact`).

**Tests:**
- at the edge of each JAM effect limit and one past it (messages, rows,
  bytes written; attests, 8 against 9, their arguments and their output,
  2 KiB against 2 KiB and a byte): `Cap` for JAM alone, on a VOS node and
  on the JAM-only host, as the model;
- a kernel past its declared 50,000 gas fails the step `OutOfGas` on JAM,
  and runs on VOS;
- installs past JAM's static limits are refused, `Cap`, each with its
  `Refused` detail and no record written: the pages (the shop's 4 MiB
  heap), the kernels (33), the program's bytes (640 KiB of data), and an
  attestable declaring 3,000,000 gas; the ledger, its attestable
  declaring none, and the default-heap shop install;
- an install for another target than its agent's is refused, `Target`;
  a refused first install records none;
- the builder refuses an install for VOS, its store untouched;
- a JAM workflow past its step's pages, and past its held pages, fails
  `Cap`; the same for VOS pauses;
- derived kernels run for both targets on both hosts, as the model;
- a compile-fail case: `#[attestable]` takes no role;
- `the_jam_limits_fit_a_package` prints and checks the figures above.

### DA: a waiting workflow's pages

**Chosen: the deterministic failure.** The core model (§12) and slice
4's F2 left re-export or failure open. Failing is a rule the agent
keeps, the same on every host and checkable on chain, where re-export
is a duty of the builder's, and a workflow whose builder was away past
retention would wait for good.

**Built:**
- JAM keeps a workflow's pages 27 days (`cap::JAM_PAGES_KEPT`): the
  imports DA, the D³L, keeps an exported segment at least 28 days (672
  epochs) after the report of the package that exported it (Gray Paper
  0.8.0, §14.3.1, and §16 for assurers), less a day's margin for a report
  before its batch time and a resuming refine after it, each by at most
  the session skew and a few slots. A workflow's record keeps the batch
  time from which every page it holds has been stored
  (`Workflow::stored`): its start's, then that of a step after which it
  holds no page an earlier step stored. A conservative bound, by one time per record,
  never a page's own.
- A step due at or past `stored` plus the keep, while the workflow
  holds pages, ends it `Failure::Expired` (12) without restoring or
  importing them, its pages dropped and its owner told.
- The builder no longer leaves such a workflow out of a sweep; one whose
  pages DA lacks within the keep still waits.

**Tests:** a JAM workflow resumed just within the keep and one just past
it, on both hosts, as the model; the builder over the emulated chain,
DA emptied: the workflow left out within the keep, then ended
`Expired` past it in a package that imports nothing.

### A heap per kind of invocation

**Built:**
- The SDK's arena is a section of its own, `.vos_heap`, which the
  guest's linker script places last in the read-write data, its state
  apart. The allocator bumps fresh memory from the arena's start.
- **The derivation** (transpiler version 2) holds the arena's first 512
  KiB (`INVOCATION_HEAP`) in the actor's program and in each kernel, all
  a handler or a kernel maps, and records the pages past them,
  `Derivation::heap`. An ELF whose arena does not end its read-write data
  from a page is refused (`DeriveError::Heap`), no longer derived whole.
- **One constant:** `vos_wire::abi::INVOCATION_HEAP`, which the
  compiler's `INVOCATION_HEAP` and the SDK's default heap,
  `PROGRAM_HEAP`, both are.
- **The allocator knows the invocation:** in an actor's program
  (`Heap`'s const parameter `ACTOR`) it gives a handler or a kernel the arena's first 512
  KiB alone, so an allocation past them fails at once, Rust's
  allocation-failure path, and the step traps, `Trapped`, whether or not
  the memory would be touched; before, it bumped into pages the program
  does not map, and only a store there faulted. A workflow's dispatch
  arm marks the invocation first (`heap::whole_arena`), its snapshot
  keeping the mark, and it allocates from the whole arena. The agent's
  own heap and other programs' (`program_runtime!` alone) are whole.
- **A workflow's machine** maps those pages itself past its program's
  read-write data, zeroed, and arms them with its writable pages: its
  record's `writable` counts them, so `ARM_PAGE` pays for them.
- **A kernel's layout** is its program's alone, the same whatever heap
  its actor declares. The pinned fixture is now the kernels actor built
  with a 4 MiB heap (`roomy`): 896 pages left out.
- On JAM a handler of the 4 MiB shop now maps 512 KiB, not 4 MiB (model:
  about 15,000 gas of loading a call, not about 124,000).

**Tests:**
- a kernel's layout and its handlers' program equal across the kernels
  actor built with the default heap and with 4 MiB;
- the actor's program is `link_elf_spi`'s but for the heap pages it
  leaves out, which are exactly the arena's past 512 KiB;
- a workflow computing over 1 MiB on the derived shop runs to its end
  beside a handler, on both hosts, as the model maps the same pages;
- a handler of an actor with a 2 MiB heap (`ample`) reserving 1 MiB it
  never touches traps, and reserving 256 KiB runs, as the model; a
  workflow reserving 1 MiB runs to its end; the allocator's own test, an
  actor's heap against a program's;
- an arena moved off its page, and another writable section named
  `.vos_heap`, are refused;
- the derivation the same in every process; the pins.

### Measurements

Measured with the processes bench (`ROWS=resume` and `ROWS=catch-up`),
on the reference laptop's pinning, on this step's code (92337a67), so
after 5373e6cf changed how a workflow is restored: its machine maps the
heap its program leaves out. Under `nice -n 10` and a 16 GiB scope, on a
quiet machine, load 0.4–2.9. The leader runs in the bench's process, so
it can deliver replies itself as the one-node bench does; its followers
are `vos node run` processes over QUIC. A first pass, on the slice's
base (b7c4fd69) and so before 5373e6cf, gave the same figures within
their spread (medians 1.77–1.92 ms on three nodes, 1.25–1.30 ms alone;
catch-up past the tail 2.24–2.55 s).

| A workflow's resume, a reply in to its step applied | Median | p99 |
|---|---|---|
| Three nodes, synced commits on NVMe (4 runs) | 1.73–1.79 ms | 2.55–3.34 ms |
| Node 1 alone, the same runs | 1.18–1.22 ms | 1.95–2.80 ms |
| Three nodes, stores on tmpfs (2 runs) | 0.91–0.98 ms | 1.80–1.88 ms |
| Node 1 alone, tmpfs | 0.70–0.71 ms | 1.02–1.27 ms |

- 603 resumes a row. Replication adds about 0.45 ms to the commit on
  disk (925–966 µs against 481–514 µs): the QUIC round trip and the
  follower's synced flush beside the leader's own. The step's refine,
  restoring the workflow, takes 0.47–0.59 ms; queueing, proposing and
  applying about 0.15 ms.

| A follower's catch-up (4 runs) | Within the kept tail | Beyond it |
|---|---|---|
| Missed while down | 40 fills, 9.6 MB of results in 5 entries | 224–232 fills, 54–56 MB in 28–29 entries |
| Names its leader | 0.22–0.27 s | 0.58–0.61 s |
| Has applied the leader's commit | 0.92–0.96 s, from the log | 2.32–2.35 s, from a snapshot |

- **The settings** (`vos_node::Config`): compaction once 1,024 entries
  or 64 MiB, a large result counted by its blob, are applied durably; a
  kept tail of at most 256 entries and 16 MiB; snapshot chunks of 1
  MiB; a result of 64 KiB or more stored as a blob.
- The kept tail held 9–10 results of about 1.9 MB (measured), so 4.4c's
  "4 to 8" was for results of 2–4 MB.
- The snapshot carried 402–410 rows, 0.25 MB: the agent's state, not
  the log missed. About 1.7 s of the catch-up passes between naming the
  leader and installing it, which fits a stream begun while the follower
  was down, resent every 2 s (`CHUNK_RESEND`) (model, from the code).

### Ristretto ids 110–114

Already so: `derive` refuses a kernel reaching any host call but a
precompile, and these are none. A test now pins it for each of the five
ids, beside BLAKE2b's precompile, which derives. Since removed, chips and
ids (step 5.5's last section).

### PolkaJam

- **The re-probe** (`nightly-2026-10-13`, still the installed version:
  polkajam and jamt 0.1.29, Gray Paper 0.8.0, the same sha256): on the
  interpreter every record PolkaJam produces is unchanged, gas included
  (fault tracking, counters, segments by `wp:` and `sr:`, the 14
  starved and re-entry records, `solicit` and `historical_lookup`); the
  availability race and late `wp:` imports dropping recur. Our JAM-only
  host now agrees on 34 of the 36 fault records; `fetch` kind 0 still
  differs. Results in `spikes/sj-jam-b/results/2026-10-16-*`; `probe.sh`
  takes the backend from `POLKAVM_BACKEND`.
- **The recompiler run still waits.** `vm.unprivileged_userfaultfd` is
  1 now, but PolkaVM's sandbox reads every CPU's L3 cache entry, and
  this machine's two low-power cores have none: every node fails at
  start, and neither core pinning off nor CPU affinity helps. It needs a
  PolkaJam build that tolerates them, or another machine. Kernel
  settings were not touched.
- **The testnet on the interpreter, with this step's code** (`just
  jam-testnet`): the agent and its actors installed for JAM, the
  workflow across three later packages (70 pages exported, 104
  imported), every package landed at its first attempt, each work result
  read back from DA equal to the simulation's and the VOS node's, the
  testnet logging no error. Refines 0.26M–41.9M gas each (measured, on
  our JAM-only host).

### Also

- **A cluster test's flake, fixed:** under load the compaction test's
  leader moved while it sent its fifty increments; each is now sent
  again at its sequence to whichever node leads, waiting 10 ms before the
  first retry and twice as long before each next, to 500 ms, so an
  election has time to end.

**Gates:** `just check` on each commit, 995 tests at the last; the node suites at the end: cluster and processes in it, the faults process tests and the five-process fault suite.

## M0 acceptance

**On the M0 code (30e78b53, plus the jar-check fix 36eac7cf).** The
measurements ran on an Intel Core Ultra 7 155H, load average 2–3, each
under `systemd-run` at 16 GiB with `nice -n 10` and `CARGO_INCREMENTAL=0`.

### What M0 delivered

| step | what | commits |
|---|---|---|
| 5.1 | Stwo from the owner's fork, olanod/stwo `vos/base` at `bbfa8bc3`, pushed: upstream `e1286720`, dashmap optional, Poseidon252 gated, and `74951f79` backported, so a preprocessed tree below the lifting height verifies. The verifier builds for `thumbv7em-none-eabihf` and wasm32 | 219894f1; the spikes' verifier fixes before it, ce72c226, 824a5f8a, b5d42dc2 |
| 5.2 | The reference Poseidon2 with Plonky3's parameters, and a packed hasher (AVX2, AVX-512F, NEON, scalar fallback) | cc10f755..37749667 (gate log e1c58e38, decision 19af5408) |
| 5.3 | The format registry, run-time selection, lossless encodings, the interaction PoW and both bit counts | 91f832df, 857bc752; reviews 1ab715cc..dbf6da1d |
| 5.5 | The witness input `0x401`, the run's ends, the io-hash; the operand binding; the Ristretto chips and ids removed | d543de94, bd4a4818, dce17dd3; 505af543..3fae02d0; ee6a1235..0dc9ba45 |
| 5.5b | The AIR audit's holes closed on three tracks (ARITH, BLAKE, CPU with page permissions), merged; the re-audit's fixes | 3f39145c..80c77822; fa2f2c43..02ae6255 |
| 5.4 | A shape per kernel: derive's shape in the install's record, shaped proving, the exact-set verifier, the kernel chain, the program id | 82abccbe..30e78b53 (the spike moved to `spike/s5-shape` by 0179ccca) |
| 5.7 | Targets per agent with JAM's limits, DA's 27 days, a heap per kind of invocation, resume and catch-up measured, PolkaJam re-probed, Ristretto ids refused | 09bbafc0..a49f1bfc |

5.6, the phone run, waits on the owner's team.

### Gates

- **`just ci-full` green, 1,860 s:** 139 test binaries, 1,720 tests.
  - `ci`: 87 binaries, 1,141 tests, 922 s.
  - `test-proof`: 50 binaries, 577 tests, 913 s. It covers formats 31
    and 33, the soundness gates and the settlement verifier on the PVM.
  - `test-bench-proof`: 2 tests, 25 s.
- **The checker loop with workflows:** seeds 601–612 across the three
  exactly-once tests. All 36 runs green, 919 s. 2,892 tours, none
  failed, across 24 leader stops mid-await and 23 mid-computation.
- **Failed first, and fixed:** `jar-check` (in `ci`) failed on the first
  run. Its patterns `kernel::` and `\b0x800\b` were meant for JAR's
  `vos_pvm::kernel` and its CSR 0x800 marker. They also matched the proof
  crate's `kernel` module (5.5) and derive's `(value + 0x800) >> 12`
  rounding. So the gate had failed on every tree since 5.5: real, not a
  flake. The patterns now name `vos_pvm::kernel::`, `InvocationKernel` and
  the CSR forms of 0x800, and still match every remnant in the pre-port
  tree (36eac7cf). The rerun above is on that fix.

### Measured

**Segment proving, format 31 against 33, at the 32k cut.** The window
kernel (`n1000000-j8`, 404,091 steps) was proved over its shape, 23 chips,
cut at class 1 into 17 segments: 15 at class 1, 2 at class 0. Each
segment was then proved alone on 31 and on 33 in turn, on 8 threads, two
rounds [measured]:

| | format 31, Poseidon2-M31 (2/44/20, interaction PoW 8) | format 33, Blake2s (MOBILE: 2/38/20) | 31 against 33 |
|---|---|---|---|
| a class-1 segment (2^15 steps), 30 proofs each | 6.59–7.17 s, median 6.79 s | 3.63–3.90 s, median 3.76 s | 1.68–1.91×, median 1.80× |
| a class-0 segment (2^12 steps), 4 proofs each | 3.47–3.67 s | 2.07–2.12 s | 1.7× |
| the 17 segments, one by one | 108.4 s | 60.4 s | 1.80× |
| prover memory, a class-1 segment | 5.6 GiB over a 0.35 GiB base (peak RSS 6.0 GiB) | 5.6 GiB (peak 6.0 GiB) | 1.0× |
| prover memory, a class-0 segment | 3.1–3.2 GiB | 3.1–3.2 GiB | 1.0× |
| proof, class 1 (postcard) | 1.47–2.01 MB | 1.25–1.73 MB | 1.17× |

- `prove_kernel` on 31 proved all 17 segments in 104–106 s, peak RSS
  6.4 GiB. The chain verifies natively against the kernel's program in
  1.08 s; on 33 it verifies in 0.43 s.
- **The memory column comes from a second, one-round run.** It trims the
  allocator and reads RSS before each prove. That run's times were 4–7%
  slower: 31 at 7.0–7.5 s, 33 at 4.1–4.2 s, a median of 1.74×.
- **The ratio holds 5.2's 1.75–1.85×** on the hardened AIR and the
  shape. Memory does not follow the channel: the traces and their
  extension dominate.
- Format 33 also takes six fewer queries than 31, so the comparison is
  of the two formats as registered, not of the channels at equal
  parameters.

**Verify gas over the shape on the JAM-only host.** This is spike 1's
guest and harness on the current verifier (`spike/s5-shape`'s
`guest-verify`): vos-pvm's GP 0.8.0 instruction gas, with PolkaJam's
host-call prices [measured].

| proof | gas | of which decode | instructions | native verify |
|---|---|---|---|---|
| 31, segment 4 (32k, class 1) | 3.3573B | 0.2019B | 1.215B | 55 ms |
| 31, segment 7 (32k, class 1) | 3.3594B | 0.2017B | 1.216B | 55 ms |
| 31, segment 16 (class 0) | 3.3300B | 0.2009B | 1.204B | 54 ms |
| 33, segment 4 (32k, class 1) | 1.4414B | 0.1812B | 0.352B | 15 ms |

- The guest's peak live heap is 6.3 MiB, and it writes 2,886 pages.
- These are 5.4's figures (3.3465–3.3510B) within 0.3%.
- Segments are recursed, not verified on chain (proving.md), so this is
  a bound and not a cost. The final proof's gate is 5.14's.

**The phone factor: not measured.** 5.6's run is with the owner's team.
The projected 1.0–2.6 stands until then.

**The AIR** [measured, from the AIR]:
- **25 chips, 8,039 columns in full:** 185 preprocessed, 4,882 main,
  2,964 interaction, 8 composition.
- **At 2^20 rows a chip** (the registry's segment reference shape): 5,177
  constraints, 9,047 sampled values, 1,553,989,632 logup fractions, and
  relations up to 265 limbs.
- **A derived kernel's shape** is 23 chips, every one but POPCOUNT and
  BITCOUNT, at 8,024 columns (180, 4,880, 2,956, 8) in each of its three
  classes.
- **Against the audit's 32-chip AIR:** it was 13,037 columns and 6,650
  constraints. The Ristretto removal took it to 7,556 columns; the
  hardening added 483.

**Security counts per format** [model, the registry's tool at each
format's reference shape; conjectured / proven, the unrounded proven
count, then the floors]:

| format | proofs | status | parameters (log blowup, queries, PoW, fold step, last layer, interaction PoW) | bits | floors |
|---|---|---|---|---|---|
| 31 | segments, Poseidon2-M31 | admitted | 2, 44, 20, 1, 0, 8 | 108 / 62 (62.79) | 100 / 60 |
| 32 | leaves and folds | reserved | 2, 44, 20, 1, 0, 8 | 108 / 63 (63.37) | 100 / 60 |
| 33 | segments, Blake2s, legacy | admitted | MOBILE: 2, 38, 20, 1, 0, — | 96 / 57 (57.49) | 96 / — |
| 34 | device proofs | reserved | 1, 86, 20, 1, 0, 8 | 106 / 62 (62.13) | 100 / 60 |
| 30 | credential proofs | reserved | 1, 86, 20, 1, 0, 8 | 106 / 62 (62.52) | 100 / 60 |
| 28 | the final wrap | reserved | 6, 20, 26, 3, 6, 8, affine DEEP batching | 146 / **74** (74.71) as built | 100 / 80 |

24, 25, 26, 27 and 29 are retired.

### Deviations from the plan, and their decisions

- **Poseidon2-M31 kept despite 5.2's gate.** The gate failed as written:
  proving was 1.75–1.85× Blake2s against 1.5×, and a leaf's commitment
  took 0.63 s against 0.5 s. The owner kept Poseidon2-M31 (2026-10-16),
  gated on a segment's total cost, its proof plus its leaf: about
  7.1–8.6 s against Blake2s's 7.6–9.1 s [measured plus projected]. M0
  measures 1.80× on the hardened AIR. The Blake2s fallback is dropped.
- **Ristretto removed** (the owner's decision). Its chips were unsound,
  and slice 7's bignum chip replaces them. All eight chips, eleven
  relations and ids 110–114 are gone, and derive refuses a kernel that
  reaches one. The AIR went from 32 chips to 25, and from 13,037 columns
  to 7,556.
- **The AIR audit and its hardening (5.5b), not in the plan.** Fable's
  review of 5.5 found the operand binding open. The audit that followed
  closed the G1–G4 holes and the page permissions (G2-1), each with a
  forgery gate run first on the unfixed AIR. A re-audit added more fixes
  and gates.
  The cost was 483 columns, to 8,039.
- **The inner parameters changed** in 5.3's reviews: from 39 queries,
  PoW 26 and interaction PoW 24 to 44 queries, PoW 20 and interaction
  PoW 8, for 62.79 proven bits. The grind fell from about 2.1 s to 27 ms
  [model], for about 12% more proof bytes. Devices take 86 queries.
- **The formats were renumbered.** Every number naming the pre-hardening
  AIR is retired, so that a number names one AIR: segments 26 → 31,
  leaves and folds 27 → 32, legacy 24 → 33, devices 29 → 34. 28 and 30
  are unchanged.
- **A shape per kernel saves 0.2%, not 30%.** 5.4's gate counted the
  Ristretto chips, which made up the audit's 38%. A kernel's code leaves
  out two tables, 15 columns, which saves 0.18–0.39% of verify gas. The
  shape stays for identity and the leaf: it pins every log size, which
  the program id binds and the leaf takes as constants.
- **`Attest.arguments` replaced** by `witness_input`, which carries the
  bytes the kernel read. Keeping both would have held the same bytes
  twice, and a step's attests at both caps would pass the 4 MiB result.
- **A target per agent.** The plan named the target in the install
  record. As built, an agent runs on one target, VOS or JAM, which its
  first install records; every instance takes it, and an install for
  another target is refused. JAM's limits are about 31× below VOS's, and
  a kernel's gas on JAM is capped at 2,457,600.
- **DA: a deterministic failure after 27 days.** Re-exporting a waiting
  workflow's pages was the other option. JAM keeps its pages 27 days, the
  Gray Paper's 28 less a day's margin; a step due past that ends the
  workflow `Expired`. It is a rule the agent keeps alike on every host,
  where re-export would be a builder's duty.
- **The A.6 fixture generator was not built.** The plan put it in M0's
  pipeline, to make `pvm/proof/fixtures` and regenerate them at each
  format bump; no step built it. It moves to M1's preparation, 5.8.0.

### Carried into M1

- **The leaf's rows are tight.** At 44 queries over the hardened
  shape's 8,024 columns, the kernel leaf's `p2` comes to about 64.8k of
  2^16 [model]. The ~9,300-column headroom, counted at 39 queries, is
  about 8,100 at 44. 5.11 counts it on the hardened AIR first. The plan
  carries it.
- **The wrap's 80 proven bits:** 74.71 as built. 5.14 chooses between
  affine DEEP batching (recommended), a batching-phase PoW, and blowup 8.
- **The program id's leaf-circuit hashes** (5.12). The id enters the
  `Derivation` once an install can compute the class roots, which today
  need the prover.
- **Pinning costs prover time.** The ALU chips pad to the class's steps,
  and WITNESS_INPUT pads to 2^16 in every segment. Narrower capacities,
  or WITNESS_INPUT in the entry class alone, are open.
- **Recorded, unfixed:**
  - C-DJUMP, an invalid dynamic jump that cannot be proved; no kernel
    needs it.
  - The ledgers' 2^27-step idle limit.
  - A BLAKE2b pointer within 256 bytes of 2^32 that cannot be proved.
  - Refine slices' page permissions, bound by replay and not in the AIR.
- **AVX-512F** is compiled but not run on this machine.
- **For the owner:**
  - 5.6, the phone run;
  - PolkaJam's recompiler run, which needs a build that tolerates cores
    without L3, or another machine.
- **M0's closing:** the Opus milestone review, folded below; then a
  push.

### The milestone review

Opus's review of M0, on `e021f40c`, found nine items: four stale docs,
fixed, and five pieces of preparation, which open M1.

- **Fixed in the docs** (items 1–3 and 8):
  - `proving.md` A.4, rewritten from the registry: 31 segments, 32
    leaves and folds, 33 legacy Blake2s, 34 devices, 28 the wrap, 30
    credentials; 24–27 and 29 retired. A.5's `Attest` is
    `{program, witness_input, output}`;
  - the leaf headroom, in `proving.md` and `recursion-air.md`: about
    8,100 columns at 44 queries, not 9,300 at 39; the kernel leaf's `p2`
    about 64.8k of 2^16, about 1% spare [model]; the levers, fewer
    queries with more PoW, FRI fold step 3 in inner proofs, or `p2` at
    2^17;
  - 5.9's gate and 5.11's per-term pin: `count.log` predates the
    hardening, so 5.9 re-runs the gate-count crate on the hardened AIR
    first;
  - `pvm/proof/SECURITY.md` (the memory roots bound; the refine bundle
    v4, its children format 33), `memory-merkle-binding.md` (Ristretto's
    removal), `proving.md` §3.2 (page permissions preprocessed, part of
    the program's identity), and 5.10's citation
    (`boundary_binding.rs:147-205`).
- **Moved to 5.8.0** (items 4–7 and 9): the window kernel on the line,
  the fixture generator, one no_std Poseidon2 crate, one transcript
  prefix, one page tree, `add_constraints` split by instruction class,
  and the inner parameters' recount with its decision rule. The review's
  smaller code-quality items wait for 5.16.

## 5.8.0 (A): the window kernel on the line, and the fixture generator

### The window kernel

- **The route: the plan's, not the fallback.** `agent/test-actors/window`
  builds for the guest target on cipher-clerk v0.3.0 (codeberg, tag
  `v0.3.0`) with `settlement` and without `pvm-precompile`, and derive
  takes its kernel: dalek compiles in, and the kernel reaches no id
  110–114. No shim, harness or patched workspace from the spike.
- **The kernel** (`settle`): each row's account decoded, its key
  `keys::hashed(id)`, its commitments `value_hash(salt, value)` at both
  anchors; the rows in key order; each anchor's `vos_tree::BatchProof`
  checked against its root; then `cipher_clerk::settlement::window`. A row
  absent at the first anchor is claimed absent there and counts from zero.
  The output is a status byte, then the `NetFlow`'s encoding.
- **The multiproof check is streamed** (`vos_tree::verify_encoded`,
  `agent/tree/src/encoded.rs`): the proof's encoding read once, nodes
  hashed bottom-up on a stack of open branches, the claims split at each
  branch by their bit at its level, as `BatchProof::generate` splits the
  keys it proves, and each claim judged where its path ends. It gives
  `BatchProof::verify`'s judgment and error on the decoded bytes, in
  either direction. A branch's hash is `Hasher::branch`, whose default is
  the tagged hash and which `Blake2b` computes as one block of words
  handed to the compression precompile (`blake2b_compress_words`, the
  precompile crate's IV). `vos_tree::BatchProof::verify` was the first
  try, and the kernel took 1,335,487 steps and 126 segments [measured]:
  decoding the proofs into entries (173k steps) and building the pruned
  tree (869k) touch so many heap pages that the page budget closed 61
  segments at class 0, and proving took 1,222 s. Streaming with
  vos-tree's byte-oriented hashes: 938,177 steps; with the branch hash
  on words: 654,338; in vos-tree, with the claims split: 632,800.
- **The arguments** (`pvm/proof/tests/window_kernel.rs`): spike 3's
  instance rebuilt in the test, a map of 1,000,000 rows at two versions
  with eight journals' pseudo-account pairs, journal 0's incoming account
  opened inside the window, so absent at the first anchor. The rows are
  `Vec<Row>`, the proofs each `BatchProof`'s encoding as bytes. Building
  the map takes about 3 s with vos-tree and the BLAKE2b fallback at
  `opt-level = 3` in the dev and test profiles (root `Cargo.toml`).
- **Tests** (`test-proof`): the window runs live on the agent's
  reference model to the statement `window` gives natively, re-runs from
  its attest to the same output, proves over its shape cut at class 1,
  and verifies as a chain against its program, its io-hash the run's
  (`the_window_proves_and_verifies_over_its_shape`); a value the second
  root does not commit, and a row claimed absent at the first anchor that
  is present there, are refused (`rows_off_the_roots_are_refused`); a
  tampered or truncated proof at either anchor, rows out of key order, a
  value that does not decode and a window `window` refuses
  (`WINDOW + SameSpace`) are refused (`bad_proofs_and_rows_are_refused`);
  and claims whose paths end out of their keys' order are accepted
  (`claims_ending_out_of_key_order_are_accepted`). The proving test also
  checks the io-hash against `compute_io_hash(&[], output, &[])`.

### Measured

The window, eight journals, format 31, on the shared Intel Core Ultra 7
155H (load average 10–14) [measured]:
- **The run:** 632,800 steps (spike: 404,091), 651 compressions, a
  25,989-byte witness input, a 69,101-byte kernel. Without the
  precompile feature, `window`'s `PseudoAccount::of` hashes in software:
  about 176k steps of the run, measured on the first try's kernel
  without the `window` call.
- **The shape:** 23 of 25 chips (`0x1f9ffff`, every chip but POPCOUNT
  and BITCOUNT), the classes derive's: class 0 (2^12 steps, 8 pages),
  1 (2^15, 8), 2 (2^12, 24).
- **The segments:** 26, cut at class 1: the entry's 165-step segment and
  the last two at class 0, the other 23 at class 1; 16 of those are full
  32,768-step windows, and the page budget closes seven early (6.1k–24.2k
  steps), all in the run's first 167k steps.
- **Proving:** 26 segments in 394 s, peak RSS 7.1 GiB, under A.7's
  24 GiB; the chain verifies natively in 3.7 s. (Before the review: 27
  segments in 291 s and 7.0 s, the machine less loaded.)

### The review

- **A completeness bug in the kernel's own check, fixed.** It matched
  claims in key order, but a proof's leaves come in the order its paths
  end: an absent key that differs from a subtree at a bit no branch
  splits on ends on the side its later bits pick, so a smaller key can
  end to the right. A tree of 0x80 and 0x81 with 0x01 and 0x40 claimed
  absent: vos-tree accepted, the kernel refused. The review's
  differential over 200k cases found about 1% wrong refusals and no
  wrong acceptances. `verify_encoded` splits the claims at each branch
  instead, and the kernel's copy (`window/src/batch.rs`) is gone: one
  implementation, in vos-tree.
- **Agreement, both ways:** `the_streamed_check_is_the_decoded_one`
  (`agent/tree/tests/tree/encoded.rs`, 4,096 cases) compares
  `verify_encoded` with decoding and `BatchProof::verify` over random
  trees of row keys and of one- and two-byte keys, claims present,
  absent, repeated, in any order and about bad keys, and tamperings of
  the entries, the bytes (a bit, a cut, a byte more), the claims, the
  root and the keys proved: equal results, errors included. With the
  split removed it fails at once. The inversion case is a unit test
  there, and a kernel test on a three-row map.
- **Errors:** a refused claim's error is reported only once the proof is
  well formed and rebuilds the root, and it is the first refused claim's
  in the claims' order, as `BatchProof::verify` reports it. The split is
  unstable within each side: the claim's index, not its place, picks the
  error.
- **The window statement is rootless at the io-hash level.** Its kernel
  has no public arguments and reads no root through the SDK, so its
  io-hash is `compute_io_hash(&[], output, &[])`: the anchors' roots are
  bound only through `NetFlow`'s fields in the output (`anchor_i`,
  `anchor_j`), which the kernel checked the proofs against. Public
  arguments and roots in the io-hash wait for the SDK's support, 5.15.

### The fixture generator (A.6)

- **`pvm/proof/tests/fixtures.rs`** generates, for each admitted segment
  format, 31 and 33, a fixed small kernel's run (two constants, their
  product and sum, a halt) proved as one class 0 segment of its program,
  into `pvm/proof/fixtures`:
  - `segment-<n>.proof`, which verifies against `segment-<n>.root` and
    as the kernel's segment;
  - `segment-<n>-tampered.patch`, one out-of-domain sample of the main
    trace changed, refused;
  - `segment-<n>-wrong-format.patch`, the proof under the other format's
    number, refused before any cryptographic check (its channel is not
    the number's).
- **The refused proofs are patches** of the valid proof's bytes (offset,
  bytes removed, bytes inserted): the full files came to 5.6 MB, the
  valid proofs alone to 1.87 MB (1,012,413 bytes at 31, 856,513 at 33).
  A venue applies the patch and judges the bytes.
- **Staleness:** `the_fixtures_are_the_generators` makes every fixture
  again and compares bytes; a difference fails, naming the files and
  `just fixtures`, which writes them anew (`VOS_FIXTURES=write`). Proving
  is deterministic: two runs wrote the same bytes.
  `the_fixtures_are_judged` reads the files and judges them as a venue
  does.
- 5.15 adds A.6's statement fixtures once the wrap exists.

### Gates

[measured, each under `systemd-run` with `nice -n 10` and
`CARGO_INCREMENTAL=0`]: `just check` green at 14 GiB, 1,005 tests; `just
test-proof` green at 24 GiB, 581 tests (`window_kernel` 2, `fixtures` 2),
27 minutes; `just clippy` clean.

After the review [measured, the same way, at 14 GiB]: `just check`
green, 1,010 tests; `test-proof`'s suites with one test thread green,
583 tests (`window_kernel` 4), 29 minutes; clippy clean on vos-tree, the
precompile crate and vos-pvm-proof with `debug-internals`; the vos-tree
proptest, 4,096 cases, green.

### Outside the track's files

- Root `Cargo.toml`: `cipher-clerk` in the workspace's dependencies, and
  `opt-level = 3` for vos-tree and vos-pvm-precompiles in the dev and test
  profiles.
- `pvm/proof/tests/common/mod.rs`: `kernel_program`, a kernel's program
  from its blob and its install's record.
- `agent/tree`: `verify_encoded` (`src/encoded.rs`), `Hasher::branch`
  with `Blake2b`'s word form (`src/hash.rs`), and their tests
  (`tests/tree/encoded.rs`).
- `pvm/proof/precompiles`: `BLAKE2B_IV` public, and
  `blake2b_compress_words`, the compression on words.

## Step 5.8.0 (B): the refactors

Track B of M1's preparation, on `s5-prep-b` from `5e29355d`. Four
refactors, a commit each; none changes a constraint.

### The check

- **Proof bytes** [measured]: a scratch harness proves 17 proofs and
  hashes each (SHA-256 of its bincode): a hand-built seven-step program
  and the bench guests `diverse`, `hash-software` and `hash-precompile`,
  each under format 31 and format 33, natural and canonical shapes, and
  the hand-built program under `prove`'s standard config. Proving is
  deterministic (two baseline runs match). After each refactor the 17
  hashes match the baseline's.

### One Poseidon2 crate

- **`vos-pvm-poseidon2`** (`pvm/proof/poseidon2`), beside `precompiles` and
  `verifier`, where `recair-air` and `final-verifier` will sit. no_std,
  no dependencies, no allocation, stable Rust:
  - its own M31, the permutation and its parameters, the linear layers
    generic over the word (for `recair-air`'s bodies), the leaf sponge,
    the node compression, and the transcript duplex with an `Observer`
    for the prover's recorder;
  - the packed SIMD permutation behind the `packed` feature, which the
    prover turns on: the verifier path never compiles it, and the crate
    builds and tests on stable with and without it;
  - the round-constant generator test is the crate's
    (`tests/round_constants.rs`).
- **The prover and the settlement verifier** keep only the Stwo
  adapters: `P2Hash`, the hasher, the channel and the Merkle channel,
  since Stwo's traits cannot be implemented in a crate without Stwo. The settlement verifier's copy of the permutation,
  constants, sponge and channel goes.
- **The PVM settlement verify** [measured], `settle_run`: 11,011,239
  instructions and 27,347,708 gas, against 10,951,979 and 27,306,959
  before (+0.5%, +0.15%). The crate's field matches Stwo's reductions
  form for form; a first version with branches and a reducing internal
  diagonal cost +26% gas.
- **A Stwo word enters reduced:** the adapters map a word through
  `M31::from(u32)`, so a non-canonical limb in a proof cannot panic the
  verifier.

### One transcript prefix

- `verify.rs`'s `transcript_prefix` replays the statement header, the
  preprocessed and main roots, the boundary states and the interaction
  PoW, the relation elements, the claimed sums and the interaction root.
  `verify_on` and the recursion seams call it; the seams' copy goes.
- **Every proof mixes its boundary states,** as production does: the
  seams no longer gate the mix on a side note's `closing_chip_active`,
  and chip-isolated harnesses (`prove_with_explicit_components`) mix
  them and grind the interaction PoW too. So the seams take the proof
  alone. Production proofs are unchanged; chip-isolated proofs, which no
  verifier accepts across a trust boundary, change.
- The preprocessed-root check, the logup sum and the boundary binding
  run around the prefix; none touches the transcript.
- `recursion_seams`' test names format 31.
- The prefix now lives in `vos_pvm_proof::proof::transcript` as
  `replay_prefix` (no_std), which the standalone verifier replays too;
  see the review below. A.1's in-AIR transcript should follow it.

### One page tree

- `page_merkle` takes its tags, leaf and node from
  `vos_pvm_program::image` (whose tags are now public) and asserts the
  two depths equal; its own copies and the comment on formats 10 to 21
  go. Refine's commitments hash with `vos_pvm_precompiles::blake2b_256`,
  the function the image tree uses, in place of `page_merkle`'s
  BLAKE2b-256.

### The CPU split

- `add_constraints`' 3,560 lines become 56 functions in 12 modules under
  `chips/cpu/constraints`, by instruction class; `add_constraints` calls
  them in the body's order. Each function reads the columns it uses
  (`trace_eval!` is a pure read); IsBranch, IsStore and IsCompare are
  functions of the row; the relation elements travel in a `Lookups`
  struct. `cpu/mod.rs` falls to 246 lines; the split totals about 4,100,
  the column reads each function repeats.
- The split was generated from the body's top-level statements, each
  function's reads drawn from the definitions it uses, then checked by
  proof bytes. A first version called the functions in module order and
  failed with `ConstraintsNotSatisfied`: the interaction trace pairs the
  relation entries in the body's order.

### The review folded

- **The closing flag's docs:** `closing_chip_active` gates the closing
  chip's rows, the register ledger's closing reads and the `final_regs`
  backfill, not the boundary mix, which every proof has. `verify` reads
  only the side note's program and the component set its steps select;
  its precondition that a re-derived side note be normalized goes
  [measured: an honest proof verifies against a side note with the flag
  cleared].
- **`host_verify_boundary_gate` kept, rewritten:** a forger can no
  longer prove "without the mix". It now checks the flag has no say in
  verification: an honest proof verifies under a cleared flag; final
  registers edited after proving are refused; a proof made with the
  flag cleared, its closing chip empty, is refused against either side
  note, edited or not. Not redundant: `boundary_binding.rs` keeps the
  columns honest and lies in the metadata, and nothing else proves an
  empty closing chip under the production mask. Every refusal is the
  boundary binding's [measured]: an edit after proving changes the
  drawn relation elements, so the recomputed claimed sums miss.
- **One prefix, really:** `replay_prefix<MC>(proof, stark, format,
  log_sizes, channel, commitment_scheme, draw)` runs the header, the two
  roots, the boundary states, the interaction PoW, `draw` for the
  relation elements, the claimed sums and the interaction root, and
  returns the elements. `verify.rs` draws through its components,
  `verify_standalone_on` through `draw_all_lookup_elements(mask)`; both
  build their components after it. The standalone verifier's checks
  keep their order. The 17 proof hashes match; the verifier's suite
  passes.
- **The settlement verifier refuses a noncanonical limb:**
  `proof_fields_are_canonical`'s walk over a Stark proof becomes the
  public `proof::stark_fields_are_canonical(stark, hash_is_canonical)`,
  and `verify_settlement_proof` calls it after decoding, so
  `vos-pvm-proof` (no default features) moves from its dev- to its
  dependencies. Before, the fixture with one queried value raised by
  the modulus verified [measured]: a second encoding of the same proof.
  The test raises a queried value, a sampled value, a FRI witness and a
  Merkle witness hash. `settle_run` [measured]: 11,028,468 instructions
  and 27,500,314 gas, against 11,011,239 and 27,347,708 (+0.16%,
  +0.56%); the ELF grows from 487,864 to 497,856 bytes.
- **`vos-poseidon2` is `vos-pvm-poseidon2`,** as its siblings.

### Left for 5.16

- **A typed row:** an `AirColumn` derive that generates a `Row<E>` view,
  each column a field read once, would replace the column reads each
  split function repeats, about 600 lines of the split's 4,100.
- **The split's carried names and comments:** the `_p19` and `_p54`
  suffixes on its locals (`f_ff_p19`, `sign_bit_result_p19`,
  `tuple_p54`, `f_is_mul_p54` and their kin), and the comments that say
  "now" or "for now" (`compare.rs`, `control.rs`, `divrem.rs`), come
  from the body before the split and need renaming and rewording.

### Gates

- `just check`: green, 1,019 tests, after the review as before.
- `just test-proof`: green, 566 tests, the settlement verifier's among
  them; 567 after the review, with the noncanonical-limb test.
- `just clippy`: green.
- `vos-pvm-poseidon2` on stable (1.96), with and without `packed`: builds and
  its 14 tests pass.

## Step 5.8: the gate VM

`recursion-air.md` §10's step 1, on `vos-core` from `4ae3cee6`.

### The crates

- **`vos-recair-air`** (`pvm/proof/recair-air`), no_std, on Stwo's
  verifier path and `vos-pvm-poseidon2`, with no prover dependency:
  - `p2`: one Poseidon2-M31 permutation a row, in `vos-pvm-poseidon2`'s
    reference arrangement (the external matrix first, 4 + 14 + 4 rounds),
    the S-box as `a = y²`, `out = a²·y`; the seven modes of §1.3, the last
    round's S-box outputs read at offset −1, the previous row's output the
    external matrix over them. 33 preprocessed, 309 main and 12
    interaction columns, 303 constraints, as §1.2 counted;
  - `qm31` (17, 16, 8; 3 constraints) and `h8` (7, 36, 12; 7), as §1.4 and
    §1.5 state them;
  - `gate`: the `Gate` relation `(address, l0..l3)`, the reserved
    addresses, the public terms, and §1.1's soundness argument written out
    in the module's docs;
  - the circuit hash: one Poseidon2-M31 absorption, from the zero digest,
    of a domain, the format's number and six parameters, the components'
    log sizes and the preprocessed root, each integer as 16-bit limbs.
- **`vos-recair`** (`pvm/proof/recair`), the prover:
  - `Context<V>`: one code path builds the wiring (`NoValue`) and the
    witness (`SecureField`); a test builds random circuits both ways and
    finds the same wiring;
  - the static check (`Circuit::check_wiring`): components a power of two
    of at least 16 rows, no chained row 0, every address below `p`, each
    used address yielded exactly once with the count of its uses, the
    absolute multiplicities below `p`. `finalize` runs it;
  - trace generation: preprocessed columns from the wiring, main columns
    from the witness, the interaction from the main columns (so a tampered
    trace gets an honest-looking interaction); a `p2` padding row holds the
    permutation of zero;
  - `prove` and `verify` on the Poseidon2-M31 channel under format 32,
    with the structural preflight, the exact-parameter and security checks
    (the relation width 5), the canonical-limb check and the Fiat-Shamir
    query-count check the segment verifiers run;
  - `gadgets`: the leaf sponge, the Merkle node and the transcript, each
    the `vos-pvm-poseidon2` mode it mirrors.
  - Adapted from starkware-libs/proving at `916aefb5` (Apache-2.0): the
    `Context` (`context/mod.rs`, from `circuits`' `context.rs` and
    `ops.rs`), its idioms (`context/arith.rs`, from `ops.rs`), its
    finalizing (`context/finalize.rs`, from `context.rs`,
    `finalize_constants.rs` and `circuit_common`'s `finalize.rs`) and the
    value trait (`value.rs`, from `ivalue.rs`); each file names its
    sources and says it was modified (Apache-2.0 §4(b)), and `NOTICE`
    lists them. `circuit.rs`, `trace.rs`, `prove.rs`, `gadgets.rs` and
    `vos-recair-air` share upstream's ideas (yields once, public logup
    terms, a circuit hash over the preprocessed root), not its code.
- **`vos-final-verifier`** (`pvm/proof/final-verifier`): a skeleton that
  builds the recursion AIR's components, so the dependency graph is
  checked on every target.

### Decisions

- **Format 32's entry, not a new number.** A recursion-AIR proof carries
  32 at its exact parameters. The registry keeps 32 reserved: it is the
  table the segment verifiers read, and they check a proof's channel, not
  its kind, so admitting 32 there would let a segment proof carry it.
  `vos_recair::verify` takes 32 by its kind and channel. Admission waits
  for the leaf to pin the padded shape (5.12). `format.rs` and `proving.md`
  A.4 said 31 to 34 name the segment AIR and only 28 and 30 the recursion
  AIR; they now say 32 proves the recursion AIR, its leaves verifying the
  segment AIR.
- **The transcript** of a recursion-AIR proof: the header (domain,
  format, PCS configuration, log sizes), the preprocessed root, the main
  root, the outputs' values (where a segment mixes its boundary states:
  the public terms read them), the interaction PoW, the `Gate`
  challenges, the claimed sums, the interaction root, then Stwo's.
- **Only guesses are yielded by a consumer.** A constant is yielded only by
  the gate that fixes it: a consumer's yield would let the prover choose
  the constant's value.
- **An `h8` input cannot yield:** its five inputs are fixed uses (§1.5's
  seven preprocessed columns). A guess read only by `h8` rows, or by a
  node's bit, is yielded at `finalize` by an identity row. Padding `h8`
  rows read the zero wire five times; its yield counts them.
- **`p2` rows are laid out chain by chain.** A transcript's absorptions
  chain from one another while its draws are wired rows between them, so
  rows cannot follow the transcript's order. Each chained row names its
  predecessor, which may have one successor, and `finalize` places each
  chain contiguously. §1.3's modes cover the new transcript: an
  absorption after a draw chains from the last absorption, and the PoW's
  second permutation chains from its first (channel first).
- **The number of outputs** is bound by the logup, not the hash: an
  output claimed fewer leaves its yield unbalanced, one claimed more a
  public term nothing cancels.
- **The degree audit** uses the recording evaluator's expressions with a
  memoized walk: constraint-framework's `degree_bound` recomputes an
  intermediate at every reference, exponential over `p2`'s partial rounds,
  and counts a preprocessed column, which `ExprEvaluator` names by its id,
  as a constant. The walk counts preprocessed columns at degree 1; with
  them as constants it agrees with the framework's count on `qm31` and
  `h8`.
- **R5, the archive's failure, does not occur here.** The three
  components, each finalizing several fractions in pairs, prove together
  on the SIMD backend at every size assignment tried; a scratch run on the
  CPU backend, the archive's, proved four assignments too [measured, not
  kept]. The failure was the archive's own code, not the pinned Stwo.

### Tests (`just check`)

- `gate_vm`: random circuits over every gate and mode prove and verify,
  each refused under another circuit's hash; the wiring built without
  values is the filled wiring's; the static check refuses a second yield
  (also with the yields' counts summing right), a yield removed, a
  miscounted yield, multiplicities totalling `p` and a chained row 0;
  `finalize` yields the guesses only `h8` reads and pads with permutations
  of zero; a circuit whose wiring fails the check is neither committed
  nor proved; a multiplicity of magnitude `p` is refused.
- `modes`: `p2` equals `vos-pvm-poseidon2` in every mode (leaves of 0–21
  values against `LeafSponge`, nodes of either bit against `compress`, a
  path into a guessed root, a transcript's absorptions, draws and PoW
  against `Transcript`), and the circuit proves and verifies. Tampers
  refused: in each of the seven modes an S-box column and the low and high
  input (the permutation recomputed), a padding row's input, by the
  constraints; an unread message lane on a used wire, a `qm31` operand
  moved with its output, an `h8` accumulator moved with its output, by the
  logup alone (the constraints hold); a `qm31` output and an `h8` sample by
  the constraints; and a finished proof's claimed sum, output,
  interaction PoW, queried value, log size and format, each for its
  reason, and its sampled values (per component, main and interaction)
  and claimed sums moved between components, by the verifier's OODS
  check.
- `gates`: the three below.
- `vos-recair-air`'s unit tests: the designed widths and counts, and
  `p2`'s columns against the permutation.

### Gates

[measured, on the Intel Core Ultra 7 155H, 22 threads, load average 2–3]
- **A 10k-gate circuit proves and verifies:** a random circuit of 10,002
  rows (3,362 `p2`, 5,762 `qm31`, 878 `h8`; log sizes 12, 13, 10) proves
  in 125 ms and verifies in 13 ms, a 196,957-byte proof; the test
  process's peak resident memory is 69 MB.
- **The padded shape** (a scratch run, not kept): a random circuit of
  150k rows padded to 2^16 / 2^17 / 2^16 proves in 1.5–1.8 s with a peak of
  1.04 GB, and verifies in 17–19 ms; §5 projected 0.6–1.4 GiB and
  1.2–2.6 s for the leaf.
- **The degree ≤ 3 audit passes:** `p2`'s 303 constraints, 143 of degree
  2 and 160 of degree 3; `qm31`'s 3 of degree 3; `h8`'s 7, one of degree
  2 and six of degree 3.
- **A three-component multi-fraction logup proves at three log sizes:**
  one circuit (20 / 12 / 10 rows) padded to `p2`, `qm31`, `h8` at 2^5,
  2^6, 2^7, then 2^7, 2^5, 2^6 and 2^6, 2^7, 2^5, then 2^10, 2^12, 2^14,
  every claimed sum nonzero.
- **`vos-final-verifier` builds without std:** on stable (1.94.1) for x86
  and wasm32; on the pinned nightly for wasm32 with every nightly feature
  refused (`-Zallow-features=`), for thumbv7em with build-std, and for the
  PVM with the settlement verifier's target spec and build-std, in
  release. `just check-no-std` runs the three nightly builds.
- **`just check`** green under `systemd-run` at 14 GiB, `nice -n 10`,
  `CARGO_INCREMENTAL=0`, 8 jobs: 1,037 tests (1,019 at 5.8.0 (B)), the new
  crates' 13 among them; clippy clean on the three crates' targets.

### The review folded

- **Attribution:** `NOTICE` named `src/context.rs`, split since into
  `context/{mod,arith,finalize}.rs`; `arith.rs` (from `ops.rs`) and
  `finalize.rs` (from `context.rs`, `finalize_constants.rs` and
  `circuit_common`'s `finalize.rs`) had no header naming their sources
  and their modification. Each now has one, `mod.rs` names only what it
  keeps, and `NOTICE` lists the three files.
- **No path commits an unchecked circuit:** `circuit_commitment` returns
  the `WiringError` of `check_wiring` before committing, and `prove`
  (and `prove_with`) refuses with `ProveError::Wiring`; a Stwo refusal is
  `ProveError::Stwo`. `circuit::signed` refuses a multiplicity of
  magnitude `p` or more instead of reducing it.
- **The refusal tests name their reasons.** Stwo's prover samples the
  composition polynomial and the trace at the OODS point and refuses a
  mismatch, so every trace tamper is the prover's refusal
  (`ConstraintsNotSatisfied`), and `refused` now asserts exactly that. A
  finished proof's tampers each assert theirs: a claimed sum, the public
  terms' sum; an output or the interaction PoW, the PoW (the outputs are
  mixed before it is ground); a queried value, the Merkle root; a log
  size, another circuit's hash; the format, the format.
- **The verifier's constraint check is exercised:** an honest proof whose
  sampled value of one column is edited, in each component's main and
  interaction trees, and claimed sums moved between components, are
  refused by Stwo's OODS comparison (DEEP-ALI). An edit moves the
  transcript, so the redrawn queries' deduplicated count usually differs
  from the proof's rows and the query-count preflight refuses first; the
  test raises the edit by 1, 2, … until one passes the preflight
  [measured: the first try did not, on this small circuit].
- **`just check`** green after the fold: 1,040 tests (three new).

### Carried to later steps

- **5.10: a `Bit` type for `node`'s direction.** `gadgets::node` takes
  `bit: Var` and trusts its producer to constrain it: a `p2` row reads
  the bit as a use, and the `Node` mode's input is linear in `b`, so a
  non-bit picks a blend of the two orders. A `Bit` newtype only
  `Context::assert_bit` or a bit decomposition produces would move that
  trust into the types.
- **5.9 on: a message wire's unread lanes are not zero.** A `p2` row's
  message lanes with `act = 0` are yielded (or used) with the wire, but
  not absorbed: nothing constrains them. A consumer of such a wire reads
  the prover's choice there and must not assume zero; a partial block's
  padding comes from `c`, not from the wire.

### A pre-existing failure, fixed

- `node/host/tests/tree_crash.rs` panicked (`no entry found for key`)
  when a round's writer was killed before its first apply committed, which
  the machine's load made likely: at version 0 neither map has values, and
  the check indexed them. It now takes a missing map as empty, whose root is
  the empty tree's, as `roots::root` reports it.

### Outside the step's files

- Root `Cargo.toml`: the three crates as members and workspace
  dependencies, `opt-level = 3` for the two recursion crates in the dev
  and test profiles.
- `justfile`: the three crates in `test` and `check`; `check-no-std`
  builds the final verifier for thumbv7em, for wasm32 with no nightly
  feature, and for the PVM.
- `pvm/proof/src/format.rs` and `proving.md` A.4: format 32's AIR, as
  above.
- `node/host/tests/tree_crash.rs`: the fix above.
