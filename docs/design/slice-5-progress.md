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
ids, beside BLAKE2b's precompile, which derives.

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
