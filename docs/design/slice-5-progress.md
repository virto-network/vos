# Slice 5: progress

The log of build step 5, against `slice-5-proving.md`. Every number is
tagged measured, model or projected.

## Step 5.2: the reference Poseidon2 and a SIMD hasher

**Gate: failed** on both counts (`proving.md` §3.2), on the 8 threads of an
Intel Core Ultra 7 155H (AVX2, no AVX-512):
- a window-kernel segment proves on Poseidon2 in **1.75–1.85×** Blake2s's
  time, against 1.5× [measured];
- a leaf's commitment of 25M permutations takes **0.63 s**, against 0.5 s
  [measured, and projected from the permutation rate].

What dominates is the permutation itself: about 112M a segment, 95% in
leaves, take 58% of the Poseidon2 prove's cycles, and the packed
permutation runs at Plonky3's own speed on this machine. The step stops
here, as the plan says; the permutation, its vectors and the SIMD hasher
are committed.

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
