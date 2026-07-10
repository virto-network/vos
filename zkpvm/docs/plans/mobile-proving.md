# Mobile proving: research + direction

**Question.** What does it take to generate zkpvm proofs on phone-class
hardware (aarch64, ~3 GB usable app RAM, NEON)? Two workloads with very
different gaps:

- **Tap-to-pay single proof** (~24k steps): RAM is already fine; the open
  question is ARM wall-clock. Estimated **~3.5–7 s on a flagship phone**
  (composed from SIMD-width/clock/bandwidth factors vs the 0.86 s x86
  MOBILE bench — needs an on-device measurement to confirm).
- **Conservation-transition chain prove** (~7.6M steps, 76×100k-step
  segments): **~26–29 GB peak per segment** today. This is the wall, and
  it is fixable with mostly-local work.

The external envelope is proven: FibRace (KKRT/Hyli, 2.2M proofs on 1,420
device models, arXiv 2510.14693) showed M31+stwo proving of ~100k-cycle
workloads at the same 96-bit security on ordinary phones — median 6.4 s,
with a hard **≥3 GB available-RAM floor** and crashes driven by memory
pressure, not CPU. Mopro measured the same ~3 GB OS app-memory cap on
iPhone 15 Pro / Pixel 6 Pro. So the design constraint is **≤3 GB peak**,
not 4 GB.

## Where the 28 GB actually goes

Measured + code-derived model (MOBILE config, blowup 2^b with b=2; `L` =
chip log_size, top chip hits L=20 at 100k steps; cell = 4 B M31):

| Component | Formula | Share |
|---|---|---|
| Blown-up LDE, all 4 commitment trees resident at once | Σ_trees Σ_cols 2^(L+b)·4 | **~55–65%** |
| Stored coefficients (OODS-opening convenience) | Σ 2^L·4 = LDE/4 | ~15% |
| SideNote (full-chain trace, held across the segment loop) | ~2.6 GB | ~10% |
| Merkle layers (retained until decommit) | ~2·2^lift·32 per tree | ~3–5% |
| FRI layers + quotient temporaries | ~2·2^lift·16 | ~2–3% |
| Twiddles | ~2·2^(Lmax+b)·4 | ~1% |

Two structural facts drive the seams below:

1. `CommitmentSchemeProver` keeps every tree's full LDE from commit until
   the end of `prove_values`; the Merkle leaf at row *i* hashes across
   **all** columns, so a tree cannot be committed column-block-by-block
   without a protocol change. But with `store_polynomials_coefficients`
   on (as we run), OODS opening reads **coefficients** — the only late
   consumers of full LDEs are FRI-quotient accumulation and decommit.
2. Base `ComponentTrace`s are consumed at interaction-gen and are *not*
   part of the peak; the peak is LDE-dominated. Blowup is the multiplier,
   and MOBILE (b=2) has already spent most of that knob — b=1 would need
   ~76 queries and sits at the soundness margin.

The chain driver adds two O(N) hazards of its own: the full-chain
SideNote (2.6 GB, ~350 B/step of which ~208 B are redundant full
register-file snapshots) is resident for the whole loop with an O(N²)
memory-replay per segment slice, and `prove_chain`/the async job
materialize **all** segment proofs in one buffer (~3 MiB each).

## Levers, ranked

**1. Smaller segments (local, machinery landed, highest ROI).**
Peak ∝ 2^Lmax ∝ seg_steps. 100k→12k steps (log-20→log-17) ≈ 28→3.5 GB;
8k lands comfortably under the 3 GB app budget. This is what every
production FRI zkVM does (RISC Zero continuations, SP1 shards, OpenVM
metered execution). Everything hard is already built: `prove_chain` /
`measure_catalog` / `vosx zk pin` are fully parameterized over
`seg_steps` (short-tail + per-comb-shape allowlist probing included);
the verifier is seg-size-agnostic (clerk-bridge stores only the
allowlist); streaming `verify_chain` is O(1) memory at any chain length;
`MAX_CHAIN_SEGMENTS = 65 536` clears ~600 segments trivially. Prove
*time* is roughly a wash (throughput ~constant across log 10–14; slight
per-segment fixed overhead penalty vs slight FRI superlinearity win).
**The one real gap: canonical-profile floors.** The BLAKE2B_BOUNDARY /
MEMORY_PAGE floors are content-driven per-window maxima that must be
re-derived for each seg_steps, and today the profile file is
hand-authored — `measure_catalog` needs a floor-measurement mode (trace
all segments, report per-chip natural-log maxima, emit the profile) so a
re-pin is one command. Then: re-run `vosx zk pin --seg-steps N`, update
the three frozen constants in `vos/tests/elf_integration.rs`, re-run the
two `#[ignore]` gates, commit the catalog.

**2. SideNote diet + chain-driver streaming (local).**
(a) Stop holding the full-chain trace: drive segments with a forward
tracer (or spill steps to disk and stream slices) — removes the 2.6 GB
constant *and* the O(N²) replay; per-segment step storage is ~35 MB.
(b) Shrink `PvmStep`: drop the two full register-file snapshots, keep
the written register + value, reconstruct at trace-gen (~2–3× smaller).
(c) CAS-publish each segment proof as produced instead of returning
`Vec<Vec<u8>>` (at 600 segments the current return is ~1.8 GB). Without
this item, small segments alone still carry a ~2.6 GB floor that blows
the 3 GB budget.

**3. Recompute-LDE-from-coeffs — the streaming-prover MVP (contained
stwo fork).** After each tree's Merkle root is computed, drop
`Poly.evals` and recompute per-column LDEs from the retained
coefficients when FRI quotients and decommit need them
(`get_evaluation_on_domain` already exists). Removes "all 4 trees' LDE
resident simultaneously" — est. **2–3× off the dominant term** for one
extra FFT pass per column. Fork surface: `prover/pcs/`
(`CommitmentTreeProver`, `prove_values`, `compute_fri_quotients`).
Upstream is drifting this way (configurable quotient chunks, leaf
packing in 2.3.0-dev), so this is plausibly upstreamable. True
intra-tree streaming commit (bounded RAM regardless of segment size) is
blocked by the row-wise leaf layout and is unclaimed research territory
industry-wide — sum-check streaming (Jolt, ePrint 2025/611) does not
port to a univariate FRI PCS; the only FRI-shaped public claims are
unvetted preprints. Don't chase it; seams 1–3 reach the target without
it.

**4. Housekeeping (local, small).** Move-out instead of clone in
`ComponentTrace::to_circle_evaluation` (transiently doubles base
columns); cap rayon (`RAYON_NUM_THREADS`=2–4) on phones — parallel
column blowup multiplies transient buffers; bump stwo 2.2.0→2.3.0
(additive: parallel FRI folds, chunked quotients, Keccak channel — the
latter is the Solidity-friendly Fiat–Shamir if direct EVM verification
ever matters) and measure its peak-RAM effect.

## ARM bring-up (orthogonal to RAM)

No source-level blocker: stwo's SimdBackend is portable `std::simd`
(u32×16) with a hand-written NEON kernel for the hot M31 multiply
(`vqdmull_s32`); Blake2s Merkle + PoW grind are portable SIMD that
lowers to NEON; zkpvm itself has no intrinsics. Setup-level items:

- Nightly toolchain per `rust-toolchain.toml` (portable_simd) for the
  aarch64 target; NDK/iOS clang for `blst` (unavoidable via javm →
  grey-crypto, ships aarch64 asm).
- `.cargo/config` sets `[build] rustflags = target-cpu=native` — wrong
  under cross-compilation; needs a `[target.aarch64-*]` override. PGO
  profile is x86-trained; retrain on-device.
- MOBILE PcsPolicy is doubly right on ARM (4× smaller committed domain
  = compute *and* LPDDR-bandwidth relief); STANDARD and MOBILE are the
  same 96 conjectured bits (20 PoW + blowup·queries = 76).
- Expect Blake2s/Merkle's share of prove time to rise vs x86 (portable
  SIMD pays the 128-bit width tax; the M31 mul degrades less).

## What NOT to pursue

- **GPU**: icicle-stwo is a stale CUDA-only fork with no lookup support
  (fatal for LogUp); ICICLE's Metal backend is production-licensed and
  never wired to stwo; no Vulkan path exists. Re-evaluate only for
  server-side aggregation.
- **Native STARK recursion**: dead, measured (see
  `recursion-decision.md`). Watch `starkware-libs/stwo-circuits` — if a
  generic verifier-AIR materializes upstream, the verdict could reopen.
- **Blowup below 2** / query inflation: at the soundness margin, larger
  proofs, saves only 2× where seams 1–3 save 10×+.
- **Wholesale re-architecture** (sum-check/jagged PCS à la SP1
  Hypercube): removes FRI entirely; wrong trade while the FRI stack
  meets the envelope.

## Honest wall-clock picture

Small segments make chain-prove *feasible* on phones, not *fast*: 7.6M
steps at phone throughput is on the order of an hour-plus of background
work (x86 desktop does it in ~22 min). That is the intended shape — the
roadmap already treats chain proving as an async job per settlement
window, off the hot path. The interactive, sub-10 s mobile story is the
tap-to-pay-scale single proof, which FibRace independently validates at
our exact field/prover/security point. Also budget for chain *transport*:
~600 segments × ~3 MiB ≈ 1.8 GB per full conservation proof — streaming
verify handles the RAM, but network cost pushes toward fewer/bigger
settlement windows and, eventually, succinct-witness step reduction.

## Suggested sequence

1. **Floor-measurement mode in `measure_catalog`** + re-pin at
   seg_steps ≈ 8–16k; fix the `prove_chain` all-proofs-in-one-buffer
   return. Exit: chain prove ≤4 GB on the desktop, time ≈ wash.
2. **SideNote diet** (streamed per-segment trace + `PvmStep` shrink).
   Exit: peak = per-segment cost only; O(N²) replay gone; ≤3 GB.
3. **aarch64 bring-up**: cross-build (blst/NDK, RUSTFLAGS override),
   on-device bench of tap-to-pay + one small segment; retrain PGO.
   Exit: measured phone numbers replacing the 3.5–7 s estimate.
4. **stwo fork: recompute-LDE-from-coeffs**; measure; offer upstream.
   Exit: headroom for bigger segments / lower-end phones.
5. Re-evaluate then: stwo 2.3.0 bump lands wherever convenient in 1–4.
