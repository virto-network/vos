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

## Plan

### Wave 1 — turnkey re-pin (the small-segment enabler)

- **1.1 Floors derivation (DONE).** `zkpvm::canonical_profile_for`:
  the per-chip elementwise max of every window's natural `log_size`
  (trace-gen only — no commit/FRI). That vector IS the canonical
  forcing profile: chips whose size is already uniform get their own
  size back (forcing is a no-op), varying chips get the chain-wide
  max, so every window collapses onto the minimal canonical-shape
  set; floors above `DEFAULT_MAX_LOG_SIZE` refuse (verifier-rejected
  by construction). Exposed two ways from the prover extension: a
  trace-only `measure_floors` `#[msg]`, and `measure_catalog` with an
  EMPTY profile — which derives from the same trace the allowlist
  probe uses (one trace, one invoke) and echoes the profile in its
  reply. Tests: two windows of a tiny trace prove to ONE commitment
  under derived floors; garbage-blob and seg_steps=0 fail soft.
- **1.2 `vosx zk pin` derives the profile (DONE).** `--profile` is
  optional: when omitted (requires `--witness`), the measure path
  sends an empty profile and pins the echo; the `--allowlist` re-pin
  derives via trace-only `measure_floors` and never proves.
  `--profile-out` writes the pinned profile in `--profile` format.
- **1.3 Measurement run (voucher-check).** Derive floors at
  seg_steps ∈ {8k, 12k, 16k} via the federation fixture's witness;
  record floors + per-probe prove RAM/time here. Cross-check first:
  derived floors at 100k must reproduce the pinned C_0/C_1 (the
  derived profile is DENSE — max for every chip — where the
  hand-authored one is sparse; equal commitments at 100k proves the
  densification is identity-neutral). Pick the production seg_steps:
  largest value whose probe peak + streamed-trace overhead fits
  ≤3 GB (expect ~8–12k). Needs the elf_integration harness (the
  representative witness is the federation fixture's) — a follow-up
  session with ~free RAM for the 100k baseline comparison.
- **1.4 Flip the pin.** Re-pin `catalog.toml` + the three frozen
  constants in `vos/tests/elf_integration.rs` + re-run the two heavy
  gates. Coordinate: the actor-storage branch re-pins the same
  constants (guest code-size change) — land after it merges.

Exit: one-command re-pin at any `seg_steps`; measured floor/RAM/time
table for 8–16k; chain prove ≤4 GB on desktop.

### Wave 2 — chain-driver memory (SideNote diet)

- **2.1 Streamed per-segment tracing.** Drive `prove_chain_segments`
  with a forward tracer that threads the memory image + register file
  across windows instead of holding the full-chain SideNote and
  re-replaying writes per slice (`segment.rs` documents the O(N²)).
  Removes the 2.6 GB full-trace residency floor.
- **2.2 `PvmStep` shrink.** Drop the two full register-file snapshots
  (~208 of ~350 B/step); keep the written register + value,
  reconstruct at trace-gen.
- **2.3 Producer-side proof streaming.** `prove_chain`/the async job
  materialize `bincode(Vec<Vec<u8>>)` — ~1.8 GB at 600 segments.
  Spill per-segment proofs (host CAS or extension-local disk) and
  page `job_result` per segment.

Exit: chain-prove peak = one segment's prove cost + O(1) driver state;
≤3 GB end-to-end at the Wave-1 seg_steps.

### Wave 3 — aarch64 bring-up

Cross-build for aarch64 (nightly rust-std, NDK/iOS clang for blst,
`[target.aarch64-*]` rustflags replacing `target-cpu=native`); bench
tap-to-pay + one small segment on a real phone; retrain PGO on-device.
Exit: measured phone numbers replacing the 3.5–7 s estimate.

### Wave 4 — stwo fork: recompute-LDE-from-coeffs

Fork `prover/pcs/` (`CommitmentTreeProver`, `prove_values`,
`compute_fri_quotients`): drop `Poly.evals` after each tree's Merkle
root, recompute per-column LDEs from retained coefficients for FRI
quotients + decommit. Consider bumping stwo 2.2.0→2.3.0 first so the
fork tracks upstream. Exit: ~2–3× off the per-segment LDE term —
headroom for bigger segments / lower-end phones.
