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

**1. Smaller segments (local, machinery landed — MEASURED: stalls at
~10–11 GiB; see Wave 1.3).** The naive model — peak ∝ 2^Lmax ∝
seg_steps, so 12k ≈ 3.5 GB — holds only for chips whose rows scale
with steps (CPU, ledgers). It fails for voucher-check on two chip
classes the sweep exposed: `PROGRAM_MEMORY` sizes on the code image
(2^18 rows in every window at every seg_steps), and the
content-dense chips (BLAKE2B_BOUNDARY, MEMORY) stall at 2^17
because their ops concentrate in short step ranges. Measured: 8k
windows still prove at ~10–11 GiB, and per-window time is pinned by
the padded floors, so total chain time grows ~linearly with window
count (965 windows ≈ 4 h vs 78 ≈ 32 min). The knob and its tooling
remain right (every production FRI zkVM shards; the verifier is
seg-size-agnostic; `MAX_CHAIN_SEGMENTS = 65 536`; the turnkey
re-pin below), but for THIS transition the lever is spent at 100k —
the RAM path runs through Wave 4 + a program-memory diet.
**The tooling gap (floor derivation) is closed:** `vosx zk pin
--seg-steps N` without `--profile` derives the floors, measures the
allowlist under them, and records both; then update the three frozen
constants in `vos/tests/elf_integration.rs`, re-run the two
`#[ignore]` gates, commit the catalog.

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

Chain proving on phones is a Wave-4+5 outcome, not a windowing outcome
(Wave 1.3 measured the walls: ~10–11 GiB per window at ANY seg_steps,
and time ∝ window count). Even once RAM fits, 7.6M steps at phone
throughput is an hour-plus of background work (x86 desktop: ~32 min at
100k windows). That is the intended shape — the roadmap already treats
chain proving as an async job per settlement window, off the hot path.
The interactive, sub-10 s mobile story is the tap-to-pay-scale single
proof, which FibRace independently validates at our exact
field/prover/security point. Also budget for chain *transport* if
windows ever shrink: ~600 segments × ~3 MiB ≈ 1.8 GB per full
conservation proof — streaming verify handles the RAM, but network
cost pushes toward fewer/bigger
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
- **1.3 Measurement run (voucher-check) — DONE, and it overturns the
  segment-shrink model.** Sweep over seg_steps ∈ {8k, 12k, 16k, 100k}
  (federation-fixture witness, 7.72M steps, x86 desktop, dense derived
  floors, probes = seg 0 / comb window / short tail):

  | seg_steps | segments | derive | probe prove | probe peak RSS |
  |---|---|---|---|---|
  | 8k | 965 | 968 s | 11–19 s | **~10–11 GiB** |
  | 12k | 644 | 702 s | 14–32 s (load-contaminated) | ~11 GiB |
  | 16k | 483 | 555 s | 10–16 s | ~11–12 GiB |
  | 100k | 78 | 133 s | 22–30 s | ~28–29 GiB |

  Findings, in order of consequence:
  1. **Windowing stalls at ~10–11 GiB.** `PROGRAM_MEMORY` is 2^18
     rows in EVERY window at EVERY seg_steps — it sizes on the
     program's code image, not on steps — and BLAKE2B_BOUNDARY /
     MEMORY stall at 2^17 in content-dense windows (ops concentrate
     in short step ranges). No uniform (or adaptive) windowing gets
     this transition under ~10 GiB; ≤3 GB needs the LDE-recompute
     fork (Wave 4, ~2–3×) PLUS a program-memory diet: sparsify code
     authentication to executed pages per segment (new AIR work,
     soundness-sensitive) and/or shrink the guest code image.
  2. **Chain-prove time ∝ window count under canonical padding.**
     Per-window cost is pinned by the padded floors (~15–25 s here),
     so 965 windows ≈ 4 h vs 78 windows ≈ 32 min for the same trace.
     Small uniform windows are a bad trade on time as well as being
     RAM-ineffective. seg_steps = 100k stays the right default until
     the walls above move.
  3. **Every seg_steps collapses to exactly 2 commitments**
     (comb-free + one-comb, short tail included) under derived
     floors — the turnkey derivation is functionally correct at all
     sizes.
  4. **Dense ≠ sparse: C_0/C_1 MISMATCH at 100k.** Forcing the
     chips the hand profile leaves at 0 shifts the program
     commitment, so switching to derived profiles is a full re-pin
     (self-consistent — the pin records the echoed profile it was
     measured under), never a drop-in.
  5. **Floors derivation costs minutes** (968 s at 8k) — the
     documented O(N²) slice-replay plus per-window trace-gen; the
     Wave-2.1 streaming driver is what fixes it.
- **1.4 Flip the pin — NOT NOW.** Per finding 2, stay at
  seg_steps = 100k; the flip becomes interesting only after the
  Wave-4 fork + a program-memory diet move the RAM walls. (The
  actor-storage re-pin has merged; catalogs are current.)

Exit (revised): one-command re-pin at any `seg_steps` ✓; measured
floor/RAM/time table ✓; the ≤3 GB path now runs through Wave 4 + a
program-memory diet, not through segment shrink.

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
also collapses the minutes-long floors derivation (Wave-1.3 finding 5).

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
fork tracks upstream. Exit: ~2–3× off the per-segment LDE term.
After Wave 1.3 this is the FIRST-ORDER RAM lever for chain proving
(segment shrink is spent), and it benefits tap-to-pay equally.

### Wave 5 — program-memory diet (opened by Wave 1.3)

`PROGRAM_MEMORY` costs 2^18 rows in every segment of voucher-check —
it authenticates the whole code image regardless of what the window
executed. Two directions, both needed for ≤3 GB chain proving when
combined with Wave 4: (a) sparsify code authentication to the pages a
segment actually executes (AIR change, soundness-sensitive — code
identity must still be pinned chain-wide, e.g. page-Merkle against the
program commitment); (b) shrink the guest image (the vos::storage
framework rebuild grew it; a code-size pass on the prelude/kernel pays
off 1:1 in every segment). Sizing spike first: count PROGRAM_MEMORY
columns and measure its actual share of the 10–11 GiB window peak
before committing to (a).
