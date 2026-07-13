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
the RAM path runs through Wave 5.2 (the BLAKE2B_BOUNDARY per-page-cost
diet — measurement showed ~10k boundary rows per touched page with
pages-per-window small and flat, so NO windowing strategy, uniform or
budgeted, moves the wall), with Wave 4 as the multiplier after.
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

Chain proving on phones is a Wave-5.2 outcome (the boundary chip's
per-page cost; Wave 4 adds margin): Wave 1.3 measured ~10–11 GiB per
window at ANY uniform seg_steps, and the 5.1 validation showed the
cause is not window placement at all — every window touches a
handful of pages and each page costs ~10k rows on the 2502-column
boundary chip. Even once RAM fits, 7.6M steps at phone
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
  1. **Uniform windowing stalls at ~10–11 GiB — and the Wave-5
     sizing spike identified the culprit precisely.** It is NOT the
     high-L chips per se: per-chip accounting (cols × 2^(L+2), model
     total 11.3 GiB ≈ the measured probe peaks) shows
     **BLAKE2B_BOUNDARY = 88.8%** of the committed bytes — 2502 main
     columns forced to the chain-max 2^17 rows in every window
     (hashing concentrates in short step ranges, so step-windowing
     can't cut its per-window max). PROGRAM_MEMORY, despite L=18, is
     31+1 columns = **1.4%**. Because the dominant chip is
     content-scaling, windowing looked like the fix — but the 5.1
     validation then showed the per-window page count is already
     minimal (~26), so the wall is the boundary chip's per-page
     cost (Wave 5.2), not window placement.
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
  Wave-5.2 boundary diet moves the RAM walls. (The
  actor-storage re-pin has merged; catalogs are current.)

Exit (revised): one-command re-pin at any `seg_steps` ✓; measured
floor/RAM/time table ✓; the ≤3 GB path now runs through Wave 5.2
(boundary per-page-cost diet), with Wave 4 as margin — not through
segmentation of any kind.

### Wave 2 — chain-driver memory (SideNote diet)

- **2.1 Streamed per-segment tracing — O(N²) replay ELIMINATED
  (`SegmentCursor`).** `zkpvm::segment::SegmentCursor` walks a chain's
  windows in ascending order, threading the entering memory image
  forward and applying each write exactly once; skipped windows advance
  the image without building a `SideNote`, so sparse probe sets stay
  cheap. Segment assembly is the same code path `segment_side_note`
  runs (equivalence unit-pinned field-by-field over a fixture with
  precompile writes threaded across window boundaries). All sequential
  full passes ride it: `prove_chain_segments`, `measure_commitments`'s
  comb scan + probes, `canonical_profile_for_bounds` — so the
  minutes-long floors derivation (Wave-1.3 finding 5) collapses with
  it, and the per-pass replay cost no longer grows with window count
  (the 8k sweep's 968 s derive was the O(N²) at 965 windows).
  Remaining for 2.1: the full-chain SideNote is still resident during
  the loop — removing the ~2.6 GB floor needs the tracer itself to
  stream (pair with 2.2's `PvmStep` shrink).
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
Multiplies with Wave 5.2 (post-diet windows × another 2–3×) and
benefits tap-to-pay equally.

### Wave 5 — content-aware windowing (sizing spike DONE 2026-07-10)

Per-chip committed-bytes accounting of an 8k canonical window
(blowup 4, interaction ≈ 0.62 × main; model total 11.3 GiB matches
the measured probe peaks):

| chip | L | pre+main cols | GiB | share |
|---|---|---|---|---|
| BLAKE2B_BOUNDARY | 17 | 43+2502 | 10.0 | **88.8%** |
| BLAKE2B | 13 | 42+2502 | 0.63 | 5.5% |
| MEMORY | 17 | 46 | 0.18 | 1.6% |
| PROGRAM_MEMORY | 18 | 31+1 | 0.16 | 1.4% |
| CPU | 13 | 592 | 0.15 | 1.3% |
| everything else | — | — | ~0.15 | ~1.4% |

The wall is ONE chip: BLAKE2B_BOUNDARY's 2502 columns forced to the
chain-max 2^17 rows (its ops concentrate in short step ranges, so the
per-window max doesn't fall with seg_steps). Both original Wave-5
hypotheses are dead: the program-memory diet is pointless (1.4%), and
the wall is NOT windowing-proof — it's step-windowing-proof.

- **5.1 Content-aware windowing — BUILT, AND ITS RAM HYPOTHESIS IS
  FALSIFIED (measured 2026-07-12).** `segment_bounds_budgeted(full,
  max_steps, max_pages)` landed in `segment.rs` (deterministic dual
  budget, page accounting mirrors `page_merkle::touched_pages`, unit
  tests) with `canonical_profile_for_bounds` for floors over any
  explicit cut. The validation sweep (real transition, 7.84M steps,
  steps ≤ 32k, page budgets {48, 96, 192}) showed the page budget
  NEVER binds: **the worst window touches only 26 distinct pages**,
  at every budget, with all precompile streams counted — yet
  BLAKE2B_BOUNDARY still floors at 2^18. Pages-per-window is small
  and flat; the cost is **~10k boundary rows PER TOUCHED PAGE**
  (2^18/26 ≈ 10k; the 8k-uniform floors fit the same constant), and
  every window touches a handful of pages no matter how it's cut. No
  segmentation strategy — uniform or budgeted — can push the
  boundary chip below ~2^17. The machinery is kept (deterministic
  budgeted cuts, floors-over-bounds, commitments still collapse to
  2): it became the binding knob once 5.2's dedup landed.
  **Plumbing DONE (2026-07-13):** `page_budget` rides the chain ABI
  (`prove_chain{,_job}`, `measure_catalog`, `measure_floors`),
  `ProgramPin`/catalog pin it beside `seg_steps` (serde default 0 —
  old catalogs load unchanged), `vosx zk pin --page-budget` records
  it. **Tuning, post-dedup (measured):**

  | budget (steps, pages) | windows | boundary floor | window peak |
  |---|---|---|---|
  | uniform 100k | 79 | 2^17 | ~20 GiB |
  | 32k, 12 | 250 | 2^17 | ~13–16 GiB |
  | **32k, 8** | **293** | **2^16** | **11.0 GiB abs (~8 GiB working set, fresh)** |
  | 16k, 6 | 592 | 2^16 | ~similar, more windows |

  (32k, 8) is the recommended deployment cut: ~8 s/window ⇒ ~40 min
  chain, and boundary stalls at 2^16 below it (≥ ~5 distinct-content
  pages per window at 4 KB leaves — 2^15 is lever 2's case). With
  Wave 4's 2–3× on top: **~3–4 GiB**, the phone envelope's edge.
- **5.2 BLAKE2B_BOUNDARY per-page-cost diet (decomposition spike
  DONE 2026-07-13).** Mechanism, confirmed in code: the boundary
  chip proves the page-Merkle multiproof's compressions on a
  **96-row schedule per compression** (12 rounds × 8 G-steps), one
  row-block **per consumption, duplicates kept** (design §4: naive
  dedup under-produces the lookup balance). Decomposition of real
  uniform-100k windows:

  | window | pages (read-only) | compressions total→unique | dup | rows now→dedup |
  |---|---|---|---|---|
  | seg 0 | 33 (27) | 2248 → 262 | ×8.6 | 2^18 → 2^15 |
  | mid | 4 (2) | 310 → 207 | ×1.5 | 2^15 → 2^15 |
  | comb | 6 (4) | 456 → 283 | ×1.6 | 2^16 → 2^15 |
  | tail | 16 (6) | 1134 → 687 | ×1.7 | 2^17 → 2^17 |

  Leaf-image chains dominate (~90–95%; the remainder are t=192
  domain-tagged node merges — the spike's t=64 node classifier was
  wrong, totals/uniques stand); duplicates come from read-only pages
  (exiting chain == entering chain) and identical-content pages
  (fresh zero pages).
  1. **Dedup via a multiplicity column — LANDED + MEASURED
     (2026-07-13).** `boundary_blake2b_calls` returns unique
     compressions with consumption counts; the boundary chip fills
     the count into the new `EmitMult` column at each compression's
     row 95 and produces `+EmitMult` (consumers keep −1 each) —
     balance preserved, design §4 updated. `EmitMult` is pinned to
     real row-95s in the clean-unwind anchor block; its value is
     free, the cross-chip sum pins it (fraction-space balance test
     with an off-by-one negative). Measured on the real transition:
     boundary floor 18 → **17** at uniform 100k, window peak
     ~28.5 → **~20 GiB** (~30% off) — and **C_0/C_1 DO NOT DRIFT**
     (drift guard green: the identity is the preprocessed root,
     EmitMult is main-trace) so this is drop-in for deployed
     verifiers, no re-pin. Remaining tuning: post-dedup boundary
     rows ≈ 70–96 per distinct-content page (64 leaf comps + node
     share, ×96 rows), so the 5.1 page budget binds only below ~26
     pages/window — a budget of ~6–12 pages projects the floor to
     2^15–2^16 (boundary term ~2.6–5 GiB) at the cost of more
     windows; the 4 KB leaf granularity (64 comps even for a
     one-byte touch) is what stands between that and 2^14, which is
     lever 2's case. Prove-time deltas from this change are
     unbenchmarked (box was under parallel load).
  2. **Smaller Merkle leaf unit (reserve).** 256B sub-leaf counts
     measured (seg0 421, mid 14, comb 23, tail 81): helps sparse
     windows ~3–5×, does NOT help dense ones alone (seg0 would stay
     ~2^18 without dedup) — only worth it after 1, if at all.
  3. **Poseidon2-M31 page hash (deep reserve).** 96 rows per 128
     hashed bytes is the constant both above levers dance around; an
     M31-native page hash cuts it ~10×+ but needs a new chip +
     format/verifier re-pin across the stack.

Exit: lever 1 implemented (multiplicity dedup) + 5.1 budget plumbed
⇒ every window ≤ ~2^15 boundary rows, windows ≤3 GiB on desktop.
