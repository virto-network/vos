# zkpvm — prover perf & mobile-proving roadmap

The single forward-looking doc for prover performance. Implementation
history lives in `git log`; this is the "state + decisions + open
questions + measured dead-ends" survivor.

**Question.** What does it take to generate zkpvm proofs on phone-class
hardware (aarch64, ~3 GB usable app RAM, NEON)? Two workloads with very
different gaps:

- **Tap-to-pay single proof** (~24k steps): RAM is already fine; the open
  question is ARM wall-clock. Estimated **~3.5–7 s on a flagship phone**
  (composed from SIMD-width/clock/bandwidth factors vs the 0.86 s x86
  MOBILE bench — needs an on-device measurement to confirm).
- **Conservation-transition chain prove** (~7.8M steps): was **~26–29 GB
  peak per segment** — the original wall. As of 2026-07-14 the production
  cut is content-budgeted (32k steps / 8 pages) and a window proves at
  **~5.2 GiB / ~4 s** (see Status below); the chain's trace is no longer
  resident and each segment proof streams to CAS as produced.

**Both-axes constraint (2026-07-13, project decision):** a RAM
reduction that costs considerable prove time is NOT acceptable — mobile
viability means fitting the RAM envelope AND staying practical on the
clock. Prefer levers that shrink committed cells (helping both axes);
schedule-only levers (recompute/streaming trades) must stay under
~10-15% time cost or ship as opt-in for RAM-desperate deployments only.
This deprioritizes the recompute-LDE fork line (its recompute tax
measured +64-86%) in favor of the boundary-diet levers.

The external envelope is proven: FibRace (KKRT/Hyli, 2.2M proofs on 1,420
device models, arXiv 2510.14693) showed M31+stwo proving of ~100k-cycle
workloads at the same 96-bit security on ordinary phones — median 6.4 s,
with a hard **≥3 GB available-RAM floor** and crashes driven by memory
pressure, not CPU. Mopro measured the same ~3 GB OS app-memory cap on
iPhone 15 Pro / Pixel 6 Pro. So the design constraint is **≤3 GB peak**,
not 4 GB.

## Status (2026-07-14) — what landed and what remains

**Landed + pushed** (master, both remotes), under the both-axes
constraint: turnkey re-pin tooling (Wave 1); content-budgeted windowing
+ `page_budget` ABI (Wave 5.1); the EmitMult boundary dedup; the
boundary-chip width diet; the (32k, 8) production flip; the compact
chain trace, streaming tracer, and streaming proof publish + native
`blob_put` (Wave 2 / 2(a) / 2.3); the byte-wide AND table + zero-numerator
logup skip (interaction diet C2); and aarch64 cross-compile plumbing +
a qemu-verified `mobile_bench` (Wave 3, no-device half). Net: **chain
window ~28.5 GiB / ~23 s → ~5.2 GiB / ~4 s**; trace no longer resident;
job results 0.9 GB → 9 KB. The full real-STARK federation e2e
(`clerk_ledger_two_bank_federation`, `VOS_FEDERATION_REAL_STARK=1`:
canonical chain-prove → CAS → cross-node `verify_chain` accept +
forged-root reject) passed on the new pins in ~17 min — a run that
previously OOM'd on the same box at ~28 GiB/segment.

**Falsified/NO-GO by measurement** (kept honest, not shipped) — details
under "Measured dead-ends": smaller Merkle leaves (path-dominated);
recompute-LDE-from-coeffs stwo fork (−9.6% RAM / +64–86% time); C1
per-compression sub-chips (payoff collapsed to ~0.45 GiB post-C2).

**Remaining, in priority order:**

1. **aarch64 on-device bench (Wave 3, blocked on hardware).** The
   turnkey artifact exists (`mobile_bench`, recipe below). qemu confirms
   correctness only — it models no target timing. Needs a phone (or an
   Apple-Silicon / cloud-ARM proxy) to answer the two live unknowns:
   real tap-to-pay wall-clock, and whether ~5 GiB background chain
   windows fit the ~3 GB device budget under memory pressure. **This is
   the decision point for everything below** — chain proving is
   async/off-hot-path, so ~5 GiB windows may already be acceptable.

2. **Far-line RAM levers — DEFERRED, pursue only if the bench says
   windows must go under ~3–5 GiB.** Both are large, soundness-touching
   builds; neither is worth starting on speculation:
   - **Row-chunked lifted-Merkle leaf hashing.** Stream a commitment
     tree's leaf layer across column chunks with per-row running hash
     states, so even the largest tree's LDE never fully materializes —
     the real fix the parked `lde-recompute` fork's `Poly` release
     machinery was substrate for (that fork's schedule-trade approach is
     dead; this is a different, mostly-new change). Attacks the
     single-tree commit residency that bounds the current window peak.
   - **Poseidon2-M31 page-Merkle hash.** blake2b costs 96 in-circuit
     rows per 128 hashed bytes; the in-tree M31-native Poseidon2
     (`poseidon2/`, settlement-verifier) cuts the boundary chip's
     per-page cost ~10×. Deepest option — new chip + format/verifier
     re-pin across manifests, catalog, and the settlement verifier.

## Where the RAM goes

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

Two structural facts: (1) `CommitmentSchemeProver` keeps every tree's
full LDE from commit until the end of `prove_values`, and the Merkle
leaf at row *i* hashes across **all** columns, so a tree can't be
committed column-block-by-block without a protocol change — but with
`store_polynomials_coefficients` on (as we run), OODS opening reads
**coefficients**, so the only late consumers of full LDEs are
FRI-quotient accumulation and decommit. (2) Base `ComponentTrace`s are
consumed at interaction-gen and aren't part of the peak; the peak is
LDE-dominated, and MOBILE (b=2) has already spent most of the blowup
knob (b=1 would need ~76 queries, at the soundness margin).

At the **chip** level the peak is dominated by ONE chip. Per-chip
committed-bytes accounting of an 8k canonical window (blowup 4,
interaction ≈ 0.62 × main; model total 11.3 GiB matches the measured
probe peaks):

| chip | L | pre+main cols | GiB | share |
|---|---|---|---|---|
| BLAKE2B_BOUNDARY | 17 | 43+2502 | 10.0 | **88.8%** |
| BLAKE2B | 13 | 42+2502 | 0.63 | 5.5% |
| MEMORY | 17 | 46 | 0.18 | 1.6% |
| PROGRAM_MEMORY | 18 | 31+1 | 0.16 | 1.4% |
| CPU | 13 | 592 | 0.15 | 1.3% |
| everything else | — | — | ~0.15 | ~1.4% |

The wall is BLAKE2B_BOUNDARY's 2502 columns forced to the chain-max 2^17
rows (its ops concentrate in short step ranges, so the per-window max
doesn't fall with seg_steps). The chain driver's own O(N) hazards — the
full-chain trace resident for the whole loop, and materializing all
segment proofs in one buffer — are both closed (Wave 2 / 2(a) / 2.3; see
git history).

## Levers, ranked

**1. Smaller segments (machinery landed — but MEASURED to stall).** The
naive model (peak ∝ 2^Lmax ∝ seg_steps) holds only for step-scaling
chips (CPU, ledgers). It fails for the content-dense chips: uniform
windowing stalls at **~10–11 GiB** because BLAKE2B_BOUNDARY floors at
2^17 in every window, and per-window time is pinned by the padded
floors, so total chain time grows ~linearly with window count (965
windows ≈ 4 h vs 78 ≈ 32 min). The knob and its turnkey re-pin tooling
stay (every FRI zkVM shards; verifier is seg-size-agnostic;
`MAX_CHAIN_SEGMENTS = 65 536`), but for THIS transition segmentation
alone is spent — the RAM path runs through the boundary-chip per-page
diet (below).

**2. SideNote diet + chain-driver streaming (LANDED).** Drive segments
with a forward/online tracer so no trace form is resident
(post-trace residency 1,057 → 15 MB; peak across a 10-window prove pass
9.34 → 8.42 GiB); hold `CompactStep`s not `PvmStep`s (360 → 136 B/step),
expand windows locally; CAS-publish each segment proof as produced
instead of returning `Vec<Vec<u8>>`.

**3. Recompute-LDE-from-coeffs — the streaming-prover MVP (contained
stwo fork). BUILT, largely falsified (−9.6% RAM / +64–86% time).** See
Measured dead-ends. Its release machinery is the right substrate for the
real Wave-4 win (row-chunked lifted-Merkle leaf hashing), but the flag
stays off and the fork stays unwired. True intra-tree streaming commit
is blocked by the row-wise leaf layout and is unclaimed industry-wide —
sum-check streaming (Jolt, ePrint 2025/611) does not port to a
univariate FRI PCS.

**4. Housekeeping (local, small).** Move-out instead of clone in
`ComponentTrace::to_circle_evaluation` (transiently doubles base
columns); cap rayon (`RAYON_NUM_THREADS`=2–4) on phones — parallel
column blowup multiplies transient buffers; bump stwo 2.2.0→2.3.0
(additive: parallel FRI folds, chunked quotients, Keccak channel — the
latter is the Solidity-friendly Fiat–Shamir if direct EVM verification
ever matters) and measure its peak-RAM effect.

## Interaction-trace diet

At production floors the interaction tree models at 1.95 GiB vs main's
4.22 GiB (second tree, not first). The two blake2b chips are ~90% of it;
the waste was ~1.17 GiB of FULL-HEIGHT columns carrying fractions gated
to 1-in-96 rows (a gate multiplies the numerator; the column still spans
2^L). Logup pairing itself is fine (two lone tails, ~7.5 MiB).

- **C2 — LANDED + MEASURED (2026-07-14): byte-wide AND table.** A new
  2^16-row `BitwiseAndByteChip` (`(a, b, a&b)` preprocessed +
  free-multiplicity column, placed last in BASE_COMPONENTS) replaces
  every paired nibble AND lookup in both blake2b chips with one byte
  lookup — byte-ness comes free from table membership. **512 main
  limbs/row die** from both `Column` and `BoundaryColumn`. Component-set
  + preprocessed-shape change ⇒ FULL re-pin at the (32k, 8) cut:
  `chip_idx::COUNT` 31→32, **C_0 `d76262877c32e2b6…`, C_1
  `913f5cbf7cdd9d99…`**. **Measured (release, apples-to-apples): window
  prove 6.41 → 4.01 s (−37%), peak RSS 6.90 → 5.17 GiB (−25%);
  interaction-gen BLAKE2B_BOUNDARY L16 617 → 352 ms (−43%).**
- **Free time lever — LANDED + MEASURED (2026-07-14, no re-pin,
  bit-identical): `LogupTraceBuilder` skips `relation.combine()` on
  zero-numerator rows.** When every batched numerator lane is zero the
  fraction is `0/denom = 0` regardless of the denominator, so the
  builder stores neutral `1` and skips the wide combine; `finalize_col`
  divides `numerator/denominator` so the dead emission's denominator
  cancels ⇒ interaction columns are BIT-IDENTICAL (pinned by
  `dead_row_skip_is_bit_identical`). Measured interaction-gen:
  BLAKE2B_BOUNDARY L16 **752 → 617 ms (−18%)**, BLAKE2B L13 **234 →
  177 ms (−24%)**. Prover-side representation only; commitments unmoved.
- **C3 (NO-GO for now): batch-4 logup** — −46% of the tree with no
  re-pin, but doubles quotient-eval domain for the heaviest constraint
  sets (both-axes violation risk); revisit only if short after C1+C2,
  batch-3 fallback.

## ARM bring-up (orthogonal to RAM)

No source-level blocker: stwo's SimdBackend is portable `std::simd`
(u32×16) with a hand-written NEON kernel for the hot M31 multiply
(`vqdmull_s32`); Blake2s Merkle + PoW grind are portable SIMD that
lowers to NEON; zkpvm itself has no intrinsics. Setup-level items:

- Nightly toolchain per `rust-toolchain.toml` (portable_simd) for the
  aarch64 target; NDK/iOS clang for `blst` (unavoidable via javm →
  grey-crypto, ships aarch64 asm).
- `.cargo/config.toml` scopes `target-cpu=native` to the host triple
  (`[target.x86_64-unknown-linux-gnu]`) so cross-builds see clean
  flags, and pre-wires the `aarch64-unknown-linux-gnu` linker; the
  Android section is commented (NDK paths are machine-specific). PGO
  profile is x86-trained; retrain on-device.
- MOBILE PcsPolicy is doubly right on ARM (4× smaller committed domain
  = compute *and* LPDDR-bandwidth relief); STANDARD and MOBILE are the
  same 96 conjectured bits (20 PoW + blowup·queries = 76).
- Expect Blake2s/Merkle's share of prove time to rise vs x86 (portable
  SIMD pays the 128-bit width tax; the M31 mul degrades less).

### Cross-compile recipe (x86_64 Linux host → aarch64-unknown-linux-gnu)

The no-device half is landed and verified: `zkpvm --features prover`
and `prover-extension` cross-`check` clean, and `mobile_bench` (the
on-device artifact, `zkpvm/src/bin/mobile_bench.rs`) links and runs
under qemu-user with the proof *verifying* — an end-to-end correctness
gate for the portable-SIMD/NEON prover path on ARM.

Host prerequisites (Arch/Manjaro package names):

- `aarch64-linux-gnu-gcc` — the linker (`.cargo/config.toml` names it)
  and the C compiler the `cc` crate auto-finds on PATH for blst's
  aarch64 asm/C. Alternative without cross-gcc: clang via
  `CC_aarch64_unknown_linux_gnu=clang`
  `CFLAGS_aarch64_unknown_linux_gnu=--target=aarch64-unknown-linux-gnu`.
- `qemu-user` (optional) — `qemu-aarch64` for an emulated smoke run;
  the cross-gcc package ships the `/usr/aarch64-linux-gnu` sysroot.

From a clean checkout (rust-toolchain.toml pins the nightly; rustup
installs the target into it):

    rustup target add aarch64-unknown-linux-gnu
    cargo check -p zkpvm --features prover --target aarch64-unknown-linux-gnu
    cargo check -p prover-extension --target aarch64-unknown-linux-gnu
    cargo build --release -p zkpvm --bin mobile_bench \
        --target aarch64-unknown-linux-gnu

Emulated smoke (correctness only — qemu timings are meaningless):

    qemu-aarch64 -L /usr/aarch64-linux-gnu \
        target/aarch64-unknown-linux-gnu/release/mobile_bench 8

On the device: push
`target/aarch64-unknown-linux-gnu/release/mobile_bench` and run
`./mobile_bench 14` (arg = log₂ steps). It traces, proves under the
MOBILE config, verifies, and prints per-stage wall-clock plus peak RSS
(`VmHWM`). Reference x86 point to beat (Core Ultra 7 155H,
target-cpu=native, idle box): log14 prove ≈ 1.7 s, peak RSS 1.3 GiB —
and note the number is badly load-sensitive (~10× under a saturated
box), so bench on an idle, cooled phone. The glibc binary runs on
linux-gnu userlands (Termux glibc / proot included); stock Android
needs `--target aarch64-linux-android` with the NDK clang linker (see
the commented section in `.cargo/config.toml`).

## Deferred single-proof / prover levers

From the single-proof latency path (tap-to-pay scale, ~24k steps),
consciously deprioritised — revisit only on a concrete requirement:

- **B4: chip-local helper relocation** — move DivRem/Mul-only helpers
  out of CpuChip. Win small (2-5%) and only on workloads that don't
  exercise the relocated chip; tap-to-pay uses every chip already.
- **C7: NAF-w4 variable-base scalar mult** — tap-to-pay is fixed-base
  only (comb chip); defensive future-proofing for variable-base
  workloads only.
- **D9: GPU Merkle commit** — 2–4× on commit stages but a server-side
  win; wrong shape for mobile-first tap-to-pay UX.
- **D10: alternate Merkle hash (Poseidon, Blake3)** — Stwo ships no
  non-Blake2s `MerkleChannel`; Blake2s has SHA-NI on the test bench, so
  the win is workload-dependent and coordination-heavy.
- **E11: segmented + recursive aggregation** — months of work; the
  right call only when single-shot payments outgrow a comfortable proof.

(The single-proof STANDARD/MOBILE bench numbers, the B5/B6 ledger-merge
findings, and Item 3.3 Plonkish-memory analysis are in git history —
`git log` on the deleted `PERF_ROADMAP.md`.)

## Upstream Stwo issues to file

Two issue drafts existed in-tree ("do not file from here"); their full
bodies + reproducers are in git history (deleted
`STWO_UPSTREAM_ISSUE_DRAFT.md` and
`STWO_MERKLE_LIFTED_OOB_ISSUE_DRAFT.md`). Filing deferred until the
project is live and well-tested; neither blocks us today.

- **Lifted protocol: degree-≥2 AIRs unsupported.** In v2.x all proving
  goes through `vcs_lifted`, whose `MerkleChannel` currently rejects
  AIRs with `LOG_CONSTRAINT_DEGREE_BOUND ≥ 2` ("not supported yet in the
  lifted protocol"; Poseidon `#[ignore]`s on it). Five of our chips are
  bound 2–3 (Blake2b, Mul, Cpu, DivRem, Ristretto), so this blocks the
  2.2.0 perf-cluster migration. Ask: is degree-≥2 support tracked / an
  ETA / a sanctioned interim path? (Flattening to bound 1 with helper
  columns is ~6–8 person-weeks across the 5 chips.)
- **Mixed-width Merkle OOB.** `MerkleProverLifted::decommit` panics with
  an index-OOB (`len N idx N+`) on small / mixed-width column traces
  (algebraic check passes; failure is at FRI decommit). The query-index
  formula uses `max_log_size = layers.len()-1 == lifting_log_size`, not
  the largest column's log size, so mixed sizes 1/8/16/64/128 in one
  component overrun the smallest column. None of upstream's examples use
  mixed-width traces, so the path looks under-exercised. Ask: documented
  constraint on column-size profile vs `lifting_log_size`, or a real
  bug? (Our bound-1 flatten + chip-isolated bench shape sidesteps both.)

## Measured dead-ends (don't re-tread)

Levers built or swept and killed by numbers — preserved so they aren't
re-attempted:

- **Smaller segments / uniform windowing — stalls, not scales.** Sweep
  over seg_steps ∈ {8k, 12k, 16k, 100k} (federation-fixture witness,
  7.72M steps, x86 desktop, dense derived floors):

  | seg_steps | segments | derive | probe prove | probe peak RSS |
  |---|---|---|---|---|
  | 8k | 965 | 968 s | 11–19 s | **~10–11 GiB** |
  | 12k | 644 | 702 s | 14–32 s (load-contaminated) | ~11 GiB |
  | 16k | 483 | 555 s | 10–16 s | ~11–12 GiB |
  | 100k | 78 | 133 s | 22–30 s | ~28–29 GiB |

  BLAKE2B_BOUNDARY is 88.8% of committed bytes and floors at ~2^17 in
  every window regardless of cut. Content-aware page budgeting doesn't
  help either: the worst window touches only **26 distinct pages** at
  any budget, and the cost is **~10k boundary rows PER TOUCHED PAGE** —
  no segmentation strategy (uniform or budgeted) pushes the boundary
  chip below ~2^17 on its own. The fix was the per-page-cost diet
  (EmitMult dedup + width diet), not window placement.

- **Smaller Merkle leaf unit — path-dominated.** At the (32k, 8) cut,
  finer leaves shrink leaf-image compressions but multiply Merkle PATHS
  (more leaves × deeper tree); sampled windows show S=1024/512/256 all
  at or above the 4 KB rows even before node dedup. Post-dedup the
  boundary floor is PATH-dominated (~20 levels × 96 rows × 2 passes per
  touched page), which leaf granularity cannot touch. Dropped.

- **Recompute-LDE-from-coeffs stwo fork — −9.6% RAM for ~+75% time.**
  Built on `olanod/stwo` branch `lde-recompute` (one commit `0b4377a`
  over upstream `e1286720`; **local, unpushed, parked at
  `~/src/gh/stwo`**; NOT wired into master). Opt-in `set_stream_lde()`:
  `Poly.evals` becomes resident/released, each tree's buffers return to
  the pool right after its Merkle root, FRI quotients recompute from
  coeffs in 64-column chunks. Proof bytes identical streaming vs not.
  **Measured (seg 0, uniform-100k, pinned profile, 62 GiB box): 32.5 →
  29.4 GiB (−9.6%) at +64–86% prove time.** Two premises were wrong: (a)
  lifted-Merkle commit needs a WHOLE tree's columns resident at once, so
  post-commit release converts sum-of-trees to max-tree — and under
  canonical forcing the largest (interaction) tree is a hard floor; (b)
  a ~26 GiB plateau (side-note, interaction-gen inputs, coeffs, in-flight
  tree) sits under the LDE term. Violates both-axes; not shipped. The
  release machinery is kept as substrate for row-chunked lifted-Merkle
  leaf hashing (the real Wave-4 increment — a different, mostly-new
  change).

- **C1 per-compression sub-chip — payoff collapsed post-C2.** Originally
  projected ~2.5 GiB (pre-C2). C2 already captured most of it (halved
  the AND-derived interaction fractions, removed 512 main limbs/row), so
  C1's incremental payoff fell to **~0.45 GiB** (clean part). NO-GO
  because the gated columns are entangled with per-row state: the output
  derivation needs `V_after` (row-95 G-function final state, not a
  stored column), forcing a wide ~329-limb balance-registered link; a
  boundary-only clean hoist nets only ~457 MiB (~5% of a ~9.5 GiB
  window) for a new chip + full re-pin; and the main chip's larger share
  needs the soundness-risky, coupled ECALL memory-binding hoist (its 64
  output-writes CONSUME `Output`). Not forced under both-axes /
  no-soundness-risk guidance. If a ~0.45 GiB clean lever is ever wanted,
  the boundary-only output-derivation sibling dodges the ECALL coupling.

## What NOT to pursue

- **GPU**: icicle-stwo is a stale CUDA-only fork with no lookup support
  (fatal for LogUp); ICICLE's Metal backend is production-licensed and
  never wired to stwo; no Vulkan path. Re-evaluate only for server-side
  aggregation.
- **Native STARK recursion**: dead, measured (see
  `../design/recursion-decision.md`). Watch `starkware-libs/stwo-circuits`
  — if a generic verifier-AIR materializes upstream, the verdict could
  reopen.
- **Blowup below 2** / query inflation: at the soundness margin, larger
  proofs, saves only 2× where the RAM seams save 10×+.
- **Wholesale re-architecture** (sum-check/jagged PCS à la SP1
  Hypercube): removes FRI entirely; wrong trade while the FRI stack
  meets the envelope.

## Honest wall-clock picture

Chain proving on phones is a per-page-cost outcome, not a segmentation
one: every window touches a handful of pages and each page costs ~10k
rows on the 2502-column boundary chip. Even once RAM fits, 7.6M steps at
phone throughput is an hour-plus of background work (x86 desktop: ~32
min at 100k windows). That is the intended shape — the roadmap treats
chain proving as an async job per settlement window, off the hot path.
The interactive, sub-10 s mobile story is the tap-to-pay-scale single
proof, which FibRace independently validates at our exact
field/prover/security point. Also budget for chain *transport* if
windows ever shrink: ~600 segments × ~3 MiB ≈ 1.8 GB per full
conservation proof — streaming verify handles the RAM, but network cost
pushes toward fewer/bigger settlement windows and, eventually,
succinct-witness step reduction.

## Benchmark methodology

Single-proof + per-stage benchmark methodology (7-trial median protocol,
STANDARD vs MOBILE stage breakdowns, opcode-mix profiles) is in git
history — regenerate the current numbers with the `prove` / `actors`
benches (`cargo test -p zkpvm --release --test prove_vos_actor
profile_clerk_private_pay_bench{,_mobile} -- --exact --nocapture`, 7
trials, discard the cold trial, take the median). The current chain
numbers live in Status above.
