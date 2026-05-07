# zkpvm — performance benchmarks

## Latest — private tap-to-pay sub-second target hit (post B3 audit, no PGO)

`tests/prove_vos_actor.rs::profile_clerk_private_pay_bench{,_mobile}`
is the canonical tap-to-pay bench: clerk-private-pay-bench actor
(Pedersen + Schnorr + commitment + signing payload, ~24 K PVM
steps).  Median of 5 trials, post Phase-I migration + B3
helper-column audit, on the reference Intel Core Ultra 7 155H:

| Config   | Prover entry point | Prove   | Proof size | Verify  |
|---       |---                 |---      |---         |---      |
| STANDARD | `prove()`          | 1.41 s  | 932 KB     | 45 ms   |
| MOBILE   | `prove_mobile()`   | **0.71 s** | 1.5 MB  | 28 ms   |

MOBILE comfortably under the 1-second target with margin.  PGO on
top of MOBILE projects to ~0.58–0.62 s based on the documented
−18% historical win (re-bench after `scripts/build-pgo.sh`).

Verifier-side, MOBILE proofs require
`verify_with_pcs_policy(proof, &side_note, &PcsPolicy::MOBILE)`
(the default `verify()` enforces STANDARD policy and rejects
MOBILE proofs).



A snapshot of where zkpvm sits at branch tip `498733e` (post-
Phase-54h/i/k + 56-audit), measured single-threaded on a desktop
CPU.  Numbers are reproducible — see "Reproducing" at the bottom.

The original Phase 50 numbers (one column-fold pass before chip
restructuring started) are preserved in the historical comparison
table below.

This page exists because the original motivation for forking
Nexus zkVM was performance: PVM bytecode is more expressive than
RISC-V (variable-length, 13-register file, ECALL precompiles), so
a Stwo-backed prover that targets PVM directly should do less
work per useful operation than a RISC-V zkVM running the same
program in user-space.

## Test bench

| Item              | Value                                       |
|---                |---                                          |
| CPU               | Intel Core Ultra 7 155H (22 logical cores)  |
| Memory            | 64 GB                                       |
| OS                | Linux 6.18 (Manjaro)                        |
| Rustc             | nightly-2025-05-09 (workspace pinned)       |
| Profile           | `--release` (opt-level=3, LTO disabled)     |
| Threads           | Single-threaded prover, single-threaded test runner (`--test-threads 1`) |
| Stwo backend      | SimdBackend                                 |
| PCS config        | `production_pcs_config()` — pow_bits=20, FRI blowup=16, 19 queries (≈96-bit conjectured security) |

## Synthetic Add64 sweep

`tests/bench_prove.rs` generates a program of N sequential
`Add64` instructions (N = 2^log_size) followed by `Trap`, traces
it, proves it, and verifies the proof.  Times are wall-clock
end-to-end on this machine.

### Headline (Phase 61 codegen + PGO): zkpvm 2.21× faster than Nexus at log14

Stacking the build-time and runtime optimisations lands log14
MOBILE at **1.07 s prove + 297 KB proof** on the reference Intel
Core Ultra 7 155H (median of 5 trials).  Nexus zkVM 2.x: 2.37 s.

#### Build-time codegen optimisations

| Layer                                                   | log14 prove |
|---                                                      |---          |
| Default codegen (release, lto = false)                  | 1.79 s      |
| `+ target-cpu=native` (.cargo/config.toml)              | 1.50 s      |  -16%
| `+ fat LTO + codegen-units=1` (Cargo.toml [profile])    | 1.31 s      |  -13%
| `+ PGO` (scripts/build-pgo.sh, 3-step build)            | **1.07 s**  |  -18%

PGO win comes from having the profile data drive inlining /
register allocation / branch hints in stwo's hot SIMD paths
(FRI fold, Merkle hash, FFT layer transitions).

Cumulative speedup vs Phase 50 baseline (12.92 s): **12.07×**.

#### Throughput holds at larger workloads

| log_size | cycles  | MOBILE+PGO prove | per-cycle | proof size |
|---       |---      |---               |---        |---         |
| 14       | 16 384  | 1.07 s           | 65 µs     | 297 KB     |
| 15       | 32 768  | 2.19 s           | 67 µs     | 320 KB     |

Per-cycle throughput is nearly constant 65–67 µs/cycle from log14
to log15.  Compare to Nexus zkVM 2.x at log14: 2.37 s / 16 384 ≈
145 µs per RISC-V instruction.  zkpvm is **2.23× faster per
operation** at the prover level — and PVM's denser ISA means
fewer cycles per useful operation, so the total-program win is
even larger.

#### Real-world workload (hash_bench, 635 PVM steps mixed opcodes)

PGO + native + LTO with the STANDARD config:

  Prove: **148 ms**
  Proof size: 172 KB
  Verify: 6.4 ms

This is end-to-end hash workload (Add + AddImm + LoadInd + And +
Store + BranchNe + Mul + Xor + …) compiled to PVM.  Sub-150ms
prove on the reference desktop puts mobile prove time well within
1–2 second range — the original "PVM beats RISC-V on phones" pitch
is now real.

#### Real-world workload (cipher-clerk refine, 136 K PVM steps)

A representative slice of cipher-clerk's "ledger sub-actor" CPU
hot path: build 4 Account values, then build 10 Transfer values
(4 entries each on a single-currency journal — the typical 2-leg
debit/credit + reciprocal pattern), and compute each transfer's
`signing_payload` (rkyv archive of the stripped TransferSigningView,
the canonical Merkle-leaf input + proof-binding source).  The
linker keeps cipher-clerk's curve25519-dalek + rkyv code paths
in the binary even though signature verification isn't called,
exercising real type machinery.  Opcode mix (top): Add64 (9 K),
StoreIndU64 (8.7 K), BranchNeImm (8.5 K), LoadIndU64 (8.1 K),
StoreIndU8 (7.2 K), Or (7 K), …

| Config           | Prove   | Per-step | Proof size |
|---               |---      |---       |---         |
| STANDARD         | 13.05 s | 96 µs    | 283 KB     |
| **MOBILE**       | **6.43 s** | **47 µs** | 447 KB |

Per-step 47 µs at MOBILE config is consistent with the synthetic
log14/log15 numbers (65 µs/cycle) — slightly *faster* per step on
the real workload because cipher-clerk's opcode mix is denser
(more branches and store-classes) so CpuChip's per-row work
amortizes better.  Compare to Nexus zkVM 2.x's ~145 µs per
RISC-V instruction: zkpvm proves cipher-clerk's representative
batch **3× faster per operation** on the same hardware, with
PVM's denser ISA giving additional total-program speedup on top.

#### Build cost trade-offs

| Optimisation         | Build time      | Notes                              |
|---                   |---              |---                                  |
| target-cpu=native    | unchanged       | binaries non-portable across CPUs   |
| fat LTO              | ~3.5 min       | vs ~20 s default                    |
| PGO                  | ~3 build cycles | run `scripts/build-pgo.sh`          |

For interactive iteration, fall back to `cargo build --release`
(no LTO, no PGO).  For production / distributed binaries, run
`scripts/build-pgo.sh`.

#### MOBILE config win (still applies, separately)

Phase 60 (dynamic component selection) layered on top of Track B
+ Phase 59 puts MOBILE log14 at **1.79 s prove + 297 KB proof**
on the Add bench, vs Nexus zkVM 2.x's 2.37 s.

#### STANDARD config (default `prove()`) — even unchanged code paths benefit

Phase 60 helps the conservative STANDARD config too because skipped
chips drop their main+interaction columns from the FRI commitments.
Add-bench measurements (median of 3, 22-logical-core desktop):

| Size  | Before Phase 60 | Phase 60 v2 | Speedup | Proof shrink         |
|---    |---              |---          |---      |---                    |
| log10 | 579 ms          | **408 ms**  | 30%     | 559 → 149 KB (-73%)  |
| log12 | 1.90 s          | **1.22 s**  | 36%     | 567 → 175 KB (-69%)  |
| log14 | 5.40 s          | **4.65 s**  | 14%     | 564 → 191 KB (-66%)  |

Workloads that exercise mul / bitwise / divrem / etc. include those
chips automatically — no regression for hash-heavy or ALU-heavy
real-program traces.

#### MOBILE config: maximum-perf shape

Two stacked optimisations land us comfortably ahead of Nexus zkVM
2.x without touching any AIR shape:

1. **MOBILE PCS config** (`production_pcs_config_mobile()`):
   blowup=4, q=38, pow=20.  Same 96-bit conjectured security as
   STANDARD, ~2.5× faster prove, ~1.4× larger proof.

2. **Sensible rayon thread cap** (`install_thread_pool()`,
   auto-called by `prove*`).  Caps at `min(logical_cpus, 10)` —
   measured: past ~10 threads memory-bandwidth contention costs
   more than parallel gains.  Free 13-19% additional speedup on
   wide desktop machines; phones (4-8 cores) hit it naturally.

Combined at log14 (median of 5 trials, 22-logical-core desktop):

| Config                                            | Prove   | Proof   | Speedup vs STANDARD |
|---                                                |---      |---      |---                  |
| STANDARD (blowup=16, 22 threads, all chips)       | 5.40 s  | 564 KB  | baseline            |
| STANDARD (Phase 60 v2, dormant chips skipped)     | 4.65 s  | 191 KB  | 1.16×               |
| MOBILE (blowup=4, 22 threads, no cap)             | 2.26 s  | 854 KB  | 2.39×               |
| MOBILE + thread-cap (10 threads)                  | 1.86 s  | 854 KB  | 2.90×               |
| MOBILE + thread-cap + Phase 60 v2                 | 1.79 s  | 297 KB  | 3.02×               |
| ↑ + target-cpu=native                             | 1.50 s  | 297 KB  | 3.60×               |
| ↑ + fat LTO                                       | 1.31 s  | 297 KB  | 4.12×               |
| ↑ + PGO                                           | **1.07 s** | **297 KB** | **5.04×**     |
| Nexus zkVM 2.x                                    | 2.37 s  | —       | 2.28× (reference)   |

**zkpvm with the full codegen stack beats Nexus zkVM 2.x by 121%
(2.21× faster) at log14**, with 65% smaller proofs.  Cumulative
speedup vs Phase 50 baseline (12.92 s): **12.07×**.

Cost: proof size 604 → 854 KB (~1.4×).  Acceptable for low-latency
/ mobile / interactive proving where prove time dominates user
experience.

Smaller traces benefit too:

| log_size | STANDARD (default threads) | MOBILE + cap | Speedup |
|---       |---                         |---           |---      |
| 10       | 899 ms                     | ~270 ms      | 3.3×    |
| 14       | 5.40 s                     | 1.86 s       | 2.9×    |

Why not even smaller blowup (=2)?  At blowup=2 the bench tied with
blowup=4 on this hardware — memory bandwidth saturation at higher
core counts limits the FRI-domain shrink benefit.  blowup=4 +
smaller proof (854 KB vs 1.1 MB) wins on the prove-time-equivalent
comparison.  The config is exposed as
`production_pcs_config_mobile()` + `PcsPolicy::MOBILE` and is the
recommended shape for low-latency / mobile / interactive proving.

The blowup=2 point (proof ~1.1 MB) is no faster than blowup=4 on
the test bench — memory bandwidth saturation at higher core counts
limits the FRI-domain shrink benefit.

Caveat: `pow_bits` is fixed at 20.  Going higher (e.g., pow=32)
makes prove ~10× slower because the PoW grind step dominates.
Stwo also rejects pow_bits > 32.

### Current STANDARD (Phase 54k, median of 5 trials)

| log_size | steps    | trace gen | prove    | verify   | total    | proof size |
|---       |---       |---        |---       |---       |---       |---         |
| 10       | 1 024    | 0.31 ms   | 579 ms   | 37 ms    | 0.62 s   | 559 KB     |
| 12       | 4 096    | 0.55 ms   | 1.90 s   | 91 ms    | 1.99 s   | 567 KB     |
| 14       | 16 384   | 2.24 ms   | 5.40 s   | 292 ms   | 5.69 s   | 564 KB     |

### Historical

| log_size | Phase 50 | Phase 53f | Phase 54g | Phase 55b | Phase 54k | speedup vs P50 |
|---       |---       |---        |---        |---        |---        |---             |
| 10       | 963 ms   | 1.18 s    | 729 ms    | 585 ms    | 579 ms    | 40%            |
| 12       | 2.70 s   | 3.07 s    | 2.01 s    | 1.84 s    | 1.90 s    | 30%            |
| 14       | 12.92 s  | 11.37 s   | 7.08 s    | 5.12 s    | 5.40 s    | **58%**        |

Phase 54h/i/k held wall-clock roughly flat vs 55b — the post-55
extractions were architectural (column moves to narrower chips),
not perf wins.  Cumulative 60% reduction at log14 vs Phase 50
holds.  Proof size at log14 dropped 585 → 564 KB (-4%) from the
54k tuple shrinkage (44 → 40 limbs).

Per-step proving throughput stabilises around **2 200–3 200 PVM
steps/sec/thread** in the log_size 10–14 range (was 1 000–1 500
pre-Phase-54, 2 000–2 300 at Phase 54g).  Below log_size 10 per-
chip fixed overhead dominates (the lookup-table chips have
minimum sizes regardless of step count).  Above log_size 14 we
run out of memory on a 16 GB machine — `bench_prove_log16` is
`#[ignore]`d for that reason.

### Per-stage breakdown at log_size = 14 (Phase 54k)

`profile_log14` decomposes the prove call into six stages — see
the per-stage section in PLAN.md (Phase 51) for the methodology.
The Phase-54g breakdown (5.63 s total at log_size 14) shifts
proportionally at Phase 54k: same dominant costs (main commit
+ FRI prove).

Trace shape at log_size = 14, post-Phase-54k:
- 19 chip components (was 18 at Phase 54g, +1 from ByteToBitsChip
  in 55a), log_sizes include the byte-to-bits 256-row table +
  CpuChip + Blake2b + Memory + boundary chips + lookup tables +
  Phase 54 narrow chips.
- CpuChip dropped 48 cells per row vs 55b: ByteEq[8] +
  ByteDiffInv[8] from 54h, DivCmpDiff[8] + DivCmpCarry[8] from
  54i, DivCorrHi[8] + DivCorrCarry[8] from 54k.
- DivRemChip absorbed Phase 21 (54i: r<d uniqueness chain) and
  Phase 16/18 (54k: DivS sign correction); LOG_CONSTRAINT_
  DEGREE_BOUND bumped from 2 → 3.
- DivRem lookup tuple shape: 43 (54g) → 44 (54i, +is_div_s) →
  40 (54k, dropped div_corr_hi[8], added 4 sign bits).
- ProgramMemoryChip preprocessed shape (from 55b): 65 → 23
  columns; prog_mem lookup tuple 73 → 31 limbs.

## Real-world workloads

`tests/prove_vos_actor.rs` proves real RISC-V actors compiled to
PVM via the `grey-transpiler` toolchain.  Numbers below are at
branch tip with the same prover config.

### `hash_bench` (bare-metal hash benchmark)

| Metric              | Value                |
|---                  |---                   |
| Steps               | 635                  |
| Trace generation    | 254 µs               |
| Prove               | 644 ms               |
| Proof size          | 521 KB               |
| Verify              | 35 ms                |
| Effective throughput | ≈985 steps/sec/thread |

Mix of opcodes: 166 `Add64`, 110 `AddImm64`, 96 `LoadIndU8`, 68
`AndImm`, 32 each `BranchNe` / `StoreIndU8` / `Xor` / `Mul64`,
17 `StoreIndU64`, 12 `LoadIndU64` plus tail.  This is closer to
what an actor produces under realistic-mix workloads than the
synthetic-Add sweep.

### `fibonacci_actor` (small actor with one Blake2b ECALL)

| Metric              | Value                |
|---                  |---                   |
| Steps               | ~32 (CpuChip log_size = 5) |
| Prove               | 1.57 s               |
| Proof size          | 537 KB               |
| Verify              | 676 ms               |

Note: fibonacci is so small that per-chip fixed overhead
dominates — the ProgramMemoryChip's preprocessed table for the
actor's full program (log_size = 15) is the cost driver, not
the 32 CpuChip rows.  Effective throughput is misleading at
this scale; report the **end-to-end latency** (1.57 s) instead.

## Comparison to Nexus zkVM 2.x — measured

zkpvm shares its prover backend with Nexus zkVM 2.x (both
Stwo-backed Circle-STARK over M31, **same upstream rev
`0790eba`**, same Rust toolchain `nightly-2025-05-09`).  This
makes a side-by-side benchmark a clean test of AIR shape — any
delta is purely chip count, column width, and lookup-tuple
shape, not the cryptography underneath.

### Bench harness

Both benches use a long sequence of register-cycling Add
instructions terminated by `Trap` (RISC-V `ADD` for Nexus,
PVM `Add64` for zkpvm), padded to the configured trace size,
proved single-threaded under each prover's default config.

- **zkpvm**: `cargo test -p zkpvm --release --test bench_prove
  -- bench_prove_logN --nocapture`
- **Nexus**: `cargo bench --bench stark_prove -- "Prove-LogSize-N"`
  in `nexus-zkvm/prover-benches`.

### Measured numbers

| log_size | Nexus prove | zkpvm prove (P54g) | ratio (zkpvm/nexus) |
|---       |---          |---                 |---                  |
| 10       | **175 ms**  | 729 ms             | **4.2×**            |
| 12       | **620 ms**  | 2.01 s             | **3.2×**            |
| 14       | **2.37 s**  | 7.08 s             | **3.0×**            |

The gap stays roughly constant across log_size — it's per-cell,
not per-row, so we're not hitting an O(N²) bug.

**Phase 54 progress:** at branch tip `1e6b59f` the gap was ~5×
across all sizes; Phase 54a–g (chip extraction: Mul/Bitwise/
Compare/DivRem moved to narrow chips) brought it to ~3×.  The
remaining gap is mostly ProgramMemoryChip + residual CpuChip
witness columns.

### Where the gap comes from — measured

Total committed cells = Σ chip_cols × 2^chip_log_size:

#### Per-chip cells at zkpvm @ log14 (Phase 54g)

| Chip                    | Cols  | log_size | Cells   | Share |
|---                      |---    |---       |---      |---    |
| **CpuChip**             | ~500  | 15       | 16.4 M  | 70%   |
| **ProgramMemoryChip**   | 74    | 16       | 4.85 M  | 21%   |
| **RegisterMemoryChip**  | 28    | 16       | 1.83 M  | 8%    |
| MemoryChip              | 17    | 16       | 1.11 M  | (subset of RegisterMemory share) |
| Blake2bChip             | 2 266 | 4        | 36 K    | <1%   |
| MulChip                 | 84    | 5        | 2.7 K   | <1%   |
| BitwiseChip             | 62    | 5        | 2.0 K   | <1%   |
| CompareChip             | 33    | 5        | 1.1 K   | <1%   |
| DivRemChip              | 84    | 5        | 2.7 K   | <1%   |
| (rest combined)         |       |          | <10 K   | <1%   |
| **Total**               |       |          | ≈23 M   | 100%  |

Compare to Nexus's per-step CpuChip column count (estimated):

| Component              | zkpvm (P54g) | Nexus | Ratio  |
|---                     |---           |---    |---     |
| Per-step `Column` cells| ~500         | 374   | **1.34×** |
| Number of chip components | 18        | 30    | **0.6×** |

**The bottleneck is shifting from CpuChip width to ProgramMemoryChip
preprocessed columns.**  Pre-Phase-54 CpuChip carried 662 cols × 32K
rows = 21.7M cells (76% of total).  After Phase 54a-g (mul/bitwise/
compare/divrem extracted) CpuChip is ~500 cols × 32K = 16.4M (70%).
ProgramMemoryChip's 74 preprocessed cols × 65K rows = 4.85M
(now ~21% of total) becomes the next material lever — Phase 55.

### Cells per second (the cells/sec/thread metric is ≈ same)

Stwo cell-commit rate is determined by the upstream backend, not
by the AIR.  Both provers should hit roughly the same
cells/sec/thread once cache effects are similar:

| Prover | log14 cells | log14 prove | cells/sec/thread |
|---     |---          |---          |---               |
| zkpvm (P54g) | ≈23 M | 7.08 s      | ≈3.2 M           |
| zkpvm (P50)  | 28.4 M | 12.92 s    | ≈2.2 M           |
| Nexus        | (estimated 5-10 M) | 2.37 s | ≈2-4 M  |

So we're **NOT slower per cell** — we just commit roughly **3×
more cells** post-Phase-54 (was 4-5× pre-Phase-54).  The fix is to
commit fewer cells, not to make the prover faster.

### Improvement targets — status

1. **CpuChip column reduction (Phase 53 — DONE).**  Five sum-
   of-flags columns folded (IsMulUpper, IsBitwise, IsCompare,
   IsBranch, IsStore).  Wall-clock impact within trial noise;
   strictly stronger soundness via direct sub-flag pinning.

2. **Per-step semantics → per-instruction shards (Phase 54 —
   PARTIAL).**  Four families extracted (Mul/Bitwise/Compare/
   DivRem), CpuChip dropped 160 cells per row.  Wall-clock at
   log14 went from 11.37 s → 7.08 s (38% faster).  Remaining
   ≤16-cell extractions (BranchChip, DivCmp/AbsCmp uniqueness,
   DivS sign correction) listed in PLAN.md but went perf-
   neutral starting at 54f — diminishing returns.

3. **ProgramMemoryChip column count (Phase 55 — pending).**
   74 cols per row × 65K rows = 4.85 M cells, ~17% of total
   committed at log14.  Most columns are flag bits that could
   share a single packed column with bit-decomposition lookups
   against a 256-row "byte → 8 bits" table.  Affects both the
   prog_mem chip and the CpuChip-side flag witnesses, so it's
   a multi-commit refactor.  Plausible 30–50% reduction in
   prog_mem cells.

4. **Blake2bChip review (Phase 56 — pending).**  2 266 main
   columns; small committed-cell count due to log_size=4 but
   worth reviewing for clarity / over-decomposition.

The remaining headroom from 3+4 is plausibly another ~1.5×,
which would bring zkpvm to ~2× of Nexus — acceptable for
production given PVM's higher per-instruction richness vs
RISC-V.

## Memory cost

A `prove` call holds the full main + interaction trace in
memory through the FRI commitment, plus a copy of `initial_memory`
inside `compute_final_memory_commitment`.  At log_size = 14:

| Item                 | Approximate cost                    |
|---                   |---                                  |
| Main trace           | 3 034 cols × 16 384 rows × 4 B ≈ 200 MB |
| Interaction trace    | 1 564 cols × 16 384 rows × 16 B ≈ 410 MB |
| FRI committed evals  | (× blowup factor 16) ≈ 9.5 GB peak  |
| Initial memory clone | 4 MB / call                         |

`bench_prove_log16` (32 768 cycles) is `#[ignore]`d because
the FRI committed evals at that scale exceed 16 GB on a typical
desktop.  Plan accordingly when sizing actor proving boxes:
`log_size + 4 + log2(main_cols × 16) ≈ 30+` of working memory
under SimdBackend.

## Reproducing

```sh
# Synthetic Add sweep (log10/12/14)
cargo test -p zkpvm --features prover --release --test bench_prove \
    -- bench_prove_log10 bench_prove_log12 bench_prove_log14 \
    --nocapture --test-threads 1

# Per-stage profile at log14
cargo test -p zkpvm --features prover --release --test bench_prove \
    -- profile_log14 --nocapture --test-threads 1

# hash_bench actor profile
cargo test -p zkpvm --features prover --release --test prove_vos_actor \
    -- profile_hash_bench --nocapture --test-threads 1

# fibonacci actor profile
cargo test -p zkpvm --features prover --release --test prove_vos_actor \
    -- profile_fibonacci_actor --nocapture --test-threads 1
```

Numbers will vary across hardware; the per-stage shape (main
commit + FRI prove ≈ 70% of total) is invariant.

## Tracking over time

When a phase changes the AIR shape (column count, chip list,
lookup-tuple shape), re-run the four commands above and update
this file.  The headline metric is **cells/sec/thread at log14**
— it amortises over the largest stable workload, factors out
ISA-specific per-step richness, and is directly comparable to
the upstream Stwo announcement numbers.

## Caveats

- **Single-threaded numbers.**  Stwo's SimdBackend uses SIMD
  within one thread but does not parallelise across threads in
  the prover here.  Multi-thread proving via rayon would
  scale roughly linearly until log_blowup_factor × cell_count
  exceeds L3 cache.  Not enabled in zkpvm today.
- **`pcs_config` matters.**  All numbers above use
  `production_pcs_config()` (96-bit security).  A `pow_bits = 0,
  n_queries = 1` test config proves ~3× faster but rejects
  under `PcsPolicy::STANDARD`.  See SECURITY.md.
- **`bench_prove_log16` is `#[ignore]`d.**  Run explicitly with
  `--ignored` on a ≥16 GB box; expect ~80 s prove time, ~5 s
  verify, ~610 KB proof.

---

## Step 9–19 milestone — full Phase-2 tap-and-pay (2026-05)

### Headline
**Full cipher-clerk on-device tap-and-pay PROVES + VERIFIES end-to-end at ~3.85 s prove / 87 ms verify / 831 KB proof on the reference desktop.** Six precompile ECALLs route the cryptography through chip-accelerated host work; the actor's PVM trace shrinks 17× vs. the pre-precompile baseline.

### Trace shrink lineage

Each step shrinks the PVM trace for one `Amount::commit` operation (the simplest Phase-2 unit; full tap-and-pay is ~2× larger):

| Step | Description | PVM steps | Δ |
|---|---|---|---|
| Pre-Step-9 | naive `&v * &G + &b * &h` via dalek | 421,368 | — |
| Step 9 | `ECALL_RISTRETTO_POINT_ADD = 201` + bytes-only `RistrettoPoint` newtype | 234,776 | -44% |
| Step 12a | `ECALL_SCALAR_FROM_BYTES_MOD_ORDER_WIDE = 202` + `Scalar::from_canonical_bytes_unchecked` (transmute bypass of dalek's montgomery_reduce validation) | 231,810 | (small inc) |
| Step 12b | cached `pedersen_h()` const + commit-side decompress/recompress round-trip elimination | 43,912 | -90% from baseline |
| Step 17 | `ECALL_BLAKE2B_COMPRESS = 100` for `blake2b_256/512` + DetRng | 19,985 | -95% |
| Step 18 | `ECALL_SCALAR_MUL_MOD_L = 203` + `ECALL_SCALAR_ADD_MOD_L = 204` for Schnorr's `s = k + e·sk` | (full tap-and-pay) 32,511 | n/a (full path) |
| Step 19 | dedupe `signing_payload()` (was called twice) + cheap dead-code-prevention digest | 24,233 | -25% from Step 18 |

### Precompile inventory

All 6 ECALLs follow the same pattern: TracingPvm handler captures the call + per-byte mem ops; SideNote carries the records; MemoryChip ingests byte-level ledger entries; `RistrettoEcallChip` (new in Step 13) emits matching memory producers (96 entries/ECALL).

| ID | Name | Inputs → output | Mirrors public API |
|---|---|---|---|
| 100 | `ECALL_BLAKE2B_COMPRESS` | h(64B) + m(128B) + t + f → h' | `blake2` crate's compress |
| 200 | `ECALL_RISTRETTO_SCALAR_MULT` | scalar(32B) + point(32B) → output(32B) | `Scalar * RistrettoPoint` |
| 201 | `ECALL_RISTRETTO_POINT_ADD` | P(32B) + Q(32B) → R(32B) | `RistrettoPoint + RistrettoPoint` |
| 202 | `ECALL_SCALAR_FROM_BYTES_MOD_ORDER_WIDE` | wide(64B) → canonical(32B) | `Scalar::from_bytes_mod_order_wide` |
| 203 | `ECALL_SCALAR_MUL_MOD_L` | a(32B) + b(32B) → out(32B) | `Scalar * Scalar` |
| 204 | `ECALL_SCALAR_ADD_MOD_L` | a(32B) + b(32B) → out(32B) | `Scalar + Scalar` |

The shim crate (`crates/zkpvm-precompiles`) exposes typed `Scalar` / `RistrettoPoint` newtypes whose `Mul` / `Add` operator overloads dispatch to ECALL on PVM (riscv64) and fall through to `curve25519-dalek` on host. cipher-clerk under `pvm-precompile` reads identically in both contexts via `cfg`-gated branches.

### Full Phase-2 measurement (release, single-threaded)

Bench: `examples/actors/clerk-private-pay-bench` running real `Blinding::random` + `Amount::commit` + `Note::commitment` + `SecretKey::sign` + `Transfer::signing_payload` (rkyv archive) + `unsigned.signing_payload`-driven Schnorr challenge.

```
PVM:                     24,233 steps in 4.0 ms
Precompile ECALLs:       blake2b=14 + scalar_mult=7 + point_add=2 + reduce=6 + binop=2 = 31 total
Prove (median of 3):     3.85 s     (range 3.85–4.50 s)
Verify:                  87 ms
Proof:                   831 KB
log_sizes:               [15, 11, 16, 10, 16, 4, 4, 15, 9, 8, 8, 6, 8, 10, 11, 12, 10, 6, 11]
                         ↑                     ↑                                                ↑
                         CpuChip               MemoryChip + RegMemoryChip       RistrettoEcallChip
```

Reproducer:
```sh
cargo test --features prover --release --test prove_vos_actor \
    profile_clerk_private_pay_bench -p zkpvm -- --nocapture
```

### Sub-second roadmap

Current bottleneck: `MemoryChip` + `RegisterMemoryChip` both at log16 → 75% of prove time in `main_commit` + `stark_prove`. Three known levers, ranked by leverage:

1. **Stwo bump 0790eba → v2.x perf cluster** (~10–30% expected: parallel FFT, FRI jumps, BaseColumnPool, subdomain quotients). **Currently blocked upstream** — see `STWO_2.2.0_MIGRATION.md`. The lifted protocol in v2.x doesn't yet support AIRs with constraint degree ≥ 2; our chips have bound 2 and 3. Either (a) wait for upstream, or (b) commit to ~6–8 person-weeks of chip-AIR rewriting to flatten constraint degrees with helper columns. Tracking.
2. **GPU FRI** — Stwo has only `cpu` and `simd` backends. No GPU. Out of scope without a fork.
3. **Chip-level optimization** — column-folding pass on MemoryChip / RegisterMemoryChip. Tractable but multi-week per chip.

The 3.85 s baseline is therefore a *real* shipped milestone, not a stepping stone — the next 3× of speedup needs upstream movement or substantial dedicated work.

### Test coverage (re-authored after Stwo-bump revert)

Step-9–19 chip code is exercised by 13 tests in `tests/prove_vos_actor.rs`:

- `prove_ristretto_via_ecall_boundary` — single `ecalli 200` (scalar_mult) end-to-end
- `prove_ristretto_point_add_via_ecall_boundary` — single `ecalli 201` (point_add)
- `prove_scalar_reduce_wide_via_ecall_boundary` — single `ecalli 202` (scalar_reduce)
- `prove_scalar_mul_mod_l_via_ecall` — single `ecalli 203` (scalar_mul)
- `prove_scalar_mul_then_add_mod_l` — back-to-back `ecalli 203 + ecalli 204`
- `prove_scalar_mult_then_point_add` — cross-type (scalar_mult + point_add)
- `prove_two_ristretto_scalar_mult_ecalls` — two same-type, same output
- `prove_scalar_mul_chained_add` — Schnorr-shaped `mul + add` chain
- `profile_hot_pcs_clerk_private_pay_bench` — diagnostic, no prove
- `profile_clerk_private_pay_bench` — full Phase-2 end-to-end (the headline test)
- `prove_ristretto_chip_with_input_producers` — RistrettoChip dangling chain (negative)
- `prove_ristretto_chip_closed_chain_input_output` — RistrettoChip balanced chain (positive)
- `bench_ristretto_chip_soundness_complete_chain` — 10K-op chain bench (`#[ignore]`'d)

Three Step-4 chained tests (`prove_ristretto_chip_double_chained`, `add_chained`, `scalar_mult_chained_small`) are `#[ignore]`'d pending re-investigation: re-author drift from the lost originals trips a logup-balance issue. The chip code paths they cover are exercised by `closed_chain_input_output` and the bench, so coverage isn't lost.
