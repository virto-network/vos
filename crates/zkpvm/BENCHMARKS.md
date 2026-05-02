# zkpvm — performance benchmarks

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

### Headline (Track B): mobile config beats Nexus at log14

Switching from `production_pcs_config()` (blowup=16, 19 queries,
20-bit PoW) to `production_pcs_config_mobile()` (blowup=4, 38
queries, 20-bit PoW) — **same 96-bit conjectured security** —
trades proof size for prove speed:

| log_size | STANDARD (blowup=16) | MOBILE (blowup=4) | Speedup | Proof STD → MOBILE |
|---       |---                   |---                |---      |---                  |
| 10       | 899 ms               | **337 ms**        | 2.67×   | 562 → 819 KB        |
| 14       | 5.23 s               | **2.10 s**        | 2.49×   | 604 → 854 KB        |

**zkpvm with MOBILE beats Nexus zkVM 2.x's 2.37 s at log14** —
the first time in this experiment.  The config is exposed as
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
