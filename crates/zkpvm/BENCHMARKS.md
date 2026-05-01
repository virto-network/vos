# zkpvm — performance benchmarks

A snapshot of where zkpvm sits at branch tip `1e6b59f` (post-
Phase-50), measured single-threaded on a desktop CPU.  Numbers
are reproducible — see "Reproducing" at the bottom.

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

| log_size | steps    | trace gen | prove    | verify   | total    | proof size |
|---       |---       |---        |---       |---       |---       |---         |
| 10       | 1 024    | 0.41 ms   | 963 ms   | 68 ms    | 1.03 s   | 499 KB     |
| 12       | 4 096    | 0.57 ms   | 2.70 s   | 264 ms   | 2.96 s   | 547 KB     |
| 14       | 16 384   | 3.10 ms   | 12.92 s  | 1.29 s   | 14.21 s  | 576 KB     |

Per-step proving throughput stabilises around **1 000–1 500 PVM
steps/sec/thread** in the log_size 10–14 range.  Below log_size
10 per-chip fixed overhead dominates (the lookup-table chips
have minimum sizes regardless of step count).  Above log_size
14 we run out of memory on a 16 GB machine — `bench_prove_log16`
is `#[ignore]`d for that reason.

### Per-stage breakdown at log_size = 14

`prove_profiled` decomposes the prove call into six stages.
At 16 384 steps:

| Stage              | Time     | Share |
|---                 |---       |---    |
| trace_gen          | 191 ms   | 1%    |
| preprocess_commit  | 1.16 s   | 9%    |
| main_commit        | 4.72 s   | 35%   |
| interaction_gen    | 620 ms   | 5%    |
| interaction_commit | 1.70 s   | 13%   |
| stark_prove (FRI)  | 4.92 s   | 37%   |
| **total**          | 13.31 s  | 100%  |

The two big costs (main commit + FRI prove) are stwo's, not
zkpvm's — proving cost scales directly with the committed-trace
size.  Trace generation is <1% of the total: zkpvm's per-step
witness fill is essentially free relative to the cryptography.

Trace shape at log_size = 14:
- 14 chip components, log_sizes
  `[15, 4, 4, 4, 16, 4, 4, 16, 4, 8, 8, 6, 8, 8]`
  (CpuChip + Blake2b + Memory + boundary chips + lookup tables).
- 3 034 main-trace columns, 1 564 interaction-trace columns
  (≈9.3 columns per active per-row constraint, similar to
  Nexus's RISC-V CpuChip column count).

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

## Comparison to Nexus zkVM 2.x

zkpvm shares a backend with Nexus zkVM 2.0+ (both Stwo-backed
Circle-STARK over M31).  Direct cycles-per-second comparisons
aren't apples-to-apples because:

- **Different ISAs**: Nexus zkVM proves RISC-V; zkpvm proves
  PVM.  PVM is variable-length (1–13 bytes per instruction)
  with a 13-register file and ECALL-based precompiles, where
  RISC-V is fixed-length 32-bit with a 32-register file.  One
  PVM step does more useful work than one RISC-V cycle.

- **Different chip layouts**: Nexus's CpuChip width and ours
  diverge — both have ~9 columns per active per-row constraint,
  but the *count* of active constraints differs because the
  per-instruction semantics differ.

A fair comparison metric is **trace cells committed per second**
(main_columns × rows / prove_time), which factors out the
ISA-shape difference:

| zkpvm @ log14 | 3 034 cols × 16 384 rows / 12.92 s | ≈3.85 M cells/sec/thread |
|---|---|---|

Nexus zkVM 2.0 announcement (Aug 2024) reported **~25 M
cells/sec/thread** on similar hardware for their RISC-V CpuChip
in the same Stwo backend.  zkpvm at this branch tip is roughly
**6–7× slower per cell**.

Where the gap comes from (in priority order):

1. **Multi-chip overhead**.  zkpvm has 14 chip components, each
   with its own preprocessed + main + interaction commitment.
   The smallest chips contribute fixed overhead per stage that
   doesn't amortise over a long execution.  At log14 the
   CpuChip is 16K rows but ProgramMemoryChip + MemoryChip are
   both 65K rows (log_size 16) because they're sized by the
   address space, not the step count.  Nexus consolidates more
   of the per-step semantics into one wider CpuChip.
2. **Lookup-pair-shape padding**.  Some constraints we
   currently ship as paired emissions (multiplicity = is_real
   per row, twice) for parity rather than as single-emission
   columns.  Each redundant column is full-size; cell count
   inflates without adding constraints.
3. **Per-row column count drift**.  As Phases 32–41 closed
   soundness gaps, the CpuChip column count grew from ~80
   (Phase 1) to 3 034 today.  Some of those columns are
   compute-once-use-once — they could fold into expression-
   level operations if the constraint framework supported it
   without breaking degree bounds.

In other words, the gap is structural (ISA breadth, chip count)
plus historical (column-count growth without periodic culling).
None of it is fundamental — a future "wide CpuChip"
consolidation phase could close most of it.  The current numbers
are good enough for Kunekt-internal use (actor proving in single
seconds for small actors, low-tens-of-seconds for substantial
ones) and the trajectory is favourable.

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
