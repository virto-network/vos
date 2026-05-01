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

| log_size | Nexus prove | zkpvm prove | ratio (zkpvm/nexus) |
|---       |---          |---          |---                  |
| 10       | **175 ms**  | 963 ms      | **5.5×**            |
| 12       | **620 ms**  | 2.70 s      | **4.4×**            |
| 14       | **2.37 s**  | 12.92 s    | **5.4×**            |

The gap stays roughly constant across log_size — it's per-cell,
not per-row, so we're not hitting an O(N²) bug.

### Where the gap comes from — measured

Total committed cells = Σ chip_cols × 2^chip_log_size:

#### Per-chip cells at zkpvm @ log14

| Chip                    | Cols  | log_size | Cells   | Share |
|---                      |---    |---       |---      |---    |
| **CpuChip**             | 662   | 15       | 21.7 M  | 76%   |
| **ProgramMemoryChip**   | 74    | 16       | 4.85 M  | 17%   |
| **RegisterMemoryChip**  | 28    | 16       | 1.83 M  | 6%    |
| Blake2bChip             | 2 266 | 4        | 36 K    | <1%   |
| MemoryChip              | 17    | 16       | 1.11 M  | (folded into RegisterMemory share) |
| (rest combined)         |       |          | <10 K   | <1%   |
| **Total**               |       |          | ≈28.4 M | 100%  |

Compare to Nexus's per-step CpuChip column count:

| Component              | zkpvm | Nexus | Ratio  |
|---                     |---    |---    |---     |
| Per-step `Column` cells| 662   | 374   | **1.77×** |
| Number of chip components | 14 | 30    | **0.47×** |

**The bottleneck is CpuChip width**, not chip count.  Nexus has
*more* chips (30 vs. our 14) but each is narrower because they
split per-instruction semantics across many small chips
(`AddChip`, `SubChip`, `JalrChip`, `BneChip`, …) — each one
constrains its own opcode in its own narrow row.  zkpvm
currently stuffs all per-opcode constraints into one wide
CpuChip (every row carries 662 columns regardless of which
opcode is being proven).

### Cells per second (the cells/sec/thread metric is ≈ same)

Stwo cell-commit rate is determined by the upstream backend, not
by the AIR.  Both provers should hit roughly the same
cells/sec/thread once cache effects are similar:

| Prover | log14 cells | log14 prove | cells/sec/thread |
|---     |---          |---          |---               |
| zkpvm  | 28.4 M      | 12.92 s     | ≈2.2 M           |
| Nexus  | (estimated 5-10 M) | 2.37 s | ≈2-4 M       |

So we're **NOT slower per cell** — we just commit roughly **3-5×
more cells**.  The fix is to commit fewer cells (narrower CpuChip),
not to make the prover faster.

### Concrete improvement targets

In priority order:

1. **CpuChip column reduction (highest impact).**  Audit the 662
   per-row cells for:
   - Compute-once-use-once values that could fold into
     expression-level operations (`val_b[i] * is_add` doesn't
     need its own column if it appears in only one constraint).
   - Paired flag columns that could collapse.  Examples: each
     branch type currently has its own `IsBrEq / IsBrNe / …`
     flag; if no constraint reads them outside the branch
     dispatch, fold into a single multiplexer expression.
   - Boolean sub-flags reachable from `IsCompare` etc. that
     could derive from `(opcode, sub_op)` instead of being
     materialised.
   Target: **−200 columns** brings cell count to ≈21.8 M, prove
   time to ≈10 s at log14.

2. **Per-step semantics → per-instruction shards (the Nexus
   way).**  Following Phase 47's split, lift each opcode family
   into its own narrow chip with row-count = number of opcode-
   matching real rows.  Concretely:
   - `is_add`-gated rows go in `AddChip` (rows = sum of is_add
     across the trace).
   - `is_sub`-gated rows in `SubChip`, etc.
   The CpuChip becomes a per-step skeleton (PC, ts, regs, opcode,
   shared flag fan-out) and the per-opcode logic moves out.
   This is structurally what Nexus does and the reason their
   gaps add up correctly.  ~2-3× reduction in committed cells
   plausible.

3. **ProgramMemoryChip column count.**  74 cols per row × 65K
   rows = 4.85 M cells, 17% of total.  Most of those columns
   are flag bits that could share a single packed column with
   bit-decomposition lookups, similar to what Range256 does.
   Plausible 50% reduction.

4. **Blake2bChip width**.  2 266 main columns is a lot for a
   chip that mostly compresses one block per ECALL.  The
   committed cell count is small (log_size = 4) so this is
   low-priority for pure throughput, but it's the largest
   single column count in the codebase and worth reviewing for
   correctness clarity.

The estimated headroom is **2-3× faster proving** without
touching soundness, which would close the gap to ≈2× of Nexus
— acceptable for production deployment given PVM's higher
per-instruction richness.

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
