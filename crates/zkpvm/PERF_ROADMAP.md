# zkpvm — perf roadmap

State, design notes, and forward-looking items for prover performance.
Implementation history lives in `git log` — this doc is the
"design + decisions + open questions" survivor.

## Current state (post-Session-3, 2026-05-08)

| Config   | Entry point      | Prove   | Proof   | Verify |
|---       |---               |---      |---      |---     |
| STANDARD | `prove()`        | ~3.36 s | 932 KB  |  45 ms |
| MOBILE   | `prove_mobile()` | **0.86 s** | 1.5 MB |  ~150 ms |

Trace shape on `profile_clerk_private_pay_bench_mobile`: 25 active
chips, `main_cols=6415`, `interaction_cols=4008`, log_sizes range
4..16.  One chip remains at log=16 (`MemoryChip`); the other ledger
chip (`RegisterMemoryChip`) is now at log=15 post-B5.

Stage breakdown at MOBILE (median trial; FRI dominant):

| Stage              | Time    | %    |
|---                 |---      |---   |
| trace_gen          | ~85 ms  | 13%  |
| preprocess_commit  | ~6 ms   |  1%  |
| main_commit        | ~230 ms | 27%  |
| interaction_gen    | ~85 ms  | 13%  |
| interaction_commit | ~80 ms  |  9%  |
| FRI prove          | ~270 ms | 31%  |
| **total**          | **~860 ms** | **100%** |

The 1-second target is hit with margin.

## What landed

**Session 1** (operational + parallel-trace, 2026-05-07):

- Item 1.1 — PGO build (`scripts/build-pgo.sh` trains on Add log10/12/14
  + clerk-private-pay-bench{,-mobile}).  ~9% MOBILE win on trace_gen.
- Item 1.2 — Producer/consumer split for `generate_component_trace`.
  `IS_PRODUCER: bool` defaults to true; consumer chips override to
  false and run in parallel with shared `&SideNote`.  ~30 ms saving
  on MOBILE consumer-chip work.

**Session 2** (Ristretto fixed-base scalar mult — comb method):

- Item 2.1 (C8) — full delivery from host-side `comb_table.rs` through
  `RistrettoCombTableChip` (preprocessed 1024×130 table) to
  `RistrettoFixedBaseConsumerChip` (1411 rows/call: anchor + add chain),
  to `RistrettoCombScalarBoundaryChip` (memory↔scalar binding), to
  `RistrettoCombCompressChip` + `RistrettoCombCompressOutputChip`
  (R1e-bis output binding via the in-circuit compress chain).
  End-to-end: a malicious prover cannot fabricate output bytes for a
  fixed-base scalar mult.  Soundness chain summary in
  [Soundness chain](#soundness-chain) below.
- Path B sibling-chip layout chosen over Path A (extend RistrettoChip
  in-place); cleaner separation, smaller diff to the existing chip.
- Off-by-three register-mapping bug fixed across all ECALL handlers
  during integration (the trace-side host code was reading PVM
  φ[10/11/12] for a0/a1/a2, but grey-transpiler maps RISC-V
  x10/x11/x12 → PVM φ[7/8/9]).
- One optimization attempt **rejected** (informative): widening the
  chip-local register-file relation from 4-limb byte-keyed to 34-limb
  row-wide tuples regressed prove time 0.86 → 1.13 s (+31%).  Stwo's
  per-emission overhead is lower than estimated; wider tuples cost
  more per fraction evaluation.  **Don't repeat this.**

**Session 3** (chip-shrink wins — partially attempted):

- B5 — `RegisterMemoryChip` log=16 → 15 via fixed-cap M=4 merge of
  consecutive same-(reg, value) reads.  **Landed perf-neutral** (see
  [B5 details](#b5-shrunk-perf-neutral)).
- B6 — `MemoryChip` log=16 → 15 via byte-flood merging.  **Confirmed
  infeasible** (see [B6 dead](#b6-dead-as-scoped)).

## Soundness chain

End-to-end binding for the mobile tap-and-pay workload
(commits visible via `git log --oneline master..HEAD`):

```
PVM step trace (CpuChip producers)
  → RegisterMemoryChip (B5-merged ledger, log=15) — register reads/writes
  → MemoryChip (byte-level ledger, log=16)        — RAM accesses
  → MemoryBoundaryChip + RegisterMemoryBoundaryChip — initial state
  → ProgramMemoryChip + JumpTableChip              — code authentication
  → Bitwise / Compare / Mul / DivRem / Popcount …  — ALU subroutines
  → Blake2bChip                                    — blake2b ECALLs
  → RistrettoChip + RistrettoEcallChip             — variable-base scalar mult,
                                                     point add, scalar reduce/binop
  → RistrettoCombTableChip (1024×130 preprocessed) — fixed-base table
  → RistrettoCombScalarBoundaryChip                — scalar bytes ↔ PVM memory
  → RistrettoFixedBaseConsumerChip (1411 rows/call) — comb running-sum + window-63 final Acc
  → RistrettoCombFinalAccLookupElements            — cross-chip X/Y/Z/T binding
  → RistrettoCombCompressChip (44 rows/call)       — Ristretto compress chain
  → RistrettoCombCompressOutputChip (32 rows/call) — output bytes ↔ PVM memory
```

A malicious prover cannot fabricate output bytes for a fixed-base
scalar mult without breaking a lookup balance.

## Cross-session conventions

- **Bench harness**: `cargo test -p zkpvm --release --test prove_vos_actor
  profile_clerk_private_pay_bench{,_mobile} -- --exact --nocapture`.
  Run 7 trials, discard cold-start trial, take median of remaining 6.
- **Test gates**: `cargo test -p zkpvm --test phase2_alu` (94 tests,
  ~10 s release) AND `cargo test -p zkpvm --test chip_isolated`
  (13 tests, ~1 s) — both must stay 100% green after every batch.
  Also: `register_ledger_negative` (4), `memory_negative` (12),
  `alu_negative` (66), `control_flow_negative` (23) — soundness
  regression coverage.
- **Stack note**: `RUST_MIN_STACK=33554432` and `--test-threads=1`
  for chip_isolated / phase2_alu — some chip-isolated harnesses
  blow the default 8M stack on parallel test runners.
- **Debug helper**: when a constraint fails with `ConstraintsNotSatisfied`,
  re-run with `--features debug-internals` and call
  `zkpvm::debug_assert_constraints_explicit(side_note, components)`
  from a `#[test]`.  Combined with `CPU_EXPR_DUMP=1`, gives row-#X /
  constraint-#Y pinpoint plus symbolic form.  See
  `tests/chip_isolated.rs::harness_cpuchip_debug_add64` for the pattern.
- **Commit cadence**: one commit per logical batch with bench numbers
  in the message.  No co-author trailer in this repo.

## B5 — shrunk, perf-neutral

`RegisterMemoryChip` ledger collapses runs of consecutive same-(reg,
value) reads into multi-slot rows.  Designed for cap M=4 (even count
fits `finalize_logup_in_pairs`).  Drops chip from log=16 → 15.

### Mechanism

Each merged ledger row carries `Mult ∈ 1..=4`, four timestamp slots
`Ts0..Ts3`, and three `SlotReal{1,2,3}` flags (slot 0 gates on
`is_real = 1 - IsPadding`).  AIR emits 4 fractions per row, gated
by `is_real` for slot 0 and `SlotReal_i` for slots 1..=3.  Row sort
by `(RegAddr, Ts0)`, read-consistency unchanged
(`(1 - IsWrite) · (Value − PrevValue) = 0` per byte).

Merge function (`crates/zkpvm/src/chips/register_memory.rs::merge_entries`)
is deterministic + invertible; the inversion property is pinned by
13 unit tests including a 200-iteration pseudo-random sweep.  Writes
never merge (different value ends a run); runs > M split into multiple
adjacent merged rows.

### Why no perf win

Both real (1.84M → 1.76M cells) and FRI metrics turned out flat:

1. **Max log_size unchanged**: `MemoryChip` still at log=16, so FRI
   folding rounds didn't drop.  Only `RegisterMemoryChip`'s per-chip
   contribution at log=16 vanished — saving roughly half of one
   chip's contribution to the topmost few folds.
2. **4 emissions per row** (vs 1 pre-B5) means interaction-gen does
   ~2× per-row tuple work.  With row count halved, total tuple work
   is ~equal.
3. **Cell counts roughly flat**: 28 cols × 65k rows ≈ 55 cols × 32k
   rows ≈ 1.8M cells.

### Why ship anyway

- Soundness regression test gates pass; verifier-side work unchanged.
- Smaller table → smaller working-set, helps prover memory pressure.
- Machinery in place for the FRI win **iff** `MemoryChip` also drops
  to log=15 (would require Item 3.3).  Cheap to keep landed.

### Decision history

Originally projected ~30% prove-time win (chip's row count halved).
Re-examined post-measurement: **B5 alone is ~5% theoretical**
because FRI is bounded by max log_size (gluing to MemoryChip at 16),
and B5 doesn't drop the max.  Bench confirmed neutral.

## B6 — dead as scoped

`MemoryChip` byte-flood merging does **not** cross log=16 → 15.

Measurement on `profile_clerk_private_pay_bench`:

```
Total ledger entries:    55155
Bytes in flood groups:   516 (0.9%)
After unbounded dedup:   54704
Longest flood:           8
```

Cap-sweep: M ∈ {1, 2, 4, 8, 16, 32}, all fall in 54704–55155 rows
(log=16).  Only 0.9% of byte entries form mergeable flood groups.

**Root cause**: sort by `(address, timestamp)` interleaves
multi-access timelines at each byte address.  An 8-byte LOAD at
ts=T to addr A produces 8 contiguous byte entries, but each byte
address A+i typically already has a prior write or initial-memory
entry at lower ts:

```
sort_by (addr, ts):
  (A+0, ts_init, write)   ← initial-mem injection
  (A+0, T,       read)    ← byte 0 of the load
  (A+1, ts_init, write)
  (A+1, T,       read)    ← byte 1 of the load
  ...
```

After interleave, byte 0's load is NOT sort-adjacent to byte 1.
The 64 length-8 floods that DO survive are pure-write streams to
fresh address ranges (no prior init, no interleaved read), e.g.,
precompile output writes.

Switching to sort `(ts, addr)` clusters access bytes naturally but
breaks the `(addr, ts)`-anchored read-consistency mechanism.  Item
3.3 is the only path forward for `MemoryChip` perf.

## Item 3.3 — Plonkish-style memory check (months of work)

Replace both ledger chips (`MemoryChip` + `RegisterMemoryChip`)
with a single chip using logUp running-sum machinery rather than
per-event entries.

### Plausible win

If a word-level memory model collapses 55k byte entries → ~7k word
accesses (most loads/stores are 8-byte aligned), the chip drops to
log=13.  With CpuChip at log=15 then becoming the new max, that's
30-50% FRI savings ≈ **10-20% total prove-time win**.  Real and
meaningful.

### Caveats

- **Stwo isn't designed for cross-row state machines**.  Plonkish
  memory checks classically use multi-row transition constraints
  (Halo2-style); Stwo's framework is per-row AIR + lookup-relation.
  Adapting requires inventing new primitives — that's why this is
  "months", not "weeks".  The estimate likely understates the work.
- **Audit surface is enormous**.  Memory authentication is the
  soundness floor of the whole VM.  Every existing memory test
  exercises new constraint paths.
- **Returns are 10-20% on a target we already hit**.  0.86 → 0.7 s
  is real but not transformative.

**Recommendation**: don't start unless there's a concrete external
requirement forcing 0.5 s or below.  Comparable alternative:
workload-side optimizations (shrink the actor's PVM step count via
better grey codegen / new precompiles) deliver similar magnitude
at lower risk and don't touch zkpvm soundness.

## Workload-side optimization — what we know

Bench profile of `profile_clerk_private_pay_bench` (24,233 PVM steps):

```
Top opcodes:
  AddImm64:    4760 (19.6%)   ← address arithmetic + small-int adds
  StoreIndU64: 3540 (14.6%)   ← 8-byte stores
  LoadIndU64:  2141 ( 8.8%)   ← 8-byte loads
  StoreIndU8:  1194 ( 4.9%)
  LoadIndU8:   1102 ( 4.5%)
  LoadImm:      967 ( 4.0%)
Memory ops total: 8290 (34.2%)
```

- **JAVM interpreter speed is irrelevant**: 4 ms / 3.36 s = 0.1% of
  prove.  Don't bother optimizing it.
- **grey-transpiler peephole passes** (load_imm + ALU/memory fusion,
  dead load_imm elimination) are mature; only ~4% of memory ops are
  in `direct` form, the rest are runtime-addressed where peephole
  fusion can't help.
- **Real lever is application-shaped**: rkyv archive of Transfer's
  signing payload is the bulk of the data-shape work.  Two paths:
  (a) implement an rkyv-archive precompile chip (months, lower
      audit risk than Item 3.3 since rkyv has a clear spec);
  (b) change the actor's signing-payload format to a simpler
      streaming hash.  Application-layer change.

Either delivers ~30-50% PVM step reduction → MemoryChip below 32k →
log=15 → max log_size 16 → 15 → ~10-15% prove-time win.

## Out of scope (revisit later)

Items considered and consciously deprioritised:

- **B4: chip-local helper relocation** — moving DivRem/Mul-only helpers
  from CpuChip into their respective chips.  Win small (2-5%) and only
  on workloads that don't exercise the relocated chip.  Tap-to-pay
  uses every chip already.  Revisit if a pure-ALU workload class
  emerges.
- **C7: NAF-w4 for variable base** — tap-to-pay uses fixed-base
  scalar-mults exclusively (now via the comb chip).  Defensive
  future-proofing for variable-base workloads only.
- **D9: GPU Merkle commit** — 2-4× speedup on commit stages but
  server-side win.  Wrong shape for mobile-first tap-to-pay UX.
- **D10: Different Merkle hash (Poseidon, Blake3)** — Stwo upstream
  doesn't ship a non-Blake2s `MerkleChannel`; Blake2s has SHA-NI on
  test bench, so the win is workload-dependent.  Coordination-heavy.
- **E11: Segmented + recursive aggregation** — months of work.
  Right call when single-shot payments outgrow what fits in a
  comfortable proof.  Not before.
- **Stwo upstream issues** — two issue drafts
  (`STWO_UPSTREAM_ISSUE_DRAFT.md` lifted-protocol degree-≥2 gap,
  `STWO_MERKLE_LIFTED_OOB_ISSUE_DRAFT.md` mixed-width Merkle OOB).
  Filing deferred until project is live and well-tested.  Neither
  blocks us — bound-1 flatten + chip-isolated bench shape sidesteps
  both.

## Bench cadence + measurement protocol

Every change in this roadmap should be benched before-and-after with
the same protocol so numbers are comparable across sessions:

```bash
# 7 trials each; discard trial 1 (cold-start), take median of trials 2-7:
for i in 1 2 3 4 5 6 7; do
  RUST_MIN_STACK=33554432 cargo test -p zkpvm --release --test prove_vos_actor \
    profile_clerk_private_pay_bench_mobile -- --exact --nocapture \
    2>&1 | grep -E '  total:|interaction_gen|main_commit'
done
```

Same for STANDARD (`profile_clerk_private_pay_bench`).  Update
`BENCHMARKS.md`'s "Latest" section after every meaningful win.

## Pre-release checklist

- [ ] PGO build verified (Item 1.1).
- [ ] `cargo test -p zkpvm` 100% green (all gates listed under Cross-session conventions).
- [ ] `BENCHMARKS.md` reflects current numbers.
- [ ] Two upstream issue drafts filed *or* explicitly deferred with reason.
- [ ] Public API surface review: `prove`, `prove_mobile`,
      `prove_with_config`, `verify`, `verify_with_pcs_policy`,
      `PcsPolicy::{STANDARD, MOBILE}` documented and tested.
- [ ] Tap-to-pay end-to-end bench reproducible from a clean checkout.
