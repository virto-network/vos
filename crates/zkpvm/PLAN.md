# zkpvm — phase plan (post-Phase 26)

A roadmap for the remaining soundness work, ordered by priority.
Each phase is sized to fit one focused session (~1–3 hours of
implementation + 30–60 min of regression sweep).  Entries point
at the relevant section of [`STATUS.md`](./STATUS.md) for context.

The pattern that's worked across Phases 16 → 26: pick one specific
gap, design the per-byte / per-flag binding, add columns to
`CpuChip` + matching preprocessed flags to `ProgramMemoryChip` (so
the flag is bound to the canonical opcode), constrain, fill the
trace, and run the minimum sweep + `prove_vos_actor`.  See the
sibling [`README.md`](./README.md) for the build / test recipe and
[`src/chips/cpu/CONSTRAINTS.md`](./src/chips/cpu/CONSTRAINTS.md) for
the lookup pair-shape rules every new constraint must respect.

## Memory soundness — finish what Phases 22–26 started

### Phase 27 — StoreImm / StoreImmInd MemValue + StoreImm direct MemAddr

Closes 8 stores' value binding plus 4 stores' address binding.
Reuses the existing `ImmBytes` / `ImmYBytes` infrastructure.

- Trace-fill extension: `ImmYBytes` currently only filled for
  `TwoRegTwoImm` (LoadImmJumpInd).  Extend to `TwoImm`
  (StoreImm[U][8/16/32/64]) and `OneRegTwoImm`
  (StoreImmInd[U][8/16/32/64]).  Pin `ImmYBytes` in the
  ProgramMemoryChip preprocessed table for those rows.
- New flag `IsStoreImmAny` (covers both StoreImm and StoreImmInd).
  Constraint: `IsStoreImmAny · mem_byte_active[i] · (mem_value[i]
  − imm_y_bytes[i]) = 0` for `i ∈ 0..8`.
- Widen Phase 25's `(IsLoadDirect + IsStoreDirect)·(MemAddr[i]
  − ImmBytes[i]) = 0` to also cover `IsStoreImmDirect` (the
  TwoImm-category direct-addr path).  Or fold all three direct
  variants under one `IsAddrFromImmOnly` flag.

Estimated scope: ~2 new flags, ImmYBytes fill extension for two
categories, two constraints.  ~200 lines.  No new lookups.

### Phase 28 — Indirect StoreInd MemValue via new `RegValA` column

Closes the last MemValue gap — every load/store byte will then be
bound.

- New `RegValA` column in `CpuChip` (8 bytes), filled to
  `regs_before[reg_a]` on rows where reg_a is the source register
  for a store.  Mirrors the existing `RegValB` / `RegValD`
  pattern.
- New `ValAIsReg` flag + index column (mirroring `ValBIsReg` /
  `ValBRegIdx`).  Producer emission to the register-memory
  ledger gated on `ValAIsReg` so RegValA is bound to the actual
  register value.
- Constraint:
  `IsStoreInd · mem_byte_active[i] · (mem_value[i] − reg_val_a[i])
   = 0` for `i ∈ 0..8`.
- Trace fill: set `ValAIsReg=1` + `ValARegIdx=reg_a` +
  `RegValA=regs_before[reg_a]` on `StoreInd*` rows.

Estimated scope: ~10 columns, register-memory producer
extension, one constraint.  ~300 lines.  Touches the ledger so
needs `prove_vos_actor` regression check.

## Divrem — close the family

### Phase 29 — DivByZero + ValDIsZero unified zero-check

Closes both the DivByZero binding and the CmovIz / CmovNz
`val_d_is_zero` gap with shared byte-wise zero-check infrastructure.

- Per-byte inverse witness `ValDByteInv[8]`: `val_d[i] · ByteInv[i]`
  is 0 iff `val_d[i] = 0`, else 1 (boolean indicator).
- Cumulative-OR columns `ValDPartialNZ[8]` (degree-3 recurrence:
  `partial[i] = partial[i-1] + indicator[i] − partial[i-1] ·
  indicator[i]`).  `ValDPartialNZ[7] = 1 ↔ val_d ≠ 0`.
- Tie `val_d_is_zero = 1 − ValDPartialNZ[7]` (or replace existing
  column with this).  Tie `div_by_zero = is_div_rem ·
  val_d_is_zero` (one direction is current; this closes both).
- Bind result on `div_by_zero=1` rows: `result[i] = 0xFF` for div
  ops (u64::MAX), `result[i] = val_b[i]` for rem ops.
- Same `val_d_is_zero` now soundly forces CmovIz fires
  (`val_d=0 ⇒ result = val_b`) and CmovNz to NOT fire
  (`val_d=0 ⇒ result = old regs_before[rd]`, already enforced via
  the register-memory ledger).

Estimated scope: ~24 columns + boolean / arithmetic constraints
+ new result-binding for div-by-zero rows.  ~400 lines.  Touches
multiple constraint families so needs full sweep + `prove_vos_actor`.

### Phase 30 — DivS r < d uniqueness

Completes Phase 21's DivU work for the signed case.

- New `AbsR[8]` / `AbsD[8]` columns (absolute values) computed
  via two's-complement negation chain when the sign bit is set:
  `AbsX = (1−sx)·x_u + sx·(2^64 − x_u)` byte-wise with carry.
- `AbsCmpDiff[8]` / `AbsCmpCarry[8]` analogous to Phase 21's chain
  but on `(AbsD, AbsR)` instead of `(val_d, div_remainder)`.
  Top carry forced to 1 on `is_div_s · ¬div_by_zero` rows.
- Range-check AbsR / AbsD / AbsCmpDiff bytes via Range256.

Estimated scope: ~32 columns + 4 carry chains + 24 range-check
emissions per row.  ~500 lines.  Largest of the open phases.

## Rotate

### Phase 32 — RotL64 — DONE

Mul-schoolbook re-route: low-64 of `a · 2^n` → UnsignedProductLow,
high-64 → mul_high.  Result = low + high (byte-wise sum, no carry —
bits non-overlapping by construction).  Original PLAN's "OR via
nibble ANDs" approach was over-engineered; sum works because
rotation guarantees the two halves' bits don't overlap.

### Phase 35 — RotR64 / RotR64Imm — DONE

Same shape as Phase 32 but with the *complementary* power:
`val_d = 2^((64 − n) mod 64)` so the schoolbook's low+high yield
the rotated-right value.  The complement is pinned via a second
shift-amount identity `RegValD + ShiftAmountCompl = 64 ·
ShiftQuotientCompl` plus a separate PowerOfTwo lookup keyed on
`ShiftAmountCompl`.  RotR64ImmAlt deferred — its operand
convention (immediate is the rotated value, register is the
shift amount) clashes with the AIR's val_b/val_d layout.

### Phase 36 — RotL32 + RotR32 + RotR32Imm — DONE

Re-routed the 32-bit mul-schoolbook (low-32 → UnsignedProductLow[0..4]),
added per-rotate result bindings (low 4 bytes = sum of low + high),
and pinned ShiftAmount/ShiftAmountCompl ∈ [0, 31] via a `val_d[4..8]
= 0` constraint on 32-bit rotate rows.  Phase 19's sign-extension
finalize covers the high 4 bytes uniformly across non-rotate Mul32
and rotate-32 rows.

### Phase 37 — 32-bit shift ShiftAmount uniqueness — DONE

Closed a latent soundness gap surfaced while building Phase 36's
32-bit rotate machinery.  The pre-existing 32-bit shift identity
`reg_val_d = ShiftAmount + 32·ShiftQuotient` admits two valid
byte-bounded shift values for any modulus-32 reg_val_d (e.g.,
ShiftAmount = 0 with ShiftQuotient = 1, or ShiftAmount = 32 with
ShiftQuotient = 0); the [0, 63] PowerOfTwo table accepts both.
Phase 36 added `val_d[4..8] = 0` on rotate-32 rows; Phase 37
widens the gate to all `is_32bit · is_shift_c` rows so
ShloL32/ShloR32/SharR32 (+ Imm/ImmAlt variants) are covered too.

### Phase 40 — RotR64ImmAlt + RotR32ImmAlt — DONE

Closed via:
- A new IsRotateRImmAlt flag (set alongside IsRotateR64 / IsRotateR32
  so the existing rotate-r constraints fire normally).
- A swapped trace-fill path (val_b ← imm, val_d ← regs[rb]) for
  TwoRegOneImm rows where is_rotate_r_imm_alt = 1, plus matching
  swap in reg_access (val_b_read = None, val_d_read = Some((rb, ...))).
- A `val_b ↔ ImmBytes` algebraic constraint pinning val_b to the
  canonical immediate.  Shape mirrors the val_b cross-constraint:
  low 4 bytes always; high 4 bytes match-or-zero gated on
  IsTruncated (32-bit ImmAlt has IsTruncated=1, which masks val_b
  high bytes to 0 in trace fill while ImmBytes carries the
  sign-extended bytes).

## BitManip remainder

### Phase 33 — CountSetBits 32 / 64 — DONE

Landed: new `PopcountChip` (256-row `(byte, popcount(byte))`
preprocessed table) plus per-byte CpuChip lookup
`(val_d[i], BytePopcount[i]) ∈ popcount` and result binding
`result[0] = Σ BytePopcount[..N]` (N = 4 if Is32Bit else 8),
`result[1..8] = 0`.

### Phase 34 — LeadingZeroBits / TrailingZeroBits — DONE

Landed: new `BitcountChip` (256-row `(byte, lz, tz)` preprocessed
table) plus per-byte CpuChip lookup `(val_d[i], BitOpLzByte[i],
BitOpTzByte[i]) ∈ bitcount` and result bindings driven by
"first-non-zero-byte" indicators built from Phase 29's
`ValDByteInv` byte-zero-check infra.  TZ reuses Phase 29's
LSB-direction `ValDPartialNZ`; LZ adds `ValDPartialNZMsb[8]`
(MSB direction over 8 bytes, for LZ64) and `ValDPartialNZMsbLo[4]`
(MSB over low 4 bytes, for LZ32).  Default fallback 64/32 when
val_d (or low 4) is zero.  `result[1..8] = 0`.

### Phase 41 — Sbrk — DONE

JAR v0.8.0 removed Sbrk from the ISA in favour of the grow_heap
hostcall, so the interpreter panics on execution.  The earlier
"needs precompile" framing was stale — Phase 41 just marks Sbrk
as `is_exit + is_trap` so the Phase 13e-redux terminal-row
constraint catches any attempted continuation, matching the
panic-and-stop semantics.  1-line classify change + 2 tests
(positive prove + terminal-forge reject).

## Cross-cutting

### Negative tests via column-level mutator

Phase 38 added forge-the-result tests for every Phase-32–36
BitManip and rotate opcode (CountSetBits 32/64,
LeadingZeroBits 32/64, TrailingZeroBits 64, RotL/R 32/64,
RotR64 wraparound).  These exercise the result-binding
constraints via `forge_two_reg_result` / `forge_three_reg_result`.

A *true* column-level mutator (forge `SignBitB` while keeping
val_b honest, forge `q' = q − 1, r' = r + d` on DivU, …)
would require exposing the prover's main-trace generation hook
so a test can mutate a single Column at a specific row before
finalizing.  Still deferred — implementing it would mean either
(a) splitting `prove` into a `generate_main_trace` step + a
`prove_from_trace` step, or (b) adding a back-door
`generate_main_trace_with_mutator` API.  Both are tractable
~50 LoC changes but no soundness gap depends on this alone:
all the tested constraints are bound to result columns that
forge-the-result already exercises.

### Documentation upkeep

When adding a new phase:
- Tag commits with `Phase N:` prefix matching the phase number.
- Add the phase to [`STATUS.md`](./STATUS.md) — both the bound
  list and (if applicable) the open-gaps list.
- Update the deferred-pieces table in this file's relevant
  section.
- Cross-reference `[N]` from columns.rs / classify.rs doc-comments.

## Performance roadmap (Phases 52+)

Phase 52 ran a side-by-side bench against Nexus zkVM 2.x on the
same hardware, same Stwo upstream rev, same Rust toolchain.
Result: zkpvm proves at roughly 5x the wall time of Nexus across
log_size 10/12/14.  Per-cell cost is similar (we share the
backend) — we just commit ≈3-5x more cells.  Top diagnoses:

- **CpuChip is 1.77x wider per row** than Nexus's
  (662 vs. 374 cells).  662 cols x 32K rows at log14 = 21.7M
  cells, 76% of all committed cells.

- **CpuChip is monolithic.**  Nexus splits per-opcode semantics
  across 30 narrow per-instruction chips (AddChip, SubChip,
  JalrChip, BneChip, ...), each constraining one opcode in its
  own narrow row.  zkpvm crams every opcode constraint into one
  wide CpuChip; every row carries 662 columns regardless of
  which opcode is on it.

See [`BENCHMARKS.md`](./BENCHMARKS.md) for the measured numbers
and cell-count breakdown.

### Phase 53 — CpuChip column audit + targeted reduction

Survey the 662 per-row cells for fold-able columns:

- **Sum-of-flags columns** like `IsMulUpper` (= `IsMulUpperUU +
  IsMulUpperSU + IsMulUpperSS`) are pinned by an existing
  identity constraint; the column is redundant if every reader
  uses the sum directly.  Drop the column, replace readers with
  the expression, drop the identity constraint.
- **Source-byte multiplexers** like `SignSrcB` (=
  `(1-Is32Bit)·val_b[7] + Is32Bit·val_b[3]`) materialise a
  constant-degree expression of existing columns.  Same
  treatment.
- **Hi-nibble witnesses** like `SignBHiNib`: these ARE witnesses
  (the prover writes them) but only feed a single nibble-AND
  lookup.  Cannot fold without restructuring the lookup.

Estimated headroom: -100 to -200 columns (CpuChip 662 → ~500),
which translates to a 15-30% prove-time reduction at log14
(roughly 2.5-4 seconds saved out of 12.92).  No soundness
change.

#### Implementation gotcha (from a Phase 53 trial run)

Each fold spans ~5 places per column (column enum,
prog_mem flag list, prog_mem tuple emission verifier-side,
prog_mem tuple emission prover-side, classify_opcode_for_program_memory,
trace fill).  Three of these are mechanical; the prover-side
prog_mem tuple emission is the gotcha:

  // Verifier side (cpu/mod.rs add_constraints) — column → sum:
  tuple.push(mu_uu[0].clone() + mu_su[0].clone() + mu_ss[0].clone());

  // Prover side (cpu/interaction.rs) — `FinalizedColumn` does
  // NOT impl `Add`, so this DOES NOT compile:
  // tuple.push(f_mu_uu[0].clone() + f_mu_su[0].clone() + f_mu_ss[0].clone());

The prover-side mirror needs `add_to_relation_computed` (the
closure-based variant of `add_to_relation_with`) where each
tuple element is computed per-vec-index from the underlying
`FinalizedColumn::at(vec_idx)` values.  See the existing
MemoryAccess byte-level lookup in interaction.rs for the
pattern — it already uses `add_to_relation_computed` to
synthesize `addr + byte_idx` per row.

So a column fold needs both:
1. Verifier-side: replace column read with sum expression.
2. Prover-side: convert the tuple emission from
   `add_to_relation_with` (slice-based) to
   `add_to_relation_computed` (closure-based) AND build the
   tuple element from `mu_uu_c.at(vec_idx) + mu_su_c.at(vec_idx)
   + mu_ss_c.at(vec_idx)` inside the closure.

That conversion is mechanical but per-emission, not per-fold —
once the prog_mem tuple emission switches to
`add_to_relation_computed`, every subsequent fold is free.  Plan:
the first fold also lifts the prog_mem tuple to the
closure-based emission; later folds just edit the closure.

Plan: do folds in batches of 5-10 columns with a sweep after
each batch.

### Phase 54 — per-opcode-family chip shards (LANDED 54a-g)

Extracted four opcode families from CpuChip into narrow chips
whose row count = matching real rows.  Mirrors Nexus's structure.

#### Status (post-54g)

| Sub-phase | Chip / scope | Cells dropped from CpuChip |
|-----------|--------------|---------------------------|
| 54a | MulChip foundation (lookup wiring) | 0 |
| 54b | Mul schoolbook carry chain | 32 |
| 54c | Phase 12c MulUpper sign correction | 32 |
| 54d | Mul result-variant dispatch | 16 |
| 54e | BitwiseChip (6 op identities + nibble lookups) | 32 |
| 54f | CompareChip (cmp_carry chain) | 16 |
| 54g | DivRemChip (schoolbook q·d+r=b chain) | 32 |
| **Total** | | **160** |

#### Wall-clock results (median of 3, prove only)

| log_size | Phase 53f baseline | Phase 54g | Speedup |
|----------|-------------------|-----------|---------|
| 10 | 1.18s | 0.73s | 38% |
| 12 | 3.07s | 2.01s | 35% |
| 14 | 11.37s | 7.08s | 38% |

vs Nexus baseline (175ms / 620ms / 2.37s): gap narrowed from
~5× to ~3× across all sizes.

#### Pattern (now well-validated)

Each extraction defines a `<Family>LookupElements` relation;
CpuChip emits a paired producer per family-row, the new chip
witnesses internally + consumes once per real row.  Variable
log_size scales with family-row count, padded with `IsPadding=1`.

Subtleties baked in:
- LOG_CONSTRAINT_DEGREE_BOUND = 2 for schoolbook chains
  (degree-4 from `is_real * is_64bit * is_op * (val_b*val_d − …)`).
- MIN_LOG_SIZE = 5 floor (stwo MIN_FFT_LOG_SIZE).
- `finalize_logup_in_pairs` needs paired emissions on both sides.
- `add_to_relation_computed` on prover side when the multiplicity
  is a sum expression (`FinalizedColumn` doesn't impl `Add`).

#### Architecture

Each extracted chip pairs with CpuChip via a per-family **lookup
relation**:
- CpuChip emits one *producer* tuple per real row of that
  family, multiplicity = the family flag (`is_mul`, `is_compare`,
  …).  Tuple shape encodes the inputs/outputs the family chip
  needs to bind: `(val_b[8], val_d[8], result[8], plus
  family-specific extras)`.
- The family chip has rows = ceil_log2(count of producer rows
  this trace), padded with `IsPadding=1` rows to the next
  power-of-two-of-lanes.  Same pattern as `MemoryChip`.
- The family chip *consumes* one tuple per real row with mult
  -1 and adds its own AIR constraints (carry chains, sign
  correction, etc.) over its narrow column set.

For an opcode family that fires on (e.g.) 5% of CpuChip rows at
log14 (~16K rows, so ~800 family rows), the chip's `log_size`
≈ 10 vs CpuChip's 14 — a 16× row reduction.  The cells that used
to be zero on 95% of CpuChip rows are simply not committed.

#### Sub-phase log

Sub-phases 54a–g landed (commits 939e2fd → 3b9742f).  CpuChip
shrunk by 160 cells per row; ~38% prove-time reduction at log14.
See the table at the top of this Phase 54 section for the per-
sub-phase breakdown.

#### Remaining 54.x extractions (low-priority)

The remaining mul/divrem/branch witnesses average ~16 cells each.
At this point Phase 54f went perf-neutral (the cell drop is offset
by the extra chip's row commitments at typical workload mix), so
further extractions are mostly architectural rather than
performance wins:

- **54h — `BranchChip`**.  Drops `ByteEq[8] + ByteDiffInv[8] = 16
  cells`.  Tuple needs to expose `eq_flag` back to CpuChip.
- **54i — DivCmp uniqueness**.  Drops `DivCmpDiff[8] +
  DivCmpCarry[8] = 16 cells` (r < d unsigned).
- **54j — AbsCmp uniqueness**.  Drops `AbsCmpDiff[8] +
  AbsCmpCarry[8] = 16 cells` (|r| < |d| signed).
- **54k — DivS sign correction**.  Move Phase 16/18 carry chain
  to DivRemChip; drops `DivCorrHi[8] + DivCorrCarry[8] = 16 cells`.

Apply opportunistically; no urgency.  Future material wins lie
in Phases 55–56 (ProgramMemoryChip column compaction, Blake2bChip
review).

#### Risks / open questions

- **Producer-multiplicity wiring**: CpuChip emits a producer per
  family-row; the family chip consumes one tuple per family-row.
  Need to ensure the lookup balance forces a 1:1 binding
  (no prover wiggle room to insert extra family rows or skip
  real ones).  Pattern: producer mult = `is_family_flag`,
  consumer mult = -(1 - is_padding).  Family chip's row count
  derived from `side_note.steps.iter().filter(is_family).count()`,
  not prover-chosen.
- **Cross-chip column fan-in**: cells like `Result[8]` are
  written by every opcode and read by both CpuChip downstream
  constraints AND family-chip constraints.  These stay on
  CpuChip and ride through the producer tuple.
- **Padding rows on family chips**: family chip's IsPadding=1
  rows must not consume from the lookup, otherwise lookup
  balance fails.  Standard pattern: gate consumer multiplicity
  on `(1 - is_padding)`.

### Phase 55 — ProgramMemoryChip column compaction

74 cols x 65K rows = 4.85M cells, 17% of committed total.  Most
of those cols are flag bits that could share a single packed
column with bit-decomposition lookups (similar to the existing
Range256 pattern).  Plausible 50% reduction = 2.4M fewer cells.

### Phase 56 — Blake2bChip review

2266 main columns is the largest single chip-column count in
the codebase.  log_size = 4 keeps committed cells low (≈36K),
so prove-time impact is small.  Worth reviewing for clarity —
the chip was an early port and may have inherited columns that
are now over-decomposed.
