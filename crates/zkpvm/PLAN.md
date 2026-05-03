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

#### Remaining 54.x extractions — status

The remaining mul/divrem/branch witnesses average ~16 cells each.
Phase 54f went perf-neutral (cell drop offset by extra chip's row
commitments at typical workload mix), so further extractions are
mostly architectural rather than performance wins.

- **54h — drop ByteEq/ByteDiffInv via direct val_b/val_d branch
  constraint** — DONE (`d748529`).  Originally scoped as a new
  BranchChip extraction; the simpler reformulation lands the
  same -16 cells without the per-chip overhead.  BranchEq/BranchNe
  constraints now read `(val_b[i] - val_d[i])` directly instead
  of the bound-to-diff `(1 - byte_eq[i])` indicator.  Same degree,
  same soundness — the loose-corner direction was already
  documented as intentionally unconstrained.

- **54i — DivCmp r<d uniqueness chain → DivRemChip** — DONE
  (`2a5397d`).  Tuple grew 43 → 44 limbs (added is_div_s).
  DivRemChip's LookupElements gained Range256LookupElements; chip
  now witnesses DivCmpDiff/Carry internally and emits per-byte
  Range256 lookups on its own narrower trace.

- **54j — AbsCmp |r|<|d| uniqueness chain → DivRemChip (narrow
  scope)** — INVESTIGATED, NOT LANDED.  As originally scoped, the
  move flowed 16 abs-value limbs (abs_d[8] + abs_r[8]) through the
  DivRemLookup tuple (44 → 60 limbs).  Wall-clock regression of
  +14% at log10, +28% at log14: the per-CpuChip-row hash cost on
  the wider producer tuple outweighed the 16-cell drop.  Reverted
  in favour of 54j-redux below.

- **54j-redux — full Phase 30 chain → DivRemChip** — DONE
  (`996b025`).  Moves AbsD/AbsDCarry/AbsR/AbsRCarry +
  AbsCmpDiff/AbsCmpCarry (48 cells) off CpuChip.  Sign bits already
  flow via the 54k tuple (SignBitD / SignBitR), so the tuple stays
  at 40 limbs and DivRemChip computes the absolute values + the
  comparison chain internally.  Net: -48 cells × ~16K rows on the
  wide trace; DivRemChip gains 6 columns × ~32 rows.  Wall-clock
  neutral; proof size at log14 grew 564 → 604 KB from the new
  DivRemChip interaction columns.

- **54k — DivS sign correction (Phase 16/18) → DivRemChip** —
  DONE (`498733e`).  Net tuple shrinkage 44 → 40 limbs (dropped
  div_corr_hi[8], added 4 sign bits).  DivCorrHi/DivCorrCarry are
  now DivRemChip-internal.  DivRemChip's
  LOG_CONSTRAINT_DEGREE_BOUND bumped 2 → 3 to fit the degree-6
  chain.  Proof size at log14 dropped 607 → 564 KB (-7%); wall-
  clock within trial noise.

Lessons learned:
- Tuple growth on a per-CpuChip-row producer is expensive: each
  added limb costs O(N_real_rows) field ops in the relation hash.
  Architectural moves that *grow* the tuple need to drop comparable
  cells from CpuChip *and* save enough downstream to offset the
  hashing.
- Tuple shrinkage (54k pattern) is a clean win — both sides save.
- LOG_CONSTRAINT_DEGREE_BOUND must be set to the maximum
  constraint degree on the chip; under-shooting silently breaks
  proofs (constraint polynomial is non-zero on the eval domain
  yet stwo only checks it on a smaller domain).

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

### Phase 55 — ProgramMemoryChip column compaction (LANDED 55a-b)

Original goal: pack the 48 individual flag bits in
`program_memory.rs` PreprocessedColumn into 6 bytes on BOTH the
prog_mem preprocessed table AND CpuChip's main-trace flag
witnesses.  Add a 256-row "byte → 8 bits" decomposition lookup
table.  Lookup tuple shrinks 73 → 31 limbs.

Sub-phases landed:
- **55a** (`001ff22`): ByteToBitsChip foundation — 256-row
  preprocessed table providing `(byte, bit0..bit7)` with a
  Multiplicity main column.  Wired into BASE_COMPONENTS but
  dormant (no consumers in 55a).  Pattern mirrors BitcountChip /
  PopcountChip.
- **55b** (`e4699f6`): Pack 48 prog_mem flags into 6 bytes.
  ProgramMemoryChip drops 48 individual IsX preprocessed cols,
  gains 6 FlagByte cols.  CpuChip gains 6 FlagByte main cols
  (filled from `pack_flags(classify_opcode_for_program_memory(opcode))`).
  CpuChip emits 6 byte-to-bits lookups per real row binding
  individual flag columns / sum-of-sub-flags expressions to the
  matching bit slot in each FlagByteI.  prog_mem consumer
  switches to the 6-byte tuple (drops 60+ lines + 5 closure
  overrides).

#### Cell drop and tuple shape

| Item                                | Before (54g)      | After (55b)       |
|---                                  |---                |---                |
| prog_mem tuple limbs                | 73                | 31                |
| ProgramMemoryChip preprocessed cols | 65                | 23                |
| CpuChip flag-related main cols      | 48 (individual)   | 48 + 6 (packed)   |
| Components                          | 18                | 19                |

#### Wall-clock impact

Bench at log10/12/14 (median of 3, prove only):
- Phase 54g baseline: 0.73s / 2.01s / 7.08s
- Phase 55b:          0.59s / 1.84s / 5.12s

Improvements: ~20% / 8% / 28%.  Cumulative speedup vs Phase 50:
39% / 32% / **60%** at log_size 10 / 12 / 14.  vs Nexus
(175 ms / 620 ms / 2.37s) — gap shrinks from ~3× (post-54g) to
roughly 2.2× at log_size 14.

#### Soundness

- Each FlagByteI on CpuChip is bound to canonical packed byte
  via the prog_mem lookup balance.
- The byte-to-bits lookup forces every emitted bit expression
  to be 0 or 1 AND that the byte equals their weighted sum;
  256 distinct rows cover all valid decompositions, so
  FlagByteI = canonical_packed ⇒ each emitted bit_j_expr =
  canonical_bit_j.
- Same chain as Phase 13c, just routed through 6 packed bytes
  + 1 decomposition table instead of 48 individual tuple slots.

#### Tests

Pre-existing 239 functional + 100 negative tests pass.  Three
prove_vos_actor failures (prove_blake2b_via_ecall,
prove_blake2b_precompile, debug_blake2s_prefix) and
security_sweep_log12 are pre-existing PcsPolicy floor failures
unaffected by Phase 55.

### Phase 56 — Blake2bChip review (DONE — analysis-only)

Blake2bChip has 2266 main columns, the largest single chip-column
count in the codebase.  log_size = 4 keeps committed cells at
≈36 K (~0.16% of the 23 M total at log14), so prove-time impact
is small but the chip is hard to read.  Phase 56 audited every
column group and concluded: **no material fold opportunity**.
Logging the breakdown here so future readers don't re-do the
audit unprompted.

#### Column breakdown (single G-row, 96 rows per compression)

| Group                                   | Cells | Why it stays                              |
|---                                      |---    |---                                        |
| AIn/BIn/CIn/DIn (G inputs)              | 32    | per-row inputs to the G-function         |
| Mx/My (per-row message words)           | 16    | selected from M0..M15 by SIGMA selectors |
| A1/Carry1/And1/C1/Carry2/And2/AOut/      | 80    | G-step intermediates + carries (XOR via   |
|   Carry3/And3/COut/Carry4/And4           |       | a + b - 2·AND); each step needs a witness |
| BOut/Rot63Carry/DOut                    | 17    | rot-63 carry + reified d-out              |
| And{1..4}{A,B,Res}Hi (nibble witnesses) | 96    | required for the bitwise-AND nibble lookup |
| M0..M15 (replicated message)            | 128   | constant across all 96 rows of a compression |
| H0..H7 (replicated chain value)         | 64    | constant across all 96 rows               |
| T (counter, 16 bytes) + THi (16 bytes)  | 32    | t-bytes + nibbles for IV[4]/[5] ^ T pinning |
| F (final flag) + And{T*,T*Hi} chain     | 33    | 4 nibble-AND witnesses for V[12..14] init |
| V0..V15 (state snapshot)                | 128   | per-row v[0..16] mid-compression          |
| Output (claimed digest, 64 bytes)       | 64    | last-row output binding to H ^ V_after    |
| HHi (H hi-nibbles for And lookup)       | 64    | nibble decomposition of H bytes           |
| VAfterHi (V_after hi-nibbles)           | 128   | nibble decomposition of derived V_after   |
| OutAnd1/Hi/OutXor1Hi/OutAnd2/Hi         | 320   | output-derivation AND witnesses           |
| HPtr/MPtr/CallTs (ECALL pointers + ts)  | 16    | per-compression ECALL inputs              |
| HRdAddrB0..3 (64 byte-addresses × 4)    | 256   | byte-decomposed address per h-read        |
| MRdAddrB0..3 (128 × 4)                  | 512   | byte-decomposed address per m-read        |
| HWrAddrB0..3 (64 × 4)                   | 256   | byte-decomposed address per h-write       |
| IsReal                                  | 1     | row-validity flag                         |
| **Total**                               | **2243** (+ 23 misc = 2266 reported)        |

#### Why nothing folds cleanly

- **Address byte-decompositions (1024 cells, 45% of the chip)**.
  The AIR needs each address byte separately for the memory-access
  lookup tuple (which is byte-addressed).  Folding requires
  computing `(HPtr + i)` on-the-fly via a per-byte carry chain —
  that's `(addr[0] = HPtr[0] + i, carry_0 = ...; addr[1] =
  HPtr[1] + carry_0, carry_1 = ...; ...)` per memory op × 256 ops
  per compression.  CpuChip's `add_to_relation_computed` pattern
  works for single-byte offsets; the 4-byte address case needs
  carry-chain witnesses anyway (which are roughly the same cell
  count as the storage we'd remove).  Net: no win.

- **Output-derivation chain (320 cells)**.  Output[i] = H[i] XOR
  V_after[i] XOR V_after[i+8].  Implemented as two AND-and-add
  steps to keep degrees down.  The 5-column witness layout
  (OutAnd1/Hi, OutXor1Hi, OutAnd2/Hi) is exactly the standard
  nibble-AND XOR pattern shared with the rest of the chip.  No
  obvious fold.

- **Nibble witnesses (And*Hi, *Hi columns)**.  Each one feeds a
  single nibble-AND lookup; cannot be removed without a different
  AND-encoding scheme.  Same story as the Phase 53 audit
  documented in the CpuChip section above.

- **State snapshots (V0..V15, M0..M15, H0..H7 = 320 cells)**.
  These are the per-row reified state; the inter-row chaining
  constraint reads `V_next` from row N+1 to bind row N's update.
  Cannot be folded without restructuring how state propagates.

#### Decision

Blake2bChip is **left as-is**.  Future material wins lie outside
the chip — at log14 even halving Blake2bChip's cell count would
shave ≈18 K cells from a 23 M total (0.08% prove-time saving).
Phase 56 closes with this audit.

#### Open follow-ups elsewhere

- **Per-step register-access ledger** (project memory note
  `project_pvm_register_auth.md`): COMPLETE in commits
  2af7a93 → e297fd2 (Phase 9a–9g).  Verified 2026-05-02.
- No further 54.x leftovers — 54h/i/k/j-redux all landed.

### Phase 57 — column-folding investigation (CLOSED, no change)

Audited CpuChip's remaining "source-byte multiplexer" columns
(SignSrcB/D/Q/R = 4 cells × log15 = 131K cells dropped) for an
inline fold to `(1-Is32Bit)·val_X[7] + Is32Bit·val_X[3]`.

**Result: +9% prove-time regression at log14** (5.40s → 5.91s
median of 5).  Same failure mode as the original 54j attempt:
- Saved cells: ~131K committed cells off CpuChip (~1% of total).
- Cost: per-row degree-2 expression in 8 lookup tuple emissions
  (4 sign-bit nibble lookups × 2 paired emissions each), with
  multiplicity = is_real (= every CpuChip row).  The relation
  hash now does 2 mults per tuple element instead of 1.

The cells saved at log15 don't outweigh the per-row hash cost
on the wide CpuChip trace.  Reverted.

#### Updated lesson — column folds vs. multiplicity

The Phase 54.x and Phase 57 attempts establish a sharper rule
than the earlier "tuple growth = bad" lesson:

> **Don't inline expressions into per-row producer tuples
> whose multiplicity is `is_real` (or any flag set on most
> rows).**  The `add_to_relation_*` cost scales with
> `Σ_row mult(row) · cost(tuple_at_row)`.  If multiplicity is
> non-zero on most rows, growing per-row tuple complexity is
> a wide multiplier on every CpuChip row.

When inlining IS perf-positive:
- Multiplicity is 0 on most rows (e.g., `is_jump_ind`, ECALL,
  Mul/DivRem family flags) — only those few rows pay.
- The folded expression was already being computed for another
  reason (free reuse).
- Multiple folds amortize over a single closure rebuild (rare).

#### Where the perf headroom actually is now

After Phase 50 → 54k (60% cumulative speedup at log14), the
remaining levers are bigger architectural changes:

1. **Multi-threading the prover via rayon** (highest ROI).
   Stwo's SimdBackend parallelises within a thread but doesn't
   spread across cores.  A 4-8× speedup is plausible on a desktop
   if main_commit + interaction_commit + FRI prove (89% of total
   time at log14) can be parallelised over chip components or
   FRI layers.  Multi-day effort; coordinates with upstream stwo.

2. **Reduce log_size on the three log-16 chips**
   (ProgramMemoryChip / RegisterMemoryChip / MemoryChip).  Each
   sized to ceil_log2 of producer-row count.  Reducing producer
   counts (e.g., consolidating reg accesses per step from 3 → 1)
   could shrink one of them to log15, halving its committed
   cells.  Each chip is ~5-8% of total cells; a single shrink =
   ~2-4% prove-time saving.  Multi-day per chip.

3. **Move rare-opcode columns to dedicated narrow chips**
   (Phase 54 pattern, applied to JumpInd ~32 cells, blake2b
   ECALL ~40 cells, etc.).  Multiplicity = is_X-flag is 0 on
   most rows, so the producer cost is nearly free.  Useful but
   small in absolute terms — these columns are already 1-2% of
   CpuChip cells.

The path that actually moves the needle is **multi-threading**.
Suggest opening a Phase 58 with that goal.

### Phase 58–61 — performance push to beat Nexus by 2× (LANDED)

zkpvm now leads Nexus zkVM 2.x by **2.21× on log14 prove time**
(1.07 s vs 2.37 s) with **65% smaller proofs** (297 KB vs ~600 KB)
at the same 96-bit conjectured security.

#### Summary of landed wins

| Phase | Lever | log14 MOBILE | Cumulative speedup vs Phase 50 |
|---    |---    |---           |---                              |
| 50    | (baseline)                              | 12.92 s | 1.0×        |
| 54k   | Phase 54.x extractions                  | 5.40 s  | 2.4×        |
| Track B  | MOBILE PCS config (blowup=4, q=38)   | 2.10 s  | 6.15×       |
| 59    | Rayon thread cap (`min(cpus,10)`)       | 1.86 s  | 6.95×       |
| 60 v2 | Dynamic component selection             | 1.79 s  | 7.21×       |
| 61a   | `target-cpu=native`                     | 1.50 s  | 8.6×        |
| 61b   | Fat LTO + codegen-units=1               | 1.31 s  | 9.86×       |
| 61c   | PGO (3-step build, `scripts/build-pgo.sh`) | **1.07 s** | **12.07×** |

Real workload (hash_bench, 635 PVM steps mixed opcodes):
**148 ms prove + 172 KB proof** with PGO + STANDARD config.

Per-cycle throughput is constant 65 µs/cycle from log14 → log15 →
holds at scale.  Nexus per-instruction: ~145 µs.  zkpvm is **2.23×
faster per operation** at the prover level; PVM's denser ISA gives
additional total-program win on top.

#### Soundness preserved

Every win in this push is sound by construction:
- MOBILE PCS config: same 96-bit conjectured security
  (`pow + n_queries · log_blowup = 20 + 38·2 = 96`).
- Dynamic component selection: chip skipped iff its lookup
  producers/consumers all have multiplicity 0.  Lookup balance
  catches a malicious skip naturally.
- Compile flags (native, LTO, PGO): purely codegen — no semantic
  change.

#### Plateau analysis (where we are)

After Phase 61, the prove-time breakdown at log14 MOBILE (1.07 s):
- FRI prove: ~39%
- main_commit: ~31%
- interaction_commit: ~11%
- interaction_gen: ~10%
- preprocess + trace: ~9%

Easy levers exhausted:
- ❌ par_iter `interaction_gen` — rayon scheduling overhead exceeds
  10 ms gain (regression -10%).  Stwo's internal rayon already
  saturates the cache-bandwidth ceiling at ~10 cores.
- ❌ Aggressive LLVM tuning (`-inline-threshold=400` etc.) —
  regression vs vanilla PGO; PGO data already targets the right
  hot paths.
- ❌ `mir-opt-level=4` — invalidates PGO profile data → reverts to
  no-PGO performance.

Remaining theoretical levers (multi-day effort each, smaller
single-digit % gains):
- **Memory family chip extraction** (Phase 54-style): drop ~30
  cells from CpuChip.  ~3-5% additional prove saving.
- **JumpInd family chip extraction**: drop ~24 cells.  ~2-3%.
- **Caching preprocessed trace per program**: amortises the ~50ms
  preprocessing cost across multiple proves of the same program.
  Multi-prove win, not single-prove.
- **Multi-process / batch proving**: orthogonal architectural
  change.  Splits a long workload across processes; aggregates
  via recursion.  Sidesteps the single-prove memory ceiling.

### Phase 58 — multi-threading scoping (research, superseded by Phase 59)

#### Status check: what parallelism we already have

Stwo's `parallel` Cargo feature has been enabled since the start
(workspace `Cargo.toml:44, 49`), and stwo internally uses rayon
for FFT, bit-reverse, Merkle commitment, and quotient evaluation.
The BENCHMARKS.md "single-threaded" caveat was stale.

Measured at log14 on the 22-core test bench (Intel Core Ultra 7
155H), single trial:

| Configuration               | Prove time |
|---                          |---         |
| `RAYON_NUM_THREADS=1`        | 9.68 s     |
| Default (rayon picks cores) | 5.54 s     |

**Existing speedup: 1.75×** — far below the 22× theoretical max.
The remaining headroom comes from two places: (a) Stwo's
parallelism is intra-component (within a single FFT or Merkle
tree) and limited by chip log_size; (b) zkpvm's `prove_impl`
processes components sequentially in `iter().map().collect()`
loops at trace_gen, interaction_gen, and tree-builder
extend_evals.

#### Where the wall-clock goes (log14, post-Phase-54k)

| Stage                | Time   | %    | Parallelism status                       |
|---                   |---     |---   |---                                       |
| trace_gen            | 0.07 s |  1%  | Serial; CpuChip dominates                |
| preprocess_commit    | 0.27 s |  5%  | Stwo-internal (rayon FFT + Merkle)       |
| main_commit          | 1.85 s | 34%  | Stwo-internal; one big tree              |
| interaction_gen      | 0.32 s |  6%  | Serial in our code                       |
| interaction_commit   | 0.75 s | 14%  | Stwo-internal; one big tree              |
| stark_prove (FRI)    | 2.24 s | 41%  | Stwo-internal                            |
| **Total**            | 5.51 s | 100% |                                          |

Stwo-internal: 89% of time.  Our serial loops: 7%.

#### Realistic upper bound

The workload at log14 commits 22 M cells × blowup 16 = 350 M
field evaluations.  At 4 B per element: 1.4 GB working set.
L3 cache on a 22-core desktop CPU is 24 MB.  Beyond ~6-8 cores
the FFT/Merkle phases hit memory-bandwidth saturation, not
core saturation.  **Realistic ceiling: 3-4× from current 1.75×,
not 22×.**  Translates to log14 prove ≈ 1.5-2 s.

That's enough to bring the gap vs Nexus zkVM 2.x (2.37 s at
log14) within striking distance — Nexus also uses stwo + rayon,
so this is more about closing the AIR-shape gap from the
prover-config side.

#### Sub-phase plan

**58a — `par_iter` the trace_gen loop** (`prove.rs:177-180`).
Most components don't mutate `SideNote`; only CpuChip + the
producers of the ECALL memory ledger do.  Approach: split into
two passes — Phase 58a-1 runs `&mut SideNote` consumers serially
(CpuChip), Phase 58a-2 par_iters the read-only consumers.
Estimated win: marginal (trace_gen is 1% of total).

**58b — par_iter the interaction_gen loop** (`prove.rs:235-245`).
`generate_interaction_trace` takes `&SideNote` (immutable) and a
shared `lookup_elements`.  Outputs are `(eval_vec, claimed_sum)`
pairs; collect via par_iter then serially `extend_evals` into the
tree builder.  Estimated win: 4-6% (interaction_gen is 6% of
total; ~80% parallelisable).

**58c — parallelise CpuChip's per-step main-trace fill**
(`cpu/trace_fill.rs:38`, the 32K-row loop).  Currently mutates
shared accumulators (`range_bytes`, `bitwise_and_bytes`,
`side_note.program_memory_counts`, `side_note.byte_to_bits_counts`,
`side_note.bitwise_and_counts`).  Approach: thread-local
accumulators + post-loop reduce; rayon `par_chunks_mut` on the
trace builder's underlying SoA storage.  Largest single-component
opportunity.  Effort: 1-2 days.  Estimated win: marginal — even
removing trace_gen entirely saves only 1% — but it unlocks 58d.

**58d — pre-fold CpuChip's circle-evaluation transform**
(`tree_builder.extend_evals` in `prove.rs:208-211, 218-222`).
If CpuChip's `to_circle_evaluation` is the bottleneck within
main_commit (need to confirm by sub-profiling), running it for
each component on a thread before extending into the builder
could amortise.  Stwo handles parallelism inside extend_evals
already, so this overlaps poorly — needs measurement.

**58e — explore cell-bandwidth optimisation**
(stwo-internal).  The 1.75× ceiling at 22 cores suggests
memory-bandwidth saturation.  Mitigations: smaller M31
representations (already 4 B), better cache locality in
`extend_evals`, or a different FRI ordering.  This is upstream
stwo work; not actionable at zkpvm level.

#### Recommended order

1. **58b** first (lowest risk, simple par_iter restructure of
   `prove_impl`'s interaction-gen loop, highest ROI per LoC).
2. **58a** second (similar shape, smaller win).
3. **58c** third (CpuChip main-trace fill parallelisation;
   bigger refactor, uncertain ROI).
4. Re-bench at each step; abort if memory-bandwidth saturation
   hits before 2× total.

#### Realistic target

If 58a+58b+58c land cleanly: log14 prove ≈ 3.5-4 s (current
5.4 s × 0.7×).  Combined with the cumulative 60% reduction
since Phase 50, that's ≈ 70-72% total reduction vs Phase 50
baseline — achievable, not transformative.

Beyond that, the realistic next lever is **batch proving**
(amortising one prove call over many segments) or a
**multi-process / multi-machine** setup (one prover per segment),
both of which sidestep the single-prove memory-bandwidth ceiling.
