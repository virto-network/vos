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

### Future — RotR64ImmAlt + RotR32ImmAlt

Both have swapped operand semantics (immediate is the rotated
value, register is the shift amount).  Need a flag distinguishing
the two TwoRegOneImm variants and a swapped-source trace-fill path
(val_b ← imm, val_d ← regs[reg_b]).  Deferred.

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

### Phase 35 — Sbrk

Host-call-like: extends the heap.  Likely needs its own
precompile chip mirroring Blake2b's pattern.  Skip until there's
demand from a benchmark / actor.

## Cross-cutting

### Negative tests via column-level mutator

Several phases (17, 18, 21, 22, 24) note "indirect coverage" —
the AIR's regression sweep proves the constraint is satisfied on
honest traces, but a *direct* "forge column X to a wrong value"
test would require a column-level mutator the test harness
doesn't currently expose.

Adding a `forge_column` helper to `tests/common/mod.rs` (mutate a
specific column at a specific row before proving) would let every
existing phase add explicit forge-and-reject tests.  ~30 lines of
infra; closes the "pin + forge test" symmetry across the 7+
phases that currently rely on indirect coverage.

### Documentation upkeep

When adding a new phase:
- Tag commits with `Phase N:` prefix matching the phase number.
- Add the phase to [`STATUS.md`](./STATUS.md) — both the bound
  list and (if applicable) the open-gaps list.
- Update the deferred-pieces table in this file's relevant
  section.
- Cross-reference `[N]` from columns.rs / classify.rs doc-comments.
