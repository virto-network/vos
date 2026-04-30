# zkpvm — implementation status

A snapshot of which constraints / chips bind which PVM semantics
in-circuit, and which gaps remain prover-trusted.  Phase numbers
in `[brackets]` match the commit-message tags on the `zkvm`
branch — `git log --oneline --grep "Phase N"` finds the relevant
commit.

## What's bound

### Core ALU
- **Add / Sub** — carry-chain identity over 8 bytes, gated per
  opcode.  32-bit variants sign-extend `result[4..8]` to
  `0xFF · SignBitResult` `[19]`.
- **NegAdd** — sub with flipped sign, same carry chain `[2]`.
- **Mul** — schoolbook over 16 byte positions, 16-bit carry per
  position (`MulCarry` + `MulCarryHi`) `[12c, 15-mul-debug]`.
- **MulUpper UU / SU / SS** — high 64 of full product, with
  sign-correction columns `MulCorrTermA` / `TermB` /
  `MulCorrCarry` distinguishing the three signedness variants
  `[12c]`.
- **DivU / RemU 32 / 64** — schoolbook `q · d + r = b` mod 2^128,
  with `r < d` uniqueness via a separate carry chain
  (`DivCmpDiff` / `DivCmpCarry` + Range256 byte-checks) `[7a, 21]`.
- **DivS / RemS 64-bit** — sign-correction at the schoolbook's
  high bytes via `DivCorrHi` / `DivCorrCarry`:
  `high(q_u·d_u + r_u) ≡ sq·d_u + sd·q_u + sr − sa  (mod 2^64)`
  `[16]`.
- **DivS / RemS 32-bit** — analogous 4-byte chain `[18]`.

### Bitwise
- **And / Or / Xor / AndInv / OrInv / Xnor** — algebraic identity
  per byte, plus per-nibble AND lookup against
  `BitwiseLookupChip` for soundness `[6]`.

### Shifts
- **ShloL** (left) — encoded via `is_mul=true`; uses
  `PowerOfTwoChip` to bind `val_d = 2^shift_amount` `[6]`.
- **ShloR** (logical right) / **SharR** (arithmetic right) —
  encoded via `is_div_rem=true`; same power-of-two lookup `[6]`.
- **32-bit shift ShiftAmount uniqueness** — closed by an
  additional `val_d[4..8] = 0` constraint on `is_32bit ·
  is_shift_c` rows.  Without this, the [0, 63] PowerOfTwo table
  admits two byte-bounded ShiftAmount values for any
  modulus-32 reg_val_d, and a malicious prover could pick val_d
  = 2^32 (instead of 2^0) for shift-by-32 to forge a 0 result
  `[37]`.

### Compare
- **SetLtU** — `cmp_lt_flag = 1 - cmp_carry[7]` from the
  subtraction chain `[2]`.
- **SetLtS** — sign-aware `cmp_lt_s_flag` derived from
  `SignBitB` / `SignBitD`, both pinned by nibble-AND lookups to
  bit 7 of the multiplexed source byte (val_b[7] in 64-bit,
  val_b[3] in 32-bit) `[17]`.
- **Min / Max** (signed and unsigned) — multiplex on the
  appropriate `cmp_lt_*_flag` `[2]`.

### Branches
- **BranchEq / Ne / Lt / Ge / Le / Gt** (signed and unsigned) —
  share the compare chain; `branch_taken` then drives `next_pc`
  selection `[2]`.
- **Static branch / jump targets** — bound to canonical
  `pc + sign_extend(offset)` via `ProgramMemoryChip`'s
  `BranchTargetCanon` column `[15-branch-target-fix]`.
- **Dynamic dispatch** (`JumpInd`, `LoadImmJumpInd`) — bound to
  jump-table targets via `JumpTableChip` lookup
  `(addr=val_b+imm, target=next_pc) ∈ jump_table` `[13d]`.
- **Trap** — terminal-row constraint forbids any successor real
  row after a Trap step (gated on per-opcode `IsTrap`)
  `[13e-redux]`.

### BitManip
- **ReverseBytes** — `result[i] = val_d[7−i]` `[12b-1]`.
- **ZeroExtend16** — `result[0..2] = val_d[0..2]`,
  `result[2..8] = 0` `[12b-1]`.
- **SignExtend8 / SignExtend16** — `result[i] = 0xFF·SignExtBit`
  on bytes ≥ source-width, with `SignExtBit` pinned to bit 7 of
  the source byte via nibble-AND lookups `[12b-2, 17]`.
- **CountSetBits32 / 64** — per-byte popcount via new
  `PopcountChip` lookup table; `result[0] = sum(BytePopcount[..N])`
  (N = 4 if Is32Bit, 8 if 64-bit), `result[1..8] = 0` `[33]`.
- **LeadingZeroBits / TrailingZeroBits 32 / 64** — per-byte
  (lz, tz) via new `BitcountChip` lookup table; result formulas
  walk a "first-non-zero-byte" indicator built from Phase 29's
  `ValDByteInv` byte-zero-check infra.  TZ uses Phase 29's
  LSB-direction `ValDPartialNZ` chain; LZ uses two new
  cumulative-OR chains: `ValDPartialNZMsb[8]` (MSB direction
  over all 8 bytes, for LZ64) and `ValDPartialNZMsbLo[4]` (MSB
  over the low 4 bytes only, for LZ32).  Default fallback is
  64 / 32 when val_d (or low 4 bytes) is zero.  `result[1..8] = 0`
  `[34]`.
- **RotL64** — encoded via the mul-schoolbook (`val_d = 2^n`):
  `result = UnsignedProductLow + mul_high` (byte-wise sum, no
  carry — bits non-overlapping by construction) `[32]`.
- **RotR64 / RotR64Imm** — same shape as RotL64 but with the
  *complementary* power: `val_d = 2^((64 − n) mod 64)` so the
  schoolbook's low + high yield the rotated-right value.  The
  complement is pinned via a second shift-amount identity
  `RegValD + ShiftAmountCompl = 64 · ShiftQuotientCompl` plus a
  separate PowerOfTwo lookup keyed on `ShiftAmountCompl` `[35]`.
- **RotL32 / RotR32 / RotR32Imm** — 32-bit equivalents of Phase
  32/35: the 32-bit mul-schoolbook now writes low-32 to
  `UnsignedProductLow[0..4]` (re-routed) and high-32 to
  `mul_high[0..4]`; rotate result low 4 bytes = sum of the two
  halves, high 4 bytes = sign-extension via Phase 19.  The
  complementary shift identity uses modulus 32 (vs 64 for the
  64-bit variants); a `val_d[4..8] = 0` constraint pins
  ShiftAmount/ShiftAmountCompl ∈ [0, 31] uniquely `[36]`.
- **RotR64ImmAlt / RotR32ImmAlt** — swapped-operand variants
  where the immediate is the rotated value and `regs[rb]` is the
  shift amount.  Trace fill swaps val_b ← imm and val_d ←
  regs[rb] on these rows; reg_access also swaps val_b_read /
  val_d_read.  A new `val_b ↔ ImmBytes` constraint (low 4 bytes
  always; high 4 bytes match-or-zero gated on IsTruncated, same
  shape as the val_b ↔ reg_val_b cross-constraint) pins the
  swapped source.  All other rotate-r logic re-uses Phase 35/36
  via the existing IsRotateR64 / IsRotateR32 flags `[40]`.

### Sign-bit pinning
- `SignBitB / SignBitD / SignBitQ / SignBitR` — each pinned to
  bit 7 of its multiplexed source byte (val_b[7]/val_b[3] etc.)
  via two `BitwiseLookupChip` emissions per real row:
  `(HiNib, 8, 8·SignBit)` and `(Src − 16·HiNib, 0xF, same)`
  `[17, 18]`.
- `SignBitResult` — bit 7 of `result[3]`, drives 32-bit ALU
  result sign-extension `[19]`.
- `LoadSignBit` — bit 7 of multiplexed source byte
  (`result[0]/result[1]/result[3]` for I8/I16/I32), drives
  inactive-byte sign-extension on signed loads `[20]`.

### Memory
- **MemSize** — pinned to opcode-canonical width via
  `IsMemSize1/2/4/8` flags (each pinned by ProgramMemoryChip)
  `[23]`.
- **MemByteActive** — boolean per byte, monotonic prefix-1 of
  length MemSize, sum equals MemSize `[22]`.
- **Active-byte load result**: `result[i] = mem_value[i]` on
  load rows for active bytes `[15-load-result]`.
- **Inactive-byte load result**: `result[i] = 0xFF · LoadSignBit`
  on load rows for inactive bytes (signed: 0xFF·sign; unsigned:
  0) `[20]`.
- **MemAddr direct** (LoadU8/I8/U16/I16/U32/I32/U64,
  StoreU8/U16/U32/U64): `MemAddr = ImmBytes[0..4]` (the `addr =
  imm` pattern) `[25]`.
- **MemAddr indirect** (LoadInd*, StoreInd*, StoreImmInd*):
  byte-wise add-with-carry chain pinning
  `MemAddr = (val_b + ImmBytes) mod 2^32` `[26]`.
- **MemValue on direct stores** (StoreU8/U16/U32/U64): pinned to
  val_b active bytes `[24]`.

### Register-memory
- **Per-step ledger** (`RegisterMemoryChip` + boundary):
  every `regs_before[r]` read and `regs_after[r]` write at every
  PVM step appears in a per-(reg, value, ts) lookup, bound to
  the snapshot at boundary `[9]`.
- **Source-operand binding**: `ValBIsReg` / `ValDIsReg` flags
  + `RegValB` / `RegValD` columns tie `val_b` / `val_d` to
  the actual register snapshot `[9d, 9f, 9g]`.

### Program structure
- **Bytecode commitment**: `ProgramMemoryChip` preprocessed
  table holds `(pc, opcode, skip_len, reg_a/b/d, imm,
  flag_bag, imm_y_canon, branch_target_canon)` per
  basic-block-starting PC.  Verifier checks the program-hash
  matches the canonical decoding of `(code, bitmask)`
  `[13a/b/c, 13f]`.
- **PC sequencing**: `ProgramExecutionLookup` ties step `n`'s
  `next_pc` to step `n+1`'s `pc`, plus initial / final boundary
  via `ProgramBoundaryChip` `[4]`.

### Precompile
- **Blake2b ECALL** — `Blake2bChip` proves one full 12-round
  compression per ECALL.  Initial / final-state lookup against
  `Blake2bStateBoundary`, message-block lookup against memory,
  H-pointer / M-pointer / T / F binding to register snapshot
  `[8a/b/c, 8d, 9c, 9d, 9e]`.

## Open soundness gaps

None known on the common path.  Every PVM ISA opcode reachable
from RISC-V actor code (or from synthetic forge tests) is bound
by an algebraic constraint or terminally constrained.  The
items the earlier draft of this file listed have all been
closed:

- Memory: MemValue on indirect stores `[28]`; MemValue on
  StoreImm / StoreImmInd `[27]`; MemAddr on direct StoreImm
  `[27]`.
- Divrem: DivS `r < d` uniqueness `[30]` + sign-of-r `[31]`;
  DivByZero binding `[29]`.
- Sign / extension: CmovIz / CmovNz val_d_is_zero `[29]`
  (shared byte-wise zero-check with DivByZero).
- Rotate: RotL64 `[32]`, RotR64 + RotR64Imm `[35]`, RotL32 +
  RotR32 + RotR32Imm `[36]`, RotR64ImmAlt + RotR32ImmAlt `[40]`.
- BitManip: CountSetBits 32/64 `[33]`, LeadingZeroBits +
  TrailingZeroBits 32/64 `[34]`, Sbrk-as-terminal `[41]`.
- Smaller: 32-bit shift ShiftAmount uniqueness `[37]`;
  is_write discriminator forge tests `[39]`.

If further gaps surface (e.g. via a forge test or a careful
re-audit), they belong here when discovered.

## Test posture

- **Direct soundness tests** — every `*_negative.rs` suite has
  forge-the-result tests for the corresponding op family
  (alu, control_flow, memory, register ledger).  Phase 38
  extended coverage to every Phase-32–36 BitManip and rotate
  opcode (CountSetBits 32/64, LeadingZeroBits 32/64,
  TrailingZeroBits 64, RotL/R 32/64, RotR64 wraparound).
- **Coverage caveat**: the `forge_three_reg_result` /
  `forge_two_reg_result` helpers only mutate
  `step.regs_after[rd]`.  Forgery on auxiliary witness columns
  (e.g. directly mutating `SignBitB` while keeping val_b honest,
  forge `q' = q − 1, r' = r + d` on DivU, …) requires a
  column-level mutator the test harness doesn't currently
  provide — in those cases the regression sweep being green is
  the practical "doesn't break" signal, while the constraint's
  own integer-vs-field analysis is the soundness argument.
  Note that `forge_step_field` does cover step-level mutation
  (opcode, reg_a/b/d, imm, skip_len) used in the bitmanip suite
  for Phase 13b/13c authentication tests.
- **Performance baseline**: `prove_vos_actor` proves real RISC-V
  actor binaries (blake2b ECALL, fibonacci, hash benches) in
  ~5 min on a modern x86 desktop.

## How to read the source

- Start with `src/chips/cpu/mod.rs::add_constraints` — that's
  where 90% of the soundness work lives.
- Follow constraints by phase number tagged in comments
  (`Phase 13d:`, `Phase 16:`, …) — each tag points at one
  commit's worth of changes.
- `src/chips/cpu/columns.rs` is the canonical column listing —
  every Column has a doc-comment with which phase added it and
  what it binds.
- `src/chips/cpu/CONSTRAINTS.md` is the house rules — read it
  before adding any new constraint or lookup.
