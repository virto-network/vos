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

(in roughly priority order — closing the first few has the
biggest exposure-to-fix-cost ratio.  See
[`PLAN.md`](./PLAN.md) for full scoping.)

### Memory (post-Phase 26)
- **MemValue on indirect stores** — `StoreInd[U][8/16/32/64]`
  source value (`regs[ra]`) isn't in any AIR column.  Needs a
  new `RegValA` column with register-memory ledger producer
  (mirrors existing `RegValB` / `RegValD`).
- **MemValue on StoreImm / StoreImmInd** — value is `imm_y`,
  but `ImmYBytes` is currently only filled for `TwoRegTwoImm`
  (LoadImmJumpInd).  Needs trace fill extension to `TwoImm`
  / `OneRegTwoImm` categories.
- **MemAddr on direct StoreImm** — `addr = imm_x` → equivalent
  to Phase 25's binding once `IsLoadDirect+IsStoreDirect` is
  widened (or a new `IsStoreImmDirect` flag added).

### Divrem
- **DivS r < d uniqueness** — Phase 21 covers DivU only.
  Signed analogue is `|r| < |d|`, requires sign-aware
  comparison (4 sub-cases on (sd, sr) with auxiliary AbsR/AbsD
  columns or per-case carry chains).
- **DivByZero binding** — on `div_by_zero = 1` the schoolbook
  bypasses but `result` is unbound.  Closing it requires
  forcing `val_d = 0 ↔ div_by_zero = 1` (both directions:
  `→` is one line, `←` needs byte-wise zero-check via per-byte
  inversion witness + cumulative-OR).

### Sign / extension
- **CmovIz / CmovNz** — `val_d_is_zero` is one-direction-pinned.
  Same fix as DivByZero (shared byte-wise zero-check
  infrastructure would close both).

### Rotate
- **RotL32 / RotR32 / RotR64** (+ Imm / ImmAlt variants) —
  still prover-trusted.  RotR64 needs piecewise modular
  arithmetic for `(64 − n) mod 64`; the 32-bit variants need
  the same plus low-32-only handling.  RotL64 is closed in
  Phase 32 via the mul-schoolbook re-route.

### BitManip
- **Sbrk** — host-call-like; needs precompile-style integration.

### Smaller
- **`is_write` discriminator** on the memory-access lookup —
  uses `is_store_col` directly.  With Phase 23 pinning
  `is_store` from opcode this is sound; lacks an explicit
  forge test confirming a load row can't claim `is_write=1`.

## Test posture

- **Direct soundness tests** — every `*_negative.rs` suite has
  forge-the-result tests for the corresponding op family
  (alu, control_flow, memory, register ledger).
- **Coverage caveat**: the `forge_three_reg_result` helper only
  mutates `step.regs_after[rd]`.  Forgery on auxiliary columns
  (e.g. directly mutating `SignBitB` while keeping val_b honest,
  forge `q' = q − 1, r' = r + d` on DivU, …) requires a
  column-level mutator the test harness doesn't currently
  provide — in those cases the regression sweep being green is
  the practical "doesn't break" signal, while the constraint's
  own integer-vs-field analysis is the soundness argument.
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
