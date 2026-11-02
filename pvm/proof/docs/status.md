# vos-pvm-proof — implementation status

Which constraints and chips bind which PVM semantics in the segment
AIR, and what stays outside the binding.  The format numbers and their
parameters are in the registry, `src/format.rs`; the trust boundary is
`SECURITY.md`.

## What's bound

### Core ALU
- **Add / Sub** — carry-chain identity over 8 bytes, gated per
  opcode.  32-bit variants sign-extend `result[4..8]` to
  `0xFF · SignBitResult`.
- **NegAdd** — sub with flipped sign, same carry chain.
- **Mul** — schoolbook over 16 byte positions, 16-bit carry per
  position (`MulCarry` + `MulCarryHi`); every
  product byte and carry Range256-checked, so the chain is the exact
  integer product.
- **MulUpper UU / SU / SS** — high 64 of full product, with
  sign-correction columns `MulCorrTermA` / `TermB` /
  `MulCorrCarry` distinguishing the three signedness variants.
- **DivU / RemU 32 / 64** — schoolbook `q · d + r = b + 2^W·H` over
  the integers (quotient, remainder, `H` and every carry Range256-checked),
  `H = 0`, with `r < d` uniqueness via a separate carry chain
  (`DivCmpDiff` / `DivCmpCarry`).
- **DivS / RemS 64-bit** — sign-correction at the schoolbook's
  high bytes via `DivCorrHi` / `DivCorrCarry`:
  `H ≡ sq·d_u + sd·q_u + sr − sa + k  (mod 2^64)`, `k` the `MIN / −1`
  overflow, and `|r| < |d|` through magnitude chains.
- **DivS / RemS 32-bit** — analogous 4-byte chain, the divisor's magnitude
  taken of its sign-extended low word.

### Bitwise
- **And / Or / Xor / AndInv / OrInv / Xnor** — algebraic identity
  per byte, plus per-nibble AND lookup against
  `BitwiseLookupChip` for soundness.

### Shifts
- **ShloL** (left) — encoded via `is_mul=true`; uses
  `PowerOfTwoChip` to bind `val_d = 2^shift_amount`.
- **ShloR** (logical right) — encoded via `is_mul=true`: a
  multiplication by `2^ShiftAmountCompl`, the complement pinned as
  for RotR below, whose high word is the result (its low word when
  the amount is 0, `ShiftZero`).
- **SharR** (arithmetic right) — encoded via `is_div_rem=true`, same
  power-of-two lookup; flagged `is_shar_r` in the DivRem tuple, floor
  division (`H ≡ sq·d − sa`).  Flag byte 0's bit 3 commits a right
  shift, and `IsMul` tells the two apart.
- **32-bit shift ShiftAmount uniqueness** — closed by an
  additional `val_d[4..8] = 0` constraint on `is_32bit ·
  is_shift_c` rows.  Without this, the [0, 63] PowerOfTwo table
  admits two byte-bounded ShiftAmount values for any
  modulus-32 reg_val_d, and a malicious prover could pick val_d
  = 2^32 (instead of 2^0) for shift-by-32 to forge a 0 result.

### Compare
- **SetLtU** — `cmp_lt_flag = 1 - cmp_carry[7]` from the
  subtraction chain.
- **SetLtS** — sign-aware `cmp_lt_s_flag` derived from
  `SignBitB` / `SignBitD`, both pinned by nibble-AND lookups to
  bit 7 of the multiplexed source byte (val_b[7] in 64-bit,
  val_b[3] in 32-bit).
- **Min / Max** (signed and unsigned) — multiplex on the
  appropriate `cmp_lt_*_flag`.

### Branches
- **BranchEq / Ne / Lt / Ge / Le / Gt** (signed and unsigned) —
  share the compare chain; `branch_taken` then drives `next_pc`
  selection.
- **Static branch / jump targets** — bound to canonical
  `pc + sign_extend(offset)` via `ProgramMemoryChip`'s
  `BranchTargetCanon` column.
- **Dynamic dispatch** (`JumpInd`, `LoadImmJumpInd`) — bound to
  jump-table targets via `JumpTableChip` lookup
  `(addr=val_b+imm, target=next_pc) ∈ jump_table`.
- **Trap** — terminal-row constraint forbids any successor real
  row after a Trap step (gated on per-opcode `IsTrap`).

### BitManip
- **ReverseBytes** — `result[i] = val_d[7−i]`.
- **ZeroExtend16** — `result[0..2] = val_d[0..2]`,
  `result[2..8] = 0`.
- **SignExtend8 / SignExtend16** — `result[i] = 0xFF·SignExtBit`
  on bytes ≥ source-width, with `SignExtBit` pinned to bit 7 of
  the source byte via nibble-AND lookups.
- **CountSetBits32 / 64** — per-byte popcount via the
  `PopcountChip` lookup table; `result[0] = sum(BytePopcount[..N])`
  (N = 4 if Is32Bit, 8 if 64-bit), `result[1..8] = 0`.
- **LeadingZeroBits / TrailingZeroBits 32 / 64** — per-byte
  (lz, tz) via the `BitcountChip` lookup table; result formulas
  walk a "first-non-zero-byte" indicator built from the
  `ValDByteInv` byte-zero check (shared with DivByZero and
  CmovIz / CmovNz).  TZ uses the LSB-direction `ValDPartialNZ`
  chain; LZ uses two cumulative-OR chains: `ValDPartialNZMsb[8]` (MSB direction
  over all 8 bytes, for LZ64) and `ValDPartialNZMsbLo[4]` (MSB
  over the low 4 bytes only, for LZ32).  Default fallback is
  64 / 32 when val_d (or low 4 bytes) is zero.  `result[1..8] = 0`.
- **RotL64** — encoded via the mul-schoolbook (`val_d = 2^n`):
  `result = UnsignedProductLow + mul_high` (byte-wise sum, no
  carry — bits non-overlapping by construction).
- **RotR64 / RotR64Imm** — same shape as RotL64 but with the
  *complementary* power: `val_d = 2^((64 − n) mod 64)` so the
  schoolbook's low + high yield the rotated-right value.  The
  complement is pinned via a second shift-amount identity
  `RegValD + ShiftAmountCompl = 64 · ShiftQuotientCompl` plus a
  separate PowerOfTwo lookup keyed on `ShiftAmountCompl`.
- **RotL32 / RotR32 / RotR32Imm** — 32-bit equivalents of RotL64 /
  RotR64: the 32-bit mul-schoolbook writes low-32 to
  `UnsignedProductLow[0..4]` and high-32 to
  `mul_high[0..4]`; rotate result low 4 bytes = sum of the two
  halves, high 4 bytes = the 32-bit result sign-extension.  The
  complementary shift identity uses modulus 32 (vs 64 for the
  64-bit variants); a `val_d[4..8] = 0` constraint pins
  ShiftAmount/ShiftAmountCompl ∈ [0, 31] uniquely.
- **RotR64ImmAlt / RotR32ImmAlt** — swapped-operand variants
  where the immediate is the rotated value and `regs[rb]` is the
  shift amount.  Trace fill swaps val_b ← imm and val_d ←
  regs[rb] on these rows; reg_access also swaps val_b_read /
  val_d_read.  A `val_b ↔ ImmBytes` constraint (low 4 bytes
  always; high 4 bytes match-or-zero gated on IsTruncated, same
  shape as the val_b ↔ reg_val_b cross-constraint) pins the
  swapped source.  All other rotate-right logic is RotR64's and
  RotR32's, via the IsRotateR64 / IsRotateR32 flags.

### Sign-bit pinning
- `SignBitB / SignBitD / SignBitQ / SignBitR` — each pinned to
  bit 7 of its multiplexed source byte (val_b[7]/val_b[3] etc.)
  via two `BitwiseLookupChip` emissions per real row:
  `(HiNib, 8, 8·SignBit)` and `(Src − 16·HiNib, 0xF, same)`.
- `SignBitResult` — bit 7 of `result[3]`, drives 32-bit ALU
  result sign-extension.
- `LoadSignBit` — bit 7 of multiplexed source byte
  (`result[0]/result[1]/result[3]` for I8/I16/I32), drives
  inactive-byte sign-extension on signed loads.

### Memory
- **MemSize** — pinned to opcode-canonical width via
  `IsMemSize1/2/4/8` flags (each pinned by ProgramMemoryChip).
- **MemByteActive** — boolean per byte, monotonic prefix-1 of
  length MemSize, sum equals MemSize.
- **Active-byte load result**: `result[i] = mem_value[i]` on
  load rows for active bytes.
- **Inactive-byte load result**: `result[i] = 0xFF · LoadSignBit`
  on load rows for inactive bytes (signed: 0xFF·sign; unsigned:
  0).
- **MemAddr direct** (LoadU8/I8/U16/I16/U32/I32/U64,
  StoreU8/U16/U32/U64): `MemAddr = ImmBytes[0..4]` (the `addr =
  imm` pattern).
- **MemAddr indirect** (LoadInd*, StoreInd*, StoreImmInd*):
  byte-wise add-with-carry chain pinning
  `MemAddr = (val_b + ImmBytes) mod 2^32`.
- **MemValue on stores** — pinned to val_b's active bytes on
  direct and indirect stores, and to the immediate on StoreImm /
  StoreImmInd (an 8-byte immediate store's high word through
  `ImmYBytes` and ProgramMemory's `ImmYCanon`).
- **Address range** — a standard load or store proves its whole
  scalar range stays outside the protected low 64 KiB and does not
  wrap through 2^32.
- **The RAM ledger** (`MemoryChip`): read-consistent and sorted by
  `(addr, ts)`, as the register ledger below; every accessed address
  lies in a page the segment lists, and each address group starts
  at its page's ts = 0 write and ends at its closing read.
- **Page permissions** — `MemoryPageChip` carries the program's
  layout as preprocessed regions (read-only data and the argument
  window readable; read-write data, heap and stack writable; nothing
  else mapped), and its ts = 0 writes carry each page's permission.
  `MemoryChip` refuses a write to a page not writable and any access
  to a page not readable.
- **Memory roots** — the entering and exit images of the listed
  pages hash, through a page-keyed blake2b Merkle multiproof
  (`Memory{Page,Merkle,RootBoundary}Chip` + `Blake2bBoundaryChip`), to
  `initial_state.memory_root` and `final_state.memory_root`; see
  `docs/design/memory-merkle-binding.md`.

### Register-memory
- **Per-step ledger** (`RegisterMemoryChip` + boundary):
  every `regs_before[r]` read and `regs_after[r]` write at every
  PVM step appears in a per-(reg, value, ts, is_write) lookup, bound
  to the snapshot at boundary.  One access a row; each register's
  chain starts at its ts = 0 boundary write and ends at the closing
  read (`RegisterMemoryClosingChip`, at `final_state.timestamp`),
  which pins the final registers.
- **Read-consistency** — each read's value is bound cross-row to
  the previous same-register row's value, the ledger is sorted by
  `(reg, ts)` with a register's reads before its writes within a
  timestamp, and `is_write` is in the tuple, so a read cannot pose
  as a write; see `docs/design/ledger-read-consistency.md`.  The
  ordering deltas are 28-bit decompositions: they cover the 100M-gas
  actor-proof budget and stay well below the M31 modulus, so a
  wrapped negative has no decomposition.
- **Source-operand binding**: `ValBIsReg` / `ValDIsReg` flags
  + `RegValB` / `RegValD` columns tie `val_b` / `val_d` to
  the actual register snapshot.

### Program structure
- **Bytecode commitment**: `ProgramMemoryChip` preprocessed
  table holds `(pc, opcode, skip_len, reg_a/b/d, imm,
  flag_bag, imm_y_canon, branch_target_canon)` and the precompile
  dispatch id per instruction start; it serves only instruction
  starts (a preprocessed `IsInstruction`).  Verifier checks the
  program-hash matches the canonical decoding of `(code, bitmask)`.
- **PC and timestamp sequencing**: `ProgramExecutionLookup` ties step
  `n`'s `next_pc` to step `n+1`'s `pc`, plus initial / final boundary
  via `ProgramBoundaryChip`; `NextTimestamp = Timestamp + 1` by a
  range-checked carry chain, so every step's ts lies in
  `[initial_ts, final_ts)`, and `initial_ts ≥ 1`.
- **Halt and trap**: a halting step's `next_pc` is `PVM_HALT_ADDR`
  (2^32 − 2^16), which no code offset reaches, so a segment's final
  pc is the halt address exactly when it ends at a halt; a trap keeps
  `next_pc = pc`.
- **Host calls**: CpuChip commits whether a supported ECALLI was
  continued, constrains the handled and cause pcs across segment
  boundaries, and a continued call selects exactly the handler
  relation of the dispatch id ProgramMemory authenticates.
- **No gas** — the AIR proves no gas accounting.

### Boundary
- **Boundary binding** — verifiers recompute each boundary chip's
  logup claimed sum from `proof.{initial,final}_state` (registers, pc,
  timestamp, memory root) with the Fiat–Shamir-drawn lookup elements
  and require it to equal the proof's, so the public boundary states
  are the committed boundary columns, and those are the trace's.
  The states and the full PCS configuration enter the Fiat–Shamir
  transcript.
- **`memory_commitment`** stays unbound metadata: it is computed
  outside the circuit and has no committed column.  The memory root
  is what binds RAM.

### Precompile
- **Blake2b ECALL** — `Blake2bChip` proves one full 12-round
  compression per ECALL.  Initial / final-state lookup against
  `Blake2bStateBoundary`, message-block lookup against memory,
  H-pointer / M-pointer / T / F binding to register snapshot.
  `IsReal` holds across a compression, a trailing partial block is
  refused, and its addresses are derived by byte carries on every
  row, from 32-bit pointers.
- **Poseidon2 call** (`0x402`) — `Poseidon2Chip`, one permutation a
  row, consumes the call the CPU row produces, reads its 64 input
  bytes and writes its 32 output bytes through the memory ledger at
  the call's timestamp, each word canonical below p.
- **Witness input** (`0x401`) — CpuChip binds the call's destination
  (φ7), capacity (φ8) and count (written to φ7, at most φ8), and
  `WitnessInputChip` writes exactly that many bytes, contiguous from
  the destination with no wrap past 2^32, at the call's timestamp.
- Precompile ids 110–114 are served by no chip: a kernel that
  reaches one is refused at derive.

## Open soundness gaps

**Per-opcode ISA coverage: no known gaps.**  Every PVM ISA opcode
reachable from RISC-V actor code (or from synthetic forge tests) is
bound by an algebraic constraint or terminally constrained.  The
parts not yet under a forgery gate, and the external audit's scope,
are in `SECURITY.md`.  A gap found by a forge test or a re-audit
belongs here.

## Test posture

- **Forgery gates** (`tests/gates/*_gate.rs`) — each builds an
  honest trace, edits the columns a from-scratch prover controls into
  a consistent forgery, and asserts the AIR refuses it.
- **Result forgery** — every `*_negative.rs` suite has
  forge-the-result tests for its op family (alu, control_flow,
  memory, register ledger), BitManip and the rotates among them.
  Their helpers (`tests/common/mod.rs`) mutate `step.regs_after[rd]`;
  a forgery on an auxiliary witness column is a gate's.

## How to read the source

- Start with `CpuChip::add_constraints` (`src/chips/cpu/constraints/`) — that's
  where 90% of the soundness work lives.
- `src/chips/cpu/columns.rs` is the canonical column listing —
  every Column has a doc-comment saying what it binds.
- `src/chips/cpu/CONSTRAINTS.md` is the house rules — read it
  before adding any new constraint or lookup.
