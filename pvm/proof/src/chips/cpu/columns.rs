//! CpuChip AIR column layout — one row per PVM step.
//!
//! Holds the program-counter / opcode / operands, the operation-category and
//! sub-op flags (add/sub/mul/bitwise/shift/compare/branch/divrem/memory/...),
//! the auxiliary witnesses (carry chains, AND nibbles, sign bits, equality
//! witnesses), the register-memory binding witnesses (ValB/ValD/Result reg
//! sources + indices), and the Blake2b ECALL-binding columns (φ[10/11/12/7]
//! + FlagBool inversion witness).

use crate::air_column::{AirColumn, PreprocessedAirColumn};

#[derive(Debug, Copy, Clone, AirColumn)]
#[row = "Row"]
pub enum Column {
    #[size = 8]
    Timestamp,
    #[size = 4]
    Pc,
    #[size = 4]
    NextPc,
    /// Exact encoded opcode byte. Its semantic decoding is authenticated by
    /// the ProgramMemory-derived flag bytes.
    #[size = 1]
    Opcode,
    #[size = 1]
    SkipLen,
    /// Carry chain for sequential PC addition: next_pc = pc + 1 + skip_len,
    /// bits on every row, so the sequential next pc's limbs are canonical.
    #[size = 3]
    PcCarry,
    #[size = 1]
    RegA,
    #[size = 1]
    RegB,
    #[size = 1]
    RegD,
    /// First source operand (8 limbs).
    #[size = 8]
    ValB,
    /// Second source operand (8 limbs).
    #[size = 8]
    ValD,
    /// Result value (8 limbs).
    #[size = 8]
    Result,
    /// Auxiliary carry/borrow (8 limbs), bits on every row. Used by add/sub.
    #[size = 8]
    Carry,
    /// `mask_next_row` so the terminal-row constraint can read the *next*
    /// row's IsPadding to assert that any real Trap step has no successor
    /// real row.  Gated on the per-opcode IsTrap flag (not IsExit, which
    /// also covers Ecalli and JumpInd — too broad).
    #[size = 1]
    #[mask_next_row]
    IsPadding,
    // ── Operation category flags ──
    #[size = 1]
    IsAdd,
    #[size = 1]
    IsSub,
    #[size = 1]
    IsMul,
    // IsBitwise is the sum (IsAnd + IsOr + IsXor + IsAndInv + IsOrInv +
    // IsXnor).  Verifier-side gates use the sum expression; the prover-
    // side prog_mem closure overrides the slot.  The lookup balance pins
    // the sum to the canonical IsBitwise.
    #[size = 1]
    IsShift,
    // IsCompare is the 8-sub-flag sum (IsSetLtU + IsSetLtS + IsCmovIz +
    // IsCmovNz + IsMinS + IsMinU + IsMaxS + IsMaxU).  Verifier-side gates
    // use the sum expression; the prover-side prog_mem closure overrides
    // the slot.  The lookup balance pins the sub-flag sum to canonical.
    #[size = 1]
    IsMove,
    #[size = 1]
    Is32Bit,
    /// Bitwise sub-op flags (exactly one is 1 when IsBitwise=1)
    #[size = 1]
    IsAnd,
    #[size = 1]
    IsOr,
    #[size = 1]
    IsXor,
    #[size = 1]
    IsAndInv,
    #[size = 1]
    IsOrInv,
    #[size = 1]
    IsXnor,
    #[size = 1]
    IsNegAdd,
    // The schoolbook + sign-correction + result-variant binding all live
    // on MulChip's narrower trace.  CpuChip's `result` on mul rows binds
    // to MulChip's `result` via the 35-limb lookup tuple.
    // IsMulUpper is the sum (IsMulUpperUU + IsMulUpperSU + IsMulUpperSS).
    // Verifier-side reads use the sum expression directly; prover-side
    // prog_mem tuple emission overrides the sum slot in its closure (see
    // cpu/interaction.rs).
    // CpuChip's `result` on bitwise rows binds to BitwiseChip's `result`
    // via the BitwiseLookup tuple (30 limbs); BitwiseChip's AIR proves the
    // per-op result identity (AND/OR/XOR/AndInv/OrInv/Xnor) and emits the
    // 16 nibble-AND lookups against BitwiseLookupChip.
    // ── Compare auxiliary ──
    /// Compare sub-op flags (exactly one is 1 when IsCompare=1)
    #[size = 1]
    IsSetLtU,
    #[size = 1]
    IsSetLtS,
    /// Swap modifier for SetGtSImm/SetGtUImm: when 1, val_b ← imm and
    /// val_d ← regs\[rb\] (so the SetLt comparison yields the GT result).
    /// Not a compare-partition sub-flag; co-occurs with IsSetLtS/IsSetLtU.
    #[size = 1]
    IsSetGt,
    #[size = 1]
    IsCmovIz,
    #[size = 1]
    IsCmovNz,
    /// CmovIzImm/CmovNzImm operand-swap modifier: val_b ← imm (the moved
    /// value, pinned to ImmBytes), val_d ← regs\[rb\] (the condition).
    /// Not a compare-partition sub-flag; co-occurs with IsCmovIz/IsCmovNz.
    #[size = 1]
    IsCmovImm,
    #[size = 1]
    IsMinS,
    #[size = 1]
    IsMinU,
    #[size = 1]
    IsMaxS,
    #[size = 1]
    IsMaxU,
    /// The "less-than" flag derived from cmp_carry (1 if val_b < val_d unsigned)
    #[size = 1]
    CmpLtFlag,
    /// 1 if val_d == 0 (all limbs zero). Used for CmovIz/CmovNz.
    #[size = 1]
    ValDIsZero,
    /// Sign bit of val_b (bit 63 for 64-bit, bit 31 for 32-bit). Used for signed compare.
    #[size = 1]
    SignBitB,
    /// Sign bit of val_d.
    #[size = 1]
    SignBitD,
    /// Signed less-than flag: 1 if val_b < val_d (signed).
    #[size = 1]
    CmpLtSFlag,
    /// 1 iff val_b == val_d (all bytes equal), on every compare and branch
    /// row: `eq_flag=1 ⇒ val_b[i] = val_d[i]` byte by byte, and
    /// `eq_flag = 1 − EqDiffSquaresTimesInvH`, 1 when they are equal. The
    /// equality branches take it as their condition, the Le/Gt ones add it
    /// to their less-than.
    #[size = 1]
    EqFlag,
    // BranchEq / BranchNe constraints read `val_b[i] - val_d[i]` directly:
    //   is_br_eq · branch_taken · (val_b[i] - val_d[i]) = 0
    //   is_br_ne · (1 - branch_taken) · (val_b[i] - val_d[i]) = 0
    // ── Shift auxiliary ──
    #[size = 1]
    ShiftAmount,
    /// 1 when is_shift AND shift_op ∈ {0,1} (left shift or logical right shift)
    #[size = 1]
    IsShiftConstrained,
    /// Raw u64 of `regs_before[reg_a_or_b]` whenever ValBIsReg=1.
    /// For 64-bit ops ValB == RegValB (constrained byte-wise); for 32-bit
    /// ALU ops ValB is truncated to `RegValB & 0xFFFFFFFF` so the upper
    /// bytes of ValB are zero while RegValB carries the full register value.
    /// Ledger producer uses RegValB; ALU constraints keep using ValB.
    #[size = 8]
    RegValB,
    /// 1 iff Is32Bit · (IsAdd + IsSub + IsMul + IsDivRem), so the
    /// ValB/ValD upper-4-bytes-equal-zero constraints gate correctly.  Tied
    /// to that product via a validity constraint below.
    #[size = 1]
    IsTruncated,
    /// ValD's source: `regs_before[reg_b]` when ValDIsReg=1, the
    /// instruction's immediate otherwise (pinned to ImmBytes).  For
    /// non-shift non-32-bit ops ValD == RegValD (constrained below); for
    /// shifts ValD gets rewritten to `2^shift_amount` but RegValD keeps the
    /// raw shift operand so the identity below binds the amount to it.
    #[size = 8]
    RegValD,
    /// The bits of `k` in `RegValD[0] = ShiftAmount + 32·k` on shift rows:
    /// as `modulus` divides 256, the amount is the low byte's residue, and
    /// every term is small, so the identity holds over the integers.  On a
    /// 64-bit shift `k` is even, making the modulus 64.
    #[size = 3]
    ShiftQuotient,
    // ── Control flow ──
    // IsBranch is the 10-sub-flag sum (IsBrEq + IsBrNe + IsBrLtU + IsBrGeU
    // + IsBrLeU + IsBrGtU + IsBrLtS + IsBrGeS + IsBrLeS + IsBrGtS).
    // Verifier-side gates use the sum expression; the prover-side prog_mem
    // closure overrides the slot.  The lookup balance forces sum ==
    // canonical.
    /// Branch comparison type flags (exactly one is set when IsBranch=1)
    #[size = 1]
    IsBrEq,
    #[size = 1]
    IsBrNe,
    #[size = 1]
    IsBrLtU,
    #[size = 1]
    IsBrGeU,
    #[size = 1]
    IsBrLeU,
    #[size = 1]
    IsBrGtU,
    #[size = 1]
    IsBrLtS,
    #[size = 1]
    IsBrGeS,
    #[size = 1]
    IsBrLeS,
    #[size = 1]
    IsBrGtS,
    /// Unconditional jump (Jump, JumpInd, Fallthrough, Unlikely, LoadImmJump)
    #[size = 1]
    IsJump,
    /// Branch was taken (1) or fell through (0)
    #[size = 1]
    BranchTaken,
    /// Branch/jump target address (4 limbs, u32)
    #[size = 4]
    BranchTarget,
    // ── DivRem auxiliary ──
    /// 1 if this is a div/rem op
    #[size = 1]
    IsDivRem,
    /// 0 = DivU, 1 = DivS, 2 = RemU, 3 = RemS
    #[size = 1]
    DivRemOp,
    /// Quotient (8 limbs). For div ops: quotient = result. For rem ops: prover-provided.
    #[size = 8]
    DivQuotient,
    /// Remainder (8 limbs). For rem ops: remainder = result. For div ops: prover-provided.
    #[size = 8]
    DivRemainder,
    /// 1 if divisor is zero (special-case handling)
    #[size = 1]
    DivByZero,
    // ── Memory access ──
    /// 1 if this is a load instruction
    #[size = 1]
    IsExit,
    #[size = 1]
    IsLoad,
    // IsStore is the sum (IsStoreDirect + IsStoreImmAny + IsStoreInd).
    // Verifier-side gates use the sum expression; the prover-side prog_mem
    // closure overrides the tuple slot.  The byte-level memory access
    // lookup uses the same sum as its is_write column.
    /// Memory address (4 limbs, u32) — only valid when IsLoad or IsStore
    #[size = 4]
    MemAddr,
    /// Memory value (8 limbs) — the byte value per-byte for the lookup
    #[size = 8]
    MemValue,
    /// Number of bytes accessed (1, 2, 4, or 8)
    #[size = 1]
    MemSize,
    /// Per-byte active flags for memory lookup (1 if byte_i < mem_size)
    #[size = 8]
    MemByteActive,
    /// Per-byte address carry chain for the memory lookup. Byte `i` of an
    /// access at base address `MemAddr` lives at `MemAddr + i`, whose
    /// canonical 4-byte little-endian decomposition needs carry propagation
    /// (a misaligned multi-byte access can cross a 256-byte boundary, e.g.
    /// an 8-byte store at `…fb`). `MemByteAddrCarry{1,2,3}[i]` are the carries
    /// out of address bytes 0,1,2 when adding `i` — so the emitted byte
    /// address is `(MemAddr[0]+i−256·c1, MemAddr[1]+c1−256·c2,
    /// MemAddr[2]+c2−256·c3, MemAddr[3]+c3)`. The carries telescope (the
    /// numeric address is always `base+i` for any boolean choice), and
    /// matching the MemoryChip ledger's canonical bytes pins them. Without
    /// this, byte addresses past a 256-boundary would mismatch the ledger and
    /// the memory logup would not balance; aligned accesses never overflow, so
    /// this only matters for misaligned cross-boundary accesses.
    #[size = 8]
    MemByteAddrCarry1,
    #[size = 8]
    MemByteAddrCarry2,
    #[size = 8]
    MemByteAddrCarry3,
    // ── Program execution sequencing ──
    /// timestamp + 1 (8 limbs), used for the program execution lookup
    #[size = 8]
    NextTimestamp,
    /// Boolean carry chain pinning `NextTimestamp` to the canonical
    /// limb-wise increment of `Timestamp`.  Without it the program
    /// execution lookup is a bare multiset permutation over
    /// (ts, pc) → (next_ts, next_pc) pairs, which balanced phantom
    /// cycles at arbitrary timestamps can satisfy — letting forged
    /// rows emit register/memory tuples outside [initial_ts,
    /// final_ts).  Limb 7 takes carry 6 and has no outgoing carry, so
    /// the increment can never wrap back to a small tuple; closing a
    /// cycle would need ≥ 2^24 rows (every carry level must overflow),
    /// far above any trace size.
    #[size = 7]
    TsCarry,
    // ── Blake2b ECALL binding ──
    /// 1 iff this step is the blake2b hostcall (Ecalli opcode with imm =
    /// ECALL_BLAKE2B_COMPRESS).  Prover-witnessed; logup balance with
    /// Blake2bChip forces this to be set correctly for every blake2b call.
    #[size = 1]
    IsBlakeEcall,
    // ── The BLAKE2b call's slots, each the register it reads
    // (`tuples::BLAKE2B_CALL_REGS`) ──
    /// h_ptr slot (sourced from φ\[7\]; low 4 bytes flow into the
    /// Blake2bCall tuple as h_ptr).  Full u64 witnessed so the upper
    /// 32 bits can hold whatever regs_before\[7\] held.
    #[size = 8]
    HPtr,
    /// m_ptr slot (sourced from φ\[8\]).  Low 4 bytes flow into the
    /// Blake2bCall tuple as m_ptr.
    #[size = 8]
    MPtr,
    /// t_low slot (sourced from φ\[9\]).  Full 8 bytes flow into the
    /// Blake2bCall tuple as T.
    #[size = 8]
    TLow,
    /// f_flag slot (sourced from φ\[10\] = a3).  Full u64 of regs_before\[10\].
    /// FlagBool below is the boolean form `(regs_before[10] != 0)`,
    /// which is what flows into the Blake2bCall tuple as F.
    #[size = 8]
    Flag,
    /// Inversion witness for the f_flag slot: the inverse of the sum of
    /// Flag's bytes, or 0 when it is 0. The sum, at most 2040, is zero
    /// exactly when the register is, so it constrains FlagBool =
    /// (Flag != 0) in-circuit as the register's value, not its field
    /// reduction.
    #[size = 1]
    FlagInv,
    /// Boolean form of the f_flag slot: 1 if regs_before\[10\] != 0.
    /// The prover fills this and the lookup balance keeps it tied to
    /// the Blake2bChip.F column at the matching compression.
    #[size = 1]
    FlagBool,
    // ── Register-memory binding ──
    /// 1 iff ValB was sourced from a register read at this step.  See
    /// `val_b_read_reg` for the per-category mapping.  Gates the ValB
    /// register-memory producer emission.
    #[size = 1]
    ValBIsReg,
    /// Register index ValB reads when ValBIsReg=1: RegA when ValBFromA,
    /// otherwise RegB, on every row.
    #[size = 1]
    ValBRegIdx,
    /// 1 iff ValB's register is RegA rather than RegB, as the instruction
    /// fixes it (flag byte 6).
    #[size = 1]
    ValBFromA,
    /// 1 iff ValD was sourced from a register read.
    #[size = 1]
    ValDIsReg,
    /// Register index ValD reads when ValDIsReg=1: RegB on every row.
    #[size = 1]
    ValDRegIdx,
    /// 1 iff Result is written to a register at this step: whenever the
    /// instruction writes one (flag byte 6), except a conditional move that
    /// does not move, and a witness-input call's count.  Gates the Result
    /// register-memory producer.
    #[size = 1]
    ResultIsReg,
    /// Register index Result is written to when ResultIsReg=1: RegD when
    /// ResultToD, otherwise RegA, or 7 on a witness-input call.
    #[size = 1]
    ResultRegIdx,
    /// 1 iff the result's register is RegD rather than RegA, as the
    /// instruction fixes it (flag byte 6).
    #[size = 1]
    ResultToD,
    // ── BitManip permutation/zero-extend ──
    /// 1 iff this step is `ReverseBytes` (result\[i\] = val_d[7-i]).
    #[size = 1]
    IsReverseBytes,
    /// 1 iff this step is `ZeroExtend16` (result[0..1] = val_d[0..1]; result[2..7] = 0).
    #[size = 1]
    IsZeroExt16,
    // ── BitManip sign-extend ──
    /// 1 iff this step is `SignExtend8`.
    #[size = 1]
    IsSignExt8,
    /// 1 iff this step is `SignExtend16`.
    #[size = 1]
    IsSignExt16,
    /// 1 iff this step's opcode is `Trap`.  Distinct from
    /// `IsExit` (which also covers Ecalli soft exits and JumpInd dynamic
    /// dispatch).  Used by the terminal-row constraint that forbids any
    /// successor real row after Trap.
    #[size = 1]
    IsTrap,
    /// 1 iff this step's opcode is `JumpInd`.  Drives the
    /// JumpTableChip lookup `(addr=val_b+imm, target=next_pc)` plus the
    /// matching 4-byte add-with-carry chain that pins JumpIndAddr to
    /// `(val_b + imm) mod 2^32`.
    #[size = 1]
    IsJumpInd,
    /// 1 iff this `JumpInd` targets the distinguished PVM halt address.
    /// Halt is a terminal dynamic jump handled before the program jump
    /// table, so it must not emit a JumpTable lookup.
    #[size = 1]
    IsHaltJumpInd,
    /// Virtual jump address (low 32 bits of `val_b + imm`),
    /// 4 little-endian bytes.  Pinned by the carry-chain constraint on
    /// JumpInd rows; emitted as the first half of the JumpTableChip
    /// lookup tuple.
    #[size = 4]
    JumpIndAddr,
    /// Per-byte add-with-carry chain for `JumpIndAddr =
    /// val_b + imm_bytes` (low 32 bits).  Bytes 0..3.  Carry-out at byte
    /// 3 is the 32-bit overflow, discarded (mirrors `% 2^32` at runtime).
    #[size = 4]
    JumpIndCarry,
    /// 1 iff this step's opcode is `LoadImmJumpInd`.  Drives the JumpTable
    /// lookup
    /// `(LoadImmJumpIndAddr, NextPc)` and the matching carry-chain
    /// `LoadImmJumpIndAddr = val_d + ImmYBytes` (low 32 bits).
    #[size = 1]
    IsLoadImmJumpInd,
    /// 1 iff this `LoadImmJumpInd` targets the distinguished PVM halt
    /// address. See [`Self::IsHaltJumpInd`].
    #[size = 1]
    IsHaltLoadImmJumpInd,
    /// The low 5 little-endian bytes of `step.imm_y`, the second
    /// immediate, sign-extended from at most 4 bytes, so byte 4 is each of
    /// its high bytes: LoadImmJumpInd's jump offset and an immediate
    /// store's value. Bound to canonical bytecode decoding via the prog_mem
    /// tuple.
    #[size = 5]
    ImmYBytes,
    /// Virtual jump address for LoadImmJumpInd
    /// (low 32 bits of `val_d + imm_y`), 4 little-endian bytes.  Pinned
    /// by the LoadImmJumpIndCarry chain; first half of the JumpTable
    /// lookup tuple for LoadImmJumpInd rows.
    #[size = 4]
    LoadImmJumpIndAddr,
    /// Per-byte carry chain for
    /// `LoadImmJumpIndAddr = val_d + ImmYBytes` (low 32 bits).
    #[size = 4]
    LoadImmJumpIndCarry,
    /// Signedness sub-flags for MulUpper.  Exactly one of the
    /// three is 1 when IsMulUpper=1.  Drive the per-variant result
    /// binding (UU = unsigned high directly, SU/SS subtract sign
    /// corrections from the unsigned high).
    #[size = 1]
    IsMulUpperUU,
    #[size = 1]
    IsMulUpperSU,
    #[size = 1]
    IsMulUpperSS,
    /// Sign bit (bit 7) of the sign-source byte (val_d\[0\] for SE8, val_d\[1\] for SE16).
    /// Pinned by a nibble-AND lookup against (SignExtSrcHiNib, 8, 8·SignExtBit).
    #[size = 1]
    SignExtBit,
    /// High nibble of the sign-source byte.  Together with a (lo_nib, 0xF, lo_nib)
    /// AND-lookup it pins the byte decomposition `src = 16·hi_nib + lo_nib`.
    #[size = 1]
    SignExtSrcHiNib,
    // ── Immediate witness column ─────────────────────────────
    /// Decoded immediate value (`step.imm`) as 8 little-endian bytes.
    /// Pinned to the canonical decoding of `code` at this PC by the
    /// ProgramMemory consumer lookup (see add_constraints near
    /// finalize_logup_in_pairs).
    #[size = 8]
    ImmBytes,
    /// 1 iff this step's opcode is one of DivS32 / DivS64 /
    /// RemS32 / RemS64.  Drives DivRemChip's signed-correction chain.
    #[size = 1]
    IsDivS,
    /// 1 iff this step's opcode is an arithmetic right shift (SharR32 /
    /// SharR64 and their immediate forms).  Committed as flag byte 0's
    /// bit 3; flows in the DivRem tuple, where it selects floor division.
    #[size = 1]
    IsSharR,
    /// Bit 7 of `div_quotient[7]` (sign of quotient on 64-bit
    /// signed div/rem).  Prover-witnessed.  Pinned via a nibble lookup;
    /// flowed to DivRemChip via the lookup tuple.
    #[size = 1]
    SignBitQ,
    /// Bit 7 of `div_remainder[7]` (sign of remainder on
    /// 64-bit signed div/rem).  Prover-witnessed.  Pinned + flowed
    /// like SignBitQ.
    #[size = 1]
    SignBitR,
    // ── Sign-bit pinning ────────────────────────────────────────
    // Each of SignBitB / SignBitD / SignBitQ / SignBitR is constrained to
    // equal bit 7 of its source byte via a pair of nibble-AND lookups
    // (mirrors the SignExtBit pattern):
    //   1) (HiNib, 8, 8·SignBit) — pins SignBit = bit 3 of HiNib.
    //   2) (Src − 16·HiNib, 0xF, same) — range-checks the low nibble,
    //      pinning the byte decomposition Src = 16·HiNib + LoNib.
    /// Multiplexed source byte for SignBitB: `val_b[7]` on 64-bit rows,
    /// `val_b[3]` on 32-bit rows.  Held as a column so the lookup tuple
    /// stays degree-1 (an inline `(1-Is32Bit)·val_b[7] + Is32Bit·val_b[3]`
    /// would be degree 2 and exceed the per-tuple bound).
    #[size = 1]
    SignSrcB,
    /// Multiplexed source byte for SignBitD: `val_d[7]` on 64-bit rows,
    /// `val_d[3]` on 32-bit rows.
    #[size = 1]
    SignSrcD,
    /// High nibble of SignSrcB.  Tied to SignBitB by the (HiNib, 8,
    /// 8·SignBitB) lookup; tied to SignSrcB by the low-nibble lookup.
    #[size = 1]
    SignBHiNib,
    /// High nibble of SignSrcD.  Same pattern as SignBHiNib.
    #[size = 1]
    SignDHiNib,
    /// High nibble of SignSrcQ (multiplexed so this works for 32-bit DivS
    /// too).  Pins SignBitQ = bit 7 of SignSrcQ.
    #[size = 1]
    SignQHiNib,
    /// High nibble of SignSrcR.  Pins SignBitR similarly.
    #[size = 1]
    SignRHiNib,
    /// Multiplexed source byte for SignBitQ —
    /// `div_quotient[7]` on 64-bit rows, `div_quotient[3]` on 32-bit
    /// rows.  Required because the 32-bit DivS correction needs the
    /// quotient's *32-bit* sign (bit 7 of byte 3); pinning to byte 7
    /// alone would force SignBitQ = 0 on 32-bit DivS rows since the
    /// trace zeroes the high 4 bytes there.
    #[size = 1]
    SignSrcQ,
    /// Multiplexed source byte for SignBitR.
    #[size = 1]
    SignSrcR,
    // ── 32-bit ALU result sign-extension ────────────────────────
    // The PVM interpreter sign-extends every 32-bit ALU result to 64-bit
    // (`q as i64 as u64` in vos_pvm/src/vm.rs).  SignBitResult = bit 7 of
    // `result[3]` is pinned via the same nibble-AND pattern as the other
    // sign bits, and the constraint `result[i] = 0xFF · SignBitResult`
    // for `i ∈ 4..8` holds on 32-bit ALU rows.
    /// Bit 7 of `result[3]`.  Pinned via the (HiNib, 8, 8·SignBitResult)
    /// lookup; equals 0 on rows where result\[3\] < 0x80, equals 1 on
    /// 32-bit ALU rows whose signed result is negative.  On non-real
    /// rows (padding) result\[3\] = 0 so SignBitResult = 0.
    #[size = 1]
    SignBitResult,
    /// High nibble of `result[3]`, paired with the (lo, 0xF, lo)
    /// range-check lookup so `result[3] = 16·HiNib + LoNib` is pinned.
    #[size = 1]
    ResultHiNib,
    // ── Signed-load inactive-byte sign-extension ────────────────
    // Constrains `result[i]` for `i ≥ MemSize` on load rows: the
    // interpreter writes 0 (unsigned loads) or 0xFF (signed loads,
    // sign-extended), and the AIR enforces that here.
    /// 1 iff this row is `LoadI8` or `LoadIndI8`.
    #[size = 1]
    IsLoadI8,
    /// 1 iff this row is `LoadI16` or `LoadIndI16`.
    #[size = 1]
    IsLoadI16,
    /// 1 iff this row is `LoadI32` or `LoadIndI32`.
    #[size = 1]
    IsLoadI32,
    /// Multiplexed source byte for the signed-load sign:
    /// `IsLoadI8·result[0] + IsLoadI16·result[1] + IsLoadI32·result[3]`.
    /// Zero on rows that aren't signed loads, so LoadSignBit collapses
    /// to 0 there too.
    #[size = 1]
    LoadSignSrc,
    /// Bit 7 of LoadSignSrc.  Pinned via the (HiNib, 8,
    /// 8·LoadSignBit) nibble-AND lookup.  Drives the inactive-byte
    /// sign-extension constraint
    /// `is_load · (1 − mem_byte_active[i]) · (result[i] − 0xFF·LoadSignBit) = 0`.
    #[size = 1]
    LoadSignBit,
    /// High nibble of LoadSignSrc.  Paired with the
    /// (lo, 0xF, lo) range check.
    #[size = 1]
    LoadSignHiNib,
    // ── Per-size memory-access flags ────────────────────────────
    // Pin `MemSize = 1·IsMemSize1 + 2·IsMemSize2 + 4·IsMemSize4 +
    // 8·IsMemSize8` so the prover can't pick a MemSize inconsistent with
    // the opcode.  Flags are pinned to the canonical opcode decoding by
    // ProgramMemoryChip.
    #[size = 1]
    IsMemSize1,
    #[size = 1]
    IsMemSize2,
    #[size = 1]
    IsMemSize4,
    #[size = 1]
    IsMemSize8,
    /// 1 iff this opcode is `StoreU8 / StoreU16 / StoreU32 /
    /// StoreU64` (the OneRegOneImm-category direct stores).  For these
    /// the trace fill puts `regs[ra]` into `val_b` (default arm in the
    /// source-operand match), so MemValue's active bytes can be pinned
    /// to val_b's bytes by a single byte-wise constraint.  Pinned to
    /// the canonical opcode decoding by ProgramMemoryChip.
    #[size = 1]
    IsStoreDirect,
    /// 1 iff this opcode is one of the *direct* loads
    /// (`LoadU8 / LoadI8 / LoadU16 / LoadI16 / LoadU32 / LoadI32 /
    /// LoadU64`, OneRegOneImm category).  For both direct loads and
    /// direct stores `addr = imm`, so MemAddr's 4 bytes are pinned to
    /// the low 4 bytes of ImmBytes (which is itself pinned to the
    /// canonical opcode immediate).
    #[size = 1]
    IsLoadDirect,
    /// 1 iff this opcode is one of the *indirect* memory
    /// ops (LoadInd[U/I][8/16/32/64] / StoreInd[U][8/16/32/64] /
    /// StoreImmInd[U][8/16/32/64]).  Drives the byte-wise add-with-
    /// carry chain pinning `MemAddr = (val_b + ImmBytes) mod 2^32`.
    #[size = 1]
    IsMemIndirect,
    /// Per-byte carry chain for the MemAddr indirect-
    /// addressing add `MemAddr = (val_b + ImmBytes) mod 2^32`.
    /// Carry-out at byte 3 is the 32-bit overflow, discarded.
    /// Boolean-constrained (val_b\[i\] + ImmBytes\[i\] + carry_in ≤ 511,
    /// carry_out ≤ 1).
    #[size = 4]
    MemAddrCarry,
    /// 1 iff this opcode is `StoreImm[U][8/16/32/64]` or
    /// `StoreImmInd[U][8/16/32/64]`.  Drives the per-byte
    /// MemValue ↔ ImmYBytes binding (the value is `imm_y` for both
    /// categories).
    #[size = 1]
    IsStoreImmAny,
    /// 1 iff this opcode is `StoreImm[U][8/16/32/64]`
    /// (TwoImm only).  Drives the direct-addr `MemAddr =
    /// ImmBytes[0..4]` binding (mirrors the direct-load pattern; the
    /// indirect StoreImmInd path is covered by the IsMemIndirect chain
    /// instead).
    #[size = 1]
    IsStoreImmDirect,
    /// 1 iff this opcode is `StoreInd[U][8/16/32/64]`
    /// (TwoRegOneImm — *register-source* indirect store).  For
    /// these the value written to memory is `regs[ra]`, which val_b
    /// doesn't carry on TwoRegOneImm rows (val_b holds regs\[rb\]
    /// = the base).  Drives the `MemValue = RegValA` per-byte
    /// binding plus the producer emission to the register-memory
    /// ledger.
    #[size = 1]
    IsStoreInd,
    /// Raw u64 of `regs_before[reg_a]` whenever
    /// IsStoreInd=1, zero otherwise.  Producer multiplicity
    /// uses IsStoreInd directly (no separate `ValAIsReg` column —
    /// the flag is the indicator).  Tuple shape mirrors the
    /// existing RegValB / RegValD producers: `(reg_a, reg_val_a,
    /// timestamp) ∈ reg_lookup` with multiplicity IsStoreInd.
    #[size = 8]
    RegValA,
    // ── Byte-wise val_d zero-check ──────────────────────────────
    // ValDIsZero is pinned in both directions (`val_d_is_zero=1 ⇒ val_d=0`
    // and `val_d=0 ⇒ val_d_is_zero=1`), and DivByZero likewise, via
    // byte-wise inversion witnesses + cumulative OR.
    /// Per-byte inverse witness.  When `val_d[i] ≠ 0`, ByteInv\[i\]
    /// must equal `1/val_d[i]` (in the field) so that
    /// `val_d[i] · ByteInv[i] = 1` (the byte indicator).  When
    /// `val_d[i] = 0`, ByteInv\[i\] is unconstrained (the indicator
    /// degenerates to 0).  Constrained by
    ///   `val_d[i] · (val_d[i] · ByteInv[i] − 1) = 0`
    /// which is satisfied iff val_d\[i\]=0 OR (ByteInv\[i\] is the inverse).
    #[size = 8]
    ValDByteInv,
    /// Cumulative OR of byte-indicators.  Recurrence (degree 3):
    ///   PartialNZ\[0\] = val_d\[0\] · ByteInv\[0\]
    ///   PartialNZ\[i\] = PartialNZ[i-1] + ByteIndicator\[i\]
    ///                  − PartialNZ[i-1] · ByteIndicator\[i\]
    /// where `ByteIndicator[i] = val_d[i] · ByteInv[i] ∈ {0, 1}`.
    /// `PartialNZ[7] = 1 ↔ val_d ≠ 0`.  ValDIsZero is then pinned
    /// to `1 − PartialNZ[7]`.
    #[size = 8]
    ValDPartialNZ,
    // ── DivS |r| < |d| chain ──────────────────────────────
    // The absolute-value and comparison chain for signed div/rem lives on
    // DivRemChip.  The sign bits SignBitD / SignBitR flow via the
    // DivRemLookup tuple; DivRemChip computes the absolute values and the
    // comparison chain internally without growing the lookup tuple.
    // ── DivS sign-of-r uniqueness ──────────────────────────────
    // Enforces the other half of PVM signed Euclidean uniqueness
    // (`sign(r) = sign(b)` when r ≠ 0; r = 0 is the only case
    // where the sign of r is unconstrained — bit 7 of all-zeros is 0
    // so SignBitR = 0 in that case).  Mirrors the byte-wise zero-check
    // pattern but on `div_remainder` instead of `val_d`.
    //
    // The constraint `is_div_s · ¬div_by_zero · ValRPartialNZ[7] ·
    // (SignBitR − SignBitB) = 0` forces SignBitR = SignBitB whenever
    // div_remainder ≠ 0.  Combined with the |r| < |d| chain, DivS
    // uniqueness is complete.
    /// Per-byte inverse witness for div_remainder.  Constrained by
    ///   `div_remainder[i] · (div_remainder[i] · ByteInv[i] − 1) = 0`
    /// — same shape as ValDByteInv.
    #[size = 8]
    ValRByteInv,
    /// Cumulative OR of div_remainder's byte-indicators.  Same
    /// recurrence as ValDPartialNZ.  PartialNZ\[7\] = 1
    /// ↔ div_remainder ≠ 0.
    #[size = 8]
    ValRPartialNZ,
    // ── RotL64 binding via mul-schoolbook + sum ─────────────────
    // RotL64(a, n) = (a << n) | (a >> (64 − n)) = mul_low + mul_high
    // (byte-wise, no carry; the bits of the two halves never overlap by
    // construction of rotation).  The 64-bit mul-schoolbook computes both
    // halves of `a · 2^n` (with val_d = 2^n via PowerOfTwo lookup), so the
    // low-64 is carried by the UnsignedProductLow column and the result
    // bindings are:
    //   non-rotate is_mul_low: result = UnsignedProductLow.
    //   RotL64:                 result = UnsignedProductLow + mul_high.
    /// 1 iff this opcode is `RotL64`.  Drives the rotation result binding
    /// (in MulChip) and the mul-schoolbook re-route.
    #[size = 1]
    IsRotateL64,
    // ── CountSetBits binding via popcount lookup ─────────────────
    /// 1 iff this opcode is `CountSetBits64` or `CountSetBits32`.
    /// Pinned to `classify_opcode(opcode).is_count_set_bits` via
    /// ProgramMemoryChip's preprocessed table.  Drives the per-byte
    /// popcount lookup `(val_d[i], BytePopcount[i]) ∈ popcount` and the
    /// result binding `result[0] = sum(BytePopcount[0..N])` (N = 4 if
    /// Is32Bit else 8) plus `result[1..8] = 0`.
    #[size = 1]
    IsCountSetBits,
    /// Per-byte popcount witnesses for the 8 bytes of `val_d`.
    /// `BytePopcount[i] = val_d[i].count_ones()` enforced via the
    /// PopcountChip lookup; `result[0]` is the sum of either the low 4
    /// (32-bit) or all 8 (64-bit).
    #[size = 8]
    BytePopcount,
    // ── LeadingZero / TrailingZero binding via bitcount lookup ──
    /// 1 iff this opcode is `LeadingZeroBits64 / 32`.
    /// Pinned to `classify_opcode(opcode).is_lzb` via ProgramMemoryChip's
    /// preprocessed table.
    #[size = 1]
    IsLzb,
    /// 1 iff this opcode is `TrailingZeroBits64 / 32`.
    #[size = 1]
    IsTzb,
    /// Per-byte leading-zeros witnesses for the 8 bytes of `val_d`.
    /// `BitOpLzByte[i] = val_d[i].leading_zeros()` (8 if val_d\[i\] = 0)
    /// enforced via the BitcountChip lookup.  Used for both LZ32 and LZ64
    /// rows; only the relevant prefix participates in the result formula.
    #[size = 8]
    BitOpLzByte,
    /// Per-byte trailing-zeros witnesses for the 8 bytes of `val_d`.
    /// `BitOpTzByte[i] = val_d[i].trailing_zeros()` (8 if val_d\[i\] = 0).
    #[size = 8]
    BitOpTzByte,
    /// Cumulative-OR of byte_indicator[i..7] (MSB-direction
    /// prefix non-zero indicator).  Mirrors `ValDPartialNZ`
    /// but walking from byte 7 down to byte 0.  `ValDPartialNZMsb[7] =
    /// byte_indicator[7]`, `ValDPartialNZMsb[i] = ValDPartialNZMsb[i+1]
    /// OR byte_indicator[i]`.  Used for LZ64's first-non-zero-from-MSB
    /// indicator.
    #[size = 8]
    ValDPartialNZMsb,
    /// Cumulative-OR of byte_indicator[i..3] (MSB-direction
    /// prefix non-zero indicator over the LOW 4 bytes only).  Used for
    /// LZ32, where the high 4 bytes of `val_d` are ignored.  Layout:
    /// `ValDPartialNZMsbLo[3] = byte_indicator[3]`, then
    /// `ValDPartialNZMsbLo[i] = ValDPartialNZMsbLo[i+1] OR byte_indicator[i]`
    /// for i = 2, 1, 0.
    #[size = 4]
    ValDPartialNZMsbLo,
    // ── RotR64 binding via mul-schoolbook + complementary shift ──
    /// 1 iff this opcode is `RotR64` / `RotR64Imm` /
    /// `RotR64ImmAlt`.  Pinned to `classify_opcode(opcode).is_rotate_r64`
    /// via ProgramMemoryChip's preprocessed table.  Drives:
    ///   - val_d = 2^ShiftAmountCompl (PowerOfTwo lookup, separate from
    ///     the classic shift's lookup);
    ///   - reg_val_d + ShiftAmountCompl = 64·ShiftQuotientCompl
    ///     (complementary shift-amount identity);
    ///   - result = UnsignedProductLow + mul_high (paired with RotL64).
    #[size = 1]
    IsRotateR64,
    /// Complementary shift amount = `(64 − n) mod 64` where
    /// `n = reg_val_d mod 64`.  Used as the PowerOfTwo lookup key on
    /// RotR64 rows, so val_d gets pinned to `2^((64 − n) mod 64)`.
    /// Range-bounded to [0, 63] by the lookup table size.
    #[size = 1]
    ShiftAmountCompl,
    /// The bits of `k` in `RegValD[0] + ShiftAmountCompl = 32·k` on
    /// rotate-right rows, `k` even on a 64-bit rotate: the complement is
    /// the negated low byte's residue, over the integers as for
    /// `ShiftQuotient`.
    #[size = 4]
    ShiftQuotientCompl,
    // ── 32-bit rotate flags ────────────────────────────────────
    /// 1 iff this opcode is `RotL32`.  Pinned by ProgramMemoryChip's
    /// preprocessed table.  Drives the 32-bit mul-schoolbook re-route +
    /// result binding (low 4 bytes = UnsignedProductLow + mul_high; high
    /// 4 bytes via the 32-bit ALU result sign-extension).
    #[size = 1]
    IsRotateL32,
    /// 1 iff this opcode is `RotR32` or `RotR32Imm`.
    /// Mirrors IsRotateR64 but with modulus 32 in the
    /// complementary shift identity and PowerOfTwo lookup.
    #[size = 1]
    IsRotateR32,
    /// 1 iff this opcode is an `ImmAlt` shift or rotate (`ShloL`,
    /// `ShloR`, `SharR` and `RotR`, 32- and 64-bit).  These are the
    /// swapped-source variants where the immediate is the shifted value
    /// and `regs[rb]` is the shift amount.  Drives the `val_b = ImmBytes`
    /// constraint pinning val_b to the canonical immediate
    /// (since val_b is not a register read for these rows
    /// — the standard val_b ↔ reg_val_b cross-constraint is
    /// inactive when val_b_is_reg=0).
    #[size = 1]
    IsImmAlt,
    /// The first 6 packed flag bytes of the canonical classify_opcode
    /// flag bag.  Each byte holds 8 individual flag bits
    /// (bit i = flag[8*k + i]).  The byte-to-bits
    /// lookup per row pins these bits to the matching CpuChip flag
    /// columns (or sum-of-sub-flags expressions for the 4 folded
    /// category slots: is_bitwise, is_compare, is_branch, is_store).
    /// ProgramMemoryChip's preprocessed
    /// FlagByte0..5 columns hold the canonical values; the prog_mem
    /// lookup balance pins each FlagByteI on CpuChip to canonical.
    /// Layout per byte is documented in `lookups/relations.rs` next
    /// to `PROG_MEMORY_N_FLAG_BYTES`.
    #[size = 1]
    FlagByte0,
    #[size = 1]
    FlagByte1,
    #[size = 1]
    FlagByte2,
    #[size = 1]
    FlagByte3,
    #[size = 1]
    FlagByte4,
    #[size = 1]
    FlagByte5,
    /// The four flag bytes CpuChip recomposes from its own columns, bound
    /// to ProgramMemory's canonical bytes by the instruction tuple: the
    /// register accesses and operand modifiers (6), the compare
    /// sub-operations (7), the branch conditions (8, 9) and the bitwise
    /// sub-operations (9).  Layout in `lookups/relations.rs`.
    #[size = 1]
    FlagByte6,
    #[size = 1]
    FlagByte7,
    #[size = 1]
    FlagByte8,
    #[size = 1]
    FlagByte9,

    // ── Degree-flatten helpers ──
    //
    // CpuChip's natural form has dozens of `is_real · is_op · is_width
    // · …` selector chains gated against linear bodies; with all
    // factors as deg-1 column refs, these reach degree 3-5.  Helpers
    // below materialise each multi-flag selector chain so every gated
    // constraint factors into (deg 1 helper) × (deg 1 body) = deg 2.
    //
    // Naming convention: `Is{Op}{Width}{Variant}H` for two-flag/three-
    // flag products of an op flag with width / variant flags.

    // ADD / SUB / MUL sign-extension selector helpers.
    /// `IsAdd · Is64Bit` (Is64Bit = 1 - Is32Bit).
    #[size = 1]
    IsAdd64bitH,
    /// `IsAdd · Is32Bit`.
    #[size = 1]
    IsAdd32bitH,
    /// `IsSub · (1 - IsNegAdd)` — non-negate path.
    #[size = 1]
    IsSubNotNegaddH,
    /// `IsSub · IsNegAdd` — negate path.
    #[size = 1]
    IsSubNegaddH,
    /// `IsSubNotNegaddH · Is64Bit`.
    #[size = 1]
    IsSub64NotNegaddH,
    /// `IsSubNegaddH · Is64Bit`.
    #[size = 1]
    IsSub64NegaddH,
    /// `IsSub · Is32Bit` — sign-extension on 32-bit Sub rows.
    #[size = 1]
    IsSub32bitH,
    /// `IsMul · Is32Bit` — sign-extension on 32-bit Mul rows.
    #[size = 1]
    IsMul32bitH,

    // Compare / DivRem-binding selector helpers.
    /// `IsCmpOrBranch · SignsDiff` body helper for cmp_lt_s expected-sign
    /// expression.  `SignsDiff = SignBitB + SignBitD - 2·SignBitB·SignBitD`
    /// is degree 2; this materialises the per-row value so the
    /// `is_cmp_or_branch · (cmp_lt_s - expected_s)` constraint becomes
    /// degree 2 instead of 3.
    #[size = 1]
    SignsDiffH,
    /// `IsCompare · ValDIsZero` — gates the val_d-is-zero pinning.
    #[size = 1]
    IsCmpVdzH,
    /// `IsCmovIz · ValDIsZero` — the if-zero CMOV path.
    #[size = 1]
    IsCmovIzVdzH,
    /// `IsCmovNz · (1 - ValDIsZero)` — the if-not-zero CMOV path.
    #[size = 1]
    IsCmovNzNotVdzH,
    /// The less-than a min or max selects by: `CmpLtSFlag` on MinS/MaxS
    /// rows, `CmpLtFlag` on every other.
    #[size = 1]
    MinMaxLtFlag,
    /// Min/Max result-binding body helpers: `MinMaxLtFlag · ValB[i]` and
    /// `MinMaxLtFlag · ValD[i]`.  Per-byte (size 8 each).
    #[size = 8]
    CmpLtValBH,
    #[size = 8]
    CmpLtValDH,

    /// `IsDivRem · (1 - DivByZero)` — div is active.
    #[size = 1]
    CpuDivActiveH,
    /// `(op-2)·(op-3)` — nonzero when op ∈ {0, 1} (div ops).
    #[size = 1]
    GateDivH,
    /// `op·(op-1)` — nonzero when op ∈ {2, 3} (rem ops).
    #[size = 1]
    GateRemH,
    /// `CpuDivActiveH · GateDivH` — full quotient-binding selector.
    #[size = 1]
    DivActiveQuotH,
    /// `CpuDivActiveH · GateRemH` — full remainder-binding selector.
    #[size = 1]
    DivActiveRemH,
    /// `IsDivRem · Is32Bit` — sign-extension on 32-bit DivRem rows.
    #[size = 1]
    IsDivRem32bitH,

    // ValDIsZero / PartialNZ recurrence + DivByZero result binding.
    /// `ValD[i] · ValDByteInv[i]` — per-byte ValD nonzero indicator
    /// (1 when ValD\[i\] != 0, else 0).  Lifts the deg-2 product into a
    /// deg-1 column for the recurrence.
    #[size = 8]
    ValDByteIndicatorH,
    /// `ValD[i] · (ValDByteIndicatorH[i] - 1)` per byte.  Lifts the
    /// deg-2 ValDByteInv pinning constraint to deg 2 when wrapped in
    /// `is_real`.
    #[size = 8]
    ValDByteIndMinus1H,
    /// `ValDPartialNZ[i-1] · ValDByteIndicatorH[i]` at limb `i - 1` for
    /// i = 1..8 — used in the OR-recurrence
    /// `PartialNZ[i] = PartialNZ[i-1] + Ind[i] - PartialNZ[i-1]·Ind[i]`.
    /// PartialNZ\[0\] is set directly to ValDByteIndicatorH\[0\], so no
    /// limb serves i = 0.
    #[size = 7]
    PartNZTimesIndH,
    /// `IsDivRem · ValDIsZero` — pins DivByZero on divrem rows.
    #[size = 1]
    IsDivRemTimesVdzH,
    /// `IsDivRem · DivByZero` — DivByZero-active selector.
    #[size = 1]
    DbzActiveH,
    /// `DbzActiveH · GateDivH` and `DbzActiveH · GateRemH` —
    /// DivByZero quotient/remainder result-binding selectors.
    #[size = 1]
    DbzActiveQuotH,
    #[size = 1]
    DbzActiveRemH,
    /// `DbzActiveRemH · (1 - Is32Bit)` — a 64-bit remainder by zero, whose
    /// result's high word is the dividend's (a 32-bit one's is the
    /// sign extension of its low word).
    #[size = 1]
    DbzActiveRem64H,

    // BitManip MSB recurrences.  (sign_ext_bit is enforced boolean
    // unconditionally, so no separate helper is needed.)
    /// `ValDPartialNZMsb[i+1] · ValDByteIndicatorH[i]` for the MSB-direction
    /// recurrence — i ∈ 0..7.
    #[size = 7]
    PartNZMsbTimesIndH,
    /// Same for the low-4-byte MSB recurrence — i ∈ 0..3.
    #[size = 3]
    PartNZMsbLoTimesIndH,

    // TZ / LZ result binding.
    /// Sum_{i=0..4} (PartialNZ\[i\] - PartialNZ[i-1]) · (8i + TzByte\[i\]).
    #[size = 1]
    TzLo4H,
    /// Sum_{i=4..8} (PartialNZ\[i\] - PartialNZ[i-1]) · (8i + TzByte\[i\]).
    #[size = 1]
    TzHi4H,
    /// Sum_{i=0..8} (PartialNZMsb\[i\] - PartialNZMsb[i+1]) · (8(7-i) + LzByte\[i\]).
    #[size = 1]
    Lz64H,
    /// Sum_{i=0..4} (PartialNZMsbLo\[i\] - PartialNZMsbLo[i+1]) · (8(3-i) + LzByte\[i\]).
    #[size = 1]
    Lz32H,
    /// `IsTzb · Is64Bit`, `IsTzb · Is32Bit`, mirror for IsLzb.
    #[size = 1]
    IsTzb64H,
    #[size = 1]
    IsTzb32H,
    #[size = 1]
    IsLzb64H,
    #[size = 1]
    IsLzb32H,

    // Branch conditions + sequential PC.
    /// `Σ (ValB[i] − ValD[i])²`, below 2^20 for byte operands, so zero
    /// exactly when they are equal.
    #[size = 1]
    EqDiffSquaresH,
    /// The inverse of `EqDiffSquaresH`, or 0 when it is 0.
    #[size = 1]
    EqDiffSquaresInv,
    /// `EqDiffSquaresH · EqDiffSquaresInv`: 1 exactly when the operands
    /// differ, which pins `EqFlag` to 0 then and to 1 when they are equal.
    #[size = 1]
    EqDiffSquaresTimesInvH,
    /// `IsCmpOrBranch · EqFlag` — gate for the val_b/val_d byte-equal pinning.
    #[size = 1]
    IsCmpOrBranchEqH,
    /// `IsBranch · BranchTaken` — feeds the is_sequential expression and
    /// keeps it deg 1.  IsBranch = sum of 10 br_* sub-flag column refs (deg 1).
    #[size = 1]
    IsBranchTakenH,

    // Control flow next_pc + memory monotonicity.
    // (BranchTaken and MemByteActive booleans are enforced unconditionally
    // as `X·(1-X)=0`, so no separate helpers are needed.)
    /// `MemByteActive[i+1] · (1 - MemByteActive[i])` per i ∈ 0..7.
    #[size = 7]
    MemByteActiveMonoH,

    // Register-memory binding selector helpers.  Many cross-constraints
    // chain 3-4 selector flags before a linear body.  (The IsTruncated /
    // ValBIsReg / ValDIsReg / ResultIsReg / FlagBool / IsBlakeEcall
    // booleans are enforced unconditionally as `X·(1-X)=0`, so no separate
    // helpers are needed.)
    /// `(1 - IsPadding) · Is32Bit` — used in the IsTruncated identity binding.
    #[size = 1]
    Real32bitH,
    /// `(1 - IsPadding) · ValBIsReg` — gate root for ValB cross-constraints.
    #[size = 1]
    ValBIsRegH,
    /// `ValBIsRegH · (1 - IsTruncated)` — non-truncated ValB upper-byte gate.
    #[size = 1]
    ValBIsRegNotTruncH,
    /// `ValBIsRegH · IsTruncated` — truncated ValB upper-byte gate.
    #[size = 1]
    ValBIsRegTruncH,
    /// `(1 - IsPadding) · (1 - ValDIsReg)` — the gate pinning RegValD to
    /// the immediate.
    #[size = 1]
    ValDIsImmH,
    /// `(1 - IsPadding) · (1 - IsShiftConstrained)` — non-shift ValD gate
    /// (the `non_shift_gate`); every real row's ValD has a source.
    #[size = 1]
    NonShiftGateH,
    /// `NonShiftGateH · (1 - IsTruncated)` — non-shift, non-truncated.
    #[size = 1]
    NonShiftGateNotTruncH,
    /// `NonShiftGateH · IsTruncated` — non-shift, truncated.
    #[size = 1]
    NonShiftGateTruncH,
    /// `(1 - IsPadding) · IsShiftConstrained` — shift-amount identity gate.
    #[size = 1]
    RealShiftCH,
    /// `(1 - IsPadding) · (IsRotateR64 + IsRotateR32)` — rotate-R identity gate.
    #[size = 1]
    IsRotateRGateH,
    /// `(1 - IsPadding) · (1 - FlagBool)` — gate for `Flag=0` constraint.
    #[size = 1]
    RealNotFlagBoolH,
    /// `(1 - IsPadding) · FlagBool` — gate for `Flag·FlagInv=1` constraint.
    #[size = 1]
    RealFlagBoolH,
    /// `(Σ Flag bytes) · FlagInv` — body helper for the Flag-nonzero proof.
    #[size = 1]
    FlagTimesInvH,

    // Deg-3 selector helpers for RotR ImmAlt val_b pinning and 32-bit
    // shift val_d-high-bytes-zero.
    /// `IsImmAlt · (1 - IsTruncated)` — non-truncated ImmAlt gate.
    #[size = 1]
    IsImmAltNotTruncH,
    /// `IsImmAlt · IsTruncated` — truncated ImmAlt gate.
    #[size = 1]
    IsImmAltTruncH,
    /// `Is32Bit · IsShiftConstrained` — 32-bit shift gate.
    #[size = 1]
    Is32ShiftCH,

    // Residual deg-3+ selector helpers.
    /// `IsReal · IsTrap` — terminal-row gate.
    #[size = 1]
    IsRealTrapH,
    // (The mem_addr_carry per-byte boolean is enforced unconditionally as
    // `X·(1-X)=0`, so no separate helper is needed.)
    /// `Is64Bit · (BytePopcount[4] + ... + BytePopcount[7])` — used in
    /// CountSetBits result-binding to keep the gated body at deg 1.
    #[size = 1]
    Is64bitPopcountHiH,
    /// `IsLoadLocal · (1 - MemByteActive[i])` — inactive-byte gate.
    #[size = 8]
    IsLoadLocalNotActiveH,
    /// `DivRemainder[i] · ValRByteInv[i]` — nonzero indicator.
    #[size = 8]
    ValRByteIndicatorH,
    /// `DivRemainder[i] · (ValRByteIndicatorH - 1)` — inv pinning.
    #[size = 8]
    ValRByteIndMinus1H,
    /// `ValRPartialNZ[i-1] · ValRByteIndicatorH[i]` at limb `i - 1` for
    /// i = 1..8 — OR-recurrence.
    #[size = 7]
    ValRPartNZTimesIndH,
    /// `IsDivS · (1 - DivByZero) · ValRPartialNZ[7]` — sign-of-r gate.
    #[size = 1]
    DivSActivePartialH,
    /// `IsDivS · (1 - DivByZero)` — root helper for DivSActivePartialH.
    #[size = 1]
    IsDivSNotDbzH,
    /// `IsShiftConstrained · (1 - IsRotateR64 - IsRotateR32)` —
    /// PowerOfTwo lookup multiplicity for the classic shift case.
    #[size = 1]
    IsShiftCNotRotrH,

    /// Boolean disposition of a host-call row. One only when an ECALLI was
    /// handled and acknowledged by the embedder; zero for unhandled calls.
    #[size = 1]
    HostCallAcknowledged,

    /// `IsLoad + IsStore`: scalar-memory instructions, all subject to the
    /// protected-zone rule.
    #[size = 1]
    IsStandardMemH,
    /// Carry into the most-significant address byte for the final active byte:
    /// `carry3[width - 1]`, selected by the authenticated width flags.
    #[size = 1]
    MemLastAddrCarryH,
    /// `canonical_high_word · (256 - addr[3] - last_carry)`, where the
    /// high word is derived from the authenticated byte-0 memory lookup.
    /// Nonzero exactly when the base is at least 0x10000 and the final active
    /// byte does not wrap through 2^32.
    #[size = 1]
    MemRangeProductH,
    /// M31 inverse of `MemRangeProductH` when nonzero, otherwise zero.
    #[size = 1]
    MemRangeInv,
    /// `MemRangeProductH · MemRangeInv`, lifted so the Standard-memory
    /// validity gate remains within CpuChip's degree-two bound.
    #[size = 1]
    MemRangeTimesInvH,

    /// ProgramMemory-authenticated exact precompile dispatch identifier
    /// (100 or 101), or zero for any other instruction. A
    /// continued host-call row must select exactly the matching precompile
    /// call relation.
    #[size = 1]
    HostCallPrecompileDispatch,

    // ── Witness-input binding ──
    /// 1 iff an acknowledged `Ecalli` of the witness input (dispatch 101).
    /// Its row reads φ7, the destination (`HPtr`), and φ8, the capacity
    /// (`MPtr`); writes the count to φ7 (`Result`, `ResultRegIdx` 7), a
    /// value below 2^24 at most φ8 (a CompareLookup tuple); and, when the
    /// count is not zero, hands `(ts, destination, count)` to
    /// `WitnessInputChip`, which writes exactly that range.
    #[size = 1]
    IsWitnessEcall,
    /// 1 iff the witness-input call wrote bytes: its count is not zero.
    #[size = 1]
    WitnessNonEmpty,
    /// M31 inverse of the witness-input count when it is not zero.
    #[size = 1]
    WitnessCountInv,
    /// `count · WitnessCountInv`, lifted so the non-zero test stays within
    /// CpuChip's degree-two bound.
    #[size = 1]
    WitnessCountTimesInvH,
}

#[derive(Debug, Copy, Clone, PreprocessedAirColumn)]
#[preprocessed_prefix = "cpu"]
pub enum PreprocessedColumn {}
