//! CpuChip AIR column layout — one row per PVM step.
//!
//! Holds the program-counter / opcode / operands, the operation-category and
//! sub-op flags (add/sub/mul/bitwise/shift/compare/branch/divrem/memory/...),
//! the auxiliary witnesses (carry chains, AND nibbles, sign bits, equality
//! witnesses), the register-memory binding witnesses (ValB/ValD/Result reg
//! sources + indices), and the Blake2b ECALL-binding columns (φ[10/11/12/7]
//! + Phi7Bool inversion witness).

use crate::air_column::{AirColumn, PreprocessedAirColumn};

#[derive(Debug, Copy, Clone, AirColumn)]
pub enum Column {
    #[size = 8]
    #[mask_next_row]
    Timestamp,
    #[size = 4]
    #[mask_next_row]
    Pc,
    #[size = 4]
    NextPc,
    #[size = 1]
    Opcode,
    #[size = 1]
    SkipLen,
    /// Carry chain for sequential PC addition: next_pc = pc + 1 + skip_len
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
    /// Auxiliary carry/borrow (8 limbs). Used by add/sub.
    #[size = 8]
    Carry,
    #[size = 1]
    IsPadding,
    #[size = 1]
    RegAWritten,
    #[size = 8]
    Gas,
    // ── Operation category flags ──
    #[size = 1]
    IsAdd,
    #[size = 1]
    IsSub,
    #[size = 1]
    IsMul,
    #[size = 1]
    IsBitwise,
    #[size = 1]
    IsShift,
    #[size = 1]
    IsCompare,
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
    // ── Mul auxiliary: high 64 bits of full product ──
    /// mul_high[0..8]: (val_b * val_d) = result + mul_high * 2^64
    #[size = 8]
    MulHigh,
    /// Mul partial-product carry chain (16 limbs for schoolbook carries)
    #[size = 16]
    MulCarry,
    /// 1 if this is MulUpper (result = high bits, mul_high = low bits)
    #[size = 1]
    IsMulUpper,
    // ── Bitwise auxiliary: per-byte AND result ──
    /// and_result[i] = val_b[i] AND val_d[i] (8 bytes)
    #[size = 8]
    AndResult,
    /// High nibble of val_b[i] (val_b[i] >> 4), for nibble-level AND lookup
    #[size = 8]
    ValBHiNib,
    /// High nibble of val_d[i] (val_d[i] >> 4), for nibble-level AND lookup
    #[size = 8]
    ValDHiNib,
    /// High nibble of and_result[i] (and_result[i] >> 4), for nibble-level AND lookup
    #[size = 8]
    AndResultHiNib,
    // ── Compare auxiliary ──
    /// Subtraction carry for comparison (8 limbs, reuses sub logic)
    #[size = 8]
    CmpCarry,
    /// Compare sub-op flags (exactly one is 1 when IsCompare=1)
    #[size = 1]
    IsSetLtU,
    #[size = 1]
    IsSetLtS,
    #[size = 1]
    IsCmovIz,
    #[size = 1]
    IsCmovNz,
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
    /// Subtraction result bytes: (val_b[i] + 255 - val_d[i] + carry_in) mod 256
    /// Range-checked to prove carry chain correctness.
    #[size = 8]
    CmpSubResult,
    /// 1 iff val_b == val_d (all bytes equal). Used for Le/Gt branches.
    /// Constrained via: eq_flag=1 ⇒ all byte_eq[i]=1 AND eq_flag=0 ⇒ NOT all equal
    #[size = 1]
    EqFlag,
    /// Per-byte equality flag: 1 if val_b[i] == val_d[i]
    #[size = 8]
    ByteEq,
    /// Per-byte diff inverse: val_b[i] != val_d[i] → (val_b[i]-val_d[i])*ByteDiffInv[i] = 1
    ///                         val_b[i] == val_d[i] → ByteDiffInv[i] can be 0 (unused)
    #[size = 8]
    ByteDiffInv,
    // ── Shift auxiliary ──
    #[size = 1]
    ShiftAmount,
    #[size = 1]
    ShiftOp,
    /// 1 when is_shift AND shift_op ∈ {0,1} (left shift or logical right shift)
    #[size = 1]
    IsShiftConstrained,
    /// Phase 9g: raw u64 of `regs_before[reg_a_or_b]` whenever ValBIsReg=1.
    /// For 64-bit ops ValB == RegValB (constrained byte-wise); for 32-bit
    /// ALU ops ValB is truncated to `RegValB & 0xFFFFFFFF` so the upper
    /// bytes of ValB are zero while RegValB carries the full register value.
    /// Ledger producer uses RegValB; ALU constraints keep using ValB.
    #[size = 8]
    RegValB,
    /// Phase 9g: 1 iff Is32Bit · (IsAdd + IsSub + IsMul + IsDivRem), so the
    /// ValB/ValD upper-4-bytes-equal-zero constraints gate correctly.  Tied
    /// to that product via a validity constraint below.
    #[size = 1]
    IsTruncated,
    /// Phase 9f: raw u64 of `regs_before[reg_b]` whenever ValDIsReg=1.
    /// For non-shift non-32-bit ops ValD == RegValD (constrained below); for
    /// shifts ValD gets rewritten to `2^shift_amount` but RegValD keeps the
    /// raw register value so the ledger producer can authenticate it.  Zero
    /// when ValDIsReg=0.
    #[size = 8]
    RegValD,
    /// Phase 9f: quotient in `RegValD = ShiftAmount + modulus · q` for
    /// shift ops.  modulus = 32 for 32-bit shifts, 64 otherwise.  Ties
    /// the prover-chosen ShiftAmount to the authenticated RegValD.
    #[size = 8]
    ShiftQuotient,
    // ── Control flow ──
    /// Conditional branch (BranchEq/Ne/Lt/Ge + imm variants)
    #[size = 1]
    IsBranch,
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
    /// Carry chain for quotient * divisor + remainder = dividend (16 limbs)
    #[size = 16]
    DivMulCarry,
    /// 1 if divisor is zero (special-case handling)
    #[size = 1]
    DivByZero,
    // ── Memory access ──
    /// 1 if this is a load instruction
    #[size = 1]
    IsExit,
    #[size = 1]
    IsLoad,
    /// 1 if this is a store instruction
    #[size = 1]
    IsStore,
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
    // ── Program execution sequencing ──
    /// timestamp + 1 (8 limbs), used for the program execution lookup
    #[size = 8]
    NextTimestamp,
    // ── Blake2b ECALL binding (Phase 8c) ──
    /// 1 iff this step is the blake2b hostcall (Ecalli opcode with imm =
    /// ECALL_BLAKE2B_COMPRESS).  Prover-witnessed; logup balance with
    /// Blake2bChip forces this to be set correctly for every blake2b call.
    #[size = 1]
    IsBlakeEcall,
    /// φ[10] at this step's regs_before (h_ptr).  Full u64 witnessed so the
    /// upper 32 bits don't have to match anything; only low 4 bytes flow into
    /// the Blake2bCall lookup tuple.
    #[size = 8]
    Phi10,
    /// φ[11] at this step's regs_before (m_ptr).
    #[size = 8]
    Phi11,
    /// φ[12] at this step's regs_before (t_low for blake2b_compress).
    #[size = 8]
    Phi12,
    /// Full u64 value of φ[7] (8 LE bytes).  Used for the register-memory
    /// producer at ECALL steps — the register ledger needs the raw value;
    /// the Blake2bCall relation uses Phi7Bool for the finalise flag.
    #[size = 8]
    Phi7,
    /// Inversion witness: if Phi7 (as field element) != 0, Phi7Inv =
    /// 1 / Phi7_combined; else 0.  Used to constrain
    /// Phi7Bool = (Phi7 != 0) in-circuit (Phase 9e).
    #[size = 8]
    Phi7Inv,
    /// Boolean version of φ[7] (finalise flag): 1 if regs_before[7] != 0.
    /// The prover fills this and the lookup balance keeps it tied to the
    /// Blake2bChip.F column at the matching compression.
    #[size = 1]
    Phi7Bool,
    // ── Register-memory binding (Phase 9d) ──
    /// 1 iff ValB was sourced from a register read at this step.  See
    /// `val_b_read_reg` for the per-category mapping.  Gates the ValB
    /// register-memory producer emission.
    #[size = 1]
    ValBIsReg,
    /// Register index that ValB was read from when ValBIsReg=1.
    #[size = 1]
    ValBRegIdx,
    /// 1 iff ValD was sourced from a register read.
    #[size = 1]
    ValDIsReg,
    /// Register index that ValD was read from when ValDIsReg=1.
    #[size = 1]
    ValDRegIdx,
    /// 1 iff Result was written to a register at this step (tracer's
    /// step.reg_write is Some).  Gates the Result register-memory producer.
    #[size = 1]
    ResultIsReg,
    /// Register index that Result was written to when ResultIsReg=1.
    #[size = 1]
    ResultRegIdx,
    // ── BitManip permutation/zero-extend (Phase 12b-1) ──
    /// 1 iff this step is `ReverseBytes` (result[i] = val_d[7-i]).
    #[size = 1]
    IsReverseBytes,
    /// 1 iff this step is `ZeroExtend16` (result[0..1] = val_d[0..1]; result[2..7] = 0).
    #[size = 1]
    IsZeroExt16,
    // ── BitManip sign-extend (Phase 12b-2) ──
    /// 1 iff this step is `SignExtend8`.
    #[size = 1]
    IsSignExt8,
    /// 1 iff this step is `SignExtend16`.
    #[size = 1]
    IsSignExt16,
    /// Sign bit (bit 7) of the sign-source byte (val_d[0] for SE8, val_d[1] for SE16).
    /// Pinned by a nibble-AND lookup against (SignExtSrcHiNib, 8, 8·SignExtBit).
    #[size = 1]
    SignExtBit,
    /// High nibble of the sign-source byte.  Together with a (lo_nib, 0xF, lo_nib)
    /// AND-lookup it pins the byte decomposition `src = 16·hi_nib + lo_nib`.
    #[size = 1]
    SignExtSrcHiNib,
}

#[derive(Debug, Copy, Clone, PreprocessedAirColumn)]
#[preprocessed_prefix = "cpu"]
pub enum PreprocessedColumn {}
