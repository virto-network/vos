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
    /// `mask_next_row` so the Phase 13e-redux terminal-row constraint can
    /// read the *next* row's IsPadding to assert that any real Trap step
    /// has no successor real row.  (Original Phase 13e tried to gate this
    /// on IsExit, which also covers Ecalli and JumpInd — too broad.  The
    /// per-opcode IsTrap flag is the narrower gate that actually fits.)
    #[size = 1]
    #[mask_next_row]
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
    /// Mul partial-product carry chain (16 limbs, low bytes).  Each
    /// schoolbook position can produce a carry up to ~16 bits at the
    /// busiest middle positions (e.g. 0xFFFFFFFF * 0xFFFFFFFF), so the
    /// carry is split across MulCarry (low byte) and MulCarryHi (high
    /// byte) for a 16-bit value per position.  Constraint reconstructs
    /// the full carry as `mul_carry[k] + 256 * mul_carry_hi[k]`.
    #[size = 16]
    MulCarry,
    /// High byte of the schoolbook carry per position; pairs with MulCarry
    /// to represent a 16-bit value.  See MulCarry doc.
    #[size = 16]
    MulCarryHi,
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
    /// Phase 13e-redux: 1 iff this step's opcode is `Trap`.  Distinct from
    /// `IsExit` (which also covers Ecalli soft exits and JumpInd dynamic
    /// dispatch).  Used by the terminal-row constraint that forbids any
    /// successor real row after Trap.
    #[size = 1]
    IsTrap,
    /// Phase 13d: 1 iff this step's opcode is `JumpInd`.  Drives the
    /// JumpTableChip lookup `(addr=val_b+imm, target=next_pc)` plus the
    /// matching 4-byte add-with-carry chain that pins JumpIndAddr to
    /// `(val_b + imm) mod 2^32`.
    #[size = 1]
    IsJumpInd,
    /// Phase 13d: virtual jump address (low 32 bits of `val_b + imm`),
    /// 4 little-endian bytes.  Pinned by the carry-chain constraint on
    /// JumpInd rows; emitted as the first half of the JumpTableChip
    /// lookup tuple.
    #[size = 4]
    JumpIndAddr,
    /// Phase 13d: per-byte add-with-carry chain for `JumpIndAddr =
    /// val_b + imm_bytes` (low 32 bits).  Bytes 0..3.  Carry-out at byte
    /// 3 is the 32-bit overflow, discarded (mirrors `% 2^32` at runtime).
    #[size = 4]
    JumpIndCarry,
    /// Phase 13d-loadimmjumpind: 1 iff this step's opcode is
    /// `LoadImmJumpInd`.  Drives the JumpTable lookup
    /// `(LoadImmJumpIndAddr, NextPc)` and the matching carry-chain
    /// `LoadImmJumpIndAddr = val_d + ImmYBytes` (low 32 bits).
    #[size = 1]
    IsLoadImmJumpInd,
    /// Phase 13d-loadimmjumpind: 4 little-endian bytes of `step.imm_y`
    /// (the second immediate, used for LoadImmJumpInd's jump offset).
    /// Bound to canonical bytecode decoding via the prog_mem tuple.
    #[size = 4]
    ImmYBytes,
    /// Phase 13d-loadimmjumpind: virtual jump address for LoadImmJumpInd
    /// (low 32 bits of `val_d + imm_y`), 4 little-endian bytes.  Pinned
    /// by the LoadImmJumpIndCarry chain; first half of the JumpTable
    /// lookup tuple for LoadImmJumpInd rows.
    #[size = 4]
    LoadImmJumpIndAddr,
    /// Phase 13d-loadimmjumpind: per-byte carry chain for
    /// `LoadImmJumpIndAddr = val_d + ImmYBytes` (low 32 bits).
    #[size = 4]
    LoadImmJumpIndCarry,
    /// Phase 12c: signedness sub-flags for MulUpper.  Exactly one of the
    /// three is 1 when IsMulUpper=1.  Drive the per-variant result
    /// binding (UU = unsigned high directly, SU/SS subtract sign
    /// corrections from the unsigned high).
    #[size = 1]
    IsMulUpperUU,
    #[size = 1]
    IsMulUpperSU,
    #[size = 1]
    IsMulUpperSS,
    /// Phase 12c: unsigned product high 64 bits (positions 8..15 of the
    /// schoolbook).  Holds the schoolbook output for `is_mul_upper`
    /// rows, decoupling the schoolbook constraint from the per-variant
    /// result binding.
    #[size = 8]
    UnsignedProductHi,
    /// Phase 12c: sign-correction term `sa·val_d` (low 64 bits).
    /// Filled to `sa·val_d` for SU/SS rows; 0 for UU.
    #[size = 8]
    MulCorrTermA,
    /// Phase 12c: sign-correction term `sb·val_b` (low 64 bits).
    /// Filled to `sb·val_b` for SS rows; 0 for UU/SU.
    #[size = 8]
    MulCorrTermB,
    /// Phase 12c: per-byte carry chain for the result-binding subtraction
    /// `result + MulCorrTermA + MulCorrTermB ≡ UnsignedProductHi (mod 2^64)`
    /// on `is_mul_upper` rows.  Carry-out at byte 7 is the 64-bit
    /// overflow, discarded.
    #[size = 8]
    MulCorrCarry,
    /// Sign bit (bit 7) of the sign-source byte (val_d[0] for SE8, val_d[1] for SE16).
    /// Pinned by a nibble-AND lookup against (SignExtSrcHiNib, 8, 8·SignExtBit).
    #[size = 1]
    SignExtBit,
    /// High nibble of the sign-source byte.  Together with a (lo_nib, 0xF, lo_nib)
    /// AND-lookup it pins the byte decomposition `src = 16·hi_nib + lo_nib`.
    #[size = 1]
    SignExtSrcHiNib,
    // ── Phase 13b: immediate witness column ─────────────────────────────
    /// Decoded immediate value (`step.imm`) as 8 little-endian bytes.
    /// Pinned to the canonical decoding of `code` at this PC by the
    /// ProgramMemory consumer lookup (see add_constraints near
    /// finalize_logup_in_pairs).
    #[size = 8]
    ImmBytes,
    /// Phase 16: 1 iff this step's opcode is one of DivS32 / DivS64 /
    /// RemS32 / RemS64.  Drives the divrem schoolbook's high-byte
    /// sign-correction (without it, signed divrem with any negative
    /// operand fails proving — see DivCorrHi / DivCorrCarry).
    #[size = 1]
    IsDivS,
    /// Phase 16: bit 7 of `div_quotient[7]` (sign of quotient on 64-bit
    /// signed div/rem).  Prover-witnessed (mirrors SignBitB / SignBitD
    /// — same trust model as Phase 12c MulUpper).  Used in the
    /// DivCorrHi carry chain.
    #[size = 1]
    SignBitQ,
    /// Phase 16: bit 7 of `div_remainder[7]` (sign of remainder on
    /// 64-bit signed div/rem).  Prover-witnessed.  Used in the
    /// DivCorrHi carry chain.
    #[size = 1]
    SignBitR,
    /// Phase 16: high 8 bytes of the divrem schoolbook's unsigned
    /// product `q_u·d_u + r_u`.  Replaces the old hard-coded "0" for
    /// k≥8 in the schoolbook constraint.  For DivU rows: forced to 0,
    /// so the schoolbook still demands `q·d + r = b` exactly.  For DivS
    /// rows: bound by a carry chain to `sq·d_u + sd·q_u + sr − sa
    /// (mod 2^64)`, the unsigned high produced by signed inputs in
    /// two's complement.
    #[size = 8]
    DivCorrHi,
    /// Phase 16: per-byte carry chain for the DivCorrHi sign-correction
    /// equation.  Carry-out at byte 7 is the 64-bit overflow,
    /// discarded (mirrors `% 2^64` at the boundary).
    #[size = 8]
    DivCorrCarry,
    /// Phase 16: high byte of the divrem schoolbook carry per position;
    /// pairs with DivMulCarry to represent a 16-bit value (mirrors
    /// MulCarry / MulCarryHi from the mul schoolbook).  At busy middle
    /// positions of `q · d` the per-byte sum can reach
    /// 8·255² + 255 ≈ 520 000 → carry ≈ 2 030, which doesn't fit in a
    /// single u8.  Pre-existing latent bug in the u8-only chain, hit
    /// for the first time by DivS rows where both q and d have many
    /// 0xFF bytes (e.g. -14 × -7 in two's complement).
    #[size = 16]
    DivMulCarryHi,
    // ── Phase 17: sign-bit pinning ────────────────────────────────────────
    // Closes the SignBitB / SignBitD / SignBitQ / SignBitR soundness gap
    // shared with Phase 12c.  Each sign bit is now constrained to equal
    // bit 7 of its source byte via a pair of nibble-AND lookups
    // (mirrors the SignExtBit pattern from Phase 12b-2):
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
    /// High nibble of SignSrcQ (Phase 18 added the multiplex so this
    /// works for 32-bit DivS too).  Pins SignBitQ = bit 7 of SignSrcQ.
    #[size = 1]
    SignQHiNib,
    /// High nibble of SignSrcR.  Pins SignBitR similarly.
    #[size = 1]
    SignRHiNib,
    /// Phase 18: multiplexed source byte for SignBitQ —
    /// `div_quotient[7]` on 64-bit rows, `div_quotient[3]` on 32-bit
    /// rows.  Required because the 32-bit DivS correction needs the
    /// quotient's *32-bit* sign (bit 7 of byte 3); pinning to byte 7
    /// alone (Phase 17) would force SignBitQ = 0 on 32-bit DivS rows
    /// since the trace zeroes the high 4 bytes there.
    #[size = 1]
    SignSrcQ,
    /// Phase 18: multiplexed source byte for SignBitR.
    #[size = 1]
    SignSrcR,
    // ── Phase 19: 32-bit ALU result sign-extension ────────────────────────
    // The PVM interpreter sign-extends every 32-bit ALU result to 64-bit
    // (`q as i64 as u64` in javm/src/vm.rs).  Until Phase 19 the AIR
    // forced `result[4..8] = 0` for every 32-bit ALU op, which only
    // worked when bit 31 of the result happened to be 0.  Phase 19
    // pins SignBitResult = bit 7 of `result[3]` via the same nibble-
    // AND pattern as the other sign bits, then replaces the
    // truncation constraint with `result[i] = 0xFF · SignBitResult`
    // for `i ∈ 4..8` on 32-bit ALU rows.
    /// Bit 7 of `result[3]`.  Pinned via the (HiNib, 8, 8·SignBitResult)
    /// lookup; equals 0 on rows where result[3] < 0x80, equals 1 on
    /// 32-bit ALU rows whose signed result is negative.  On non-real
    /// rows (padding) result[3] = 0 so SignBitResult = 0.
    #[size = 1]
    SignBitResult,
    /// High nibble of `result[3]`, paired with the (lo, 0xF, lo)
    /// range-check lookup so `result[3] = 16·HiNib + LoNib` is pinned.
    #[size = 1]
    ResultHiNib,
    // ── Phase 20: signed-load inactive-byte sign-extension ────────────────
    // Closes the soundness gap on `result[i]` for `i ≥ MemSize` on load
    // rows.  Until Phase 20 those bytes were unconstrained — the
    // interpreter writes 0 (unsigned loads) or 0xFF (signed loads,
    // sign-extended), but the AIR didn't enforce either.
    /// Phase 20: 1 iff this row is `LoadI8` or `LoadIndI8`.
    #[size = 1]
    IsLoadI8,
    /// Phase 20: 1 iff this row is `LoadI16` or `LoadIndI16`.
    #[size = 1]
    IsLoadI16,
    /// Phase 20: 1 iff this row is `LoadI32` or `LoadIndI32`.
    #[size = 1]
    IsLoadI32,
    /// Phase 20: multiplexed source byte for the signed-load sign:
    /// `IsLoadI8·result[0] + IsLoadI16·result[1] + IsLoadI32·result[3]`.
    /// Zero on rows that aren't signed loads, so LoadSignBit collapses
    /// to 0 there too.
    #[size = 1]
    LoadSignSrc,
    /// Phase 20: bit 7 of LoadSignSrc.  Pinned via the (HiNib, 8,
    /// 8·LoadSignBit) nibble-AND lookup.  Drives the inactive-byte
    /// sign-extension constraint
    /// `is_load · (1 − mem_byte_active[i]) · (result[i] − 0xFF·LoadSignBit) = 0`.
    #[size = 1]
    LoadSignBit,
    /// Phase 20: high nibble of LoadSignSrc.  Paired with the
    /// (lo, 0xF, lo) range check.
    #[size = 1]
    LoadSignHiNib,
    // ── Phase 21: DivU quotient uniqueness (r < d) ─────────────────────────
    // Closes the off-by-multiple gap on DivU.  The schoolbook
    // `q·d + r = b` alone has multiple solutions (e.g. (q, r) and
    // (q−1, r+d) both satisfy when r+d < 2^64); the standard fix is
    // to additionally require `r < d`, which uniquely determines the
    // pair under Euclidean division.
    //
    // Encoded byte-wise as the carry chain for `val_d − 1 − div_remainder`
    // (equivalently `val_d + ~div_remainder` with carry_in[0] = 0):
    //   DivCmpDiff[i] + DivCmpCarry[i]·256
    //     = val_d[i] + (255 − div_remainder[i]) + carry_in
    // The top carry `DivCmpCarry[7]` is 1 iff `val_d > div_remainder`,
    // i.e.  `r < d`.  Forced to 1 on `is_div_rem · ¬div_by_zero ·
    // ¬is_div_s` rows.  DivS uniqueness has its own sign-aware
    // formulation; left for a follow-up.
    /// Phase 21: byte-level diff for the val_d > div_remainder check.
    /// Range-checked via BitwiseAnd `(diff, 0xFF, diff)` per row to
    /// pin each byte to [0, 255] (without range check the prover can
    /// pick field-level values that satisfy the chain in M31 but not
    /// as integers).
    #[size = 8]
    DivCmpDiff,
    /// Phase 21: per-byte carry chain for the val_d > div_remainder
    /// check.  Range max = 1 (val_d[i] + 255 − div_remainder[i] +
    /// carry_in ≤ 511 with carry_in ≤ 1).  Boolean-constrained.
    #[size = 8]
    DivCmpCarry,
    // ── Phase 23: per-size memory-access flags ────────────────────────────
    // Pin `MemSize = 1·IsMemSize1 + 2·IsMemSize2 + 4·IsMemSize4 +
    // 8·IsMemSize8` so the prover can't pick a MemSize inconsistent with
    // the opcode (Phase 22's prefix-1 + sum bound MemByteActive's shape
    // to MemSize, but left MemSize itself prover-witnessed).  Flags are
    // pinned to the canonical opcode decoding by ProgramMemoryChip.
    #[size = 1] IsMemSize1,
    #[size = 1] IsMemSize2,
    #[size = 1] IsMemSize4,
    #[size = 1] IsMemSize8,
    /// Phase 24: 1 iff this opcode is `StoreU8 / StoreU16 / StoreU32 /
    /// StoreU64` (the OneRegOneImm-category direct stores).  For these
    /// the trace fill puts `regs[ra]` into `val_b` (default arm in the
    /// source-operand match), so MemValue's active bytes can be pinned
    /// to val_b's bytes by a single byte-wise constraint.  Pinned to
    /// the canonical opcode decoding by ProgramMemoryChip.
    #[size = 1]
    IsStoreDirect,
    /// Phase 25: 1 iff this opcode is one of the *direct* loads
    /// (`LoadU8 / LoadI8 / LoadU16 / LoadI16 / LoadU32 / LoadI32 /
    /// LoadU64`, OneRegOneImm category).  For both direct loads and
    /// direct stores `addr = imm`, so MemAddr's 4 bytes are pinned to
    /// the low 4 bytes of ImmBytes (which is itself pinned to the
    /// canonical opcode immediate by Phase 13b).
    #[size = 1]
    IsLoadDirect,
    /// Phase 26: 1 iff this opcode is one of the *indirect* memory
    /// ops (LoadInd[U/I][8/16/32/64] / StoreInd[U][8/16/32/64] /
    /// StoreImmInd[U][8/16/32/64]).  Drives the byte-wise add-with-
    /// carry chain pinning `MemAddr = (val_b + ImmBytes) mod 2^32`.
    #[size = 1]
    IsMemIndirect,
    /// Phase 26: per-byte carry chain for the MemAddr indirect-
    /// addressing add `MemAddr = (val_b + ImmBytes) mod 2^32`.
    /// Carry-out at byte 3 is the 32-bit overflow, discarded.
    /// Boolean-constrained (val_b[i] + ImmBytes[i] + carry_in ≤ 511,
    /// carry_out ≤ 1).
    #[size = 4]
    MemAddrCarry,
    /// Phase 27: 1 iff this opcode is `StoreImm[U][8/16/32/64]` or
    /// `StoreImmInd[U][8/16/32/64]`.  Drives the per-byte
    /// MemValue ↔ ImmYBytes binding (the value is `imm_y` for both
    /// categories).
    #[size = 1]
    IsStoreImmAny,
    /// Phase 27: 1 iff this opcode is `StoreImm[U][8/16/32/64]`
    /// (TwoImm only).  Drives the direct-addr `MemAddr =
    /// ImmBytes[0..4]` binding (mirrors Phase 25's pattern; the
    /// indirect StoreImmInd path is covered by Phase 26 instead).
    #[size = 1]
    IsStoreImmDirect,
    /// Phase 28: 1 iff this opcode is `StoreInd[U][8/16/32/64]`
    /// (TwoRegOneImm — *register-source* indirect store).  For
    /// these the value written to memory is `regs[ra]`, which val_b
    /// doesn't carry on TwoRegOneImm rows (val_b holds regs[rb]
    /// = the base).  Drives the `MemValue = RegValA` per-byte
    /// binding plus the producer emission to the register-memory
    /// ledger.
    #[size = 1]
    IsStoreInd,
    /// Phase 28: raw u64 of `regs_before[reg_a]` whenever
    /// IsStoreInd=1, zero otherwise.  Producer multiplicity
    /// uses IsStoreInd directly (no separate `ValAIsReg` column —
    /// the flag is the indicator).  Tuple shape mirrors the
    /// existing RegValB / RegValD producers: `(reg_a, reg_val_a,
    /// timestamp) ∈ reg_lookup` with multiplicity IsStoreInd.
    #[size = 8]
    RegValA,
    // ── Phase 29: byte-wise val_d zero-check ──────────────────────────────
    // Pre-Phase-29 ValDIsZero was one-direction-pinned only
    // (`val_d_is_zero=1 ⇒ val_d=0`, gated on is_compare); the converse
    // (`val_d=0 ⇒ val_d_is_zero=1`) was unenforced.  Same gap on
    // div_by_zero — `div_by_zero=1 ⇒ schoolbook bypassed` but result
    // unbound.  Phase 29 closes both via byte-wise inversion witnesses
    // + cumulative OR.
    /// Per-byte inverse witness.  When `val_d[i] ≠ 0`, ByteInv[i]
    /// must equal `1/val_d[i]` (in the field) so that
    /// `val_d[i] · ByteInv[i] = 1` (the byte indicator).  When
    /// `val_d[i] = 0`, ByteInv[i] is unconstrained (the indicator
    /// degenerates to 0).  Constrained by
    ///   `val_d[i] · (val_d[i] · ByteInv[i] − 1) = 0`
    /// which is satisfied iff val_d[i]=0 OR (ByteInv[i] is the inverse).
    #[size = 8]
    ValDByteInv,
    /// Cumulative OR of byte-indicators.  Recurrence (degree 3):
    ///   PartialNZ[0] = val_d[0] · ByteInv[0]
    ///   PartialNZ[i] = PartialNZ[i-1] + ByteIndicator[i]
    ///                  − PartialNZ[i-1] · ByteIndicator[i]
    /// where `ByteIndicator[i] = val_d[i] · ByteInv[i] ∈ {0, 1}`.
    /// `PartialNZ[7] = 1 ↔ val_d ≠ 0`.  ValDIsZero is then pinned
    /// to `1 − PartialNZ[7]`.
    #[size = 8]
    ValDPartialNZ,
    // ── Phase 30: DivS |r| < |d| uniqueness ───────────────────────────────
    // Closes the off-by-(d) attack on DivS that Phase 21 closed for DivU
    // (see PLAN.md).  Uniqueness for signed Euclidean division
    // (round-toward-zero, PVM convention) requires both `|r| < |d|` AND
    // `sign(r) = sign(b)` (or r = 0).  Phase 30 implements the magnitude
    // half; the sign-of-r constraint is deferred.
    //
    // Mechanism: two's-complement conditional negation chains compute
    // |val_d| and |div_remainder| into AbsD / AbsR; then the existing
    // Phase-21-style `(AbsD - 1 - AbsR) ≥ 0` carry chain into
    // AbsCmpDiff / AbsCmpCarry pins `|val_d| > |div_remainder|`.
    //
    // For each value (val_d / div_remainder):
    //   if SignBit = 0: Abs[i] = value[i], AbsCarry[i] = 0
    //   if SignBit = 1: Abs[i] + AbsCarry[i]·256
    //                     = (255 − value[i]) + carry_in
    //                  with carry_in[0] = 1 (the +1 of two's complement)
    /// |val_d| absolute-value bytes.
    #[size = 8]
    AbsD,
    /// Per-byte carry chain for the `~val_d + 1` two's-complement
    /// negation (active when SignBitD = 1; forced to 0 when
    /// SignBitD = 0).  Boolean per byte.
    #[size = 8]
    AbsDCarry,
    /// |div_remainder| absolute-value bytes.
    #[size = 8]
    AbsR,
    /// Per-byte carry chain for the `~div_remainder + 1` negation.
    /// Boolean per byte.
    #[size = 8]
    AbsRCarry,
    /// Byte-level diff for the `AbsD > AbsR` check (mirrors
    /// DivCmpDiff from Phase 21 but on absolute values).  Range-
    /// checked via Range256 to pin each byte to [0, 255].
    #[size = 8]
    AbsCmpDiff,
    /// Per-byte carry chain for the `AbsD > AbsR` check.  Top carry
    /// forced to 1 on `is_div_s · ¬div_by_zero` rows.  Boolean per
    /// byte.
    #[size = 8]
    AbsCmpCarry,
    // ── Phase 31: DivS sign-of-r uniqueness ──────────────────────────────
    // Closes the OTHER half of PVM signed Euclidean uniqueness
    // (`sign(r) = sign(b)` when r ≠ 0; r = 0 is the only case
    // where the sign of r is unconstrained — bit 7 of all-zeros is 0
    // so SignBitR = 0 in that case).  Mirrors Phase 29's byte-wise
    // zero-check pattern but on `div_remainder` instead of `val_d`.
    //
    // The constraint `is_div_s · ¬div_by_zero · ValRPartialNZ[7] ·
    // (SignBitR − SignBitB) = 0` forces SignBitR = SignBitB whenever
    // div_remainder ≠ 0.  Combined with Phase 30's |r| < |d|, DivS
    // uniqueness is now complete.
    /// Per-byte inverse witness for div_remainder.  Constrained by
    ///   `div_remainder[i] · (div_remainder[i] · ByteInv[i] − 1) = 0`
    /// — same shape as Phase 29's ValDByteInv.
    #[size = 8]
    ValRByteInv,
    /// Cumulative OR of div_remainder's byte-indicators.  Same
    /// recurrence as Phase 29's ValDPartialNZ.  PartialNZ[7] = 1
    /// ↔ div_remainder ≠ 0.
    #[size = 8]
    ValRPartialNZ,
    // ── Phase 32: RotL64 binding via mul-schoolbook + sum ─────────────────
    // RotL64(a, n) = (a << n) | (a >> (64 − n)) = mul_low + mul_high
    // (byte-wise, no carry; the bits of the two halves never overlap by
    // construction of rotation).  The existing 64-bit mul-schoolbook
    // already computes both halves of `a · 2^n` (with val_d = 2^n via
    // PowerOfTwo lookup) — Phase 32 re-routes the low-64 from `result`
    // to the new UnsignedProductLow column, then adds two result
    // bindings:
    //   non-rotate is_mul_low: result = UnsignedProductLow.
    //   RotL64:                 result = UnsignedProductLow + mul_high.
    /// Phase 32: 1 iff this opcode is `RotL64`.  Drives the rotation
    /// result binding (result = UnsignedProductLow + mul_high) and
    /// the mul-schoolbook re-route.
    #[size = 1]
    IsRotateL64,
    /// Phase 32: low-64 bytes of the unsigned schoolbook product
    /// `a · val_d` for `is_mul · is_64bit · ¬is_mul_upper` rows.
    /// Decouples the schoolbook computation from the per-op result
    /// binding (mirrors Phase 12c's UnsignedProductHi pattern).
    #[size = 8]
    UnsignedProductLow,
}

#[derive(Debug, Copy, Clone, PreprocessedAirColumn)]
#[preprocessed_prefix = "cpu"]
pub enum PreprocessedColumn {}
