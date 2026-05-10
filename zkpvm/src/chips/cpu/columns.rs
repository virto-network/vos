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
    // Phase 53c: IsBitwise folded into (IsAnd + IsOr + IsXor +
    // IsAndInv + IsOrInv + IsXnor).  Verifier-side gates use the
    // sum expression; prover-side prog_mem closure overrides the
    // slot.  Strictly stronger soundness than before — the lookup
    // balance now pins the sum to the canonical IsBitwise (was:
    // only IsBitwise itself was pinned, sum could diverge).
    #[size = 1]
    IsShift,
    // Phase 53d: IsCompare folded into the 8-sub-flag sum
    // (IsSetLtU + IsSetLtS + IsCmovIz + IsCmovNz + IsMinS + IsMinU
    // + IsMaxS + IsMaxU).  Same closure-override pattern as
    // Phase 53b/c.  Strictly stronger soundness — sub-flag sum
    // now pinned to canonical via the prog_mem lookup balance.
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
    // Phase 54b/c/d: MulHigh[8] + MulCarry[16] + MulCarryHi[16] +
    // UnsignedProductHi[8] + UnsignedProductLow[8] all moved to MulChip.
    // The schoolbook + sign-correction + result-variant binding all
    // live on MulChip's narrower trace.  CpuChip's `result` on mul
    // rows binds to MulChip's `result` via the 35-limb lookup tuple.
    // Phase 53: IsMulUpper folded into (IsMulUpperUU + IsMulUpperSU
    // + IsMulUpperSS).  Verifier-side reads use the sum expression
    // directly; prover-side prog_mem tuple emission overrides the
    // sum slot in its closure (see cpu/interaction.rs).
    // Phase 54e: AndResult[8] + ValBHiNib[8] + ValDHiNib[8] +
    // AndResultHiNib[8] all moved to BitwiseChip.  CpuChip's `result`
    // on bitwise rows binds to BitwiseChip's `result` via the
    // BitwiseLookup tuple (30 limbs); BitwiseChip's AIR proves the
    // per-op result identity (AND/OR/XOR/AndInv/OrInv/Xnor) and
    // emits the 16 nibble-AND lookups against BitwiseLookupChip.
    // ── Compare auxiliary ──
    // Phase 54f: CmpCarry[8] moved to CompareChip.
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
    // Phase 54f: CmpSubResult[8] moved to CompareChip.  CompareChip's
    // AIR pins it via the val_b + ~val_d + 1 carry chain and emits
    // the per-byte Range256 lookup.
    /// 1 iff val_b == val_d (all bytes equal). Used for Le/Gt branches.
    /// Constrained one-directionally: `eq_flag=1 ⇒ val_b[i] = val_d[i]` for
    /// every byte i, gated on `is_cmp_or_branch`.  The converse is benign in
    /// PVM semantics — the prover would have to produce the wrong next_pc to
    /// undermark eq_flag, which is bound by ProgramMemoryChip.
    #[size = 1]
    EqFlag,
    // Phase 54h: ByteEq[8] + ByteDiffInv[8] dropped.  BranchEq / BranchNe
    // constraints now read `val_b[i] - val_d[i]` directly:
    //   is_br_eq · branch_taken · (val_b[i] - val_d[i]) = 0
    //   is_br_ne · (1 - branch_taken) · (val_b[i] - val_d[i]) = 0
    // Same degree, same soundness as the prior `(1 - byte_eq[i])` form
    // since byte_eq was bound to the diff-is-zero indicator.
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
    // Phase 53e: IsBranch folded into the 10-sub-flag sum
    // (IsBrEq + IsBrNe + IsBrLtU + IsBrGeU + IsBrLeU + IsBrGtU
    //  + IsBrLtS + IsBrGeS + IsBrLeS + IsBrGtS).  Same closure-
    // override pattern as Phase 53b/c/d.  Strictly stronger
    // soundness — the lookup balance forces sum == canonical.
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
    // Phase 54g: DivMulCarry[16] moved to DivRemChip alongside the
    // schoolbook q·d + r = b carry chain.
    /// 1 if divisor is zero (special-case handling)
    #[size = 1]
    DivByZero,
    // ── Memory access ──
    /// 1 if this is a load instruction
    #[size = 1]
    IsExit,
    #[size = 1]
    IsLoad,
    // Phase 53f: IsStore folded into (IsStoreDirect + IsStoreImmAny +
    // IsStoreInd).  Verifier-side gates use the sum expression; prover-
    // side prog_mem closure overrides the tuple slot.  The byte-level
    // memory access lookup uses the same sum as its is_write column.
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
    // ── Blake2b ECALL slot columns ──
    //
    // Naming note: these columns retain their pre-off-by-three-fix
    // labels ("Phi10", "Phi11", "Phi12", "Phi7") for diff minimisation;
    // their actual SOURCES were rewired in the fix (commit 7d20d4c) so
    // each slot now holds the value of a *different* PVM register than
    // its name implies.  See `chips/cpu/trace_fill.rs` Phase 8c block
    // and `chips/cpu/{mod,interaction}.rs::ECALL_REG_IDXS` for the
    // canonical slot ↔ register mapping.
    //
    /// h_ptr slot (sourced from φ[7]; low 4 bytes flow into the
    /// Blake2bCall tuple as h_ptr).  Full u64 witnessed so the upper
    /// 32 bits can hold whatever regs_before[7] held.
    #[size = 8]
    Phi10,
    /// m_ptr slot (sourced from φ[8]).  Low 4 bytes flow into the
    /// Blake2bCall tuple as m_ptr.
    #[size = 8]
    Phi11,
    /// t_low slot (sourced from φ[9]).  Full 8 bytes flow into the
    /// Blake2bCall tuple as T.
    #[size = 8]
    Phi12,
    /// f_flag slot (sourced from φ[10] = a3).  Full u64 of regs_before[10].
    /// Phi7Bool below is the boolean form `(regs_before[10] != 0)`,
    /// which is what flows into the Blake2bCall tuple as F.
    #[size = 8]
    Phi7,
    /// Inversion witness for the f_flag slot: if Phi7 (as field
    /// element) != 0, Phi7Inv = 1 / Phi7_combined; else 0.  Used to
    /// constrain Phi7Bool = (Phi7 != 0) in-circuit (Phase 9e).
    #[size = 8]
    Phi7Inv,
    /// Boolean form of the f_flag slot: 1 if regs_before[10] != 0.
    /// The prover fills this and the lookup balance keeps it tied to
    /// the Blake2bChip.F column at the matching compression.
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
    // Phase 54c: UnsignedProductHi[8], MulCorrTermA[8], MulCorrTermB[8],
    // MulCorrCarry[8] all moved to MulChip.  The Phase 12c MulUpper
    // SS/SU sign-correction constraint that pinned them now lives there.
    // CpuChip's mul-row Result is bound to MulChip's via the lookup
    // tuple.
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
    /// RemS32 / RemS64.  Drives DivRemChip's signed-correction chain.
    #[size = 1]
    IsDivS,
    /// Phase 16: bit 7 of `div_quotient[7]` (sign of quotient on 64-bit
    /// signed div/rem).  Prover-witnessed.  Pinned via a Phase 17/18
    /// nibble lookup; flowed to DivRemChip via the lookup tuple.
    #[size = 1]
    SignBitQ,
    /// Phase 16: bit 7 of `div_remainder[7]` (sign of remainder on
    /// 64-bit signed div/rem).  Prover-witnessed.  Pinned + flowed
    /// like SignBitQ.
    #[size = 1]
    SignBitR,
    // Phase 16 → 54k: DivCorrHi[8] + DivCorrCarry[8] moved to DivRemChip.
    //   - DivCorrHi was the high 8 bytes of the schoolbook output, used
    //     to bind q·d + r ≡ val_b mod 2^128 with sign correction on
    //     DivS rows.  Now an internal DivRemChip column.
    //   - DivCorrCarry was the per-byte carry of the Phase 16 sign-
    //     correction chain.  Internal to DivRemChip.
    // Phase 54g: DivMulCarryHi[16] moved to DivRemChip.
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
    // ── Phase 21 → 54i: DivU r<d uniqueness moved to DivRemChip ─────────────
    // DivCmpDiff[8] + DivCmpCarry[8] dropped from CpuChip.  DivRemChip
    // now witnesses the `val_d - 1 - div_remainder` carry chain
    // internally and emits the per-byte Range256 lookups.  is_div_s
    // flows through the DivRemLookup tuple to gate the chain off on
    // signed-div rows (which use Phase 30 / 54j |r|<|d| separately).
    // ── Phase 23: per-size memory-access flags ────────────────────────────
    // Pin `MemSize = 1·IsMemSize1 + 2·IsMemSize2 + 4·IsMemSize4 +
    // 8·IsMemSize8` so the prover can't pick a MemSize inconsistent with
    // the opcode (Phase 22's prefix-1 + sum bound MemByteActive's shape
    // to MemSize, but left MemSize itself prover-witnessed).  Flags are
    // pinned to the canonical opcode decoding by ProgramMemoryChip.
    #[size = 1]
    IsMemSize1,
    #[size = 1]
    IsMemSize2,
    #[size = 1]
    IsMemSize4,
    #[size = 1]
    IsMemSize8,
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
    // ── Phase 30 → 54j-redux: DivS |r| < |d| chain moved to DivRemChip ────
    // The full Phase 30 chain (AbsD/AbsDCarry/AbsR/AbsRCarry +
    // AbsCmpDiff/AbsCmpCarry = 48 cells) now lives on DivRemChip.
    // Sign bits already flow via the 54k tuple (SignBitD / SignBitR);
    // DivRemChip computes the absolute values and the comparison chain
    // internally without growing the lookup tuple.
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
    /// result binding (now in MulChip after Phase 54d) and the
    /// mul-schoolbook re-route.
    #[size = 1]
    IsRotateL64,
    // Phase 54d: UnsignedProductLow[8] moved to MulChip.
    // ── Phase 33: CountSetBits binding via popcount lookup ─────────────────
    /// Phase 33: 1 iff this opcode is `CountSetBits64` or `CountSetBits32`.
    /// Pinned to `classify_opcode(opcode).is_count_set_bits` via
    /// ProgramMemoryChip's preprocessed table.  Drives the per-byte
    /// popcount lookup `(val_d[i], BytePopcount[i]) ∈ popcount` and the
    /// result binding `result[0] = sum(BytePopcount[0..N])` (N = 4 if
    /// Is32Bit else 8) plus `result[1..8] = 0`.
    #[size = 1]
    IsCountSetBits,
    /// Phase 33: per-byte popcount witnesses for the 8 bytes of `val_d`.
    /// `BytePopcount[i] = val_d[i].count_ones()` enforced via the
    /// PopcountChip lookup; `result[0]` is the sum of either the low 4
    /// (32-bit) or all 8 (64-bit).
    #[size = 8]
    BytePopcount,
    // ── Phase 34: LeadingZero / TrailingZero binding via bitcount lookup ──
    /// Phase 34: 1 iff this opcode is `LeadingZeroBits64 / 32`.
    /// Pinned to `classify_opcode(opcode).is_lzb` via ProgramMemoryChip's
    /// preprocessed table.
    #[size = 1]
    IsLzb,
    /// Phase 34: 1 iff this opcode is `TrailingZeroBits64 / 32`.
    #[size = 1]
    IsTzb,
    /// Phase 34: per-byte leading-zeros witnesses for the 8 bytes of `val_d`.
    /// `BitOpLzByte[i] = val_d[i].leading_zeros()` (8 if val_d[i] = 0)
    /// enforced via the BitcountChip lookup.  Used for both LZ32 and LZ64
    /// rows; only the relevant prefix participates in the result formula.
    #[size = 8]
    BitOpLzByte,
    /// Phase 34: per-byte trailing-zeros witnesses for the 8 bytes of `val_d`.
    /// `BitOpTzByte[i] = val_d[i].trailing_zeros()` (8 if val_d[i] = 0).
    #[size = 8]
    BitOpTzByte,
    /// Phase 34: cumulative-OR of byte_indicator[i..7] (MSB-direction
    /// prefix non-zero indicator).  Mirrors Phase 29's `ValDPartialNZ`
    /// but walking from byte 7 down to byte 0.  `ValDPartialNZMsb[7] =
    /// byte_indicator[7]`, `ValDPartialNZMsb[i] = ValDPartialNZMsb[i+1]
    /// OR byte_indicator[i]`.  Used for LZ64's first-non-zero-from-MSB
    /// indicator.
    #[size = 8]
    ValDPartialNZMsb,
    /// Phase 34: cumulative-OR of byte_indicator[i..3] (MSB-direction
    /// prefix non-zero indicator over the LOW 4 bytes only).  Used for
    /// LZ32, where the high 4 bytes of `val_d` are ignored.  Layout:
    /// `ValDPartialNZMsbLo[3] = byte_indicator[3]`, then
    /// `ValDPartialNZMsbLo[i] = ValDPartialNZMsbLo[i+1] OR byte_indicator[i]`
    /// for i = 2, 1, 0.
    #[size = 4]
    ValDPartialNZMsbLo,
    // ── Phase 35: RotR64 binding via mul-schoolbook + complementary shift ──
    /// Phase 35: 1 iff this opcode is `RotR64` / `RotR64Imm` /
    /// `RotR64ImmAlt`.  Pinned to `classify_opcode(opcode).is_rotate_r64`
    /// via ProgramMemoryChip's preprocessed table.  Drives:
    ///   - val_d = 2^ShiftAmountCompl (PowerOfTwo lookup, separate from
    ///     the classic shift's lookup);
    ///   - reg_val_d + ShiftAmountCompl = 64·ShiftQuotientCompl
    ///     (complementary shift-amount identity);
    ///   - result = UnsignedProductLow + mul_high (paired with RotL64).
    #[size = 1]
    IsRotateR64,
    /// Phase 35: complementary shift amount = `(64 − n) mod 64` where
    /// `n = reg_val_d mod 64`.  Used as the PowerOfTwo lookup key on
    /// RotR64 rows, so val_d gets pinned to `2^((64 − n) mod 64)`.
    /// Range-bounded to [0, 63] by the lookup table size.
    #[size = 1]
    ShiftAmountCompl,
    /// Phase 35: integer quotient in
    /// `reg_val_d + ShiftAmountCompl = 64·ShiftQuotientCompl`.  Range-
    /// bounded by the 8-byte decomposition + Range256 byte checks.
    /// Phase 36: same column reused for the modulus-32 variant
    /// (RotR32) — the constraint then reads `reg_val_d +
    /// ShiftAmountCompl = 32·ShiftQuotientCompl`.
    #[size = 8]
    ShiftQuotientCompl,
    // ── Phase 36: 32-bit rotate flags ────────────────────────────────────
    /// Phase 36: 1 iff this opcode is `RotL32`.  Pinned by
    /// ProgramMemoryChip's preprocessed table.  Drives the 32-bit
    /// mul-schoolbook re-route + result binding (low 4 bytes =
    /// UnsignedProductLow + mul_high; high 4 bytes via Phase 19
    /// sign-extension).
    #[size = 1]
    IsRotateL32,
    /// Phase 36: 1 iff this opcode is `RotR32` or `RotR32Imm`.
    /// Mirrors IsRotateR64 but with modulus 32 in the
    /// complementary shift identity and PowerOfTwo lookup.
    #[size = 1]
    IsRotateR32,
    /// Phase 40: 1 iff this opcode is `RotR64ImmAlt` or
    /// `RotR32ImmAlt`.  These are the swapped-source variants
    /// where the immediate is the rotated value and `regs[rb]`
    /// is the shift amount.  Drives the `val_b = ImmBytes`
    /// constraint pinning val_b to the canonical immediate
    /// (since val_b is no longer a register read for these rows
    /// — the standard val_b ↔ reg_val_b cross-constraint is
    /// inactive when val_b_is_reg=0).
    #[size = 1]
    IsRotateRImmAlt,
    /// Phase 55b: 6 packed flag bytes mirroring the canonical
    /// classify_opcode flag bag.  Each byte holds 8 of the 48
    /// individual flag bits (bit i = flag[8*k + i]).  The byte-to-bits
    /// lookup per row pins these bits to the matching CpuChip flag
    /// columns (or sum-of-sub-flags expressions for the 5 folded
    /// category slots: is_mul_upper, is_bitwise, is_compare,
    /// is_branch, is_store).  ProgramMemoryChip's preprocessed
    /// FlagByte0..5 columns hold the canonical values; the prog_mem
    /// lookup balance pins each FlagByteI on CpuChip to canonical.
    /// Together these collapse the 48-flag prog_mem region to 6 bytes.
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

    // ── Phase I-cpu Stwo-v2.x degree-flatten helpers ──
    //
    // CpuChip's natural form has dozens of `is_real · is_op · is_width
    // · …` selector chains gated against linear bodies; with all
    // factors as deg-1 column refs, these reach degree 3-5.  Helpers
    // below materialise each multi-flag selector chain so every gated
    // constraint factors into (deg 1 helper) × (deg 1 body) = deg 2.
    //
    // Naming convention: `Is{Op}{Width}{Variant}H` for two-flag/three-
    // flag products of an op flag with width / variant flags.

    // Wave 1: ADD / SUB / MUL sign-extension blocks.
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

    // Wave 2: Compare / DivRem-binding blocks.
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
    /// MinU/MaxU result-binding body helpers: `CmpLtFlag · ValB[i]` and
    /// `CmpLtFlag · ValD[i]`.  Per-byte (size 8 each).
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

    // Wave 3: ValDIsZero / PartialNZ recurrence + DivByZero result binding.
    /// `ValD[i] · ValDByteInv[i]` — per-byte ValD nonzero indicator
    /// (1 when ValD[i] != 0, else 0).  Lifts the deg-2 product into a
    /// deg-1 column for the recurrence.
    #[size = 8]
    ValDByteIndicatorH,
    /// `ValD[i] · (ValDByteIndicatorH[i] - 1)` per byte.  Lifts the
    /// deg-2 ValDByteInv pinning constraint to deg 2 when wrapped in
    /// `is_real`.
    #[size = 8]
    ValDByteIndMinus1H,
    /// `ValDPartialNZ[i-1] · ValDByteIndicatorH[i]` for i = 1..8 — used
    /// in the OR-recurrence `PartialNZ[i] = PartialNZ[i-1] + Ind[i] -
    /// PartialNZ[i-1]·Ind[i]`.  Index 0 is unused (PartialNZ[0] is set
    /// directly to ValDByteIndicatorH[0]).
    #[size = 8]
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

    // Wave 4a: BitManip MSB recurrences.  (B3 audit dropped
    // SignExtBitBoolH — sign_ext_bit is now boolean unconditionally.)
    /// `ValDPartialNZMsb[i+1] · ValDByteIndicatorH[i]` for the MSB-direction
    /// recurrence — i ∈ 0..7 (index 7 unused; default fill = 0).
    #[size = 8]
    PartNZMsbTimesIndH,
    /// Same for the low-4-byte MSB recurrence — i ∈ 0..3 (index 3 unused).
    #[size = 4]
    PartNZMsbLoTimesIndH,

    // Wave 4b: TZ / LZ result binding.
    /// Sum_{i=0..4} (PartialNZ[i] - PartialNZ[i-1]) · (8i + TzByte[i]).
    #[size = 1]
    TzLo4H,
    /// Sum_{i=4..8} (PartialNZ[i] - PartialNZ[i-1]) · (8i + TzByte[i]).
    #[size = 1]
    TzHi4H,
    /// Sum_{i=0..8} (PartialNZMsb[i] - PartialNZMsb[i+1]) · (8(7-i) + LzByte[i]).
    #[size = 1]
    Lz64H,
    /// Sum_{i=0..4} (PartialNZMsbLo[i] - PartialNZMsbLo[i+1]) · (8(3-i) + LzByte[i]).
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

    // Wave 5: Branch conditions + sequential PC.
    /// `IsBrEq · BranchTaken` — `val_b == val_d` constraint gate.
    #[size = 1]
    IsBrEqTakenH,
    /// `IsBrNe · (1 - BranchTaken)` — `val_b == val_d` (when not taken) gate.
    #[size = 1]
    IsBrNeNotTakenH,
    /// `IsCmpOrBranch · EqFlag` — gate for the val_b/val_d byte-equal pinning.
    #[size = 1]
    IsCmpOrBranchEqH,
    /// `IsBranch · BranchTaken` — feeds the is_sequential expression and
    /// keeps it deg 1.  IsBranch = sum of 10 br_* sub-flag column refs (deg 1).
    #[size = 1]
    IsBranchTakenH,

    // Wave 6: Control flow next_pc + memory monotonicity.
    // (B3 audit dropped BranchTakenBoolH / MemByteActiveBoolH —
    // booleans are now enforced unconditionally as `X·(1-X)=0`.)
    /// `MemByteActive[i+1] · (1 - MemByteActive[i])` per i ∈ 0..7
    /// (index 7 unused, default fill = 0).
    #[size = 8]
    MemByteActiveMonoH,

    // Wave 7: Phase 9 register-memory binding.  Many cross-constraints
    // chain 3-4 selector flags before a linear body.  (B3 audit
    // dropped 6 *BoolH helpers — IsTruncated/ValBIsReg/ValDIsReg/
    // ResultIsReg/Phi7Bool/IsBlakeEcall — all now enforced as
    // unconditional `X·(1-X)=0` constraints.)
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
    /// `(1 - IsPadding) · ValDIsReg` — gate root for ValD cross-constraints.
    #[size = 1]
    ValDIsRegH,
    /// `ValDIsRegH · (1 - IsShiftConstrained)` — non-shift ValD gate
    /// (matches the original `non_shift_gate`).
    #[size = 1]
    NonShiftGateH,
    /// `NonShiftGateH · (1 - IsTruncated)` — non-shift, non-truncated.
    #[size = 1]
    NonShiftGateNotTruncH,
    /// `NonShiftGateH · IsTruncated` — non-shift, truncated.
    #[size = 1]
    NonShiftGateTruncH,
    /// `ValDIsRegH · IsShiftConstrained` — shift-amount identity gate.
    #[size = 1]
    ValDIsRegShiftCH,
    /// `(1 - IsPadding) · (IsRotateR64 + IsRotateR32)` — rotate-R identity gate.
    #[size = 1]
    IsRotateRGateH,
    /// `(1 - IsPadding) · (1 - Phi7Bool)` — gate for `Phi7=0` constraint.
    #[size = 1]
    RealNotPhi7BoolH,
    /// `(1 - IsPadding) · Phi7Bool` — gate for `Phi7·Phi7Inv=1` constraint.
    #[size = 1]
    RealPhi7BoolH,
    /// `Phi7Field · Phi7InvField` — body helper for the Phi7-nonzero proof.
    #[size = 1]
    Phi7TimesInvH,

    // Wave 7-fix: missed deg-3 patterns from Phase 40 (RotR ImmAlt val_b
    // pinning) and Phase 36/37 (32-bit shift val_d-high-bytes-zero).
    /// `IsRotateRImmAlt · (1 - IsTruncated)` — non-truncated ImmAlt gate.
    #[size = 1]
    IsRotRImmAltNotTruncH,
    /// `IsRotateRImmAlt · IsTruncated` — truncated ImmAlt gate.
    #[size = 1]
    IsRotRImmAltTruncH,
    /// `Is32Bit · IsShiftConstrained` — 32-bit shift gate.
    #[size = 1]
    Is32ShiftCH,

    // Wave 8: residual deg-3+ patterns missed by the earlier wave grep.
    /// `IsReal · IsTrap` — Phase 13e terminal-row gate.
    #[size = 1]
    IsRealTrapH,
    // (B3 audit dropped MemAddrCarryBoolH — mem_addr_carry per-byte boolean
    // is now enforced unconditionally as `X·(1-X)=0`.)
    /// `Is64Bit · (BytePopcount[4] + ... + BytePopcount[7])` — used in
    /// CountSetBits result-binding to keep the gated body at deg 1.
    #[size = 1]
    Is64bitPopcountHiH,
    /// `IsLoadLocal · (1 - MemByteActive[i])` — Phase 20 inactive-byte gate.
    #[size = 8]
    IsLoadLocalNotActiveH,
    /// `DivRemainder[i] · ValRByteInv[i]` — Phase 31 nonzero indicator.
    #[size = 8]
    ValRByteIndicatorH,
    /// `DivRemainder[i] · (ValRByteIndicatorH - 1)` — Phase 31 inv pinning.
    #[size = 8]
    ValRByteIndMinus1H,
    /// `ValRPartialNZ[i-1] · ValRByteIndicatorH[i]` — Phase 31 OR-recurrence.
    #[size = 8]
    ValRPartNZTimesIndH,
    /// `IsDivS · (1 - DivByZero) · ValRPartialNZ[7]` — Phase 31 sign-of-r gate.
    #[size = 1]
    DivSActivePartialH,
    /// `IsDivS · (1 - DivByZero)` — root helper for DivSActivePartialH.
    #[size = 1]
    IsDivSNotDbzH,
    /// `IsShiftConstrained · (1 - IsRotateR64 - IsRotateR32)` — Phase 36
    /// PowerOfTwo lookup multiplicity for the classic shift case.
    #[size = 1]
    IsShiftCNotRotrH,
}

#[derive(Debug, Copy, Clone, PreprocessedAirColumn)]
#[preprocessed_prefix = "cpu"]
pub enum PreprocessedColumn {}
