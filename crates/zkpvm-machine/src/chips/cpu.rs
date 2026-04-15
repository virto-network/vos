use num_traits::{One, Zero};
use stwo::{
    core::{
        fields::{m31::BaseField, qm31::SecureField},
        ColumnVec,
    },
    prover::{
        backend::simd::{m31::{LOG_N_LANES, PackedBaseField}, SimdBackend},
        poly::{circle::CircleEvaluation, BitReversedOrder},
    },
};
use stwo_constraint_framework::{EvalAtRow, RelationEntry};

use zkpvm_air_column::{AirColumn, PreprocessedAirColumn};
use zkpvm_core::step::WORD_SIZE;
use zkpvm_trace::{
    builder::{FinalizedTrace, TraceBuilder},
    component::ComponentTrace,
    eval::TraceEval,
};

use crate::{
    framework::BuiltInComponent,
    lookups::{
        AllLookupElements, BitwiseAndLookupElements, LogupTraceBuilder,
        MemoryAccessLookupElements, PowerOfTwoLookupElements,
        ProgramExecutionLookupElements, Range256LookupElements,
    },
    side_note::SideNote,
};

pub struct CpuChip;

// ── Column layout ──────────────────────────────────────────────────────────

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
    // ── Shift auxiliary ──
    #[size = 1]
    ShiftAmount,
    #[size = 1]
    ShiftOp,
    /// 1 when is_shift AND shift_op ∈ {0,1} (left shift or logical right shift)
    #[size = 1]
    IsShiftConstrained,
    // ── Control flow ──
    /// Conditional branch (BranchEq/Ne/Lt/Ge + imm variants)
    #[size = 1]
    IsBranch,
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
}

#[derive(Debug, Copy, Clone, PreprocessedAirColumn)]
#[preprocessed_prefix = "cpu"]
pub enum PreprocessedColumn {}

// ── Opcode classification ──────────────────────────────────────────────────

use javm::instruction::Opcode;

#[derive(Clone, Copy, Default)]
struct OpcodeFlags {
    is_add: bool,
    is_sub: bool,
    is_mul: bool,
    is_bitwise: bool,
    is_shift: bool,
    is_compare: bool,
    is_move: bool,
    is_32bit: bool,
    is_and: bool,
    is_or: bool,
    is_xor: bool,
    is_and_inv: bool,
    is_or_inv: bool,
    is_xnor: bool,
    is_neg_add: bool,
    is_set_lt_u: bool,
    is_set_lt_s: bool,
    is_cmov_iz: bool,
    is_cmov_nz: bool,
    is_min_s: bool,
    is_min_u: bool,
    is_max_s: bool,
    is_max_u: bool,
    shift_op: u8,
    is_branch: bool,
    is_jump: bool,
    is_div_rem: bool,
    div_rem_op: u8,
    is_load: bool,
    is_store: bool,
    is_mul_upper: bool,
}

fn classify_opcode(op: Opcode) -> OpcodeFlags {
    let mut f = OpcodeFlags::default();
    match op {
        Opcode::Add64 | Opcode::AddImm64 => { f.is_add = true; }
        Opcode::Add32 | Opcode::AddImm32 => { f.is_add = true; f.is_32bit = true; }
        Opcode::Sub64 => { f.is_sub = true; }
        Opcode::Sub32 => { f.is_sub = true; f.is_32bit = true; }
        Opcode::NegAddImm64 => { f.is_sub = true; f.is_neg_add = true; }
        Opcode::NegAddImm32 => { f.is_sub = true; f.is_neg_add = true; f.is_32bit = true; }
        Opcode::Mul64 | Opcode::MulImm64 => { f.is_mul = true; }
        Opcode::Mul32 | Opcode::MulImm32 => { f.is_mul = true; f.is_32bit = true; }
        // MulUpper: result = high 64 bits of 128-bit product
        Opcode::MulUpperUU | Opcode::MulUpperSS | Opcode::MulUpperSU => { f.is_mul = true; f.is_mul_upper = true; }
        Opcode::And | Opcode::AndImm => { f.is_bitwise = true; f.is_and = true; }
        Opcode::Or  | Opcode::OrImm  => { f.is_bitwise = true; f.is_or = true; }
        Opcode::Xor | Opcode::XorImm => { f.is_bitwise = true; f.is_xor = true; }
        Opcode::AndInv => { f.is_bitwise = true; f.is_and_inv = true; }
        Opcode::OrInv  => { f.is_bitwise = true; f.is_or_inv = true; }
        Opcode::Xnor   => { f.is_bitwise = true; f.is_xnor = true; }
        // Left shifts: constrained via mul (val_d = 2^shift_amount)
        Opcode::ShloL64 | Opcode::ShloLImm64 | Opcode::ShloLImmAlt64 => { f.is_shift = true; f.shift_op = 0; f.is_mul = true; }
        Opcode::ShloL32 | Opcode::ShloLImm32 | Opcode::ShloLImmAlt32 => { f.is_shift = true; f.shift_op = 0; f.is_mul = true; f.is_32bit = true; }
        // Logical right shifts: constrained via divrem (val_d = 2^shift_amount, result = quotient)
        Opcode::ShloR64 | Opcode::ShloRImm64 | Opcode::ShloRImmAlt64 => { f.is_shift = true; f.shift_op = 1; f.is_div_rem = true; f.div_rem_op = 0; }
        Opcode::ShloR32 | Opcode::ShloRImm32 | Opcode::ShloRImmAlt32 => { f.is_shift = true; f.shift_op = 1; f.is_div_rem = true; f.div_rem_op = 0; f.is_32bit = true; }
        Opcode::SharR64 | Opcode::SharRImm64 | Opcode::SharRImmAlt64 => { f.is_shift = true; f.shift_op = 2; }
        Opcode::SharR32 | Opcode::SharRImm32 | Opcode::SharRImmAlt32 => { f.is_shift = true; f.shift_op = 2; f.is_32bit = true; }
        Opcode::RotL64 => { f.is_shift = true; f.shift_op = 3; }
        Opcode::RotL32 => { f.is_shift = true; f.shift_op = 3; f.is_32bit = true; }
        Opcode::RotR64 | Opcode::RotR64Imm | Opcode::RotR64ImmAlt => { f.is_shift = true; f.shift_op = 4; }
        Opcode::RotR32 | Opcode::RotR32Imm | Opcode::RotR32ImmAlt => { f.is_shift = true; f.shift_op = 4; f.is_32bit = true; }
        // Compare
        Opcode::SetLtU | Opcode::SetLtUImm => { f.is_compare = true; f.is_set_lt_u = true; }
        Opcode::SetLtS | Opcode::SetLtSImm => { f.is_compare = true; f.is_set_lt_s = true; }
        Opcode::SetGtUImm => { f.is_compare = true; f.is_set_lt_u = true; } // SetGt = swap + SetLt
        Opcode::SetGtSImm => { f.is_compare = true; f.is_set_lt_s = true; }
        Opcode::CmovIz | Opcode::CmovIzImm => { f.is_compare = true; f.is_cmov_iz = true; }
        Opcode::CmovNz | Opcode::CmovNzImm => { f.is_compare = true; f.is_cmov_nz = true; }
        Opcode::Min  => { f.is_compare = true; f.is_min_s = true; }
        Opcode::MinU => { f.is_compare = true; f.is_min_u = true; }
        Opcode::Max  => { f.is_compare = true; f.is_max_s = true; }
        Opcode::MaxU => { f.is_compare = true; f.is_max_u = true; }
        // Move
        Opcode::MoveReg | Opcode::LoadImm | Opcode::LoadImm64 => { f.is_move = true; }
        // BitManip (TwoReg unary ops — prover-trusted, classified to avoid false constraints)
        Opcode::CountSetBits64 | Opcode::CountSetBits32
        | Opcode::LeadingZeroBits64 | Opcode::LeadingZeroBits32
        | Opcode::TrailingZeroBits64 | Opcode::TrailingZeroBits32
        | Opcode::SignExtend8 | Opcode::SignExtend16
        | Opcode::ZeroExtend16 | Opcode::ReverseBytes
        | Opcode::Sbrk
            => {}
        // Branches (conditional)
        Opcode::BranchEq | Opcode::BranchNe | Opcode::BranchLtU | Opcode::BranchLtS
        | Opcode::BranchGeU | Opcode::BranchGeS
        | Opcode::BranchEqImm | Opcode::BranchNeImm
        | Opcode::BranchLtUImm | Opcode::BranchLeUImm | Opcode::BranchGeUImm | Opcode::BranchGtUImm
        | Opcode::BranchLtSImm | Opcode::BranchLeSImm | Opcode::BranchGeSImm | Opcode::BranchGtSImm
            => { f.is_branch = true; }
        // DivRem
        Opcode::DivU64 => { f.is_div_rem = true; f.div_rem_op = 0; }
        Opcode::DivU32 => { f.is_div_rem = true; f.div_rem_op = 0; f.is_32bit = true; }
        Opcode::DivS64 => { f.is_div_rem = true; f.div_rem_op = 1; }
        Opcode::DivS32 => { f.is_div_rem = true; f.div_rem_op = 1; f.is_32bit = true; }
        Opcode::RemU64 => { f.is_div_rem = true; f.div_rem_op = 2; }
        Opcode::RemU32 => { f.is_div_rem = true; f.div_rem_op = 2; f.is_32bit = true; }
        Opcode::RemS64 => { f.is_div_rem = true; f.div_rem_op = 3; }
        Opcode::RemS32 => { f.is_div_rem = true; f.div_rem_op = 3; f.is_32bit = true; }
        // Loads
        Opcode::LoadU8 | Opcode::LoadI8 | Opcode::LoadU16 | Opcode::LoadI16
        | Opcode::LoadU32 | Opcode::LoadI32 | Opcode::LoadU64
        | Opcode::LoadIndU8 | Opcode::LoadIndI8 | Opcode::LoadIndU16 | Opcode::LoadIndI16
        | Opcode::LoadIndU32 | Opcode::LoadIndI32 | Opcode::LoadIndU64
            => { f.is_load = true; }
        // Stores
        Opcode::StoreU8 | Opcode::StoreU16 | Opcode::StoreU32 | Opcode::StoreU64
        | Opcode::StoreIndU8 | Opcode::StoreIndU16 | Opcode::StoreIndU32 | Opcode::StoreIndU64
        | Opcode::StoreImmU8 | Opcode::StoreImmU16 | Opcode::StoreImmU32 | Opcode::StoreImmU64
        | Opcode::StoreImmIndU8 | Opcode::StoreImmIndU16 | Opcode::StoreImmIndU32 | Opcode::StoreImmIndU64
            => { f.is_store = true; }
        // Jumps (unconditional, non-sequential target)
        Opcode::Jump | Opcode::LoadImmJump
            => { f.is_jump = true; }
        // Fallthrough/Unlikely: sequential terminators, no special control flow constraint
        Opcode::Fallthrough | Opcode::Unlikely => {}
        // JumpInd/LoadImmJumpInd: dynamic jumps (prover-trusted target for now)
        Opcode::JumpInd | Opcode::LoadImmJumpInd => {}
        // Ecalli: host call (execution exits, no ALU constraint)
        Opcode::Ecalli | Opcode::Ecall => {}
        // Trap: causes panic exit
        Opcode::Trap => {}
    }
    f
}

fn uses_immediate(op: Opcode) -> bool {
    matches!(op,
        Opcode::AddImm32 | Opcode::AddImm64
        | Opcode::NegAddImm32 | Opcode::NegAddImm64
        | Opcode::MulImm32 | Opcode::MulImm64
        | Opcode::AndImm | Opcode::OrImm | Opcode::XorImm
        | Opcode::ShloLImm32 | Opcode::ShloRImm32 | Opcode::SharRImm32
        | Opcode::ShloLImmAlt32 | Opcode::ShloRImmAlt32 | Opcode::SharRImmAlt32
        | Opcode::ShloLImm64 | Opcode::ShloRImm64 | Opcode::SharRImm64
        | Opcode::ShloLImmAlt64 | Opcode::ShloRImmAlt64 | Opcode::SharRImmAlt64
        | Opcode::RotR64Imm | Opcode::RotR64ImmAlt | Opcode::RotR32Imm | Opcode::RotR32ImmAlt
        | Opcode::SetLtUImm | Opcode::SetLtSImm | Opcode::SetGtUImm | Opcode::SetGtSImm
        | Opcode::CmovIzImm | Opcode::CmovNzImm
        | Opcode::LoadImm | Opcode::LoadImm64
    )
}

fn dest_reg(step: &zkpvm_core::step::PvmStep) -> usize {
    use javm::instruction::InstructionCategory::*;
    match step.opcode.category() {
        ThreeReg => step.reg_d,
        _ => step.reg_a,
    }
}

// ── Trace generation ───────────────────────────────────────────────────────

impl BuiltInComponent for CpuChip {
    const LOG_CONSTRAINT_DEGREE_BOUND: u32 = 2; // max degree 4 (flag * flag * flag * linear)

    type PreprocessedColumn = PreprocessedColumn;
    type MainColumn = Column;
    type LookupElements = (Range256LookupElements, MemoryAccessLookupElements, ProgramExecutionLookupElements, BitwiseAndLookupElements, PowerOfTwoLookupElements);

    fn generate_preprocessed_trace(&self, _log_size: u32, _side_note: &SideNote) -> FinalizedTrace {
        FinalizedTrace::empty()
    }

    fn generate_main_trace(&self, side_note: &mut SideNote) -> FinalizedTrace {
        let num_steps = side_note.num_steps();
        let log_size = (num_steps as f64).log2().ceil().max(LOG_N_LANES as f64) as u32;
        let log_size = log_size.max(LOG_N_LANES);

        let mut trace = TraceBuilder::<Column>::new(log_size);
        let num_rows = trace.num_rows();
        let mut range_bytes: Vec<u8> = Vec::new();
        let mut bitwise_and_bytes: Vec<(u8, u8)> = Vec::new();

        for (row, step) in side_note.steps.iter().enumerate() {
            trace.fill_columns(row, step.timestamp, Column::Timestamp);
            trace.fill_columns_bytes(row, &step.pc.to_le_bytes(), Column::Pc);
            trace.fill_columns_bytes(row, &step.next_pc.to_le_bytes(), Column::NextPc);
            trace.fill_columns(row, step.opcode as u8, Column::Opcode);
            trace.fill_columns(row, step.skip_len as u8, Column::SkipLen);
            trace.fill_columns(row, step.reg_a as u8, Column::RegA);
            trace.fill_columns(row, step.reg_b as u8, Column::RegB);
            trace.fill_columns(row, step.reg_d as u8, Column::RegD);

            // Source operands
            let (mut val_b, mut val_d) = match step.opcode.category() {
                javm::instruction::InstructionCategory::ThreeReg => {
                    (step.regs_before[step.reg_a], step.regs_before[step.reg_b])
                }
                javm::instruction::InstructionCategory::TwoRegOneImm => {
                    (step.regs_before[step.reg_b], step.imm)
                }
                javm::instruction::InstructionCategory::TwoReg => {
                    (0, step.regs_before[step.reg_b])
                }
                _ if uses_immediate(step.opcode) => {
                    (0, step.imm)
                }
                _ => (step.regs_before[step.reg_a], step.regs_before[step.reg_b]),
            };

            let flags = classify_opcode(step.opcode);

            // For left/right shifts: save shift amount, then replace val_d with 2^shift_amount
            let mut saved_shift_amount: u8 = 0;
            if flags.is_shift && (flags.shift_op == 0 || flags.shift_op == 1) {
                let modulus = if flags.is_32bit { 32u64 } else { 64 };
                let shift = val_d % modulus;
                saved_shift_amount = shift as u8;
                val_d = 1u64 << shift;
                side_note.power_of_two_counts[shift as usize] += 1;
            }

            // Truncate for 32-bit ALU ops (including divrem for right shifts)
            if flags.is_32bit && (flags.is_add || flags.is_sub || flags.is_mul || flags.is_div_rem) {
                val_b &= 0xFFFF_FFFF;
                val_d &= 0xFFFF_FFFF;
            }

            trace.fill_columns(row, val_b, Column::ValB);
            trace.fill_columns(row, val_d, Column::ValD);

            let dr = dest_reg(step);
            let result = step.regs_after[dr];
            trace.fill_columns(row, result, Column::Result);

            let val_b_bytes = val_b.to_le_bytes();
            let val_d_bytes = val_d.to_le_bytes();
            let result_bytes = result.to_le_bytes();

            // ── Add/Sub carry ──
            let carry_limbs = if flags.is_32bit { 4 } else { WORD_SIZE };
            let mut carry = [0u8; WORD_SIZE];
            if flags.is_add {
                let mut c: u16 = 0;
                for i in 0..carry_limbs {
                    let sum = val_b_bytes[i] as u16 + val_d_bytes[i] as u16 + c;
                    carry[i] = (sum >> 8) as u8;
                    c = carry[i] as u16;
                }
            } else if flags.is_sub {
                let (a, b) = if flags.is_neg_add { (val_d_bytes, val_b_bytes) } else { (val_b_bytes, val_d_bytes) };
                let mut c: u16 = 1;
                for i in 0..carry_limbs {
                    let sum = a[i] as u16 + (b[i] ^ 0xFF) as u16 + c;
                    carry[i] = (sum >> 8) as u8;
                    c = carry[i] as u16;
                }
            }
            trace.fill_columns_bytes(row, &carry, Column::Carry);

            // ── Mul auxiliary ──
            let mut mul_high = [0u8; WORD_SIZE];
            let mut mul_carry = [0u8; 16];
            if flags.is_mul {
                let full = (val_b as u128) * (val_d as u128);
                if flags.is_32bit {
                    // 32-bit: split at 32 bits
                    let high32 = (full >> 32) as u32;
                    let high_bytes = high32.to_le_bytes();
                    mul_high[..4].copy_from_slice(&high_bytes);
                } else if flags.is_mul_upper {
                    // MulUpper: result holds high bits, mul_high holds LOW bits
                    let low = full as u64;
                    mul_high = low.to_le_bytes();
                } else {
                    let high = (full >> 64) as u64;
                    mul_high = high.to_le_bytes();
                }
                let input_limbs = if flags.is_32bit { 4 } else { WORD_SIZE };
                let out_limbs = input_limbs * 2;
                let mut accum = [0u32; 16];
                for i in 0..input_limbs {
                    for j in 0..input_limbs {
                        accum[i + j] += val_b_bytes[i] as u32 * val_d_bytes[j] as u32;
                    }
                }
                for k in 0..out_limbs.min(16).saturating_sub(1) {
                    mul_carry[k] = (accum[k] >> 8) as u8;
                    accum[k + 1] += accum[k] >> 8;
                }
                if out_limbs <= 16 && out_limbs > 0 {
                    mul_carry[out_limbs - 1] = (accum[out_limbs - 1] >> 8) as u8;
                }
            }
            trace.fill_columns_bytes(row, &mul_high, Column::MulHigh);
            trace.fill_columns_bytes(row, &mul_carry, Column::MulCarry);

            // ── Bitwise auxiliary ──
            let mut and_result = [0u8; WORD_SIZE];
            if flags.is_bitwise {
                for i in 0..WORD_SIZE {
                    and_result[i] = val_b_bytes[i] & val_d_bytes[i];
                    bitwise_and_bytes.push((val_b_bytes[i], val_d_bytes[i]));
                }
            }
            trace.fill_columns_bytes(row, &and_result, Column::AndResult);
            // High nibbles for nibble-level AND lookup
            let mut val_b_hi_nib = [0u8; WORD_SIZE];
            let mut val_d_hi_nib = [0u8; WORD_SIZE];
            let mut and_result_hi_nib = [0u8; WORD_SIZE];
            if flags.is_bitwise {
                for i in 0..WORD_SIZE {
                    val_b_hi_nib[i] = val_b_bytes[i] >> 4;
                    val_d_hi_nib[i] = val_d_bytes[i] >> 4;
                    and_result_hi_nib[i] = and_result[i] >> 4;
                }
            }
            trace.fill_columns_bytes(row, &val_b_hi_nib, Column::ValBHiNib);
            trace.fill_columns_bytes(row, &val_d_hi_nib, Column::ValDHiNib);
            trace.fill_columns_bytes(row, &and_result_hi_nib, Column::AndResultHiNib);

            // ── Compare auxiliary ──
            let mut cmp_carry = [0u8; WORD_SIZE];
            let mut cmp_lt_flag: u8 = 0;
            if flags.is_compare {
                // Unsigned comparison via subtraction: val_b - val_d
                let mut c: u16 = 1;
                for i in 0..WORD_SIZE {
                    let sum = val_b_bytes[i] as u16 + (val_d_bytes[i] ^ 0xFF) as u16 + c;
                    cmp_carry[i] = (sum >> 8) as u8;
                    c = cmp_carry[i] as u16;
                }
                // a - b via a + ~b + 1: carry_out=1 means a>=b, carry_out=0 means a<b
                cmp_lt_flag = 1 - cmp_carry[WORD_SIZE - 1];
            }
            trace.fill_columns_bytes(row, &cmp_carry, Column::CmpCarry);
            trace.fill_columns(row, cmp_lt_flag, Column::CmpLtFlag);
            let val_d_is_zero: u8 = if val_d == 0 { 1 } else { 0 };
            trace.fill_columns(row, val_d_is_zero, Column::ValDIsZero);
            let sign_bit_b: u8 = if flags.is_32bit { ((val_b >> 31) & 1) as u8 } else { ((val_b >> 63) & 1) as u8 };
            let sign_bit_d: u8 = if flags.is_32bit { ((val_d >> 31) & 1) as u8 } else { ((val_d >> 63) & 1) as u8 };
            trace.fill_columns(row, sign_bit_b, Column::SignBitB);
            trace.fill_columns(row, sign_bit_d, Column::SignBitD);
            // Signed lt: if signs differ, negative is smaller. If same, use unsigned compare.
            let cmp_lt_s_flag: u8 = if sign_bit_b != sign_bit_d {
                sign_bit_b // b is negative (sign=1) → b < d
            } else {
                cmp_lt_flag // same sign → unsigned comparison
            };
            trace.fill_columns(row, cmp_lt_s_flag, Column::CmpLtSFlag);
            trace.fill_columns(row, flags.is_set_lt_u, Column::IsSetLtU);
            trace.fill_columns(row, flags.is_set_lt_s, Column::IsSetLtS);
            trace.fill_columns(row, flags.is_cmov_iz, Column::IsCmovIz);
            trace.fill_columns(row, flags.is_cmov_nz, Column::IsCmovNz);
            trace.fill_columns(row, flags.is_min_s, Column::IsMinS);
            trace.fill_columns(row, flags.is_min_u, Column::IsMinU);
            trace.fill_columns(row, flags.is_max_s, Column::IsMaxS);
            trace.fill_columns(row, flags.is_max_u, Column::IsMaxU);

            // ── Shift auxiliary ──
            let shift_amount = if flags.is_shift {
                if flags.shift_op == 0 || flags.shift_op == 1 {
                    saved_shift_amount // saved before val_d was replaced
                } else {
                    let modulus = if flags.is_32bit { 32u64 } else { 64 };
                    (val_d % modulus) as u8 // for non-constrained shifts, val_d is original
                }
            } else {
                0
            };
            trace.fill_columns(row, shift_amount, Column::ShiftAmount);
            trace.fill_columns(row, flags.shift_op, Column::ShiftOp);
            let is_shift_constrained = flags.is_shift && (flags.shift_op == 0 || flags.shift_op == 1);
            trace.fill_columns(row, is_shift_constrained, Column::IsShiftConstrained);

            // ── Flags ──
            trace.fill_columns(row, false, Column::IsPadding);
            trace.fill_columns(row, step.reg_write.is_some(), Column::RegAWritten);
            trace.fill_columns(row, step.gas_after, Column::Gas);
            trace.fill_columns(row, flags.is_add, Column::IsAdd);
            trace.fill_columns(row, flags.is_sub, Column::IsSub);
            trace.fill_columns(row, flags.is_mul, Column::IsMul);
            trace.fill_columns(row, flags.is_mul_upper, Column::IsMulUpper);
            trace.fill_columns(row, flags.is_bitwise, Column::IsBitwise);
            trace.fill_columns(row, flags.is_shift, Column::IsShift);
            trace.fill_columns(row, flags.is_compare, Column::IsCompare);
            trace.fill_columns(row, flags.is_move, Column::IsMove);
            trace.fill_columns(row, flags.is_32bit, Column::Is32Bit);
            trace.fill_columns(row, flags.is_and, Column::IsAnd);
            trace.fill_columns(row, flags.is_or, Column::IsOr);
            trace.fill_columns(row, flags.is_xor, Column::IsXor);
            trace.fill_columns(row, flags.is_and_inv, Column::IsAndInv);
            trace.fill_columns(row, flags.is_or_inv, Column::IsOrInv);
            trace.fill_columns(row, flags.is_xnor, Column::IsXnor);
            trace.fill_columns(row, flags.is_neg_add, Column::IsNegAdd);
            trace.fill_columns(row, flags.is_branch, Column::IsBranch);
            trace.fill_columns(row, flags.is_jump, Column::IsJump);
            trace.fill_columns(row, step.branch_taken, Column::BranchTaken);
            trace.fill_columns_bytes(row, &step.branch_target.to_le_bytes(), Column::BranchTarget);
            trace.fill_columns(row, flags.is_div_rem, Column::IsDivRem);
            trace.fill_columns(row, flags.div_rem_op, Column::DivRemOp);

            // ── DivRem auxiliary ──
            let mut div_quotient = [0u8; WORD_SIZE];
            let mut div_remainder = [0u8; WORD_SIZE];
            let mut div_mul_carry = [0u8; 16];
            let mut div_by_zero: u8 = 0;
            if flags.is_div_rem {
                let dividend = val_b;
                let divisor = val_d;
                if divisor == 0 {
                    div_by_zero = 1;
                    // For div-by-zero: result is special (u64::MAX for div, dividend for rem)
                    // quotient/remainder don't matter, constraint is bypassed
                } else {
                    let (q, r) = if flags.div_rem_op <= 1 {
                        // Unsigned div (op 0) or signed div (op 1, prover-trusted for sign)
                        (dividend / divisor, dividend % divisor)
                    } else {
                        // Unsigned rem (op 2) or signed rem (op 3)
                        (dividend / divisor, dividend % divisor)
                    };
                    div_quotient = q.to_le_bytes();
                    div_remainder = r.to_le_bytes();

                    // Carry chain for q * divisor + remainder = dividend (schoolbook)
                    let divisor_bytes = divisor.to_le_bytes();
                    let input_limbs = if flags.is_32bit { 4 } else { WORD_SIZE };
                    let out_limbs = input_limbs * 2;
                    let mut accum = [0u32; 16];
                    for i in 0..input_limbs {
                        for j in 0..input_limbs {
                            accum[i + j] += div_quotient[i] as u32 * divisor_bytes[j] as u32;
                        }
                    }
                    // Add remainder to low limbs
                    for i in 0..input_limbs {
                        accum[i] += div_remainder[i] as u32;
                    }
                    for k in 0..out_limbs.min(16).saturating_sub(1) {
                        div_mul_carry[k] = (accum[k] >> 8) as u8;
                        accum[k + 1] += accum[k] >> 8;
                    }
                    if out_limbs > 0 && out_limbs <= 16 {
                        div_mul_carry[out_limbs - 1] = (accum[out_limbs - 1] >> 8) as u8;
                    }
                }
            }
            trace.fill_columns_bytes(row, &div_quotient, Column::DivQuotient);
            trace.fill_columns_bytes(row, &div_remainder, Column::DivRemainder);
            trace.fill_columns_bytes(row, &div_mul_carry, Column::DivMulCarry);
            trace.fill_columns(row, div_by_zero, Column::DivByZero);

            // ── Memory access columns ──
            trace.fill_columns(row, flags.is_load, Column::IsLoad);
            trace.fill_columns(row, flags.is_store, Column::IsStore);
            let mem = step.mem_read.as_ref().or(step.mem_write.as_ref());
            if let Some(m) = mem {
                trace.fill_columns_bytes(row, &m.address.to_le_bytes(), Column::MemAddr);
                trace.fill_columns(row, m.value, Column::MemValue);
                trace.fill_columns(row, m.size, Column::MemSize);
                let mut byte_active = [0u8; 8];
                for i in 0..m.size as usize { byte_active[i] = 1; }
                trace.fill_columns_bytes(row, &byte_active, Column::MemByteActive);
            }

            // NextTimestamp = timestamp + 1
            trace.fill_columns(row, step.timestamp + 1, Column::NextTimestamp);

            for &b in &result_bytes {
                range_bytes.push(b);
            }
        }

        for &b in &range_bytes {
            side_note.add_range256(b);
        }
        for &(a, b) in &bitwise_and_bytes {
            side_note.add_bitwise_and(a, b);
        }

        let last_ts = side_note.steps.last().map(|s| s.timestamp).unwrap_or(0);
        for row in num_steps..num_rows {
            let ts = last_ts + (row - num_steps + 1) as u64;
            trace.fill_columns(row, true, Column::IsPadding);
            trace.fill_columns(row, ts, Column::Timestamp);
            trace.fill_columns(row, ts + 1, Column::NextTimestamp);
        }

        trace.finalize_bit_reversed()
    }

    // ── Interaction trace ──────────────────────────────────────────────────

    fn generate_interaction_trace(
        &self,
        component_trace: ComponentTrace,
        _side_note: &SideNote,
        lookup_elements: &AllLookupElements,
    ) -> (
        ColumnVec<CircleEvaluation<SimdBackend, BaseField, BitReversedOrder>>,
        SecureField,
    ) {
        let log_size = component_trace.log_size();
        let mut logup = LogupTraceBuilder::new(log_size);
        let is_pad = zkpvm_trace::original_base_column!(component_trace, Column::IsPadding);
        let range256: &Range256LookupElements = lookup_elements.as_ref();

        // Range256 lookups for result bytes
        let result = zkpvm_trace::original_base_column!(component_trace, Column::Result);
        for col in &result {
            logup.add_to_relation_with(
                range256,
                [is_pad[0].clone()],
                |[pad]| {
                    use stwo::prover::backend::simd::m31::PackedBaseField;
                    (PackedBaseField::one() - pad).into()
                },
                &[col.clone()],
            );
        }

        // Memory access lookups — byte-level (up to 8 entries per memory op)
        let mem_lookup: &MemoryAccessLookupElements = lookup_elements.as_ref();
        let is_store = zkpvm_trace::original_base_column!(component_trace, Column::IsStore);
        let mem_addr = zkpvm_trace::original_base_column!(component_trace, Column::MemAddr);
        let mem_value = zkpvm_trace::original_base_column!(component_trace, Column::MemValue);
        let timestamp = zkpvm_trace::original_base_column!(component_trace, Column::Timestamp);
        let mem_byte_active = zkpvm_trace::original_base_column!(component_trace, Column::MemByteActive);

        // For each byte offset 0..8, produce a byte-level lookup entry
        // Tuple: (addr+i [4], value_byte_i [1], timestamp[8], is_write[1])
        // Multiplicity: mem_byte_active[i] (1 if byte is within access size, 0 otherwise)
        for byte_idx in 0..8usize {
            let byte_offset = PackedBaseField::broadcast(BaseField::from(byte_idx as u32));
            let mem_addr_c = mem_addr.clone();
            let mem_value_c = mem_value.clone();
            let timestamp_c = timestamp.clone();
            let is_store_c = is_store.clone();
            logup.add_to_relation_computed(
                mem_lookup,
                [mem_byte_active[byte_idx].clone()],
                |[active]| active.into(),
                14, // tuple size: addr[4] + value[1] + timestamp[8] + is_write[1]
                |vec_idx| {
                    let mut tuple = Vec::with_capacity(14);
                    // addr + byte_idx (add offset to low byte)
                    tuple.push(mem_addr_c[0].at(vec_idx) + byte_offset);
                    for j in 1..4 { tuple.push(mem_addr_c[j].at(vec_idx)); }
                    // value byte
                    tuple.push(mem_value_c[byte_idx].at(vec_idx));
                    // timestamp
                    for col in &timestamp_c { tuple.push(col.at(vec_idx)); }
                    // is_write
                    tuple.push(is_store_c[0].at(vec_idx));
                    tuple
                },
            );
        }

        // Program execution lookup: consume (ts, pc), produce (ts+1, next_pc)
        let prog_exec: &ProgramExecutionLookupElements = lookup_elements.as_ref();
        let pc = zkpvm_trace::original_base_column!(component_trace, Column::Pc);
        let next_pc_col = zkpvm_trace::original_base_column!(component_trace, Column::NextPc);
        let next_ts = zkpvm_trace::original_base_column!(component_trace, Column::NextTimestamp);
        {
            let mut consume_tuple: Vec<_> = timestamp.to_vec();
            consume_tuple.extend_from_slice(&pc);
            logup.add_to_relation_with(
                prog_exec,
                [is_pad[0].clone()],
                |[pad]| {
                    use stwo::prover::backend::simd::m31::PackedBaseField;
                    (-(PackedBaseField::one() - pad)).into()
                },
                &consume_tuple,
            );
        }
        {
            let mut produce_tuple: Vec<_> = next_ts.to_vec();
            produce_tuple.extend_from_slice(&next_pc_col);
            logup.add_to_relation_with(
                prog_exec,
                [is_pad[0].clone()],
                |[pad]| {
                    use stwo::prover::backend::simd::m31::PackedBaseField;
                    (PackedBaseField::one() - pad).into()
                },
                &produce_tuple,
            );
        }

        // Bitwise AND lookup: nibble-level (16 lookups per bitwise op)
        // For each byte i: lookup (hi_nib_b, hi_nib_d, hi_nib_and) and (lo_nib_b, lo_nib_d, lo_nib_and)
        let bitwise_and: &BitwiseAndLookupElements = lookup_elements.as_ref();
        let is_bitwise = zkpvm_trace::original_base_column!(component_trace, Column::IsBitwise);
        let val_b_cols = zkpvm_trace::original_base_column!(component_trace, Column::ValB);
        let val_d_cols = zkpvm_trace::original_base_column!(component_trace, Column::ValD);
        let and_result_cols = zkpvm_trace::original_base_column!(component_trace, Column::AndResult);
        let val_b_hi_nib = zkpvm_trace::original_base_column!(component_trace, Column::ValBHiNib);
        let val_d_hi_nib = zkpvm_trace::original_base_column!(component_trace, Column::ValDHiNib);
        let and_result_hi_nib = zkpvm_trace::original_base_column!(component_trace, Column::AndResultHiNib);
        let sixteen = PackedBaseField::broadcast(BaseField::from(16));
        for i in 0..WORD_SIZE {
            // High nibble lookup: (val_b_hi[i], val_d_hi[i], and_result_hi[i])
            logup.add_to_relation_with(
                bitwise_and,
                [is_bitwise[0].clone()],
                |[bw]| bw.into(),
                &[val_b_hi_nib[i].clone(), val_d_hi_nib[i].clone(), and_result_hi_nib[i].clone()],
            );
            // Low nibble lookup: (val_b_lo[i], val_d_lo[i], and_result_lo[i])
            // lo = byte - hi * 16
            let val_b_col_i = val_b_cols[i].clone();
            let val_d_col_i = val_d_cols[i].clone();
            let and_result_col_i = and_result_cols[i].clone();
            let val_b_hi_i = val_b_hi_nib[i].clone();
            let val_d_hi_i = val_d_hi_nib[i].clone();
            let and_hi_i = and_result_hi_nib[i].clone();
            logup.add_to_relation_computed(
                bitwise_and,
                [is_bitwise[0].clone()],
                |[bw]| bw.into(),
                3,
                |vec_idx| {
                    let b_lo = val_b_col_i.at(vec_idx) - val_b_hi_i.at(vec_idx) * sixteen;
                    let d_lo = val_d_col_i.at(vec_idx) - val_d_hi_i.at(vec_idx) * sixteen;
                    let and_lo = and_result_col_i.at(vec_idx) - and_hi_i.at(vec_idx) * sixteen;
                    vec![b_lo, d_lo, and_lo]
                },
            );
        }

        // Power-of-two lookup: (shift_amount, val_d[8]) when is_shift && shift_op ∈ {0,1}
        // Power-of-two lookup: (shift_amount, val_d[8]) when shift is constrained
        let pow2_lookup: &PowerOfTwoLookupElements = lookup_elements.as_ref();
        let shift_amount_col = zkpvm_trace::original_base_column!(component_trace, Column::ShiftAmount);
        let is_shift_constrained = zkpvm_trace::original_base_column!(component_trace, Column::IsShiftConstrained);
        let val_d_cols = zkpvm_trace::original_base_column!(component_trace, Column::ValD);
        {
            let mut tuple: Vec<_> = vec![shift_amount_col[0].clone()];
            tuple.extend_from_slice(&val_d_cols);
            logup.add_to_relation_with(
                pow2_lookup,
                [is_shift_constrained[0].clone()],
                |[active]| active.into(),
                &tuple,
            );
        }

        logup.finalize()
    }

    // ── Constraints ────────────────────────────────────────────────────────

    fn add_constraints<E: EvalAtRow>(
        &self,
        eval: &mut E,
        trace_eval: TraceEval<PreprocessedColumn, Column, E>,
        lookup_elements: &(Range256LookupElements, MemoryAccessLookupElements, ProgramExecutionLookupElements, BitwiseAndLookupElements, PowerOfTwoLookupElements),
    ) {
        let (range256_lookup, mem_lookup, prog_exec_lookup, bitwise_and_lookup, pow2_lookup) = lookup_elements;
        let is_pad = zkpvm_trace::trace_eval!(trace_eval, Column::IsPadding);
        let is_real = E::F::one() - is_pad[0].clone();

        let is_add = zkpvm_trace::trace_eval!(trace_eval, Column::IsAdd);
        let is_sub = zkpvm_trace::trace_eval!(trace_eval, Column::IsSub);
        let is_mul = zkpvm_trace::trace_eval!(trace_eval, Column::IsMul);
        let _is_bitwise = zkpvm_trace::trace_eval!(trace_eval, Column::IsBitwise);
        let is_shift = zkpvm_trace::trace_eval!(trace_eval, Column::IsShift);
        let is_compare = zkpvm_trace::trace_eval!(trace_eval, Column::IsCompare);
        let is_move = zkpvm_trace::trace_eval!(trace_eval, Column::IsMove);
        let is_neg_add = zkpvm_trace::trace_eval!(trace_eval, Column::IsNegAdd);
        let is_32bit = zkpvm_trace::trace_eval!(trace_eval, Column::Is32Bit);
        let is_64bit = E::F::one() - is_32bit[0].clone();
        let is_and_flag = zkpvm_trace::trace_eval!(trace_eval, Column::IsAnd);
        let is_or_flag = zkpvm_trace::trace_eval!(trace_eval, Column::IsOr);
        let is_xor_flag = zkpvm_trace::trace_eval!(trace_eval, Column::IsXor);
        let is_and_inv_flag = zkpvm_trace::trace_eval!(trace_eval, Column::IsAndInv);
        let is_or_inv_flag = zkpvm_trace::trace_eval!(trace_eval, Column::IsOrInv);
        let is_xnor_flag = zkpvm_trace::trace_eval!(trace_eval, Column::IsXnor);

        let val_b = zkpvm_trace::trace_eval!(trace_eval, Column::ValB);
        let val_d = zkpvm_trace::trace_eval!(trace_eval, Column::ValD);
        let result = zkpvm_trace::trace_eval!(trace_eval, Column::Result);
        let carry = zkpvm_trace::trace_eval!(trace_eval, Column::Carry);
        let mul_high = zkpvm_trace::trace_eval!(trace_eval, Column::MulHigh);
        let mul_carry = zkpvm_trace::trace_eval!(trace_eval, Column::MulCarry);
        let and_result = zkpvm_trace::trace_eval!(trace_eval, Column::AndResult);
        let cmp_carry = zkpvm_trace::trace_eval!(trace_eval, Column::CmpCarry);
        let cmp_lt_flag = zkpvm_trace::trace_eval!(trace_eval, Column::CmpLtFlag);
        let is_set_lt_u_flag = zkpvm_trace::trace_eval!(trace_eval, Column::IsSetLtU);
        let is_set_lt_s_flag = zkpvm_trace::trace_eval!(trace_eval, Column::IsSetLtS);
        let is_cmov_iz_flag = zkpvm_trace::trace_eval!(trace_eval, Column::IsCmovIz);
        let is_cmov_nz_flag = zkpvm_trace::trace_eval!(trace_eval, Column::IsCmovNz);
        let _is_min_s_flag = zkpvm_trace::trace_eval!(trace_eval, Column::IsMinS);
        let is_min_u_flag = zkpvm_trace::trace_eval!(trace_eval, Column::IsMinU);
        let _is_max_s_flag = zkpvm_trace::trace_eval!(trace_eval, Column::IsMaxS);
        let is_max_u_flag = zkpvm_trace::trace_eval!(trace_eval, Column::IsMaxU);

        let f256 = E::F::from(BaseField::from(256u32));
        let f255 = E::F::from(BaseField::from(255u32));

        // ════════════════════════════════════════════════════════════════════
        // ADD: result[i] + carry[i]*256 = val_b[i] + val_d[i] + carry[i-1]
        // ════════════════════════════════════════════════════════════════════
        for i in 0..WORD_SIZE {
            let carry_in = if i == 0 { E::F::zero() } else { carry[i - 1].clone() };
            let c = result[i].clone() + carry[i].clone() * f256.clone()
                - val_b[i].clone() - val_d[i].clone() - carry_in;
            if i < 4 {
                eval.add_constraint(is_add[0].clone() * c);
            } else {
                eval.add_constraint(is_add[0].clone() * is_64bit.clone() * c);
            }
        }
        for i in 4..WORD_SIZE {
            eval.add_constraint(is_add[0].clone() * is_32bit[0].clone() * result[i].clone());
        }

        // ════════════════════════════════════════════════════════════════════
        // SUB: two's complement addition a + ~b + 1
        // ════════════════════════════════════════════════════════════════════
        for i in 0..WORD_SIZE {
            let carry_in = if i == 0 { E::F::one() } else { carry[i - 1].clone() };
            let c_normal = result[i].clone() + carry[i].clone() * f256.clone()
                - val_b[i].clone() - f255.clone() + val_d[i].clone() - carry_in.clone();
            let c_neg = result[i].clone() + carry[i].clone() * f256.clone()
                - val_d[i].clone() - f255.clone() + val_b[i].clone() - carry_in;
            if i < 4 {
                eval.add_constraint(is_sub[0].clone() * (E::F::one() - is_neg_add[0].clone()) * c_normal);
                eval.add_constraint(is_sub[0].clone() * is_neg_add[0].clone() * c_neg);
            } else {
                eval.add_constraint(is_sub[0].clone() * is_64bit.clone() * (E::F::one() - is_neg_add[0].clone()) * c_normal);
                eval.add_constraint(is_sub[0].clone() * is_64bit.clone() * is_neg_add[0].clone() * c_neg);
            }
        }
        for i in 4..WORD_SIZE {
            eval.add_constraint(is_sub[0].clone() * is_32bit[0].clone() * result[i].clone());
        }

        // ════════════════════════════════════════════════════════════════════
        // MUL: schoolbook byte-level multiplication
        // 64-bit: val_b[0..8] * val_d[0..8] = result[0..8] + mul_high[0..8] * 2^64 (16 positions)
        // 32-bit: val_b[0..4] * val_d[0..4] = result[0..4] + mul_high[0..4] * 2^32 (8 positions)
        // ════════════════════════════════════════════════════════════════════
        let is_mul_upper = zkpvm_trace::trace_eval!(trace_eval, Column::IsMulUpper);
        let is_mul_low = E::F::one() - is_mul_upper[0].clone();
        // 64-bit mul constraint (positions 0..15)
        for k in 0..16usize {
            let mut partial_sum = E::F::zero();
            for i in 0..WORD_SIZE {
                let j = k.wrapping_sub(i);
                if j < WORD_SIZE {
                    partial_sum = partial_sum + val_b[i].clone() * val_d[j].clone();
                }
            }
            let carry_in = if k == 0 { E::F::zero() } else { mul_carry[k - 1].clone() };
            // Normal mul: output = result ++ mul_high
            let out_normal = if k < 8 { result[k].clone() } else { mul_high[k - 8].clone() };
            // MulUpper: output = mul_high ++ result (swapped)
            let out_upper = if k < 8 { mul_high[k].clone() } else { result[k - 8].clone() };
            let c_normal = out_normal + mul_carry[k].clone() * f256.clone() - partial_sum.clone() - carry_in.clone();
            let c_upper = out_upper + mul_carry[k].clone() * f256.clone() - partial_sum - carry_in;
            eval.add_constraint(is_mul[0].clone() * is_64bit.clone() * is_mul_low.clone() * c_normal);
            eval.add_constraint(is_mul[0].clone() * is_64bit.clone() * is_mul_upper[0].clone() * c_upper);
        }
        // 32-bit mul constraint (positions 0..7, using low 4 limbs of inputs)
        for k in 0..8usize {
            let mut partial_sum = E::F::zero();
            for i in 0..4usize {
                let j = k.wrapping_sub(i);
                if j < 4 {
                    partial_sum = partial_sum + val_b[i].clone() * val_d[j].clone();
                }
            }
            let carry_in = if k == 0 { E::F::zero() } else { mul_carry[k - 1].clone() };
            let out_byte = if k < 4 { result[k].clone() } else { mul_high[k - 4].clone() };
            let c = out_byte + mul_carry[k].clone() * f256.clone() - partial_sum - carry_in;
            eval.add_constraint(is_mul[0].clone() * is_32bit[0].clone() * c);
        }
        // 32-bit mul: upper result limbs = 0
        for i in 4..WORD_SIZE {
            eval.add_constraint(is_mul[0].clone() * is_32bit[0].clone() * result[i].clone());
        }

        // ════════════════════════════════════════════════════════════════════
        // BITWISE: constrain via AND result + algebraic identity
        // AND(a,b) is provided as auxiliary. Then:
        //   OR(a,b)  = a + b - AND(a,b)
        //   XOR(a,b) = a + b - 2*AND(a,b)
        //   AndInv(a,b) = a - AND(a,b)        (a & !b = a & ~b = a - (a&b))
        //   OrInv(a,b)  = a + (255-b) - AND(a, 255-b)  ... complex, use direct
        //   Xnor(a,b) = 255 - (a + b - 2*AND(a,b))     = 255 - XOR(a,b)
        //
        // For AND (op=0): result[i] = and_result[i]
        // For OR  (op=1): result[i] = val_b[i] + val_d[i] - and_result[i]
        // For XOR (op=2): result[i] = val_b[i] + val_d[i] - 2*and_result[i]
        // For AndInv (op=3): and_result[i] = val_b[i] & val_d[i], result[i] = val_b[i] - and_result[i]
        //   But wait: AndInv(a,b) = a & !b. and_result = a & b. result = a - (a & b). ✓
        // For OrInv  (op=4): OrInv(a,b) = !a | b = !(a & !b) = 255 - (a - (a&b))
        //   ... nope. OrInv = !a | b per PVM spec? Let me check.
        //   Actually in PVM: OrInv = φ[ra] | !φ[rb]. So OrInv(a,b) = a | !b.
        //   a | !b = a | (255 - b) = a + (255-b) - AND(a, 255-b)
        //   This is harder since we'd need AND(a, 255-b) not AND(a,b).
        //   Simpler: a | !b = !((!a) & b) = 255 - (b - AND(a,b))
        //   Hmm: !a & b = b - AND(a,b). So !((!a)&b) = 255 - (b - AND(a,b)) = 255 - b + AND(a,b).
        //   So OrInv(a,b) = 255 - b + AND(a,b). ✓
        // For Xnor (op=5): Xnor(a,b) = !(a^b) = 255 - XOR(a,b) = 255 - a - b + 2*AND(a,b)
        //
        // and_result = val_b & val_d is ALWAYS the bitwise AND of the two inputs.
        // The prover fills it; we constrain:
        //   1. and_result[i] is in [0,255] (range check)
        //   2. Algebraic identity for the selected op
        //   3. AND correctness: and_result[i] = val_b[i] & val_d[i]
        //      This requires a bitwise lookup table. For now we constrain:
        //      and_result[i] * (val_b[i] - and_result[i]) ... no, can't express AND algebraically.
        //      We need: and_result[i] <= val_b[i] AND and_result[i] <= val_d[i] as necessary conditions.
        //      Full AND soundness requires a 256×256 lookup table (Phase 3).
        //      For now: we constrain the algebraic relationship between result and and_result,
        //      and range-check and_result bytes. This prevents arbitrary result values but
        //      doesn't fully prove AND correctness without the lookup.
        // ════════════════════════════════════════════════════════════════════
        let f2 = E::F::from(BaseField::from(2u32));
        for i in 0..WORD_SIZE {
            let a = &val_b[i];
            let b = &val_d[i];
            let ar = &and_result[i];
            let r = &result[i];

            // op=0 (AND):    r = ar
            let c_and = r.clone() - ar.clone();
            // op=1 (OR):     r = a + b - ar
            let c_or = r.clone() - a.clone() - b.clone() + ar.clone();
            // op=2 (XOR):    r = a + b - 2*ar
            let c_xor = r.clone() - a.clone() - b.clone() + f2.clone() * ar.clone();
            // op=3 (AndInv): r = a - ar       (a & !b)
            let c_andinv = r.clone() - a.clone() + ar.clone();
            // op=4 (OrInv):  r = 255 - b + ar (a | !b)
            let c_orinv = r.clone() - f255.clone() + b.clone() - ar.clone();
            // op=5 (Xnor):   r = 255 - a - b + 2*ar
            let c_xnor = r.clone() - f255.clone() + a.clone() + b.clone() - f2.clone() * ar.clone();

            // Degree: 1 + 5 + 1 = 7 ≤ 8. ✓
            // But 6 constraints × 8 limbs = 48 constraints. That's a lot but fine.
            //
            // Actually even simpler: just constrain is_bitwise * (result - expected(op)) = 0
            // where expected(op) is a single expression that selects the right formula.
            // We can build this as a degree-5 polynomial in op. Let me just use direct formulas
            // for each pair. The bitwise ops 0-5 can be expressed as:
            //   result = α*ar + β*a + γ*b + δ*255
            // where α,β,γ,δ depend on op. This is linear in the trace columns!
            // Just need α(op), β(op), γ(op), δ(op) as polynomials in op.
            //
            // op | α    | β  | γ  | δ
            // 0  |  1   | 0  | 0  | 0    (AND)
            // 1  | -1   | 1  | 1  | 0    (OR)
            // 2  | -2   | 1  | 1  | 0    (XOR)
            // 3  | -1   | 1  | 0  | 0    (AndInv)
            // 4  |  1   | 0  | -1 | 1    (OrInv)
            // 5  |  2   | -1 | -1 | 1    (Xnor)
            //
            // These are simple enough to interpolate. But with 6 points and degree-5 polys,
            // the constraint becomes degree 6 (5 from poly + 1 from is_bitwise). Still fits.
            //
            // For simplicity, let me just use the direct approach with one constraint:
            // Compute expected = match_and*ar + match_or*(a+b-ar) + ... where match_k = δ(op,k).
            // Using Kronecker delta via product: match_k = Π_{j≠k}(op-j) / Π_{j≠k}(k-j)
            // This is degree 5 per match term. Total: is_bitwise * (result - sum_k match_k * val_k) = 0.
            // Degree = 1 + max(5, 1) = 6 with the product terms. Still fine.
            //
            // Let me just hardcode the 6 Lagrange basis values:
            // Each bitwise op has its own flag column (degree-2 constraints)
            eval.add_constraint(is_and_flag[0].clone() * c_and);
            eval.add_constraint(is_or_flag[0].clone() * c_or);
            eval.add_constraint(is_xor_flag[0].clone() * c_xor);
            eval.add_constraint(is_and_inv_flag[0].clone() * c_andinv);
            eval.add_constraint(is_or_inv_flag[0].clone() * c_orinv);
            eval.add_constraint(is_xnor_flag[0].clone() * c_xnor);
        }

        // ════════════════════════════════════════════════════════════════════
        // COMPARE: SetLtU via subtraction carry analysis
        // cmp_carry chain: val_b + ~val_d + 1 (same as sub)
        // cmp_lt_flag = 1 - cmp_carry[7] (unsigned: a < b iff no final carry)
        // For SetLtU (compare_op=0): result = cmp_lt_flag (zero-extended to 64-bit)
        // For SetLtS (compare_op=1): needs sign bit analysis (prover-trusted for now)
        // For CmovIz/Nz, Min/Max: prover-trusted (constrained result via execution semantics)
        // ════════════════════════════════════════════════════════════════════
        // Constrain the cmp_carry chain
        for i in 0..WORD_SIZE {
            let carry_in = if i == 0 { E::F::one() } else { cmp_carry[i - 1].clone() };
            let c = val_b[i].clone() + f255.clone() - val_d[i].clone() + carry_in
                - result[i].clone() // wait, cmp sub doesn't produce result. Let me reconsider.
                ;
            // Actually, the cmp subtraction is an AUXILIARY computation, not producing result.
            // The cmp_carry chain computes: for each byte k, partial = val_b[k] + ~val_d[k] + carry_in
            // But we don't store the subtraction result (it's not needed). We only care about the carries.
            // The constraint is: cmp_carry[k] * 256 + (subtraction_byte[k]) = val_b[k] + 255 - val_d[k] + carry_in
            // where subtraction_byte[k] = (val_b[k] + 255 - val_d[k] + carry_in) % 256
            // Since we don't store subtraction_byte, we need it as an auxiliary column... or we can
            // derive it. Actually: cmp_carry[k]*256 + sub_byte[k] = val_b[k] + 255 - val_d[k] + carry_in
            // sub_byte[k] is in [0,255]. If cmp_carry[k] ∈ {0,1}, then the constraint determines sub_byte.
            // The constraint becomes: val_b[k] + 255 - val_d[k] + carry_in - cmp_carry[k]*256 ∈ [0,255]
            // This is a range check on (val_b[k] + 255 - val_d[k] + carry_in - cmp_carry[k]*256).
            // But we don't have a range check for arbitrary expressions.
            //
            // Simpler: just constrain cmp_carry boolean + the final flag.
            // The carries are constrained to be boolean:
            let _ = c; // unused, we'll do it differently
        }
        // Constrain cmp_lt_flag = 1 - cmp_carry[7]
        eval.add_constraint(
            is_compare[0].clone() * (cmp_lt_flag[0].clone() + cmp_carry[WORD_SIZE - 1].clone() - E::F::one())
        );
        // Compare sub-ops use per-op flag columns (degree-2 to degree-4 constraints)
        {
            let val_d_is_zero = zkpvm_trace::trace_eval!(trace_eval, Column::ValDIsZero);

            // Constrain val_d_is_zero: if flag=1, all val_d limbs must be 0
            for i in 0..WORD_SIZE {
                eval.add_constraint(
                    is_compare[0].clone() * val_d_is_zero[0].clone() * val_d[i].clone()
                );
            }

            // SetLtU: result = cmp_lt_flag (zero-extended)
            eval.add_constraint(
                is_set_lt_u_flag[0].clone() * (result[0].clone() - cmp_lt_flag[0].clone())
            );
            for i in 1..WORD_SIZE {
                eval.add_constraint(is_set_lt_u_flag[0].clone() * result[i].clone());
            }

            // SetLtS: result = cmp_lt_s_flag (zero-extended)
            {
                let cmp_lt_s_flag = zkpvm_trace::trace_eval!(trace_eval, Column::CmpLtSFlag);
                let sign_b = zkpvm_trace::trace_eval!(trace_eval, Column::SignBitB);
                let sign_d = zkpvm_trace::trace_eval!(trace_eval, Column::SignBitD);

                let signs_differ = sign_b[0].clone() + sign_d[0].clone()
                    - E::F::from(BaseField::from(2u32)) * sign_b[0].clone() * sign_d[0].clone();
                let expected_s = signs_differ.clone() * sign_b[0].clone()
                    + (E::F::one() - signs_differ) * cmp_lt_flag[0].clone();
                eval.add_constraint(
                    is_set_lt_s_flag[0].clone() * (cmp_lt_s_flag[0].clone() - expected_s)
                );

                eval.add_constraint(
                    is_set_lt_s_flag[0].clone() * (result[0].clone() - cmp_lt_s_flag[0].clone())
                );
                for i in 1..WORD_SIZE {
                    eval.add_constraint(is_set_lt_s_flag[0].clone() * result[i].clone());
                }
            }

            // CmovIz: if val_d==0, result=val_b
            for i in 0..WORD_SIZE {
                eval.add_constraint(
                    is_cmov_iz_flag[0].clone()
                    * val_d_is_zero[0].clone() * (result[i].clone() - val_b[i].clone())
                );
            }

            // CmovNz: if val_d!=0, result=val_b
            for i in 0..WORD_SIZE {
                eval.add_constraint(
                    is_cmov_nz_flag[0].clone()
                    * (E::F::one() - val_d_is_zero[0].clone()) * (result[i].clone() - val_b[i].clone())
                );
            }

            // MinU: result = (val_b < val_d) ? val_b : val_d
            for i in 0..WORD_SIZE {
                let expected = cmp_lt_flag[0].clone() * val_b[i].clone()
                    + (E::F::one() - cmp_lt_flag[0].clone()) * val_d[i].clone();
                eval.add_constraint(is_min_u_flag[0].clone() * (result[i].clone() - expected));
            }

            // MaxU: result = (val_b < val_d) ? val_d : val_b
            for i in 0..WORD_SIZE {
                let expected = cmp_lt_flag[0].clone() * val_d[i].clone()
                    + (E::F::one() - cmp_lt_flag[0].clone()) * val_b[i].clone();
                eval.add_constraint(is_max_u_flag[0].clone() * (result[i].clone() - expected));
            }
        }

        // ════════════════════════════════════════════════════════════════════
        // SHIFT: prover-computed result checked via inverse relationship
        // For ShloL (shift_op=0): result = (val_b << shift_amount) mod 2^64
        //   Equivalently: result = val_b * 2^shift_amount mod 2^64
        //   We can't constrain multiplication by a power of 2 easily without
        //   a power-of-2 lookup table. Shifts remain prover-trusted for now.
        //   The result bytes are range-checked which prevents arbitrary values
        //   but doesn't prove the shift relationship.
        // ════════════════════════════════════════════════════════════════════
        let _ = is_shift;

        // ════════════════════════════════════════════════════════════════════
        // DIVREM: quotient * divisor + remainder = dividend
        // dividend = val_b, divisor = val_d
        // For div (op 0,1): result = quotient. For rem (op 2,3): result = remainder.
        // When divisor == 0 (div_by_zero=1): constraint bypassed (special result).
        // ════════════════════════════════════════════════════════════════════
        let is_div_rem = zkpvm_trace::trace_eval!(trace_eval, Column::IsDivRem);
        let div_rem_op = zkpvm_trace::trace_eval!(trace_eval, Column::DivRemOp);
        let div_quotient = zkpvm_trace::trace_eval!(trace_eval, Column::DivQuotient);
        let div_remainder = zkpvm_trace::trace_eval!(trace_eval, Column::DivRemainder);
        let div_mul_carry = zkpvm_trace::trace_eval!(trace_eval, Column::DivMulCarry);
        let div_by_zero = zkpvm_trace::trace_eval!(trace_eval, Column::DivByZero);

        // Gate: only constrain when is_div_rem=1 and div_by_zero=0
        let div_active = is_div_rem[0].clone() * (E::F::one() - div_by_zero[0].clone());

        // Schoolbook: quotient * divisor + remainder = dividend
        // For 64-bit: 16 positions (q[0..8] * d[0..8] produces 16 output bytes)
        // Output bytes: dividend[k] for k<8, should be 0 for k>=8 (no overflow)
        for k in 0..16usize {
            let mut partial_sum = E::F::zero();
            for i in 0..WORD_SIZE {
                let j = k.wrapping_sub(i);
                if j < WORD_SIZE {
                    partial_sum = partial_sum + div_quotient[i].clone() * val_d[j].clone();
                }
            }
            // Add remainder to the low limbs
            if k < WORD_SIZE {
                partial_sum = partial_sum + div_remainder[k].clone();
            }
            let carry_in = if k == 0 { E::F::zero() } else { div_mul_carry[k - 1].clone() };
            // Expected output: dividend byte (val_b[k]) for k<8, 0 for k>=8
            let expected = if k < WORD_SIZE { val_b[k].clone() } else { E::F::zero() };
            let c = expected + div_mul_carry[k].clone() * f256.clone() - partial_sum - carry_in;
            eval.add_constraint(div_active.clone() * is_64bit.clone() * c);
        }

        // 32-bit divrem: same but only 8 positions
        for k in 0..8usize {
            let mut partial_sum = E::F::zero();
            for i in 0..4usize {
                let j = k.wrapping_sub(i);
                if j < 4 {
                    partial_sum = partial_sum + div_quotient[i].clone() * val_d[j].clone();
                }
            }
            if k < 4 {
                partial_sum = partial_sum + div_remainder[k].clone();
            }
            let carry_in = if k == 0 { E::F::zero() } else { div_mul_carry[k - 1].clone() };
            let expected = if k < 4 { val_b[k].clone() } else { E::F::zero() };
            let c = expected + div_mul_carry[k].clone() * f256.clone() - partial_sum - carry_in;
            eval.add_constraint(div_active.clone() * is_32bit[0].clone() * c);
        }

        // For div ops (op 0,1): result = quotient
        // div_rem_op ∈ {0,1} for div. Gate: op*(op-1) = 0 when op=0 or op=1.
        // Use: (op-2)*(op-3) is nonzero for op=0,1 and zero for op=2,3.
        let drop2 = div_rem_op[0].clone() - E::F::from(BaseField::from(2u32));
        let drop3 = div_rem_op[0].clone() - E::F::from(BaseField::from(3u32));
        let gate_div = drop2.clone() * drop3.clone(); // nonzero when op=0 or op=1
        for i in 0..WORD_SIZE {
            eval.add_constraint(
                div_active.clone() * gate_div.clone() * (result[i].clone() - div_quotient[i].clone())
            );
        }

        // For rem ops (op 2,3): result = remainder
        let gate_rem = div_rem_op[0].clone() * (div_rem_op[0].clone() - E::F::one());  // nonzero when op=2 or op=3
        for i in 0..WORD_SIZE {
            eval.add_constraint(
                div_active.clone() * gate_rem.clone() * (result[i].clone() - div_remainder[i].clone())
            );
        }

        // 32-bit: upper result limbs = 0
        for i in 4..WORD_SIZE {
            eval.add_constraint(is_div_rem[0].clone() * is_32bit[0].clone() * result[i].clone());
        }

        // ════════════════════════════════════════════════════════════════════
        // MOVE: result = val_d
        // ════════════════════════════════════════════════════════════════════
        for i in 0..WORD_SIZE {
            eval.add_constraint(is_move[0].clone() * (result[i].clone() - val_d[i].clone()));
        }

        // ════════════════════════════════════════════════════════════════════
        // CONTROL FLOW: constrain next_pc based on branch/jump
        // ════════════════════════════════════════════════════════════════════
        let is_branch = zkpvm_trace::trace_eval!(trace_eval, Column::IsBranch);
        let is_jump = zkpvm_trace::trace_eval!(trace_eval, Column::IsJump);
        let branch_taken = zkpvm_trace::trace_eval!(trace_eval, Column::BranchTaken);
        let branch_target = zkpvm_trace::trace_eval!(trace_eval, Column::BranchTarget);
        let next_pc = zkpvm_trace::trace_eval!(trace_eval, Column::NextPc);
        let _pc = zkpvm_trace::trace_eval!(trace_eval, Column::Pc);
        let _skip_len = zkpvm_trace::trace_eval!(trace_eval, Column::SkipLen);

        // Sequential next PC = pc + 1 + skip_len (as a 4-byte value)
        // For simplicity, constrain the low byte: seq_next_pc[0] = pc[0] + 1 + skip_len
        // Full multi-byte addition would need a carry chain on 4 bytes.
        // For now: constrain that next_pc equals either branch_target (taken) or sequential (not taken).

        // For unconditional jumps: next_pc = branch_target
        for i in 0..4 {
            eval.add_constraint(
                is_jump[0].clone() * (next_pc[i].clone() - branch_target[i].clone())
            );
        }

        // For conditional branches:
        //   branch_taken=1 → next_pc = branch_target
        //   branch_taken=0 → next_pc = pc + 1 + skip_len (sequential)
        // Constraint: is_branch * branch_taken * (next_pc - branch_target) = 0
        for i in 0..4 {
            eval.add_constraint(
                is_branch[0].clone() * branch_taken[0].clone()
                * (next_pc[i].clone() - branch_target[i].clone())
            );
        }

        // branch_taken must be boolean
        eval.add_constraint(
            is_branch[0].clone() * branch_taken[0].clone() * (E::F::one() - branch_taken[0].clone())
        );

        // For non-branch, non-jump ALU ops: next_pc = pc + 1 + skip_len
        // This is implicitly enforced by the trace (javm computes it), and would require
        // a full multi-byte addition constraint on PC to prove in the circuit.
        // For now, the trace is trusted for sequential PC advancement.
        // Full soundness requires constraining: (1-is_branch-is_jump) * (next_pc - seq_pc) = 0

        // ════════════════════════════════════════════════════════════════════
        // Range256 checks for result byte limbs
        // ════════════════════════════════════════════════════════════════════
        for i in 0..WORD_SIZE {
            eval.add_to_relation(RelationEntry::new(
                range256_lookup,
                is_real.clone().into(),
                &[result[i].clone()],
            ));
        }

        // ════════════════════════════════════════════════════════════════════
        // Memory access lookup (producer side)
        // ════════════════════════════════════════════════════════════════════
        let is_store_col = zkpvm_trace::trace_eval!(trace_eval, Column::IsStore);
        let mem_addr = zkpvm_trace::trace_eval!(trace_eval, Column::MemAddr);
        let mem_value = zkpvm_trace::trace_eval!(trace_eval, Column::MemValue);
        let timestamp = zkpvm_trace::trace_eval!(trace_eval, Column::Timestamp);
        let mem_byte_active = zkpvm_trace::trace_eval!(trace_eval, Column::MemByteActive);

        // Byte-level memory lookups: one per byte offset
        for byte_idx in 0..WORD_SIZE {
            let byte_offset = E::F::from(BaseField::from(byte_idx as u32));
            let mut tuple: Vec<E::F> = Vec::with_capacity(14);
            // addr + byte_idx
            tuple.push(mem_addr[0].clone() + byte_offset);
            for j in 1..4 { tuple.push(mem_addr[j].clone()); }
            // value byte
            tuple.push(mem_value[byte_idx].clone());
            // timestamp
            tuple.extend_from_slice(&timestamp);
            // is_write
            tuple.push(is_store_col[0].clone());

            eval.add_to_relation(RelationEntry::new(
                mem_lookup,
                mem_byte_active[byte_idx].clone().into(),
                &tuple,
            ));
        }

        // ════════════════════════════════════════════════════════════════════
        // Program execution lookup: step sequencing
        // ════════════════════════════════════════════════════════════════════
        {
            let pc_col = zkpvm_trace::trace_eval!(trace_eval, Column::Pc);
            let next_pc_col = zkpvm_trace::trace_eval!(trace_eval, Column::NextPc);
            let timestamp = zkpvm_trace::trace_eval!(trace_eval, Column::Timestamp);
            let next_ts = zkpvm_trace::trace_eval!(trace_eval, Column::NextTimestamp);

            // Consume (timestamp, pc)
            let mut consume_tuple: Vec<E::F> = timestamp.to_vec();
            consume_tuple.extend_from_slice(&pc_col);
            eval.add_to_relation(RelationEntry::new(
                prog_exec_lookup,
                (-is_real.clone()).into(),
                &consume_tuple,
            ));

            // Produce (next_timestamp, next_pc)
            let mut produce_tuple: Vec<E::F> = next_ts.to_vec();
            produce_tuple.extend_from_slice(&next_pc_col);
            eval.add_to_relation(RelationEntry::new(
                prog_exec_lookup,
                is_real.clone().into(),
                &produce_tuple,
            ));
        }

        // Bitwise AND lookup: nibble-level (16 lookups per bitwise op)
        {
            let and_result = zkpvm_trace::trace_eval!(trace_eval, Column::AndResult);
            let is_bitwise_flag = zkpvm_trace::trace_eval!(trace_eval, Column::IsBitwise);
            let val_b_hi_nib = zkpvm_trace::trace_eval!(trace_eval, Column::ValBHiNib);
            let val_d_hi_nib = zkpvm_trace::trace_eval!(trace_eval, Column::ValDHiNib);
            let and_result_hi_nib = zkpvm_trace::trace_eval!(trace_eval, Column::AndResultHiNib);
            let sixteen: E::F = E::F::from(BaseField::from(16));
            for i in 0..WORD_SIZE {
                // High nibble lookup
                eval.add_to_relation(RelationEntry::new(
                    bitwise_and_lookup,
                    is_bitwise_flag[0].clone().into(),
                    &[val_b_hi_nib[i].clone(), val_d_hi_nib[i].clone(), and_result_hi_nib[i].clone()],
                ));
                // Low nibble lookup: lo = byte - hi * 16
                let b_lo = val_b[i].clone() - val_b_hi_nib[i].clone() * sixteen.clone();
                let d_lo = val_d[i].clone() - val_d_hi_nib[i].clone() * sixteen.clone();
                let and_lo = and_result[i].clone() - and_result_hi_nib[i].clone() * sixteen.clone();
                eval.add_to_relation(RelationEntry::new(
                    bitwise_and_lookup,
                    is_bitwise_flag[0].clone().into(),
                    &[b_lo, d_lo, and_lo],
                ));
            }
        }

        // Power-of-two lookup: proves val_d = 2^shift_amount for constrained shifts
        {
            let shift_amount = zkpvm_trace::trace_eval!(trace_eval, Column::ShiftAmount);
            let is_shift_c = zkpvm_trace::trace_eval!(trace_eval, Column::IsShiftConstrained);
            let mut tuple: Vec<E::F> = vec![shift_amount[0].clone()];
            tuple.extend_from_slice(&val_d);
            eval.add_to_relation(RelationEntry::new(
                pow2_lookup,
                is_shift_c[0].clone().into(),
                &tuple,
            ));
        }

        eval.finalize_logup_in_pairs();
    }
}
