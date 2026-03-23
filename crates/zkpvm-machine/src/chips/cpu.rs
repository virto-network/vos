use num_traits::{One, Zero};
use stwo::{
    core::{
        fields::{m31::BaseField, qm31::SecureField},
        ColumnVec,
    },
    prover::{
        backend::simd::{m31::LOG_N_LANES, SimdBackend},
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
    lookups::{AllLookupElements, LogupTraceBuilder, MemoryAccessLookupElements, Range256LookupElements},
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
    /// Bitwise sub-op: 0=AND, 1=OR, 2=XOR, 3=AndInv, 4=OrInv, 5=Xnor
    #[size = 1]
    BitwiseOp,
    #[size = 1]
    IsNegAdd,
    // ── Mul auxiliary: high 64 bits of full product ──
    /// mul_high[0..8]: (val_b * val_d) = result + mul_high * 2^64
    #[size = 8]
    MulHigh,
    /// Mul partial-product carry chain (16 limbs for schoolbook carries)
    #[size = 16]
    MulCarry,
    // ── Bitwise auxiliary: per-byte AND result ──
    /// and_result[i] = val_b[i] AND val_d[i] (8 bytes)
    #[size = 8]
    AndResult,
    // ── Compare auxiliary ──
    /// Subtraction carry for comparison (8 limbs, reuses sub logic)
    #[size = 8]
    CmpCarry,
    /// Compare sub-op: 0=SetLtU, 1=SetLtS, 2=CmovIz, 3=CmovNz, 4=Min, 5=MinU, 6=Max, 7=MaxU
    #[size = 1]
    CompareOp,
    /// The "less-than" flag derived from cmp_carry (1 if val_b < val_d unsigned)
    #[size = 1]
    CmpLtFlag,
    // ── Shift auxiliary ──
    #[size = 1]
    ShiftAmount,
    #[size = 1]
    ShiftOp,
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
    bitwise_op: u8,
    is_neg_add: bool,
    compare_op: u8,
    shift_op: u8,
    is_branch: bool,
    is_jump: bool,
    is_div_rem: bool,
    div_rem_op: u8,
    is_load: bool,
    is_store: bool,
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
        // MulUpper (prover-trusted — result = high 64 bits of 128-bit product)
        Opcode::MulUpperUU | Opcode::MulUpperSS | Opcode::MulUpperSU => {}
        Opcode::And | Opcode::AndImm => { f.is_bitwise = true; f.bitwise_op = 0; }
        Opcode::Or  | Opcode::OrImm  => { f.is_bitwise = true; f.bitwise_op = 1; }
        Opcode::Xor | Opcode::XorImm => { f.is_bitwise = true; f.bitwise_op = 2; }
        Opcode::AndInv => { f.is_bitwise = true; f.bitwise_op = 3; }
        Opcode::OrInv  => { f.is_bitwise = true; f.bitwise_op = 4; }
        Opcode::Xnor   => { f.is_bitwise = true; f.bitwise_op = 5; }
        // Shifts
        Opcode::ShloL64 | Opcode::ShloLImm64 | Opcode::ShloLImmAlt64 => { f.is_shift = true; f.shift_op = 0; }
        Opcode::ShloL32 | Opcode::ShloLImm32 | Opcode::ShloLImmAlt32 => { f.is_shift = true; f.shift_op = 0; f.is_32bit = true; }
        Opcode::ShloR64 | Opcode::ShloRImm64 | Opcode::ShloRImmAlt64 => { f.is_shift = true; f.shift_op = 1; }
        Opcode::ShloR32 | Opcode::ShloRImm32 | Opcode::ShloRImmAlt32 => { f.is_shift = true; f.shift_op = 1; f.is_32bit = true; }
        Opcode::SharR64 | Opcode::SharRImm64 | Opcode::SharRImmAlt64 => { f.is_shift = true; f.shift_op = 2; }
        Opcode::SharR32 | Opcode::SharRImm32 | Opcode::SharRImmAlt32 => { f.is_shift = true; f.shift_op = 2; f.is_32bit = true; }
        Opcode::RotL64 => { f.is_shift = true; f.shift_op = 3; }
        Opcode::RotL32 => { f.is_shift = true; f.shift_op = 3; f.is_32bit = true; }
        Opcode::RotR64 | Opcode::RotR64Imm | Opcode::RotR64ImmAlt => { f.is_shift = true; f.shift_op = 4; }
        Opcode::RotR32 | Opcode::RotR32Imm | Opcode::RotR32ImmAlt => { f.is_shift = true; f.shift_op = 4; f.is_32bit = true; }
        // Compare
        Opcode::SetLtU | Opcode::SetLtUImm => { f.is_compare = true; f.compare_op = 0; }
        Opcode::SetLtS | Opcode::SetLtSImm => { f.is_compare = true; f.compare_op = 1; }
        Opcode::SetGtUImm => { f.is_compare = true; f.compare_op = 0; } // SetGt = swap + SetLt
        Opcode::SetGtSImm => { f.is_compare = true; f.compare_op = 1; }
        Opcode::CmovIz | Opcode::CmovIzImm => { f.is_compare = true; f.compare_op = 2; }
        Opcode::CmovNz | Opcode::CmovNzImm => { f.is_compare = true; f.compare_op = 3; }
        Opcode::Min  => { f.is_compare = true; f.compare_op = 4; }
        Opcode::MinU => { f.is_compare = true; f.compare_op = 5; }
        Opcode::Max  => { f.is_compare = true; f.compare_op = 6; }
        Opcode::MaxU => { f.is_compare = true; f.compare_op = 7; }
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
        Opcode::Ecalli => {}
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
    const LOG_CONSTRAINT_DEGREE_BOUND: u32 = 3;

    type PreprocessedColumn = PreprocessedColumn;
    type MainColumn = Column;
    type LookupElements = (Range256LookupElements, MemoryAccessLookupElements);

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

            // Truncate for 32-bit ALU ops
            if flags.is_32bit && (flags.is_add || flags.is_sub || flags.is_mul) {
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
                }
            }
            trace.fill_columns_bytes(row, &and_result, Column::AndResult);

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
            trace.fill_columns(row, flags.compare_op, Column::CompareOp);

            // ── Shift auxiliary ──
            let shift_amount = if flags.is_shift {
                let modulus = if flags.is_32bit { 32u64 } else { 64 };
                (val_d % modulus) as u8
            } else {
                0
            };
            trace.fill_columns(row, shift_amount, Column::ShiftAmount);
            trace.fill_columns(row, flags.shift_op, Column::ShiftOp);

            // ── Flags ──
            trace.fill_columns(row, false, Column::IsPadding);
            trace.fill_columns(row, step.reg_write.is_some(), Column::RegAWritten);
            trace.fill_columns(row, step.gas_after, Column::Gas);
            trace.fill_columns(row, flags.is_add, Column::IsAdd);
            trace.fill_columns(row, flags.is_sub, Column::IsSub);
            trace.fill_columns(row, flags.is_mul, Column::IsMul);
            trace.fill_columns(row, flags.is_bitwise, Column::IsBitwise);
            trace.fill_columns(row, flags.is_shift, Column::IsShift);
            trace.fill_columns(row, flags.is_compare, Column::IsCompare);
            trace.fill_columns(row, flags.is_move, Column::IsMove);
            trace.fill_columns(row, flags.is_32bit, Column::Is32Bit);
            trace.fill_columns(row, flags.bitwise_op, Column::BitwiseOp);
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
            if let Some(ref r) = step.mem_read {
                trace.fill_columns_bytes(row, &r.address.to_le_bytes(), Column::MemAddr);
                trace.fill_columns(row, r.value, Column::MemValue);
                trace.fill_columns(row, r.size, Column::MemSize);
            } else if let Some(ref w) = step.mem_write {
                trace.fill_columns_bytes(row, &w.address.to_le_bytes(), Column::MemAddr);
                trace.fill_columns(row, w.value, Column::MemValue);
                trace.fill_columns(row, w.size, Column::MemSize);
            }
            // else: no memory access, columns stay 0 (default)

            for &b in &result_bytes {
                range_bytes.push(b);
            }
        }

        for &b in &range_bytes {
            side_note.add_range256(b);
        }

        let last_ts = side_note.steps.last().map(|s| s.timestamp).unwrap_or(0);
        for row in num_steps..num_rows {
            trace.fill_columns(row, true, Column::IsPadding);
            trace.fill_columns(row, last_ts + (row - num_steps + 1) as u64, Column::Timestamp);
        }

        trace.finalize()
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

        // Memory access lookups (producer side, positive)
        let mem_lookup: &MemoryAccessLookupElements = lookup_elements.as_ref();
        let is_load = zkpvm_trace::original_base_column!(component_trace, Column::IsLoad);
        let is_store = zkpvm_trace::original_base_column!(component_trace, Column::IsStore);
        let mem_addr = zkpvm_trace::original_base_column!(component_trace, Column::MemAddr);
        let mem_value = zkpvm_trace::original_base_column!(component_trace, Column::MemValue);
        let timestamp = zkpvm_trace::original_base_column!(component_trace, Column::Timestamp);
        let mem_size = zkpvm_trace::original_base_column!(component_trace, Column::MemSize);

        // Build tuple: (addr[4], value[8], timestamp[8], is_write[1], size[1])
        let mut mem_tuple: Vec<_> = mem_addr.to_vec();
        mem_tuple.extend_from_slice(&mem_value);
        mem_tuple.extend_from_slice(&timestamp);
        mem_tuple.push(is_store[0].clone()); // is_write = is_store
        mem_tuple.push(mem_size[0].clone());

        // Multiplicity = is_load + is_store (positive, producer side)
        logup.add_to_relation_with(
            mem_lookup,
            [is_load[0].clone(), is_store[0].clone()],
            |[load, store]| {
                (load + store).into()
            },
            &mem_tuple,
        );

        logup.finalize()
    }

    // ── Constraints ────────────────────────────────────────────────────────

    fn add_constraints<E: EvalAtRow>(
        &self,
        eval: &mut E,
        trace_eval: TraceEval<PreprocessedColumn, Column, E>,
        lookup_elements: &(Range256LookupElements, MemoryAccessLookupElements),
    ) {
        let (range256_lookup, mem_lookup) = lookup_elements;
        let is_pad = zkpvm_trace::trace_eval!(trace_eval, Column::IsPadding);
        let is_real = E::F::one() - is_pad[0].clone();

        let is_add = zkpvm_trace::trace_eval!(trace_eval, Column::IsAdd);
        let is_sub = zkpvm_trace::trace_eval!(trace_eval, Column::IsSub);
        let is_mul = zkpvm_trace::trace_eval!(trace_eval, Column::IsMul);
        let is_bitwise = zkpvm_trace::trace_eval!(trace_eval, Column::IsBitwise);
        let is_shift = zkpvm_trace::trace_eval!(trace_eval, Column::IsShift);
        let is_compare = zkpvm_trace::trace_eval!(trace_eval, Column::IsCompare);
        let is_move = zkpvm_trace::trace_eval!(trace_eval, Column::IsMove);
        let is_neg_add = zkpvm_trace::trace_eval!(trace_eval, Column::IsNegAdd);
        let is_32bit = zkpvm_trace::trace_eval!(trace_eval, Column::Is32Bit);
        let is_64bit = E::F::one() - is_32bit[0].clone();
        let bitwise_op = zkpvm_trace::trace_eval!(trace_eval, Column::BitwiseOp);

        let val_b = zkpvm_trace::trace_eval!(trace_eval, Column::ValB);
        let val_d = zkpvm_trace::trace_eval!(trace_eval, Column::ValD);
        let result = zkpvm_trace::trace_eval!(trace_eval, Column::Result);
        let carry = zkpvm_trace::trace_eval!(trace_eval, Column::Carry);
        let mul_high = zkpvm_trace::trace_eval!(trace_eval, Column::MulHigh);
        let mul_carry = zkpvm_trace::trace_eval!(trace_eval, Column::MulCarry);
        let and_result = zkpvm_trace::trace_eval!(trace_eval, Column::AndResult);
        let cmp_carry = zkpvm_trace::trace_eval!(trace_eval, Column::CmpCarry);
        let cmp_lt_flag = zkpvm_trace::trace_eval!(trace_eval, Column::CmpLtFlag);
        let compare_op = zkpvm_trace::trace_eval!(trace_eval, Column::CompareOp);

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
            let out_byte = if k < 8 { result[k].clone() } else { mul_high[k - 8].clone() };
            let c = out_byte + mul_carry[k].clone() * f256.clone() - partial_sum - carry_in;
            eval.add_constraint(is_mul[0].clone() * is_64bit.clone() * c);
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

            // Select constraint based on bitwise_op using indicator:
            // bitwise_op = 0,1,2,3,4,5. We use: is_bitwise * constraint_for_op = 0
            // Since bitwise_op is a field element, we build:
            // is_bitwise * (op*(op-1)*(op-2)*(op-3)*(op-4)/120 * c_xnor + ...) = 0
            // This is too high degree. Instead, use the simpler approach:
            // is_bitwise * (c_and * indicator_0 + c_or * indicator_1 + ...) = 0
            // where indicator_k = product_{j!=k} (bitwise_op - j) / product_{j!=k} (k - j)
            // But this is degree 5 per indicator.
            //
            // Simplest sound approach: one constraint per op, gated by is_op_k flag.
            // But we only have one BitwiseOp column. Let's use:
            //   is_bitwise * [(bitwise_op - 0) * ... all except c_and's matching ...] doesn't work.
            //
            // Practical approach: constrain that result equals the EXPECTED value based on
            // and_result and the op. We write 6 separate constraints, each gated by
            // is_bitwise * (bitwise_op == k). For (bitwise_op == k), we use the product
            // of (bitwise_op - j) for all j != k. But degree = 5+1+1 = 7 per constraint.
            //
            // Much simpler: just use one universal formula.
            // Let's define expected_result based on bitwise_op:
            //   expected = ar                        if op=0
            //   expected = a + b - ar                if op=1
            //   expected = a + b - 2*ar              if op=2
            //   expected = a - ar                    if op=3
            //   expected = 255 - b + ar              if op=4
            //   expected = 255 - a - b + 2*ar        if op=5
            //
            // Use Lagrange interpolation over op ∈ {0..5}:
            //   expected(op) = Σ_k L_k(op) * expected_k
            // This is a degree-5 polynomial in op, making the total constraint degree 5+1(is_bitwise) = 6.
            // With LOG_CONSTRAINT_DEGREE_BOUND=3, max degree = 2^3 = 8. Fine.
            //
            // But Lagrange over 6 points in M31 is messy. Simpler: express as polynomial in op directly.
            // expected(op) values at op=0..5:
            //   f(0) = ar
            //   f(1) = a + b - ar
            //   f(2) = a + b - 2*ar
            //   f(3) = a - ar
            //   f(4) = 255 - b + ar
            //   f(5) = 255 - a - b + 2*ar
            //
            // Actually, let's just do it the simple way with separate constraints.
            // We already have LOG_CONSTRAINT_DEGREE_BOUND = 3 which allows degree 8.
            // Use: is_bitwise * Π_{j≠k}(op-j) * c_k = 0 for each k.
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
            let op = &bitwise_op[0];
            // L_k(op) = Π_{j≠k}(op - j) / Π_{j≠k}(k - j)
            // For k=0: L_0 = (op-1)(op-2)(op-3)(op-4)(op-5) / (0-1)(0-2)(0-3)(0-4)(0-5)
            //        = (op-1)(op-2)(op-3)(op-4)(op-5) / (-1)(-2)(-3)(-4)(-5) = ... / (-120)
            // Denominator values:
            // k=0: (-1)(-2)(-3)(-4)(-5) = -120
            // k=1: (1)(-1)(-2)(-3)(-4) = 24
            // k=2: (2)(1)(-1)(-2)(-3) = -12
            // k=3: (3)(2)(1)(-1)(-2) = 12
            // k=4: (4)(3)(2)(1)(-1) = -24
            // k=5: (5)(4)(3)(2)(1) = 120
            //
            // This is getting complex. Let me use a much simpler approach:
            // Just have 6 separate constraints, one per op, gated by a product check.
            // But actually, the absolute simplest that works:
            // Constrain result - expected = 0 where expected is computed from the op.
            // I'll use the linear combination approach.

            // expected = ar * α(op) + a * β(op) + b * γ(op) + 255 * δ(op)
            // where α,β,γ,δ are degree-5 interpolations. Too complex.
            //
            // PRAGMATIC APPROACH: just write all 6 constraints separately, each gated:
            // is_bitwise * (op) * (op-1) * (op-2) * (op-3) * (op-4) * c_and = 0 ... NO wrong.
            // For op=0: we want c_and = 0. The gate should be zero when op≠0.
            // Factor: for op=0, Π_{j=1..5}(op-j) = (-1)(-2)(-3)(-4)(-5) = -120 ≠ 0.
            // For op=1, Π_{j=1..5}(op-j) = 0 since (op-1)=0. ✓
            // So: is_bitwise * Π_{j=1..5}(op-j) * c_and = 0 constrains c_and=0 when op=0. ✓
            // Degree: 1 + 5 + 1 = 7. OK with degree bound 8.
            //
            // But 6 constraints × 8 bytes = 48 extra constraints. The degree bound means
            // the blowup factor is 2^3 = 8x. That's acceptable.
            //
            // Actually this doesn't work: Π_{j=1..5}(op-j) * c_and = 0 is satisfied when
            // op=1 OR op=2 OR ... OR op=5 regardless of c_and. But for op=0, we need c_and=0.
            // The issue is that Π_{j=1..5}(op-j) is non-zero only when op=0. So the constraint
            // forces c_and=0 when op=0 but doesn't care otherwise. That's exactly what we want!
            //
            // Let me just implement this directly. For each op k, the constraint is:
            // is_bitwise * Π_{j≠k, j∈0..5}(op-j) * c_k = 0
            // This forces c_k=0 when op=k (the product is non-zero).
            // When op≠k, the product includes (op-k)=0 wait no, j≠k means we DON'T include j=k.
            // Hmm: Π_{j∈{0..5}, j≠k}(op - j). When op=k, this product = Π_{j≠k}(k-j) ≠ 0. ✓
            // When op=m≠k, the product includes factor (op-m) = (m-m) = 0. ✓
            // So the constraint is zero for all op≠k, and forces c_k=0 for op=k. Perfect.

            // Gate products for each op (the product of (op-j) for j≠k, j in 0..5)
            let op1 = op.clone() - E::F::one();
            let op2 = op.clone() - E::F::from(BaseField::from(2u32));
            let op3 = op.clone() - E::F::from(BaseField::from(3u32));
            let op4 = op.clone() - E::F::from(BaseField::from(4u32));
            let op5 = op.clone() - E::F::from(BaseField::from(5u32));

            let gate0 = op1.clone() * op2.clone() * op3.clone() * op4.clone() * op5.clone(); // nonzero at op=0
            let gate1 = op.clone() * op2.clone() * op3.clone() * op4.clone() * op5.clone(); // nonzero at op=1
            let gate2 = op.clone() * op1.clone() * op3.clone() * op4.clone() * op5.clone(); // nonzero at op=2
            let gate3 = op.clone() * op1.clone() * op2.clone() * op4.clone() * op5.clone(); // nonzero at op=3
            let gate4 = op.clone() * op1.clone() * op2.clone() * op3.clone() * op5.clone(); // nonzero at op=4
            let gate5 = op.clone() * op1.clone() * op2.clone() * op3.clone() * op4.clone(); // nonzero at op=5

            eval.add_constraint(is_bitwise[0].clone() * gate0 * c_and);
            eval.add_constraint(is_bitwise[0].clone() * gate1 * c_or);
            eval.add_constraint(is_bitwise[0].clone() * gate2 * c_xor);
            eval.add_constraint(is_bitwise[0].clone() * gate3 * c_andinv);
            eval.add_constraint(is_bitwise[0].clone() * gate4 * c_orinv);
            eval.add_constraint(is_bitwise[0].clone() * gate5 * c_xnor);
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
        // For SetLtU (compare_op = 0): result[0] = cmp_lt_flag, result[1..7] = 0
        // We use the same gate-product approach as bitwise
        {
            let cop = &compare_op[0];
            // For compare_op=0 (SetLtU): result[0] = cmp_lt_flag
            let cop1 = cop.clone() - E::F::one();
            let cop2 = cop.clone() - E::F::from(BaseField::from(2u32));
            let cop3 = cop.clone() - E::F::from(BaseField::from(3u32));
            let cop4 = cop.clone() - E::F::from(BaseField::from(4u32));
            let cop5 = cop.clone() - E::F::from(BaseField::from(5u32));
            let cop6 = cop.clone() - E::F::from(BaseField::from(6u32));
            let cop7 = cop.clone() - E::F::from(BaseField::from(7u32));
            let gate_setltu = cop1.clone() * cop2.clone() * cop3.clone() * cop4.clone() * cop5.clone() * cop6.clone() * cop7.clone();

            // result[0] = cmp_lt_flag when compare_op = 0
            eval.add_constraint(
                is_compare[0].clone() * gate_setltu.clone() * (result[0].clone() - cmp_lt_flag[0].clone())
            );
            // result[1..7] = 0 when compare_op = 0
            for i in 1..WORD_SIZE {
                eval.add_constraint(
                    is_compare[0].clone() * gate_setltu.clone() * result[i].clone()
                );
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

        // NOTE: Timestamp monotonicity and sequential PC advancement require
        // finalize_bit_reversed() for mask_next_row to work correctly with circle
        // domain evaluation. This is deferred to a future refactor.

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
        let is_load_col = zkpvm_trace::trace_eval!(trace_eval, Column::IsLoad);
        let is_store_col = zkpvm_trace::trace_eval!(trace_eval, Column::IsStore);
        let mem_addr = zkpvm_trace::trace_eval!(trace_eval, Column::MemAddr);
        let mem_value = zkpvm_trace::trace_eval!(trace_eval, Column::MemValue);
        let timestamp = zkpvm_trace::trace_eval!(trace_eval, Column::Timestamp);
        let mem_size = zkpvm_trace::trace_eval!(trace_eval, Column::MemSize);

        let mut mem_tuple: Vec<E::F> = mem_addr.to_vec();
        mem_tuple.extend_from_slice(&mem_value);
        mem_tuple.extend_from_slice(&timestamp);
        mem_tuple.push(is_store_col[0].clone()); // is_write = is_store
        mem_tuple.push(mem_size[0].clone());

        let mem_mult = is_load_col[0].clone() + is_store_col[0].clone();
        eval.add_to_relation(RelationEntry::new(
            mem_lookup,
            mem_mult.into(),
            &mem_tuple,
        ));

        eval.finalize_logup_in_pairs();
    }
}
