//! Opcode → flag classification used to drive CpuChip's per-step witnesses.
//!
//! `OpcodeFlags` is the bag of category/sub-op booleans that mirrors the AIR's
//! per-row flag columns; `classify_opcode` populates one from a PVM Opcode.
//! `uses_immediate` and `dest_reg` are companion predicates used by both the
//! main-trace fill and the register-access derivation.

use javm::instruction::Opcode;

#[derive(Clone, Copy, Default)]
pub(super) struct OpcodeFlags {
    pub is_add: bool,
    pub is_sub: bool,
    pub is_mul: bool,
    pub is_bitwise: bool,
    pub is_shift: bool,
    pub is_compare: bool,
    pub is_move: bool,
    pub is_32bit: bool,
    pub is_and: bool,
    pub is_or: bool,
    pub is_xor: bool,
    pub is_and_inv: bool,
    pub is_or_inv: bool,
    pub is_xnor: bool,
    pub is_neg_add: bool,
    pub is_set_lt_u: bool,
    pub is_set_lt_s: bool,
    pub is_cmov_iz: bool,
    pub is_cmov_nz: bool,
    pub is_min_s: bool,
    pub is_min_u: bool,
    pub is_max_s: bool,
    pub is_max_u: bool,
    pub shift_op: u8,
    pub is_branch: bool,
    pub is_br_eq: bool,
    pub is_br_ne: bool,
    pub is_br_lt_u: bool,
    pub is_br_ge_u: bool,
    pub is_br_le_u: bool,
    pub is_br_gt_u: bool,
    pub is_br_lt_s: bool,
    pub is_br_ge_s: bool,
    pub is_br_le_s: bool,
    pub is_br_gt_s: bool,
    pub is_jump: bool,
    pub is_div_rem: bool,
    pub div_rem_op: u8,
    pub is_load: bool,
    pub is_store: bool,
    pub is_mul_upper: bool,
    pub is_exit: bool,
}

pub(super) fn classify_opcode(op: Opcode) -> OpcodeFlags {
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
        // Arithmetic right shifts: same as logical right but with sign extension
        // Uses divrem + power-of-two (like ShloR). Sign extension handled separately.
        Opcode::SharR64 | Opcode::SharRImm64 | Opcode::SharRImmAlt64 => { f.is_shift = true; f.shift_op = 2; f.is_div_rem = true; f.div_rem_op = 0; }
        Opcode::SharR32 | Opcode::SharRImm32 | Opcode::SharRImmAlt32 => { f.is_shift = true; f.shift_op = 2; f.is_div_rem = true; f.div_rem_op = 0; f.is_32bit = true; }
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
        // Branches (conditional) — classify by comparison type
        // For Le/Gt variants we'll flip the operand order / invert
        Opcode::BranchEq | Opcode::BranchEqImm
            => { f.is_branch = true; f.is_br_eq = true; }
        Opcode::BranchNe | Opcode::BranchNeImm
            => { f.is_branch = true; f.is_br_ne = true; }
        // Unsigned: branch_taken = val_b < val_d
        Opcode::BranchLtU | Opcode::BranchLtUImm
            => { f.is_branch = true; f.is_br_lt_u = true; }
        // Unsigned: branch_taken = val_b >= val_d (= !lt)
        Opcode::BranchGeU | Opcode::BranchGeUImm
            => { f.is_branch = true; f.is_br_ge_u = true; }
        // Unsigned: branch_taken = val_b <= val_d (imm only; swap operands vs ge)
        Opcode::BranchLeUImm
            => { f.is_branch = true; f.is_br_le_u = true; }
        // Unsigned: branch_taken = val_b > val_d (imm only)
        Opcode::BranchGtUImm
            => { f.is_branch = true; f.is_br_gt_u = true; }
        // Signed: branch_taken = val_b < val_d (signed)
        Opcode::BranchLtS | Opcode::BranchLtSImm
            => { f.is_branch = true; f.is_br_lt_s = true; }
        Opcode::BranchGeS | Opcode::BranchGeSImm
            => { f.is_branch = true; f.is_br_ge_s = true; }
        Opcode::BranchLeSImm
            => { f.is_branch = true; f.is_br_le_s = true; }
        Opcode::BranchGtSImm
            => { f.is_branch = true; f.is_br_gt_s = true; }
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
        // Fallthrough/Unlikely: pure sequential terminators (basic-block hints
        // with no semantic effect).  All flags stay 0 so the default
        // sequential-PC identity (next_pc = pc + 1 + skip_len) constrains them
        // — see fallthrough_forged_next_pc_rejected and
        // unlikely_forged_next_pc_rejected in tests/control_flow.rs.
        Opcode::Fallthrough | Opcode::Unlikely => {}
        // JumpInd/LoadImmJumpInd: dynamic jumps (target prover-trusted, exclude from sequential PC)
        Opcode::JumpInd | Opcode::LoadImmJumpInd => { f.is_exit = true; }
        // Ecalli: host call (execution exits, no ALU constraint)
        Opcode::Ecalli | Opcode::Ecall => { f.is_exit = true; }
        // Trap: causes panic exit
        Opcode::Trap => { f.is_exit = true; }
    }
    f
}

pub(super) fn uses_immediate(op: Opcode) -> bool {
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

pub(super) fn dest_reg(step: &crate::core::step::PvmStep) -> usize {
    use javm::instruction::InstructionCategory::*;
    match step.opcode.category() {
        ThreeReg => step.reg_d,
        _ => step.reg_a,
    }
}
