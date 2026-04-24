//! Per-step register-access description shared between CpuChip (which fills
//! the producer side of the register-memory ledger) and RegisterMemoryChip
//! (which builds the ledger itself).
//!
//! The two chips must agree byte-for-byte on the (reg_idx, value, ts) tuples
//! they emit, otherwise the logup balance breaks.  Centralising the
//! derivation here keeps them in sync.

use super::classify::uses_immediate;
use crate::core::tracing::ECALL_BLAKE2B_COMPRESS;

/// Phase 9d: register-access descriptor for a single PVM step.  Used by both
/// CpuChip (to fill the ValB/ValD/Result register-source flags + indices) and
/// RegisterMemoryChip (to build the ledger).  Must stay in sync across the two
/// chips because the logup balance depends on matching (reg_idx, value, ts)
/// tuples on both sides.
pub(crate) struct StepRegAccesses {
    /// (reg_idx, value) if ValB came from a register read at this step.
    pub val_b_read: Option<(u8, u64)>,
    /// (reg_idx, value) if ValD came from a register read at this step.
    pub val_d_read: Option<(u8, u64)>,
    /// (reg_idx, value) if the step wrote a register.
    pub result_write: Option<(u8, u64)>,
    /// Phase 9e: ECALL-specific register reads.  Blake2b hostcall reads φ[7],
    /// φ[10], φ[11], φ[12] at the ECALL step's timestamp; these entries land
    /// in the ledger alongside the regular ValB/ValD reads and match the
    /// producers CpuChip emits gated by IsBlakeEcall.  Empty for non-blake2b
    /// steps.
    pub ecall_reads: Vec<(u8, u64)>,
}

/// Mirrors the ValB/ValD assignment matrix in generate_main_trace.
///
/// Skipped cases (follow-up 9g): in-trace ValB/ValD get rewritten mid-step
/// for these, so the ledger tuple wouldn't match what the logup emits.
///   - shifts with `shift_op <= 2` rewrite ValD to `2^shift_amount`
///   - 32-bit add/sub/mul/divrem truncate both ValB and ValD to 32 bits
/// These emissions are dropped here (authentication lost for those reads);
/// a later phase can add RegValB/RegValD dedicated columns and cross-
/// constraints so the ledger sees the raw register values.
pub(crate) fn step_reg_accesses(step: &crate::core::step::PvmStep) -> StepRegAccesses {
    use javm::instruction::InstructionCategory::*;
    // Phase 9g: the previous skip for 32-bit Add/Sub/Mul/DivRem is lifted.
    // Cross-constraints in add_constraints handle the truncation: ValB low
    // 4 bytes match RegValB; upper 4 bytes match only when !IsTruncated.
    let val_b_read = match step.opcode.category() {
        ThreeReg => Some((step.reg_a as u8, step.regs_before[step.reg_a])),
        TwoRegOneImm => Some((step.reg_b as u8, step.regs_before[step.reg_b])),
        OneRegImmOffset => Some((step.reg_a as u8, step.regs_before[step.reg_a])),
        TwoReg => None,
        _ if uses_immediate(step.opcode) => None,
        _ => Some((step.reg_a as u8, step.regs_before[step.reg_a])),
    };
    // Shifts with shift_op ≤ 2 rewrite ValD mid-step; Phase 9f restores the
    // ledger emission using the RegValD column (holds raw regs[reg_b]).
    let val_d_read = match step.opcode.category() {
        ThreeReg | TwoReg => Some((step.reg_b as u8, step.regs_before[step.reg_b])),
        TwoRegOneImm | OneRegImmOffset => None,
        _ if uses_immediate(step.opcode) => None,
        _ => Some((step.reg_b as u8, step.regs_before[step.reg_b])),
    };
    let result_write = step.reg_write.map(|idx| (idx as u8, step.regs_after[idx]));
    // Phase 9e: blake2b ECALL reads φ[7], φ[10], φ[11], φ[12] at this step's ts.
    let is_blake_ecall = matches!(step.opcode,
            crate::core::opcode::Opcode::Ecalli | crate::core::opcode::Opcode::Ecall)
        && step.imm == ECALL_BLAKE2B_COMPRESS as u64;
    let ecall_reads = if is_blake_ecall {
        vec![
            (7u8, step.regs_before[7]),
            (10u8, step.regs_before[10]),
            (11u8, step.regs_before[11]),
            (12u8, step.regs_before[12]),
        ]
    } else {
        Vec::new()
    };
    StepRegAccesses { val_b_read, val_d_read, result_write, ecall_reads }
}
