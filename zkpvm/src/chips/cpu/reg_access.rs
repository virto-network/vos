//! Per-step register-access description shared between CpuChip (which fills
//! the producer side of the register-memory ledger) and RegisterMemoryChip
//! (which builds the ledger itself).
//!
//! The two chips must agree byte-for-byte on the (reg_idx, value, ts) tuples
//! they emit, otherwise the logup balance breaks.  Centralising the
//! derivation here keeps them in sync.

use super::classify::{classify_opcode, uses_immediate};
use crate::core::ecall::{
    ECALL_BLAKE2B_COMPRESS, ECALL_RISTRETTO_POINT_ADD, ECALL_RISTRETTO_SCALAR_MULT,
    ECALL_SCALAR_ADD_MOD_L, ECALL_SCALAR_FROM_BYTES_MOD_ORDER_WIDE, ECALL_SCALAR_MUL_MOD_L,
};
#[allow(unused_imports)]
use alloc::{boxed::Box, vec, vec::Vec};

/// Register-access descriptor for a single PVM step.  Used by both
/// CpuChip (to fill the ValB/ValD/Result register-source flags + indices) and
/// RegisterMemoryChip (to build the ledger).  Must stay in sync across the two
/// chips because the logup balance depends on matching (reg_idx, value, ts)
/// tuples on both sides.
pub(crate) struct StepRegAccesses {
    /// (reg_idx, value) if ValB came from a register read at this step.
    pub val_b_read: Option<(u8, u64)>,
    /// (reg_idx, value) if ValD came from a register read at this step.
    pub val_d_read: Option<(u8, u64)>,
    /// (reg_idx, value) if the step reads `regs[ra]` for a
    /// purpose not already captured by `val_b_read`.  Currently set
    /// only on `StoreInd[U][8/16/32/64]` rows — there val_b holds the
    /// *base* `regs[rb]`, while the value to be written is `regs[ra]`,
    /// neither of which lands in a column without this read.
    pub val_a_read: Option<(u8, u64)>,
    /// (reg_idx, value) if the step wrote a register.
    pub result_write: Option<(u8, u64)>,
    /// ECALL-specific register reads.  Blake2b hostcall reads φ[7],
    /// φ[10], φ[11], φ[12] at the ECALL step's timestamp; these entries land
    /// in the ledger alongside the regular ValB/ValD reads and match the
    /// producers CpuChip emits gated by IsBlakeEcall.  Empty for non-blake2b
    /// steps.
    pub ecall_reads: Vec<(u8, u64)>,
}

/// Mirrors the ValB/ValD assignment matrix in generate_main_trace.
///
/// Skipped cases: in-trace ValB/ValD get rewritten mid-step
/// for these, so the ledger tuple wouldn't match what the logup emits.
///   - shifts with `shift_op <= 2` rewrite ValD to `2^shift_amount`
///   - 32-bit add/sub/mul/divrem truncate both ValB and ValD to 32 bits
/// When emissions are dropped here, authentication is lost for those reads;
/// dedicated RegValB/RegValD columns and cross-constraints let the ledger
/// see the raw register values.
pub(crate) fn step_reg_accesses(step: &crate::core::step::PvmStep) -> StepRegAccesses {
    use javm::instruction::InstructionCategory::*;
    // RotR64ImmAlt / RotR32ImmAlt swap the source convention
    // — val_b ← imm (no register read), val_d ← regs[rb].
    let is_rotate_r_imm_alt = classify_opcode(step.opcode).is_rotate_r_imm_alt;
    // SetGtSImm/SetGtUImm use the same source swap — val_b ← imm
    // (no register read), val_d ← regs[rb] — so the SetLt comparison yields
    // greater-than.
    let is_set_gt = classify_opcode(step.opcode).is_set_gt;
    // CmovIzImm/CmovNzImm swap the same way: val_b ← imm (the moved value,
    // no register read), val_d ← regs[rb] (the condition ValDIsZero gates).
    let is_cmov_imm = classify_opcode(step.opcode).is_cmov_imm;
    // Cross-constraints in add_constraints handle the 32-bit Add/Sub/Mul/DivRem
    // truncation: ValB low 4 bytes match RegValB; upper 4 bytes match only when
    // !IsTruncated.
    let val_b_read = match step.opcode.category() {
        ThreeReg => Some((step.reg_a as u8, step.regs_before[step.reg_a])),
        // Source swap for RotR*ImmAlt / SetGt / CmovImm: val_b is imm, not a register.
        TwoRegOneImm if is_rotate_r_imm_alt || is_set_gt || is_cmov_imm => None,
        TwoRegOneImm => Some((step.reg_b as u8, step.regs_before[step.reg_b])),
        OneRegImmOffset => Some((step.reg_a as u8, step.regs_before[step.reg_a])),
        TwoReg => None,
        _ if uses_immediate(step.opcode) => None,
        _ => Some((step.reg_a as u8, step.regs_before[step.reg_a])),
    };
    // Shifts with shift_op ≤ 2 rewrite ValD mid-step; the ledger emission is
    // restored using the RegValD column (holds raw regs[reg_b]).
    let val_d_read = match step.opcode.category() {
        ThreeReg | TwoReg => Some((step.reg_b as u8, step.regs_before[step.reg_b])),
        // Source swap: val_d is regs[rb] for
        // RotR*ImmAlt / SetGt* / Cmov*Imm.
        TwoRegOneImm if is_rotate_r_imm_alt || is_set_gt || is_cmov_imm => {
            Some((step.reg_b as u8, step.regs_before[step.reg_b]))
        }
        TwoRegOneImm | OneRegImmOffset => None,
        _ if uses_immediate(step.opcode) => None,
        _ => Some((step.reg_b as u8, step.regs_before[step.reg_b])),
    };
    // StoreInd source-value read.  TwoRegOneImm's val_b
    // already covers reg_b (the base); val_a_read picks up reg_a
    // (the source value) for StoreInd[U][8/16/32/64].
    let val_a_read = if classify_opcode(step.opcode).is_store_ind {
        Some((step.reg_a as u8, step.regs_before[step.reg_a]))
    } else {
        None
    };
    let result_write = step.reg_write.map(|idx| (idx as u8, step.regs_after[idx]));
    // blake2b ECALL reads φ[7], φ[8], φ[9], φ[10] at this step's
    // ts.  The actor's a0/a1/a2/a3 (h_ptr/m_ptr/
    // t_low/f_flag) map to PVM φ[7/8/9/10] via grey-transpiler's
    // `map_register`.  CpuChip's `ECALL_REG_IDXS` (in `mod.rs` and
    // `interaction.rs`) emits register-file producers at [10, 7, 8, 9]
    // — matching this ledger consumer per blake2b ECALL step.
    // ECALL register-read ledger consumers.
    // These must match the producers CpuChip emits gated by the matching
    // Is*Ecall column, otherwise the register-memory logup balance breaks.
    //   blake2b: φ[7,8,9,10] (h_ptr/m_ptr/t_low/f_flag).
    //   ristretto scalar_mult/point_add/scalar_binop: φ[7,8,9].
    //   ristretto reduce_wide (112): φ[7,8] only.
    let is_ecall = matches!(
        step.opcode,
        crate::core::opcode::Opcode::Ecalli | crate::core::opcode::Opcode::Ecall
    );
    let imm = step.imm;
    let is_blake_ecall = is_ecall && imm == ECALL_BLAKE2B_COMPRESS as u64;
    let is_ristretto_reduce = is_ecall && imm == ECALL_SCALAR_FROM_BYTES_MOD_ORDER_WIDE as u64;
    let is_ristretto_three = is_ecall
        && (imm == ECALL_RISTRETTO_SCALAR_MULT as u64
            || imm == ECALL_RISTRETTO_POINT_ADD as u64
            || imm == ECALL_SCALAR_MUL_MOD_L as u64
            || imm == ECALL_SCALAR_ADD_MOD_L as u64);
    let ecall_reads = if is_blake_ecall {
        vec![
            (7u8, step.regs_before[7]),
            (8u8, step.regs_before[8]),
            (9u8, step.regs_before[9]),
            (10u8, step.regs_before[10]),
        ]
    } else if is_ristretto_three {
        vec![
            (7u8, step.regs_before[7]),
            (8u8, step.regs_before[8]),
            (9u8, step.regs_before[9]),
        ]
    } else if is_ristretto_reduce {
        vec![(7u8, step.regs_before[7]), (8u8, step.regs_before[8])]
    } else {
        Vec::new()
    };
    StepRegAccesses {
        val_b_read,
        val_d_read,
        val_a_read,
        result_write,
        ecall_reads,
    }
}
