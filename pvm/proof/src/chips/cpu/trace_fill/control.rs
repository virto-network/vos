//! Branches and dynamic jumps.

use super::*;

/// Whether a branch is taken, and its target.
pub(super) fn branch(out: &mut Sinks, s: Step, cmp: &Compare) -> bool {
    let Sinks { trace, .. } = out;
    let Step { row, step, flags } = s;
    let Compare {
        cmp_lt_flag,
        cmp_lt_s_flag,
        eq_flag,
        ..
    } = *cmp;
    // A branch's BranchTaken is its condition, which the AIR binds. The
    // step records whether its pc took the target, which cannot tell
    // when the target is its fallthrough: there the condition decides.
    let lt_or_eq = |lt: u8| lt == 1 || eq_flag == 1;
    let condition = if flags.is_br_eq {
        eq_flag == 1
    } else if flags.is_br_ne {
        eq_flag == 0
    } else if flags.is_br_lt_u {
        cmp_lt_flag == 1
    } else if flags.is_br_ge_u {
        cmp_lt_flag == 0
    } else if flags.is_br_le_u {
        lt_or_eq(cmp_lt_flag)
    } else if flags.is_br_gt_u {
        !lt_or_eq(cmp_lt_flag)
    } else if flags.is_br_lt_s {
        cmp_lt_s_flag == 1
    } else if flags.is_br_ge_s {
        cmp_lt_s_flag == 0
    } else if flags.is_br_le_s {
        lt_or_eq(cmp_lt_s_flag)
    } else if flags.is_br_gt_s {
        !lt_or_eq(cmp_lt_s_flag)
    } else {
        false
    };
    let fallthrough = step.pc + 1 + step.skip_len;
    let branch_taken = step.branch_taken || (condition && step.branch_target == fallthrough);
    trace.fill_columns(row, branch_taken, Column::BranchTaken);
    trace.fill_columns_bytes(row, &step.branch_target.to_le_bytes(), Column::BranchTarget);
    branch_taken
}

/// The dynamic jumps: their halt flags, addresses and jump-table counts.
pub(super) fn jumps(out: &mut Sinks, s: Step, ops: &Operands) {
    let Sinks {
        trace, side_note, ..
    } = out;
    let Step { row, step, flags } = s;
    let Operands { val_b, val_d, .. } = *ops;
    trace.fill_columns(row, flags.is_jump_ind, Column::IsJumpInd);
    let is_halt_jump_ind = flags.is_jump_ind
        && step.exit
        && (val_b.wrapping_add(step.imm) as u32 == vos_pvm::PVM_HALT_ADDR as u32);
    trace.fill_columns(row, is_halt_jump_ind, Column::IsHaltJumpInd);
    trace.fill_columns(row, flags.is_load_imm_jump_ind, Column::IsLoadImmJumpInd);
    let is_halt_load_imm_jump_ind = flags.is_load_imm_jump_ind
        && step.exit
        && (val_d.wrapping_add(step.imm_y) as u32 == vos_pvm::PVM_HALT_ADDR as u32);
    trace.fill_columns(row, is_halt_load_imm_jump_ind, Column::IsHaltLoadImmJumpInd);
    // ImmYBytes always carries the low 5 bytes of step.imm_y so the
    // prog_mem lookup balances on every row (canonical = 0 for ops
    // without a second immediate).
    trace.fill_columns_bytes(row, &step.imm_y.to_le_bytes()[..5], Column::ImmYBytes);
    // Per-byte add-with-carry chain for JumpIndAddr =
    // (val_b + step.imm) mod 2^32.  The constraint is gated by
    // IsJumpInd, so on non-JumpInd rows the columns are left at
    // zero (default fill).  The runtime addr feeds JumpTableChip's
    // multiplicity counter via side_note.jump_table_counts.
    if flags.is_jump_ind {
        let val_b_lo = (val_b as u32).to_le_bytes();
        let imm_lo = (step.imm as u32).to_le_bytes();
        let mut carry_in: u16 = 0;
        let mut addr_bytes = [0u8; 4];
        let mut carry_bytes = [0u8; 4];
        for i in 0..4 {
            let s = val_b_lo[i] as u16 + imm_lo[i] as u16 + carry_in;
            addr_bytes[i] = s as u8;
            carry_in = s >> 8;
            carry_bytes[i] = carry_in as u8;
        }
        trace.fill_columns_bytes(row, &addr_bytes, Column::JumpIndAddr);
        trace.fill_columns_bytes(row, &carry_bytes, Column::JumpIndCarry);

        // Count this dispatch in side_note.jump_table_counts so
        // JumpTableChip's producer multiplicity matches.  Index =
        // addr/2 - 1 (mirrors the runtime djump indexing).
        let addr = u32::from_le_bytes(addr_bytes);
        if !is_halt_jump_ind && addr >= 2 && addr.is_multiple_of(2) {
            let idx = (addr / 2 - 1) as usize;
            if let Some(counts) = side_note.jump_table_counts.get_mut(idx) {
                *counts += 1;
            }
        }
    }
    // LoadImmJumpInd carry chain for
    // LoadImmJumpIndAddr = (val_d + imm_y) mod 2^32.
    if flags.is_load_imm_jump_ind {
        let val_d_lo = (val_d as u32).to_le_bytes();
        let imm_y_lo = (step.imm_y as u32).to_le_bytes();
        let mut carry_in: u16 = 0;
        let mut addr_bytes = [0u8; 4];
        let mut carry_bytes = [0u8; 4];
        for i in 0..4 {
            let s = val_d_lo[i] as u16 + imm_y_lo[i] as u16 + carry_in;
            addr_bytes[i] = s as u8;
            carry_in = s >> 8;
            carry_bytes[i] = carry_in as u8;
        }
        trace.fill_columns_bytes(row, &addr_bytes, Column::LoadImmJumpIndAddr);
        trace.fill_columns_bytes(row, &carry_bytes, Column::LoadImmJumpIndCarry);

        let addr = u32::from_le_bytes(addr_bytes);
        if !is_halt_load_imm_jump_ind && addr >= 2 && addr.is_multiple_of(2) {
            let idx = (addr / 2 - 1) as usize;
            if let Some(counts) = side_note.jump_table_counts.get_mut(idx) {
                *counts += 1;
            }
        }
    }
}
