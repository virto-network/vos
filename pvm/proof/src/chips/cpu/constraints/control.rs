//! Control flow: branches, jumps, the next PC, step sequencing and Trap.
use alloc::vec::Vec;

use num_traits::{One, Zero};
use stwo::core::fields::m31::BaseField;
use stwo_constraint_framework::{EvalAtRow, RelationEntry};

use super::{Lookups, Trace, is_branch, is_compare};
use crate::chips::cpu::columns::Column;
use crate::core::step::WORD_SIZE;

/// Distinguished dynamic-jump target that terminates a PVM normally.
/// Kept feature-independent because the verifier does not link `vos_pvm`.
const PVM_HALT_ADDR_BYTES: [u8; 4] = 0xffff_0000u32.to_le_bytes();

/// The branch-condition and sequential-PC helpers.
pub(in crate::chips::cpu) fn branch_helpers<E: EvalAtRow>(eval: &mut E, trace_eval: &Trace<E>) {
    let val_b = crate::trace::trace_eval!(trace_eval, Column::ValB);
    let val_d = crate::trace::trace_eval!(trace_eval, Column::ValD);
    let is_cmp_or_branch = is_compare(trace_eval) + is_branch(trace_eval);
    // ── Branch condition + sequential-PC helpers ──
    let is_cmp_or_branch_eq_h = crate::trace::trace_eval!(trace_eval, Column::IsCmpOrBranchEqH);
    let is_branch_taken_h = crate::trace::trace_eval!(trace_eval, Column::IsBranchTakenH);
    {
        let branch_taken_top = crate::trace::trace_eval!(trace_eval, Column::BranchTaken);
        let eq_flag_top = crate::trace::trace_eval!(trace_eval, Column::EqFlag);
        // EqFlag is the operands' equality, both ways, on every compare
        // and branch row: equal operands have a zero sum of squared byte
        // differences, so a zero product with its inverse; different
        // ones a product of 1. Over the integers the sum is zero only
        // when every difference is (each square is non-negative and
        // their sum below 2^20); in the field, the byte-wise pinning
        // below refuses EqFlag = 1 for different operands whatever the
        // sum.
        let squares = crate::trace::trace_eval!(trace_eval, Column::EqDiffSquaresH);
        let squares_inv = crate::trace::trace_eval!(trace_eval, Column::EqDiffSquaresInv);
        let squares_times_inv =
            crate::trace::trace_eval!(trace_eval, Column::EqDiffSquaresTimesInvH);
        let mut sum = E::F::zero();
        for i in 0..WORD_SIZE {
            let diff = val_b[i].clone() - val_d[i].clone();
            sum += diff.clone() * diff;
        }
        eval.add_constraint(squares[0].clone() - sum);
        eval.add_constraint(
            squares_times_inv[0].clone() - squares[0].clone() * squares_inv[0].clone(),
        );
        eval.add_constraint(
            is_cmp_or_branch.clone()
                * (E::F::one() - eq_flag_top[0].clone() - squares_times_inv[0].clone()),
        );
        // EqFlag boolean enforced unconditionally.
        eval.add_constraint(eq_flag_top[0].clone() * (E::F::one() - eq_flag_top[0].clone()));
        eval.add_constraint(
            is_cmp_or_branch_eq_h[0].clone() - is_cmp_or_branch.clone() * eq_flag_top[0].clone(),
        );
        eval.add_constraint(
            is_branch_taken_h[0].clone() - is_branch(trace_eval) * branch_taken_top[0].clone(),
        );
    }
}

/// The control-flow and memory-boolean helpers.
pub(in crate::chips::cpu) fn control_flow_helpers<E: EvalAtRow>(
    eval: &mut E,
    trace_eval: &Trace<E>,
) {
    // ── Control-flow + memory-boolean helpers ──
    let mem_byte_active_mono_h = crate::trace::trace_eval!(trace_eval, Column::MemByteActiveMonoH);
    {
        let branch_taken_w6 = crate::trace::trace_eval!(trace_eval, Column::BranchTaken);
        let mem_byte_active_w6 = crate::trace::trace_eval!(trace_eval, Column::MemByteActive);
        // branch_taken/mem_byte_active boolean enforced unconditionally.
        // Trace fills both as 0 on padding/non-mem rows.
        eval.add_constraint(
            branch_taken_w6[0].clone() * (E::F::one() - branch_taken_w6[0].clone()),
        );
        for i in 0..WORD_SIZE {
            eval.add_constraint(
                mem_byte_active_w6[i].clone() * (E::F::one() - mem_byte_active_w6[i].clone()),
            );
        }
        for i in 0..WORD_SIZE - 1 {
            eval.add_constraint(
                mem_byte_active_mono_h[i].clone()
                    - mem_byte_active_w6[i + 1].clone()
                        * (E::F::one() - mem_byte_active_w6[i].clone()),
            );
        }
    }
}

/// Control flow: the next PC of jumps and branches.
pub(in crate::chips::cpu) fn next_pc<E: EvalAtRow>(eval: &mut E, trace_eval: &Trace<E>) {
    let is_branch_taken_h = crate::trace::trace_eval!(trace_eval, Column::IsBranchTakenH);
    // ════════════════════════════════════════════════════════════════════
    // CONTROL FLOW: constrain next_pc based on branch/jump
    // ════════════════════════════════════════════════════════════════════
    let is_jump = crate::trace::trace_eval!(trace_eval, Column::IsJump);
    let branch_target = crate::trace::trace_eval!(trace_eval, Column::BranchTarget);
    let next_pc = crate::trace::trace_eval!(trace_eval, Column::NextPc);

    // A jump or a taken branch continues at branch_target; every other
    // real row at pc + 1 + skip_len, all four bytes with their carries
    // (`branch_conditions`).

    // For unconditional jumps: next_pc = branch_target
    for i in 0..4 {
        eval.add_constraint(is_jump[0].clone() * (next_pc[i].clone() - branch_target[i].clone()));
    }

    // For conditional branches:
    //   branch_taken=1 → next_pc = branch_target
    // Gate via IsBranchTakenH (defined above).
    for i in 0..4 {
        eval.add_constraint(
            is_branch_taken_h[0].clone() * (next_pc[i].clone() - branch_target[i].clone()),
        );
    }

    // branch_taken is boolean on every row (`control_flow_helpers`).
}

/// The branch conditions, and the sequential next PC.
pub(in crate::chips::cpu) fn branch_conditions<E: EvalAtRow>(eval: &mut E, trace_eval: &Trace<E>) {
    let val_b = crate::trace::trace_eval!(trace_eval, Column::ValB);
    let val_d = crate::trace::trace_eval!(trace_eval, Column::ValD);
    let cmp_lt_flag = crate::trace::trace_eval!(trace_eval, Column::CmpLtFlag);
    let cmp_lt_s_flag = crate::trace::trace_eval!(trace_eval, Column::CmpLtSFlag);
    let is_br_eq = crate::trace::trace_eval!(trace_eval, Column::IsBrEq);
    let is_br_ne = crate::trace::trace_eval!(trace_eval, Column::IsBrNe);
    let is_br_lt_u = crate::trace::trace_eval!(trace_eval, Column::IsBrLtU);
    let is_br_ge_u = crate::trace::trace_eval!(trace_eval, Column::IsBrGeU);
    let is_br_le_u = crate::trace::trace_eval!(trace_eval, Column::IsBrLeU);
    let is_br_gt_u = crate::trace::trace_eval!(trace_eval, Column::IsBrGtU);
    let is_br_lt_s = crate::trace::trace_eval!(trace_eval, Column::IsBrLtS);
    let is_br_ge_s = crate::trace::trace_eval!(trace_eval, Column::IsBrGeS);
    let is_br_le_s = crate::trace::trace_eval!(trace_eval, Column::IsBrLeS);
    let is_br_gt_s = crate::trace::trace_eval!(trace_eval, Column::IsBrGtS);
    let f256 = E::F::from(BaseField::from(256u32));
    let is_cmp_or_branch_eq_h = crate::trace::trace_eval!(trace_eval, Column::IsCmpOrBranchEqH);
    let is_branch_taken_h = crate::trace::trace_eval!(trace_eval, Column::IsBranchTakenH);
    let is_jump = crate::trace::trace_eval!(trace_eval, Column::IsJump);
    let branch_taken = crate::trace::trace_eval!(trace_eval, Column::BranchTaken);
    let next_pc = crate::trace::trace_eval!(trace_eval, Column::NextPc);
    // ── Branch condition constraints ──
    // Equal: taken exactly when the operands are equal; not equal:
    // exactly when they differ. EqFlag is their equality both ways.
    let eq_flag = crate::trace::trace_eval!(trace_eval, Column::EqFlag);
    eval.add_constraint(is_br_eq[0].clone() * (branch_taken[0].clone() - eq_flag[0].clone()));
    eval.add_constraint(
        is_br_ne[0].clone() * (branch_taken[0].clone() + eq_flag[0].clone() - E::F::one()),
    );

    // Unsigned Lt: branch_taken = cmp_lt_flag
    eval.add_constraint(is_br_lt_u[0].clone() * (branch_taken[0].clone() - cmp_lt_flag[0].clone()));
    // Unsigned Ge: branch_taken = 1 - cmp_lt_flag
    eval.add_constraint(
        is_br_ge_u[0].clone() * (branch_taken[0].clone() - (E::F::one() - cmp_lt_flag[0].clone())),
    );
    // Signed Lt: branch_taken = cmp_lt_s_flag
    eval.add_constraint(
        is_br_lt_s[0].clone() * (branch_taken[0].clone() - cmp_lt_s_flag[0].clone()),
    );
    // Signed Ge: branch_taken = 1 - cmp_lt_s_flag
    eval.add_constraint(
        is_br_ge_s[0].clone()
            * (branch_taken[0].clone() - (E::F::one() - cmp_lt_s_flag[0].clone())),
    );
    // EqFlag = 1 ⇒ val_b[i] = val_d[i] (byte-wise) — gate via
    // IsCmpOrBranchEqH; its converse is the squares' inverse above.
    for i in 0..WORD_SIZE {
        eval.add_constraint(
            is_cmp_or_branch_eq_h[0].clone() * (val_b[i].clone() - val_d[i].clone()),
        );
    }
    // Le/Gt: (≤) = (<) or (=), the two exclusive, so taken = lt + eq.

    // Unsigned Le: branch_taken = cmp_lt_flag + eq_flag - cmp_lt_flag*eq_flag (OR)
    // Simpler since cmp_lt_flag and eq_flag can't both be 1 (if lt, not equal):
    // branch_taken = cmp_lt_flag + eq_flag
    eval.add_constraint(
        is_br_le_u[0].clone()
            * (branch_taken[0].clone() - cmp_lt_flag[0].clone() - eq_flag[0].clone()),
    );
    // Unsigned Gt: branch_taken = 1 - (cmp_lt_flag + eq_flag)
    eval.add_constraint(
        is_br_gt_u[0].clone()
            * (branch_taken[0].clone() - E::F::one() + cmp_lt_flag[0].clone() + eq_flag[0].clone()),
    );
    // Signed Le: branch_taken = cmp_lt_s_flag + eq_flag
    eval.add_constraint(
        is_br_le_s[0].clone()
            * (branch_taken[0].clone() - cmp_lt_s_flag[0].clone() - eq_flag[0].clone()),
    );
    // Signed Gt: branch_taken = 1 - (cmp_lt_s_flag + eq_flag)
    eval.add_constraint(
        is_br_gt_s[0].clone()
            * (branch_taken[0].clone() - E::F::one()
                + cmp_lt_s_flag[0].clone()
                + eq_flag[0].clone()),
    );

    // Sequential PC: next_pc = pc + 1 + skip_len (4-byte addition with carry)
    // Fires for: non-jump AND (non-branch OR branch-not-taken)
    // is_sequential = (1 - is_jump) * (1 - is_branch * branch_taken)
    //              = 1 - is_jump - is_branch*branch_taken + is_jump*is_branch*branch_taken
    // Since is_jump and is_branch are mutually exclusive, is_jump*is_branch=0, so:
    // is_sequential = 1 - is_jump - is_branch*branch_taken
    // But we can also just constrain each case separately:
    // For byte 0: next_pc[0] + pc_carry[0]*256 = pc[0] + 1 + skip_len
    // For byte i>0: next_pc[i] + pc_carry[i]*256 = pc[i] + pc_carry[i-1]
    // For byte 3: next_pc[3] = pc[3] + pc_carry[2] (no overflow for valid programs)
    {
        let pc = crate::trace::trace_eval!(trace_eval, Column::Pc);
        let skip_len = crate::trace::trace_eval!(trace_eval, Column::SkipLen);
        let pc_carry = crate::trace::trace_eval!(trace_eval, Column::PcCarry);
        let is_pad = crate::trace::trace_eval!(trace_eval, Column::IsPadding);
        let is_exit = crate::trace::trace_eval!(trace_eval, Column::IsExit);
        // Route is_branch · branch_taken through IsBranchTakenH so
        // is_sequential stays at deg 1.
        let is_sequential = E::F::one()
            - is_pad[0].clone()
            - is_jump[0].clone()
            - is_branch_taken_h[0].clone()
            - is_exit[0].clone();
        for c in pc_carry.iter() {
            eval.add_constraint(c.clone() * (E::F::one() - c.clone()));
        }

        // Byte 0: next_pc[0] + carry[0]*256 = pc[0] + 1 + skip_len
        eval.add_constraint(
            is_sequential.clone()
                * (next_pc[0].clone() + pc_carry[0].clone() * f256.clone()
                    - pc[0].clone()
                    - E::F::one()
                    - skip_len[0].clone()),
        );
        // Bytes 1,2: next_pc[i] + carry[i]*256 = pc[i] + carry[i-1]
        for i in 1..3 {
            eval.add_constraint(
                is_sequential.clone()
                    * (next_pc[i].clone() + pc_carry[i].clone() * f256.clone()
                        - pc[i].clone()
                        - pc_carry[i - 1].clone()),
            );
        }
        // Byte 3: next_pc[3] = pc[3] + carry[2]
        eval.add_constraint(
            is_sequential.clone() * (next_pc[3].clone() - pc[3].clone() - pc_carry[2].clone()),
        );
    }
}

/// The program-execution lookup: step sequencing.
pub(in crate::chips::cpu) fn program_execution<E: EvalAtRow>(
    eval: &mut E,
    trace_eval: &Trace<E>,
    lookups: &Lookups<'_>,
) {
    let prog_exec_lookup = lookups.prog_exec_lookup;
    let is_pad = crate::trace::trace_eval!(trace_eval, Column::IsPadding);
    let is_real = E::F::one() - is_pad[0].clone();
    // ════════════════════════════════════════════════════════════════════
    // Program execution lookup: step sequencing
    // ════════════════════════════════════════════════════════════════════
    {
        let pc_col = crate::trace::trace_eval!(trace_eval, Column::Pc);
        let next_pc_col = crate::trace::trace_eval!(trace_eval, Column::NextPc);
        let timestamp = crate::trace::trace_eval!(trace_eval, Column::Timestamp);
        let next_ts = crate::trace::trace_eval!(trace_eval, Column::NextTimestamp);

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
}

/// No real row follows a Trap.
pub(in crate::chips::cpu) fn trap_terminal<E: EvalAtRow>(eval: &mut E, trace_eval: &Trace<E>) {
    let is_real_trap_h = crate::trace::trace_eval!(trace_eval, Column::IsRealTrapH);
    let next_pc = crate::trace::trace_eval!(trace_eval, Column::NextPc);
    // ════════════════════════════════════════════════════════════════════
    // Terminal-row constraint gated on per-opcode IsTrap
    //
    // Forbids a real successor row after Trap.  Gating on IsExit would
    // be wrong: that flag is shared with Ecalli (which legitimately has
    // successors after blake2b hostcalls) and with JumpInd /
    // LoadImmJumpInd (dynamic dispatch — also has successors).  The
    // narrower IsTrap flag fires only on Opcode::Trap.
    //
    // Reads the *next* row's IsPadding via `trace_eval_next_row!` (the
    // IsPadding column is `#[mask_next_row]`).  When the current row is
    // a real Trap, the next row's IsPadding must be 1.
    {
        let is_padding_next = crate::trace::trace_eval_next_row!(trace_eval, Column::IsPadding);
        let is_trap_col = crate::trace::trace_eval!(trace_eval, Column::IsTrap);
        // Boolean witness.
        eval.add_constraint(is_trap_col[0].clone() * (E::F::one() - is_trap_col[0].clone()));
        // Terminal: real Trap forbids successor real row.
        eval.add_constraint(is_real_trap_h[0].clone() * (E::F::one() - is_padding_next[0].clone()));
        // A trap stays at its pc: no other constraint binds a Trap's
        // next pc, which a segment ending at it publishes as its final
        // pc, and only a halt continues at the halt address.
        let pc = crate::trace::trace_eval!(trace_eval, Column::Pc);
        for (next, pc) in next_pc.iter().zip(&pc) {
            eval.add_constraint(is_trap_col[0].clone() * (next.clone() - pc.clone()));
        }
    }
}

/// JumpInd: the target through the jump table.
pub(in crate::chips::cpu) fn jump_ind<E: EvalAtRow>(
    eval: &mut E,
    trace_eval: &Trace<E>,
    lookups: &Lookups<'_>,
) {
    let jump_table_lookup = lookups.jump_table_lookup;
    let val_b = crate::trace::trace_eval!(trace_eval, Column::ValB);
    let next_pc = crate::trace::trace_eval!(trace_eval, Column::NextPc);
    let f256 = E::F::from(BaseField::from(256));
    // ════════════════════════════════════════════════════════════════════
    // JumpInd target binding via JumpTableChip
    //
    // (1) Carry-chain constraint: pin JumpIndAddr to (val_b + imm) low 32 bits.
    //   For each byte i in 0..4:
    //     is_jump_ind · (jump_ind_addr[i] + carry[i]·256
    //                    - val_b[i] - imm_bytes[i] - carry_in[i]) = 0
    //   carry_in[0] = 0; carry_in[i>0] = carry[i-1]; carry[3] is the
    //   32-bit overflow, discarded.
    //
    // (2) JumpTableChip lookup: emit (jump_ind_addr[4], next_pc[4]) per
    //   JumpInd row, paired (2 emissions, ProgramMemoryChip-style mult
    //   doubling).  Multiplicity = is_jump_ind (degree 1).
    //
    // The producer side (JumpTableChip) commits via preprocessed Addr +
    // Target columns to `(2*(idx+1), jump_table[idx])` per program-
    // defined entry, so the lookup balances iff next_pc =
    // jump_table[(val_b+imm)/2 - 1] — exactly the runtime djump.
    {
        let is_jump_ind_col = crate::trace::trace_eval!(trace_eval, Column::IsJumpInd);
        let is_halt_jump_ind = crate::trace::trace_eval!(trace_eval, Column::IsHaltJumpInd);
        let jump_ind_addr = crate::trace::trace_eval!(trace_eval, Column::JumpIndAddr);
        let jump_ind_carry = crate::trace::trace_eval!(trace_eval, Column::JumpIndCarry);
        let imm_bytes_col = crate::trace::trace_eval!(trace_eval, Column::ImmBytes);
        let is_padding_next = crate::trace::trace_eval_next_row!(trace_eval, Column::IsPadding);
        // Boolean witnesses. A halt selector is only valid on JumpInd,
        // pins the computed address to the distinguished halt target,
        // continues at that target, outside a derived program's code,
        // whose static targets and jump-table entries all lie in it (so
        // its segment's `pc_out` is the halt address exactly when it
        // ends at a halt), and forbids a successor row.
        eval.add_constraint(
            is_jump_ind_col[0].clone() * (E::F::one() - is_jump_ind_col[0].clone()),
        );
        eval.add_constraint(
            is_halt_jump_ind[0].clone() * (E::F::one() - is_halt_jump_ind[0].clone()),
        );
        eval.add_constraint(
            is_halt_jump_ind[0].clone() * (E::F::one() - is_jump_ind_col[0].clone()),
        );
        for i in 0..4 {
            let carry_in: E::F = if i == 0 {
                E::F::zero()
            } else {
                jump_ind_carry[i - 1].clone()
            };
            // Carries are integer carry bits, not arbitrary field
            // elements. Without this constraint a prover can solve the
            // byte equations backwards from PVM_HALT_ADDR with
            // field-valued carries, assert `is_halt = 1`, and suppress
            // the jump-table lookup for an ordinary dynamic jump.
            eval.add_constraint(
                jump_ind_carry[i].clone() * (E::F::one() - jump_ind_carry[i].clone()),
            );
            eval.add_constraint(
                is_jump_ind_col[0].clone()
                    * (jump_ind_addr[i].clone() + jump_ind_carry[i].clone() * f256.clone()
                        - val_b[i].clone()
                        - imm_bytes_col[i].clone()
                        - carry_in),
            );
            eval.add_constraint(
                is_halt_jump_ind[0].clone()
                    * (jump_ind_addr[i].clone()
                        - E::F::from(BaseField::from(PVM_HALT_ADDR_BYTES[i] as u32))),
            );
            eval.add_constraint(
                is_halt_jump_ind[0].clone()
                    * (next_pc[i].clone()
                        - E::F::from(BaseField::from(PVM_HALT_ADDR_BYTES[i] as u32))),
            );
        }
        eval.add_constraint(
            is_halt_jump_ind[0].clone() * (E::F::one() - is_padding_next[0].clone()),
        );
        // Paired JumpTable consumer (mult = is_jump_ind on each emission;
        // ProgramMemory-style pair doubling so the per-pair degree stays
        // bounded).  Tuple = (jump_ind_addr[4], next_pc[4]) — pinned to
        // ((val_b+imm) low 32 bits, runtime-jumped target) for JumpInd.
        let mut jt_tuple: Vec<E::F> = jump_ind_addr.to_vec();
        jt_tuple.extend_from_slice(&next_pc);
        eval.add_to_relation(RelationEntry::new(
            jump_table_lookup,
            (is_jump_ind_col[0].clone() - is_halt_jump_ind[0].clone()).into(),
            &jt_tuple,
        ));
        eval.add_to_relation(RelationEntry::new(
            jump_table_lookup,
            (is_jump_ind_col[0].clone() - is_halt_jump_ind[0].clone()).into(),
            &jt_tuple,
        ));
    }
}

/// LoadImmJumpInd: the target through the jump table, and the loaded immediate.
pub(in crate::chips::cpu) fn load_imm_jump_ind<E: EvalAtRow>(
    eval: &mut E,
    trace_eval: &Trace<E>,
    lookups: &Lookups<'_>,
) {
    let jump_table_lookup = lookups.jump_table_lookup;
    let val_d = crate::trace::trace_eval!(trace_eval, Column::ValD);
    let result = crate::trace::trace_eval!(trace_eval, Column::Result);
    let next_pc = crate::trace::trace_eval!(trace_eval, Column::NextPc);
    let f256 = E::F::from(BaseField::from(256));
    // ════════════════════════════════════════════════════════════════════
    // LoadImmJumpInd target binding via JumpTable
    //
    // Same chip lookup as JumpInd, but with a different addr formula.
    // At runtime: addr = (regs[rb] + imm_y) mod 2^32, then djump.
    // val_d = regs[rb] for TwoRegTwoImm (default arm in trace fill),
    // imm_y is the new ImmYBytes column (bound to canonical via
    // prog_mem tuple).
    //
    // Carry chain: pin LoadImmJumpIndAddr to (val_d + imm_y) low 32.
    // Lookup: (LoadImmJumpIndAddr, NextPc) ∈ jump_table.
    //
    // The load side writes `regs[ra] = imm_x`: the row's Result is its
    // ImmBytes.
    {
        let is_lij_col = crate::trace::trace_eval!(trace_eval, Column::IsLoadImmJumpInd);
        let is_halt_lij = crate::trace::trace_eval!(trace_eval, Column::IsHaltLoadImmJumpInd);
        let lij_addr = crate::trace::trace_eval!(trace_eval, Column::LoadImmJumpIndAddr);
        let lij_carry = crate::trace::trace_eval!(trace_eval, Column::LoadImmJumpIndCarry);
        let imm_y_bytes = crate::trace::trace_eval!(trace_eval, Column::ImmYBytes);
        let is_padding_next = crate::trace::trace_eval_next_row!(trace_eval, Column::IsPadding);
        let imm_x_bytes = crate::trace::trace_eval!(trace_eval, Column::ImmBytes);
        for (result_byte, imm_byte) in result.iter().zip(&imm_x_bytes) {
            eval.add_constraint(is_lij_col[0].clone() * (result_byte.clone() - imm_byte.clone()));
        }
        // Boolean witnesses and the same terminal-halt binding as
        // JumpInd above.
        eval.add_constraint(is_lij_col[0].clone() * (E::F::one() - is_lij_col[0].clone()));
        eval.add_constraint(is_halt_lij[0].clone() * (E::F::one() - is_halt_lij[0].clone()));
        eval.add_constraint(is_halt_lij[0].clone() * (E::F::one() - is_lij_col[0].clone()));
        // Carry chain: lij_addr = val_d + imm_y_bytes (low 32 bits).
        for i in 0..4 {
            let carry_in: E::F = if i == 0 {
                E::F::zero()
            } else {
                lij_carry[i - 1].clone()
            };
            eval.add_constraint(lij_carry[i].clone() * (E::F::one() - lij_carry[i].clone()));
            eval.add_constraint(
                is_lij_col[0].clone()
                    * (lij_addr[i].clone() + lij_carry[i].clone() * f256.clone()
                        - val_d[i].clone()
                        - imm_y_bytes[i].clone()
                        - carry_in),
            );
            eval.add_constraint(
                is_halt_lij[0].clone()
                    * (lij_addr[i].clone()
                        - E::F::from(BaseField::from(PVM_HALT_ADDR_BYTES[i] as u32))),
            );
            eval.add_constraint(
                is_halt_lij[0].clone()
                    * (next_pc[i].clone()
                        - E::F::from(BaseField::from(PVM_HALT_ADDR_BYTES[i] as u32))),
            );
        }
        eval.add_constraint(is_halt_lij[0].clone() * (E::F::one() - is_padding_next[0].clone()));
        // Paired JumpTable consumer.
        let mut lij_tuple: Vec<E::F> = lij_addr.to_vec();
        lij_tuple.extend_from_slice(&next_pc);
        eval.add_to_relation(RelationEntry::new(
            jump_table_lookup,
            (is_lij_col[0].clone() - is_halt_lij[0].clone()).into(),
            &lij_tuple,
        ));
        eval.add_to_relation(RelationEntry::new(
            jump_table_lookup,
            (is_lij_col[0].clone() - is_halt_lij[0].clone()).into(),
            &lij_tuple,
        ));
    }
}
