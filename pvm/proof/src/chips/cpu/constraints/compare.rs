//! Compares: the signed less-than flag and each compare op's result.
use num_traits::One;
use stwo::core::fields::m31::BaseField;
use stwo_constraint_framework::EvalAtRow;

use super::{Trace, is_branch, is_compare};
use crate::chips::cpu::columns::Column;
use crate::core::step::WORD_SIZE;

/// The compare and DivRem-binding helpers.
pub(in crate::chips::cpu) fn compare_and_divrem_helpers<E: EvalAtRow>(
    eval: &mut E,
    trace_eval: &Trace<E>,
) {
    let is_32bit = crate::trace::trace_eval!(trace_eval, Column::Is32Bit);
    let val_b = crate::trace::trace_eval!(trace_eval, Column::ValB);
    let val_d = crate::trace::trace_eval!(trace_eval, Column::ValD);
    let cmp_lt_flag = crate::trace::trace_eval!(trace_eval, Column::CmpLtFlag);
    let cmp_lt_s_flag = crate::trace::trace_eval!(trace_eval, Column::CmpLtSFlag);
    let is_cmov_iz_flag = crate::trace::trace_eval!(trace_eval, Column::IsCmovIz);
    let is_cmov_nz_flag = crate::trace::trace_eval!(trace_eval, Column::IsCmovNz);
    let is_min_s_flag = crate::trace::trace_eval!(trace_eval, Column::IsMinS);
    let is_max_s_flag = crate::trace::trace_eval!(trace_eval, Column::IsMaxS);
    // ── Compare / DivRem-binding helpers ──
    let signs_diff_h = crate::trace::trace_eval!(trace_eval, Column::SignsDiffH);
    let is_cmp_vdz_h = crate::trace::trace_eval!(trace_eval, Column::IsCmpVdzH);
    let is_cmov_iz_vdz_h = crate::trace::trace_eval!(trace_eval, Column::IsCmovIzVdzH);
    let is_cmov_nz_not_vdz_h = crate::trace::trace_eval!(trace_eval, Column::IsCmovNzNotVdzH);
    let cmp_lt_val_b_h = crate::trace::trace_eval!(trace_eval, Column::CmpLtValBH);
    let cmp_lt_val_d_h = crate::trace::trace_eval!(trace_eval, Column::CmpLtValDH);
    let cpu_div_active_h = crate::trace::trace_eval!(trace_eval, Column::CpuDivActiveH);
    let gate_div_h = crate::trace::trace_eval!(trace_eval, Column::GateDivH);
    let gate_rem_h = crate::trace::trace_eval!(trace_eval, Column::GateRemH);
    let div_active_quot_h = crate::trace::trace_eval!(trace_eval, Column::DivActiveQuotH);
    let div_active_rem_h = crate::trace::trace_eval!(trace_eval, Column::DivActiveRemH);
    let is_div_rem_32_h = crate::trace::trace_eval!(trace_eval, Column::IsDivRem32bitH);
    let val_d_is_zero_for_h = crate::trace::trace_eval!(trace_eval, Column::ValDIsZero);
    // SignsDiffH defined further down once sign_b/sign_d columns are
    // referenced.  Defined here using the existing column refs.
    {
        let sb = crate::trace::trace_eval!(trace_eval, Column::SignBitB);
        let sd = crate::trace::trace_eval!(trace_eval, Column::SignBitD);
        // SignsDiff = sb + sd - 2·sb·sd.
        eval.add_constraint(
            signs_diff_h[0].clone()
                - (sb[0].clone() + sd[0].clone()
                    - E::F::from(BaseField::from(2u32)) * sb[0].clone() * sd[0].clone()),
        );
    }
    // ValDIsZero is a column; IsCompare/IsCmovIz/IsCmovNz selectors
    // are sums of column refs (deg 1).  Helpers below all deg 2 def.
    eval.add_constraint(
        is_cmp_vdz_h[0].clone() - is_compare(trace_eval) * val_d_is_zero_for_h[0].clone(),
    );
    eval.add_constraint(
        is_cmov_iz_vdz_h[0].clone() - is_cmov_iz_flag[0].clone() * val_d_is_zero_for_h[0].clone(),
    );
    eval.add_constraint(
        is_cmov_nz_not_vdz_h[0].clone()
            - is_cmov_nz_flag[0].clone() * (E::F::one() - val_d_is_zero_for_h[0].clone()),
    );
    // A min or max selects by its less-than, signed on MinS/MaxS rows.
    let min_max_lt = crate::trace::trace_eval!(trace_eval, Column::MinMaxLtFlag);
    eval.add_constraint(
        min_max_lt[0].clone()
            - cmp_lt_flag[0].clone()
            - (is_min_s_flag[0].clone() + is_max_s_flag[0].clone())
                * (cmp_lt_s_flag[0].clone() - cmp_lt_flag[0].clone()),
    );
    for i in 0..WORD_SIZE {
        eval.add_constraint(cmp_lt_val_b_h[i].clone() - min_max_lt[0].clone() * val_b[i].clone());
        eval.add_constraint(cmp_lt_val_d_h[i].clone() - min_max_lt[0].clone() * val_d[i].clone());
    }
    // DivRem helpers.
    let div_by_zero_for_h = crate::trace::trace_eval!(trace_eval, Column::DivByZero);
    let is_div_rem_for_h = crate::trace::trace_eval!(trace_eval, Column::IsDivRem);
    let div_rem_op_for_h = crate::trace::trace_eval!(trace_eval, Column::DivRemOp);
    eval.add_constraint(
        cpu_div_active_h[0].clone()
            - is_div_rem_for_h[0].clone() * (E::F::one() - div_by_zero_for_h[0].clone()),
    );
    let drop2_for_h = div_rem_op_for_h[0].clone() - E::F::from(BaseField::from(2u32));
    let drop3_for_h = div_rem_op_for_h[0].clone() - E::F::from(BaseField::from(3u32));
    eval.add_constraint(gate_div_h[0].clone() - drop2_for_h.clone() * drop3_for_h.clone());
    eval.add_constraint(
        gate_rem_h[0].clone()
            - div_rem_op_for_h[0].clone() * (div_rem_op_for_h[0].clone() - E::F::one()),
    );
    eval.add_constraint(
        div_active_quot_h[0].clone() - cpu_div_active_h[0].clone() * gate_div_h[0].clone(),
    );
    eval.add_constraint(
        div_active_rem_h[0].clone() - cpu_div_active_h[0].clone() * gate_rem_h[0].clone(),
    );
    eval.add_constraint(
        is_div_rem_32_h[0].clone() - is_div_rem_for_h[0].clone() * is_32bit[0].clone(),
    );
}

/// Compare: the signed less-than flag and the result of each compare op.
pub(in crate::chips::cpu) fn compare<E: EvalAtRow>(eval: &mut E, trace_eval: &Trace<E>) {
    let val_b = crate::trace::trace_eval!(trace_eval, Column::ValB);
    let val_d = crate::trace::trace_eval!(trace_eval, Column::ValD);
    let result = crate::trace::trace_eval!(trace_eval, Column::Result);
    let cmp_lt_flag = crate::trace::trace_eval!(trace_eval, Column::CmpLtFlag);
    let cmp_lt_s_flag = crate::trace::trace_eval!(trace_eval, Column::CmpLtSFlag);
    let is_set_lt_u_flag = crate::trace::trace_eval!(trace_eval, Column::IsSetLtU);
    let is_set_lt_s_flag = crate::trace::trace_eval!(trace_eval, Column::IsSetLtS);
    let is_min_s_flag = crate::trace::trace_eval!(trace_eval, Column::IsMinS);
    let is_min_u_flag = crate::trace::trace_eval!(trace_eval, Column::IsMinU);
    let is_max_s_flag = crate::trace::trace_eval!(trace_eval, Column::IsMaxS);
    let is_max_u_flag = crate::trace::trace_eval!(trace_eval, Column::IsMaxU);
    let signs_diff_h = crate::trace::trace_eval!(trace_eval, Column::SignsDiffH);
    let is_cmp_vdz_h = crate::trace::trace_eval!(trace_eval, Column::IsCmpVdzH);
    let is_cmov_iz_vdz_h = crate::trace::trace_eval!(trace_eval, Column::IsCmovIzVdzH);
    let is_cmov_nz_not_vdz_h = crate::trace::trace_eval!(trace_eval, Column::IsCmovNzNotVdzH);
    let cmp_lt_val_b_h = crate::trace::trace_eval!(trace_eval, Column::CmpLtValBH);
    let cmp_lt_val_d_h = crate::trace::trace_eval!(trace_eval, Column::CmpLtValDH);
    // ════════════════════════════════════════════════════════════════════
    // MulUpper SS/SU sign-correction lives in MulChip.  CpuChip's
    // mu_uu/mu_su/mu_ss flags + sign_bit_b/d values are sent through the
    // MultiplicationLookup tuple so MulChip's constraint binds against
    // them.  CpuChip's result on `is_mul_upper` rows is consumed by
    // MulChip's sign-correction chain (which proves it equals
    // unsigned_product_hi − sa·val_d − sb·val_b mod 2^64).
    // ════════════════════════════════════════════════════════════════════

    // ════════════════════════════════════════════════════════════════════
    // BITWISE result-binding lives in BitwiseChip.  CpuChip's `result`
    // on bitwise rows is bound via the BitwiseLookup tuple (val_b,
    // val_d, result + 6 sub-flags) to BitwiseChip's `result`, which is
    // pinned by BitwiseChip's per-op identity + the 16 nibble-AND
    // lookups.
    // ════════════════════════════════════════════════════════════════════

    // ════════════════════════════════════════════════════════════════════
    // COMPARE: SetLtU via subtraction carry analysis
    // cmp_carry chain: val_b + ~val_d + 1 (same as sub)
    // cmp_lt_flag = 1 - cmp_carry[7] (unsigned: a < b iff no final carry)
    // SetLtU: result = cmp_lt_flag, zero-extended.
    // SetLtS: result = cmp_lt_s_flag, bound below by the sign bits.
    // CmovIz/Nz and Min/Max: result bound below to the selected operand.
    // ════════════════════════════════════════════════════════════════════
    let is_cmp_or_branch = is_compare(trace_eval) + is_branch(trace_eval);
    // The cmp_carry chain + cmp_lt_flag derivation live in CompareChip.
    // CpuChip's cmp_lt_flag is bound via the CompareLookup tuple to
    // CompareChip's pinned value.
    // Constrain cmp_lt_s_flag via sign-bit analysis (also for branches).
    // SignsDiffH lifts the per-row deg-2 `signs_differ` into a column
    // ref so the gated constraint is deg 2.
    {
        let sign_b_b = crate::trace::trace_eval!(trace_eval, Column::SignBitB);
        let expected_s = signs_diff_h[0].clone() * sign_b_b[0].clone()
            + (E::F::one() - signs_diff_h[0].clone()) * cmp_lt_flag[0].clone();
        eval.add_constraint(is_cmp_or_branch.clone() * (cmp_lt_s_flag[0].clone() - expected_s));
    }
    // Compare sub-ops use per-op flag columns (flattened to deg 2).
    {
        // Constrain val_d_is_zero: gated via IsCmpVdzH (deg 1 helper).
        for i in 0..WORD_SIZE {
            eval.add_constraint(is_cmp_vdz_h[0].clone() * val_d[i].clone());
        }

        // SetLtU: result = cmp_lt_flag (zero-extended)
        eval.add_constraint(
            is_set_lt_u_flag[0].clone() * (result[0].clone() - cmp_lt_flag[0].clone()),
        );
        for i in 1..WORD_SIZE {
            eval.add_constraint(is_set_lt_u_flag[0].clone() * result[i].clone());
        }

        // SetLtS: result = cmp_lt_s_flag (zero-extended)
        {
            let cmp_lt_s_flag = crate::trace::trace_eval!(trace_eval, Column::CmpLtSFlag);
            let sign_b = crate::trace::trace_eval!(trace_eval, Column::SignBitB);

            let expected_s = signs_diff_h[0].clone() * sign_b[0].clone()
                + (E::F::one() - signs_diff_h[0].clone()) * cmp_lt_flag[0].clone();
            eval.add_constraint(
                is_set_lt_s_flag[0].clone() * (cmp_lt_s_flag[0].clone() - expected_s),
            );

            eval.add_constraint(
                is_set_lt_s_flag[0].clone() * (result[0].clone() - cmp_lt_s_flag[0].clone()),
            );
            for i in 1..WORD_SIZE {
                eval.add_constraint(is_set_lt_s_flag[0].clone() * result[i].clone());
            }
        }

        // SetGt operand swap: on SetGtSImm/SetGtUImm rows, val_b holds the
        // immediate (the register is routed to val_d via ValDIsReg). Pin
        // val_b to the canonical ImmBytes so the SetLt comparison computes
        // (imm < reg) = (reg > imm) — the greater-than result, which the
        // is_set_lt_s/u result constraints above then write to `result`.
        // SetGt is a 64-bit compare (no truncation), so all 8 bytes bind.
        {
            let is_set_gt_flag = crate::trace::trace_eval!(trace_eval, Column::IsSetGt);
            let imm_bytes_sg = crate::trace::trace_eval!(trace_eval, Column::ImmBytes);
            // Boolean.
            eval.add_constraint(
                is_set_gt_flag[0].clone() * (E::F::one() - is_set_gt_flag[0].clone()),
            );
            for i in 0..WORD_SIZE {
                eval.add_constraint(
                    is_set_gt_flag[0].clone() * (val_b[i].clone() - imm_bytes_sg[i].clone()),
                );
            }
        }

        // CmovIzImm/CmovNzImm operand swap: the register cmov convention
        // puts the moved value in val_b and the condition in val_d (which
        // ValDIsZero gates), but the imm variants move the IMMEDIATE
        // guarded by regs[rb]. The swap routes the condition register to
        // val_d (via ValDIsReg) and pins val_b to the canonical ImmBytes
        // so the gated `result = val_b` constraints below bind the real
        // moved value. Full 8 bytes bind — the imm is the 64-bit value
        // written to the destination.
        {
            let is_cmov_imm_flag = crate::trace::trace_eval!(trace_eval, Column::IsCmovImm);
            let imm_bytes_ci = crate::trace::trace_eval!(trace_eval, Column::ImmBytes);
            // Boolean.
            eval.add_constraint(
                is_cmov_imm_flag[0].clone() * (E::F::one() - is_cmov_imm_flag[0].clone()),
            );
            for i in 0..WORD_SIZE {
                eval.add_constraint(
                    is_cmov_imm_flag[0].clone() * (val_b[i].clone() - imm_bytes_ci[i].clone()),
                );
            }
        }

        // CmovIz / CmovNz — gated via the per-condition helpers.
        for i in 0..WORD_SIZE {
            eval.add_constraint(
                is_cmov_iz_vdz_h[0].clone() * (result[i].clone() - val_b[i].clone()),
            );
            eval.add_constraint(
                is_cmov_nz_not_vdz_h[0].clone() * (result[i].clone() - val_b[i].clone()),
            );
        }

        // Min/Max, unsigned and signed — body lifted into CmpLtValBH /
        // CmpLtValDH so the result-binding constraint becomes deg 2
        // (selector × linear).
        let is_min = is_min_u_flag[0].clone() + is_min_s_flag[0].clone();
        let is_max = is_max_u_flag[0].clone() + is_max_s_flag[0].clone();
        for i in 0..WORD_SIZE {
            let expected_min =
                cmp_lt_val_b_h[i].clone() + val_d[i].clone() - cmp_lt_val_d_h[i].clone();
            eval.add_constraint(is_min.clone() * (result[i].clone() - expected_min));
            let expected_max =
                cmp_lt_val_d_h[i].clone() + val_b[i].clone() - cmp_lt_val_b_h[i].clone();
            eval.add_constraint(is_max.clone() * (result[i].clone() - expected_max));
        }
    }
}
