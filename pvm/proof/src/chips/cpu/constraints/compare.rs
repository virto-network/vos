//! Compares: the signed less-than flag and each compare op's result.
use num_traits::One;
use stwo::core::fields::m31::BaseField;
use stwo_constraint_framework::EvalAtRow;

use super::{Row, is_branch, is_compare};
use crate::core::step::WORD_SIZE;

/// The compare and DivRem-binding helpers.
pub(in crate::chips::cpu) fn compare_and_divrem_helpers<E: EvalAtRow>(
    eval: &mut E,
    row: &Row<E::F>,
) {
    // ── Compare / DivRem-binding helpers ──
    // SignsDiffH defined further down once sign_b/sign_d columns are
    // referenced.  Defined here using the existing column refs.
    {
        // SignsDiff = sb + sd - 2·sb·sd.
        eval.add_constraint(
            row.signs_diff_h[0].clone()
                - (row.sign_bit_b[0].clone() + row.sign_bit_d[0].clone()
                    - E::F::from(BaseField::from(2u32))
                        * row.sign_bit_b[0].clone()
                        * row.sign_bit_d[0].clone()),
        );
    }
    // ValDIsZero is a column; IsCompare/IsCmovIz/IsCmovNz selectors
    // are sums of column refs (deg 1).  Helpers below all deg 2 def.
    eval.add_constraint(
        row.is_cmp_vdz_h[0].clone() - is_compare(row) * row.val_d_is_zero[0].clone(),
    );
    eval.add_constraint(
        row.is_cmov_iz_vdz_h[0].clone() - row.is_cmov_iz[0].clone() * row.val_d_is_zero[0].clone(),
    );
    eval.add_constraint(
        row.is_cmov_nz_not_vdz_h[0].clone()
            - row.is_cmov_nz[0].clone() * (E::F::one() - row.val_d_is_zero[0].clone()),
    );
    // A min or max selects by its less-than, signed on MinS/MaxS rows.
    eval.add_constraint(
        row.min_max_lt_flag[0].clone()
            - row.cmp_lt_flag[0].clone()
            - (row.is_min_s[0].clone() + row.is_max_s[0].clone())
                * (row.cmp_lt_s_flag[0].clone() - row.cmp_lt_flag[0].clone()),
    );
    for i in 0..WORD_SIZE {
        eval.add_constraint(
            row.cmp_lt_val_bh[i].clone() - row.min_max_lt_flag[0].clone() * row.val_b[i].clone(),
        );
        eval.add_constraint(
            row.cmp_lt_val_dh[i].clone() - row.min_max_lt_flag[0].clone() * row.val_d[i].clone(),
        );
    }
    // DivRem helpers.
    eval.add_constraint(
        row.cpu_div_active_h[0].clone()
            - row.is_div_rem[0].clone() * (E::F::one() - row.div_by_zero[0].clone()),
    );
    let drop2_for_h = row.div_rem_op[0].clone() - E::F::from(BaseField::from(2u32));
    let drop3_for_h = row.div_rem_op[0].clone() - E::F::from(BaseField::from(3u32));
    eval.add_constraint(row.gate_div_h[0].clone() - drop2_for_h.clone() * drop3_for_h.clone());
    eval.add_constraint(
        row.gate_rem_h[0].clone()
            - row.div_rem_op[0].clone() * (row.div_rem_op[0].clone() - E::F::one()),
    );
    eval.add_constraint(
        row.div_active_quot_h[0].clone()
            - row.cpu_div_active_h[0].clone() * row.gate_div_h[0].clone(),
    );
    eval.add_constraint(
        row.div_active_rem_h[0].clone()
            - row.cpu_div_active_h[0].clone() * row.gate_rem_h[0].clone(),
    );
    eval.add_constraint(
        row.is_div_rem32bit_h[0].clone() - row.is_div_rem[0].clone() * row.is32_bit[0].clone(),
    );
}

/// Compare: the signed less-than flag and the result of each compare op.
pub(in crate::chips::cpu) fn compare<E: EvalAtRow>(eval: &mut E, row: &Row<E::F>) {
    // MulUpper SS/SU sign-correction lives in MulChip.  CpuChip's
    // mu_uu/mu_su/mu_ss flags + sign_bit_b/d values are sent through the
    // MultiplicationLookup tuple so MulChip's constraint binds against
    // them.  CpuChip's result on `is_mul_upper` rows is consumed by
    // MulChip's sign-correction chain (which proves it equals
    // unsigned_product_hi − sa·val_d − sb·val_b mod 2^64).

    // BITWISE result-binding lives in BitwiseChip.  CpuChip's `result`
    // on bitwise rows is bound via the BitwiseLookup tuple (val_b,
    // val_d, result + 6 sub-flags) to BitwiseChip's `result`, which is
    // pinned by BitwiseChip's per-op identity + the 16 nibble-AND
    // lookups.

    // COMPARE: SetLtU via subtraction carry analysis
    // cmp_carry chain: val_b + ~val_d + 1 (same as sub)
    // cmp_lt_flag = 1 - cmp_carry[7] (unsigned: a < b iff no final carry)
    // SetLtU: result = cmp_lt_flag, zero-extended.
    // SetLtS: result = cmp_lt_s_flag, bound below by the sign bits.
    // CmovIz/Nz and Min/Max: result bound below to the selected operand.
    let is_cmp_or_branch = is_compare(row) + is_branch(row);
    // The cmp_carry chain + cmp_lt_flag derivation live in CompareChip.
    // CpuChip's cmp_lt_flag is bound via the CompareLookup tuple to
    // CompareChip's pinned value.
    // Constrain cmp_lt_s_flag via sign-bit analysis (also for branches).
    // SignsDiffH lifts the per-row deg-2 `signs_differ` into a column
    // ref so the gated constraint is deg 2.
    {
        let expected_s = row.signs_diff_h[0].clone() * row.sign_bit_b[0].clone()
            + (E::F::one() - row.signs_diff_h[0].clone()) * row.cmp_lt_flag[0].clone();
        eval.add_constraint(is_cmp_or_branch.clone() * (row.cmp_lt_s_flag[0].clone() - expected_s));
    }
    // Compare sub-ops use per-op flag columns (flattened to deg 2).
    {
        // Constrain val_d_is_zero: gated via IsCmpVdzH (deg 1 helper).
        for i in 0..WORD_SIZE {
            eval.add_constraint(row.is_cmp_vdz_h[0].clone() * row.val_d[i].clone());
        }

        // SetLtU: result = cmp_lt_flag (zero-extended)
        eval.add_constraint(
            row.is_set_lt_u[0].clone() * (row.result[0].clone() - row.cmp_lt_flag[0].clone()),
        );
        for i in 1..WORD_SIZE {
            eval.add_constraint(row.is_set_lt_u[0].clone() * row.result[i].clone());
        }

        // SetLtS: result = cmp_lt_s_flag (zero-extended)
        {
            let expected_s = row.signs_diff_h[0].clone() * row.sign_bit_b[0].clone()
                + (E::F::one() - row.signs_diff_h[0].clone()) * row.cmp_lt_flag[0].clone();
            eval.add_constraint(
                row.is_set_lt_s[0].clone() * (row.cmp_lt_s_flag[0].clone() - expected_s),
            );

            eval.add_constraint(
                row.is_set_lt_s[0].clone() * (row.result[0].clone() - row.cmp_lt_s_flag[0].clone()),
            );
            for i in 1..WORD_SIZE {
                eval.add_constraint(row.is_set_lt_s[0].clone() * row.result[i].clone());
            }
        }

        // SetGt operand swap: on SetGtSImm/SetGtUImm rows, val_b holds the
        // immediate (the register is routed to val_d via ValDIsReg). Pin
        // val_b to the canonical ImmBytes so the SetLt comparison computes
        // (imm < reg) = (reg > imm) — the greater-than result, which the
        // is_set_lt_s/u result constraints above then write to `result`.
        // SetGt is a 64-bit compare (no truncation), so all 8 bytes bind.
        {
            // Boolean.
            eval.add_constraint(
                row.is_set_gt[0].clone() * (E::F::one() - row.is_set_gt[0].clone()),
            );
            for i in 0..WORD_SIZE {
                eval.add_constraint(
                    row.is_set_gt[0].clone() * (row.val_b[i].clone() - row.imm_bytes[i].clone()),
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
            // Boolean.
            eval.add_constraint(
                row.is_cmov_imm[0].clone() * (E::F::one() - row.is_cmov_imm[0].clone()),
            );
            for i in 0..WORD_SIZE {
                eval.add_constraint(
                    row.is_cmov_imm[0].clone() * (row.val_b[i].clone() - row.imm_bytes[i].clone()),
                );
            }
        }

        // CmovIz / CmovNz — gated via the per-condition helpers.
        for i in 0..WORD_SIZE {
            eval.add_constraint(
                row.is_cmov_iz_vdz_h[0].clone() * (row.result[i].clone() - row.val_b[i].clone()),
            );
            eval.add_constraint(
                row.is_cmov_nz_not_vdz_h[0].clone()
                    * (row.result[i].clone() - row.val_b[i].clone()),
            );
        }

        // Min/Max, unsigned and signed — body lifted into CmpLtValBH /
        // CmpLtValDH so the result-binding constraint becomes deg 2
        // (selector × linear).
        let is_min = row.is_min_u[0].clone() + row.is_min_s[0].clone();
        let is_max = row.is_max_u[0].clone() + row.is_max_s[0].clone();
        for i in 0..WORD_SIZE {
            let expected_min =
                row.cmp_lt_val_bh[i].clone() + row.val_d[i].clone() - row.cmp_lt_val_dh[i].clone();
            eval.add_constraint(is_min.clone() * (row.result[i].clone() - expected_min));
            let expected_max =
                row.cmp_lt_val_dh[i].clone() + row.val_b[i].clone() - row.cmp_lt_val_bh[i].clone();
            eval.add_constraint(is_max.clone() * (row.result[i].clone() - expected_max));
        }
    }
}
