//! Add, Sub, Mul and Move, and their selector helpers.
use num_traits::{One, Zero};
use stwo::core::fields::m31::BaseField;
use stwo_constraint_framework::EvalAtRow;

use super::Trace;
use crate::chips::cpu::columns::Column;
use crate::core::step::WORD_SIZE;

/// The Add, Sub and 32-bit Mul selector helpers.
pub(in crate::chips::cpu) fn selector_helpers<E: EvalAtRow>(eval: &mut E, trace_eval: &Trace<E>) {
    let is_add = crate::trace::trace_eval!(trace_eval, Column::IsAdd);
    let is_sub = crate::trace::trace_eval!(trace_eval, Column::IsSub);
    let is_mul = crate::trace::trace_eval!(trace_eval, Column::IsMul);
    let is_neg_add = crate::trace::trace_eval!(trace_eval, Column::IsNegAdd);
    let is_32bit = crate::trace::trace_eval!(trace_eval, Column::Is32Bit);
    let is_64bit = E::F::one() - is_32bit[0].clone();
    // ── Selector helpers (Add/Sub/Mul-sign-ext) ──
    let is_add_64_h = crate::trace::trace_eval!(trace_eval, Column::IsAdd64bitH);
    let is_add_32_h = crate::trace::trace_eval!(trace_eval, Column::IsAdd32bitH);
    let is_sub_not_negadd_h = crate::trace::trace_eval!(trace_eval, Column::IsSubNotNegaddH);
    let is_sub_negadd_h = crate::trace::trace_eval!(trace_eval, Column::IsSubNegaddH);
    let is_sub_64_not_negadd_h = crate::trace::trace_eval!(trace_eval, Column::IsSub64NotNegaddH);
    let is_sub_64_negadd_h = crate::trace::trace_eval!(trace_eval, Column::IsSub64NegaddH);
    let is_sub_32_h = crate::trace::trace_eval!(trace_eval, Column::IsSub32bitH);
    let is_mul_32_h = crate::trace::trace_eval!(trace_eval, Column::IsMul32bitH);
    // Helper-defining constraints (deg 2 each).
    eval.add_constraint(is_add_64_h[0].clone() - is_add[0].clone() * is_64bit.clone());
    eval.add_constraint(is_add_32_h[0].clone() - is_add[0].clone() * is_32bit[0].clone());
    eval.add_constraint(
        is_sub_not_negadd_h[0].clone() - is_sub[0].clone() * (E::F::one() - is_neg_add[0].clone()),
    );
    eval.add_constraint(is_sub_negadd_h[0].clone() - is_sub[0].clone() * is_neg_add[0].clone());
    eval.add_constraint(
        is_sub_64_not_negadd_h[0].clone() - is_sub_not_negadd_h[0].clone() * is_64bit.clone(),
    );
    eval.add_constraint(
        is_sub_64_negadd_h[0].clone() - is_sub_negadd_h[0].clone() * is_64bit.clone(),
    );
    eval.add_constraint(is_sub_32_h[0].clone() - is_sub[0].clone() * is_32bit[0].clone());
    eval.add_constraint(is_mul_32_h[0].clone() - is_mul[0].clone() * is_32bit[0].clone());
}

/// Add: a byte-wise carry chain, sign-extended on 32-bit rows.
pub(in crate::chips::cpu) fn add<E: EvalAtRow>(eval: &mut E, trace_eval: &Trace<E>) {
    let is_add = crate::trace::trace_eval!(trace_eval, Column::IsAdd);
    let val_b = crate::trace::trace_eval!(trace_eval, Column::ValB);
    let val_d = crate::trace::trace_eval!(trace_eval, Column::ValD);
    let result = crate::trace::trace_eval!(trace_eval, Column::Result);
    let sign_bit_result_p19 = crate::trace::trace_eval!(trace_eval, Column::SignBitResult);
    let f_ff_p19: E::F = E::F::from(BaseField::from(255));
    let carry = crate::trace::trace_eval!(trace_eval, Column::Carry);
    let f256 = E::F::from(BaseField::from(256u32));
    let is_add_64_h = crate::trace::trace_eval!(trace_eval, Column::IsAdd64bitH);
    let is_add_32_h = crate::trace::trace_eval!(trace_eval, Column::IsAdd32bitH);
    // ════════════════════════════════════════════════════════════════════
    // ADD: result[i] + carry[i]*256 = val_b[i] + val_d[i] + carry[i-1]
    // ════════════════════════════════════════════════════════════════════
    // The carries are bits on every row: a field-valued carry solves any
    // byte equation, for any result.
    for c in carry.iter() {
        eval.add_constraint(c.clone() * (E::F::one() - c.clone()));
    }
    for i in 0..WORD_SIZE {
        let carry_in = if i == 0 {
            E::F::zero()
        } else {
            carry[i - 1].clone()
        };
        let c = result[i].clone() + carry[i].clone() * f256.clone()
            - val_b[i].clone()
            - val_d[i].clone()
            - carry_in;
        if i < 4 {
            eval.add_constraint(is_add[0].clone() * c);
        } else {
            eval.add_constraint(is_add_64_h[0].clone() * c);
        }
    }
    // `result[4..8] = 0xFF · SignBitResult` on 32-bit Add rows.
    for i in 4..WORD_SIZE {
        eval.add_constraint(
            is_add_32_h[0].clone()
                * (result[i].clone() - f_ff_p19.clone() * sign_bit_result_p19[0].clone()),
        );
    }
}

/// Sub: two's-complement addition, sign-extended on 32-bit rows.
pub(in crate::chips::cpu) fn sub<E: EvalAtRow>(eval: &mut E, trace_eval: &Trace<E>) {
    let val_b = crate::trace::trace_eval!(trace_eval, Column::ValB);
    let val_d = crate::trace::trace_eval!(trace_eval, Column::ValD);
    let result = crate::trace::trace_eval!(trace_eval, Column::Result);
    let sign_bit_result_p19 = crate::trace::trace_eval!(trace_eval, Column::SignBitResult);
    let f_ff_p19: E::F = E::F::from(BaseField::from(255));
    let carry = crate::trace::trace_eval!(trace_eval, Column::Carry);
    let f256 = E::F::from(BaseField::from(256u32));
    let f255 = E::F::from(BaseField::from(255u32));
    let is_sub_not_negadd_h = crate::trace::trace_eval!(trace_eval, Column::IsSubNotNegaddH);
    let is_sub_negadd_h = crate::trace::trace_eval!(trace_eval, Column::IsSubNegaddH);
    let is_sub_64_not_negadd_h = crate::trace::trace_eval!(trace_eval, Column::IsSub64NotNegaddH);
    let is_sub_64_negadd_h = crate::trace::trace_eval!(trace_eval, Column::IsSub64NegaddH);
    let is_sub_32_h = crate::trace::trace_eval!(trace_eval, Column::IsSub32bitH);
    // ════════════════════════════════════════════════════════════════════
    // SUB: two's complement addition a + ~b + 1
    // ════════════════════════════════════════════════════════════════════
    for i in 0..WORD_SIZE {
        let carry_in = if i == 0 {
            E::F::one()
        } else {
            carry[i - 1].clone()
        };
        let c_normal =
            result[i].clone() + carry[i].clone() * f256.clone() - val_b[i].clone() - f255.clone()
                + val_d[i].clone()
                - carry_in.clone();
        let c_neg =
            result[i].clone() + carry[i].clone() * f256.clone() - val_d[i].clone() - f255.clone()
                + val_b[i].clone()
                - carry_in;
        if i < 4 {
            eval.add_constraint(is_sub_not_negadd_h[0].clone() * c_normal);
            eval.add_constraint(is_sub_negadd_h[0].clone() * c_neg);
        } else {
            eval.add_constraint(is_sub_64_not_negadd_h[0].clone() * c_normal);
            eval.add_constraint(is_sub_64_negadd_h[0].clone() * c_neg);
        }
    }
    for i in 4..WORD_SIZE {
        eval.add_constraint(
            is_sub_32_h[0].clone()
                * (result[i].clone() - f_ff_p19.clone() * sign_bit_result_p19[0].clone()),
        );
    }
}

/// 32-bit Mul: the result sign-extended; the product itself is bound through MulChip.
pub(in crate::chips::cpu) fn mul<E: EvalAtRow>(eval: &mut E, trace_eval: &Trace<E>) {
    let result = crate::trace::trace_eval!(trace_eval, Column::Result);
    let sign_bit_result_p19 = crate::trace::trace_eval!(trace_eval, Column::SignBitResult);
    let f_ff_p19: E::F = E::F::from(BaseField::from(255));
    let is_mul_32_h = crate::trace::trace_eval!(trace_eval, Column::IsMul32bitH);
    // ════════════════════════════════════════════════════════════════════
    // MUL: CpuChip witnesses UnsignedProductLow/Hi/MulHigh (used by the
    // result-variant binding below); their values are pinned by lookup
    // balance to MulChip's carry-chain-pinned witnesses.
    // ════════════════════════════════════════════════════════════════════
    // The result-variant binding lives in MulChip.  CpuChip keeps the
    // 32-bit sign-extension on result high bytes since it reads only
    // result + sign_bit_result (both CpuChip columns).
    // 32-bit mul: upper result limbs (i ∈ 4..8) = 0xFF · SignBitResult
    // (sign-extension).
    for i in 4..WORD_SIZE {
        eval.add_constraint(
            is_mul_32_h[0].clone()
                * (result[i].clone() - f_ff_p19.clone() * sign_bit_result_p19[0].clone()),
        );
    }
}

/// ImmAlt shifts and rotates: `val_b` is the immediate.
pub(in crate::chips::cpu) fn imm_alt_operands<E: EvalAtRow>(eval: &mut E, trace_eval: &Trace<E>) {
    let is_32bit = crate::trace::trace_eval!(trace_eval, Column::Is32Bit);
    let val_b = crate::trace::trace_eval!(trace_eval, Column::ValB);
    let val_d = crate::trace::trace_eval!(trace_eval, Column::ValD);

    {
        // Pin val_b ↔ ImmBytes on the ImmAlt shift and rotate rows.
        // These swap the operand convention (immediate is the shifted
        // value, register is the shift amount), so val_b is not a
        // register read — the standard val_b ↔ reg_val_b
        // cross-constraint is inactive (val_b_is_reg=0).  Without this
        // constraint val_b would be effectively unbound.
        //
        // Shape mirrors the val_b cross-constraint:
        //   - low 4 bytes: val_b[i] = ImmBytes[i] always.
        //   - high 4 bytes: match ImmBytes when not truncated;
        //     zero when truncated (32-bit ImmAlt has IsTruncated
        //     = is_32bit · (is_mul + is_div_rem) = 1, which masks val_b high
        //     bytes to 0 in trace fill, while ImmBytes carries
        //     the sign-extended bytes from step.imm.to_le_bytes()).
        let f_is_imm_alt_p40 = crate::trace::trace_eval!(trace_eval, Column::IsImmAlt);
        let imm_bytes_p40 = crate::trace::trace_eval!(trace_eval, Column::ImmBytes);
        let is_truncated_p40 = crate::trace::trace_eval!(trace_eval, Column::IsTruncated);
        // Helpers for the 3-factor selectors below.
        let is_imm_alt_not_trunc_h =
            crate::trace::trace_eval!(trace_eval, Column::IsImmAltNotTruncH);
        let is_imm_alt_trunc_h = crate::trace::trace_eval!(trace_eval, Column::IsImmAltTruncH);
        eval.add_constraint(
            is_imm_alt_not_trunc_h[0].clone()
                - f_is_imm_alt_p40[0].clone() * (E::F::one() - is_truncated_p40[0].clone()),
        );
        eval.add_constraint(
            is_imm_alt_trunc_h[0].clone()
                - f_is_imm_alt_p40[0].clone() * is_truncated_p40[0].clone(),
        );
        for i in 0..4 {
            eval.add_constraint(
                f_is_imm_alt_p40[0].clone() * (val_b[i].clone() - imm_bytes_p40[i].clone()),
            );
        }
        for i in 4..WORD_SIZE {
            eval.add_constraint(
                is_imm_alt_not_trunc_h[0].clone() * (val_b[i].clone() - imm_bytes_p40[i].clone()),
            );
            eval.add_constraint(is_imm_alt_trunc_h[0].clone() * val_b[i].clone());
        }

        // Pin val_d high 4 bytes = 0 on ALL 32-bit shift-constrained
        // rows.  Combined with the PowerOfTwo lookup (table covers
        // shifts [0, 63]), this forces ShiftAmount / ShiftAmountCompl
        // ∈ [0, 31] uniquely — necessary for soundness because the
        // mod-32 shift identity admits two valid byte-bounded shift
        // amounts otherwise (e.g., reg_val_d = 32 → ShiftAmount = 0
        // with ShiftQuotient = 1, or ShiftAmount = 32 with
        // ShiftQuotient = 0; the first gives val_d = 1, the second
        // val_d = 2^32, and the schoolbook produces different results
        // between the two).  The gate `is_32bit · is_shift_c` covers
        // all 32-bit shift-constrained rows (ShloL32/ShloR32/SharR32
        // and their Imm/ImmAlt variants as well as RotL32/RotR32).
        let is_shift_c_p37 = crate::trace::trace_eval!(trace_eval, Column::IsShiftConstrained);
        // Lift `is_32bit · is_shift_c` to a deg-1 helper.
        let is_32_shift_c_h = crate::trace::trace_eval!(trace_eval, Column::Is32ShiftCH);
        eval.add_constraint(
            is_32_shift_c_h[0].clone() - is_32bit[0].clone() * is_shift_c_p37[0].clone(),
        );
        for i in 4..WORD_SIZE {
            eval.add_constraint(is_32_shift_c_h[0].clone() * val_d[i].clone());
        }
    }
}

/// Move: the result is `val_d`.
pub(in crate::chips::cpu) fn move_reg<E: EvalAtRow>(eval: &mut E, trace_eval: &Trace<E>) {
    let is_move = crate::trace::trace_eval!(trace_eval, Column::IsMove);
    let val_d = crate::trace::trace_eval!(trace_eval, Column::ValD);
    let result = crate::trace::trace_eval!(trace_eval, Column::Result);
    // ════════════════════════════════════════════════════════════════════
    // MOVE: result = val_d
    // ════════════════════════════════════════════════════════════════════
    for i in 0..WORD_SIZE {
        eval.add_constraint(is_move[0].clone() * (result[i].clone() - val_d[i].clone()));
    }
}
