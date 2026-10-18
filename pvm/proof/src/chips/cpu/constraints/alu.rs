//! Add, Sub, Mul and Move, and their selector helpers.
use num_traits::{One, Zero};
use stwo::core::fields::m31::BaseField;
use stwo_constraint_framework::EvalAtRow;

use super::Row;
use crate::core::step::WORD_SIZE;

/// The Add, Sub and 32-bit Mul selector helpers.
pub(in crate::chips::cpu) fn selector_helpers<E: EvalAtRow>(eval: &mut E, row: &Row<E::F>) {
    let is_64bit = E::F::one() - row.is32_bit[0].clone();
    // ── Selector helpers (Add/Sub/Mul-sign-ext) ──
    // Helper-defining constraints (deg 2 each).
    eval.add_constraint(row.is_add64bit_h[0].clone() - row.is_add[0].clone() * is_64bit.clone());
    eval.add_constraint(
        row.is_add32bit_h[0].clone() - row.is_add[0].clone() * row.is32_bit[0].clone(),
    );
    eval.add_constraint(
        row.is_sub_not_negadd_h[0].clone()
            - row.is_sub[0].clone() * (E::F::one() - row.is_neg_add[0].clone()),
    );
    eval.add_constraint(
        row.is_sub_negadd_h[0].clone() - row.is_sub[0].clone() * row.is_neg_add[0].clone(),
    );
    eval.add_constraint(
        row.is_sub64_not_negadd_h[0].clone()
            - row.is_sub_not_negadd_h[0].clone() * is_64bit.clone(),
    );
    eval.add_constraint(
        row.is_sub64_negadd_h[0].clone() - row.is_sub_negadd_h[0].clone() * is_64bit.clone(),
    );
    eval.add_constraint(
        row.is_sub32bit_h[0].clone() - row.is_sub[0].clone() * row.is32_bit[0].clone(),
    );
    eval.add_constraint(
        row.is_mul32bit_h[0].clone() - row.is_mul[0].clone() * row.is32_bit[0].clone(),
    );
}

/// Add: a byte-wise carry chain, sign-extended on 32-bit rows.
pub(in crate::chips::cpu) fn add<E: EvalAtRow>(eval: &mut E, row: &Row<E::F>) {
    let ff: E::F = E::F::from(BaseField::from(255));
    let f256 = E::F::from(BaseField::from(256u32));
    // ════════════════════════════════════════════════════════════════════
    // ADD: result[i] + carry[i]*256 = val_b[i] + val_d[i] + carry[i-1]
    // ════════════════════════════════════════════════════════════════════
    // The carries are bits on every row: a field-valued carry solves any
    // byte equation, for any result.
    for c in row.carry.iter() {
        eval.add_constraint(c.clone() * (E::F::one() - c.clone()));
    }
    for i in 0..WORD_SIZE {
        let carry_in = if i == 0 {
            E::F::zero()
        } else {
            row.carry[i - 1].clone()
        };
        let c = row.result[i].clone() + row.carry[i].clone() * f256.clone()
            - row.val_b[i].clone()
            - row.val_d[i].clone()
            - carry_in;
        if i < 4 {
            eval.add_constraint(row.is_add[0].clone() * c);
        } else {
            eval.add_constraint(row.is_add64bit_h[0].clone() * c);
        }
    }
    // `result[4..8] = 0xFF · SignBitResult` on 32-bit Add rows.
    for i in 4..WORD_SIZE {
        eval.add_constraint(
            row.is_add32bit_h[0].clone()
                * (row.result[i].clone() - ff.clone() * row.sign_bit_result[0].clone()),
        );
    }
}

/// Sub: two's-complement addition, sign-extended on 32-bit rows.
pub(in crate::chips::cpu) fn sub<E: EvalAtRow>(eval: &mut E, row: &Row<E::F>) {
    let ff: E::F = E::F::from(BaseField::from(255));
    let f256 = E::F::from(BaseField::from(256u32));
    let f255 = E::F::from(BaseField::from(255u32));
    // ════════════════════════════════════════════════════════════════════
    // SUB: two's complement addition a + ~b + 1
    // ════════════════════════════════════════════════════════════════════
    for i in 0..WORD_SIZE {
        let carry_in = if i == 0 {
            E::F::one()
        } else {
            row.carry[i - 1].clone()
        };
        let c_normal = row.result[i].clone() + row.carry[i].clone() * f256.clone()
            - row.val_b[i].clone()
            - f255.clone()
            + row.val_d[i].clone()
            - carry_in.clone();
        let c_neg = row.result[i].clone() + row.carry[i].clone() * f256.clone()
            - row.val_d[i].clone()
            - f255.clone()
            + row.val_b[i].clone()
            - carry_in;
        if i < 4 {
            eval.add_constraint(row.is_sub_not_negadd_h[0].clone() * c_normal);
            eval.add_constraint(row.is_sub_negadd_h[0].clone() * c_neg);
        } else {
            eval.add_constraint(row.is_sub64_not_negadd_h[0].clone() * c_normal);
            eval.add_constraint(row.is_sub64_negadd_h[0].clone() * c_neg);
        }
    }
    for i in 4..WORD_SIZE {
        eval.add_constraint(
            row.is_sub32bit_h[0].clone()
                * (row.result[i].clone() - ff.clone() * row.sign_bit_result[0].clone()),
        );
    }
}

/// 32-bit Mul: the result sign-extended; the product itself is bound through MulChip.
pub(in crate::chips::cpu) fn mul<E: EvalAtRow>(eval: &mut E, row: &Row<E::F>) {
    let ff: E::F = E::F::from(BaseField::from(255));
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
            row.is_mul32bit_h[0].clone()
                * (row.result[i].clone() - ff.clone() * row.sign_bit_result[0].clone()),
        );
    }
}

/// ImmAlt shifts and rotates: `val_b` is the immediate.
pub(in crate::chips::cpu) fn imm_alt_operands<E: EvalAtRow>(eval: &mut E, row: &Row<E::F>) {
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
        // Helpers for the 3-factor selectors below.
        eval.add_constraint(
            row.is_imm_alt_not_trunc_h[0].clone()
                - row.is_imm_alt[0].clone() * (E::F::one() - row.is_truncated[0].clone()),
        );
        eval.add_constraint(
            row.is_imm_alt_trunc_h[0].clone()
                - row.is_imm_alt[0].clone() * row.is_truncated[0].clone(),
        );
        for i in 0..4 {
            eval.add_constraint(
                row.is_imm_alt[0].clone() * (row.val_b[i].clone() - row.imm_bytes[i].clone()),
            );
        }
        for i in 4..WORD_SIZE {
            eval.add_constraint(
                row.is_imm_alt_not_trunc_h[0].clone()
                    * (row.val_b[i].clone() - row.imm_bytes[i].clone()),
            );
            eval.add_constraint(row.is_imm_alt_trunc_h[0].clone() * row.val_b[i].clone());
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
        // Lift `is_32bit · is_shift_c` to a deg-1 helper.
        eval.add_constraint(
            row.is32_shift_ch[0].clone()
                - row.is32_bit[0].clone() * row.is_shift_constrained[0].clone(),
        );
        for i in 4..WORD_SIZE {
            eval.add_constraint(row.is32_shift_ch[0].clone() * row.val_d[i].clone());
        }
    }
}

/// Move: the result is `val_d`.
pub(in crate::chips::cpu) fn move_reg<E: EvalAtRow>(eval: &mut E, row: &Row<E::F>) {
    // ════════════════════════════════════════════════════════════════════
    // MOVE: result = val_d
    // ════════════════════════════════════════════════════════════════════
    for i in 0..WORD_SIZE {
        eval.add_constraint(
            row.is_move[0].clone() * (row.result[i].clone() - row.val_d[i].clone()),
        );
    }
}
