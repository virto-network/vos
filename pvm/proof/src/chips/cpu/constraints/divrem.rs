//! DivRem: the result, the zero-divisor check and the remainder's sign.
use num_traits::One;
use stwo::core::fields::m31::BaseField;
use stwo_constraint_framework::EvalAtRow;

use super::Trace;
use crate::chips::cpu::columns::Column;
use crate::core::step::WORD_SIZE;

/// The ValDIsZero and division-by-zero helpers.
pub(in crate::chips::cpu) fn zero_divisor_helpers<E: EvalAtRow>(
    eval: &mut E,
    trace_eval: &Trace<E>,
) {
    let is_32bit = crate::trace::trace_eval!(trace_eval, Column::Is32Bit);
    let val_d = crate::trace::trace_eval!(trace_eval, Column::ValD);
    let gate_div_h = crate::trace::trace_eval!(trace_eval, Column::GateDivH);
    let gate_rem_h = crate::trace::trace_eval!(trace_eval, Column::GateRemH);
    let val_d_is_zero_for_h = crate::trace::trace_eval!(trace_eval, Column::ValDIsZero);
    let div_by_zero_for_h = crate::trace::trace_eval!(trace_eval, Column::DivByZero);
    let is_div_rem_for_h = crate::trace::trace_eval!(trace_eval, Column::IsDivRem);
    // ── ValDIsZero / DBZ binding helpers ──
    let val_d_byte_indicator_h = crate::trace::trace_eval!(trace_eval, Column::ValDByteIndicatorH);
    let val_d_byte_ind_minus_1_h =
        crate::trace::trace_eval!(trace_eval, Column::ValDByteIndMinus1H);
    let part_nz_times_ind_h = crate::trace::trace_eval!(trace_eval, Column::PartNZTimesIndH);
    let is_div_rem_times_vdz_h = crate::trace::trace_eval!(trace_eval, Column::IsDivRemTimesVdzH);
    let dbz_active_h = crate::trace::trace_eval!(trace_eval, Column::DbzActiveH);
    let dbz_active_quot_h = crate::trace::trace_eval!(trace_eval, Column::DbzActiveQuotH);
    let dbz_active_rem_h = crate::trace::trace_eval!(trace_eval, Column::DbzActiveRemH);
    // ValDByteInv columns aren't read here directly — they're pulled
    // in within the inverse-pinning block below.  But we do define
    // helpers in terms of them at this top region for visibility:
    {
        let val_d_byte_inv_top = crate::trace::trace_eval!(trace_eval, Column::ValDByteInv);
        let val_d_partial_nz_top = crate::trace::trace_eval!(trace_eval, Column::ValDPartialNZ);
        for i in 0..WORD_SIZE {
            eval.add_constraint(
                val_d_byte_indicator_h[i].clone()
                    - val_d[i].clone() * val_d_byte_inv_top[i].clone(),
            );
            // ValDByteIndMinus1H[i] = ValD[i] · (ByteIndicator - 1)
            //                       = ValD · ByteIndicator − ValD
            eval.add_constraint(
                val_d_byte_ind_minus_1_h[i].clone()
                    - val_d[i].clone() * val_d_byte_indicator_h[i].clone()
                    + val_d[i].clone(),
            );
        }
        // PartNZTimesIndH[i] = PartialNZ[i-1] · ByteIndicator[i] for i ≥ 1.
        // Index 0 unused; default fill = 0.
        for i in 1..WORD_SIZE {
            eval.add_constraint(
                part_nz_times_ind_h[i].clone()
                    - val_d_partial_nz_top[i - 1].clone() * val_d_byte_indicator_h[i].clone(),
            );
        }
    }
    eval.add_constraint(
        is_div_rem_times_vdz_h[0].clone()
            - is_div_rem_for_h[0].clone() * val_d_is_zero_for_h[0].clone(),
    );
    eval.add_constraint(
        dbz_active_h[0].clone() - is_div_rem_for_h[0].clone() * div_by_zero_for_h[0].clone(),
    );
    eval.add_constraint(
        dbz_active_quot_h[0].clone() - dbz_active_h[0].clone() * gate_div_h[0].clone(),
    );
    eval.add_constraint(
        dbz_active_rem_h[0].clone() - dbz_active_h[0].clone() * gate_rem_h[0].clone(),
    );
    let dbz_active_rem_64_h = crate::trace::trace_eval!(trace_eval, Column::DbzActiveRem64H);
    eval.add_constraint(
        dbz_active_rem_64_h[0].clone()
            - dbz_active_rem_h[0].clone() * (E::F::one() - is_32bit[0].clone()),
    );
}

/// DivRem: the result is the quotient or the remainder, sign-extended on 32-bit rows.
pub(in crate::chips::cpu) fn divrem<E: EvalAtRow>(eval: &mut E, trace_eval: &Trace<E>) {
    let result = crate::trace::trace_eval!(trace_eval, Column::Result);
    let sign_bit_result_p19 = crate::trace::trace_eval!(trace_eval, Column::SignBitResult);
    let f_ff_p19: E::F = E::F::from(BaseField::from(255));
    let div_active_quot_h = crate::trace::trace_eval!(trace_eval, Column::DivActiveQuotH);
    let div_active_rem_h = crate::trace::trace_eval!(trace_eval, Column::DivActiveRemH);
    let is_div_rem_32_h = crate::trace::trace_eval!(trace_eval, Column::IsDivRem32bitH);
    // ════════════════════════════════════════════════════════════════════
    // SHIFT: prover-computed result checked via inverse relationship
    // For ShloL (shift_op=0): result = (val_b << shift_amount) mod 2^64
    //   Equivalently: result = val_b * 2^shift_amount mod 2^64
    //   We can't constrain multiplication by a power of 2 easily without
    //   a power-of-2 lookup table. Shifts remain prover-trusted for now.
    //   The result bytes are range-checked which prevents arbitrary values
    //   but doesn't prove the shift relationship.
    // ════════════════════════════════════════════════════════════════════

    // ════════════════════════════════════════════════════════════════════
    // DIVREM: quotient * divisor + remainder = dividend
    // dividend = val_b, divisor = val_d
    // For div (op 0,1): result = quotient. For rem (op 2,3): result = remainder.
    // When divisor == 0 (div_by_zero=1): constraint bypassed (special result).
    // ════════════════════════════════════════════════════════════════════
    let div_quotient = crate::trace::trace_eval!(trace_eval, Column::DivQuotient);
    let div_remainder = crate::trace::trace_eval!(trace_eval, Column::DivRemainder);
    // The divrem chains live in DivRemChip: the schoolbook q·d+r=b
    // chain, the r<d uniqueness chain, and the DivS sign-correction
    // chain.  CpuChip flows val_b/val_d/q/r + 4 sign bits + flags via
    // the 41-limb DivRemLookup tuple; DivCorrHi/DivCorrCarry are
    // DivRemChip-internal columns.

    // Gate via DivActiveQuotH / DivActiveRemH / IsDivRem32bitH (each a
    // deg-1 helper) so result-binding constraints sit at deg 2.

    // For div ops (op ∈ {0, 1}): result = quotient.
    for i in 0..WORD_SIZE {
        eval.add_constraint(
            div_active_quot_h[0].clone() * (result[i].clone() - div_quotient[i].clone()),
        );
    }

    // For rem ops (op ∈ {2, 3}): result = remainder.
    for i in 0..WORD_SIZE {
        eval.add_constraint(
            div_active_rem_h[0].clone() * (result[i].clone() - div_remainder[i].clone()),
        );
    }

    // 32-bit: upper result limbs match the sign-extension pattern.
    for i in 4..WORD_SIZE {
        eval.add_constraint(
            is_div_rem_32_h[0].clone()
                * (result[i].clone() - f_ff_p19.clone() * sign_bit_result_p19[0].clone()),
        );
    }

    // ════════════════════════════════════════════════════════════════════
    // The DivU r<d uniqueness chain lives in DivRemChip.  The
    // DivRemLookup tuple flows is_div_s alongside
    // is_div_rem/div_by_zero/is_32bit; DivRemChip witnesses
    // DivCmpDiff[8]/DivCmpCarry[8] internally and emits the Range256
    // lookups on its own (narrower) trace.
}

/// The byte-wise zero check of `val_d` and the division-by-zero result.
pub(in crate::chips::cpu) fn zero_divisor<E: EvalAtRow>(eval: &mut E, trace_eval: &Trace<E>) {
    let is_pad = crate::trace::trace_eval!(trace_eval, Column::IsPadding);
    let is_real = E::F::one() - is_pad[0].clone();
    let val_b = crate::trace::trace_eval!(trace_eval, Column::ValB);
    let result = crate::trace::trace_eval!(trace_eval, Column::Result);
    let div_by_zero_for_h = crate::trace::trace_eval!(trace_eval, Column::DivByZero);
    let val_d_byte_indicator_h = crate::trace::trace_eval!(trace_eval, Column::ValDByteIndicatorH);
    let val_d_byte_ind_minus_1_h =
        crate::trace::trace_eval!(trace_eval, Column::ValDByteIndMinus1H);
    let part_nz_times_ind_h = crate::trace::trace_eval!(trace_eval, Column::PartNZTimesIndH);
    let is_div_rem_times_vdz_h = crate::trace::trace_eval!(trace_eval, Column::IsDivRemTimesVdzH);
    let dbz_active_quot_h = crate::trace::trace_eval!(trace_eval, Column::DbzActiveQuotH);
    let dbz_active_rem_h = crate::trace::trace_eval!(trace_eval, Column::DbzActiveRemH);
    let dbz_active_rem_64_h = crate::trace::trace_eval!(trace_eval, Column::DbzActiveRem64H);
    // ════════════════════════════════════════════════════════════════════
    // Byte-wise val_d zero-check + DivByZero result binding
    //
    // Closes two related soundness gaps with shared infrastructure:
    //   (a) ValDIsZero ⇔ (val_d == 0) — both directions pinned, so
    //       CmovIz / CmovNz fire as the interpreter does.  (Pinning
    //       only the `=1 ⇒ val_d=0` direction, gated on is_compare,
    //       would leave the converse unproven.)
    //   (b) DivByZero result binding: on `is_div_rem · div_by_zero`
    //       rows the schoolbook is bypassed; result is bound to
    //       u64::MAX (div ops) or val_b (rem ops), matching the
    //       interpreter's div-by-zero convention.
    //
    // Mechanism — byte-wise inversion witness + cumulative OR:
    //   ByteIndicator[i] = val_d[i] · ByteInv[i]    (degree 2)
    //   constrained by   val_d[i] · (ByteIndicator[i] − 1) = 0
    //   which forces ByteIndicator[i] = 1 when val_d[i] ≠ 0
    //   (because ByteInv[i] must equal 1/val_d[i]) and accepts
    //   any ByteIndicator value when val_d[i] = 0 — but the
    //   prover only gains by setting it to 0 there (the OR doesn't
    //   short-circuit otherwise).  PartialNZ accumulates OR:
    //     PartialNZ[0]   = ByteIndicator[0]
    //     PartialNZ[i]   = PartialNZ[i-1] + ByteIndicator[i]
    //                      − PartialNZ[i-1] · ByteIndicator[i]
    //   PartialNZ[7] = 1 ↔ any byte non-zero ↔ val_d ≠ 0.
    //   ValDIsZero = 1 − PartialNZ[7].
    // ValDIsZero recurrence + DBZ binding.
    {
        let val_d_partial_nz = crate::trace::trace_eval!(trace_eval, Column::ValDPartialNZ);
        let val_d_is_zero_p29 = crate::trace::trace_eval!(trace_eval, Column::ValDIsZero);

        // Per-byte indicator: `val_d · (val_d · inv − 1) = 0`.  Lifted
        // via `ValDByteIndMinus1H[i] = val_d[i] · (ByteIndicator − 1)`
        // (helper-defined above); main constraint is is_real · helper = deg 2.
        for i in 0..WORD_SIZE {
            eval.add_constraint(is_real.clone() * val_d_byte_ind_minus_1_h[i].clone());
        }

        // PartialNZ recurrence — flattened via PartNZTimesIndH.
        // PartialNZ[0] = ByteIndicator[0].
        eval.add_constraint(
            is_real.clone() * (val_d_partial_nz[0].clone() - val_d_byte_indicator_h[0].clone()),
        );
        for i in 1..WORD_SIZE {
            // OR(PartialNZ[i-1], Ind[i]) = PartialNZ[i-1] + Ind[i] -
            //                              PartialNZ[i-1]·Ind[i]
            // The product term is now PartNZTimesIndH[i] (deg 1 helper).
            eval.add_constraint(
                is_real.clone()
                    * (val_d_partial_nz[i].clone()
                        - val_d_partial_nz[i - 1].clone()
                        - val_d_byte_indicator_h[i].clone()
                        + part_nz_times_ind_h[i].clone()),
            );
        }

        // ValDIsZero = 1 − PartialNZ[7].  (deg 2, unchanged)
        eval.add_constraint(
            is_real.clone()
                * (val_d_is_zero_p29[0].clone() + val_d_partial_nz[WORD_SIZE - 1].clone()
                    - E::F::one()),
        );

        // DivByZero = is_div_rem · ValDIsZero — flattened via IsDivRemTimesVdzH.
        eval.add_constraint(
            is_real.clone() * (div_by_zero_for_h[0].clone() - is_div_rem_times_vdz_h[0].clone()),
        );

        // DivByZero result binding — flattened via DbzActiveQuotH/RemH.
        let f_ff_p29: E::F = E::F::from(BaseField::from(255));
        for i in 0..WORD_SIZE {
            eval.add_constraint(
                dbz_active_quot_h[0].clone() * (result[i].clone() - f_ff_p29.clone()),
            );
            let gate = if i < 4 {
                &dbz_active_rem_h
            } else {
                &dbz_active_rem_64_h
            };
            eval.add_constraint(gate[0].clone() * (result[i].clone() - val_b[i].clone()));
        }
    }
}

/// DivS: the remainder takes the dividend's sign when non-zero.
pub(in crate::chips::cpu) fn remainder_sign<E: EvalAtRow>(eval: &mut E, trace_eval: &Trace<E>) {
    let is_pad = crate::trace::trace_eval!(trace_eval, Column::IsPadding);
    let is_real = E::F::one() - is_pad[0].clone();
    let val_r_byte_indicator_h = crate::trace::trace_eval!(trace_eval, Column::ValRByteIndicatorH);
    let val_r_byte_ind_minus_1_h =
        crate::trace::trace_eval!(trace_eval, Column::ValRByteIndMinus1H);
    let val_r_part_nz_times_ind_h =
        crate::trace::trace_eval!(trace_eval, Column::ValRPartNZTimesIndH);
    let div_s_active_partial_h = crate::trace::trace_eval!(trace_eval, Column::DivSActivePartialH);
    let div_remainder = crate::trace::trace_eval!(trace_eval, Column::DivRemainder);
    // ════════════════════════════════════════════════════════════════════
    // The full DivS |r|<|d| chain lives in DivRemChip.
    // AbsD/AbsDCarry/AbsR/AbsRCarry + AbsCmpDiff/AbsCmpCarry are
    // DivRemChip-internal columns; the chains run on the narrower
    // trace using sign_bit_d / sign_bit_r flowed via the DivRemLookup
    // tuple.

    // ════════════════════════════════════════════════════════════════════
    // DivS sign-of-r uniqueness (`sign(r) = sign(b)` when r ≠ 0)
    //
    // Mirrors the byte-wise zero-check pattern but on `div_remainder`.
    // PartialNZ accumulates OR of byte-indicators; PartialNZ[7] = 1 ↔
    // div_remainder ≠ 0.
    //
    // Final constraint:
    //   is_div_s · ¬div_by_zero · ValRPartialNZ[7] ·
    //                                  (SignBitR − SignBitB) = 0
    // forces SignBitR = SignBitB whenever the remainder is non-
    // zero, matching PVM's round-toward-zero convention where
    // sign(r) = sign(b).  Combined with the |r| < |d| bound, DivS
    // uniqueness is complete: there's exactly one (q, r) pair
    // satisfying both bounds + the schoolbook + the sign-correction.
    {
        let val_r_byte_inv = crate::trace::trace_eval!(trace_eval, Column::ValRByteInv);
        let val_r_partial_nz = crate::trace::trace_eval!(trace_eval, Column::ValRPartialNZ);
        let sign_bit_b_p31 = crate::trace::trace_eval!(trace_eval, Column::SignBitB);
        let sign_bit_r_p31 = crate::trace::trace_eval!(trace_eval, Column::SignBitR);

        // Per-byte indicator pinning.
        for i in 0..WORD_SIZE {
            eval.add_constraint(is_real.clone() * val_r_byte_ind_minus_1_h[i].clone());
        }
        // PartialNZ recurrence.
        eval.add_constraint(
            is_real.clone() * (val_r_partial_nz[0].clone() - val_r_byte_indicator_h[0].clone()),
        );
        for i in 1..WORD_SIZE {
            eval.add_constraint(
                is_real.clone()
                    * (val_r_partial_nz[i].clone()
                        - val_r_partial_nz[i - 1].clone()
                        - val_r_byte_indicator_h[i].clone()
                        + val_r_part_nz_times_ind_h[i].clone()),
            );
        }
        // Sign-of-r constraint.
        eval.add_constraint(
            div_s_active_partial_h[0].clone()
                * (sign_bit_r_p31[0].clone() - sign_bit_b_p31[0].clone()),
        );
        let _ = (val_r_byte_inv, div_remainder); // routed via helpers
    }
}
