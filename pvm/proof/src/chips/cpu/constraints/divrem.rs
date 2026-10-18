//! DivRem: the result, the zero-divisor check and the remainder's sign.
use num_traits::One;
use stwo::core::fields::m31::BaseField;
use stwo_constraint_framework::EvalAtRow;

use super::Row;
use crate::core::step::WORD_SIZE;

/// The ValDIsZero and division-by-zero helpers.
pub(in crate::chips::cpu) fn zero_divisor_helpers<E: EvalAtRow>(eval: &mut E, row: &Row<E::F>) {
    // ── ValDIsZero / DBZ binding helpers ──
    // ValDByteInv columns aren't read here directly — they're pulled
    // in within the inverse-pinning block below.  But we do define
    // helpers in terms of them at this top region for visibility:
    {
        for i in 0..WORD_SIZE {
            eval.add_constraint(
                row.val_d_byte_indicator_h[i].clone()
                    - row.val_d[i].clone() * row.val_d_byte_inv[i].clone(),
            );
            // ValDByteIndMinus1H[i] = ValD[i] · (ByteIndicator - 1)
            //                       = ValD · ByteIndicator − ValD
            eval.add_constraint(
                row.val_d_byte_ind_minus1_h[i].clone()
                    - row.val_d[i].clone() * row.val_d_byte_indicator_h[i].clone()
                    + row.val_d[i].clone(),
            );
        }
        // PartNZTimesIndH[i - 1] = PartialNZ[i-1] · ByteIndicator[i] for i ≥ 1.
        for i in 1..WORD_SIZE {
            eval.add_constraint(
                row.part_nz_times_ind_h[i - 1].clone()
                    - row.val_d_partial_nz[i - 1].clone() * row.val_d_byte_indicator_h[i].clone(),
            );
        }
    }
    eval.add_constraint(
        row.is_div_rem_times_vdz_h[0].clone()
            - row.is_div_rem[0].clone() * row.val_d_is_zero[0].clone(),
    );
    eval.add_constraint(
        row.dbz_active_h[0].clone() - row.is_div_rem[0].clone() * row.div_by_zero[0].clone(),
    );
    eval.add_constraint(
        row.dbz_active_quot_h[0].clone() - row.dbz_active_h[0].clone() * row.gate_div_h[0].clone(),
    );
    eval.add_constraint(
        row.dbz_active_rem_h[0].clone() - row.dbz_active_h[0].clone() * row.gate_rem_h[0].clone(),
    );
    eval.add_constraint(
        row.dbz_active_rem64_h[0].clone()
            - row.dbz_active_rem_h[0].clone() * (E::F::one() - row.is32_bit[0].clone()),
    );
}

/// DivRem: the result is the quotient or the remainder, sign-extended on 32-bit rows.
pub(in crate::chips::cpu) fn divrem<E: EvalAtRow>(eval: &mut E, row: &Row<E::F>) {
    let f_ff_p19: E::F = E::F::from(BaseField::from(255));
    // ════════════════════════════════════════════════════════════════════
    // DIVREM: quotient * divisor + remainder = dividend
    // dividend = val_b, divisor = val_d
    // For div (op 0,1): result = quotient. For rem (op 2,3): result = remainder.
    // When divisor == 0 (div_by_zero=1): constraint bypassed (special result).
    // ════════════════════════════════════════════════════════════════════
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
            row.div_active_quot_h[0].clone()
                * (row.result[i].clone() - row.div_quotient[i].clone()),
        );
    }

    // For rem ops (op ∈ {2, 3}): result = remainder.
    for i in 0..WORD_SIZE {
        eval.add_constraint(
            row.div_active_rem_h[0].clone()
                * (row.result[i].clone() - row.div_remainder[i].clone()),
        );
    }

    // 32-bit: upper result limbs match the sign-extension pattern.
    for i in 4..WORD_SIZE {
        eval.add_constraint(
            row.is_div_rem32bit_h[0].clone()
                * (row.result[i].clone() - f_ff_p19.clone() * row.sign_bit_result[0].clone()),
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
pub(in crate::chips::cpu) fn zero_divisor<E: EvalAtRow>(eval: &mut E, row: &Row<E::F>) {
    let is_real = E::F::one() - row.is_padding[0].clone();
    // ════════════════════════════════════════════════════════════════════
    // Byte-wise val_d zero-check + DivByZero result binding
    //
    // Binds two related values with shared infrastructure:
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
        // Per-byte indicator: `val_d · (val_d · inv − 1) = 0`.  Lifted
        // via `ValDByteIndMinus1H[i] = val_d[i] · (ByteIndicator − 1)`
        // (helper-defined above); main constraint is is_real · helper = deg 2.
        for i in 0..WORD_SIZE {
            eval.add_constraint(is_real.clone() * row.val_d_byte_ind_minus1_h[i].clone());
        }

        // PartialNZ recurrence — flattened via PartNZTimesIndH.
        // PartialNZ[0] = ByteIndicator[0].
        eval.add_constraint(
            is_real.clone()
                * (row.val_d_partial_nz[0].clone() - row.val_d_byte_indicator_h[0].clone()),
        );
        for i in 1..WORD_SIZE {
            // OR(PartialNZ[i-1], Ind[i]) = PartialNZ[i-1] + Ind[i] -
            //                              PartialNZ[i-1]·Ind[i]
            // The product term is PartNZTimesIndH[i - 1] (deg 1 helper).
            eval.add_constraint(
                is_real.clone()
                    * (row.val_d_partial_nz[i].clone()
                        - row.val_d_partial_nz[i - 1].clone()
                        - row.val_d_byte_indicator_h[i].clone()
                        + row.part_nz_times_ind_h[i - 1].clone()),
            );
        }

        // ValDIsZero = 1 − PartialNZ[7].  (deg 2, unchanged)
        eval.add_constraint(
            is_real.clone()
                * (row.val_d_is_zero[0].clone() + row.val_d_partial_nz[WORD_SIZE - 1].clone()
                    - E::F::one()),
        );

        // DivByZero = is_div_rem · ValDIsZero — flattened via IsDivRemTimesVdzH.
        eval.add_constraint(
            is_real.clone() * (row.div_by_zero[0].clone() - row.is_div_rem_times_vdz_h[0].clone()),
        );

        // DivByZero result binding — flattened via DbzActiveQuotH/RemH.
        let f_ff_p29: E::F = E::F::from(BaseField::from(255));
        for i in 0..WORD_SIZE {
            eval.add_constraint(
                row.dbz_active_quot_h[0].clone() * (row.result[i].clone() - f_ff_p29.clone()),
            );
            let gate = if i < 4 {
                &row.dbz_active_rem_h
            } else {
                &row.dbz_active_rem64_h
            };
            eval.add_constraint(gate[0].clone() * (row.result[i].clone() - row.val_b[i].clone()));
        }
    }
}

/// DivS: the remainder takes the dividend's sign when non-zero.
pub(in crate::chips::cpu) fn remainder_sign<E: EvalAtRow>(eval: &mut E, row: &Row<E::F>) {
    let is_real = E::F::one() - row.is_padding[0].clone();
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
        // Per-byte indicator pinning.
        for i in 0..WORD_SIZE {
            eval.add_constraint(is_real.clone() * row.val_r_byte_ind_minus1_h[i].clone());
        }
        // PartialNZ recurrence.
        eval.add_constraint(
            is_real.clone()
                * (row.val_r_partial_nz[0].clone() - row.val_r_byte_indicator_h[0].clone()),
        );
        for i in 1..WORD_SIZE {
            eval.add_constraint(
                is_real.clone()
                    * (row.val_r_partial_nz[i].clone()
                        - row.val_r_partial_nz[i - 1].clone()
                        - row.val_r_byte_indicator_h[i].clone()
                        + row.val_r_part_nz_times_ind_h[i - 1].clone()),
            );
        }
        // Sign-of-r constraint.
        eval.add_constraint(
            row.div_s_active_partial_h[0].clone()
                * (row.sign_bit_r[0].clone() - row.sign_bit_b[0].clone()),
        );
    }
}
