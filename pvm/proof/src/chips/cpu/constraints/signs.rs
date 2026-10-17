//! The sign bits of the operands, quotient and remainder.
use num_traits::One;
use stwo::core::fields::m31::BaseField;
use stwo_constraint_framework::{EvalAtRow, RelationEntry};

use super::{Lookups, Trace};
use crate::chips::cpu::columns::Column;

/// The sign bits' source bytes.
pub(in crate::chips::cpu) fn sign_sources<E: EvalAtRow>(eval: &mut E, trace_eval: &Trace<E>) {
    let is_pad = crate::trace::trace_eval!(trace_eval, Column::IsPadding);
    let is_real = E::F::one() - is_pad[0].clone();
    let val_b = crate::trace::trace_eval!(trace_eval, Column::ValB);
    let val_d = crate::trace::trace_eval!(trace_eval, Column::ValD);
    let real_32bit_h = crate::trace::trace_eval!(trace_eval, Column::Real32bitH);
    // ════════════════════════════════════════════════════════════════════
    // Pin SignBitB / SignBitD / SignBitQ / SignBitR to bit 7
    // of their respective source bytes via nibble-AND lookups.
    // Without this tie those four sign bits would be prover-witnessed
    // with no in-circuit link to the actual byte's bit 7, so a
    // malicious prover could lie on rows where the AIR uses them
    // (signed compare/branch, MulUpper SS/SU, DivS sign-correction).
    //
    // For each (sign_bit, source_byte, hi_nib) triple we emit:
    //   (hi_nib, 8, 8·sign_bit) — pins sign_bit = bit 3 of hi_nib.
    //   (source − 16·hi_nib, 0xF, source − 16·hi_nib) — range-checks
    //     the low nibble (forces it ∈ [0, 15] AND lo&0xF = lo, which
    //     pins the decomposition source = 16·hi_nib + lo).
    // Together: sign_bit = bit 7 of source.
    //
    // Source bytes:
    //   SignBitB → SignSrcB = (1−Is32Bit)·val_b[7] + Is32Bit·val_b[3]
    //   SignBitD → SignSrcD = (1−Is32Bit)·val_d[7] + Is32Bit·val_d[3]
    //   SignBitQ → div_quotient[7]  (DivS chain is is_64bit-only)
    //   SignBitR → div_remainder[7]
    //
    // Multiplicity = is_real on every row (8 emissions × is_real).
    // Tuple shape stays degree-1, so we hit the BitwiseLookupChip with
    // 8 emissions per real row; bitwise_and_counts is charged
    // accordingly.  Even-emission block, placed last → no pair-shape
    // reshuffle (CONSTRAINTS.md rule 2).
    //
    // Ground constraint: pin SignSrcB / SignSrcD / SignSrcQ /
    // SignSrcR to the canonical Is32Bit-multiplexed source byte.
    {
        let is_32bit_local = crate::trace::trace_eval!(trace_eval, Column::Is32Bit);
        let sign_src_b = crate::trace::trace_eval!(trace_eval, Column::SignSrcB);
        let sign_src_d = crate::trace::trace_eval!(trace_eval, Column::SignSrcD);
        let sign_src_q = crate::trace::trace_eval!(trace_eval, Column::SignSrcQ);
        let sign_src_r = crate::trace::trace_eval!(trace_eval, Column::SignSrcR);
        let div_quotient_local = crate::trace::trace_eval!(trace_eval, Column::DivQuotient);
        let div_remainder_local = crate::trace::trace_eval!(trace_eval, Column::DivRemainder);
        // Route `is_real · is_32bit` through the Real32bitH helper.
        // `is_real · (1 - is_32bit) · X` → `(is_real - Real32bitH) · X`,
        // and `is_real · is_32bit · X` → `Real32bitH · X`.
        let _ = is_32bit_local;
        let real_minus_32 = is_real.clone() - real_32bit_h[0].clone();
        eval.add_constraint(
            is_real.clone() * sign_src_b[0].clone()
                - real_minus_32.clone() * val_b[7].clone()
                - real_32bit_h[0].clone() * val_b[3].clone(),
        );
        eval.add_constraint(
            is_real.clone() * sign_src_d[0].clone()
                - real_minus_32.clone() * val_d[7].clone()
                - real_32bit_h[0].clone() * val_d[3].clone(),
        );
        eval.add_constraint(
            is_real.clone() * sign_src_q[0].clone()
                - real_minus_32.clone() * div_quotient_local[7].clone()
                - real_32bit_h[0].clone() * div_quotient_local[3].clone(),
        );
        eval.add_constraint(
            is_real.clone() * sign_src_r[0].clone()
                - real_minus_32 * div_remainder_local[7].clone()
                - real_32bit_h[0].clone() * div_remainder_local[3].clone(),
        );
    }
}

/// The sign bits pinned to bit 7 of their source bytes, through nibble lookups.
pub(in crate::chips::cpu) fn sign_nibbles<E: EvalAtRow>(
    eval: &mut E,
    trace_eval: &Trace<E>,
    lookups: &Lookups<'_>,
) {
    let bitwise_and_lookup = lookups.bitwise_and_lookup;
    let is_pad = crate::trace::trace_eval!(trace_eval, Column::IsPadding);
    let is_real = E::F::one() - is_pad[0].clone();
    let result = crate::trace::trace_eval!(trace_eval, Column::Result);
    // Sign-bit nibble lookups (last lookup block before finalize).
    {
        let sign_src_b = crate::trace::trace_eval!(trace_eval, Column::SignSrcB);
        let sign_src_d = crate::trace::trace_eval!(trace_eval, Column::SignSrcD);
        let sign_b_hi = crate::trace::trace_eval!(trace_eval, Column::SignBHiNib);
        let sign_d_hi = crate::trace::trace_eval!(trace_eval, Column::SignDHiNib);
        let sign_q_hi = crate::trace::trace_eval!(trace_eval, Column::SignQHiNib);
        let sign_r_hi = crate::trace::trace_eval!(trace_eval, Column::SignRHiNib);
        let sign_bit_b = crate::trace::trace_eval!(trace_eval, Column::SignBitB);
        let sign_bit_d = crate::trace::trace_eval!(trace_eval, Column::SignBitD);
        let sign_bit_q = crate::trace::trace_eval!(trace_eval, Column::SignBitQ);
        let sign_bit_r = crate::trace::trace_eval!(trace_eval, Column::SignBitR);
        let sign_src_q = crate::trace::trace_eval!(trace_eval, Column::SignSrcQ);
        let sign_src_r = crate::trace::trace_eval!(trace_eval, Column::SignSrcR);
        let eight_p17: E::F = E::F::from(BaseField::from(8));
        let sixteen_p17: E::F = E::F::from(BaseField::from(16));
        let fifteen_p17: E::F = E::F::from(BaseField::from(15));

        // SignBitB: (hi_b, 8, 8·bit_b), (src_b − 16·hi_b, 0xF, same).
        eval.add_to_relation(RelationEntry::new(
            bitwise_and_lookup,
            is_real.clone().into(),
            &[
                sign_b_hi[0].clone(),
                eight_p17.clone(),
                sign_bit_b[0].clone() * eight_p17.clone(),
            ],
        ));
        let lo_b = sign_src_b[0].clone() - sign_b_hi[0].clone() * sixteen_p17.clone();
        eval.add_to_relation(RelationEntry::new(
            bitwise_and_lookup,
            is_real.clone().into(),
            &[lo_b.clone(), fifteen_p17.clone(), lo_b],
        ));

        // SignBitD.
        eval.add_to_relation(RelationEntry::new(
            bitwise_and_lookup,
            is_real.clone().into(),
            &[
                sign_d_hi[0].clone(),
                eight_p17.clone(),
                sign_bit_d[0].clone() * eight_p17.clone(),
            ],
        ));
        let lo_d = sign_src_d[0].clone() - sign_d_hi[0].clone() * sixteen_p17.clone();
        eval.add_to_relation(RelationEntry::new(
            bitwise_and_lookup,
            is_real.clone().into(),
            &[lo_d.clone(), fifteen_p17.clone(), lo_d],
        ));

        // SignBitQ — source is the multiplexed SignSrcQ
        // (div_quotient[7] in 64-bit, div_quotient[3] in 32-bit).
        eval.add_to_relation(RelationEntry::new(
            bitwise_and_lookup,
            is_real.clone().into(),
            &[
                sign_q_hi[0].clone(),
                eight_p17.clone(),
                sign_bit_q[0].clone() * eight_p17.clone(),
            ],
        ));
        let lo_q = sign_src_q[0].clone() - sign_q_hi[0].clone() * sixteen_p17.clone();
        eval.add_to_relation(RelationEntry::new(
            bitwise_and_lookup,
            is_real.clone().into(),
            &[lo_q.clone(), fifteen_p17.clone(), lo_q],
        ));

        // SignBitR — source is SignSrcR (multiplexed).
        eval.add_to_relation(RelationEntry::new(
            bitwise_and_lookup,
            is_real.clone().into(),
            &[
                sign_r_hi[0].clone(),
                eight_p17.clone(),
                sign_bit_r[0].clone() * eight_p17.clone(),
            ],
        ));
        let lo_r = sign_src_r[0].clone() - sign_r_hi[0].clone() * sixteen_p17.clone();
        eval.add_to_relation(RelationEntry::new(
            bitwise_and_lookup,
            is_real.clone().into(),
            &[lo_r.clone(), fifteen_p17.clone(), lo_r],
        ));

        // SignBitResult — pin to bit 7 of result[3].  No Is32Bit
        // multiplex needed: on 64-bit rows the result-sign-extension
        // constraint is gated on is_32bit and won't fire, so
        // SignBitResult's value is unused.  Keeping the same shape as
        // the other 4 sign-bit pins keeps the lookup-pair structure
        // uniform.
        let sign_bit_result = crate::trace::trace_eval!(trace_eval, Column::SignBitResult);
        let result_hi = crate::trace::trace_eval!(trace_eval, Column::ResultHiNib);
        eval.add_to_relation(RelationEntry::new(
            bitwise_and_lookup,
            is_real.clone().into(),
            &[
                result_hi[0].clone(),
                eight_p17.clone(),
                sign_bit_result[0].clone() * eight_p17.clone(),
            ],
        ));
        let lo_res = result[3].clone() - result_hi[0].clone() * sixteen_p17.clone();
        eval.add_to_relation(RelationEntry::new(
            bitwise_and_lookup,
            is_real.clone().into(),
            &[lo_res.clone(), fifteen_p17.clone(), lo_res],
        ));

        // LoadSignBit — pin to bit 7 of LoadSignSrc.
        let load_sign_bit_pin = crate::trace::trace_eval!(trace_eval, Column::LoadSignBit);
        let load_sign_hi = crate::trace::trace_eval!(trace_eval, Column::LoadSignHiNib);
        let load_sign_src_pin = crate::trace::trace_eval!(trace_eval, Column::LoadSignSrc);
        eval.add_to_relation(RelationEntry::new(
            bitwise_and_lookup,
            is_real.clone().into(),
            &[
                load_sign_hi[0].clone(),
                eight_p17.clone(),
                load_sign_bit_pin[0].clone() * eight_p17.clone(),
            ],
        ));
        let lo_load = load_sign_src_pin[0].clone() - load_sign_hi[0].clone() * sixteen_p17.clone();
        eval.add_to_relation(RelationEntry::new(
            bitwise_and_lookup,
            is_real.clone().into(),
            &[lo_load.clone(), fifteen_p17.clone(), lo_load],
        ));

        let _ = sixteen_p17; // already consumed via lo_load
    }

    // DivCmpDiff Range256 emissions live in DivRemChip (which
    // witnesses + range-checks them on its own trace).

    // AbsCmpDiff Range256 emissions live in DivRemChip (which
    // witnesses + range-checks them on its own trace).
}
