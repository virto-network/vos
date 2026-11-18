//! The sign bits of the operands, quotient and remainder.
use num_traits::One;
use stwo::core::fields::m31::BaseField;
use stwo_constraint_framework::{EvalAtRow, RelationEntry};

use super::{Lookups, Row};

/// The sign bits' source bytes.
pub(in crate::chips::cpu) fn sign_sources<E: EvalAtRow>(eval: &mut E, row: &Row<E::F>) {
    let is_real = E::F::one() - row.is_padding[0].clone();
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
        // Route `is_real · is_32bit` through the Real32bitH helper.
        // `is_real · (1 - is_32bit) · X` → `(is_real - Real32bitH) · X`,
        // and `is_real · is_32bit · X` → `Real32bitH · X`.
        let real_minus_32 = is_real.clone() - row.real32bit_h[0].clone();
        eval.add_constraint(
            is_real.clone() * row.sign_src_b[0].clone()
                - real_minus_32.clone() * row.val_b[7].clone()
                - row.real32bit_h[0].clone() * row.val_b[3].clone(),
        );
        eval.add_constraint(
            is_real.clone() * row.sign_src_d[0].clone()
                - real_minus_32.clone() * row.val_d[7].clone()
                - row.real32bit_h[0].clone() * row.val_d[3].clone(),
        );
        eval.add_constraint(
            is_real.clone() * row.sign_src_q[0].clone()
                - real_minus_32.clone() * row.div_quotient[7].clone()
                - row.real32bit_h[0].clone() * row.div_quotient[3].clone(),
        );
        eval.add_constraint(
            is_real.clone() * row.sign_src_r[0].clone()
                - real_minus_32 * row.div_remainder[7].clone()
                - row.real32bit_h[0].clone() * row.div_remainder[3].clone(),
        );
    }
}

/// The sign bits pinned to bit 7 of their source bytes, through nibble lookups.
pub(in crate::chips::cpu) fn sign_nibbles<E: EvalAtRow>(
    eval: &mut E,
    row: &Row<E::F>,
    lookups: &Lookups,
) {
    let bitwise_and_lookup = &lookups.bitwise_and_lookup;
    let is_real = E::F::one() - row.is_padding[0].clone();
    // Sign-bit nibble lookups (last lookup block before finalize).
    {
        let eight: E::F = E::F::from(BaseField::from(8));
        let sixteen: E::F = E::F::from(BaseField::from(16));
        let fifteen: E::F = E::F::from(BaseField::from(15));

        // SignBitB: (hi_b, 8, 8·bit_b), (src_b − 16·hi_b, 0xF, same).
        eval.add_to_relation(RelationEntry::new(
            bitwise_and_lookup,
            is_real.clone().into(),
            &[
                row.sign_b_hi_nib[0].clone(),
                eight.clone(),
                row.sign_bit_b[0].clone() * eight.clone(),
            ],
        ));
        let lo_b = row.sign_src_b[0].clone() - row.sign_b_hi_nib[0].clone() * sixteen.clone();
        eval.add_to_relation(RelationEntry::new(
            bitwise_and_lookup,
            is_real.clone().into(),
            &[lo_b.clone(), fifteen.clone(), lo_b],
        ));

        // SignBitD.
        eval.add_to_relation(RelationEntry::new(
            bitwise_and_lookup,
            is_real.clone().into(),
            &[
                row.sign_d_hi_nib[0].clone(),
                eight.clone(),
                row.sign_bit_d[0].clone() * eight.clone(),
            ],
        ));
        let lo_d = row.sign_src_d[0].clone() - row.sign_d_hi_nib[0].clone() * sixteen.clone();
        eval.add_to_relation(RelationEntry::new(
            bitwise_and_lookup,
            is_real.clone().into(),
            &[lo_d.clone(), fifteen.clone(), lo_d],
        ));

        // SignBitQ — source is the multiplexed SignSrcQ
        // (div_quotient[7] in 64-bit, div_quotient[3] in 32-bit).
        eval.add_to_relation(RelationEntry::new(
            bitwise_and_lookup,
            is_real.clone().into(),
            &[
                row.sign_q_hi_nib[0].clone(),
                eight.clone(),
                row.sign_bit_q[0].clone() * eight.clone(),
            ],
        ));
        let lo_q = row.sign_src_q[0].clone() - row.sign_q_hi_nib[0].clone() * sixteen.clone();
        eval.add_to_relation(RelationEntry::new(
            bitwise_and_lookup,
            is_real.clone().into(),
            &[lo_q.clone(), fifteen.clone(), lo_q],
        ));

        // SignBitR — source is SignSrcR (multiplexed).
        eval.add_to_relation(RelationEntry::new(
            bitwise_and_lookup,
            is_real.clone().into(),
            &[
                row.sign_r_hi_nib[0].clone(),
                eight.clone(),
                row.sign_bit_r[0].clone() * eight.clone(),
            ],
        ));
        let lo_r = row.sign_src_r[0].clone() - row.sign_r_hi_nib[0].clone() * sixteen.clone();
        eval.add_to_relation(RelationEntry::new(
            bitwise_and_lookup,
            is_real.clone().into(),
            &[lo_r.clone(), fifteen.clone(), lo_r],
        ));

        // SignBitResult — pin to bit 7 of result[3].  No Is32Bit
        // multiplex needed: on 64-bit rows the result-sign-extension
        // constraint is gated on is_32bit and won't fire, so
        // SignBitResult's value is unused.  Keeping the same shape as
        // the other 4 sign-bit pins keeps the lookup-pair structure
        // uniform.
        eval.add_to_relation(RelationEntry::new(
            bitwise_and_lookup,
            is_real.clone().into(),
            &[
                row.result_hi_nib[0].clone(),
                eight.clone(),
                row.sign_bit_result[0].clone() * eight.clone(),
            ],
        ));
        let lo_res = row.result[3].clone() - row.result_hi_nib[0].clone() * sixteen.clone();
        eval.add_to_relation(RelationEntry::new(
            bitwise_and_lookup,
            is_real.clone().into(),
            &[lo_res.clone(), fifteen.clone(), lo_res],
        ));

        // LoadSignBit — pin to bit 7 of LoadSignSrc.
        eval.add_to_relation(RelationEntry::new(
            bitwise_and_lookup,
            is_real.clone().into(),
            &[
                row.load_sign_hi_nib[0].clone(),
                eight.clone(),
                row.load_sign_bit[0].clone() * eight.clone(),
            ],
        ));
        let lo_load =
            row.load_sign_src[0].clone() - row.load_sign_hi_nib[0].clone() * sixteen.clone();
        eval.add_to_relation(RelationEntry::new(
            bitwise_and_lookup,
            is_real.clone().into(),
            &[lo_load.clone(), fifteen.clone(), lo_load],
        ));
    }

    // DivCmpDiff Range256 emissions live in DivRemChip (which
    // witnesses + range-checks them on its own trace).

    // AbsCmpDiff Range256 emissions live in DivRemChip (which
    // witnesses + range-checks them on its own trace).
}
