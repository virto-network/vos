//! The lookups that bind a row to the arithmetic chips' tables.
use alloc::{vec, vec::Vec};

use num_traits::One;
use stwo_constraint_framework::{EvalAtRow, RelationEntry};

use super::{Lookups, Trace, is_branch, is_compare};
use crate::chips::cpu::columns::Column;
use crate::core::step::WORD_SIZE;

/// The power-of-two, popcount and bitcount lookups.
pub(in crate::chips::cpu) fn table_lookups<E: EvalAtRow>(
    eval: &mut E,
    trace_eval: &Trace<E>,
    lookups: &Lookups<'_>,
) {
    let pow2_lookup = lookups.pow2_lookup;
    let popcount_lookup = lookups.popcount_lookup;
    let bitcount_lookup = lookups.bitcount_lookup;
    let is_shift_c_not_rotr_h = crate::trace::trace_eval!(trace_eval, Column::IsShiftCNotRotrH);
    let val_d = crate::trace::trace_eval!(trace_eval, Column::ValD);
    let is_count_set_bits = crate::trace::trace_eval!(trace_eval, Column::IsCountSetBits);
    let byte_popcount = crate::trace::trace_eval!(trace_eval, Column::BytePopcount);
    let is_lzb = crate::trace::trace_eval!(trace_eval, Column::IsLzb);
    let is_tzb = crate::trace::trace_eval!(trace_eval, Column::IsTzb);
    let bit_op_lz_byte = crate::trace::trace_eval!(trace_eval, Column::BitOpLzByte);
    let bit_op_tz_byte = crate::trace::trace_eval!(trace_eval, Column::BitOpTzByte);
    // BitwiseAndLookup nibble emissions live in BitwiseChip.  CpuChip
    // emits the BitwiseLookup producer (paired) just before
    // finalize_logup_in_pairs.

    // Power-of-two lookup: proves val_d = 2^shift_amount for constrained shifts.
    //
    // The classic emission is gated on
    //   is_shift_c · (1 − is_rotate_r64 − is_rotate_r32)
    // so RotR64 + RotR32 rows fall through.  For those rows val_d
    // gets pinned to `2^ShiftAmountCompl` instead, via a second
    // emission keyed on `ShiftAmountCompl` and gated on
    // `is_rotate_r64 + is_rotate_r32`.  Classic-shift and RotL64 /
    // RotL32 rows use the first emission with ShiftAmount = n_real.
    let is_rotate_r64_pow2 = crate::trace::trace_eval!(trace_eval, Column::IsRotateR64);
    let is_rotate_r32_pow2 = crate::trace::trace_eval!(trace_eval, Column::IsRotateR32);
    let shift_amount_compl_pow2 = crate::trace::trace_eval!(trace_eval, Column::ShiftAmountCompl);
    {
        let shift_amount = crate::trace::trace_eval!(trace_eval, Column::ShiftAmount);
        let is_shift_c = crate::trace::trace_eval!(trace_eval, Column::IsShiftConstrained);
        let mut tuple: Vec<E::F> = vec![shift_amount[0].clone()];
        tuple.extend_from_slice(&val_d);
        // Route `is_shift_c · (1 - rot_r64 - rot_r32)` through
        // IsShiftCNotRotrH so the lookup multiplicity stays at deg 1.
        // Helper-defining constraint below.
        eval.add_constraint(
            is_shift_c_not_rotr_h[0].clone()
                - is_shift_c[0].clone()
                    * (E::F::one() - is_rotate_r64_pow2[0].clone() - is_rotate_r32_pow2[0].clone()),
        );
        eval.add_to_relation(RelationEntry::new(
            pow2_lookup,
            is_shift_c_not_rotr_h[0].clone().into(),
            &tuple,
        ));
    }
    // Separate PowerOfTwo emission for RotR64 + RotR32 keyed on
    // ShiftAmountCompl.
    {
        let mut tuple: Vec<E::F> = vec![shift_amount_compl_pow2[0].clone()];
        tuple.extend_from_slice(&val_d);
        let mult = is_rotate_r64_pow2[0].clone() + is_rotate_r32_pow2[0].clone();
        eval.add_to_relation(RelationEntry::new(pow2_lookup, mult.into(), &tuple));
    }

    // Popcount lookup — per-byte (val_d[i], BytePopcount[i]) on
    // CountSetBits rows.  Emitted for all 8 bytes of val_d regardless of
    // is_32bit; the result-binding sums only the relevant bytes.  The
    // PopcountChip's preprocessed table holds the canonical (byte,
    // popcount(byte)) for byte ∈ [0, 256).  Producer multiplicity =
    // is_count_set_bits per byte.
    {
        for i in 0..WORD_SIZE {
            let tuple = vec![val_d[i].clone(), byte_popcount[i].clone()];
            eval.add_to_relation(RelationEntry::new(
                popcount_lookup,
                is_count_set_bits[0].clone().into(),
                &tuple,
            ));
        }
    }

    // Bitcount lookup — per-byte (val_d[i], BitOpLzByte[i],
    // BitOpTzByte[i]) on LZ/TZ rows.  Producer multiplicity =
    // is_lzb + is_tzb (mutually exclusive — at most one is 1 per row).
    {
        for i in 0..WORD_SIZE {
            let tuple = vec![
                val_d[i].clone(),
                bit_op_lz_byte[i].clone(),
                bit_op_tz_byte[i].clone(),
            ];
            eval.add_to_relation(RelationEntry::new(
                bitcount_lookup,
                (is_lzb[0].clone() + is_tzb[0].clone()).into(),
                &tuple,
            ));
        }
    }
}

/// The MultiplicationLookup producer.
pub(in crate::chips::cpu) fn mul_lookup<E: EvalAtRow>(
    eval: &mut E,
    trace_eval: &Trace<E>,
    lookups: &Lookups<'_>,
) {
    let mul_lookup = lookups.mul_lookup;
    // ── MultiplicationLookup producer ──
    // Tuple (35 limbs): val_b[8] + val_d[8] + result[8] +
    //   sign_bit_b + sign_bit_d + 4 rotate flags + 5 mul flags.
    // MulChip consumes the same tuple per real row and runs:
    //   - the schoolbook carry chain: pins upl/uph/mul_high.
    //   - sign correction: pins result for is_mul_upper rows.
    //   - result-variant dispatch: pins result for non-upper mul rows
    //     from upl ± mul_high based on rotate flags.
    {
        let f_is_mul_p54 = crate::trace::trace_eval!(trace_eval, Column::IsMul);
        let f_mu_uu_p54 = crate::trace::trace_eval!(trace_eval, Column::IsMulUpperUU);
        let f_mu_su_p54 = crate::trace::trace_eval!(trace_eval, Column::IsMulUpperSU);
        let f_mu_ss_p54 = crate::trace::trace_eval!(trace_eval, Column::IsMulUpperSS);
        let f_is_32bit_p54 = crate::trace::trace_eval!(trace_eval, Column::Is32Bit);
        let f_rot_l64_p54 = crate::trace::trace_eval!(trace_eval, Column::IsRotateL64);
        let f_rot_r64_p54 = crate::trace::trace_eval!(trace_eval, Column::IsRotateR64);
        let f_rot_l32_p54 = crate::trace::trace_eval!(trace_eval, Column::IsRotateL32);
        let f_rot_r32_p54 = crate::trace::trace_eval!(trace_eval, Column::IsRotateR32);
        let val_b_p54 = crate::trace::trace_eval!(trace_eval, Column::ValB);
        let val_d_p54 = crate::trace::trace_eval!(trace_eval, Column::ValD);
        let result_p54 = crate::trace::trace_eval!(trace_eval, Column::Result);
        let sign_bit_b_p54 = crate::trace::trace_eval!(trace_eval, Column::SignBitB);
        let sign_bit_d_p54 = crate::trace::trace_eval!(trace_eval, Column::SignBitD);
        let is_mul_lo_e = f_is_mul_p54[0].clone()
            - f_mu_uu_p54[0].clone()
            - f_mu_su_p54[0].clone()
            - f_mu_ss_p54[0].clone();
        let mut tuple_p54: Vec<E::F> = Vec::with_capacity(35);
        tuple_p54.extend_from_slice(&val_b_p54);
        tuple_p54.extend_from_slice(&val_d_p54);
        tuple_p54.extend_from_slice(&result_p54);
        tuple_p54.push(sign_bit_b_p54[0].clone());
        tuple_p54.push(sign_bit_d_p54[0].clone());
        tuple_p54.push(f_rot_l64_p54[0].clone());
        tuple_p54.push(f_rot_r64_p54[0].clone());
        tuple_p54.push(f_rot_l32_p54[0].clone());
        tuple_p54.push(f_rot_r32_p54[0].clone());
        tuple_p54.push(is_mul_lo_e);
        tuple_p54.push(f_mu_uu_p54[0].clone());
        tuple_p54.push(f_mu_su_p54[0].clone());
        tuple_p54.push(f_mu_ss_p54[0].clone());
        tuple_p54.push(f_is_32bit_p54[0].clone());
        for _ in 0..2 {
            eval.add_to_relation(RelationEntry::new(
                mul_lookup,
                f_is_mul_p54[0].clone().into(),
                &tuple_p54,
            ));
        }
    }
}

/// The DivRemLookup producer.
pub(in crate::chips::cpu) fn divrem_lookup<E: EvalAtRow>(
    eval: &mut E,
    trace_eval: &Trace<E>,
    lookups: &Lookups<'_>,
) {
    let divrem_lookup = lookups.divrem_lookup;
    // ── DivRemLookup producer ──
    // Tuple (41 limbs): val_b[8] + val_d[8] + div_quotient[8] +
    //   div_remainder[8] + sign_bit_b + sign_bit_d + sign_bit_q +
    //   sign_bit_r + is_div_rem + div_by_zero + is_32bit + is_div_s +
    //   is_shar_r.
    // Multiplicity = is_div_rem.
    // The 4 sign bits let DivRemChip's sign-correction chain run;
    // div_corr_hi[8] is DivRemChip-internal (not in this tuple).
    {
        let val_b_p54g = crate::trace::trace_eval!(trace_eval, Column::ValB);
        let val_d_p54g = crate::trace::trace_eval!(trace_eval, Column::ValD);
        let dq_p54g = crate::trace::trace_eval!(trace_eval, Column::DivQuotient);
        let dr_p54g = crate::trace::trace_eval!(trace_eval, Column::DivRemainder);
        let sb_p54k = crate::trace::trace_eval!(trace_eval, Column::SignBitB);
        let sd_p54k = crate::trace::trace_eval!(trace_eval, Column::SignBitD);
        let sq_p54k = crate::trace::trace_eval!(trace_eval, Column::SignBitQ);
        let sr_p54k = crate::trace::trace_eval!(trace_eval, Column::SignBitR);
        let dbz_p54g = crate::trace::trace_eval!(trace_eval, Column::DivByZero);
        let is_dr_p54g = crate::trace::trace_eval!(trace_eval, Column::IsDivRem);
        let is_32_p54g = crate::trace::trace_eval!(trace_eval, Column::Is32Bit);
        let is_ds_p54g = crate::trace::trace_eval!(trace_eval, Column::IsDivS);
        let mut tuple_p54g: Vec<E::F> = Vec::with_capacity(41);
        tuple_p54g.extend_from_slice(&val_b_p54g);
        tuple_p54g.extend_from_slice(&val_d_p54g);
        tuple_p54g.extend_from_slice(&dq_p54g);
        tuple_p54g.extend_from_slice(&dr_p54g);
        tuple_p54g.push(sb_p54k[0].clone());
        tuple_p54g.push(sd_p54k[0].clone());
        tuple_p54g.push(sq_p54k[0].clone());
        tuple_p54g.push(sr_p54k[0].clone());
        tuple_p54g.push(is_dr_p54g[0].clone());
        tuple_p54g.push(dbz_p54g[0].clone());
        tuple_p54g.push(is_32_p54g[0].clone());
        tuple_p54g.push(is_ds_p54g[0].clone());
        tuple_p54g.push(trace_eval.column_eval::<1>(Column::IsSharR)[0].clone());
        for _ in 0..2 {
            eval.add_to_relation(RelationEntry::new(
                divrem_lookup,
                is_dr_p54g[0].clone().into(),
                &tuple_p54g,
            ));
        }
    }
}

/// The CompareLookup producer.
pub(in crate::chips::cpu) fn compare_lookup<E: EvalAtRow>(
    eval: &mut E,
    trace_eval: &Trace<E>,
    lookups: &Lookups<'_>,
) {
    let compare_lookup = lookups.compare_lookup;
    let is_cmp_or_branch = is_compare(trace_eval) + is_branch(trace_eval);
    // ── CompareLookup producer ──
    // Tuple (17 limbs): val_b[8] + val_d[8] + cmp_lt_flag.
    // Multiplicity = is_compare + is_branch.  Two paired emissions.
    {
        let val_b_p54f = crate::trace::trace_eval!(trace_eval, Column::ValB);
        let val_d_p54f = crate::trace::trace_eval!(trace_eval, Column::ValD);
        let cmp_lt_p54f = crate::trace::trace_eval!(trace_eval, Column::CmpLtFlag);
        let mut tuple_p54f: Vec<E::F> = Vec::with_capacity(17);
        tuple_p54f.extend_from_slice(&val_b_p54f);
        tuple_p54f.extend_from_slice(&val_d_p54f);
        tuple_p54f.push(cmp_lt_p54f[0].clone());
        for _ in 0..2 {
            eval.add_to_relation(RelationEntry::new(
                compare_lookup,
                is_cmp_or_branch.clone().into(),
                &tuple_p54f,
            ));
        }
    }
}

/// The BitwiseLookup producer.
pub(in crate::chips::cpu) fn bitwise_lookup<E: EvalAtRow>(
    eval: &mut E,
    trace_eval: &Trace<E>,
    lookups: &Lookups<'_>,
) {
    let bitwise_lookup = lookups.bitwise_lookup;
    // ── BitwiseLookup producer ──
    // Tuple (30 limbs): val_b[8] + val_d[8] + result[8] + 6 sub-flags.
    // Multiplicity = is_bitwise_e (sum of 6 sub-flags).  Two paired
    // emissions for finalize_logup_in_pairs.
    {
        let val_b_p54e = crate::trace::trace_eval!(trace_eval, Column::ValB);
        let val_d_p54e = crate::trace::trace_eval!(trace_eval, Column::ValD);
        let result_p54e = crate::trace::trace_eval!(trace_eval, Column::Result);
        let f_and = crate::trace::trace_eval!(trace_eval, Column::IsAnd);
        let f_or = crate::trace::trace_eval!(trace_eval, Column::IsOr);
        let f_xor = crate::trace::trace_eval!(trace_eval, Column::IsXor);
        let f_andinv = crate::trace::trace_eval!(trace_eval, Column::IsAndInv);
        let f_orinv = crate::trace::trace_eval!(trace_eval, Column::IsOrInv);
        let f_xnor = crate::trace::trace_eval!(trace_eval, Column::IsXnor);
        let is_bitwise_p54e = f_and[0].clone()
            + f_or[0].clone()
            + f_xor[0].clone()
            + f_andinv[0].clone()
            + f_orinv[0].clone()
            + f_xnor[0].clone();
        let mut tuple_p54e: Vec<E::F> = Vec::with_capacity(30);
        tuple_p54e.extend_from_slice(&val_b_p54e);
        tuple_p54e.extend_from_slice(&val_d_p54e);
        tuple_p54e.extend_from_slice(&result_p54e);
        tuple_p54e.push(f_and[0].clone());
        tuple_p54e.push(f_or[0].clone());
        tuple_p54e.push(f_xor[0].clone());
        tuple_p54e.push(f_andinv[0].clone());
        tuple_p54e.push(f_orinv[0].clone());
        tuple_p54e.push(f_xnor[0].clone());
        for _ in 0..2 {
            eval.add_to_relation(RelationEntry::new(
                bitwise_lookup,
                is_bitwise_p54e.clone().into(),
                &tuple_p54e,
            ));
        }
    }
}
