//! The lookups that bind a row to the arithmetic chips' tables.
use alloc::{vec, vec::Vec};

use num_traits::One;
use stwo_constraint_framework::{EvalAtRow, RelationEntry};

use super::{Lookups, Row, is_bitwise, is_branch, is_compare, values};
use crate::chips::cpu::tuples::{BITWISE, COMPARE, DIVREM, MUL_HEAD, MUL_TAIL, MUL_UPPER};
use crate::core::step::WORD_SIZE;

/// The power-of-two, popcount and bitcount lookups.
pub(in crate::chips::cpu) fn table_lookups<E: EvalAtRow>(
    eval: &mut E,
    row: &Row<E::F>,
    lookups: &Lookups,
) {
    let pow2_lookup = &lookups.pow2_lookup;
    let popcount_lookup = &lookups.popcount_lookup;
    let bitcount_lookup = &lookups.bitcount_lookup;
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
    {
        let mut tuple: Vec<E::F> = vec![row.shift_amount[0].clone()];
        tuple.extend_from_slice(&row.val_d);
        // Route `is_shift_c · (1 - rot_r64 - rot_r32)` through
        // IsShiftCNotRotrH so the lookup multiplicity stays at deg 1.
        // Helper-defining constraint below.
        eval.add_constraint(
            row.is_shift_c_not_rotr_h[0].clone()
                - row.is_shift_constrained[0].clone()
                    * (E::F::one() - row.is_rotate_r64[0].clone() - row.is_rotate_r32[0].clone()),
        );
        eval.add_to_relation(RelationEntry::new(
            pow2_lookup,
            row.is_shift_c_not_rotr_h[0].clone().into(),
            &tuple,
        ));
    }
    // Separate PowerOfTwo emission for RotR64 + RotR32 keyed on
    // ShiftAmountCompl.
    {
        let mut tuple: Vec<E::F> = vec![row.shift_amount_compl[0].clone()];
        tuple.extend_from_slice(&row.val_d);
        let mult = row.is_rotate_r64[0].clone() + row.is_rotate_r32[0].clone();
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
            let tuple = vec![row.val_d[i].clone(), row.byte_popcount[i].clone()];
            eval.add_to_relation(RelationEntry::new(
                popcount_lookup,
                row.is_count_set_bits[0].clone().into(),
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
                row.val_d[i].clone(),
                row.bit_op_lz_byte[i].clone(),
                row.bit_op_tz_byte[i].clone(),
            ];
            eval.add_to_relation(RelationEntry::new(
                bitcount_lookup,
                (row.is_lzb[0].clone() + row.is_tzb[0].clone()).into(),
                &tuple,
            ));
        }
    }
}

/// The MultiplicationLookup producer.
pub(in crate::chips::cpu) fn mul_lookup<E: EvalAtRow>(
    eval: &mut E,
    row: &Row<E::F>,
    lookups: &Lookups,
) {
    // ── MultiplicationLookup producer ──
    // Tuple (35 limbs): val_b[8] + val_d[8] + result[8] +
    //   sign_bit_b + sign_bit_d + 4 rotate flags + 5 mul flags.
    // MulChip consumes the same tuple per real row and runs:
    //   - the schoolbook carry chain: pins upl/uph/mul_high.
    //   - sign correction: pins result for is_mul_upper rows.
    //   - result-variant dispatch: pins result for non-upper mul rows
    //     from upl ± mul_high based on rotate flags.
    let is_mul_lo = MUL_UPPER
        .iter()
        .fold(row.is_mul[0].clone(), |is_mul_lo, &upper| {
            is_mul_lo - row.column(upper)[0].clone()
        });
    let mut tuple = values(row, &MUL_HEAD);
    tuple.push(is_mul_lo);
    tuple.extend(values(row, &MUL_TAIL));
    for _ in 0..2 {
        eval.add_to_relation(RelationEntry::new(
            &lookups.mul_lookup,
            row.is_mul[0].clone().into(),
            &tuple,
        ));
    }
}

/// The DivRemLookup producer.
pub(in crate::chips::cpu) fn divrem_lookup<E: EvalAtRow>(
    eval: &mut E,
    row: &Row<E::F>,
    lookups: &Lookups,
) {
    // ── DivRemLookup producer ──
    // Tuple (41 limbs): val_b[8] + val_d[8] + div_quotient[8] +
    //   div_remainder[8] + sign_bit_b + sign_bit_d + sign_bit_q +
    //   sign_bit_r + is_div_rem + div_by_zero + is_32bit + is_div_s +
    //   is_shar_r.
    // Multiplicity = is_div_rem.
    // The 4 sign bits let DivRemChip's sign-correction chain run;
    // div_corr_hi[8] is DivRemChip-internal (not in this tuple).
    let tuple = values(row, &DIVREM);
    for _ in 0..2 {
        eval.add_to_relation(RelationEntry::new(
            &lookups.divrem_lookup,
            row.is_div_rem[0].clone().into(),
            &tuple,
        ));
    }
}

/// The CompareLookup producer.
pub(in crate::chips::cpu) fn compare_lookup<E: EvalAtRow>(
    eval: &mut E,
    row: &Row<E::F>,
    lookups: &Lookups,
) {
    // ── CompareLookup producer ──
    // Tuple (17 limbs): val_b[8] + val_d[8] + cmp_lt_flag.
    // Multiplicity = is_compare + is_branch.  Two paired emissions.
    let is_cmp_or_branch = is_compare(row) + is_branch(row);
    let tuple = values(row, &COMPARE);
    for _ in 0..2 {
        eval.add_to_relation(RelationEntry::new(
            &lookups.compare_lookup,
            is_cmp_or_branch.clone().into(),
            &tuple,
        ));
    }
}

/// The BitwiseLookup producer.
pub(in crate::chips::cpu) fn bitwise_lookup<E: EvalAtRow>(
    eval: &mut E,
    row: &Row<E::F>,
    lookups: &Lookups,
) {
    // ── BitwiseLookup producer ──
    // Tuple (30 limbs): val_b[8] + val_d[8] + result[8] + 6 sub-flags.
    // Multiplicity = IsBitwise (sum of 6 sub-flags).  Two paired
    // emissions for finalize_logup_in_pairs.
    let is_bitwise = is_bitwise(row);
    let tuple = values(row, &BITWISE);
    for _ in 0..2 {
        eval.add_to_relation(RelationEntry::new(
            &lookups.bitwise_lookup,
            is_bitwise.clone().into(),
            &tuple,
        ));
    }
}
