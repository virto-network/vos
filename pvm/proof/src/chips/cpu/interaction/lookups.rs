//! The lookups into the table and arithmetic chips.

use num_traits::Zero;

use super::*;
use crate::chips::cpu::tuples::{
    BITWISE, BITWISE_FLAGS, BRANCH_FLAGS, COMPARE, COMPARE_FLAGS, DIVREM, MUL_HEAD, MUL_TAIL,
    MUL_UPPER, width,
};
use crate::trace::component::FinalizedColumn;

/// The power-of-two, popcount and bitcount lookups.
pub(super) fn table_lookups(
    logup: &mut LogupTraceBuilder,
    component_trace: &ComponentTrace,
    lookup_elements: &AllLookupElements,
) {
    // Power-of-two lookup: (shift_amount, val_d[8]) when shift is constrained.
    // Two emissions: one keyed on ShiftAmount with multiplicity
    // `is_shift_c · (1 − is_rotate_r64 − is_rotate_r32)`, and one keyed
    // on ShiftAmountCompl with multiplicity `is_rotate_r64 + is_rotate_r32`.
    let pow2_lookup: &PowerOfTwoLookupElements = lookup_elements.as_ref();
    let shift_amount_col =
        crate::trace::original_base_column!(component_trace, Column::ShiftAmount);
    let is_shift_constrained =
        crate::trace::original_base_column!(component_trace, Column::IsShiftConstrained);
    let is_rotate_r64_col_pow2 =
        crate::trace::original_base_column!(component_trace, Column::IsRotateR64);
    let is_rotate_r32_col_pow2 =
        crate::trace::original_base_column!(component_trace, Column::IsRotateR32);
    let shift_amount_compl_col =
        crate::trace::original_base_column!(component_trace, Column::ShiftAmountCompl);
    let val_d_cols = crate::trace::original_base_column!(component_trace, Column::ValD);
    {
        let mut tuple: Vec<_> = vec![shift_amount_col[0].clone()];
        tuple.extend_from_slice(&val_d_cols);
        logup.add_to_relation_with(
            pow2_lookup,
            [
                is_shift_constrained[0].clone(),
                is_rotate_r64_col_pow2[0].clone(),
                is_rotate_r32_col_pow2[0].clone(),
            ],
            |[shc, r64, r32]| (shc - r64 - r32).into(),
            &tuple,
        );
    }
    // Separate PowerOfTwo emission for RotR64 / RotR32 keyed on
    // ShiftAmountCompl.
    {
        let mut tuple: Vec<_> = vec![shift_amount_compl_col[0].clone()];
        tuple.extend_from_slice(&val_d_cols);
        logup.add_to_relation_with(
            pow2_lookup,
            [
                is_rotate_r64_col_pow2[0].clone(),
                is_rotate_r32_col_pow2[0].clone(),
            ],
            |[r64, r32]| (r64 + r32).into(),
            &tuple,
        );
    }

    // Popcount lookup — per-byte (val_d[i], BytePopcount[i]) on
    // CountSetBits rows.  Mirror of the verifier-side emission.
    {
        let popcount_lookup: &PopcountLookupElements = lookup_elements.as_ref();
        let is_count_set_bits_col =
            crate::trace::original_base_column!(component_trace, Column::IsCountSetBits);
        let byte_popcount_col =
            crate::trace::original_base_column!(component_trace, Column::BytePopcount);
        for i in 0..WORD_SIZE {
            logup.add_to_relation_with(
                popcount_lookup,
                [is_count_set_bits_col[0].clone()],
                |[active]| active.into(),
                &[val_d_cols[i].clone(), byte_popcount_col[i].clone()],
            );
        }
    }

    // Bitcount lookup — per-byte (val_d[i], BitOpLzByte[i],
    // BitOpTzByte[i]) on LZ/TZ rows.  Multiplicity = is_lzb + is_tzb.
    {
        let bitcount_lookup: &BitcountLookupElements = lookup_elements.as_ref();
        let is_lzb_col = crate::trace::original_base_column!(component_trace, Column::IsLzb);
        let is_tzb_col = crate::trace::original_base_column!(component_trace, Column::IsTzb);
        let lz_col = crate::trace::original_base_column!(component_trace, Column::BitOpLzByte);
        let tz_col = crate::trace::original_base_column!(component_trace, Column::BitOpTzByte);
        for i in 0..WORD_SIZE {
            logup.add_to_relation_with(
                bitcount_lookup,
                [is_lzb_col[0].clone(), is_tzb_col[0].clone()],
                |[lz, tz]| (lz + tz).into(),
                &[val_d_cols[i].clone(), lz_col[i].clone(), tz_col[i].clone()],
            );
        }
    }
}

/// The arithmetic chips' tuples: multiplication, division, comparison and
/// the bitwise operations. DivCmpDiff's and AbsCmpDiff's Range256 lookups
/// are DivRemChip's own.
pub(super) fn arithmetic(
    logup: &mut LogupTraceBuilder,
    component_trace: &ComponentTrace,
    lookup_elements: &AllLookupElements,
) {
    let flag = |column: Column| component_trace.original_base_column::<1, _>(column)[0].clone();

    // ── MultiplicationLookup producer (prover-side mirror) ──
    // Tuple (35 limbs): val_b[8] + val_d[8] + result[8] +
    //   sign_bit_b + sign_bit_d + 4 rotate flags + 5 mul flags, IsMulLo
    //   (no column) computed in its slot.
    {
        let mul: &MultiplicationLookupElements = lookup_elements.as_ref();
        let is_mul_lo_slot = width(&MUL_HEAD);
        let mut tuple = columns(component_trace, &MUL_HEAD);
        tuple.push(FinalizedColumn::Constant(BaseField::from(0)));
        tuple.extend(columns(component_trace, &MUL_TAIL));
        let width = tuple.len();
        for _ in 0..2 {
            let is_mul = flag(Column::IsMul);
            let upper = MUL_UPPER.map(flag);
            let tuple = tuple.clone();
            logup.add_to_relation_computed(
                mul,
                [flag(Column::IsMul)],
                |[m]| m.into(),
                width,
                move |i| {
                    let mut t: Vec<_> = tuple.iter().map(|c| c.at(i)).collect();
                    t[is_mul_lo_slot] = upper.iter().fold(is_mul.at(i), |lo, c| lo - c.at(i));
                    t
                },
            );
        }
    }

    // ── DivRemLookup producer (prover-side mirror) ──
    // 41-limb tuple (4 sign bits, is_div_s, is_shar_r).
    {
        let divrem: &DivRemLookupElements = lookup_elements.as_ref();
        let tuple = columns(component_trace, &DIVREM);
        for _ in 0..2 {
            logup.add_to_relation_with(divrem, [flag(Column::IsDivRem)], |[m]| m.into(), &tuple);
        }
    }

    // ── CompareLookup producer (prover-side mirror) ──
    // Tuple (17 limbs): val_b[8] + val_d[8] + cmp_lt_flag.
    // Multiplicity = is_compare + is_branch (= sum of 18 sub-flags).
    {
        let compare: &CompareLookupElements = lookup_elements.as_ref();
        let tuple = columns(component_trace, &COMPARE);
        let flags: [_; COMPARE_FLAGS.len() + BRANCH_FLAGS.len()] = core::array::from_fn(|i| {
            flag(
                COMPARE_FLAGS
                    .get(i)
                    .copied()
                    .unwrap_or_else(|| BRANCH_FLAGS[i - COMPARE_FLAGS.len()]),
            )
        });
        for _ in 0..2 {
            logup.add_to_relation_with(compare, flags.clone(), |f| sum(f).into(), &tuple);
        }
    }

    // ── BitwiseLookup producer (prover-side mirror) ──
    // Tuple (30 limbs): val_b[8] + val_d[8] + result[8] + 6 sub-flags.
    {
        let bitwise: &BitwiseLookupElements = lookup_elements.as_ref();
        let tuple = columns(component_trace, &BITWISE);
        for _ in 0..2 {
            logup.add_to_relation_with(bitwise, BITWISE_FLAGS.map(flag), |f| sum(f).into(), &tuple);
        }
    }
}

/// The finalized parts of `columns`, in order: a tuple of
/// [`tuples`](crate::chips::cpu::tuples).
fn columns<'a>(
    component_trace: &'a ComponentTrace,
    columns: &[Column],
) -> Vec<FinalizedColumn<'a>> {
    columns
        .iter()
        .flat_map(|&column| component_trace.original_columns(column))
        .collect()
}

/// The sum of a row's flags.
fn sum<const N: usize>(flags: [PackedBaseField; N]) -> PackedBaseField {
    flags
        .into_iter()
        .fold(PackedBaseField::zero(), |sum, flag| sum + flag)
}
