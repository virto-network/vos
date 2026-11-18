//! The chip's trace generation, the prover's half.

use super::*;
use crate::framework::BuiltInProverComponent;
use crate::lookups::{AllLookupElements, LogupTraceBuilder};
use crate::side_note::{MulEntry, SideNote};
use crate::trace::{
    builder::{FinalizedTrace, TraceBuilder},
    component::ComponentTrace,
};
use stwo::{
    core::{ColumnVec, fields::qm31::SecureField},
    prover::{
        backend::simd::SimdBackend,
        poly::{BitReversedOrder, circle::CircleEvaluation},
    },
};

/// The Range256 values a row emits, as a multiset.
pub fn range_checked_bytes(e: &MulEntry) -> impl Iterator<Item = u8> + '_ {
    e.unsigned_product_low
        .to_le_bytes()
        .into_iter()
        .chain(e.mul_high.to_le_bytes())
        .chain(e.unsigned_product_hi.to_le_bytes())
        .chain(e.mul_carry)
        .chain(e.mul_carry_hi)
        .chain(e.mul_corr_carry)
}

impl BuiltInProverComponent for MulChip {
    const IS_PRODUCER: bool = false;

    fn generate_main_trace_immut_min(
        &self,
        side_note: &SideNote,
        min_log_size: u32,
    ) -> FinalizedTrace {
        let entries = &side_note.mul_entries;
        let log_size = crate::trace::utils::ceil_log2_at_least_lanes(entries.len())
            .max(super::super::MIN_ARITHMETIC_LOG_SIZE)
            .max(min_log_size);
        let mut trace = TraceBuilder::<Column>::new(log_size);
        let num_rows = trace.num_rows();

        for (row, e) in entries.iter().enumerate() {
            trace.fill_columns_bytes(row, &e.val_b.to_le_bytes(), Column::ValB);
            trace.fill_columns_bytes(row, &e.val_d.to_le_bytes(), Column::ValD);
            trace.fill_columns_bytes(row, &e.result.to_le_bytes(), Column::Result);
            trace.fill_columns_bytes(row, &e.mul_high.to_le_bytes(), Column::MulHigh);
            trace.fill_columns_bytes(
                row,
                &e.unsigned_product_low.to_le_bytes(),
                Column::UnsignedProductLow,
            );
            trace.fill_columns_bytes(
                row,
                &e.unsigned_product_hi.to_le_bytes(),
                Column::UnsignedProductHi,
            );
            trace.fill_columns_bytes(row, &e.mul_carry, Column::MulCarry);
            trace.fill_columns_bytes(row, &e.mul_carry_hi, Column::MulCarryHi);
            trace.fill_columns_bytes(row, &e.mul_corr_term_a, Column::MulCorrTermA);
            trace.fill_columns_bytes(row, &e.mul_corr_term_b, Column::MulCorrTermB);
            trace.fill_columns_bytes(row, &e.mul_corr_carry, Column::MulCorrCarry);
            trace.fill_columns(row, e.sign_bit_b, Column::SignBitB);
            trace.fill_columns(row, e.sign_bit_d, Column::SignBitD);
            trace.fill_columns(row, e.is_rotate_l64, Column::IsRotateL64);
            trace.fill_columns(row, e.is_rotate_r64, Column::IsRotateR64);
            trace.fill_columns(row, e.is_rotate_l32, Column::IsRotateL32);
            trace.fill_columns(row, e.is_rotate_r32, Column::IsRotateR32);
            trace.fill_columns(row, e.is_shlo_r, Column::IsShloR);
            trace.fill_columns(row, e.shift_zero, Column::ShiftZero);
            trace.fill_columns(row, e.is_mul_lo, Column::IsMulLo);
            trace.fill_columns(row, e.is_mul_upper_uu, Column::IsMulUpperUU);
            trace.fill_columns(row, e.is_mul_upper_su, Column::IsMulUpperSU);
            trace.fill_columns(row, e.is_mul_upper_ss, Column::IsMulUpperSS);
            trace.fill_columns(row, e.is_32bit, Column::Is32Bit);
            trace.fill_columns(row, false, Column::IsPadding);

            // ── Helper fills ──
            // Selector helpers — in valid traces, evaluated bool products.
            let real = true; // not padding
            let np_64 = real && !e.is_32bit;
            let mu_e = e.is_mul_upper_uu || e.is_mul_upper_su || e.is_mul_upper_ss;
            let mlo_active = np_64 && e.is_mul_lo;
            let mup_active = np_64 && mu_e;
            let i32_active = real && e.is_32bit;
            let no_rot_64 = !e.is_rotate_l64 && !e.is_rotate_r64 && !e.is_shlo_r;
            let no_rot_32 = !e.is_rotate_l32 && !e.is_rotate_r32 && !e.is_shlo_r;
            trace.fill_columns(row, np_64, Column::NotPadding64bit);
            trace.fill_columns(row, mlo_active, Column::MulLoActive);
            trace.fill_columns(row, mup_active, Column::MulUpperActive);
            trace.fill_columns(row, i32_active, Column::Is32BitActive);
            trace.fill_columns(row, mlo_active && no_rot_64, Column::MulLoNoRotate64);
            trace.fill_columns(row, i32_active && no_rot_32, Column::Is32BitNoRotate32);
            trace.fill_columns(row, np_64 && e.is_shlo_r, Column::ShloR64Active);

            // PartialSum helpers — values can exceed u8, so fill via BaseField.
            use stwo::core::fields::m31::BaseField;
            let val_b_bytes = e.val_b.to_le_bytes();
            let val_d_bytes = e.val_d.to_le_bytes();
            let mut psum_64 = [BaseField::from(0u32); 16];
            for k in 0..16usize {
                let mut s: u32 = 0;
                for i in 0..WORD_SIZE {
                    let j = k.wrapping_sub(i);
                    if j < WORD_SIZE {
                        s += val_b_bytes[i] as u32 * val_d_bytes[j] as u32;
                    }
                }
                psum_64[k] = BaseField::from(s);
            }
            trace.fill_columns_base_field(row, &psum_64, Column::PartialSum64);
            let mut psum_32 = [BaseField::from(0u32); 8];
            for k in 0..8usize {
                let mut s: u32 = 0;
                for i in 0..4usize {
                    let j = k.wrapping_sub(i);
                    if j < 4 {
                        s += val_b_bytes[i] as u32 * val_d_bytes[j] as u32;
                    }
                }
                psum_32[k] = BaseField::from(s);
            }
            trace.fill_columns_base_field(row, &psum_32, Column::PartialSum32);

            // Sign-correction body helpers.  SignBitB · ValD[i] and
            // SignBitD · ValB[i] both fit in u8 (sign_bit ∈ {0,1},
            // val ∈ 0..256).
            let mut sda = [0u8; 8];
            let mut sdb = [0u8; 8];
            for i in 0..WORD_SIZE {
                sda[i] = e.sign_bit_b * val_d_bytes[i];
                sdb[i] = e.sign_bit_d * val_b_bytes[i];
            }
            trace.fill_columns_bytes(row, &sda, Column::SignDA);
            trace.fill_columns_bytes(row, &sdb, Column::SignDB);
        }

        for row in entries.len()..num_rows {
            trace.fill_columns(row, true, Column::IsPadding);
        }

        trace.finalize_bit_reversed()
    }

    fn generate_interaction_trace(
        &self,
        component_trace: &ComponentTrace,
        _side_note: &SideNote,
        lookup_elements: &AllLookupElements,
    ) -> (
        ColumnVec<CircleEvaluation<SimdBackend, BaseField, BitReversedOrder>>,
        SecureField,
    ) {
        let log_size = component_trace.log_size();
        let mut logup = LogupTraceBuilder::new(log_size);

        let mul: &MultiplicationLookupElements = lookup_elements.as_ref();
        let range256: &Range256LookupElements = lookup_elements.as_ref();
        let upl = crate::trace::original_base_column!(component_trace, Column::UnsignedProductLow);
        let mul_high = crate::trace::original_base_column!(component_trace, Column::MulHigh);
        let uph = crate::trace::original_base_column!(component_trace, Column::UnsignedProductHi);
        let mul_carry = crate::trace::original_base_column!(component_trace, Column::MulCarry);
        let mul_carry_hi = crate::trace::original_base_column!(component_trace, Column::MulCarryHi);
        let corr_carry = crate::trace::original_base_column!(component_trace, Column::MulCorrCarry);
        let val_b = crate::trace::original_base_column!(component_trace, Column::ValB);
        let val_d = crate::trace::original_base_column!(component_trace, Column::ValD);
        let result = crate::trace::original_base_column!(component_trace, Column::Result);
        let sign_bit_b = crate::trace::original_base_column!(component_trace, Column::SignBitB);
        let sign_bit_d = crate::trace::original_base_column!(component_trace, Column::SignBitD);
        let is_rot_l64 = crate::trace::original_base_column!(component_trace, Column::IsRotateL64);
        let is_rot_r64 = crate::trace::original_base_column!(component_trace, Column::IsRotateR64);
        let is_rot_l32 = crate::trace::original_base_column!(component_trace, Column::IsRotateL32);
        let is_rot_r32 = crate::trace::original_base_column!(component_trace, Column::IsRotateR32);
        let is_shlo_r = crate::trace::original_base_column!(component_trace, Column::IsShloR);
        let shift_zero = crate::trace::original_base_column!(component_trace, Column::ShiftZero);
        let is_mul_lo = crate::trace::original_base_column!(component_trace, Column::IsMulLo);
        let is_mu_uu = crate::trace::original_base_column!(component_trace, Column::IsMulUpperUU);
        let is_mu_su = crate::trace::original_base_column!(component_trace, Column::IsMulUpperSU);
        let is_mu_ss = crate::trace::original_base_column!(component_trace, Column::IsMulUpperSS);
        let is_32bit = crate::trace::original_base_column!(component_trace, Column::Is32Bit);
        let is_padding = crate::trace::original_base_column!(component_trace, Column::IsPadding);

        for value in [
            &upl[..],
            &mul_high,
            &uph,
            &mul_carry,
            &mul_carry_hi,
            &corr_carry,
        ]
        .into_iter()
        .flatten()
        {
            logup.add_to_relation_with(
                range256,
                [is_padding[0].clone()],
                |[pad]| {
                    use stwo::prover::backend::simd::m31::PackedBaseField;
                    (PackedBaseField::one() - pad).into()
                },
                core::slice::from_ref(value),
            );
        }

        let mut tuple: Vec<_> = val_b.to_vec();
        tuple.extend_from_slice(&val_d);
        tuple.extend_from_slice(&result);
        tuple.push(sign_bit_b[0].clone());
        tuple.push(sign_bit_d[0].clone());
        tuple.push(is_rot_l64[0].clone());
        tuple.push(is_rot_r64[0].clone());
        tuple.push(is_rot_l32[0].clone());
        tuple.push(is_rot_r32[0].clone());
        tuple.push(is_shlo_r[0].clone());
        tuple.push(shift_zero[0].clone());
        tuple.push(is_mul_lo[0].clone());
        tuple.push(is_mu_uu[0].clone());
        tuple.push(is_mu_su[0].clone());
        tuple.push(is_mu_ss[0].clone());
        tuple.push(is_32bit[0].clone());

        for _ in 0..2 {
            logup.add_to_relation_with(
                mul,
                [is_padding[0].clone()],
                |[pad]| {
                    use stwo::prover::backend::simd::m31::PackedBaseField;
                    (-(PackedBaseField::one() - pad)).into()
                },
                &tuple,
            );
        }

        logup.finalize()
    }
}
