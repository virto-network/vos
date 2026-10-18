//! DivRemChip's main and interaction traces.

use alloc::vec::Vec;
use num_traits::One;
use stwo::core::fields::m31::BaseField;
use stwo::{
    core::{ColumnVec, fields::qm31::SecureField},
    prover::{
        backend::simd::{SimdBackend, m31::LOG_N_LANES},
        poly::{BitReversedOrder, circle::CircleEvaluation},
    },
};

use super::{Column, DivRemChip};
use crate::core::step::WORD_SIZE;
use crate::framework::BuiltInProverComponent;
use crate::lookups::{
    AllLookupElements, DivRemLookupElements, LogupTraceBuilder, Range256LookupElements,
};
use crate::side_note::SideNote;
use crate::trace::{
    builder::{FinalizedTrace, TraceBuilder},
    component::ComponentTrace,
};

impl BuiltInProverComponent for DivRemChip {
    const IS_PRODUCER: bool = false;

    fn generate_main_trace_immut(&self, side_note: &SideNote) -> FinalizedTrace {
        self.generate_main_trace_immut_min(side_note, 0)
    }

    fn generate_main_trace_immut_min(
        &self,
        side_note: &SideNote,
        min_log_size: u32,
    ) -> FinalizedTrace {
        let entries = &side_note.divrem_entries;
        const MIN_LOG_SIZE: u32 = 5;

        if entries.is_empty() {
            let log_size = LOG_N_LANES.max(MIN_LOG_SIZE).max(min_log_size);
            let mut trace = TraceBuilder::<Column>::new(log_size);
            for row in 0..trace.num_rows() {
                trace.fill_columns(row, true, Column::IsPadding);
            }
            return trace.finalize_bit_reversed();
        }

        let log_size = crate::trace::utils::ceil_log2_at_least_lanes(entries.len())
            .max(MIN_LOG_SIZE)
            .max(min_log_size);
        let mut trace = TraceBuilder::<Column>::new(log_size);
        let num_rows = trace.num_rows();

        for (row, e) in entries.iter().enumerate() {
            trace.fill_columns_bytes(row, &e.val_b.to_le_bytes(), Column::ValB);
            trace.fill_columns_bytes(row, &e.val_d.to_le_bytes(), Column::ValD);
            trace.fill_columns_bytes(row, &e.div_quotient.to_le_bytes(), Column::DivQuotient);
            trace.fill_columns_bytes(row, &e.div_remainder.to_le_bytes(), Column::DivRemainder);
            trace.fill_columns_bytes(row, &e.div_corr_hi, Column::DivCorrHi);
            trace.fill_columns_bytes(row, &e.div_mul_carry, Column::DivMulCarry);
            trace.fill_columns_bytes(row, &e.div_mul_carry_hi, Column::DivMulCarryHi);
            trace.fill_columns(row, true, Column::IsDivRem);
            trace.fill_columns(row, e.div_by_zero, Column::DivByZero);
            trace.fill_columns(row, e.is_32bit, Column::Is32Bit);
            trace.fill_columns(row, e.is_div_s, Column::IsDivS);
            trace.fill_columns(row, e.is_shar_r, Column::IsSharR);
            trace.fill_columns(row, e.div_overflow, Column::DivOverflow);
            trace.fill_columns_bytes(row, &e.div_cmp_diff, Column::DivCmpDiff);
            trace.fill_columns_bytes(row, &e.div_cmp_carry, Column::DivCmpCarry);
            trace.fill_columns_bytes(row, &e.div_corr_carry, Column::DivCorrCarry);
            trace.fill_columns(row, e.sign_bit_b, Column::SignBitB);
            trace.fill_columns(row, e.sign_bit_d, Column::SignBitD);
            trace.fill_columns(row, e.sign_bit_q, Column::SignBitQ);
            trace.fill_columns(row, e.sign_bit_r, Column::SignBitR);
            trace.fill_columns_bytes(row, &e.abs_d, Column::AbsD);
            trace.fill_columns_bytes(row, &e.abs_d_carry, Column::AbsDCarry);
            trace.fill_columns_bytes(row, &e.abs_r, Column::AbsR);
            trace.fill_columns_bytes(row, &e.abs_r_carry, Column::AbsRCarry);
            trace.fill_columns_bytes(row, &e.abs_cmp_diff, Column::AbsCmpDiff);
            trace.fill_columns_bytes(row, &e.abs_cmp_carry, Column::AbsCmpCarry);
            trace.fill_columns(row, false, Column::IsPadding);

            // ── Helper fills (a real row: IsDivRem = 1, IsPadding = 0) ──
            let active = !e.div_by_zero;
            let unsigned = active && !e.is_div_s;
            let sign_chain = active && (e.is_div_s || e.is_shar_r);
            trace.fill_columns(row, active, Column::DivActiveH);
            trace.fill_columns(row, active, Column::NotPaddingDivH);
            trace.fill_columns(row, active && !e.is_32bit, Column::DivActive64H);
            trace.fill_columns(row, active && e.is_32bit, Column::DivActive32H);
            trace.fill_columns(row, unsigned, Column::DivUActiveH);
            trace.fill_columns(row, unsigned && !e.is_32bit, Column::DivU64H);
            trace.fill_columns(row, unsigned && e.is_32bit, Column::DivU32H);
            trace.fill_columns(row, active && e.is_div_s, Column::DivSActiveH);
            trace.fill_columns(row, sign_chain, Column::SignChainH);
            trace.fill_columns(row, sign_chain && !e.is_32bit, Column::SignChain64H);
            trace.fill_columns(row, sign_chain && e.is_32bit, Column::SignChain32H);
            trace.fill_columns(row, active && !sign_chain, Column::ZeroHighH);
            trace.fill_columns(row, e.sign_bit_d == 0, Column::RealNotSdH);
            trace.fill_columns(row, e.sign_bit_d == 1, Column::RealSdH);
            trace.fill_columns(row, e.sign_bit_r == 0, Column::RealNotSrH);
            trace.fill_columns(row, e.sign_bit_r == 1, Column::RealSrH);
            trace.fill_columns(row, e.div_overflow && !e.is_32bit, Column::DivOverflow64H);
            let sign_d_div_s = e.sign_bit_d * e.is_div_s as u8;
            trace.fill_columns(row, sign_d_div_s, Column::SignDDivSH);

            // PartialSum bodies as BaseField (values can exceed u8).
            let q_bytes = e.div_quotient.to_le_bytes();
            let d_bytes = e.val_d.to_le_bytes();
            let partial_sums = |width: usize, n: usize| -> Vec<BaseField> {
                (0..n)
                    .map(|k| {
                        let s: u32 = (0..width)
                            .filter_map(|i| {
                                let j = k.wrapping_sub(i);
                                (j < width).then(|| q_bytes[i] as u32 * d_bytes[j] as u32)
                            })
                            .sum();
                        BaseField::from(s)
                    })
                    .collect()
            };
            trace.fill_columns_base_field(
                row,
                &partial_sums(WORD_SIZE, 16),
                Column::DivPartialSum64,
            );
            trace.fill_columns_base_field(row, &partial_sums(4, 8), Column::DivPartialSum32);

            let sign_q_d = d_bytes.map(|d| e.sign_bit_q * d);
            let sign_d_q = q_bytes.map(|q| sign_d_div_s * q);
            trace.fill_columns_bytes(row, &sign_q_d, Column::SignQValDH);
            trace.fill_columns_bytes(row, &sign_d_q, Column::SignDQuotH);
        }

        for row in entries.len()..num_rows {
            trace.fill_columns(row, true, Column::IsPadding);
        }

        trace.finalize_bit_reversed()
    }

    fn generate_interaction_trace(
        &self,
        component_trace: ComponentTrace,
        _side_note: &SideNote,
        lookup_elements: &AllLookupElements,
    ) -> (
        ColumnVec<CircleEvaluation<SimdBackend, BaseField, BitReversedOrder>>,
        SecureField,
    ) {
        use stwo::prover::backend::simd::m31::PackedBaseField;

        let log_size = component_trace.log_size();
        let mut logup = LogupTraceBuilder::new(log_size);

        let divrem: &DivRemLookupElements = lookup_elements.as_ref();
        let range256: &Range256LookupElements = lookup_elements.as_ref();
        let val_b = crate::trace::original_base_column!(component_trace, Column::ValB);
        let val_d = crate::trace::original_base_column!(component_trace, Column::ValD);
        let div_quotient =
            crate::trace::original_base_column!(component_trace, Column::DivQuotient);
        let div_remainder =
            crate::trace::original_base_column!(component_trace, Column::DivRemainder);
        let div_corr_hi = crate::trace::original_base_column!(component_trace, Column::DivCorrHi);
        let mul_carry = crate::trace::original_base_column!(component_trace, Column::DivMulCarry);
        let mul_carry_hi =
            crate::trace::original_base_column!(component_trace, Column::DivMulCarryHi);
        let div_corr_carry =
            crate::trace::original_base_column!(component_trace, Column::DivCorrCarry);
        let abs_d = crate::trace::original_base_column!(component_trace, Column::AbsD);
        let abs_r = crate::trace::original_base_column!(component_trace, Column::AbsR);
        let is_div_rem = crate::trace::original_base_column!(component_trace, Column::IsDivRem);
        let div_by_zero = crate::trace::original_base_column!(component_trace, Column::DivByZero);
        let is_32bit = crate::trace::original_base_column!(component_trace, Column::Is32Bit);
        let is_div_s = crate::trace::original_base_column!(component_trace, Column::IsDivS);
        let is_shar_r = crate::trace::original_base_column!(component_trace, Column::IsSharR);
        let sign_bit_b = crate::trace::original_base_column!(component_trace, Column::SignBitB);
        let sign_bit_d = crate::trace::original_base_column!(component_trace, Column::SignBitD);
        let sign_bit_q = crate::trace::original_base_column!(component_trace, Column::SignBitQ);
        let sign_bit_r = crate::trace::original_base_column!(component_trace, Column::SignBitR);
        let div_cmp_diff = crate::trace::original_base_column!(component_trace, Column::DivCmpDiff);
        let abs_cmp_diff = crate::trace::original_base_column!(component_trace, Column::AbsCmpDiff);
        let is_padding = crate::trace::original_base_column!(component_trace, Column::IsPadding);

        for value in [
            &div_quotient[..],
            &div_remainder,
            &div_corr_hi,
            &mul_carry,
            &mul_carry_hi,
            &div_corr_carry,
            &abs_d,
            &abs_r,
            &div_cmp_diff,
            &abs_cmp_diff,
        ]
        .into_iter()
        .flatten()
        {
            logup.add_to_relation_with(
                range256,
                [is_padding[0].clone()],
                |[pad]| (PackedBaseField::one() - pad).into(),
                core::slice::from_ref(value),
            );
        }

        let mut tuple: Vec<_> = val_b.to_vec();
        tuple.extend_from_slice(&val_d);
        tuple.extend_from_slice(&div_quotient);
        tuple.extend_from_slice(&div_remainder);
        tuple.push(sign_bit_b[0].clone());
        tuple.push(sign_bit_d[0].clone());
        tuple.push(sign_bit_q[0].clone());
        tuple.push(sign_bit_r[0].clone());
        tuple.push(is_div_rem[0].clone());
        tuple.push(div_by_zero[0].clone());
        tuple.push(is_32bit[0].clone());
        tuple.push(is_div_s[0].clone());
        tuple.push(is_shar_r[0].clone());

        for _ in 0..2 {
            logup.add_to_relation_with(
                divrem,
                [is_padding[0].clone()],
                |[pad]| (-(PackedBaseField::one() - pad)).into(),
                &tuple,
            );
        }

        logup.finalize()
    }
}
