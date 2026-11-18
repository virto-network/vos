//! The chip's trace generation, the prover's half.

use super::*;
use crate::framework::BuiltInProverComponent;
use crate::lookups::{AllLookupElements, LogupTraceBuilder};
use crate::side_note::SideNote;
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

impl BuiltInProverComponent for BitwiseChip {
    const IS_PRODUCER: bool = false;

    fn generate_main_trace_immut_min(
        &self,
        side_note: &SideNote,
        min_log_size: u32,
    ) -> FinalizedTrace {
        let entries = &side_note.bitwise_entries;
        let log_size = crate::trace::utils::ceil_log2_at_least_lanes(entries.len())
            .max(super::super::MIN_ARITHMETIC_LOG_SIZE)
            .max(min_log_size);
        let mut trace = TraceBuilder::<Column>::new(log_size);
        let num_rows = trace.num_rows();

        for (row, e) in entries.iter().enumerate() {
            trace.fill_columns_bytes(row, &e.val_b.to_le_bytes(), Column::ValB);
            trace.fill_columns_bytes(row, &e.val_d.to_le_bytes(), Column::ValD);
            trace.fill_columns_bytes(row, &e.result.to_le_bytes(), Column::Result);
            trace.fill_columns_bytes(row, &e.and_result, Column::AndResult);
            trace.fill_columns_bytes(row, &e.val_b_hi_nib, Column::ValBHiNib);
            trace.fill_columns_bytes(row, &e.val_d_hi_nib, Column::ValDHiNib);
            trace.fill_columns_bytes(row, &e.and_result_hi_nib, Column::AndResultHiNib);
            trace.fill_columns(row, e.is_and, Column::IsAnd);
            trace.fill_columns(row, e.is_or, Column::IsOr);
            trace.fill_columns(row, e.is_xor, Column::IsXor);
            trace.fill_columns(row, e.is_and_inv, Column::IsAndInv);
            trace.fill_columns(row, e.is_or_inv, Column::IsOrInv);
            trace.fill_columns(row, e.is_xnor, Column::IsXnor);
            trace.fill_columns(row, false, Column::IsPadding);
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
        use stwo::prover::backend::simd::m31::PackedBaseField;

        let log_size = component_trace.log_size();
        let mut logup = LogupTraceBuilder::new(log_size);

        let bitwise: &BitwiseLookupElements = lookup_elements.as_ref();
        let bitwise_and: &BitwiseAndLookupElements = lookup_elements.as_ref();
        let val_b = crate::trace::original_base_column!(component_trace, Column::ValB);
        let val_d = crate::trace::original_base_column!(component_trace, Column::ValD);
        let result = crate::trace::original_base_column!(component_trace, Column::Result);
        let and_result = crate::trace::original_base_column!(component_trace, Column::AndResult);
        let val_b_hi_nib = crate::trace::original_base_column!(component_trace, Column::ValBHiNib);
        let val_d_hi_nib = crate::trace::original_base_column!(component_trace, Column::ValDHiNib);
        let and_result_hi_nib =
            crate::trace::original_base_column!(component_trace, Column::AndResultHiNib);
        let is_and = crate::trace::original_base_column!(component_trace, Column::IsAnd);
        let is_or = crate::trace::original_base_column!(component_trace, Column::IsOr);
        let is_xor = crate::trace::original_base_column!(component_trace, Column::IsXor);
        let is_and_inv = crate::trace::original_base_column!(component_trace, Column::IsAndInv);
        let is_or_inv = crate::trace::original_base_column!(component_trace, Column::IsOrInv);
        let is_xnor = crate::trace::original_base_column!(component_trace, Column::IsXnor);
        let is_padding = crate::trace::original_base_column!(component_trace, Column::IsPadding);

        // ── Bitwise AND nibble-level lookups ──
        let sixteen = PackedBaseField::broadcast(BaseField::from(16));
        for i in 0..WORD_SIZE {
            let pad_c = is_padding[0].clone();
            // High nibble lookup
            logup.add_to_relation_with(
                bitwise_and,
                [pad_c.clone()],
                |[pad]| (PackedBaseField::one() - pad).into(),
                &[
                    val_b_hi_nib[i].clone(),
                    val_d_hi_nib[i].clone(),
                    and_result_hi_nib[i].clone(),
                ],
            );
            // Low nibble lookup
            let val_b_col_i = val_b[i].clone();
            let val_d_col_i = val_d[i].clone();
            let and_result_col_i = and_result[i].clone();
            let val_b_hi_i = val_b_hi_nib[i].clone();
            let val_d_hi_i = val_d_hi_nib[i].clone();
            let and_hi_i = and_result_hi_nib[i].clone();
            logup.add_to_relation_computed(
                bitwise_and,
                [pad_c],
                |[pad]| (PackedBaseField::one() - pad).into(),
                3,
                move |vec_idx| {
                    let b_lo = val_b_col_i.at(vec_idx) - val_b_hi_i.at(vec_idx) * sixteen;
                    let d_lo = val_d_col_i.at(vec_idx) - val_d_hi_i.at(vec_idx) * sixteen;
                    let and_lo = and_result_col_i.at(vec_idx) - and_hi_i.at(vec_idx) * sixteen;
                    vec![b_lo, d_lo, and_lo]
                },
            );
        }

        // ── BitwiseLookup consumer ──
        let mut tuple: Vec<_> = val_b.to_vec();
        tuple.extend_from_slice(&val_d);
        tuple.extend_from_slice(&result);
        tuple.push(is_and[0].clone());
        tuple.push(is_or[0].clone());
        tuple.push(is_xor[0].clone());
        tuple.push(is_and_inv[0].clone());
        tuple.push(is_or_inv[0].clone());
        tuple.push(is_xnor[0].clone());

        for _ in 0..2 {
            logup.add_to_relation_with(
                bitwise,
                [is_padding[0].clone()],
                |[pad]| (-(PackedBaseField::one() - pad)).into(),
                &tuple,
            );
        }

        logup.finalize()
    }
}
