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

impl BuiltInProverComponent for CompareChip {
    const IS_PRODUCER: bool = false;

    fn generate_main_trace_immut_min(
        &self,
        side_note: &SideNote,
        min_log_size: u32,
    ) -> FinalizedTrace {
        let entries = &side_note.compare_entries;
        let log_size = crate::trace::utils::ceil_log2_at_least_lanes(entries.len())
            .max(super::super::MIN_ARITHMETIC_LOG_SIZE)
            .max(min_log_size);
        let mut trace = TraceBuilder::<Column>::new(log_size);
        let num_rows = trace.num_rows();

        for (row, e) in entries.iter().enumerate() {
            trace.fill_columns_bytes(row, &e.val_b.to_le_bytes(), Column::ValB);
            trace.fill_columns_bytes(row, &e.val_d.to_le_bytes(), Column::ValD);
            trace.fill_columns(row, e.cmp_lt_flag, Column::CmpLtFlag);
            trace.fill_columns_bytes(row, &e.cmp_sub_result, Column::CmpSubResult);
            trace.fill_columns_bytes(row, &e.cmp_carry, Column::CmpCarry);
            trace.fill_columns(row, false, Column::IsPadding);
            // Helper fills.  Boolean helpers are 0 in valid
            // traces (cmp_lt_flag, cmp_carry[i] ∈ {0, 1}).
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

        let compare: &CompareLookupElements = lookup_elements.as_ref();
        let range256: &Range256LookupElements = lookup_elements.as_ref();
        let val_b = crate::trace::original_base_column!(component_trace, Column::ValB);
        let val_d = crate::trace::original_base_column!(component_trace, Column::ValD);
        let cmp_lt_flag = crate::trace::original_base_column!(component_trace, Column::CmpLtFlag);
        let cmp_sub_result =
            crate::trace::original_base_column!(component_trace, Column::CmpSubResult);
        let is_padding = crate::trace::original_base_column!(component_trace, Column::IsPadding);

        // Range256 emissions for cmp_sub_result bytes (8 per row).
        for col in &cmp_sub_result {
            logup.add_to_relation_with(
                range256,
                [is_padding[0].clone()],
                |[pad]| (PackedBaseField::one() - pad).into(),
                std::slice::from_ref(col),
            );
        }

        // CompareLookup consumer.
        let mut tuple: Vec<_> = val_b.to_vec();
        tuple.extend_from_slice(&val_d);
        tuple.push(cmp_lt_flag[0].clone());

        for _ in 0..2 {
            logup.add_to_relation_with(
                compare,
                [is_padding[0].clone()],
                |[pad]| (-(PackedBaseField::one() - pad)).into(),
                &tuple,
            );
        }

        logup.finalize()
    }
}
