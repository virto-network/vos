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

impl BuiltInProverComponent for BitwiseLookupChip {
    const IS_PRODUCER: bool = false;

    fn generate_preprocessed_trace(&self, log_size: u32, _side_note: &SideNote) -> FinalizedTrace {
        let log_size = super::super::table_log_size(BITWISE_LOG_SIZE, log_size);
        let mut trace = TraceBuilder::<PreprocessedColumn>::new(log_size);
        let num_rows = trace.num_rows();

        for row in 0..num_rows {
            let entry = row % 256;
            let a = (entry / 16) as u8;
            let b = (entry % 16) as u8;
            trace.fill_columns(row, a, PreprocessedColumn::A);
            trace.fill_columns(row, b, PreprocessedColumn::B);
            trace.fill_columns(row, a & b, PreprocessedColumn::AndResult);
        }

        trace.finalize_bit_reversed()
    }

    fn generate_main_trace_immut_min(
        &self,
        side_note: &SideNote,
        min_log_size: u32,
    ) -> FinalizedTrace {
        let log_size = super::super::table_log_size(BITWISE_LOG_SIZE, min_log_size);
        let mut trace = TraceBuilder::<Column>::new(log_size);
        let num_rows = trace.num_rows();

        for row in 0..num_rows {
            if row < 256 {
                let a = (row / 16) as u8;
                let b = (row % 16) as u8;
                let mult = side_note
                    .bitwise_and_counts
                    .get(&(a, b))
                    .copied()
                    .unwrap_or(0);
                trace.fill_columns(row, BaseField::from(mult), Column::Multiplicity);
            }
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

        let bitwise_lookup: &BitwiseAndLookupElements = lookup_elements.as_ref();
        let a = crate::trace::preprocessed_base_column!(component_trace, PreprocessedColumn::A);
        let b = crate::trace::preprocessed_base_column!(component_trace, PreprocessedColumn::B);
        let and_result =
            crate::trace::preprocessed_base_column!(component_trace, PreprocessedColumn::AndResult);
        let mult = crate::trace::original_base_column!(component_trace, Column::Multiplicity);

        // Consumer side (negative multiplicity)
        logup.add_to_relation_with(
            bitwise_lookup,
            [mult[0].clone()],
            |[m]| (-m).into(),
            &[a[0].clone(), b[0].clone(), and_result[0].clone()],
        );

        logup.finalize()
    }
}
