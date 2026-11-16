//! The chip's trace generation, the prover's half.

use super::*;
use crate::framework::BuiltInProverComponent;
use crate::lookups::{AllLookupElements, LogupTraceBuilder};
use crate::side_note::SideNote;
use crate::trace::{
    builder::{FinalizedTrace, TraceBuilder},
    component::ComponentTrace,
};
use stwo::core::fields::m31::BaseField;
use stwo::{
    core::{ColumnVec, fields::qm31::SecureField},
    prover::{
        backend::simd::SimdBackend,
        poly::{BitReversedOrder, circle::CircleEvaluation},
    },
};

const RANGE_LOG_SIZE: u32 = 8; // 256 rows, one per byte value

impl BuiltInProverComponent for RangeMultiplicity256 {
    const IS_PRODUCER: bool = false;

    fn generate_preprocessed_trace(&self, log_size: u32, _side_note: &SideNote) -> FinalizedTrace {
        let log_size = super::super::table_log_size(RANGE_LOG_SIZE, log_size);
        let mut trace = TraceBuilder::<PreprocessedColumn>::new(log_size);
        let num_rows = trace.num_rows();

        for row in 0..num_rows {
            trace.fill_columns(row, (row % 256) as u8, PreprocessedColumn::Value);
        }

        trace.finalize_bit_reversed()
    }

    fn generate_main_trace_immut_min(
        &self,
        side_note: &SideNote,
        min_log_size: u32,
    ) -> FinalizedTrace {
        let log_size = super::super::table_log_size(RANGE_LOG_SIZE, min_log_size);
        let mut trace = TraceBuilder::<Column>::new(log_size);
        let num_rows = trace.num_rows();

        for row in 0..num_rows {
            let mult = if row < 256 {
                side_note.range256_counts[row]
            } else {
                0
            };
            trace.fill_columns(row, BaseField::from(mult), Column::Multiplicity);
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

        let range256: &Range256LookupElements = lookup_elements.as_ref();
        let value =
            crate::trace::preprocessed_base_column!(component_trace, PreprocessedColumn::Value);
        let mult = crate::trace::original_base_column!(component_trace, Column::Multiplicity);

        // Negative contribution: this is the "receiver" side
        logup.add_to_relation_with(
            range256,
            [mult[0].clone()],
            |[m]| {
                // Negate: the multiplicity chip provides the values, so it subtracts
                let neg: stwo::prover::backend::simd::qm31::PackedSecureField = (-m).into();
                neg
            },
            &[value[0].clone()],
        );

        logup.finalize()
    }
}
