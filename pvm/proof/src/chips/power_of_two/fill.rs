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

impl BuiltInProverComponent for PowerOfTwoChip {
    const IS_PRODUCER: bool = false;

    fn generate_preprocessed_trace(&self, log_size: u32, _side_note: &SideNote) -> FinalizedTrace {
        let log_size = super::super::table_log_size(POW2_LOG_SIZE, log_size);
        let mut trace = TraceBuilder::<PreprocessedColumn>::new(log_size);

        for row in 0..trace.num_rows() {
            let shift = row % 64;
            trace.fill_columns(row, shift as u8, PreprocessedColumn::ShiftAmount);
            trace.fill_columns(row, 1u64 << shift, PreprocessedColumn::PowerVal);
        }

        trace.finalize_bit_reversed()
    }

    fn generate_main_trace_immut_min(
        &self,
        side_note: &SideNote,
        min_log_size: u32,
    ) -> FinalizedTrace {
        let log_size = super::super::table_log_size(POW2_LOG_SIZE, min_log_size);
        let mut trace = TraceBuilder::<Column>::new(log_size);

        // Count shift usage: the CpuChip stores ShiftAmount for shift ops.
        // We count how many times each shift_amount value (0-63) is used.
        let mut counts = [0u32; 64];
        // Use pre-accumulated counts from SideNote
        for (i, &c) in side_note.power_of_two_counts.iter().enumerate() {
            if i < 64 {
                counts[i] = c;
            }
        }

        for (row, &count) in counts.iter().enumerate() {
            trace.fill_columns(row, BaseField::from(count), Column::Multiplicity);
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

        let pow2_lookup: &PowerOfTwoLookupElements = lookup_elements.as_ref();
        let shift_amount = crate::trace::preprocessed_base_column!(
            component_trace,
            PreprocessedColumn::ShiftAmount
        );
        let power_val =
            crate::trace::preprocessed_base_column!(component_trace, PreprocessedColumn::PowerVal);
        let mult = crate::trace::original_base_column!(component_trace, Column::Multiplicity);

        // Consumer side (negative multiplicity)
        let mut tuple: Vec<_> = vec![shift_amount[0].clone()];
        tuple.extend_from_slice(&power_val);

        logup.add_to_relation_with(pow2_lookup, [mult[0].clone()], |[m]| (-m).into(), &tuple);

        logup.finalize()
    }
}
