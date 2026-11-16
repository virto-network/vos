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

impl BuiltInProverComponent for ByteToBitsChip {
    const IS_PRODUCER: bool = false;

    fn generate_preprocessed_trace(&self, log_size: u32, _side_note: &SideNote) -> FinalizedTrace {
        let log_size = super::super::table_log_size(BYTE_TO_BITS_LOG_SIZE, log_size);
        let mut trace = TraceBuilder::<PreprocessedColumn>::new(log_size);

        for row in 0..trace.num_rows() {
            let byte = row as u8;
            trace.fill_columns(row, byte, PreprocessedColumn::Byte);
            trace.fill_columns(row, (byte >> 0) & 1, PreprocessedColumn::Bit0);
            trace.fill_columns(row, (byte >> 1) & 1, PreprocessedColumn::Bit1);
            trace.fill_columns(row, (byte >> 2) & 1, PreprocessedColumn::Bit2);
            trace.fill_columns(row, (byte >> 3) & 1, PreprocessedColumn::Bit3);
            trace.fill_columns(row, (byte >> 4) & 1, PreprocessedColumn::Bit4);
            trace.fill_columns(row, (byte >> 5) & 1, PreprocessedColumn::Bit5);
            trace.fill_columns(row, (byte >> 6) & 1, PreprocessedColumn::Bit6);
            trace.fill_columns(row, (byte >> 7) & 1, PreprocessedColumn::Bit7);
        }

        trace.finalize_bit_reversed()
    }

    fn generate_main_trace_immut_min(
        &self,
        side_note: &SideNote,
        min_log_size: u32,
    ) -> FinalizedTrace {
        let log_size = super::super::table_log_size(BYTE_TO_BITS_LOG_SIZE, min_log_size);
        let mut trace = TraceBuilder::<Column>::new(log_size);

        for row in 0..256usize {
            let count = side_note.byte_to_bits_counts[row];
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

        let elems: &ByteToBitsLookupElements = lookup_elements.as_ref();
        let byte =
            crate::trace::preprocessed_base_column!(component_trace, PreprocessedColumn::Byte);
        let b0 = crate::trace::preprocessed_base_column!(component_trace, PreprocessedColumn::Bit0);
        let b1 = crate::trace::preprocessed_base_column!(component_trace, PreprocessedColumn::Bit1);
        let b2 = crate::trace::preprocessed_base_column!(component_trace, PreprocessedColumn::Bit2);
        let b3 = crate::trace::preprocessed_base_column!(component_trace, PreprocessedColumn::Bit3);
        let b4 = crate::trace::preprocessed_base_column!(component_trace, PreprocessedColumn::Bit4);
        let b5 = crate::trace::preprocessed_base_column!(component_trace, PreprocessedColumn::Bit5);
        let b6 = crate::trace::preprocessed_base_column!(component_trace, PreprocessedColumn::Bit6);
        let b7 = crate::trace::preprocessed_base_column!(component_trace, PreprocessedColumn::Bit7);
        let mult = crate::trace::original_base_column!(component_trace, Column::Multiplicity);

        let tuple = vec![
            byte[0].clone(),
            b0[0].clone(),
            b1[0].clone(),
            b2[0].clone(),
            b3[0].clone(),
            b4[0].clone(),
            b5[0].clone(),
            b6[0].clone(),
            b7[0].clone(),
        ];
        logup.add_to_relation_with(elems, [mult[0].clone()], |[m]| (-m).into(), &tuple);

        logup.finalize()
    }
}
