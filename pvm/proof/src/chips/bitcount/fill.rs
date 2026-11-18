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

const BITCOUNT_LOG_SIZE: u32 = 8; // 2^8 = 256 rows

impl BuiltInProverComponent for BitcountChip {
    const IS_PRODUCER: bool = false;

    fn generate_preprocessed_trace(&self, log_size: u32, _side_note: &SideNote) -> FinalizedTrace {
        let log_size = super::super::table_log_size(BITCOUNT_LOG_SIZE, log_size);
        let mut trace = TraceBuilder::<PreprocessedColumn>::new(log_size);

        for row in 0..trace.num_rows() {
            let byte = row as u8;
            let lz: u8 = if byte == 0 {
                8
            } else {
                byte.leading_zeros() as u8
            };
            let tz: u8 = if byte == 0 {
                8
            } else {
                byte.trailing_zeros() as u8
            };
            trace.fill_columns(row, byte, PreprocessedColumn::Byte);
            trace.fill_columns(row, lz, PreprocessedColumn::LzByte);
            trace.fill_columns(row, tz, PreprocessedColumn::TzByte);
        }

        trace.finalize_bit_reversed()
    }

    fn generate_main_trace_immut_min(
        &self,
        side_note: &SideNote,
        min_log_size: u32,
    ) -> FinalizedTrace {
        let log_size = super::super::table_log_size(BITCOUNT_LOG_SIZE, min_log_size);
        let mut trace = TraceBuilder::<Column>::new(log_size);

        for row in 0..256usize {
            let count = side_note.bitcount_counts[row];
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

        let bitcount: &BitcountLookupElements = lookup_elements.as_ref();
        let byte =
            crate::trace::preprocessed_base_column!(component_trace, PreprocessedColumn::Byte);
        let lz =
            crate::trace::preprocessed_base_column!(component_trace, PreprocessedColumn::LzByte);
        let tz =
            crate::trace::preprocessed_base_column!(component_trace, PreprocessedColumn::TzByte);
        let mult = crate::trace::original_base_column!(component_trace, Column::Multiplicity);

        let tuple = vec![byte[0].clone(), lz[0].clone(), tz[0].clone()];
        logup.add_to_relation_with(bitcount, [mult[0].clone()], |[m]| (-m).into(), &tuple);

        logup.finalize()
    }
}
