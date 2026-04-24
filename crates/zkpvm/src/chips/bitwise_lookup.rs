use stwo::{
    core::{
        fields::{m31::BaseField, qm31::SecureField},
        ColumnVec,
    },
    prover::{
        backend::simd::{m31::LOG_N_LANES, SimdBackend},
        poly::{circle::CircleEvaluation, BitReversedOrder},
    },
};
use stwo_constraint_framework::{EvalAtRow, RelationEntry};

use crate::air_column::{AirColumn, PreprocessedAirColumn};
use crate::trace::{
    builder::{FinalizedTrace, TraceBuilder},
    component::ComponentTrace,
    eval::TraceEval,
};

use crate::{
    framework::BuiltInComponent,
    lookups::{AllLookupElements, LogupTraceBuilder, BitwiseAndLookupElements},
    side_note::SideNote,
};

/// BitwiseLookupChip: 16×16 table for nibble-level AND.
///
/// Each row provides (a, b, a&b) for 4-bit values with multiplicity = number
/// of times this combination was used. The CpuChip splits bytes into nibbles
/// and produces 16 lookups per bitwise op (2 nibbles × 8 bytes).
pub struct BitwiseLookupChip;

const BITWISE_LOG_SIZE: u32 = 8; // 2^8 = 256 rows = 16×16

#[derive(Debug, Copy, Clone, AirColumn)]
pub enum Column {
    /// Nibble value a (0-15)
    #[size = 1]
    A,
    /// Nibble value b (0-15)
    #[size = 1]
    B,
    /// a AND b
    #[size = 1]
    AndResult,
    /// Multiplicity: how many times this (a, b) pair was used
    #[size = 1]
    Multiplicity,
}

#[derive(Debug, Copy, Clone, PreprocessedAirColumn)]
#[preprocessed_prefix = "bitand"]
pub enum PreprocessedColumn {
    /// a value (preprocessed, known to verifier)
    #[size = 1]
    A,
    /// b value (preprocessed)
    #[size = 1]
    B,
    /// a & b (preprocessed)
    #[size = 1]
    AndResult,
}

impl BuiltInComponent for BitwiseLookupChip {
    type PreprocessedColumn = PreprocessedColumn;
    type MainColumn = Column;
    type LookupElements = BitwiseAndLookupElements;

    fn generate_preprocessed_trace(&self, _log_size: u32, _side_note: &SideNote) -> FinalizedTrace {
        let log_size = BITWISE_LOG_SIZE.max(LOG_N_LANES);
        let mut trace = TraceBuilder::<PreprocessedColumn>::new(log_size);
        let num_rows = trace.num_rows();

        for row in 0..num_rows {
            if row < 256 {
                let a = (row / 16) as u8;
                let b = (row % 16) as u8;
                trace.fill_columns(row, a, PreprocessedColumn::A);
                trace.fill_columns(row, b, PreprocessedColumn::B);
                trace.fill_columns(row, a & b, PreprocessedColumn::AndResult);
            }
        }

        trace.finalize_bit_reversed()
    }

    fn generate_main_trace(&self, side_note: &mut SideNote) -> FinalizedTrace {
        let log_size = BITWISE_LOG_SIZE.max(LOG_N_LANES);
        let mut trace = TraceBuilder::<Column>::new(log_size);
        let num_rows = trace.num_rows();

        for row in 0..num_rows {
            if row < 256 {
                let a = (row / 16) as u8;
                let b = (row % 16) as u8;
                trace.fill_columns(row, a, Column::A);
                trace.fill_columns(row, b, Column::B);
                trace.fill_columns(row, a & b, Column::AndResult);

                let mult = side_note.bitwise_and_counts
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
        component_trace: ComponentTrace,
        _side_note: &SideNote,
        lookup_elements: &AllLookupElements,
    ) -> (
        ColumnVec<CircleEvaluation<SimdBackend, BaseField, BitReversedOrder>>,
        SecureField,
    ) {
        let log_size = component_trace.log_size();
        let mut logup = LogupTraceBuilder::new(log_size);

        let bitwise_lookup: &BitwiseAndLookupElements = lookup_elements.as_ref();
        let a = crate::trace::original_base_column!(component_trace, Column::A);
        let b = crate::trace::original_base_column!(component_trace, Column::B);
        let and_result = crate::trace::original_base_column!(component_trace, Column::AndResult);
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

    fn add_constraints<E: EvalAtRow>(
        &self,
        eval: &mut E,
        trace_eval: TraceEval<PreprocessedColumn, Column, E>,
        lookup_elements: &BitwiseAndLookupElements,
    ) {
        let a = crate::trace::trace_eval!(trace_eval, Column::A);
        let b = crate::trace::trace_eval!(trace_eval, Column::B);
        let and_result = crate::trace::trace_eval!(trace_eval, Column::AndResult);
        let mult = crate::trace::trace_eval!(trace_eval, Column::Multiplicity);

        // Consumer: negative multiplicity
        eval.add_to_relation(RelationEntry::new(
            lookup_elements,
            (-mult[0].clone()).into(),
            &[a[0].clone(), b[0].clone(), and_result[0].clone()],
        ));

        eval.finalize_logup();
    }
}
