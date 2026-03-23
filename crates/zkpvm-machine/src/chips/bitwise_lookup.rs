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

use zkpvm_air_column::{AirColumn, PreprocessedAirColumn};
use zkpvm_trace::{
    builder::{FinalizedTrace, TraceBuilder},
    component::ComponentTrace,
    eval::TraceEval,
};

use crate::{
    framework::BuiltInComponent,
    lookups::{AllLookupElements, LogupTraceBuilder, BitwiseAndLookupElements},
    side_note::SideNote,
};

/// BitwiseLookupChip: 256×256 table for byte-level AND.
///
/// Each row provides (a, b, a&b) with multiplicity = number of times
/// this combination was used by bitwise instructions.
/// The CpuChip produces positive entries, this chip consumes them.
pub struct BitwiseLookupChip;

const BITWISE_LOG_SIZE: u32 = 16; // 2^16 = 65536 rows = 256×256

#[derive(Debug, Copy, Clone, AirColumn)]
pub enum Column {
    /// Byte value a (0-255)
    #[size = 1]
    A,
    /// Byte value b (0-255)
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
            if row < 65536 {
                let a = (row / 256) as u8;
                let b = (row % 256) as u8;
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
            if row < 65536 {
                let a = (row / 256) as u8;
                let b = (row % 256) as u8;
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
        let a = zkpvm_trace::original_base_column!(component_trace, Column::A);
        let b = zkpvm_trace::original_base_column!(component_trace, Column::B);
        let and_result = zkpvm_trace::original_base_column!(component_trace, Column::AndResult);
        let mult = zkpvm_trace::original_base_column!(component_trace, Column::Multiplicity);

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
        let a = zkpvm_trace::trace_eval!(trace_eval, Column::A);
        let b = zkpvm_trace::trace_eval!(trace_eval, Column::B);
        let and_result = zkpvm_trace::trace_eval!(trace_eval, Column::AndResult);
        let mult = zkpvm_trace::trace_eval!(trace_eval, Column::Multiplicity);

        // Consumer: negative multiplicity
        eval.add_to_relation(RelationEntry::new(
            lookup_elements,
            (-mult[0].clone()).into(),
            &[a[0].clone(), b[0].clone(), and_result[0].clone()],
        ));

        eval.finalize_logup();
    }
}
