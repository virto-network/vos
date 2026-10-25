use stwo::core::fields::m31::BaseField;
#[cfg(feature = "prover")]
use stwo::{
    core::{ColumnVec, fields::qm31::SecureField},
    prover::{
        backend::simd::SimdBackend,
        poly::{BitReversedOrder, circle::CircleEvaluation},
    },
};
use stwo_constraint_framework::{EvalAtRow, RelationEntry};

use crate::air_column::{AirColumn, PreprocessedAirColumn};
use crate::trace::eval::TraceEval;
#[cfg(feature = "prover")]
use crate::trace::{
    builder::{FinalizedTrace, TraceBuilder},
    component::ComponentTrace,
};

#[cfg(feature = "prover")]
use crate::framework::BuiltInProverComponent;
#[cfg(feature = "prover")]
use crate::lookups::{AllLookupElements, LogupTraceBuilder};
#[cfg(feature = "prover")]
use crate::side_note::SideNote;
use crate::{
    framework::{BuiltInComponent, Logup},
    lookups::BitwiseAndLookupElements,
};

/// BitwiseLookupChip: 16×16 table for nibble-level AND.
///
/// Each row provides (a, b, a&b) for 4-bit values with multiplicity = number
/// of times this combination was used. The CpuChip splits bytes into nibbles
/// and produces 16 lookups per bitwise op (2 nibbles × 8 bytes).
pub struct BitwiseLookupChip;

const BITWISE_LOG_SIZE: u32 = 8; // 2^8 = 256 rows = 16×16

/// The table's entries are its preprocessed columns, which the verifier
/// commits; the main trace holds only their multiplicities.
#[derive(Debug, Copy, Clone, AirColumn)]
pub enum Column {
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
    const LOGUP: Logup = Logup::Single;
    type PreprocessedColumn = PreprocessedColumn;
    type MainColumn = Column;
    type LookupElements = BitwiseAndLookupElements;

    fn add_constraints<E: EvalAtRow>(
        &self,
        eval: &mut E,
        trace_eval: TraceEval<PreprocessedColumn, Column, E>,
        lookup_elements: &BitwiseAndLookupElements,
    ) {
        let a = crate::trace::preprocessed_trace_eval!(trace_eval, PreprocessedColumn::A);
        let b = crate::trace::preprocessed_trace_eval!(trace_eval, PreprocessedColumn::B);
        let and_result =
            crate::trace::preprocessed_trace_eval!(trace_eval, PreprocessedColumn::AndResult);
        let mult = crate::trace::trace_eval!(trace_eval, Column::Multiplicity);

        // Consumer: negative multiplicity
        eval.add_to_relation(RelationEntry::new(
            lookup_elements,
            (-mult[0].clone()).into(),
            &[a[0].clone(), b[0].clone(), and_result[0].clone()],
        ));
    }
}

#[cfg(feature = "prover")]
impl BuiltInProverComponent for BitwiseLookupChip {
    const IS_PRODUCER: bool = false;

    fn generate_preprocessed_trace(&self, log_size: u32, _side_note: &SideNote) -> FinalizedTrace {
        let log_size = super::table_log_size(BITWISE_LOG_SIZE, log_size);
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
        let log_size = super::table_log_size(BITWISE_LOG_SIZE, min_log_size);
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
