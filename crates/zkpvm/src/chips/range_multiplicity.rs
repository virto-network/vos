use alloc::{boxed::Box, vec, vec::Vec};
use stwo::core::fields::m31::BaseField;
#[cfg(feature = "prover")]
use stwo::{
    core::{
        fields::qm31::SecureField,
        ColumnVec,
    },
    prover::{
        backend::simd::{m31::LOG_N_LANES, SimdBackend},
        poly::{circle::CircleEvaluation, BitReversedOrder},
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

use crate::{
    framework::{BuiltInComponent},
    lookups::{Range256LookupElements},
};
#[cfg(feature = "prover")]
use crate::framework::BuiltInProverComponent;
#[cfg(feature = "prover")]
use crate::lookups::{AllLookupElements, LogupTraceBuilder};
#[cfg(feature = "prover")]
use crate::side_note::SideNote;

/// Range multiplicity chip: proves that all byte values (0-255) are valid.
/// This is the "receiver" side of the range check lookup.
pub struct RangeMultiplicity256;

const RANGE_LOG_SIZE: u32 = 8; // 256 rows, one per byte value

#[derive(Debug, Copy, Clone, AirColumn)]
pub enum Column {
    /// The byte value (0-255).
    #[size = 1]
    Value,
    /// Multiplicity count for this value.
    #[size = 1]
    Multiplicity,
}

#[derive(Debug, Copy, Clone, PreprocessedAirColumn)]
#[preprocessed_prefix = "range256"]
pub enum PreprocessedColumn {
    /// The byte value (preprocessed, known to verifier).
    #[size = 1]
    Value,
}

impl BuiltInComponent for RangeMultiplicity256 {
    type PreprocessedColumn = PreprocessedColumn;
    type MainColumn = Column;
    type LookupElements = Range256LookupElements;

    fn add_constraints<E: EvalAtRow>(
        &self,
        eval: &mut E,
        trace_eval: TraceEval<PreprocessedColumn, Column, E>,
        lookup_elements: &Range256LookupElements,
    ) {
        let value = crate::trace::trace_eval!(trace_eval, Column::Value);
        let mult = crate::trace::trace_eval!(trace_eval, Column::Multiplicity);

        // Negative multiplicity (receiver side)
        eval.add_to_relation(RelationEntry::new(
            lookup_elements,
            (-mult[0].clone()).into(),
            &[value[0].clone()],
        ));

        eval.finalize_logup();
    }
}

#[cfg(feature = "prover")]
impl BuiltInProverComponent for RangeMultiplicity256 {
    fn generate_preprocessed_trace(
        &self,
        _log_size: u32,
        _side_note: &SideNote,
    ) -> FinalizedTrace {
        let log_size = RANGE_LOG_SIZE.max(LOG_N_LANES);
        let mut trace = TraceBuilder::<PreprocessedColumn>::new(log_size);
        let num_rows = trace.num_rows();

        for row in 0..num_rows {
            let value = if row < 256 { row as u8 } else { 0 };
            trace.fill_columns(row, value, PreprocessedColumn::Value);
        }

        trace.finalize_bit_reversed()
    }

    fn generate_main_trace(&self, side_note: &mut SideNote) -> FinalizedTrace {
        let log_size = RANGE_LOG_SIZE.max(LOG_N_LANES);
        let mut trace = TraceBuilder::<Column>::new(log_size);
        let num_rows = trace.num_rows();

        for row in 0..num_rows {
            let value = if row < 256 { row as u8 } else { 0 };
            trace.fill_columns(row, value, Column::Value);

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
        component_trace: ComponentTrace,
        _side_note: &SideNote,
        lookup_elements: &AllLookupElements,
    ) -> (
        ColumnVec<CircleEvaluation<SimdBackend, BaseField, BitReversedOrder>>,
        SecureField,
    ) {
        let log_size = component_trace.log_size();
        let mut logup = LogupTraceBuilder::new(log_size);

        let range256: &Range256LookupElements = lookup_elements.as_ref();
        let value = crate::trace::original_base_column!(component_trace, Column::Value);
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
