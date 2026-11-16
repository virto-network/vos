use stwo_constraint_framework::{EvalAtRow, RelationEntry};

use crate::air_column::{AirColumn, PreprocessedAirColumn};
use crate::trace::eval::TraceEval;

use crate::{
    framework::{BuiltInComponent, Logup},
    lookups::Range256LookupElements,
};

/// Range multiplicity chip: proves that all byte values (0-255) are valid.
/// This is the "receiver" side of the range check lookup.
#[derive(Clone, Copy)]
pub struct RangeMultiplicity256;

/// The table's entries are its preprocessed column, which the verifier
/// commits; the main trace holds only their multiplicities.
#[derive(Debug, Copy, Clone, AirColumn)]
pub enum Column {
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
    const LOGUP: Logup = Logup::Single;
    type PreprocessedColumn = PreprocessedColumn;
    type MainColumn = Column;
    type LookupElements = Range256LookupElements;

    fn add_constraints<E: EvalAtRow>(
        &self,
        eval: &mut E,
        trace_eval: TraceEval<PreprocessedColumn, Column, E>,
        lookup_elements: &Range256LookupElements,
    ) {
        let value = crate::trace::preprocessed_trace_eval!(trace_eval, PreprocessedColumn::Value);
        let mult = crate::trace::trace_eval!(trace_eval, Column::Multiplicity);

        // Negative multiplicity (receiver side)
        eval.add_to_relation(RelationEntry::new(
            lookup_elements,
            (-mult[0].clone()).into(),
            &[value[0].clone()],
        ));
    }
}

#[cfg(feature = "prover")]
mod fill;
