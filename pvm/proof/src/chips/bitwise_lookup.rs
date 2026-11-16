use stwo_constraint_framework::{EvalAtRow, RelationEntry};

use crate::air_column::{AirColumn, PreprocessedAirColumn};
use crate::trace::eval::TraceEval;

use crate::{
    framework::{BuiltInComponent, Logup},
    lookups::BitwiseAndLookupElements,
};

/// BitwiseLookupChip: 16×16 table for nibble-level AND.
///
/// Each row provides (a, b, a&b) for 4-bit values with multiplicity = number
/// of times this combination was used. The CpuChip splits bytes into nibbles
/// and produces 16 lookups per bitwise op (2 nibbles × 8 bytes).
#[derive(Clone, Copy)]
pub struct BitwiseLookupChip;

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
mod fill;
