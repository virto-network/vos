use stwo_constraint_framework::{EvalAtRow, RelationEntry};

use crate::air_column::{AirColumn, PreprocessedAirColumn};
use crate::trace::eval::TraceEval;

use crate::{
    framework::{BuiltInComponent, Logup},
    lookups::BitwiseAndByteLookupElements,
};

/// Byte-wide bitwise-AND table: 2^16 rows of `(a, b, a & b)` for every byte
/// pair, with a free multiplicity column.  The blake2b chips consume this
/// (one lookup per byte AND) instead of the two nibble lookups against the
/// 16×16 `BitwiseLookupChip`; the byte-ness of `a`/`b` comes free from table
/// membership, so the per-nibble witness columns those chips carried die.
///
/// Row `a·256 + b` holds `(a, b, a & b)` — the same index
/// `side_note.bitwise_and_byte_counts` is keyed by.
#[derive(Clone, Copy)]
pub struct BitwiseAndByteChip;

#[derive(Debug, Copy, Clone, AirColumn)]
pub enum Column {
    /// Multiplicity: how many times this `(a, b)` pair was used.
    #[size = 1]
    Multiplicity,
}

#[derive(Debug, Copy, Clone, PreprocessedAirColumn)]
#[preprocessed_prefix = "bitandbyte"]
pub enum PreprocessedColumn {
    /// Byte value a (preprocessed, known to verifier).
    #[size = 1]
    A,
    /// Byte value b (preprocessed).
    #[size = 1]
    B,
    /// a & b (preprocessed).
    #[size = 1]
    AndResult,
}

impl BuiltInComponent for BitwiseAndByteChip {
    const LOGUP: Logup = Logup::Single;
    type PreprocessedColumn = PreprocessedColumn;
    type MainColumn = Column;
    type LookupElements = BitwiseAndByteLookupElements;

    fn add_constraints<E: EvalAtRow>(
        &self,
        eval: &mut E,
        trace_eval: TraceEval<PreprocessedColumn, Column, E>,
        lookup_elements: &BitwiseAndByteLookupElements,
    ) {
        let a = crate::trace::preprocessed_trace_eval!(trace_eval, PreprocessedColumn::A);
        let b = crate::trace::preprocessed_trace_eval!(trace_eval, PreprocessedColumn::B);
        let and_result =
            crate::trace::preprocessed_trace_eval!(trace_eval, PreprocessedColumn::AndResult);
        let mult = crate::trace::trace_eval!(trace_eval, Column::Multiplicity);

        // Consumer/receiver side: negative multiplicity.
        eval.add_to_relation(RelationEntry::new(
            lookup_elements,
            (-mult[0].clone()).into(),
            &[a[0].clone(), b[0].clone(), and_result[0].clone()],
        ));
    }
}

#[cfg(feature = "prover")]
mod fill;
