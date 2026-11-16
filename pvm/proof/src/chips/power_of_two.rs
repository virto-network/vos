use crate::prelude::*;
use stwo_constraint_framework::{EvalAtRow, RelationEntry};

use crate::air_column::{AirColumn, PreprocessedAirColumn};
use crate::trace::eval::TraceEval;

use crate::{
    framework::{BuiltInComponent, Logup},
    lookups::PowerOfTwoLookupElements,
};

/// PowerOfTwoChip: 64-row lookup table proving val_d = 2^shift_amount.
///
/// Each row i provides (shift_amount=i, power_val=2^i as 8 LE bytes).
/// The CpuChip produces positive entries when is_shift=1 and shift_op ∈ {0,1}.
/// This chip consumes them with negative multiplicity.
#[derive(Clone, Copy)]
pub struct PowerOfTwoChip;

/// The table's entries are its preprocessed columns, which the verifier
/// commits; the main trace holds only their multiplicities.
#[derive(Debug, Copy, Clone, AirColumn)]
pub enum Column {
    /// Multiplicity: how many times this entry was used
    #[size = 1]
    Multiplicity,
}

#[derive(Debug, Copy, Clone, PreprocessedAirColumn)]
#[preprocessed_prefix = "pow2"]
pub enum PreprocessedColumn {
    /// Shift amount (preprocessed, known)
    #[size = 1]
    ShiftAmount,
    /// Power value (preprocessed, known)
    #[size = 8]
    PowerVal,
}

impl BuiltInComponent for PowerOfTwoChip {
    const LOGUP: Logup = Logup::Single;
    type PreprocessedColumn = PreprocessedColumn;
    type MainColumn = Column;
    type LookupElements = PowerOfTwoLookupElements;

    fn add_constraints<E: EvalAtRow>(
        &self,
        eval: &mut E,
        trace_eval: TraceEval<PreprocessedColumn, Column, E>,
        lookup_elements: &PowerOfTwoLookupElements,
    ) {
        let shift_amount =
            crate::trace::preprocessed_trace_eval!(trace_eval, PreprocessedColumn::ShiftAmount);
        let power_val =
            crate::trace::preprocessed_trace_eval!(trace_eval, PreprocessedColumn::PowerVal);
        let mult = crate::trace::trace_eval!(trace_eval, Column::Multiplicity);

        let mut tuple: Vec<E::F> = vec![shift_amount[0].clone()];
        tuple.extend_from_slice(&power_val);

        eval.add_to_relation(RelationEntry::new(
            lookup_elements,
            (-mult[0].clone()).into(),
            &tuple,
        ));
    }
}

#[cfg(feature = "prover")]
mod fill;
