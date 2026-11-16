//! PopcountChip — 256-row lookup table proving
//! `popcount = byte.count_ones()`.
//!
//! Each row holds `(byte, popcount(byte))` for `byte ∈ [0, 256)`.
//! CpuChip emits per-byte lookups on `IsCountSetBits` rows
//! (CountSetBits32 / CountSetBits64): `(val_d[i], BytePopcount[i]) ∈
//! popcount`.  This chip consumes them with negative multiplicity.
//!
//! Mirrors the PowerOfTwoChip pattern (a fixed preprocessed table
//! plus a Multiplicity column counted from CpuChip's per-row charges).

use crate::prelude::*;
use stwo_constraint_framework::{EvalAtRow, RelationEntry};

use crate::air_column::{AirColumn, PreprocessedAirColumn};
use crate::trace::eval::TraceEval;

use crate::{
    framework::{BuiltInComponent, Logup},
    lookups::PopcountLookupElements,
};

#[derive(Clone, Copy)]
pub struct PopcountChip;

#[derive(Debug, Copy, Clone, AirColumn)]
pub enum Column {
    /// Multiplicity: how many CpuChip emissions hit this byte.
    #[size = 1]
    Multiplicity,
}

#[derive(Debug, Copy, Clone, PreprocessedAirColumn)]
#[preprocessed_prefix = "popcount"]
pub enum PreprocessedColumn {
    /// Byte value (0..255).
    #[size = 1]
    Byte,
    /// `byte.count_ones()` (0..8).
    #[size = 1]
    Popcount,
}

impl BuiltInComponent for PopcountChip {
    const LOGUP: Logup = Logup::Single;
    type PreprocessedColumn = PreprocessedColumn;
    type MainColumn = Column;
    type LookupElements = PopcountLookupElements;

    fn add_constraints<E: EvalAtRow>(
        &self,
        eval: &mut E,
        trace_eval: TraceEval<PreprocessedColumn, Column, E>,
        lookup_elements: &PopcountLookupElements,
    ) {
        let byte = crate::trace::preprocessed_trace_eval!(trace_eval, PreprocessedColumn::Byte);
        let popcount =
            crate::trace::preprocessed_trace_eval!(trace_eval, PreprocessedColumn::Popcount);
        let mult = crate::trace::trace_eval!(trace_eval, Column::Multiplicity);

        // Tuple shape: (byte, popcount).
        let tuple = vec![byte[0].clone(), popcount[0].clone()];
        eval.add_to_relation(RelationEntry::new(
            lookup_elements,
            (-mult[0].clone()).into(),
            &tuple,
        ));
    }
}

#[cfg(feature = "prover")]
mod fill;
