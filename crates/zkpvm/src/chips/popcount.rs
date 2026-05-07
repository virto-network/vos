//! Phase 33: PopcountChip — 256-row lookup table proving
//! `popcount = byte.count_ones()`.
//!
//! Each row holds `(byte, popcount(byte))` for `byte ∈ [0, 256)`.
//! CpuChip emits per-byte lookups on `IsCountSetBits` rows
//! (CountSetBits32 / CountSetBits64): `(val_d[i], BytePopcount[i]) ∈
//! popcount`.  This chip consumes them with negative multiplicity.
//!
//! Mirrors the PowerOfTwoChip pattern (a fixed preprocessed table
//! plus a Multiplicity column counted from CpuChip's per-row charges).

#[allow(unused_imports)]
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
    framework::BuiltInComponent,
    lookups::PopcountLookupElements,
};
#[cfg(feature = "prover")]
use crate::framework::BuiltInProverComponent;
#[cfg(feature = "prover")]
use crate::lookups::{AllLookupElements, LogupTraceBuilder};
#[cfg(feature = "prover")]
use crate::side_note::SideNote;

pub struct PopcountChip;

const POPCOUNT_LOG_SIZE: u32 = 8; // 2^8 = 256 rows

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
        let popcount = crate::trace::preprocessed_trace_eval!(trace_eval, PreprocessedColumn::Popcount);
        let mult = crate::trace::trace_eval!(trace_eval, Column::Multiplicity);

        // Tuple shape: (byte, popcount).
        let tuple = vec![byte[0].clone(), popcount[0].clone()];
        eval.add_to_relation(RelationEntry::new(
            lookup_elements,
            (-mult[0].clone()).into(),
            &tuple,
        ));

        eval.finalize_logup();
    }
}

#[cfg(feature = "prover")]
impl BuiltInProverComponent for PopcountChip {
    const IS_PRODUCER: bool = false;

    fn generate_preprocessed_trace(&self, _log_size: u32, _side_note: &SideNote) -> FinalizedTrace {
        let log_size = POPCOUNT_LOG_SIZE.max(LOG_N_LANES);
        let mut trace = TraceBuilder::<PreprocessedColumn>::new(log_size);

        for row in 0..256usize {
            trace.fill_columns(row, row as u8, PreprocessedColumn::Byte);
            trace.fill_columns(row, (row as u8).count_ones() as u8, PreprocessedColumn::Popcount);
        }

        trace.finalize_bit_reversed()
    }

    fn generate_main_trace_immut(&self, side_note: &SideNote) -> FinalizedTrace {
        let log_size = POPCOUNT_LOG_SIZE.max(LOG_N_LANES);
        let mut trace = TraceBuilder::<Column>::new(log_size);

        for row in 0..256usize {
            let count = side_note.popcount_counts[row];
            trace.fill_columns(row, BaseField::from(count), Column::Multiplicity);
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

        let popcount: &PopcountLookupElements = lookup_elements.as_ref();
        let byte = crate::trace::preprocessed_base_column!(component_trace, PreprocessedColumn::Byte);
        let popc = crate::trace::preprocessed_base_column!(component_trace, PreprocessedColumn::Popcount);
        let mult = crate::trace::original_base_column!(component_trace, Column::Multiplicity);

        let tuple = vec![byte[0].clone(), popc[0].clone()];
        logup.add_to_relation_with(
            popcount,
            [mult[0].clone()],
            |[m]| (-m).into(),
            &tuple,
        );

        logup.finalize()
    }
}
