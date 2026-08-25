#[allow(unused_imports)]
use alloc::{boxed::Box, vec, vec::Vec};
use stwo::core::fields::m31::BaseField;
#[cfg(feature = "prover")]
use stwo::{
    core::{ColumnVec, fields::qm31::SecureField},
    prover::{
        backend::simd::{SimdBackend, m31::LOG_N_LANES},
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
use crate::{framework::BuiltInComponent, lookups::BitwiseAndByteLookupElements};

/// Byte-wide bitwise-AND table: 2^16 rows of `(a, b, a & b)` for every byte
/// pair, with a free multiplicity column.  The blake2b chips consume this
/// (one lookup per byte AND) instead of the two nibble lookups against the
/// 16×16 `BitwiseLookupChip`; the byte-ness of `a`/`b` comes free from table
/// membership, so the per-nibble witness columns those chips carried die.
///
/// Row `a·256 + b` holds `(a, b, a & b)` — the same index
/// `side_note.bitwise_and_byte_counts` is keyed by.
pub struct BitwiseAndByteChip;

const BITWISE_BYTE_LOG_SIZE: u32 = 16; // 2^16 = 256×256 rows

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

        eval.finalize_logup();
    }
}

#[cfg(feature = "prover")]
impl BuiltInProverComponent for BitwiseAndByteChip {
    const IS_PRODUCER: bool = false;

    fn generate_preprocessed_trace(&self, _log_size: u32, _side_note: &SideNote) -> FinalizedTrace {
        let log_size = BITWISE_BYTE_LOG_SIZE.max(LOG_N_LANES);
        let mut trace = TraceBuilder::<PreprocessedColumn>::new(log_size);
        let num_rows = trace.num_rows();

        for row in 0..num_rows {
            let a = (row >> 8) as u8;
            let b = (row & 0xFF) as u8;
            trace.fill_columns(row, a, PreprocessedColumn::A);
            trace.fill_columns(row, b, PreprocessedColumn::B);
            trace.fill_columns(row, a & b, PreprocessedColumn::AndResult);
        }

        trace.finalize_bit_reversed()
    }

    fn generate_main_trace_immut(&self, side_note: &SideNote) -> FinalizedTrace {
        let log_size = BITWISE_BYTE_LOG_SIZE.max(LOG_N_LANES);
        let mut trace = TraceBuilder::<Column>::new(log_size);
        let num_rows = trace.num_rows();

        for row in 0..num_rows {
            let mult = side_note
                .bitwise_and_byte_counts
                .get(row)
                .copied()
                .unwrap_or(0);
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

        let bitwise_byte: &BitwiseAndByteLookupElements = lookup_elements.as_ref();
        let a = crate::trace::preprocessed_base_column!(component_trace, PreprocessedColumn::A);
        let b = crate::trace::preprocessed_base_column!(component_trace, PreprocessedColumn::B);
        let and_result =
            crate::trace::preprocessed_base_column!(component_trace, PreprocessedColumn::AndResult);
        let mult = crate::trace::original_base_column!(component_trace, Column::Multiplicity);

        // Consumer side (negative multiplicity).
        logup.add_to_relation_with(
            bitwise_byte,
            [mult[0].clone()],
            |[m]| (-m).into(),
            &[a[0].clone(), b[0].clone(), and_result[0].clone()],
        );

        logup.finalize()
    }
}
