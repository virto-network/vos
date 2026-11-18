//! The compression core `Blake2bChip` and `Blake2bBoundaryChip` share: its
//! schedule, constraints, interaction trace and witness.

use stwo_constraint_framework::EvalAtRow;

use crate::air_column::{AirColumn, PreprocessedAirColumn};
use crate::chips::blake2b::columns::PreprocessedColumn;
use crate::trace::eval::TraceEval;

mod constraints;
#[cfg(feature = "prover")]
mod fill;
#[cfg(feature = "prover")]
mod interaction;

pub(super) use constraints::add_compression_core;
#[cfg(feature = "prover")]
pub(super) use fill::{build_compression_rows, fill_compression_trace, fill_schedule_preprocessed};
#[cfg(feature = "prover")]
pub(super) use interaction::add_compression_interaction_core;

/// The row-index-derived schedule selectors the compression core needs,
/// pulled out of the preprocessed trace by the caller so the core is
/// agnostic to which chip's `PreprocessedColumn` (i.e. which
/// `preprocessed_prefix`) backs them.  `Blake2bChip` and
/// `Blake2bBoundaryChip` carry structurally identical selectors under
/// distinct prefixes (distinct preprocessed-tree IDs are mandatory — stwo
/// dedups preprocessed columns by ID but the prover commits each
/// component's preprocessed trace positionally).
pub(super) struct Blake2bSchedule<F> {
    pub is_first: [F; 1],
    pub is_last: [F; 1],
    pub is_gidx: [[F; 1]; 8],
    pub is_mx_slot: [[F; 1]; 16],
    pub is_my_slot: [[F; 1]; 16],
}

/// A `PreprocessedColumn` enum exposing the blake2b compression schedule
/// selectors by name.  Implemented by both the main and boundary chips'
/// preprocessed columns (same variants, distinct prefix).
pub(super) trait ScheduleColumns: PreprocessedAirColumn + Copy {
    const IS_FIRST: Self;
    const IS_LAST: Self;
    const IS_GIDX: [Self; 8];
    const IS_MX_SLOT: [Self; 16];
    const IS_MY_SLOT: [Self; 16];
}

impl ScheduleColumns for PreprocessedColumn {
    const IS_FIRST: Self = PreprocessedColumn::IsFirstOfCompression;
    const IS_LAST: Self = PreprocessedColumn::IsLastOfCompression;
    const IS_GIDX: [Self; 8] = [
        PreprocessedColumn::IsGIdx0,
        PreprocessedColumn::IsGIdx1,
        PreprocessedColumn::IsGIdx2,
        PreprocessedColumn::IsGIdx3,
        PreprocessedColumn::IsGIdx4,
        PreprocessedColumn::IsGIdx5,
        PreprocessedColumn::IsGIdx6,
        PreprocessedColumn::IsGIdx7,
    ];
    const IS_MX_SLOT: [Self; 16] = [
        PreprocessedColumn::IsMxSlot0,
        PreprocessedColumn::IsMxSlot1,
        PreprocessedColumn::IsMxSlot2,
        PreprocessedColumn::IsMxSlot3,
        PreprocessedColumn::IsMxSlot4,
        PreprocessedColumn::IsMxSlot5,
        PreprocessedColumn::IsMxSlot6,
        PreprocessedColumn::IsMxSlot7,
        PreprocessedColumn::IsMxSlot8,
        PreprocessedColumn::IsMxSlot9,
        PreprocessedColumn::IsMxSlot10,
        PreprocessedColumn::IsMxSlot11,
        PreprocessedColumn::IsMxSlot12,
        PreprocessedColumn::IsMxSlot13,
        PreprocessedColumn::IsMxSlot14,
        PreprocessedColumn::IsMxSlot15,
    ];
    const IS_MY_SLOT: [Self; 16] = [
        PreprocessedColumn::IsMySlot0,
        PreprocessedColumn::IsMySlot1,
        PreprocessedColumn::IsMySlot2,
        PreprocessedColumn::IsMySlot3,
        PreprocessedColumn::IsMySlot4,
        PreprocessedColumn::IsMySlot5,
        PreprocessedColumn::IsMySlot6,
        PreprocessedColumn::IsMySlot7,
        PreprocessedColumn::IsMySlot8,
        PreprocessedColumn::IsMySlot9,
        PreprocessedColumn::IsMySlot10,
        PreprocessedColumn::IsMySlot11,
        PreprocessedColumn::IsMySlot12,
        PreprocessedColumn::IsMySlot13,
        PreprocessedColumn::IsMySlot14,
        PreprocessedColumn::IsMySlot15,
    ];
}

/// Read the compression schedule selectors from a chip's preprocessed trace.
pub(super) fn read_schedule<P: ScheduleColumns, C: AirColumn, E: EvalAtRow>(
    trace_eval: &TraceEval<P, C, E>,
) -> Blake2bSchedule<E::F> {
    Blake2bSchedule {
        is_first: trace_eval.preprocessed_column_eval::<1>(P::IS_FIRST),
        is_last: trace_eval.preprocessed_column_eval::<1>(P::IS_LAST),
        is_gidx: core::array::from_fn(|j| trace_eval.preprocessed_column_eval::<1>(P::IS_GIDX[j])),
        is_mx_slot: core::array::from_fn(|k| {
            trace_eval.preprocessed_column_eval::<1>(P::IS_MX_SLOT[k])
        }),
        is_my_slot: core::array::from_fn(|k| {
            trace_eval.preprocessed_column_eval::<1>(P::IS_MY_SLOT[k])
        }),
    }
}
