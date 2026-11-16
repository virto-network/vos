//! The chip's pin code: its preprocessed columns, which the preprocessed
//! root a verifier holds commits.

use super::*;
use crate::side_note::SideNote;
use crate::trace::builder::{FinalizedTrace, TraceBuilder};

impl MemoryPageChip {
    /// The preprocessed columns at `log_size`, `side_note` the program's
    /// (`BuiltInProverComponent::generate_preprocessed_trace`).
    pub(super) fn preprocessed_trace(&self, log_size: u32, side_note: &SideNote) -> FinalizedTrace {
        let mut trace = TraceBuilder::<PreprocessedColumn>::new(log_size);
        let regions = side_note.layout().regions;
        let firsts = regions.map(|range| BaseField::from(range.first));
        let ends = regions.map(|range| BaseField::from(range.end));
        for row in 0..trace.num_rows() {
            trace.fill_columns_base_field(row, &firsts, PreprocessedColumn::RegionFirst);
            trace.fill_columns_base_field(row, &ends, PreprocessedColumn::RegionEnd);
            let block = row % BLOCKS_PER_PAGE;
            trace.fill_columns(row, block == 0, PreprocessedColumn::IsBlock0);
            trace.fill_columns(
                row,
                block == BLOCKS_PER_PAGE - 1,
                PreprocessedColumn::IsLastBlock,
            );
            trace.fill_columns(row, (block & 1) as u8, PreprocessedColumn::BlockLo);
            trace.fill_columns(row, (block >> 1) as u8, PreprocessedColumn::BlockHi);
            trace.fill_columns(row, 128u64 * (block as u64 + 2), PreprocessedColumn::TBlock);
            trace.fill_columns(
                row,
                block == BLOCKS_PER_PAGE - 1,
                PreprocessedColumn::FBlock,
            );
        }
        trace.finalize_bit_reversed()
    }
}
