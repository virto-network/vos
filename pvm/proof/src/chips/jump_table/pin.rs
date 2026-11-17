//! The chip's pin code: its preprocessed columns, which the preprocessed
//! root a verifier holds commits.

use super::*;
use crate::side_note::SideNote;
use crate::trace::builder::{FinalizedTrace, TraceBuilder};

impl JumpTableChip {
    /// The preprocessed columns at `log_size`, `side_note` the program's
    /// (`BuiltInProverComponent::generate_preprocessed_trace`).
    pub(super) fn preprocessed_trace(&self, log_size: u32, side_note: &SideNote) -> FinalizedTrace {
        let log_size = chip_log_size(side_note.jump_table.len()).max(log_size);
        let mut trace = TraceBuilder::<PreprocessedColumn>::new(log_size);
        let num_rows = trace.num_rows();

        for row in 0..num_rows {
            if row < side_note.jump_table.len() {
                let addr: u32 = 2 * ((row as u32) + 1);
                trace.fill_columns_bytes(row, &addr.to_le_bytes(), PreprocessedColumn::Addr);
                trace.fill_columns_bytes(
                    row,
                    &side_note.jump_table[row].to_le_bytes(),
                    PreprocessedColumn::Target,
                );
                trace.fill_columns(row, true, PreprocessedColumn::IsEntry);
            }
            // Padding rows: addr/target/is_entry stay at 0.
        }

        trace.finalize_bit_reversed()
    }
}

/// The least log size whose rows hold the table: a smaller one cannot pin
/// it.
pub(crate) fn table_log_size(side_note: &SideNote) -> u32 {
    chip_log_size(side_note.jump_table.len())
}

pub(super) fn chip_log_size(len: usize) -> u32 {
    crate::trace::utils::ceil_log2_at_least_lanes(len.max(1))
}
