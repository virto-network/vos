//! The chip's pin code: its preprocessed columns, which the preprocessed
//! root a verifier holds commits.

use super::*;
use crate::device::WORD_BYTES;
use crate::side_note::SideNote;
use crate::trace::builder::{FinalizedTrace, TraceBuilder};

impl DataWordTableChip {
    /// The preprocessed columns at `log_size`, `side_note` the program's
    /// (`BuiltInProverComponent::generate_preprocessed_trace`).
    pub(super) fn preprocessed_trace(&self, log_size: u32, side_note: &SideNote) -> FinalizedTrace {
        let entries = entries(side_note);
        let mut trace = TraceBuilder::<PreprocessedColumn>::new(log_size);
        for row in 0..trace.num_rows() {
            let (address, value) = entries[row % entries.len()];
            trace.fill_columns(row, address.to_le_bytes(), PreprocessedColumn::Address);
            trace.fill_columns_bytes(row, &value, PreprocessedColumn::Value);
        }
        trace.finalize_bit_reversed()
    }
}

/// The table's entries: the data's words, or address 0's zeros when there
/// is none.
pub(super) fn entries(side_note: &SideNote) -> Vec<(u32, [u8; WORD_BYTES])> {
    let layout = &crate::chips::device_run(side_note).layout;
    let entries: Vec<(u32, [u8; WORD_BYTES])> = layout
        .data
        .iter()
        .flat_map(|(base, bytes)| {
            bytes
                .chunks_exact(WORD_BYTES)
                .enumerate()
                .map(move |(word, chunk)| {
                    (
                        base + (word * WORD_BYTES) as u32,
                        chunk.try_into().expect("a word"),
                    )
                })
        })
        .collect();
    if entries.is_empty() {
        vec![(0, [0; WORD_BYTES])]
    } else {
        entries
    }
}
