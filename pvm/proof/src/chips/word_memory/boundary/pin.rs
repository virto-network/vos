//! The chip's pin code: its preprocessed columns, which the preprocessed
//! root a verifier holds commits.

use super::*;
use crate::side_note::SideNote;
use crate::trace::builder::{FinalizedTrace, TraceBuilder};

impl DeviceWordMemoryChip {
    /// The preprocessed columns at `log_size`, `side_note` the program's
    /// (`BuiltInProverComponent::generate_preprocessed_trace`).
    pub(super) fn preprocessed_trace(&self, log_size: u32, side_note: &SideNote) -> FinalizedTrace {
        let mut trace = TraceBuilder::<PreprocessedColumn>::new(log_size);
        let regions = crate::chips::device_run(side_note).layout.regions;
        let firsts = regions.map(|range| BaseField::from(range.first));
        let ends = regions.map(|range| BaseField::from(range.end));
        for row in 0..trace.num_rows() {
            trace.fill_columns_base_field(row, &firsts, PreprocessedColumn::RegionFirst);
            trace.fill_columns_base_field(row, &ends, PreprocessedColumn::RegionEnd);
        }
        trace.finalize_bit_reversed()
    }
}
