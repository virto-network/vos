//! The chip's pin code: its preprocessed columns, which the preprocessed
//! root a verifier holds commits.

use super::*;
use crate::core::step::NUM_REGS;
use crate::side_note::SideNote;
use crate::trace::builder::{FinalizedTrace, TraceBuilder};

impl DeviceBoundaryChip {
    /// The preprocessed columns at `log_size`, `side_note` the program's
    /// (`BuiltInProverComponent::generate_preprocessed_trace`).
    pub(super) fn preprocessed_trace(&self, log_size: u32, side_note: &SideNote) -> FinalizedTrace {
        let entry = crate::chips::device_run(side_note).layout.registers;
        let mut trace = TraceBuilder::<PreprocessedColumn>::new(log_size);
        for (row, &value) in entry.iter().enumerate() {
            trace.fill_columns(row, true, PreprocessedColumn::IsRegister);
            trace.fill_columns(
                row,
                BaseField::from(row as u32),
                PreprocessedColumn::Register,
            );
            trace.fill_columns(row, value, PreprocessedColumn::InitialValue);
            trace.fill_columns(row, IO_REGISTERS.contains(&row), PreprocessedColumn::IsIo);
            trace.fill_columns(row, row == 0, PreprocessedColumn::IsFirst);
            trace.fill_columns(row, row + 1 < NUM_REGS, PreprocessedColumn::IsChained);
        }
        trace.finalize_bit_reversed()
    }
}
