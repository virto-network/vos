//! ByteToBitsChip — 256-row lookup table proving
//! `(byte, bit0, bit1, bit2, bit3, bit4, bit5, bit6, bit7)` where
//! `byte = sum_{i=0..8} 2^i * bit_i`.
//!
//! The flag-packing scheme uses this chip: ProgramMemoryChip's
//! preprocessed table holds the 48 category/sub-category flags as 6
//! packed bytes; CpuChip's main trace mirrors the 6 packed bytes plus
//! the 48 individual flag columns it already commits to.  Per CpuChip
//! row, 6 byte-to-bits lookups bind each individual flag to its slot
//! in the corresponding packed byte.  Bits in inactive slots (the 6th
//! byte only uses bits 0..7 — no padding needed since 48 is a
//! multiple of 8) are also bound, which is fine because they're
//! committed columns and bind through the lookup balance to the
//! canonical packed byte that was decoded from the opcode.
//!
//! This chip can be wired with or without consumers.  With no
//! consumers, Multiplicity is all zero and claimed_sum is 0 — it just
//! commits the preprocessed decomposition table.  The CpuChip-side
//! consumer populates it otherwise.
//!
//! Mirrors the BitcountChip / PopcountChip pattern: a fixed
//! preprocessed table plus a Multiplicity column counted from
//! CpuChip's per-row charges.

use crate::prelude::*;
use stwo_constraint_framework::{EvalAtRow, RelationEntry};

use crate::air_column::{AirColumn, PreprocessedAirColumn};
use crate::trace::eval::TraceEval;

use crate::{
    framework::{BuiltInComponent, Logup},
    lookups::ByteToBitsLookupElements,
};

#[derive(Clone, Copy)]
pub struct ByteToBitsChip;

#[derive(Debug, Copy, Clone, AirColumn)]
pub enum Column {
    /// Multiplicity: how many CpuChip emissions hit this byte.  Zero
    /// when wired with no consumers; populated by the CpuChip-side
    /// consumer's per-row flag-byte decomposition emissions otherwise.
    #[size = 1]
    Multiplicity,
}

#[derive(Debug, Copy, Clone, PreprocessedAirColumn)]
#[preprocessed_prefix = "byte_to_bits"]
pub enum PreprocessedColumn {
    /// Byte value (0..255).
    #[size = 1]
    Byte,
    #[size = 1]
    Bit0,
    #[size = 1]
    Bit1,
    #[size = 1]
    Bit2,
    #[size = 1]
    Bit3,
    #[size = 1]
    Bit4,
    #[size = 1]
    Bit5,
    #[size = 1]
    Bit6,
    #[size = 1]
    Bit7,
}

impl BuiltInComponent for ByteToBitsChip {
    const LOGUP: Logup = Logup::Single;
    type PreprocessedColumn = PreprocessedColumn;
    type MainColumn = Column;
    type LookupElements = ByteToBitsLookupElements;

    fn add_constraints<E: EvalAtRow>(
        &self,
        eval: &mut E,
        trace_eval: TraceEval<PreprocessedColumn, Column, E>,
        lookup_elements: &ByteToBitsLookupElements,
    ) {
        let byte = crate::trace::preprocessed_trace_eval!(trace_eval, PreprocessedColumn::Byte);
        let b0 = crate::trace::preprocessed_trace_eval!(trace_eval, PreprocessedColumn::Bit0);
        let b1 = crate::trace::preprocessed_trace_eval!(trace_eval, PreprocessedColumn::Bit1);
        let b2 = crate::trace::preprocessed_trace_eval!(trace_eval, PreprocessedColumn::Bit2);
        let b3 = crate::trace::preprocessed_trace_eval!(trace_eval, PreprocessedColumn::Bit3);
        let b4 = crate::trace::preprocessed_trace_eval!(trace_eval, PreprocessedColumn::Bit4);
        let b5 = crate::trace::preprocessed_trace_eval!(trace_eval, PreprocessedColumn::Bit5);
        let b6 = crate::trace::preprocessed_trace_eval!(trace_eval, PreprocessedColumn::Bit6);
        let b7 = crate::trace::preprocessed_trace_eval!(trace_eval, PreprocessedColumn::Bit7);
        let mult = crate::trace::trace_eval!(trace_eval, Column::Multiplicity);

        let tuple = vec![
            byte[0].clone(),
            b0[0].clone(),
            b1[0].clone(),
            b2[0].clone(),
            b3[0].clone(),
            b4[0].clone(),
            b5[0].clone(),
            b6[0].clone(),
            b7[0].clone(),
        ];
        eval.add_to_relation(RelationEntry::new(
            lookup_elements,
            (-mult[0].clone()).into(),
            &tuple,
        ));
    }
}

#[cfg(feature = "prover")]
mod fill;
