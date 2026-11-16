//! BitcountChip — 256-row lookup table proving
//! `(byte, byte.leading_zeros(), byte.trailing_zeros())`.
//!
//! Each row holds `(byte, lz_byte, tz_byte)` for `byte ∈ [0, 256)`.
//! For `byte = 0`: lz_byte = 8, tz_byte = 8 (all bits zero, so the
//! count caps at the byte width).  For `byte > 0`: lz_byte is the
//! leading-zero count of the byte (0..7), tz_byte the trailing.
//!
//! CpuChip emits per-byte lookups on `IsLzb / IsTzb` rows
//! (LeadingZeroBits / TrailingZeroBits 32 / 64): `(val_d[i],
//! BitOpLzByte[i], BitOpTzByte[i]) ∈ bitcount`.  This chip consumes
//! them with negative multiplicity.
//!
//! Mirrors the PopcountChip / PowerOfTwoChip pattern (a fixed
//! preprocessed table plus a Multiplicity column counted from
//! CpuChip's per-row charges).

use crate::prelude::*;
use stwo::core::fields::m31::BaseField;
use stwo_constraint_framework::{EvalAtRow, RelationEntry};

use crate::air_column::{AirColumn, PreprocessedAirColumn};
use crate::trace::eval::TraceEval;

use crate::{
    framework::{BuiltInComponent, Logup},
    lookups::BitcountLookupElements,
};

#[derive(Clone, Copy)]
pub struct BitcountChip;

const BITCOUNT_LOG_SIZE: u32 = 8; // 2^8 = 256 rows

#[derive(Debug, Copy, Clone, AirColumn)]
pub enum Column {
    /// Multiplicity: how many CpuChip emissions hit this byte.
    #[size = 1]
    Multiplicity,
}

#[derive(Debug, Copy, Clone, PreprocessedAirColumn)]
#[preprocessed_prefix = "bitcount"]
pub enum PreprocessedColumn {
    /// Byte value (0..255).
    #[size = 1]
    Byte,
    /// `byte.leading_zeros()` (0..8); 8 iff byte = 0.
    #[size = 1]
    LzByte,
    /// `byte.trailing_zeros()` (0..8); 8 iff byte = 0.
    #[size = 1]
    TzByte,
}

impl BuiltInComponent for BitcountChip {
    const LOGUP: Logup = Logup::Single;
    type PreprocessedColumn = PreprocessedColumn;
    type MainColumn = Column;
    type LookupElements = BitcountLookupElements;

    fn add_constraints<E: EvalAtRow>(
        &self,
        eval: &mut E,
        trace_eval: TraceEval<PreprocessedColumn, Column, E>,
        lookup_elements: &BitcountLookupElements,
    ) {
        let byte = crate::trace::preprocessed_trace_eval!(trace_eval, PreprocessedColumn::Byte);
        let lz = crate::trace::preprocessed_trace_eval!(trace_eval, PreprocessedColumn::LzByte);
        let tz = crate::trace::preprocessed_trace_eval!(trace_eval, PreprocessedColumn::TzByte);
        let mult = crate::trace::trace_eval!(trace_eval, Column::Multiplicity);

        let tuple = vec![byte[0].clone(), lz[0].clone(), tz[0].clone()];
        eval.add_to_relation(RelationEntry::new(
            lookup_elements,
            (-mult[0].clone()).into(),
            &tuple,
        ));
    }
}

#[cfg(feature = "prover")]
mod fill;
