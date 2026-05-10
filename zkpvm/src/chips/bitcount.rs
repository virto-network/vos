//! Phase 34: BitcountChip — 256-row lookup table proving
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
use crate::{framework::BuiltInComponent, lookups::BitcountLookupElements};

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

        eval.finalize_logup();
    }
}

#[cfg(feature = "prover")]
impl BuiltInProverComponent for BitcountChip {
    const IS_PRODUCER: bool = false;

    fn generate_preprocessed_trace(&self, _log_size: u32, _side_note: &SideNote) -> FinalizedTrace {
        let log_size = BITCOUNT_LOG_SIZE.max(LOG_N_LANES);
        let mut trace = TraceBuilder::<PreprocessedColumn>::new(log_size);

        for row in 0..256usize {
            let byte = row as u8;
            let lz: u8 = if byte == 0 {
                8
            } else {
                byte.leading_zeros() as u8
            };
            let tz: u8 = if byte == 0 {
                8
            } else {
                byte.trailing_zeros() as u8
            };
            trace.fill_columns(row, byte, PreprocessedColumn::Byte);
            trace.fill_columns(row, lz, PreprocessedColumn::LzByte);
            trace.fill_columns(row, tz, PreprocessedColumn::TzByte);
        }

        trace.finalize_bit_reversed()
    }

    fn generate_main_trace_immut(&self, side_note: &SideNote) -> FinalizedTrace {
        let log_size = BITCOUNT_LOG_SIZE.max(LOG_N_LANES);
        let mut trace = TraceBuilder::<Column>::new(log_size);

        for row in 0..256usize {
            let count = side_note.bitcount_counts[row];
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

        let bitcount: &BitcountLookupElements = lookup_elements.as_ref();
        let byte =
            crate::trace::preprocessed_base_column!(component_trace, PreprocessedColumn::Byte);
        let lz =
            crate::trace::preprocessed_base_column!(component_trace, PreprocessedColumn::LzByte);
        let tz =
            crate::trace::preprocessed_base_column!(component_trace, PreprocessedColumn::TzByte);
        let mult = crate::trace::original_base_column!(component_trace, Column::Multiplicity);

        let tuple = vec![byte[0].clone(), lz[0].clone(), tz[0].clone()];
        logup.add_to_relation_with(bitcount, [mult[0].clone()], |[m]| (-m).into(), &tuple);

        logup.finalize()
    }
}
