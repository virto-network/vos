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
use crate::{framework::BuiltInComponent, lookups::ByteToBitsLookupElements};

pub struct ByteToBitsChip;

const BYTE_TO_BITS_LOG_SIZE: u32 = 8; // 2^8 = 256 rows

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

        eval.finalize_logup();
    }
}

#[cfg(feature = "prover")]
impl BuiltInProverComponent for ByteToBitsChip {
    const IS_PRODUCER: bool = false;

    fn generate_preprocessed_trace(&self, _log_size: u32, _side_note: &SideNote) -> FinalizedTrace {
        let log_size = BYTE_TO_BITS_LOG_SIZE.max(LOG_N_LANES);
        let mut trace = TraceBuilder::<PreprocessedColumn>::new(log_size);

        for row in 0..256usize {
            let byte = row as u8;
            trace.fill_columns(row, byte, PreprocessedColumn::Byte);
            trace.fill_columns(row, (byte >> 0) & 1, PreprocessedColumn::Bit0);
            trace.fill_columns(row, (byte >> 1) & 1, PreprocessedColumn::Bit1);
            trace.fill_columns(row, (byte >> 2) & 1, PreprocessedColumn::Bit2);
            trace.fill_columns(row, (byte >> 3) & 1, PreprocessedColumn::Bit3);
            trace.fill_columns(row, (byte >> 4) & 1, PreprocessedColumn::Bit4);
            trace.fill_columns(row, (byte >> 5) & 1, PreprocessedColumn::Bit5);
            trace.fill_columns(row, (byte >> 6) & 1, PreprocessedColumn::Bit6);
            trace.fill_columns(row, (byte >> 7) & 1, PreprocessedColumn::Bit7);
        }

        trace.finalize_bit_reversed()
    }

    fn generate_main_trace_immut(&self, side_note: &SideNote) -> FinalizedTrace {
        let log_size = BYTE_TO_BITS_LOG_SIZE.max(LOG_N_LANES);
        let mut trace = TraceBuilder::<Column>::new(log_size);

        for row in 0..256usize {
            let count = side_note.byte_to_bits_counts[row];
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

        let elems: &ByteToBitsLookupElements = lookup_elements.as_ref();
        let byte =
            crate::trace::preprocessed_base_column!(component_trace, PreprocessedColumn::Byte);
        let b0 = crate::trace::preprocessed_base_column!(component_trace, PreprocessedColumn::Bit0);
        let b1 = crate::trace::preprocessed_base_column!(component_trace, PreprocessedColumn::Bit1);
        let b2 = crate::trace::preprocessed_base_column!(component_trace, PreprocessedColumn::Bit2);
        let b3 = crate::trace::preprocessed_base_column!(component_trace, PreprocessedColumn::Bit3);
        let b4 = crate::trace::preprocessed_base_column!(component_trace, PreprocessedColumn::Bit4);
        let b5 = crate::trace::preprocessed_base_column!(component_trace, PreprocessedColumn::Bit5);
        let b6 = crate::trace::preprocessed_base_column!(component_trace, PreprocessedColumn::Bit6);
        let b7 = crate::trace::preprocessed_base_column!(component_trace, PreprocessedColumn::Bit7);
        let mult = crate::trace::original_base_column!(component_trace, Column::Multiplicity);

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
        logup.add_to_relation_with(elems, [mult[0].clone()], |[m]| (-m).into(), &tuple);

        logup.finalize()
    }
}
