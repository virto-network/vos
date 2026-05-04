//! Ristretto255 scalar-mult precompile chip.
//!
//! See `DESIGN.md` in this directory for the full architecture.
//! Phase R1b (this file): empty stub.  Provides the trait surface
//! (`BuiltInComponent` + `BuiltInProverComponent`) so the chip can
//! sit in `BASE_COMPONENTS` and be conditionally selected by
//! `active_components` based on `ChipActivity.ristretto`, but emits
//! no constraints, no lookups, and a single padding row of zeros.
//!
//! Until R1c lands (p25519 field arithmetic), the chip is always
//! gated OFF — `activity_from_steps` only flips `ristretto = true`
//! when the trace contains an `ECALL_RISTRETTO_SCALAR_MULT` step,
//! which today no actor issues.  Pure-compute actors (fibonacci,
//! hasher, hash-bench) and the existing clerk benches all skip the
//! chip entirely.

#[allow(unused_imports)]
use alloc::{boxed::Box, vec, vec::Vec};
use stwo::core::fields::m31::BaseField;
#[cfg(feature = "prover")]
use stwo::{
    core::{
        fields::qm31::SecureField,
        ColumnVec,
    },
    prover::{
        backend::simd::{m31::LOG_N_LANES, SimdBackend},
        poly::{circle::CircleEvaluation, BitReversedOrder},
    },
};
use stwo_constraint_framework::EvalAtRow;

#[cfg(feature = "prover")]
pub mod field;

use crate::air_column::{AirColumn, PreprocessedAirColumn};
use crate::trace::eval::TraceEval;
#[cfg(feature = "prover")]
use crate::trace::{
    builder::{FinalizedTrace, TraceBuilder},
    component::ComponentTrace,
};

use crate::{
    framework::BuiltInComponent,
    lookups::Range256LookupElements,
};
#[cfg(feature = "prover")]
use crate::framework::BuiltInProverComponent;
#[cfg(feature = "prover")]
use crate::lookups::{AllLookupElements, LogupTraceBuilder};
#[cfg(feature = "prover")]
use crate::side_note::SideNote;

pub struct RistrettoChip;

/// Smallest valid log_size — one SIMD lane's worth of padding rows.
/// Real chip will switch to a per-call sizing once R1c–R1e land.
const RISTRETTO_LOG_SIZE: u32 = LOG_N_LANES;

#[derive(Debug, Copy, Clone, AirColumn)]
pub enum Column {
    /// Placeholder.  Replaced by the real per-row witness layout
    /// (point coords, scalar nibbles, field-mult intermediates,
    /// boundary cells) when R1c–R1e land.  Holds zero on every row of
    /// the empty stub.
    #[size = 1]
    Placeholder,
}

#[derive(Debug, Copy, Clone, PreprocessedAirColumn)]
#[preprocessed_prefix = "ristretto"]
pub enum PreprocessedColumn {
    /// Placeholder.  Real preprocessed columns (operation classifier,
    /// row-position-within-call, etc.) come with R1e.
    #[size = 1]
    Placeholder,
}

impl BuiltInComponent for RistrettoChip {
    type PreprocessedColumn = PreprocessedColumn;
    type MainColumn = Column;
    /// Placeholder.  Real lookups (MemoryAccess for boundary I/O,
    /// RistrettoCall for binding to CpuChip's ECALL step, byte-mul
    /// table for field arithmetic) come with R1c–R1e.
    type LookupElements = Range256LookupElements;

    fn add_constraints<E: EvalAtRow>(
        &self,
        eval: &mut E,
        _trace_eval: TraceEval<PreprocessedColumn, Column, E>,
        _lookup_elements: &Range256LookupElements,
    ) {
        // No constraints in the empty stub.  A `finalize_logup()` is
        // still required so the framework knows the chip's lookup
        // bookkeeping is closed.
        eval.finalize_logup();
    }
}

#[cfg(feature = "prover")]
impl BuiltInProverComponent for RistrettoChip {
    fn generate_preprocessed_trace(
        &self,
        _log_size: u32,
        _side_note: &SideNote,
    ) -> FinalizedTrace {
        let mut trace = TraceBuilder::<PreprocessedColumn>::new(RISTRETTO_LOG_SIZE);
        let num_rows = trace.num_rows();
        for row in 0..num_rows {
            trace.fill_columns(row, BaseField::from(0u32), PreprocessedColumn::Placeholder);
        }
        trace.finalize_bit_reversed()
    }

    fn generate_main_trace(&self, _side_note: &mut SideNote) -> FinalizedTrace {
        let mut trace = TraceBuilder::<Column>::new(RISTRETTO_LOG_SIZE);
        let num_rows = trace.num_rows();
        for row in 0..num_rows {
            trace.fill_columns(row, BaseField::from(0u32), Column::Placeholder);
        }
        trace.finalize_bit_reversed()
    }

    fn generate_interaction_trace(
        &self,
        component_trace: ComponentTrace,
        _side_note: &SideNote,
        _lookup_elements: &AllLookupElements,
    ) -> (
        ColumnVec<CircleEvaluation<SimdBackend, BaseField, BitReversedOrder>>,
        SecureField,
    ) {
        let log_size = component_trace.log_size();
        let logup = LogupTraceBuilder::new(log_size);
        // No relation entries — the chip emits and consumes nothing
        // until R1c–R1e wire in real lookups.
        logup.finalize()
    }
}
