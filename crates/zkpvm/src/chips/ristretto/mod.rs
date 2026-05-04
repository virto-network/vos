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
#[cfg(feature = "prover")]
pub mod witness;

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

/// Per-row column layout for the field-arithmetic phase of the chip.
///
/// One row witnesses ONE p25519 field operation (add/sub today;
/// mul/inv come with R1c-3..R1c-5).  Edwards point ops (R1d) compose
/// multiple field-op rows; the scalar-mult main loop (R1e) schedules
/// rows + boundary lookup cells around them.
///
/// Bytes are little-endian throughout (matches `field::Bytes` and the
/// ECALL boundary wire format).  Carry/borrow cells are 0/1 only.
#[derive(Debug, Copy, Clone, AirColumn)]
pub enum Column {
    /// Operand a, 32 LE bytes.
    #[size = 32]
    FieldA,
    /// Operand b, 32 LE bytes.
    #[size = 32]
    FieldB,
    /// Output: a OP b (mod p), 32 LE bytes.
    #[size = 32]
    FieldOut,

    /// For is_add rows: byte-wise sum a+b before the conditional `-p`
    /// reduction step.  Lives in [0, 2²⁵⁶) so always fits 32 bytes.
    /// For other op flavors this column is unused (zero).
    #[size = 32]
    AddIntermediate,
    /// For is_add rows: per-position carry-out chain of `a + b`.
    /// Each entry is 0 or 1.  R1c-3 will pin via the per-byte sum
    /// constraint chain.
    #[size = 32]
    AddCarry,
    /// 1 iff the unreduced sum was ≥ p (so out = intermediate − p);
    /// 0 if out = intermediate directly.  R1c-3 will additionally
    /// pin determinism (output < p) via a finalize chain.
    #[size = 1]
    IsOverflow,
    /// Per-position borrow chain for the conditional reduction
    /// `out = intermediate − is_overflow · p`.  Each entry is 0 or 1.
    #[size = 32]
    SubBorrow,

    /// Operation classifier flags — exactly one is 1 on a real row.
    /// R1c-3+ adds is_mul and is_inv to this set.
    #[size = 1]
    IsAdd,
    #[size = 1]
    IsSub,

    /// 0 iff this is a padding / unused row.
    #[size = 1]
    IsReal,
}

#[derive(Debug, Copy, Clone, PreprocessedAirColumn)]
#[preprocessed_prefix = "ristretto"]
pub enum PreprocessedColumn {
    /// Reserved.  Real preprocessed columns (e.g. p-byte constants for
    /// the conditional-reduction sub-chain, row-position-within-call,
    /// scalar-window NAF table) come with R1c-3..R1e.  Stubbed at one
    /// zero column so the AirColumn macro has a non-empty enum and the
    /// preprocessed trace shape stays valid.
    #[size = 1]
    Reserved,
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
            trace.fill_columns(row, BaseField::from(0u32), PreprocessedColumn::Reserved);
        }
        trace.finalize_bit_reversed()
    }

    fn generate_main_trace(&self, _side_note: &mut SideNote) -> FinalizedTrace {
        // R1c-2: trace is still all-zero rows.  Real per-call rows
        // come from `side_note.ristretto_field_rows` once R1e schedules
        // them through the chip; for now the chip is gated off in
        // active_components anyway, so num_rows worth of padding is
        // sufficient for the framework's commitment shape.
        let mut trace = TraceBuilder::<Column>::new(RISTRETTO_LOG_SIZE);
        let num_rows = trace.num_rows();
        for row in 0..num_rows {
            // Padding row: is_real = 0, all other cells = 0.
            // Layout exists in `Column` enum so future commits can
            // light it up row-by-row without re-touching the chip's
            // shape (which would bump PROOF_FORMAT_VERSION).
            trace.fill_columns(row, BaseField::from(0u32), Column::IsReal);
            let _ = row; // silence unused on the padding-only path
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
