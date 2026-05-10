//! Session 2.1 step 8 — RistrettoCombScalarBoundaryChip.
//!
//! Boundary chip that closes two soundness gaps in one place:
//!  1. Binds the comb-anchor chip's per-window `ScalarWindow` values
//!     to the actor's input scalar bytes (via the
//!     `RistrettoCombScalarBoundaryLookupElements` 3-limb relation).
//!  2. Pins those scalar bytes to PVM memory by emitting standard
//!     14-limb `MemoryAccessLookupElements` producers.  The producer
//!     side that previously lived in `RistrettoEcallChip` for
//!     fixed-base records moves here, so the ledger entry the
//!     `MemoryChip` consumes for each scalar byte is balanced by a
//!     producer that *also* commits to the byte's nibble decomposition.
//!
//! Per fixed-basepoint scalar mult call, the chip lays out 32 rows
//! (one per scalar byte).  Each row carries:
//!   - `IsReal` — 1 on real rows, 0 on padding.
//!   - `CallIdx` — the call's position in `ristretto_comb_calls`.
//!   - `LowNibble`, `HighNibble` — the two 4-bit windows the byte
//!     decomposes into.
//!   - `ScalarByte` — the byte itself, constrained to equal
//!     `LowNibble + 16·HighNibble`.
//!   - `Addr[4]` — `scalar_ptr + byte_idx` in LE bytes.  Forced to a
//!     valid PVM-memory address via the memory-access lookup balance.
//!   - `Ts[8]` — the ECALL step's timestamp.  Same forcing as Addr.
//!
//! Two preprocessed columns hold the row's window indices directly
//! (`WindowEven = 2·(row mod 32)`, `WindowOdd = 2·(row mod 32) + 1`)
//! so both constraint and interaction sides can reference them as
//! plain column refs.
//!
//! Three emissions per real row: 2 to scalar boundary (−IsReal) +
//! 1 to memory (+IsReal).  Stwo's `finalize_logup_in_pairs` batches
//! adjacent pairs and admits a trailing single — the memory emission
//! ends up alone in its own batch, which the framework handles.

#[allow(unused_imports)]
use alloc::{boxed::Box, vec, vec::Vec};
use num_traits::One;
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
use crate::{
    framework::BuiltInComponent,
    lookups::{MemoryAccessLookupElements, RistrettoCombScalarBoundaryLookupElements},
};

pub struct RistrettoCombScalarBoundaryChip;

/// 32 scalar bytes per fixed-base scalar mult call.
pub const ROWS_PER_CALL: usize = 32;

#[derive(Debug, Copy, Clone, AirColumn)]
pub enum Column {
    /// 1 if this row witnesses an actual scalar byte; 0 if padding.
    #[size = 1]
    IsReal,
    /// Index of the scalar-mult call in `ristretto_comb_calls`.
    #[size = 1]
    CallIdx,
    /// Low 4-bit window of `ScalarByte` (`scalar[byte_idx] & 0x0F`).
    #[size = 1]
    LowNibble,
    /// High 4-bit window of `ScalarByte` (`scalar[byte_idx] >> 4`).
    #[size = 1]
    HighNibble,
    /// The scalar byte itself.  Pinned to PVM memory via the memory
    /// lookup; pinned to the nibbles via the per-row constraint
    /// `ScalarByte = LowNibble + 16·HighNibble`.
    #[size = 1]
    ScalarByte,
    /// Address `scalar_ptr + byte_idx` in 4 LE bytes.
    #[size = 4]
    Addr,
    /// ECALL step timestamp, 8 LE bytes.
    #[size = 8]
    Ts,
}

#[derive(Debug, Copy, Clone, PreprocessedAirColumn)]
#[preprocessed_prefix = "ristretto_comb_scalar_boundary"]
pub enum PreprocessedColumn {
    /// `WindowEven[row] = 2 * (row mod 32)` — even window index used
    /// as the scalar-boundary tuple's `window_idx` for the low-nibble
    /// emission.
    #[size = 1]
    WindowEven,
    /// `WindowOdd[row] = 2 * (row mod 32) + 1` — odd window index
    /// used for the high-nibble emission.
    #[size = 1]
    WindowOdd,
}

impl BuiltInComponent for RistrettoCombScalarBoundaryChip {
    type PreprocessedColumn = PreprocessedColumn;
    type MainColumn = Column;
    type LookupElements = (
        RistrettoCombScalarBoundaryLookupElements,
        MemoryAccessLookupElements,
    );

    fn add_constraints<E: EvalAtRow>(
        &self,
        eval: &mut E,
        trace_eval: TraceEval<PreprocessedColumn, Column, E>,
        lookup_elements: &(
            RistrettoCombScalarBoundaryLookupElements,
            MemoryAccessLookupElements,
        ),
    ) {
        let (scalar_lookup, memory_lookup) = lookup_elements;

        let is_real = crate::trace::trace_eval!(trace_eval, Column::IsReal);
        let call_idx = crate::trace::trace_eval!(trace_eval, Column::CallIdx);
        let low_nibble = crate::trace::trace_eval!(trace_eval, Column::LowNibble);
        let high_nibble = crate::trace::trace_eval!(trace_eval, Column::HighNibble);
        let scalar_byte = crate::trace::trace_eval!(trace_eval, Column::ScalarByte);
        let addr = crate::trace::trace_eval!(trace_eval, Column::Addr);
        let ts = crate::trace::trace_eval!(trace_eval, Column::Ts);
        let win_even =
            crate::trace::preprocessed_trace_eval!(trace_eval, PreprocessedColumn::WindowEven);
        let win_odd =
            crate::trace::preprocessed_trace_eval!(trace_eval, PreprocessedColumn::WindowOdd);

        // is_real ∈ {0, 1}.
        eval.add_constraint(is_real[0].clone() * (E::F::one() - is_real[0].clone()));

        // ScalarByte = LowNibble + 16·HighNibble (gated by is_real).
        // Range constraints on the nibbles (≤ 15) come from the
        // anchor → table chain: the anchor's ScalarWindow column is
        // forced to a valid table key by the comb relation, and the
        // scalar-boundary balance forces our nibble columns to equal
        // the anchor's value.
        let f16 = E::F::from(BaseField::from(16u32));
        eval.add_constraint(
            is_real[0].clone()
                * (scalar_byte[0].clone() - low_nibble[0].clone() - f16 * high_nibble[0].clone()),
        );

        // ── Scalar-boundary emissions ──
        eval.add_to_relation(RelationEntry::new(
            scalar_lookup,
            (-is_real[0].clone()).into(),
            &[
                call_idx[0].clone(),
                win_even[0].clone(),
                low_nibble[0].clone(),
            ],
        ));
        eval.add_to_relation(RelationEntry::new(
            scalar_lookup,
            (-is_real[0].clone()).into(),
            &[
                call_idx[0].clone(),
                win_odd[0].clone(),
                high_nibble[0].clone(),
            ],
        ));

        // ── Memory ledger producer ──
        // Tuple: (addr[4], value[1], ts[8], is_write[1]) — 14 limbs,
        // matches the consumer side in MemoryChip exactly.  is_write
        // is the constant 0 (scalar bytes are read).
        let zero = E::F::from(BaseField::from(0u32));
        let mut tuple: Vec<E::F> = Vec::with_capacity(14);
        tuple.extend_from_slice(&addr);
        tuple.push(scalar_byte[0].clone());
        tuple.extend_from_slice(&ts);
        tuple.push(zero);
        eval.add_to_relation(RelationEntry::new(
            memory_lookup,
            is_real[0].clone().into(),
            &tuple,
        ));

        eval.finalize_logup_in_pairs();
    }
}

#[cfg(feature = "prover")]
impl BuiltInProverComponent for RistrettoCombScalarBoundaryChip {
    const IS_PRODUCER: bool = false;

    fn generate_preprocessed_trace(&self, _log_size: u32, side_note: &SideNote) -> FinalizedTrace {
        let log_size = boundary_log_size(side_note);
        let mut trace = TraceBuilder::<PreprocessedColumn>::new(log_size);
        let num_rows = trace.num_rows();
        for row in 0..num_rows {
            let byte_idx = (row % ROWS_PER_CALL) as u32;
            trace.fill_columns(
                row,
                BaseField::from(2 * byte_idx),
                PreprocessedColumn::WindowEven,
            );
            trace.fill_columns(
                row,
                BaseField::from(2 * byte_idx + 1),
                PreprocessedColumn::WindowOdd,
            );
        }
        trace.finalize_bit_reversed()
    }

    fn generate_main_trace_immut(&self, side_note: &SideNote) -> FinalizedTrace {
        use crate::core::tracing::ScalarMultKind;
        let log_size = boundary_log_size(side_note);
        let mut trace = TraceBuilder::<Column>::new(log_size);

        // Walk `ristretto_comb_calls` and the parallel
        // `ristretto_mem_ops` filtered to FixedBasepoint records.
        // The two vectors are produced in lock-step by
        // `ingest_ristretto_boundary` so a positional zip is correct
        // (there's no per-call cross-reference id to match on).
        let mut fixed_mem_ops = side_note
            .ristretto_mem_ops
            .iter()
            .filter(|op| op.kind == ScalarMultKind::FixedBasepoint);

        let mut row = 0usize;
        for (call_idx, call) in side_note.ristretto_comb_calls.iter().enumerate() {
            // Honest-prover invariant: ristretto_comb_calls and
            // FixedBasepoint mem_ops are produced together in
            // ingest_ristretto_boundary.  Chip-isolated tests that
            // populate ristretto_comb_calls without populating
            // ristretto_mem_ops fall back to zero addr/ts — the
            // memory-ledger producer goes unbalanced and the
            // open-chain harness rejects, which is the desired
            // behaviour for those tests.
            let mem_op = fixed_mem_ops.next();
            let scalar_ptr = mem_op.map(|op| op.scalar_ptr).unwrap_or(0);
            let ts = mem_op.map(|op| op.ts).unwrap_or(0);
            let ts_bytes = ts.to_le_bytes();

            for byte_idx in 0..ROWS_PER_CALL {
                let byte = call.scalar[byte_idx];
                let low = byte & 0x0F;
                let high = (byte >> 4) & 0x0F;
                let addr = scalar_ptr + byte_idx as u32;
                let addr_bytes = addr.to_le_bytes();

                trace.fill_columns(row, 1u8, Column::IsReal);
                trace.fill_columns(row, call_idx as u8, Column::CallIdx);
                trace.fill_columns(row, low, Column::LowNibble);
                trace.fill_columns(row, high, Column::HighNibble);
                trace.fill_columns(row, byte, Column::ScalarByte);
                trace.fill_columns_bytes(row, &addr_bytes, Column::Addr);
                trace.fill_columns_bytes(row, &ts_bytes, Column::Ts);
                row += 1;
            }
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

        let scalar: &RistrettoCombScalarBoundaryLookupElements = lookup_elements.as_ref();
        let memory: &MemoryAccessLookupElements = lookup_elements.as_ref();

        let is_real = crate::trace::original_base_column!(component_trace, Column::IsReal);
        let call_idx = crate::trace::original_base_column!(component_trace, Column::CallIdx);
        let low_nibble = crate::trace::original_base_column!(component_trace, Column::LowNibble);
        let high_nibble = crate::trace::original_base_column!(component_trace, Column::HighNibble);
        let scalar_byte = crate::trace::original_base_column!(component_trace, Column::ScalarByte);
        let addr = crate::trace::original_base_column!(component_trace, Column::Addr);
        let ts = crate::trace::original_base_column!(component_trace, Column::Ts);
        let win_even = crate::trace::preprocessed_base_column!(
            component_trace,
            PreprocessedColumn::WindowEven
        );
        let win_odd =
            crate::trace::preprocessed_base_column!(component_trace, PreprocessedColumn::WindowOdd);

        use crate::trace::component::FinalizedColumn;
        use stwo::core::fields::m31::BaseField as BF;
        let zero: FinalizedColumn<'_> = BF::from(0u32).into();

        // ── Scalar-boundary low-nibble emission ──
        logup.add_to_relation_with(
            scalar,
            [is_real[0].clone()],
            |[r]| (-r).into(),
            &[
                call_idx[0].clone(),
                win_even[0].clone(),
                low_nibble[0].clone(),
            ],
        );
        // ── Scalar-boundary high-nibble emission ──
        logup.add_to_relation_with(
            scalar,
            [is_real[0].clone()],
            |[r]| (-r).into(),
            &[
                call_idx[0].clone(),
                win_odd[0].clone(),
                high_nibble[0].clone(),
            ],
        );

        // ── Memory ledger producer (+is_real) ──
        let mut tuple: Vec<FinalizedColumn<'_>> = Vec::with_capacity(14);
        tuple.extend(addr.iter().cloned());
        tuple.push(scalar_byte[0].clone());
        tuple.extend(ts.iter().cloned());
        tuple.push(zero);
        logup.add_to_relation_with(memory, [is_real[0].clone()], |[r]| r.into(), &tuple);

        logup.finalize()
    }
}

#[cfg(feature = "prover")]
fn boundary_log_size(side_note: &SideNote) -> u32 {
    let n_rows = side_note.ristretto_comb_calls.len() * ROWS_PER_CALL;
    log_size_for(n_rows)
}

#[cfg(feature = "prover")]
fn log_size_for(n_rows: usize) -> u32 {
    if n_rows <= 1 {
        return LOG_N_LANES;
    }
    let n = n_rows as u32;
    let log = 32 - (n - 1).leading_zeros();
    log.max(LOG_N_LANES)
}
