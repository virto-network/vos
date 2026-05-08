//! Session 2.1 step 8 (partial) — RistrettoCombScalarBoundaryChip.
//!
//! Boundary chip that binds the comb-anchor chip's per-window
//! ScalarWindow values to the actor's input scalar bytes.  Per
//! fixed-basepoint scalar mult call, lays out 64 rows (one per 4-bit
//! window).  Each row holds:
//!   - `CallIdx` — the call's position in `ristretto_comb_calls`.
//!   - `WindowIdx` — the window number (0..64).
//!   - `KValue` — the expected nibble value derived from
//!     `ristretto_comb_calls[call].scalar[window/2]` at the
//!     `(window % 2)`-th 4-bit position.
//!
//! Emits −IsReal per row to
//! `RistrettoCombScalarBoundaryLookupElements` keyed on (CallIdx,
//! WindowIdx, KValue).  Balanced by `RistrettoCombAnchorChip`'s
//! +IsReal emission per anchor row at (CallIdx, WindowIdx,
//! ScalarWindow).  Balance forces ScalarWindow = expected nibble.
//!
//! **Soundness limitation (deferred)**: this chip pulls the scalar
//! bytes from `side_note.ristretto_comb_calls`, which is populated
//! from `ristretto_calls.scalar` in `ingest_ristretto_boundary` and
//! NOT directly bound to PVM memory.  An attacker controlling the
//! prover could in principle put non-memory bytes there.  Closing
//! this gap requires reorganising RistrettoEcallChip to skip its
//! scalar-byte memory producers for FixedBasepoint records and
//! having this chip emit them instead — multi-day refactor.

#[allow(unused_imports)]
use alloc::{boxed::Box, vec, vec::Vec};
use stwo::core::fields::m31::BaseField;
#[cfg(feature = "prover")]
use stwo::{
    core::{fields::qm31::SecureField, ColumnVec},
    prover::{
        backend::simd::{m31::LOG_N_LANES, SimdBackend},
        poly::{circle::CircleEvaluation, BitReversedOrder},
    },
};
use num_traits::One;
use stwo_constraint_framework::{EvalAtRow, RelationEntry};

use crate::air_column::{AirColumn, PreprocessedAirColumn};
use crate::trace::eval::TraceEval;
#[cfg(feature = "prover")]
use crate::trace::{
    builder::{FinalizedTrace, TraceBuilder},
    component::ComponentTrace,
};

use crate::{
    framework::BuiltInComponent, lookups::RistrettoCombScalarBoundaryLookupElements,
};
#[cfg(feature = "prover")]
use crate::framework::BuiltInProverComponent;
#[cfg(feature = "prover")]
use crate::lookups::{AllLookupElements, LogupTraceBuilder};
#[cfg(feature = "prover")]
use crate::side_note::SideNote;

pub struct RistrettoCombScalarBoundaryChip;

#[derive(Debug, Copy, Clone, AirColumn)]
pub enum Column {
    /// 1 if this row witnesses an actual scalar-mult window's nibble;
    /// 0 if padding.
    #[size = 1]
    IsReal,
    /// Index of the scalar-mult call in `ristretto_comb_calls`.
    #[size = 1]
    CallIdx,
    /// Window index `i ∈ 0..64`.
    #[size = 1]
    WindowIdx,
    /// Expected 4-bit nibble value `k_i ∈ 0..16` derived from the
    /// actor's scalar bytes.
    #[size = 1]
    KValue,
}

#[derive(Debug, Copy, Clone, PreprocessedAirColumn)]
#[preprocessed_prefix = "ristretto_comb_scalar_boundary"]
pub enum PreprocessedColumn {}

impl BuiltInComponent for RistrettoCombScalarBoundaryChip {
    type PreprocessedColumn = PreprocessedColumn;
    type MainColumn = Column;
    type LookupElements = RistrettoCombScalarBoundaryLookupElements;

    fn add_constraints<E: EvalAtRow>(
        &self,
        eval: &mut E,
        trace_eval: TraceEval<PreprocessedColumn, Column, E>,
        lookup_elements: &RistrettoCombScalarBoundaryLookupElements,
    ) {
        let is_real = crate::trace::trace_eval!(trace_eval, Column::IsReal);
        let call_idx = crate::trace::trace_eval!(trace_eval, Column::CallIdx);
        let window_idx = crate::trace::trace_eval!(trace_eval, Column::WindowIdx);
        let k_value = crate::trace::trace_eval!(trace_eval, Column::KValue);

        // is_real ∈ {0, 1}.
        eval.add_constraint(is_real[0].clone() * (E::F::one() - is_real[0].clone()));

        // Emit −is_real per row to the scalar boundary relation.
        eval.add_to_relation(RelationEntry::new(
            lookup_elements,
            (-is_real[0].clone()).into(),
            &[
                call_idx[0].clone(),
                window_idx[0].clone(),
                k_value[0].clone(),
            ],
        ));

        eval.finalize_logup();
    }
}

#[cfg(feature = "prover")]
impl BuiltInProverComponent for RistrettoCombScalarBoundaryChip {
    const IS_PRODUCER: bool = false;

    fn generate_main_trace_immut(&self, side_note: &SideNote) -> FinalizedTrace {
        use crate::chips::ristretto::comb_table::NUM_WINDOWS;
        let n_rows = side_note.ristretto_comb_calls.len() * NUM_WINDOWS;
        let log_size = log_size_for(n_rows);
        let mut trace = TraceBuilder::<Column>::new(log_size);

        let mut row = 0usize;
        for (call_idx, call) in side_note.ristretto_comb_calls.iter().enumerate() {
            for w in 0..NUM_WINDOWS {
                let byte = call.scalar[w / 2];
                let nibble_idx = w % 2;
                let k_i = ((byte >> (nibble_idx * 4)) & 0x0F) as u8;
                trace.fill_columns(row, 1u8, Column::IsReal);
                trace.fill_columns(row, call_idx as u8, Column::CallIdx);
                trace.fill_columns(row, w as u8, Column::WindowIdx);
                trace.fill_columns(row, k_i, Column::KValue);
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

        let scalar: &RistrettoCombScalarBoundaryLookupElements =
            lookup_elements.as_ref();

        let is_real = crate::trace::original_base_column!(component_trace, Column::IsReal);
        let call_idx =
            crate::trace::original_base_column!(component_trace, Column::CallIdx);
        let window_idx =
            crate::trace::original_base_column!(component_trace, Column::WindowIdx);
        let k_value =
            crate::trace::original_base_column!(component_trace, Column::KValue);

        logup.add_to_relation_with(
            scalar,
            [is_real[0].clone()],
            |[r]| (-r).into(),
            &[
                call_idx[0].clone(),
                window_idx[0].clone(),
                k_value[0].clone(),
            ],
        );

        logup.finalize()
    }
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
