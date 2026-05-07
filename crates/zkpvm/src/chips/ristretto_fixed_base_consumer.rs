//! Session 2.1 step 5 (Path B) — RistrettoFixedBaseConsumerChip.
//!
//! Consumer-side chip for the comb-method fixed-base scalar mult.
//! Per fixed-basepoint scalar mult call, emits 64 lookup rows — one
//! per 4-bit window — each carrying the looked-up table entry
//! `T[i][k_i]` and emitting `+IsReal` to `RistrettoCombLookupElements`.
//! `RistrettoCombTableChip` (the producer) emits `−Multiplicity` per
//! table row; balance closes when the consumer's `+1` emissions are
//! counted into the producer's Multiplicity column.
//!
//! **Scope (chip-isolated POC)**: this chip proves the 130-limb
//! relation balance.  It does NOT yet bind the input scalar bytes or
//! the output point bytes to the ECALL boundary — that's step 8.
//! Soundness gap: a malicious prover can supply any `(window_idx,
//! scalar_window, x, y, z, t)` tuple matching some table row and the
//! chip accepts.  Step 8 closes this by binding the per-call
//! `(scalar, output)` to the chip's first / last rows via
//! RistrettoEcallChip's existing boundary relation.
//!
//! Mirrors the BlakeStateChip / RistrettoChip pattern: per-row
//! algebra is driven by witness columns; no schoolbook-style
//! constraint chain (the heavy lifting moves to the preprocessed
//! table).

#[allow(unused_imports)]
use alloc::{boxed::Box, vec, vec::Vec};
#[cfg(feature = "prover")]
use stwo::{
    core::{fields::qm31::SecureField, fields::m31::BaseField, ColumnVec},
    prover::{
        backend::simd::{m31::LOG_N_LANES, SimdBackend},
        poly::{circle::CircleEvaluation, BitReversedOrder},
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

use crate::{framework::BuiltInComponent, lookups::RistrettoCombLookupElements};
#[cfg(feature = "prover")]
use crate::framework::BuiltInProverComponent;
#[cfg(feature = "prover")]
use crate::lookups::{AllLookupElements, LogupTraceBuilder};
#[cfg(feature = "prover")]
use crate::side_note::SideNote;

pub struct RistrettoFixedBaseConsumerChip;

#[derive(Debug, Copy, Clone, AirColumn)]
pub enum Column {
    /// 1 if this row witnesses an actual scalar-mult window; 0 if
    /// padding.  Multiplies the +1 lookup contribution so padding rows
    /// don't unbalance the relation.
    #[size = 1]
    IsReal,
    /// Window index `i ∈ 0..64`.  Padding rows hold 0.
    #[size = 1]
    WindowIdx,
    /// 4-bit scalar window value `j ∈ 0..16`.  Padding rows hold 0.
    #[size = 1]
    ScalarWindow,
    /// `T[i][j].x` — 32 LE bytes.  Looked-up table entry coords;
    /// padding rows hold zeros (must match T[0][0] = identity, which
    /// is `(0, 1, 1, 0)` — see notes below on the closure trick).
    #[size = 32]
    X,
    #[size = 32]
    Y,
    #[size = 32]
    Z,
    #[size = 32]
    T,
}

#[derive(Debug, Copy, Clone, PreprocessedAirColumn)]
#[preprocessed_prefix = "ristretto_fixed_base_consumer"]
pub enum PreprocessedColumn {}

impl BuiltInComponent for RistrettoFixedBaseConsumerChip {
    type PreprocessedColumn = PreprocessedColumn;
    type MainColumn = Column;
    type LookupElements = RistrettoCombLookupElements;

    fn add_constraints<E: EvalAtRow>(
        &self,
        eval: &mut E,
        trace_eval: TraceEval<PreprocessedColumn, Column, E>,
        lookup_elements: &RistrettoCombLookupElements,
    ) {
        let is_real = crate::trace::trace_eval!(trace_eval, Column::IsReal);
        let window_idx = crate::trace::trace_eval!(trace_eval, Column::WindowIdx);
        let scalar_window = crate::trace::trace_eval!(trace_eval, Column::ScalarWindow);
        let x = crate::trace::trace_eval!(trace_eval, Column::X);
        let y = crate::trace::trace_eval!(trace_eval, Column::Y);
        let z = crate::trace::trace_eval!(trace_eval, Column::Z);
        let t = crate::trace::trace_eval!(trace_eval, Column::T);

        // is_real ∈ {0, 1}.
        eval.add_constraint(is_real[0].clone() * (E::F::from(BaseField::from(1u32)) - is_real[0].clone()));

        let mut tuple: Vec<E::F> = Vec::with_capacity(1 + 1 + 32 * 4);
        tuple.push(window_idx[0].clone());
        tuple.push(scalar_window[0].clone());
        tuple.extend(x.iter().cloned());
        tuple.extend(y.iter().cloned());
        tuple.extend(z.iter().cloned());
        tuple.extend(t.iter().cloned());

        eval.add_to_relation(RelationEntry::new(
            lookup_elements,
            is_real[0].clone().into(),
            &tuple,
        ));

        eval.finalize_logup();
    }
}

#[cfg(feature = "prover")]
impl BuiltInProverComponent for RistrettoFixedBaseConsumerChip {
    const IS_PRODUCER: bool = false;

    fn generate_main_trace_immut(&self, side_note: &SideNote) -> FinalizedTrace {
        use crate::chips::ristretto::comb_table::{
            ed25519_basepoint_extended, CombTable, NUM_WINDOWS, WINDOW_SIZE,
        };

        let n_calls = side_note.ristretto_comb_calls.len();
        let n_real_rows = n_calls * NUM_WINDOWS;
        let log_size = log_size_for(n_real_rows).max(LOG_N_LANES);
        let mut trace = TraceBuilder::<Column>::new(log_size);

        // Cache the comb table — same singleton the producer chip
        // commits to as its preprocessed columns.
        let table = CombTable::from_base(&ed25519_basepoint_extended());

        let mut row = 0usize;
        for call in &side_note.ristretto_comb_calls {
            for i in 0..NUM_WINDOWS {
                let byte = call.scalar[i / 2];
                let nibble_idx = i % 2;
                let k_i = ((byte >> (nibble_idx * 4)) & 0x0F) as usize;
                let entry = &table.rows[i][k_i];
                trace.fill_columns(row, 1u8, Column::IsReal);
                trace.fill_columns(row, i as u8, Column::WindowIdx);
                trace.fill_columns(row, k_i as u8, Column::ScalarWindow);
                trace.fill_columns_bytes(row, &entry.x, Column::X);
                trace.fill_columns_bytes(row, &entry.y, Column::Y);
                trace.fill_columns_bytes(row, &entry.z, Column::Z);
                trace.fill_columns_bytes(row, &entry.t, Column::T);
                row += 1;
            }
        }

        // Padding rows: leave defaults (zeros).  IsReal = 0 means the
        // lookup contribution is `0 · tuple = 0` — padding rows don't
        // affect the relation balance.  WindowIdx/ScalarWindow/X/Y/Z/T
        // = 0 satisfies the boolean constraint on IsReal trivially.
        let _ = WINDOW_SIZE; // suppress unused warning; kept for symmetry with consumer side.
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

        let comb: &RistrettoCombLookupElements = lookup_elements.as_ref();
        let is_real = crate::trace::original_base_column!(component_trace, Column::IsReal);
        let window_idx = crate::trace::original_base_column!(component_trace, Column::WindowIdx);
        let scalar_window =
            crate::trace::original_base_column!(component_trace, Column::ScalarWindow);
        let x = crate::trace::original_base_column!(component_trace, Column::X);
        let y = crate::trace::original_base_column!(component_trace, Column::Y);
        let z = crate::trace::original_base_column!(component_trace, Column::Z);
        let t = crate::trace::original_base_column!(component_trace, Column::T);

        let mut tuple: Vec<_> = Vec::with_capacity(1 + 1 + 32 * 4);
        tuple.push(window_idx[0].clone());
        tuple.push(scalar_window[0].clone());
        tuple.extend(x.iter().cloned());
        tuple.extend(y.iter().cloned());
        tuple.extend(z.iter().cloned());
        tuple.extend(t.iter().cloned());

        logup.add_to_relation_with(comb, [is_real[0].clone()], |[r]| r.into(), &tuple);

        logup.finalize()
    }
}

#[cfg(feature = "prover")]
fn log_size_for(n_rows: usize) -> u32 {
    if n_rows <= 1 {
        return 0;
    }
    let n = n_rows as u32;
    32 - (n - 1).leading_zeros()
}
