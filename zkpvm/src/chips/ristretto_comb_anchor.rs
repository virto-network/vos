//! Session 2.1 column-shrink — RistrettoCombAnchorChip.
//!
//! Sibling chip carrying the lookup-anchor metadata that previously
//! lived on the consumer chip's per-window anchor row.  Splitting it
//! out trims ~137 cells from the consumer chip's per-row width
//! (X/Y/Z/T = 128 bytes + IsLookupAnchor + WindowIdx + ScalarWindow
//! + Y/Z/T source-row Lo/Hi pairs).  At consumer-chip log_size=13
//! (8192 rows) that's ~1.1M cells dropped from the prover.
//!
//! Per fixed-basepoint scalar mult call: 64 rows (one per window)
//! holding `(CallIdx, WindowIdx, ScalarWindow, X[32], Y[32], Z[32],
//! T[32])` — the looked-up table entry `T[i][k_i]`.
//!
//! Two emissions per real row:
//!  1. `RistrettoCombLookupElements` (+IsReal) with the 130-limb
//!     tuple `(WindowIdx, ScalarWindow, X, Y, Z, T)`.  Drained by
//!     `RistrettoCombTableChip` (-Multiplicity).
//!  2. `RistrettoCombCoordBoundaryLookupElements` (+IsReal) with the
//!     5-limb tuple `(CallIdx, WindowIdx, coord_kind, byte_idx,
//!     value)` — 4 coords × 32 bytes = 128 emissions per row.
//!     Drained by the consumer chip's IsInput coord rows.

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
    lookups::{
        RistrettoCombCoordBoundaryLookupElements, RistrettoCombLookupElements,
        RistrettoCombScalarBoundaryLookupElements,
    },
};

pub struct RistrettoCombAnchorChip;

#[derive(Debug, Copy, Clone, AirColumn)]
pub enum Column {
    /// 1 if this row witnesses an actual scalar-mult window; 0 if padding.
    #[size = 1]
    IsReal,
    /// Index of the scalar-mult call in `ristretto_comb_calls`.  Used
    /// in the coord-boundary tuple key so the consumer chip can match
    /// per-call emissions across different scalar mults.  Must match
    /// the call index the consumer chip uses.
    #[size = 1]
    CallIdx,
    /// Window index `i ∈ 0..64`.
    #[size = 1]
    WindowIdx,
    /// 4-bit scalar window value `k_i ∈ 0..16`.
    #[size = 1]
    ScalarWindow,
    /// `T[i][k_i].x` — 32 LE bytes.
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
#[preprocessed_prefix = "ristretto_comb_anchor"]
pub enum PreprocessedColumn {
    /// `ByteIdx[k] = k` for k=0..32.  Used as the byte_idx element of
    /// coord-boundary lookup tuples.
    #[size = 32]
    ByteIdx,
}

impl BuiltInComponent for RistrettoCombAnchorChip {
    type PreprocessedColumn = PreprocessedColumn;
    type MainColumn = Column;
    type LookupElements = (
        RistrettoCombLookupElements,
        RistrettoCombCoordBoundaryLookupElements,
        RistrettoCombScalarBoundaryLookupElements,
    );

    fn add_constraints<E: EvalAtRow>(
        &self,
        eval: &mut E,
        trace_eval: TraceEval<PreprocessedColumn, Column, E>,
        lookup_elements: &(
            RistrettoCombLookupElements,
            RistrettoCombCoordBoundaryLookupElements,
            RistrettoCombScalarBoundaryLookupElements,
        ),
    ) {
        let (comb_lookup, coord_lookup, scalar_lookup) = lookup_elements;
        let is_real = crate::trace::trace_eval!(trace_eval, Column::IsReal);
        let call_idx = crate::trace::trace_eval!(trace_eval, Column::CallIdx);
        let window_idx = crate::trace::trace_eval!(trace_eval, Column::WindowIdx);
        let scalar_window = crate::trace::trace_eval!(trace_eval, Column::ScalarWindow);
        let x = crate::trace::trace_eval!(trace_eval, Column::X);
        let y = crate::trace::trace_eval!(trace_eval, Column::Y);
        let z = crate::trace::trace_eval!(trace_eval, Column::Z);
        let t = crate::trace::trace_eval!(trace_eval, Column::T);
        let byte_idx_pp =
            crate::trace::preprocessed_trace_eval!(trace_eval, PreprocessedColumn::ByteIdx);

        // is_real ∈ {0, 1}.
        eval.add_constraint(is_real[0].clone() * (E::F::one() - is_real[0].clone()));

        // ── Comb relation emission (130-limb tuple) ──
        let mut tuple: Vec<E::F> = Vec::with_capacity(1 + 1 + 32 * 4);
        tuple.push(window_idx[0].clone());
        tuple.push(scalar_window[0].clone());
        tuple.extend(x.iter().cloned());
        tuple.extend(y.iter().cloned());
        tuple.extend(z.iter().cloned());
        tuple.extend(t.iter().cloned());
        eval.add_to_relation(RelationEntry::new(
            comb_lookup,
            is_real[0].clone().into(),
            &tuple,
        ));

        // ── Coord-boundary relation: 4 coords × 32 bytes = 128 emits ──
        let f0 = E::F::from(BaseField::from(0u32));
        let f1 = E::F::from(BaseField::from(1u32));
        let f2 = E::F::from(BaseField::from(2u32));
        let f3 = E::F::from(BaseField::from(3u32));
        for k in 0..32usize {
            // X coord (kind=0).
            eval.add_to_relation(RelationEntry::new(
                coord_lookup,
                is_real[0].clone().into(),
                &[
                    call_idx[0].clone(),
                    window_idx[0].clone(),
                    f0.clone(),
                    byte_idx_pp[k].clone(),
                    x[k].clone(),
                ],
            ));
            // Y coord (kind=1).
            eval.add_to_relation(RelationEntry::new(
                coord_lookup,
                is_real[0].clone().into(),
                &[
                    call_idx[0].clone(),
                    window_idx[0].clone(),
                    f1.clone(),
                    byte_idx_pp[k].clone(),
                    y[k].clone(),
                ],
            ));
            // Z coord (kind=2).
            eval.add_to_relation(RelationEntry::new(
                coord_lookup,
                is_real[0].clone().into(),
                &[
                    call_idx[0].clone(),
                    window_idx[0].clone(),
                    f2.clone(),
                    byte_idx_pp[k].clone(),
                    z[k].clone(),
                ],
            ));
            // T coord (kind=3).
            eval.add_to_relation(RelationEntry::new(
                coord_lookup,
                is_real[0].clone().into(),
                &[
                    call_idx[0].clone(),
                    window_idx[0].clone(),
                    f3.clone(),
                    byte_idx_pp[k].clone(),
                    t[k].clone(),
                ],
            ));
        }

        // ── Scalar boundary relation (step 8): bind ScalarWindow per
        // (call, window) to the actor's scalar's nibble.  Emits 1
        // tuple per row.
        eval.add_to_relation(RelationEntry::new(
            scalar_lookup,
            is_real[0].clone().into(),
            &[
                call_idx[0].clone(),
                window_idx[0].clone(),
                scalar_window[0].clone(),
            ],
        ));

        eval.finalize_logup_in_pairs();
    }
}

#[cfg(feature = "prover")]
impl BuiltInProverComponent for RistrettoCombAnchorChip {
    const IS_PRODUCER: bool = false;

    fn generate_preprocessed_trace(&self, log_size: u32, _side_note: &SideNote) -> FinalizedTrace {
        // Canonical-shape: use the (possibly forced) main-trace `log_size`.
        // ByteIdx is pure-positional ⇒ witness-independent preprocessed trace.
        let mut trace = TraceBuilder::<PreprocessedColumn>::new(log_size);
        let num_rows = trace.num_rows();
        for row in 0..num_rows {
            let byte_idx_arr: [u8; 32] = core::array::from_fn(|k| k as u8);
            trace.fill_columns_bytes(row, &byte_idx_arr, PreprocessedColumn::ByteIdx);
        }
        trace.finalize_bit_reversed()
    }

    fn generate_main_trace_immut(&self, side_note: &SideNote) -> FinalizedTrace {
        self.generate_main_trace_immut_min(side_note, 0)
    }

    fn generate_main_trace_immut_min(
        &self,
        side_note: &SideNote,
        min_log_size: u32,
    ) -> FinalizedTrace {
        use crate::chips::ristretto::comb_table::{
            CombTable, NUM_WINDOWS, ed25519_basepoint_extended,
        };
        let log_size = anchor_log_size(side_note).max(min_log_size);
        let mut trace = TraceBuilder::<Column>::new(log_size);

        let table = CombTable::from_base(&ed25519_basepoint_extended());

        let mut row = 0usize;
        for (call_idx, call) in side_note.ristretto_comb_calls.iter().enumerate() {
            for w in 0..NUM_WINDOWS {
                let byte = call.scalar[w / 2];
                let nibble_idx = w % 2;
                let k_i = ((byte >> (nibble_idx * 4)) & 0x0F) as usize;
                let entry = &table.rows[w][k_i];
                trace.fill_columns(row, 1u8, Column::IsReal);
                trace.fill_columns(row, call_idx as u8, Column::CallIdx);
                trace.fill_columns(row, w as u8, Column::WindowIdx);
                trace.fill_columns(row, k_i as u8, Column::ScalarWindow);
                trace.fill_columns_bytes(row, &entry.x, Column::X);
                trace.fill_columns_bytes(row, &entry.y, Column::Y);
                trace.fill_columns_bytes(row, &entry.z, Column::Z);
                trace.fill_columns_bytes(row, &entry.t, Column::T);
                row += 1;
            }
        }
        // Padding rows leave defaults (zeros).  IsReal = 0 disables emissions.
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
        let coord: &RistrettoCombCoordBoundaryLookupElements = lookup_elements.as_ref();

        let is_real = crate::trace::original_base_column!(component_trace, Column::IsReal);
        let call_idx = crate::trace::original_base_column!(component_trace, Column::CallIdx);
        let window_idx = crate::trace::original_base_column!(component_trace, Column::WindowIdx);
        let scalar_window =
            crate::trace::original_base_column!(component_trace, Column::ScalarWindow);
        let x = crate::trace::original_base_column!(component_trace, Column::X);
        let y = crate::trace::original_base_column!(component_trace, Column::Y);
        let z = crate::trace::original_base_column!(component_trace, Column::Z);
        let t = crate::trace::original_base_column!(component_trace, Column::T);
        let byte_idx_pp =
            crate::trace::preprocessed_base_column!(component_trace, PreprocessedColumn::ByteIdx);

        // Comb relation emission.
        let mut tuple: Vec<_> = Vec::with_capacity(1 + 1 + 32 * 4);
        tuple.push(window_idx[0].clone());
        tuple.push(scalar_window[0].clone());
        tuple.extend(x.iter().cloned());
        tuple.extend(y.iter().cloned());
        tuple.extend(z.iter().cloned());
        tuple.extend(t.iter().cloned());
        logup.add_to_relation_with(comb, [is_real[0].clone()], |[r]| r.into(), &tuple);

        // Coord-boundary emissions.  Constants for coord_kind: use
        // FinalizedColumn::Constant via the From<BaseField> impl.
        use crate::trace::component::FinalizedColumn;
        use stwo::core::fields::m31::BaseField as BF;
        let kind_0: FinalizedColumn<'_> = BF::from(0u32).into();
        let kind_1: FinalizedColumn<'_> = BF::from(1u32).into();
        let kind_2: FinalizedColumn<'_> = BF::from(2u32).into();
        let kind_3: FinalizedColumn<'_> = BF::from(3u32).into();

        for k in 0..32 {
            for (kind, col) in [(&kind_0, &x), (&kind_1, &y), (&kind_2, &z), (&kind_3, &t)] {
                logup.add_to_relation_with(
                    coord,
                    [is_real[0].clone()],
                    |[r]| r.into(),
                    &[
                        call_idx[0].clone(),
                        window_idx[0].clone(),
                        kind.clone(),
                        byte_idx_pp[k].clone(),
                        col[k].clone(),
                    ],
                );
            }
        }

        // Scalar boundary emission.
        let scalar: &RistrettoCombScalarBoundaryLookupElements = lookup_elements.as_ref();
        logup.add_to_relation_with(
            scalar,
            [is_real[0].clone()],
            |[r]| r.into(),
            &[
                call_idx[0].clone(),
                window_idx[0].clone(),
                scalar_window[0].clone(),
            ],
        );

        logup.finalize()
    }
}

#[cfg(feature = "prover")]
fn anchor_log_size(side_note: &SideNote) -> u32 {
    use crate::chips::ristretto::comb_table::NUM_WINDOWS;
    let n_rows = side_note.ristretto_comb_calls.len() * NUM_WINDOWS;
    log_size_for(n_rows).max(LOG_N_LANES)
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
