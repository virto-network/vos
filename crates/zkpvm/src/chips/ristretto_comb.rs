//! Session 2.1 of the perf roadmap — RistrettoCombTableChip.
//!
//! Producer-side chip for the Ristretto/Ed25519 fixed-base scalar-mult
//! comb method.  Holds the precomputed lookup table
//! `T[i][j] = j · 2^(4·i) · G` for `i ∈ 0..64`, `j ∈ 0..16` (1024
//! entries total) as preprocessed columns.  The Multiplicity column
//! counts how many fixed-base scalar-mult lookups hit each entry, and
//! the chip emits a `-Multiplicity` contribution to the
//! `RistrettoCombLookupElements` relation per row, drained by the
//! consumer chip (deferred — Session 2.1 step 5+).
//!
//! Mirrors the PopcountChip / BitwiseLookupChip pattern: fixed
//! preprocessed table plus a single Multiplicity column counted from
//! consumer-side per-row charges.
//!
//! Today this chip is dormant — `BASE_COMPONENTS` doesn't include it
//! yet (gated by `activity.ristretto_comb`, false until the consumer
//! lands).  Adding it here without the consumer keeps lookups balanced
//! at 0 (multiplicity = 0 ⇒ no contribution); when the consumer lands
//! the chip activates and the relation closes.

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

pub struct RistrettoCombTableChip;

/// `64 windows × 16 entries = 1024` rows ⇒ `log_size = 10`.
const COMB_LOG_SIZE: u32 = 10;

#[derive(Debug, Copy, Clone, AirColumn)]
pub enum Column {
    /// How many consumer lookups hit this `(window_idx, scalar_window)`
    /// entry.  Filled from `side_note.ristretto_comb_counts` (see
    /// `crate::side_note`).
    #[size = 1]
    Multiplicity,
}

#[derive(Debug, Copy, Clone, PreprocessedAirColumn)]
#[preprocessed_prefix = "ristretto_comb"]
pub enum PreprocessedColumn {
    /// Window index `i ∈ 0..64`.
    #[size = 1]
    WindowIdx,
    /// 4-bit scalar window value `j ∈ 0..16`.
    #[size = 1]
    ScalarWindow,
    /// `T[i][j].x` — 32 LE bytes.
    #[size = 32]
    X,
    /// `T[i][j].y` — 32 LE bytes.
    #[size = 32]
    Y,
    /// `T[i][j].z` — 32 LE bytes.
    #[size = 32]
    Z,
    /// `T[i][j].t` — 32 LE bytes.
    #[size = 32]
    T,
}

impl BuiltInComponent for RistrettoCombTableChip {
    type PreprocessedColumn = PreprocessedColumn;
    type MainColumn = Column;
    type LookupElements = RistrettoCombLookupElements;

    fn add_constraints<E: EvalAtRow>(
        &self,
        eval: &mut E,
        trace_eval: TraceEval<PreprocessedColumn, Column, E>,
        lookup_elements: &RistrettoCombLookupElements,
    ) {
        let window_idx =
            crate::trace::preprocessed_trace_eval!(trace_eval, PreprocessedColumn::WindowIdx);
        let scalar_window =
            crate::trace::preprocessed_trace_eval!(trace_eval, PreprocessedColumn::ScalarWindow);
        let x = crate::trace::preprocessed_trace_eval!(trace_eval, PreprocessedColumn::X);
        let y = crate::trace::preprocessed_trace_eval!(trace_eval, PreprocessedColumn::Y);
        let z = crate::trace::preprocessed_trace_eval!(trace_eval, PreprocessedColumn::Z);
        let t = crate::trace::preprocessed_trace_eval!(trace_eval, PreprocessedColumn::T);
        let mult = crate::trace::trace_eval!(trace_eval, Column::Multiplicity);

        let mut tuple: Vec<E::F> = Vec::with_capacity(1 + 1 + 32 * 4);
        tuple.push(window_idx[0].clone());
        tuple.push(scalar_window[0].clone());
        tuple.extend(x.iter().cloned());
        tuple.extend(y.iter().cloned());
        tuple.extend(z.iter().cloned());
        tuple.extend(t.iter().cloned());

        eval.add_to_relation(RelationEntry::new(
            lookup_elements,
            (-mult[0].clone()).into(),
            &tuple,
        ));

        eval.finalize_logup();
    }
}

#[cfg(feature = "prover")]
impl BuiltInProverComponent for RistrettoCombTableChip {
    const IS_PRODUCER: bool = false;

    fn generate_preprocessed_trace(
        &self,
        _log_size: u32,
        _side_note: &SideNote,
    ) -> FinalizedTrace {
        use crate::chips::ristretto::comb_table::{
            ed25519_basepoint_extended, CombTable, NUM_WINDOWS, WINDOW_SIZE,
        };
        let log_size = COMB_LOG_SIZE.max(LOG_N_LANES);
        let mut trace = TraceBuilder::<PreprocessedColumn>::new(log_size);

        let table = CombTable::from_base(&ed25519_basepoint_extended());
        for w in 0..NUM_WINDOWS {
            for s in 0..WINDOW_SIZE {
                let row = w * WINDOW_SIZE + s;
                let entry = &table.rows[w][s];
                trace.fill_columns(row, w as u8, PreprocessedColumn::WindowIdx);
                trace.fill_columns(row, s as u8, PreprocessedColumn::ScalarWindow);
                trace.fill_columns_bytes(row, &entry.x, PreprocessedColumn::X);
                trace.fill_columns_bytes(row, &entry.y, PreprocessedColumn::Y);
                trace.fill_columns_bytes(row, &entry.z, PreprocessedColumn::Z);
                trace.fill_columns_bytes(row, &entry.t, PreprocessedColumn::T);
            }
        }

        trace.finalize_bit_reversed()
    }

    fn generate_main_trace_immut(&self, side_note: &SideNote) -> FinalizedTrace {
        let log_size = COMB_LOG_SIZE.max(LOG_N_LANES);
        let mut trace = TraceBuilder::<Column>::new(log_size);
        for row in 0..(1usize << COMB_LOG_SIZE) {
            let count = side_note
                .ristretto_comb_counts
                .get(row)
                .copied()
                .unwrap_or(0u32);
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

        let comb: &RistrettoCombLookupElements = lookup_elements.as_ref();
        let window_idx = crate::trace::preprocessed_base_column!(
            component_trace,
            PreprocessedColumn::WindowIdx
        );
        let scalar_window = crate::trace::preprocessed_base_column!(
            component_trace,
            PreprocessedColumn::ScalarWindow
        );
        let x = crate::trace::preprocessed_base_column!(component_trace, PreprocessedColumn::X);
        let y = crate::trace::preprocessed_base_column!(component_trace, PreprocessedColumn::Y);
        let z = crate::trace::preprocessed_base_column!(component_trace, PreprocessedColumn::Z);
        let t = crate::trace::preprocessed_base_column!(component_trace, PreprocessedColumn::T);
        let mult =
            crate::trace::original_base_column!(component_trace, Column::Multiplicity);

        let mut tuple: Vec<_> = Vec::with_capacity(1 + 1 + 32 * 4);
        tuple.push(window_idx[0].clone());
        tuple.push(scalar_window[0].clone());
        tuple.extend(x.iter().cloned());
        tuple.extend(y.iter().cloned());
        tuple.extend(z.iter().cloned());
        tuple.extend(t.iter().cloned());

        logup.add_to_relation_with(comb, [mult[0].clone()], |[m]| (-m).into(), &tuple);

        logup.finalize()
    }
}
