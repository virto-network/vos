//! A run's columns as the masked segment proves them: each active chip's
//! preprocessed, main and interaction columns, its rows at least a floor,
//! and its interaction trace with its blinding fraction
//! ([`MaskedSegmentTrace::interaction`]).

use num_traits::Zero;
use rayon::prelude::*;
use stwo::core::ColumnVec;
use stwo::core::fields::FieldExpOps;
use stwo::core::fields::m31::BaseField;
use stwo::core::fields::qm31::SecureField;
use stwo::core::utils::{bit_reverse_index, coset_index_to_circle_domain_index};
use stwo::prover::backend::simd::SimdBackend;
use stwo::prover::backend::simd::column::BaseColumn;
use stwo::prover::poly::BitReversedOrder;
use stwo::prover::poly::circle::CircleEvaluation;
use stwo_constraint_framework::{ORIGINAL_TRACE_IDX, PREPROCESSED_TRACE_IDX};

use crate::lookups::AllLookupElements;
use crate::proof::SegmentState;
use crate::prove::{
    ProvingError, backfill_final_regs, backfill_initial_regs, derive_segment_states,
    generate_component_traces, prepare_side_note_for_verification, validate_memory_witnesses,
};
use crate::side_note::SideNote;
use crate::trace::component::ComponentTrace;
use crate::{BASE_COMPONENTS, chip_idx, chips_of_mask};

/// Columns as Stwo's evaluations, in bit-reversed order.
pub type Evaluations = ColumnVec<CircleEvaluation<SimdBackend, BaseField, BitReversedOrder>>;

/// A run's chips, traced: what the masked prover commits.
pub struct MaskedSegmentTrace {
    /// The chips, as an active-chip mask.
    pub active: u32,
    /// Each chip's log size, in chip order.
    pub log_sizes: Vec<u32>,
    pub initial_state: SegmentState,
    pub final_state: SegmentState,
    traces: Vec<ComponentTrace>,
}

/// `side_note`'s run traced over the chips `active` names, each chip at
/// least its floor in `floors` (in chip order): the unmasked prover's
/// preparation, then the chips' main and preprocessed columns.
pub fn masked_segment_trace(
    side_note: &mut SideNote,
    active: u32,
    floors: &[u32],
) -> Result<MaskedSegmentTrace, ProvingError> {
    if active & !chip_idx::ALL != 0 || active.count_ones() as usize != floors.len() {
        return Err(ProvingError::MalformedShape);
    }
    prepare_side_note_for_verification(side_note);
    validate_memory_witnesses(side_note)?;
    backfill_initial_regs(side_note);
    if side_note.closing_chip_active {
        backfill_final_regs(side_note);
    }
    side_note.ingest_memory_pages();
    let components: Vec<_> = chips_of_mask(active)
        .map(|chip| BASE_COMPONENTS[chip])
        .collect();
    let traces = generate_component_traces(side_note, &components, floors);
    let (initial_state, final_state) = derive_segment_states(side_note);
    Ok(MaskedSegmentTrace {
        active,
        log_sizes: traces.iter().map(ComponentTrace::log_size).collect(),
        initial_state,
        final_state,
        traces,
    })
}

impl MaskedSegmentTrace {
    /// The preprocessed columns, chip after chip.
    pub fn preprocessed(&self) -> Evaluations {
        self.traces
            .iter()
            .flat_map(|trace| trace.to_circle_evaluation(PREPROCESSED_TRACE_IDX))
            .collect()
    }

    /// Each chip's main columns.
    pub fn main(&self) -> Vec<Evaluations> {
        self.traces
            .iter()
            .map(|trace| trace.to_circle_evaluation(ORIGINAL_TRACE_IDX))
            .collect()
    }

    /// Each chip's main columns, in bit-reversed order, to change: what a
    /// forged trace starts from.
    pub fn main_columns_mut(&mut self) -> impl Iterator<Item = &mut Vec<BaseColumn>> {
        self.traces
            .iter_mut()
            .map(|trace| &mut trace.original_trace)
    }

    /// The values mixed after the main tree's root: the boundary states
    /// ([`super::public_values`]).
    pub fn public(&self) -> Vec<SecureField> {
        super::public_values(&self.initial_state, &self.final_state)
    }

    /// Each chip's interaction columns and claimed sum under `relations`,
    /// its blinding fraction `(numerator, denominator)` in `blinding` (on the
    /// first row of the coset, zero on every other) joined to its last batch:
    /// the running sum, the last column, takes it at the first row and its
    /// share of the shift on every row.
    pub fn interaction(
        &self,
        side_note: &SideNote,
        relations: &AllLookupElements,
        blinding: &[(SecureField, SecureField)],
    ) -> Vec<(Evaluations, SecureField)> {
        let components: Vec<_> = chips_of_mask(self.active)
            .map(|chip| BASE_COMPONENTS[chip])
            .collect();
        components
            .par_iter()
            .zip(&self.traces)
            .enumerate()
            .map(|(index, (component, trace))| {
                let (columns, claimed_sum) =
                    component.generate_interaction_trace(trace.clone(), side_note, relations);
                let blind = blinding
                    .get(index)
                    .map_or(SecureField::zero(), |&(numerator, denominator)| {
                        numerator * denominator.inverse()
                    });
                blinded(columns, claimed_sum, trace.log_size, blind)
            })
            .collect()
    }
}

/// `columns`, a chip's interaction trace, with `blind` added to its last
/// batch at the coset's first row: its running sum (the last four columns)
/// moved by `blind·(1 − (r + 1)/N)` at coset row `r` of `N`, which adds
/// `blind` at row 0 and `blind/N` to the shift, the claimed sum `blind`.
fn blinded(
    mut columns: Evaluations,
    claimed_sum: SecureField,
    log_size: u32,
    blind: SecureField,
) -> (Evaluations, SecureField) {
    if blind.is_zero() || columns.len() < 4 {
        return (columns, claimed_sum);
    }
    let rows = 1usize << log_size;
    let step = blind * BaseField::from(rows as u32).inverse();
    let first = columns.len() - 4;
    let mut running = columns.split_off(first);
    let mut values: Vec<&mut [BaseField]> = running
        .iter_mut()
        .map(|column| column.values.as_mut_slice())
        .collect();
    let mut shift = blind;
    for row in 0..rows {
        shift -= step;
        let at = bit_reverse_index(coset_index_to_circle_domain_index(row, log_size), log_size);
        for (column, limb) in values.iter_mut().zip(shift.to_m31_array()) {
            column[at] += limb;
        }
    }
    columns.extend(running);
    (columns, claimed_sum + blind)
}
