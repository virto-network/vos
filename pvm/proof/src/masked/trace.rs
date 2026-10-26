//! A run's columns as a masked segment proves them: each active chip's
//! preprocessed, main and interaction columns, and its interaction trace
//! with its blinding fraction ([`ChipTraces::interaction`]). The node's
//! segment ([`masked_segment_trace`]) takes each chip at least a floor; the
//! device's ([`masked_device_trace`]) at the program's log sizes exactly.

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
use stwo_constraint_framework::PREPROCESSED_TRACE_IDX;

use crate::framework::MachineProverComponent;
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

/// A run's chips, traced, in a chip set's order: what the masked prover
/// commits.
pub struct ChipTraces {
    components: Vec<&'static dyn MachineProverComponent>,
    traces: Vec<ComponentTrace>,
}

/// A run's chips, traced as the node's segment: what the masked prover
/// commits.
pub struct MaskedSegmentTrace {
    /// The chips, as an active-chip mask.
    pub active: u32,
    /// Each chip's log size, in chip order.
    pub log_sizes: Vec<u32>,
    pub initial_state: SegmentState,
    pub final_state: SegmentState,
    chips: ChipTraces,
}

impl core::ops::Deref for MaskedSegmentTrace {
    type Target = ChipTraces;

    fn deref(&self) -> &ChipTraces {
        &self.chips
    }
}

impl core::ops::DerefMut for MaskedSegmentTrace {
    fn deref_mut(&mut self) -> &mut ChipTraces {
        &mut self.chips
    }
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
        chips: ChipTraces { components, traces },
    })
}

/// A run's chips, traced as the device's segment (`crate::device`).
pub struct MaskedDeviceTrace {
    /// The chips, as a device mask.
    pub active: u32,
    /// Each chip's log size, in `DEVICE_ORDER`: the program's.
    pub log_sizes: Vec<u32>,
    /// φ9..12 at the halt, 32 LE bytes: the one public output.
    pub io: [u8; 32],
    chips: ChipTraces,
}

impl core::ops::Deref for MaskedDeviceTrace {
    type Target = ChipTraces;

    fn deref(&self) -> &ChipTraces {
        &self.chips
    }
}

impl core::ops::DerefMut for MaskedDeviceTrace {
    fn deref_mut(&mut self) -> &mut ChipTraces {
        &mut self.chips
    }
}

impl MaskedDeviceTrace {
    /// The values mixed after the main tree's root: the io-hash
    /// ([`super::device_public_values`]).
    pub fn public(&self) -> Vec<SecureField> {
        super::device_public_values(&self.io)
    }
}

/// The log sizes a device segment is traced at.
#[derive(Clone, Copy, Debug)]
pub enum DeviceSizes<'a> {
    /// The program's, exactly: a run that needs more rows of a chip is
    /// refused ([`ProvingError::Shape`]), one that needs fewer is padded.
    Pinned(&'a [u32]),
    /// At least these: a reference run's sizes, for choosing a program's.
    AtLeast(&'a [u32]),
}

/// `side_note`'s run traced as the device's segment of a program laid out
/// as `layout`, over the chips `active` names (a device mask), each at its
/// log size in `sizes`: the program's shape, never the run's. The run is
/// taken whole: its first touches are the layout's, its registers at entry
/// the layout's.
pub fn masked_device_trace(
    side_note: &mut SideNote,
    layout: &crate::device::DeviceLayout,
    active: u32,
    sizes: DeviceSizes<'_>,
) -> Result<MaskedDeviceTrace, ProvingError> {
    let (DeviceSizes::Pinned(log_sizes) | DeviceSizes::AtLeast(log_sizes)) = sizes;
    use super::ChipSet;
    let chips = super::Device::chips(active).ok_or(ProvingError::MalformedShape)?;
    if chips.len() != log_sizes.len() {
        return Err(ProvingError::MalformedShape);
    }
    validate_memory_witnesses(side_note)?;
    prepare_side_note_for_verification(side_note);
    side_note.device = Some(alloc::sync::Arc::new(crate::device::DeviceRun::of(
        side_note,
        layout.clone(),
    )));
    let components: Vec<_> = chips
        .iter()
        .map(|&chip| crate::device_component(chip))
        .collect();
    let traces = generate_component_traces(side_note, &components, log_sizes);
    if let DeviceSizes::Pinned(log_sizes) = sizes
        && let Some((&chip, (trace, &pinned))) = chips
            .iter()
            .zip(traces.iter().zip(log_sizes))
            .find(|(_, (trace, pinned))| trace.log_size != **pinned)
    {
        return Err(ProvingError::Shape {
            chip,
            log_size: trace.log_size,
            pinned,
        });
    }
    let mut io = [0u8; 32];
    for (bytes, register) in io
        .chunks_exact_mut(8)
        .zip(&side_note.final_regs[crate::chips::device_boundary::IO_REGISTERS])
    {
        bytes.copy_from_slice(&register.to_le_bytes());
    }
    Ok(MaskedDeviceTrace {
        active,
        log_sizes: traces.iter().map(ComponentTrace::log_size).collect(),
        io,
        chips: ChipTraces { components, traces },
    })
}

/// The preprocessed columns of a device program laid out as `layout`,
/// `code` its kernel's side note (no run needed), at the shape `active`,
/// `log_sizes`: what its program id's preprocessed root commits.
pub fn device_preprocessed(
    code: &SideNote,
    layout: &crate::device::DeviceLayout,
    active: u32,
    log_sizes: &[u32],
) -> Result<Evaluations, ProvingError> {
    use super::ChipSet;
    let chips = super::Device::chips(active).ok_or(ProvingError::MalformedShape)?;
    if chips.len() != log_sizes.len() {
        return Err(ProvingError::MalformedShape);
    }
    let mut side_note = SideNote::new(Vec::new(), code.code.to_vec(), code.bitmask.to_vec())
        .with_jump_table(code.jump_table.to_vec());
    side_note.device = Some(alloc::sync::Arc::new(crate::device::DeviceRun::empty(
        layout.clone(),
    )));
    Ok(chips
        .iter()
        .zip(log_sizes)
        .flat_map(|(&chip, &log_size)| {
            crate::device_component(chip).generate_preprocessed_trace(log_size, &side_note)
        })
        .collect())
}

impl MaskedSegmentTrace {
    /// The values mixed after the main tree's root: the boundary states
    /// ([`super::public_values`]).
    pub fn public(&self) -> Vec<SecureField> {
        super::public_values(&self.initial_state, &self.final_state)
    }
}

impl ChipTraces {
    /// The preprocessed columns, chip after chip.
    pub fn preprocessed(&self) -> Evaluations {
        self.traces
            .iter()
            .flat_map(|trace| trace.to_circle_evaluation(PREPROCESSED_TRACE_IDX))
            .collect()
    }

    /// Chip `chip`'s main columns (its position among the trace's chips),
    /// in bit-reversed order, borrowed: the masked prover interpolates them
    /// a column at a time, with no copy of the trace.
    pub fn main(&self, chip: usize) -> Vec<&BaseColumn> {
        self.traces
            .get(chip)
            .map_or_else(Vec::new, |trace| trace.original_trace.iter().collect())
    }

    /// Each chip's main columns, in bit-reversed order, to change: what a
    /// forged trace starts from. The soundness gates' seam alone.
    #[cfg(feature = "seeded-masks")]
    pub fn main_columns_mut(&mut self) -> impl Iterator<Item = &mut Vec<BaseColumn>> {
        self.traces
            .iter_mut()
            .map(|trace| &mut trace.original_trace)
    }

    /// Each chip's preprocessed columns, in bit-reversed order, to change: a
    /// table or code the prover chooses. The soundness gates' seam alone.
    #[cfg(feature = "seeded-masks")]
    pub fn preprocessed_columns_mut(&mut self) -> impl Iterator<Item = &mut Vec<BaseColumn>> {
        self.traces
            .iter_mut()
            .map(|trace| &mut trace.preprocessed_trace)
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
        self.components
            .par_iter()
            .zip(&self.traces)
            .enumerate()
            .map(|(index, (component, trace))| {
                let (columns, claimed_sum) =
                    component.generate_interaction_trace(trace, side_note, relations);
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
    if blind.is_zero() {
        return (columns, claimed_sum);
    }
    assert!(
        columns.len() >= 4,
        "a chip with no fraction has no running sum to blind"
    );
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
