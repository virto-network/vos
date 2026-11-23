//! A run's columns as a masked segment proves them: each active chip's
//! preprocessed, main and interaction columns, and its interaction trace
//! with its blinding fraction ([`ChipTraces::interaction`]), each chip at
//! the program's log size exactly ([`masked_device_trace`]).

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

use crate::chip_idx;
use crate::framework::MachineProverComponent;
use crate::lookups::AllLookupElements;
use crate::prove::{
    SegmentError, check_run_length, check_stop, check_transfers, generate_component_traces,
    prepare_side_note_for_verification, steps_fit, validate_memory_witnesses,
};
use crate::side_note::SideNote;
use crate::trace::component::ComponentTrace;

/// Columns as Stwo's evaluations, in bit-reversed order.
pub type Evaluations = ColumnVec<CircleEvaluation<SimdBackend, BaseField, BitReversedOrder>>;

/// A run's chips, traced, in a chip set's order: what the masked prover
/// commits.
pub struct ChipTraces {
    components: Vec<&'static dyn MachineProverComponent>,
    traces: Vec<ComponentTrace>,
    /// The per-program CPU the first chip is, its cut columns zeroed in its
    /// trace; `None` for the full CPU.
    cpu: Option<crate::chips::ProgramCpuChip>,
}

/// `column`'s values overwritten with zeros by volatile writes, which the
/// compiler keeps though nothing reads them after: a witness's column, once
/// it is no longer needed. The allocator gets the zeros back.
#[allow(unsafe_code)]
pub fn wipe_column(column: &mut BaseColumn) {
    use stwo::prover::backend::simd::m31::PackedBaseField;
    for packed in &mut column.data {
        // SAFETY: `packed` is a valid, aligned, exclusive reference.
        unsafe { core::ptr::write_volatile(packed, PackedBaseField::zero()) };
    }
    core::sync::atomic::compiler_fence(core::sync::atomic::Ordering::SeqCst);
}

/// Each chip's main columns, the witness, wiped when the traces are
/// dropped ([`wipe_column`]); the preprocessed columns are the program's.
impl Drop for ChipTraces {
    fn drop(&mut self) {
        for trace in &mut self.traces {
            trace.original_trace.iter_mut().for_each(wipe_column);
        }
    }
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
    /// refused ([`SegmentError::Shape`]), one that needs fewer is padded.
    Pinned(&'a [u32]),
    /// At least these: a reference run's sizes, for choosing a program's.
    AtLeast(&'a [u32]),
}

/// `side_note`'s run traced as the device's segment of a program laid out
/// as `layout`, over the chips `shape` names (a device mask) and its CPU,
/// each at its log size in `sizes`: the program's shape, never the run's.
/// The run is taken whole: its first touches are the layout's, its
/// registers at entry the layout's. A per-program CPU's cut columns are
/// zeroed in its trace.
pub fn masked_device_trace(
    side_note: &mut SideNote,
    layout: &crate::device::DeviceLayout,
    shape: crate::device::DeviceShape,
    sizes: DeviceSizes<'_>,
) -> Result<MaskedDeviceTrace, SegmentError> {
    let (DeviceSizes::Pinned(log_sizes) | DeviceSizes::AtLeast(log_sizes)) = sizes;
    let active = shape.chips;
    let chips = super::DeviceComponents::chips(shape).ok_or(SegmentError::MalformedShape)?;
    if chips.len() != log_sizes.len() {
        return Err(SegmentError::MalformedShape);
    }
    check_run_length(side_note)?;
    check_transfers(side_note)?;
    check_stop(side_note)?;
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
    let cpu = shape.program_cpu();
    side_note.cpu_rows_local = cpu.is_some();
    let pinned = matches!(sizes, DeviceSizes::Pinned(_));
    // A run is refused at its first chip past its size, before any later
    // chip is traced: the CPU, a row a step, before any.
    if pinned && chips.first() == Some(&chip_idx::CPU) && !steps_fit(side_note, log_sizes[0]) {
        return Err(SegmentError::Shape {
            chip: chip_idx::CPU,
            overflow: true,
        });
    }
    let mut traces = generate_component_traces(side_note, &components, log_sizes, pinned).map_err(
        |(position, log_size)| SegmentError::Shape {
            chip: chips[position],
            overflow: log_size > log_sizes[position],
        },
    )?;
    if let Some(cpu) = &cpu {
        assert_eq!(
            chips.first(),
            Some(&chip_idx::CPU),
            "the CPU is the first chip"
        );
        cpu.cut(&mut traces[0]);
    }
    if let DeviceSizes::Pinned(log_sizes) = sizes
        && let Some((&chip, (trace, &pinned))) = chips
            .iter()
            .zip(traces.iter().zip(log_sizes))
            .find(|(_, (trace, pinned))| trace.log_size != **pinned)
    {
        return Err(SegmentError::Shape {
            chip,
            overflow: trace.log_size > pinned,
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
        chips: ChipTraces {
            components,
            traces,
            cpu,
        },
    })
}

/// The preprocessed columns of a device program laid out as `layout`,
/// `code` its kernel's side note (no run needed), at the shape `shape`,
/// `log_sizes`: what its program id's preprocessed root commits. Refused
/// as [`SegmentError::Shape`] when a table (the code, the jump table, the
/// data, a fixed table's entries, [`crate::shape::FIXED_TABLES`]) needs more
/// rows than its chip's log size: a release artifact's sizes are held to
/// them before any column is generated.
pub fn device_preprocessed(
    code: &SideNote,
    layout: &crate::device::DeviceLayout,
    shape: crate::device::DeviceShape,
    log_sizes: &[u32],
) -> Result<Evaluations, SegmentError> {
    let chips = super::DeviceComponents::chips(shape).ok_or(SegmentError::MalformedShape)?;
    if chips.len() != log_sizes.len() {
        return Err(SegmentError::MalformedShape);
    }
    check_transfers(code)?;
    let mut side_note = SideNote::new(Vec::new(), code.code.to_vec(), code.bitmask.to_vec())
        .with_jump_table(code.jump_table.to_vec());
    side_note.device = Some(alloc::sync::Arc::new(crate::device::DeviceRun::empty(
        layout.clone(),
    )));
    use crate::device::device_chip;
    for (&chip, &log_size) in chips.iter().zip(log_sizes) {
        let fixed = crate::shape::FIXED_TABLES
            .iter()
            .find(|&&(table, _)| table == chip)
            .map_or(0, |&(_, least)| u32::from(least));
        let table = match chip {
            device_chip::PROGRAM_MEMORY => crate::chips::program_memory::table_log_size(&side_note),
            device_chip::JUMP_TABLE => crate::chips::jump_table::table_log_size(&side_note),
            device_chip::DATA_TABLE => crate::chips::word_memory::data::table_log_size(&side_note),
            _ => fixed,
        };
        if table > log_size {
            return Err(SegmentError::Shape {
                chip,
                overflow: true,
            });
        }
    }
    Ok(chips
        .iter()
        .zip(log_sizes)
        .flat_map(|(&chip, &log_size)| {
            crate::device_component(chip).generate_preprocessed_trace(log_size, &side_note)
        })
        .collect())
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
        match (self.traces.get(chip), &self.cpu) {
            (None, _) => Vec::new(),
            (Some(trace), Some(cpu)) if chip == 0 => cpu.committed(trace).collect(),
            (Some(trace), _) => trace.original_trace.iter().collect(),
        }
    }

    /// Each chip's main columns, in bit-reversed order, to change: what a
    /// forged trace starts from. The soundness gates' seam alone. A cut
    /// CPU's columns are its full trace's: a change to a cut column reaches
    /// its interaction trace but not its commitment.
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
                let (columns, claimed_sum) = match &self.cpu {
                    Some(cpu) if index == 0 => cpu.interaction_trace(trace, relations),
                    _ => component.generate_interaction_trace(trace, side_note, relations),
                };
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

impl super::DeviceComponents {
    /// The chips' provers, in the set's order.
    pub fn provers(&self) -> Vec<&dyn stwo::prover::ComponentProver<SimdBackend>> {
        self.components
            .iter()
            .map(|component| &**component)
            .collect()
    }
}
