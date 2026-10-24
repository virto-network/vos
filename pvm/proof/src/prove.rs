use stwo::{
    core::{
        ColumnVec,
        channel::Channel,
        fields::{m31::BaseField, qm31::SecureField},
    },
    prover::{
        CommitmentSchemeProver, ComponentProver,
        backend::simd::SimdBackend,
        poly::{BitReversedOrder, circle::CircleEvaluation},
    },
};
use stwo_constraint_framework::TraceLocationAllocator;

use stwo::prover::backend::BackendForChannel;

use crate::format::{Format, Status};
use crate::pcs::{FsChannel, PcsStack};

use crate::trace::{
    component::ComponentTrace,
    eval::{ORIGINAL_TRACE_IDX, PREPROCESSED_TRACE_IDX},
};

// prove_impl uses super::active_components(side_note) instead
// of the static BASE_COMPONENTS list to skip dormant chips.
use crate::{lookups::AllLookupElements, side_note::SideNote};

pub use crate::proof::{Proof, SegmentState};

mod canonical;
pub(crate) use canonical::preprocessed_root;
#[cfg(feature = "debug-internals")]
mod debug;
mod profile;
mod shaped;

pub use canonical::{
    canonical_profile_for_bounds, program_commitment_for_profile,
    program_commitment_for_profile_format, prove_canonical, prove_canonical_format, prove_chain,
};
#[cfg(feature = "debug-internals")]
pub use debug::{debug_assert_constraints_explicit, debug_claimed_sums};
pub use profile::ProveProfile;
pub use shaped::{KernelSegment, program_commitment_for_shape, prove_kernel, prove_shaped};

/// Why a proof was not produced.
#[derive(Debug)]
pub enum ProvingError {
    /// Stwo's refusal, or a trace whose constraints cannot hold.
    Stwo(stwo::prover::ProvingError),
    /// The registry does not admit the format, or no stack implements its
    /// channel: the prover produces only what a verifier accepts.
    FormatNotAdmitted(u32),
    /// A sparse memory image without its program's layout: its proof would
    /// carry an identity with every page writable.
    NoMemoryLayout,
    /// Chip `chip` (a [`chip_idx`](crate::chip_idx)) takes log size
    /// `log_size`, not the `pinned` one its shape gives it: its rows need
    /// more, or it is a fixed size other than the shape's.
    Shape {
        chip: usize,
        log_size: u32,
        pinned: u32,
    },
    /// The shape names a chip outside the segment AIR, has a log size more
    /// or fewer than its chips, or lacks the class named.
    MalformedShape,
}

impl ProvingError {
    /// A trace whose constraints cannot hold.
    const NOT_SATISFIED: Self = Self::Stwo(stwo::prover::ProvingError::ConstraintsNotSatisfied);
}

impl From<stwo::prover::ProvingError> for ProvingError {
    fn from(error: stwo::prover::ProvingError) -> Self {
        Self::Stwo(error)
    }
}

impl core::fmt::Display for ProvingError {
    fn fmt(&self, formatter: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        match self {
            Self::Stwo(error) => error.fmt(formatter),
            Self::FormatNotAdmitted(number) => {
                write!(formatter, "the prover does not produce format {number}")
            }
            Self::NoMemoryLayout => {
                formatter.write_str("a sparse memory image without its program's layout")
            }
            Self::Shape {
                chip,
                log_size,
                pinned,
            } => write!(
                formatter,
                "chip {chip} takes log size {log_size}, its shape {pinned}"
            ),
            Self::MalformedShape => formatter.write_str("the shape is not one of the segment AIR"),
        }
    }
}

impl std::error::Error for ProvingError {}

/// Cap rayon's global thread pool at a sensible default for our
/// workload, unless the user has explicitly set `RAYON_NUM_THREADS`
/// or initialised their own pool.  Idempotent — safe to call many
/// times; only the first effective call wins (we use a `OnceLock`
/// guard around `ThreadPoolBuilder::build_global`).
///
/// Past about 10 threads, memory-bandwidth contention overtakes the
/// parallel gains, so the cap is `min(logical_cpus, 10)`: phones (4-8
/// cores) run uncapped.
///
/// Returns the number of threads the pool ended up with.
pub fn install_thread_pool() -> usize {
    use std::sync::OnceLock;
    static INSTALLED: OnceLock<usize> = OnceLock::new();
    *INSTALLED.get_or_init(|| {
        // Honour explicit RAYON_NUM_THREADS — user knows best.
        if std::env::var_os("RAYON_NUM_THREADS").is_some() {
            return rayon::current_num_threads();
        }
        let logical = std::thread::available_parallelism()
            .map(|n| n.get())
            .unwrap_or(1);
        let target = logical.min(10);
        // build_global panics if a pool already exists; ignore that
        // case (e.g., test harness, downstream lib that set its own).
        let _ = rayon::ThreadPoolBuilder::new()
            .num_threads(target)
            .build_global();
        rayon::current_num_threads()
    })
}

/// What the prover produces: an admitted format, at its parameters.
#[derive(Clone, Copy)]
pub(crate) struct Target {
    pub format: &'static Format,
}

impl Target {
    /// The segment format, what the default entry points produce.
    pub const SEGMENT: Self = Self {
        format: &crate::format::SEGMENT,
    };

    /// An admitted format; the prover is told only formats a verifier
    /// accepts.
    pub fn of(format: &'static Format) -> Result<Self, ProvingError> {
        if format.status != Status::Admitted {
            return Err(ProvingError::FormatNotAdmitted(format.number));
        }
        Ok(Self { format })
    }
}

/// Prove under the segment format (35), over the trace's natural shape.
pub fn prove(side_note: &mut SideNote) -> Result<Proof, ProvingError> {
    install_thread_pool();
    let (proof, _) = prove_impl(side_note, Target::SEGMENT, false)?;
    Ok(proof)
}

/// Prove under `format`, at its parameters, over the trace's natural shape;
/// [`ProvingError::FormatNotAdmitted`] on a format the registry does not
/// admit.
pub fn prove_format(
    side_note: &mut SideNote,
    format: &'static Format,
) -> Result<Proof, ProvingError> {
    install_thread_pool();
    let (proof, _) = prove_impl(side_note, Target::of(format)?, false)?;
    Ok(proof)
}

/// [`prove`], with each phase's time and the trace's shape.
pub fn prove_profiled(side_note: &mut SideNote) -> Result<(Proof, ProveProfile), ProvingError> {
    install_thread_pool();
    prove_impl(side_note, Target::SEGMENT, true)
}

/// The entering / exit RAM page-Merkle roots for this segment, from
/// the ingested page payload.  Falls back to the all-zero root only on the
/// never-proved empty path (no payload).
fn segment_memory_roots(side_note: &SideNote) -> ([u8; 32], [u8; 32]) {
    match &side_note.memory_pages {
        Some(p) => (p.multiproof.root_before, p.multiproof.root_after),
        None => ([0u8; 32], [0u8; 32]),
    }
}

/// The blake3 hash of the final memory state: every write applied to the
/// initial memory. O(initial_memory.len() + Σ writes), with a full clone of
/// a dense `initial_memory`.
fn compute_final_memory_commitment(side_note: &SideNote) -> [u8; 32] {
    // Replay ALL of this (segment's) writes — regular stores AND precompile
    // output writes (blake2b's, which live in
    // `blake2b_mem_ops`, not `step.mem_write`) — over the initial memory. Using
    // step writes alone leaves precompile-output bytes stale, so a downstream
    // segment's initial-memory commitment (which DOES reflect those writes,
    // via `segment::replay_writes`) would mismatch and `verify_chain`'s
    // boundary-continuity check would reject. `ts_upper = None` ⇒ all writes.
    if side_note.sparse_initial_memory.is_some() {
        let image = crate::segment::replay_sparse_writes(side_note, None);
        sparse_memory_commitment(&image)
    } else {
        let mem = crate::segment::replay_writes(side_note, None);
        *blake3::hash(&mem).as_bytes()
    }
}

fn initial_memory_commitment(side_note: &SideNote) -> [u8; 32] {
    side_note.sparse_initial_memory.as_ref().map_or_else(
        || *blake3::hash(&side_note.initial_memory).as_bytes(),
        sparse_memory_commitment,
    )
}

fn sparse_memory_commitment(image: &crate::SparseMemoryImage) -> [u8; 32] {
    let mut hasher = blake3::Hasher::new();
    hasher.update(b"vos/pvm/sparse-memory/v1\0");
    hasher.update(&image.span().to_le_bytes());
    hasher.update(&(image.pages().len() as u64).to_le_bytes());
    for page in image.pages() {
        hasher.update(&page.page_index.to_le_bytes());
        hasher.update(&page.bytes);
    }
    *hasher.finalize().as_bytes()
}

/// Normalize a `SideNote` the way the production prove path does before
/// trace generation: activate the closing chip (its rows, the ledger's
/// closing reads and component selection key off it) and backfill the
/// initial/final register images from the trace.
///
/// `prove` applies it itself; calling this twice is idempotent. Verifying
/// needs none of it: `verify` reads only the side note's program and the
/// component set its steps select, and takes the boundary states from the
/// proof, whatever the flag says.
pub fn prepare_side_note_for_verification(side_note: &mut SideNote) {
    // The default path always uses BASE_COMPONENTS which
    // includes `RegisterMemoryClosingChip`. Mark the side_note so the
    // closing chip's rows and the ledger's closing reads engage and
    // `proof.final_state.registers` becomes a load-bearing public
    // output. Chip-isolated callers (`prove_with_explicit_components`)
    // opt-in themselves only if their slice contains the closing chip.
    side_note.closing_chip_active = true;
    backfill_initial_regs(side_note);
    backfill_final_regs(side_note);
}

/// Backfill `initial_regs` from the first step's `regs_before` if the
/// caller left it at the default all-zero but the tracer recorded
/// non-zero initial state (segment slicers set it explicitly).
fn backfill_initial_regs(side_note: &mut SideNote) {
    if !side_note.steps.is_empty() && side_note.initial_regs.iter().all(|&r| r == 0) {
        let first = &side_note.steps[0];
        let n = crate::core::step::NUM_REGS.min(first.regs_before.len());
        side_note.initial_regs[..n].copy_from_slice(&first.regs_before[..n]);
    }
}

/// Backfill `final_regs` from the last step's `regs_after`. Always
/// overwrites (not gated on all-zero like `initial_regs`) so a stale
/// value can never ship as the claimed final state.
fn backfill_final_regs(side_note: &mut SideNote) {
    if !side_note.steps.is_empty() {
        let last = &side_note.steps[side_note.steps.len() - 1];
        let n = crate::core::step::NUM_REGS.min(last.regs_after.len());
        side_note.final_regs = [0u64; crate::core::step::NUM_REGS];
        side_note.final_regs[..n].copy_from_slice(&last.regs_after[..n]);
    }
}

/// Reject memory witnesses that cannot represent a completed PVM memory
/// instruction before any page-boundary construction or trace allocation,
/// and a sparse image without its program's layout.
///
/// A faulting instruction is present in the execution trace so its terminal
/// PC/gas state can be observed, but it performed no memory access. The CPU
/// AIR currently models only completed load/store transitions: opcode-bound
/// flags require the canonical width and the ordinary successor PC. Trying to
/// encode a page fault or low-zone exception as a zero-width access would
/// therefore fail only late in STARK proving. Fail closed here instead.
///
/// Wrapped wide accesses are also outside the current proof contract. The
/// MemoryChip ledger decomposes addresses cyclically for panic-free witness
/// handling, while CpuChip's four-limb lookup has no fifth carry. Reject such
/// hand-built witnesses canonically instead of admitting backend-dependent
/// overflow or an unbalanced lookup.
fn validate_memory_witnesses(side_note: &SideNote) -> Result<(), ProvingError> {
    const ADDRESS_SPACE_SIZE: u64 = 1u64 << 32;

    if side_note.memory_layout().is_none() {
        return Err(ProvingError::NoMemoryLayout);
    }

    for step in &side_note.steps {
        let flags = crate::chips::cpu::classify::classify_opcode(step.opcode);
        let expected_size = if flags.is_mem_size_1 {
            Some(1)
        } else if flags.is_mem_size_2 {
            Some(2)
        } else if flags.is_mem_size_4 {
            Some(4)
        } else if flags.is_mem_size_8 {
            Some(8)
        } else {
            None
        };

        let access = match (flags.is_load, flags.is_store) {
            (true, false) if step.mem_write.is_none() => step.mem_read.as_ref(),
            (false, true) if step.mem_read.is_none() => step.mem_write.as_ref(),
            (false, false) if step.mem_read.is_none() && step.mem_write.is_none() => continue,
            _ => return Err(ProvingError::NOT_SATISFIED),
        };
        let (Some(access), Some(expected_size)) = (access, expected_size) else {
            return Err(ProvingError::NOT_SATISFIED);
        };
        if access.size != expected_size
            || u64::from(access.address) + u64::from(access.size) > ADDRESS_SPACE_SIZE
        {
            return Err(ProvingError::NOT_SATISFIED);
        }
    }
    Ok(())
}

fn prove_impl(
    side_note: &mut SideNote,
    target: Target,
    profile: bool,
) -> Result<(Proof, ProveProfile), ProvingError> {
    prepare_side_note_for_verification(side_note);
    // Filter BASE_COMPONENTS to active chips for THIS trace.
    // Verifier reconstructs the same list via active_components_verifier().
    let components_owned = super::active_components(side_note);
    let components: &[&dyn crate::framework::MachineProverComponent] = &components_owned;
    let component_mask = super::active_component_mask(side_note);
    prove_impl_with_components(side_note, target, profile, components, component_mask, &[])
}

/// Chip-isolated prove path.  Bypasses `active_components` so
/// callers can pick an arbitrary component slice — used by the chip-rewrite
/// validation harness to prove a single high-bound chip + its lookup
/// closure without dragging in always-active CpuChip.  Proofs produced here have
/// `component_mask = 0` and are not verifiable via `verify_standalone`;
/// pair only with `verify_with_explicit_components`.
pub fn prove_with_explicit_components(
    side_note: &mut SideNote,
    components: &[&'static dyn crate::framework::MachineProverComponent],
) -> Result<Proof, ProvingError> {
    install_thread_pool();
    let (proof, _) =
        prove_impl_with_components(side_note, Target::SEGMENT, false, components, 0, &[])?;
    Ok(proof)
}

/// Chip-isolated prove path under an admitted `format`, at its parameters:
/// the chips `component_mask` selects, in chip order, each at least its
/// floor in `min_log_sizes`. The proof carries the mask, so the recursion
/// seams read its shape; like [`prove_with_explicit_components`]'s, it pairs
/// only with `verify_with_explicit_components`, which skips the boundary
/// binding. A measurement seam, not a prove path: behind `debug-internals`.
#[cfg(feature = "debug-internals")]
pub fn prove_chip_isolated_format(
    side_note: &mut SideNote,
    format: &'static Format,
    component_mask: u32,
    min_log_sizes: &[u32],
) -> Result<Proof, ProvingError> {
    install_thread_pool();
    let components: Vec<&dyn crate::framework::MachineProverComponent> =
        crate::chips_of_mask(component_mask)
            .map(|chip| crate::BASE_COMPONENTS[chip])
            .collect();
    let (proof, _) = prove_impl_with_components(
        side_note,
        Target::of(format)?,
        false,
        &components,
        component_mask,
        min_log_sizes,
    )?;
    Ok(proof)
}

fn prove_impl_with_components(
    side_note: &mut SideNote,
    target: Target,
    profile: bool,
    components: &[&dyn crate::framework::MachineProverComponent],
    component_mask: u32,
    min_log_sizes: &[u32],
) -> Result<(Proof, ProveProfile), ProvingError> {
    prove_impl_with_components_overridden(
        side_note,
        target,
        profile,
        components,
        component_mask,
        None,
        Sizes::Floors(min_log_sizes),
    )
}

/// The log sizes a proof's chips take: at least floors (none: natural
/// sizes), or exactly a shape's.
#[derive(Clone, Copy)]
pub(crate) enum Sizes<'a> {
    Floors(&'a [u32]),
    Pinned(&'a [u32]),
}

impl<'a> Sizes<'a> {
    pub(crate) const NATURAL: Sizes<'static> = Sizes::Floors(&[]);

    fn floors(self) -> &'a [u32] {
        match self {
            Self::Floors(sizes) | Self::Pinned(sizes) => sizes,
        }
    }
}

/// The components' main traces: the producers in order, filling the side
/// note's multiplicities, then the consumers in parallel.
fn generate_component_traces(
    side_note: &mut SideNote,
    components: &[&dyn crate::framework::MachineProverComponent],
    min_log_sizes: &[u32],
) -> Vec<ComponentTrace> {
    let mut traces: Vec<Option<ComponentTrace>> = (0..components.len()).map(|_| None).collect();
    for (index, component) in components.iter().enumerate() {
        if component.is_producer() {
            let min_log_size = min_log_sizes.get(index).copied().unwrap_or(0);
            traces[index] = Some(component.generate_component_trace_min(side_note, min_log_size));
        }
    }
    {
        use rayon::prelude::*;
        let consumer_indices: Vec<usize> = components
            .iter()
            .enumerate()
            .filter_map(|(index, component)| (!component.is_producer()).then_some(index))
            .collect();
        let side_note_ref: &SideNote = side_note;
        let consumer_traces: Vec<(usize, ComponentTrace)> = consumer_indices
            .par_iter()
            .map(|&index| {
                let min_log_size = min_log_sizes.get(index).copied().unwrap_or(0);
                (
                    index,
                    components[index]
                        .generate_component_trace_immut_min(side_note_ref, min_log_size),
                )
            })
            .collect();
        for (index, trace) in consumer_traces {
            traces[index] = Some(trace);
        }
    }
    traces
        .into_iter()
        .map(|trace| trace.expect("every component is classified as producer or consumer"))
        .collect()
}

/// The boundary states a proof ships: the sparse-image hashes and the
/// page-Merkle roots the boundary chips bind.
fn derive_segment_states(side_note: &SideNote) -> (SegmentState, SegmentState) {
    let (root_before, root_after) = segment_memory_roots(side_note);
    let initial_state = if side_note.steps.is_empty() {
        SegmentState {
            pc: 0,
            timestamp: 0,
            registers: [0; 13],
            memory_commitment: [0; 32],
            memory_root: root_before,
        }
    } else {
        let first = &side_note.steps[0];
        SegmentState {
            pc: first.pc,
            timestamp: first.timestamp,
            registers: side_note.initial_regs,
            memory_commitment: initial_memory_commitment(side_note),
            memory_root: root_before,
        }
    };
    let final_state = if side_note.steps.is_empty() {
        SegmentState {
            pc: 0,
            timestamp: 0,
            registers: [0; 13],
            memory_commitment: [0; 32],
            memory_root: root_after,
        }
    } else {
        let last = &side_note.steps[side_note.steps.len() - 1];
        let mut registers = [0u64; 13];
        registers[..last.regs_after.len().min(13)]
            .copy_from_slice(&last.regs_after[..13.min(last.regs_after.len())]);
        SegmentState {
            pc: last.next_pc,
            timestamp: last.timestamp + 1,
            registers,
            memory_commitment: compute_final_memory_commitment(side_note),
            memory_root: root_after,
        }
    };
    (initial_state, final_state)
}

/// Prove with caller-supplied boundary metadata in place of the
/// trace-derived `proof.{initial,final}_state`: the chips commit the
/// honest trace columns, but the FS-transcript mix and the shipped
/// metadata fields carry the caller's values instead.
///
/// This reproduces exactly what a from-scratch malicious prover can do —
/// run the whole pipeline with lying boundary metadata that is
/// self-consistent with its own transcript. It exists so the
/// boundary-binding gate test (`tests/gates/boundary_binding.rs`) can assert
/// such proofs are REJECTED by `verify` / `verify_standalone`. It grants
/// no capability an adversary lacks, but it is not part of the supported
/// proving API.
#[doc(hidden)]
pub fn prove_with_boundary_override(
    side_note: &mut SideNote,
    initial_state: SegmentState,
    final_state: SegmentState,
) -> Result<Proof, ProvingError> {
    install_thread_pool();
    prepare_side_note_for_verification(side_note);
    let components_owned = super::active_components(side_note);
    let components: &[&dyn crate::framework::MachineProverComponent] = &components_owned;
    let component_mask = super::active_component_mask(side_note);
    let (proof, _) = prove_impl_with_components_overridden(
        side_note,
        Target::SEGMENT,
        false,
        components,
        component_mask,
        Some((initial_state, final_state)),
        Sizes::NATURAL,
    )?;
    Ok(proof)
}

#[allow(clippy::too_many_arguments)]
fn prove_impl_with_components_overridden(
    side_note: &mut SideNote,
    target: Target,
    profile: bool,
    components: &[&dyn crate::framework::MachineProverComponent],
    component_mask: u32,
    boundary_override: Option<(SegmentState, SegmentState)>,
    sizes: Sizes<'_>,
) -> Result<(Proof, ProveProfile), ProvingError> {
    crate::with_stack!(target.format.channel, Stack => prove_on::<Stack>(
        side_note,
        target,
        profile,
        components,
        component_mask,
        boundary_override,
        sizes,
    ), unbuilt => Err(ProvingError::FormatNotAdmitted(target.format.number)))
}

#[allow(clippy::too_many_arguments)]
fn prove_on<MC: PcsStack>(
    side_note: &mut SideNote,
    target: Target,
    profile: bool,
    components: &[&dyn crate::framework::MachineProverComponent],
    component_mask: u32,
    boundary_override: Option<(SegmentState, SegmentState)>,
    sizes: Sizes<'_>,
) -> Result<(Proof, ProveProfile), ProvingError>
where
    SimdBackend: BackendForChannel<MC>,
{
    use std::time::Instant;
    use stwo::core::proof_of_work::GrindOps;

    let format = target.format;
    let config = format.pcs_config();

    // This must precede memory-page ingestion and every component trace
    // allocation: malformed/fault traces are a caller-boundary error, not an
    // expensive attempt at an unsatisfiable proof.
    validate_memory_witnesses(side_note)?;

    // RegisterMemoryBoundaryChip needs `initial_regs`
    // populated.
    backfill_initial_regs(side_note);

    // Refresh `final_regs` when the closing chip is in the
    // component set, so a caller that constructed the SideNote with
    // stale final_regs can't accidentally produce a proof whose
    // claimed final state diverges from the actual trace's last step.
    // Skipped for chip-isolated harnesses that opted out of the
    // closing chip — those proofs leave `final_regs` untouched (the
    // field is unused without the chip).
    if side_note.closing_chip_active {
        backfill_final_regs(side_note);
    }

    // Build the memory-page Merkle boundary payload (listed pages,
    // entering/exit images, multiproof, merge schedule, `merkle_blake2b_calls`)
    // before trace generation — `MemoryChip` injects the per-page ledger entries
    // from it, `MemoryPageChip` / `MemoryMerkleChip` / `MemoryRootBoundaryChip`
    // produce the leaf/merge/root tuples, and `Blake2bBoundaryChip` proves the
    // compressions.  Prove-path only; idempotent.
    side_note.ingest_memory_pages();

    // Trace gen — split into a sequential *producer* pass and a parallel
    // *consumer* pass.  Producers (CpuChip, Blake2bChip) write per-row
    // multiplicities + entries into `side_note` while filling their main
    // trace; consumer chips (ALU/range/lookup tables, boundary chips,
    // memory ledgers, …) only read those, so they run on
    // rayon with shared `&SideNote`.  Mirrors the producer/consumer
    // split already used by interaction-trace generation a few stages
    // below.
    let t = Instant::now();
    let traces = generate_component_traces(side_note, components, sizes.floors());
    let log_sizes: Vec<u32> = traces.iter().map(ComponentTrace::log_size).collect();
    if let Sizes::Pinned(pinned) = sizes
        && let Some((position, (&log_size, &pinned))) = log_sizes
            .iter()
            .zip(pinned)
            .enumerate()
            .find(|(_, (log_size, pinned))| log_size != pinned)
    {
        let chip = crate::chips_of_mask(component_mask)
            .nth(position)
            .unwrap_or(position);
        return Err(ProvingError::Shape {
            chip,
            log_size,
            pinned,
        });
    }
    let trace_gen = t.elapsed();

    let twiddles = canonical::twiddles_for(components, &log_sizes, &config);

    let prover_channel = &mut MC::C::default();
    crate::proof::mix_statement_header(prover_channel, format.number, &config, &log_sizes);

    let mut commitment_scheme = CommitmentSchemeProver::<SimdBackend, MC>::new(config, &twiddles);
    // Stwo v2.x requires polynomial coefficients to be stored — without
    // this, ComponentProver::get_evaluation_on_domain panics with "The
    // polynomial's coefficients are not stored".  The toggle costs some
    // memory but is the only supported path for our chip shape.
    commitment_scheme.set_store_polynomials_coefficients();

    // Preprocessed trace.
    let t = Instant::now();
    let mut tree_builder = commitment_scheme.tree_builder();
    for component_trace in &traces {
        tree_builder.extend_evals(component_trace.to_circle_evaluation(PREPROCESSED_TRACE_IDX));
    }
    tree_builder.commit(prover_channel);
    let preprocess_commit = t.elapsed();

    // Main trace.
    let t = Instant::now();
    let mut tree_builder = commitment_scheme.tree_builder();
    let mut total_main_columns = 0;
    for component_trace in &traces {
        let evals = component_trace.to_circle_evaluation(ORIGINAL_TRACE_IDX);
        total_main_columns += evals.len();
        tree_builder.extend_evals(evals);
    }
    tree_builder.commit(prover_channel);
    let main_commit = t.elapsed();

    // The shipped boundary states: the trace's, or the forgery seam's.
    // `initial_state.registers` is `side_note.initial_regs`, the field the
    // boundary chip's main trace emits from, so the proof field and the
    // chip's committed values are equal by construction; the memory roots
    // are the entering and exit page-Merkle roots `MemoryRootBoundaryChip`
    // binds.
    let (initial_state, final_state) =
        boundary_override.unwrap_or_else(|| derive_segment_states(side_note));

    // A.1's third and fourth items: the boundary states, then the
    // interaction PoW, before any relation challenge is drawn. A finished
    // proof is so tamper-evident, and the verifier's boundary binding, which
    // recomputes the boundary chips' claimed sums from the shipped states
    // with the drawn challenges, binds them against a from-scratch prover
    // (see `boundary_binding`). Every proof mixes them, chip-isolated
    // harnesses' too, so the verifier replays one transcript prefix.
    crate::proof::mix_boundary_states(prover_channel, &initial_state, &final_state);
    let interaction_pow =
        <SimdBackend as GrindOps<MC::C>>::grind(prover_channel, format.interaction_pow_bits());
    prover_channel.mix_u64(interaction_pow);

    let mut lookup_elements = AllLookupElements::default();
    components.iter().for_each(|c| {
        c.draw_lookup_elements(&mut lookup_elements, prover_channel.as_ref_channel())
    });

    // Interaction trace — parallelize per-chip generation across rayon
    // threads.  Each `generate_interaction_trace` call only borrows
    // `&SideNote` and `&AllLookupElements` immutably and consumes its
    // own owned `ComponentTrace`, so the bodies are independent.  Only
    // `tree_builder.extend_evals` is mutating, so we do that
    // sequentially after the parallel pass.
    let t = Instant::now();
    #[allow(clippy::type_complexity)]
    let interaction_results: Vec<(
        ColumnVec<CircleEvaluation<SimdBackend, BaseField, BitReversedOrder>>,
        SecureField,
    )> = {
        use rayon::prelude::*;
        components
            .par_iter()
            .zip(traces.into_par_iter())
            .map(|(c, component_trace)| {
                c.generate_interaction_trace(component_trace, side_note, &lookup_elements)
            })
            .collect()
    };
    let mut tree_builder = commitment_scheme.tree_builder();
    let mut total_interaction_columns = 0;
    let mut claimed_sums: Vec<SecureField> = Vec::with_capacity(interaction_results.len());
    for (interaction_trace, claimed_sum) in interaction_results {
        total_interaction_columns += interaction_trace.len();
        tree_builder.extend_evals(interaction_trace);
        claimed_sums.push(claimed_sum);
    }
    let interaction_gen = t.elapsed();

    let t = Instant::now();
    prover_channel.mix_felts(&claimed_sums);
    tree_builder.commit(prover_channel);
    let interaction_commit = t.elapsed();

    let tree_span_provider = &mut TraceLocationAllocator::default();
    let components: Vec<Box<dyn ComponentProver<SimdBackend>>> = components
        .iter()
        .zip(&log_sizes)
        .zip(&claimed_sums)
        .map(|((c, log_size), claimed_sum)| {
            c.to_component_prover(
                tree_span_provider,
                &lookup_elements,
                *log_size,
                *claimed_sum,
            )
        })
        .collect();
    let components_ref: Vec<&dyn ComponentProver<SimdBackend>> =
        components.iter().map(|c| &**c).collect();

    let t = Instant::now();
    let proof =
        stwo::prover::prove::<SimdBackend, MC>(&components_ref, prover_channel, commitment_scheme)?;
    let stark_prove = t.elapsed();

    let num_components = components.len();
    let prof = ProveProfile {
        trace_gen,
        preprocess_commit,
        main_commit,
        interaction_gen,
        interaction_commit,
        stark_prove,
        log_sizes: log_sizes.clone(),
        total_main_columns,
        total_interaction_columns,
    };

    // Printed only in a build with `debug-internals`, on the explicit
    // `profile` flag or whenever `ZKPVM_PROFILE` is set in the environment
    // (so the phase breakdown is reachable through paths that hard-code
    // `profile = false`, e.g. `prove_canonical`): a segment's sizes are its
    // step counts. A production build returns the profile to its caller
    // and prints nothing.
    #[cfg(feature = "debug-internals")]
    if profile || std::env::var_os("ZKPVM_PROFILE").is_some() {
        eprintln!("{prof}");
    }
    #[cfg(not(feature = "debug-internals"))]
    let _ = profile;

    // Caller supplies the bitmask (empty for chip-isolated harness).
    Ok((
        Proof {
            format_version: format.number,
            stark_proof: MC::into_any(proof),
            interaction_pow,
            claimed_sums,
            num_components,
            log_sizes,
            component_mask,
            pcs_config: config,
            initial_state,
            final_state,
        },
        prof,
    ))
}
