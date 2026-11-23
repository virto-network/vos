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

use crate::{lookups::AllLookupElements, side_note::SideNote};

pub use crate::proof::{Proof, SegmentState};

pub(crate) mod active;
#[cfg(feature = "debug-internals")]
mod debug;
mod preprocessed;
pub(crate) use preprocessed::preprocessed_root;
pub(crate) mod plan;
mod profile;
mod request;
mod shaped;

#[cfg(feature = "debug-internals")]
pub use debug::debug_assert_constraints_explicit;
pub use plan::{KernelPlan, PlannedSegment, SEGMENT_GAS, max_segments, plan_kernel};
pub use profile::ProveProfile;
pub(crate) use request::{ProveRequest, Sizes};
pub use shaped::{KernelSegment, program_commitment_for_shape, prove_kernel, prove_shaped};

/// Why a proof was not produced.
#[derive(Debug)]
pub enum SegmentError {
    /// Stwo's refusal, or a trace whose constraints cannot hold.
    Stwo(stwo::prover::ProvingError),
    /// The registry does not admit the format, or no stack implements its
    /// channel: the prover produces only what a verifier accepts.
    FormatNotAdmitted(u32),
    /// A sparse memory image without its program's layout: its proof would
    /// carry an identity with every page writable.
    NoMemoryLayout,
    /// Chip `chip` (a [`chip_idx`](crate::chip_idx)) takes another log
    /// size than its shape gives it: its rows need more (`overflow`), or it
    /// is a fixed size other than the shape's. The size it needs, a value
    /// of the run, is not held.
    Shape { chip: usize, overflow: bool },
    /// The shape names a chip outside the segment AIR, has a log size more
    /// or fewer than its chips, or lacks the class named.
    MalformedShape,
    /// The program's code jumps or branches statically to the halt
    /// address: the machine panics there, where a proof would end the run
    /// as a halt.
    Transfer,
    /// The run is longer than [`MAX_RUN_STEPS`]: its ledgers' ordering
    /// deltas would pass their bits. Refused before any trace.
    RunLength,
    /// The run stops at an instruction it does not complete, where no proof
    /// ends a run: a fault, a panic at a static or dynamic transfer, or out
    /// of gas at any instruction but a trap or a host call. The segment AIR
    /// ends a run only at a trap, a host call or a dynamic jump to the halt
    /// address; the stopped instruction's row would claim it executed.
    /// Refused before any trace.
    Stop,
    /// The run takes more segments than its gas buys
    /// ([`max_segments`]): refused before any proof, or once the cuts a
    /// chip's rows force pass it.
    Segments,
}

impl SegmentError {
    /// A trace whose constraints cannot hold.
    const NOT_SATISFIED: Self = Self::Stwo(stwo::prover::ProvingError::ConstraintsNotSatisfied);
}

impl From<stwo::prover::ProvingError> for SegmentError {
    fn from(error: stwo::prover::ProvingError) -> Self {
        Self::Stwo(error)
    }
}

impl core::fmt::Display for SegmentError {
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
                overflow: true,
            } => write!(formatter, "chip {chip} needs more rows than its shape"),
            Self::Shape {
                chip,
                overflow: false,
            } => write!(formatter, "chip {chip} is another size than its shape"),
            Self::MalformedShape => formatter.write_str("the shape is not one of the segment AIR"),
            Self::Transfer => formatter.write_str("the code jumps statically to the halt address"),
            Self::RunLength => {
                formatter.write_str("the run is longer than a proof's ledgers order")
            }
            Self::Stop => formatter.write_str("the run stops where no proof ends a run"),
            Self::Segments => formatter.write_str("the run takes more segments than its gas buys"),
        }
    }
}

impl std::error::Error for SegmentError {}

/// The most steps a run proves, `2^27 − 1`. A ledger orders its rows by the
/// key `2·ts + is_write`, each chain from its `ts = 0` write to its closing
/// read at the run's last timestamp plus one, and range-checks each gap in
/// 28 bits (`ORDER_DELTA_BITS`); timestamps are the run's, from 1. So a run
/// of `n` steps has a gap up to `2(n + 1) − 1`, which fits 28 bits for `n`
/// below `2^27`: an absolute bound on a run's length, whatever its segments.
/// A longer run, or a segment ending past it, is refused
/// ([`SegmentError::RunLength`]) before any trace.
pub const MAX_RUN_STEPS: usize = (1 << 27) - 1;

/// Whether `side_note`'s code holds no static transfer to the halt address
/// ([`SegmentError::Transfer`]), which its pin cannot take.
pub(crate) fn check_transfers(side_note: &SideNote) -> Result<(), SegmentError> {
    if crate::chips::program_memory::jumps_to_halt(&side_note.code, &side_note.bitmask) {
        return Err(SegmentError::Transfer);
    }
    Ok(())
}

/// Whether `side_note`'s run, if it stops, stops where a proof ends a run
/// ([`SegmentError::Stop`]): at a trap, a host call (served or not, paid or
/// not: its row claims no more than the machine's state at the call) or a
/// dynamic jump to the halt address. A step the machine stopped without
/// completing it (a fault, a panic at a transfer, out of gas at any other
/// instruction) leaves its state as it was, which the instruction's row
/// would contradict, or, for a dynamic jump, would look its target up in a
/// jump table that does not hold it. The recorded opcode is trusted: a run
/// reaches only instruction starts, but at its first step, whose pc the
/// caller sets.
pub(crate) fn check_stop(side_note: &SideNote) -> Result<(), SegmentError> {
    use crate::core::opcode::Opcode;
    let Some(step) = side_note.steps.last().filter(|step| step.exit) else {
        return Ok(());
    };
    let ends_run = match step.opcode {
        Opcode::Trap | Opcode::Invalid | Opcode::Ecalli => true,
        Opcode::JumpInd | Opcode::LoadImmJumpInd => {
            u64::from(step.next_pc) == vos_pvm::PVM_HALT_ADDR
        }
        _ => false,
    };
    if !ends_run {
        return Err(SegmentError::Stop);
    }
    Ok(())
}

/// Whether `side_note`'s last step is within [`MAX_RUN_STEPS`] of the run's
/// start: its ledgers' closing reads order within their bits.
pub(crate) fn check_run_length(side_note: &SideNote) -> Result<(), SegmentError> {
    let closing = crate::chips::register_memory_closing::closing_ts_for(side_note);
    if closing > MAX_RUN_STEPS as u64 + 1 {
        return Err(SegmentError::RunLength);
    }
    Ok(())
}

/// Cap rayon's global thread pool at a sensible default for our
/// workload, unless the user has explicitly set `RAYON_NUM_THREADS`, and
/// give its workers 16 MiB of stack. Idempotent: only the first call
/// builds it. When another user built the global pool first, its stacks
/// are theirs (rayon's default 2 MiB, at which a release prover's worker
/// overflows): the prover then proves on a pool of its own
/// ([`on_prover_pool`]), and this reports it.
///
/// Past about 10 threads, memory-bandwidth contention overtakes the
/// parallel gains, so the cap is `min(logical_cpus, 10)`: phones (4-8
/// cores) run uncapped.
///
/// Returns the number of threads the prover's pool has.
pub fn install_thread_pool() -> usize {
    prover_pool().map_or_else(
        rayon::current_num_threads,
        rayon::ThreadPool::current_num_threads,
    )
}

/// The prover's own pool, when the global one is not the prover's: `None`
/// when [`install_thread_pool`]'s build of the global pool took.
fn prover_pool() -> Option<&'static rayon::ThreadPool> {
    use std::sync::OnceLock;
    static OWN: OnceLock<Option<rayon::ThreadPool>> = OnceLock::new();
    OWN.get_or_init(|| {
        // Honour explicit RAYON_NUM_THREADS — user knows best: zero
        // threads is the builder's own reading of it.
        let threads = if std::env::var_os("RAYON_NUM_THREADS").is_some() {
            0
        } else {
            let logical = std::thread::available_parallelism()
                .map(|n| n.get())
                .unwrap_or(1);
            logical.min(10)
        };
        let builder = || {
            rayon::ThreadPoolBuilder::new()
                .num_threads(threads)
                .stack_size(WORKER_STACK)
        };
        match builder().build_global() {
            Ok(()) => None,
            Err(_) => Some(
                builder()
                    .thread_name(|index| format!("vos-prover-{index}"))
                    .build()
                    .expect("the prover's pool"),
            ),
        }
    })
    .as_ref()
}

/// `work` on a pool whose workers have the prover's 16 MiB stacks: on the
/// caller's own pool when it is on one (a caller that pools its threads
/// sizes their stacks, as the light node's prover does), else on the
/// global pool when it is the prover's ([`install_thread_pool`]), else on
/// the prover's own. Every proving entry point runs its work so.
pub fn on_prover_pool<R: Send>(work: impl FnOnce() -> R + Send) -> R {
    if rayon::current_thread_index().is_some() {
        return work();
    }
    match prover_pool() {
        Some(pool) => pool.install(work),
        None => work(),
    }
}

/// A prover worker's stack: 16 MiB, as a worker blocked in a `join` runs
/// the tasks it steals on its own stack, so its depth grows with the
/// nesting; at the platform's default 2 MiB a release prover's worker can
/// overflow it. Reserved, not committed: a worker touches only the pages
/// it uses.
const WORKER_STACK: usize = 16 << 20;

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
    pub fn of(format: &'static Format) -> Result<Self, SegmentError> {
        if format.status != Status::Admitted {
            return Err(SegmentError::FormatNotAdmitted(format.number));
        }
        Ok(Self { format })
    }
}

/// Prove under the segment format (41), over the trace's natural shape.
pub fn prove(side_note: &mut SideNote) -> Result<Proof, SegmentError> {
    install_thread_pool();
    let (proof, _) = prove_impl(side_note, Target::SEGMENT, false)?;
    Ok(proof)
}

/// Prove under `format`, at its parameters, over the trace's natural shape;
/// [`SegmentError::FormatNotAdmitted`] on a format the registry does not
/// admit.
pub fn prove_format(
    side_note: &mut SideNote,
    format: &'static Format,
) -> Result<Proof, SegmentError> {
    install_thread_pool();
    let (proof, _) = prove_impl(side_note, Target::of(format)?, false)?;
    Ok(proof)
}

/// [`prove`], with each phase's time and the trace's shape.
pub fn prove_profiled(side_note: &mut SideNote) -> Result<(Proof, ProveProfile), SegmentError> {
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
pub(crate) fn backfill_initial_regs(side_note: &mut SideNote) {
    if !side_note.steps.is_empty() && side_note.initial_regs.iter().all(|&r| r == 0) {
        let first = &side_note.steps[0];
        let n = crate::core::step::NUM_REGS.min(first.regs_before.len());
        side_note.initial_regs[..n].copy_from_slice(&first.regs_before[..n]);
    }
}

/// Backfill `final_regs` from the last step's `regs_after`. Always
/// overwrites (not gated on all-zero like `initial_regs`) so a stale
/// value can never ship as the claimed final state.
pub(crate) fn backfill_final_regs(side_note: &mut SideNote) {
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
pub(crate) fn validate_memory_witnesses(side_note: &SideNote) -> Result<(), SegmentError> {
    const ADDRESS_SPACE_SIZE: u64 = 1u64 << 32;

    if side_note.memory_layout().is_none() {
        return Err(SegmentError::NoMemoryLayout);
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
            _ => return Err(SegmentError::NOT_SATISFIED),
        };
        let (Some(access), Some(expected_size)) = (access, expected_size) else {
            return Err(SegmentError::NOT_SATISFIED);
        };
        if access.size != expected_size
            || u64::from(access.address) + u64::from(access.size) > ADDRESS_SPACE_SIZE
        {
            return Err(SegmentError::NOT_SATISFIED);
        }
    }
    Ok(())
}

fn prove_impl(
    side_note: &mut SideNote,
    target: Target,
    profile: bool,
) -> Result<(Proof, ProveProfile), SegmentError> {
    prepare_side_note_for_verification(side_note);
    // Filter BASE_COMPONENTS to active chips for THIS trace.
    // The verifier reconstructs the same list from the proof's component mask.
    let components_owned = super::active_components(side_note);
    let components: &[&dyn crate::framework::MachineProverComponent] = &components_owned;
    let component_mask = super::active_component_mask(side_note);
    prove_with(
        side_note,
        ProveRequest {
            profile,
            ..ProveRequest::new(target, components, component_mask, Sizes::NATURAL)
        },
    )
}

/// Chip-isolated prove path.  Bypasses `active_components` so
/// callers can pick an arbitrary component slice — used by the chip-rewrite
/// validation harness to prove a single high-bound chip + its lookup
/// closure without dragging in always-active CpuChip.  Proofs produced here have
/// `component_mask = 0` and are not verifiable via `verify_standalone`;
/// pair only with `verify_with_explicit_components`. A test seam
/// (`chip-isolated`).
#[cfg(feature = "chip-isolated")]
pub fn prove_with_explicit_components(
    side_note: &mut SideNote,
    components: &[&'static dyn crate::framework::MachineProverComponent],
) -> Result<Proof, SegmentError> {
    install_thread_pool();
    let request = ProveRequest::new(Target::SEGMENT, components, 0, Sizes::NATURAL);
    let (proof, _) = prove_with(side_note, request)?;
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
) -> Result<Proof, SegmentError> {
    install_thread_pool();
    let components: Vec<&dyn crate::framework::MachineProverComponent> =
        crate::chips_of_mask(component_mask)
            .map(|chip| crate::BASE_COMPONENTS[chip])
            .collect();
    let request = ProveRequest::new(
        Target::of(format)?,
        &components,
        component_mask,
        Sizes::Floors(min_log_sizes),
    );
    let (proof, _) = prove_with(side_note, request)?;
    Ok(proof)
}

/// The components' main traces: the producers in order, filling the side
/// note's multiplicities, then the consumers in parallel. With `pinned`, each
/// at exactly its size in `min_log_sizes`: the position and log size of the
/// first producer of another size are returned as soon as it is traced,
/// before any later chip's; a consumer's is the caller's to compare.
pub(crate) fn generate_component_traces(
    side_note: &mut SideNote,
    components: &[&dyn crate::framework::MachineProverComponent],
    min_log_sizes: &[u32],
    pinned: bool,
) -> Result<Vec<ComponentTrace>, (usize, u32)> {
    let mut traces: Vec<Option<ComponentTrace>> = (0..components.len()).map(|_| None).collect();
    for (index, component) in components.iter().enumerate() {
        if component.is_producer() {
            let min_log_size = min_log_sizes.get(index).copied().unwrap_or(0);
            let trace = component.generate_component_trace_min(side_note, min_log_size);
            if pinned && trace.log_size() != min_log_size {
                return Err((index, trace.log_size()));
            }
            traces[index] = Some(trace);
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
    Ok(traces
        .into_iter()
        .map(|trace| trace.expect("every component is classified as producer or consumer"))
        .collect())
}

/// Whether `side_note`'s steps fit a CPU of `log_size`, a row a step: what a
/// pinned trace checks before any chip is traced.
pub(crate) fn steps_fit(side_note: &SideNote, log_size: u32) -> bool {
    crate::trace::utils::ceil_log2_at_least_lanes(side_note.num_steps()) <= log_size
}

/// The boundary states a proof ships, with the page-Merkle roots the
/// boundary chips bind.
pub(crate) fn derive_segment_states(side_note: &SideNote) -> (SegmentState, SegmentState) {
    let (root_before, root_after) = segment_memory_roots(side_note);
    let initial_state = if side_note.steps.is_empty() {
        SegmentState {
            pc: 0,
            timestamp: 0,
            registers: [0; 13],
            memory_root: root_before,
        }
    } else {
        let first = &side_note.steps[0];
        SegmentState {
            pc: first.pc,
            timestamp: first.timestamp,
            registers: side_note.initial_regs,
            memory_root: root_before,
        }
    };
    let final_state = if side_note.steps.is_empty() {
        SegmentState {
            pc: 0,
            timestamp: 0,
            registers: [0; 13],
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
/// proving API: a test seam (`chip-isolated`).
#[cfg(feature = "chip-isolated")]
pub fn prove_with_boundary_override(
    side_note: &mut SideNote,
    initial_state: SegmentState,
    final_state: SegmentState,
) -> Result<Proof, SegmentError> {
    install_thread_pool();
    prepare_side_note_for_verification(side_note);
    let components_owned = super::active_components(side_note);
    let components: &[&dyn crate::framework::MachineProverComponent] = &components_owned;
    let component_mask = super::active_component_mask(side_note);
    let request = ProveRequest {
        boundary_override: Some((initial_state, final_state)),
        ..ProveRequest::new(Target::SEGMENT, components, component_mask, Sizes::NATURAL)
    };
    let (proof, _) = prove_with(side_note, request)?;
    Ok(proof)
}

/// Makes `request`'s proof on its format's channel.
pub(crate) fn prove_with(
    side_note: &mut SideNote,
    request: ProveRequest<'_>,
) -> Result<(Proof, ProveProfile), SegmentError> {
    let format = request.target.format;
    on_prover_pool(|| {
        crate::with_stack!(format.channel, Stack => prove_on::<Stack>(side_note, request),
            unbuilt => Err(SegmentError::FormatNotAdmitted(format.number)))
    })
}

fn prove_on<MC: PcsStack>(
    side_note: &mut SideNote,
    request: ProveRequest<'_>,
) -> Result<(Proof, ProveProfile), SegmentError>
where
    SimdBackend: BackendForChannel<MC>,
{
    let ProveRequest {
        target,
        components,
        component_mask,
        sizes,
        profile,
        boundary_override,
    } = request;
    use std::time::Instant;
    use stwo::core::proof_of_work::GrindOps;

    let format = target.format;
    let config = format.pcs_config();

    prepare(side_note)?;

    let t = Instant::now();
    let pinned = matches!(sizes, Sizes::Pinned(_));
    let refusal = |position: usize, overflow: bool| SegmentError::Shape {
        chip: crate::chips_of_mask(component_mask)
            .nth(position)
            .unwrap_or(position),
        overflow,
    };
    // The CPU is the first chip of a mask holding it, a row a step.
    if pinned
        && component_mask & 1 << crate::chip_idx::CPU != 0
        && !steps_fit(side_note, sizes.floors().first().copied().unwrap_or(0))
    {
        return Err(refusal(0, true));
    }
    let traces = generate_component_traces(side_note, components, sizes.floors(), pinned).map_err(
        |(position, log_size)| {
            let pinned = sizes.floors().get(position).copied().unwrap_or(0);
            refusal(position, log_size > pinned)
        },
    )?;
    let log_sizes = traced_sizes(&traces, sizes, component_mask)?;
    let trace_gen = t.elapsed();

    let twiddles = preprocessed::twiddles_for(components, &log_sizes, &config);

    let prover_channel = &mut MC::C::default();
    crate::format::mix_statement_header(prover_channel, format.number, &config, &log_sizes);

    let mut commitment_scheme = CommitmentSchemeProver::<SimdBackend, MC>::new(config, &twiddles);
    // Stwo v2.x requires polynomial coefficients to be stored — without
    // this, ComponentProver::get_evaluation_on_domain panics with "The
    // polynomial's coefficients are not stored".  The toggle costs some
    // memory but is the only supported path for our chip shape.
    commitment_scheme.set_store_polynomials_coefficients();

    let t = Instant::now();
    commit_trees(
        &mut commitment_scheme,
        prover_channel,
        &traces,
        PREPROCESSED_TRACE_IDX,
    );
    let preprocess_commit = t.elapsed();

    let t = Instant::now();
    let total_main_columns = commit_trees(
        &mut commitment_scheme,
        prover_channel,
        &traces,
        ORIGINAL_TRACE_IDX,
    );
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
                c.generate_interaction_trace(&component_trace, side_note, &lookup_elements)
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
    // `profile` flag or whenever `VOS_PROOF_PROFILE` is set in the
    // environment (so the phase breakdown is reachable through paths that
    // hard-code `profile = false`, e.g. `prove_shaped`): a segment's
    // sizes are its step counts. A production build returns the profile to
    // its caller and prints nothing.
    #[cfg(feature = "debug-internals")]
    if profile || std::env::var_os("VOS_PROOF_PROFILE").is_some() {
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

/// What a proof needs of `side_note` before its traces: its length within
/// [`MAX_RUN_STEPS`], no static transfer to the halt address, its stop
/// where a proof ends a run, its memory witnesses checked (a malformed or
/// stopped trace is the caller's error, not an expensive attempt at an
/// unsatisfiable proof), its boundary registers filled, and its memory
/// pages' Merkle payload built.
fn prepare(side_note: &mut SideNote) -> Result<(), SegmentError> {
    check_run_length(side_note)?;
    check_transfers(side_note)?;
    check_stop(side_note)?;
    validate_memory_witnesses(side_note)?;
    // RegisterMemoryBoundaryChip needs `initial_regs` populated.
    backfill_initial_regs(side_note);
    // Refresh `final_regs` when the closing chip is in the component set,
    // so a caller that constructed the SideNote with stale final_regs can't
    // produce a proof whose claimed final state diverges from the trace's
    // last step. Chip-isolated harnesses without the closing chip leave
    // `final_regs` untouched (the field is unused without the chip).
    if side_note.closing_chip_active {
        backfill_final_regs(side_note);
    }
    // The memory-page Merkle boundary payload (listed pages, entering and
    // exit images, multiproof, merge schedule, `merkle_blake2b_calls`),
    // before trace generation: `MemoryChip` injects the per-page ledger
    // entries from it, `MemoryPageChip`, `MemoryMerkleChip` and
    // `MemoryRootBoundaryChip` produce the leaf, merge and root tuples, and
    // `Blake2bBoundaryChip` proves the compressions. Idempotent.
    side_note.ingest_memory_pages();
    Ok(())
}

/// The traces' log sizes, each the shape's when `sizes` pins them.
fn traced_sizes(
    traces: &[ComponentTrace],
    sizes: Sizes<'_>,
    component_mask: u32,
) -> Result<Vec<u32>, SegmentError> {
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
        return Err(SegmentError::Shape {
            chip,
            overflow: log_size > pinned,
        });
    }
    Ok(log_sizes)
}

/// Commit the traces' columns of tree `tree`, in the components' order:
/// how many there are.
fn commit_trees<MC: PcsStack>(
    commitment_scheme: &mut CommitmentSchemeProver<'_, SimdBackend, MC>,
    channel: &mut MC::C,
    traces: &[ComponentTrace],
    tree: usize,
) -> usize
where
    SimdBackend: BackendForChannel<MC>,
{
    let mut tree_builder = commitment_scheme.tree_builder();
    let mut columns = 0;
    for component_trace in traces {
        let evals = component_trace.to_circle_evaluation(tree);
        columns += evals.len();
        tree_builder.extend_evals(evals);
    }
    tree_builder.commit(channel);
    columns
}

#[cfg(test)]
mod tests {
    use super::*;
    use vos_pvm::instruction::Opcode;

    /// A code whose jump lands on the halt address, which the program
    /// memory's pin cannot take, is refused before any trace or pin; one
    /// jumping elsewhere is not refused for it.
    #[test]
    fn a_static_jump_to_the_halt_address_is_refused() {
        let jump = |target: u32| {
            let mut code = vec![Opcode::Jump as u8];
            code.extend_from_slice(&target.to_le_bytes());
            code.push(Opcode::Trap as u8);
            SideNote::new(Vec::new(), code, vec![1, 0, 0, 0, 0, 1])
        };
        let mut halt = jump(vos_pvm::PVM_HALT_ADDR as u32);
        assert!(matches!(
            check_transfers(&halt),
            Err(SegmentError::Transfer)
        ));
        assert!(matches!(prove(&mut halt), Err(SegmentError::Transfer)));
        let shape = crate::shape::ProofShape {
            components: crate::chip_idx::ALWAYS,
            log_sizes: vec![16; crate::chip_idx::ALWAYS.count_ones() as usize],
        };
        assert!(program_commitment_for_shape(&halt, &shape, &crate::format::SEGMENT).is_none());
        assert!(check_transfers(&jump(5)).is_ok());
    }
}
