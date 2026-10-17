use alloc::collections::BTreeMap;
use alloc::string::{String, ToString};
use alloc::sync::Arc;

use crate::prove::ProvingError;
use vos_pvm::args;
use vos_pvm::inner::InnerMachineIdentity;
use vos_pvm::instruction::Opcode;
use vos_pvm::interpreter::{InstructionObservation, Interpreter};
use vos_pvm::refine::MemoryModel;
use vos_pvm::refine_host::{
    RefineContext, RefineHostPhase, RefineMachineIdentity, RefineObservation,
};
use vos_pvm::{ExitReason, Gas, PVM_REGISTER_COUNT};

use crate::SideNote;
use crate::core::step::PvmStep;
use crate::core::tracing::{
    compute_skip, decode_branch_target, decode_imm_y, decode_immediate, decode_mem_access,
    decode_reg_indices,
};

use super::*;

/// Directly observed (not re-executed) witness for one machine slice.
pub struct RefineTraceSlice {
    pub order: u32,
    pub identity: RefineMachineId,
    pub entry_state: [u8; 32],
    pub observed_exit_state: [u8; 32],
    pub exit: RefineSliceExit,
    pub side_note: SideNote,
}

/// Traced closure produced by the sole `RefineContext` interpreter run.
pub struct RefineTraceBundle {
    pub outer_program: RefineProgramId,
    pub arguments_commitment: [u8; 32],
    pub gas_limit: u64,
    pub slices: Vec<RefineTraceSlice>,
    pub host_boundaries: Vec<RefineHostBoundary>,
    pub result: RefineSliceExit,
}

/// Exact output and public-I/O registers captured with one observed trace.
///
/// Construction succeeds only for a normal halt whose complete output
/// window is readable and no larger than the caller's ceiling. The trace,
/// bytes, and register commitment therefore always describe the same sole
/// interpreter run; a caller cannot accidentally pair a proved trace with
/// output recovered by a second execution.
pub struct RefineObservedRun {
    pub trace: RefineTraceBundle,
    pub output: Vec<u8>,
    pub public_io: [u8; 32],
}

#[derive(Debug)]
pub enum RefineTraceError {
    Load(vos_pvm::refine::RefineError),
    Observation(String),
    OutputUnavailable,
    Prove(ProvingError),
    ReplayMismatch(&'static str),
    Verify(String),
}

impl core::fmt::Display for RefineTraceError {
    fn fmt(&self, formatter: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        match self {
            Self::Load(error) => write!(formatter, "cannot load Refine program: {error}"),
            Self::Observation(error) => {
                write!(formatter, "invalid Refine observation: {error}")
            }
            Self::OutputUnavailable => formatter.write_str(
                "Refine did not halt with a readable output inside the configured ceiling",
            ),
            Self::Prove(error) => write!(formatter, "cannot prove Refine slice: {error}"),
            Self::ReplayMismatch(field) => {
                write!(formatter, "Refine replay differs at {field}")
            }
            Self::Verify(error) => write!(formatter, "Refine child proof failed: {error}"),
        }
    }
}

impl std::error::Error for RefineTraceError {}

impl From<vos_pvm::refine::RefineError> for RefineTraceError {
    fn from(error: vos_pvm::refine::RefineError) -> Self {
        Self::Load(error)
    }
}

struct ActiveSlice {
    identity: RefineMachineId,
    entry_state: [u8; 32],
    initial_memory: crate::SparseMemoryImage,
    code: Arc<[u8]>,
    bitmask: Arc<[u8]>,
    jump_table: Arc<[u32]>,
    program_location: ProgramLocation,
    initial_regs: [u64; PVM_REGISTER_COUNT],
    last_regs: [u64; PVM_REGISTER_COUNT],
    next_timestamp: u64,
    steps: Vec<PvmStep>,
    blake2b_calls: Vec<crate::chips::blake2b::Blake2bCall>,
    blake2b_mem_ops: Vec<crate::core::tracing::Blake2bMemOp>,
}

#[derive(Clone)]
struct ProgramStatic {
    code: Arc<[u8]>,
    bitmask: Arc<[u8]>,
    jump_table: Arc<[u32]>,
}

#[derive(Clone, Copy)]
struct CachedInnerProgram {
    id: RefineProgramId,
    allocation: (usize, usize),
}

/// Cheap continuity token for interpreter-owned immutable program data.
/// RefineContext never mutates these vectors after loading; comparing
/// their allocations and lengths on every observation avoids an
/// O(instructions × program-size) byte comparison. Executed opcodes and
/// decoded semantics are still checked against the shared snapshot.
#[derive(Clone, Copy)]
struct ProgramLocation {
    code: (usize, usize),
    bitmask: (usize, usize),
    jump_table: (usize, usize),
}

impl ProgramLocation {
    fn of(machine: &Interpreter) -> Self {
        Self {
            code: (machine.code.as_ptr() as usize, machine.code.len()),
            bitmask: (machine.bitmask.as_ptr() as usize, machine.bitmask.len()),
            jump_table: (
                machine.jump_table.as_ptr() as usize,
                machine.jump_table.len(),
            ),
        }
    }

    fn matches(self, machine: &Interpreter) -> bool {
        self.code == (machine.code.as_ptr() as usize, machine.code.len())
            && self.bitmask == (machine.bitmask.as_ptr() as usize, machine.bitmask.len())
            && self.jump_table
                == (
                    machine.jump_table.as_ptr() as usize,
                    machine.jump_table.len(),
                )
    }
}

struct MachineStateCache {
    value_revision: u64,
    value_commitment: [u8; 32],
    value_image: crate::SparseMemoryImage,
    permission_revision: u64,
    permission_commitment: [u8; 32],
}

struct PendingBoundary {
    call: u8,
    slices_before: u32,
    state_before: [u8; 32],
    registers_before: [u64; 13],
}

struct Collector {
    outer_program: RefineProgramId,
    active: Option<ActiveSlice>,
    slices: Vec<RefineTraceSlice>,
    boundaries: Vec<RefineHostBoundary>,
    pending_boundary: Option<PendingBoundary>,
    timestamps: BTreeMap<RefineMachineIdentity, u64>,
    inner_programs: BTreeMap<InnerMachineIdentity, CachedInnerProgram>,
    program_statics: BTreeMap<RefineProgramId, ProgramStatic>,
    machine_state_cache: BTreeMap<RefineMachineId, MachineStateCache>,
    #[cfg(test)]
    full_value_scans: usize,
    #[cfg(test)]
    full_permission_scans: usize,
    #[cfg(test)]
    static_program_copies: usize,
    #[cfg(test)]
    program_identity_hashes: usize,
    #[cfg(test)]
    static_location_checks: usize,
    error: Option<String>,
}

impl Collector {
    fn new(outer_program: RefineProgramId) -> Self {
        Self {
            outer_program,
            active: None,
            slices: Vec::new(),
            boundaries: Vec::new(),
            pending_boundary: None,
            timestamps: BTreeMap::new(),
            inner_programs: BTreeMap::new(),
            program_statics: BTreeMap::new(),
            machine_state_cache: BTreeMap::new(),
            #[cfg(test)]
            full_value_scans: 0,
            #[cfg(test)]
            full_permission_scans: 0,
            #[cfg(test)]
            static_program_copies: 0,
            #[cfg(test)]
            program_identity_hashes: 0,
            #[cfg(test)]
            static_location_checks: 0,
            error: None,
        }
    }

    fn fail(&mut self, message: impl Into<String>) {
        if self.error.is_none() {
            self.error = Some(message.into());
        }
    }

    fn update_programs(&mut self, inner: &vos_pvm::inner::InnerMachines) {
        for view in inner.views() {
            let allocation = (view.program.as_ptr() as usize, view.program.len());
            match self.inner_programs.get(&view.identity) {
                Some(cached) if cached.allocation != allocation => {
                    self.fail("an installed inner program changed allocation or length");
                    return;
                }
                Some(_) => {}
                None => {
                    self.inner_programs.insert(
                        view.identity,
                        CachedInnerProgram {
                            id: refine_program_id(view.program),
                            allocation,
                        },
                    );
                    #[cfg(test)]
                    {
                        self.program_identity_hashes += 1;
                    }
                }
            }
        }
    }

    fn machine_id(&self, identity: RefineMachineIdentity) -> Option<RefineMachineId> {
        match identity {
            RefineMachineIdentity::Outer => Some(RefineMachineId::Outer {
                program: self.outer_program,
            }),
            RefineMachineIdentity::Inner(identity) => self
                .inner_programs
                .get(&identity)
                .copied()
                .map(|program| RefineMachineId::Inner {
                    slot: identity.slot,
                    generation: identity.generation,
                    program: program.id,
                }),
        }
    }

    fn program_static(
        &mut self,
        identity: RefineMachineId,
        machine: &Interpreter,
    ) -> ProgramStatic {
        self.program_statics
            .entry(identity.program())
            .or_insert_with(|| {
                #[cfg(test)]
                {
                    self.static_program_copies += 1;
                }
                ProgramStatic {
                    code: Arc::clone(&machine.code),
                    bitmask: Arc::clone(&machine.bitmask),
                    jump_table: Arc::clone(&machine.jump_table),
                }
            })
            .clone()
    }

    fn update_machine_cache(&mut self, identity: RefineMachineId, machine: &Interpreter) {
        let memory = machine.memory();
        let value_revision = memory.value_revision();
        let permission_revision = memory.permissions_revision();
        let value_changed = self
            .machine_state_cache
            .get(&identity)
            .is_none_or(|cache| cache.value_revision != value_revision);
        let permissions_changed = self
            .machine_state_cache
            .get(&identity)
            .is_none_or(|cache| cache.permission_revision != permission_revision);

        if value_changed {
            let image: crate::SparseMemoryImage = memory.nonzero_page_image().into();
            let value_commitment = sparse_value_commitment(&image);
            #[cfg(test)]
            {
                self.full_value_scans += 1;
            }
            match self.machine_state_cache.get_mut(&identity) {
                Some(cache) => {
                    cache.value_revision = value_revision;
                    cache.value_commitment = value_commitment;
                    cache.value_image = image;
                }
                None => {
                    let permission_commitment = permission_commitment(memory);
                    #[cfg(test)]
                    {
                        self.full_permission_scans += 1;
                    }
                    self.machine_state_cache.insert(
                        identity,
                        MachineStateCache {
                            value_revision,
                            value_commitment,
                            value_image: image,
                            permission_revision,
                            permission_commitment,
                        },
                    );
                    return;
                }
            }
        }

        if permissions_changed {
            let commitment = permission_commitment(memory);
            #[cfg(test)]
            {
                self.full_permission_scans += 1;
            }
            let cache = self
                .machine_state_cache
                .get_mut(&identity)
                .expect("value cache is installed above");
            cache.permission_revision = permission_revision;
            cache.permission_commitment = commitment;
        }
    }

    fn machine_state_commitment(
        &mut self,
        identity: RefineMachineId,
        machine: &Interpreter,
    ) -> [u8; 32] {
        self.update_machine_cache(identity, machine);
        let cache = self
            .machine_state_cache
            .get(&identity)
            .expect("machine cache was installed above");
        architectural_state_commitment(
            machine,
            identity.program(),
            cache.value_commitment,
            cache.permission_commitment,
        )
    }

    fn memory_image(
        &mut self,
        identity: RefineMachineId,
        machine: &Interpreter,
    ) -> crate::SparseMemoryImage {
        self.update_machine_cache(identity, machine);
        self.machine_state_cache
            .get(&identity)
            .expect("machine cache was installed above")
            .value_image
            .clone()
    }

    fn context_state_commitment(
        &mut self,
        outer: &Interpreter,
        inner: &vos_pvm::inner::InnerMachines,
    ) -> Option<[u8; 32]> {
        let outer_identity = RefineMachineId::Outer {
            program: self.outer_program,
        };
        let outer_commitment = self.machine_state_commitment(outer_identity, outer);
        let views = inner.views().collect::<Vec<_>>();
        let mut machine_commitments = Vec::with_capacity(views.len());
        for view in &views {
            let program = self.inner_programs.get(&view.identity)?.id;
            let identity = RefineMachineId::Inner {
                slot: view.identity.slot,
                generation: view.identity.generation,
                program,
            };
            let commitment = view
                .machine
                .map(|machine| self.machine_state_commitment(identity, machine));
            machine_commitments.push((view.identity, program, view.initial_pc, commitment));
        }

        let mut bytes = Vec::new();
        bytes.extend_from_slice(b"vos/pvm/refine-context-state/v2\0");
        bytes.extend_from_slice(&outer_commitment);
        put_u64(&mut bytes, inner.next_generation());
        put_u32(&mut bytes, machine_commitments.len() as u32);
        for (identity, program, initial_pc, commitment) in machine_commitments {
            put_u32(&mut bytes, identity.slot);
            put_u64(&mut bytes, identity.generation);
            bytes.extend_from_slice(&program.0);
            put_u32(&mut bytes, initial_pc);
            match commitment {
                Some(commitment) => {
                    bytes.push(1);
                    bytes.extend_from_slice(&commitment);
                }
                None => bytes.push(0),
            }
        }
        Some(crate::page_merkle::blake2b256(&bytes))
    }

    fn observe(&mut self, event: RefineObservation<'_>) {
        if self.error.is_some() {
            return;
        }
        match event {
            RefineObservation::MachineEnter { identity, machine } => {
                if self.active.is_some() {
                    self.fail("machine entered while another slice is active");
                    return;
                }
                if !machine.memory().is_sparse() {
                    self.fail("Refine proof tracing requires sparse memory");
                    return;
                }
                let Some(bundle_identity) = self.machine_id(identity) else {
                    self.fail("inner machine entered without an installed program identity");
                    return;
                };
                let program = self.program_static(bundle_identity, machine);
                let timestamp = self.timestamps.get(&identity).copied().unwrap_or(1);
                let entry_state = self.machine_state_commitment(bundle_identity, machine);
                let initial_memory = self.memory_image(bundle_identity, machine);
                self.active = Some(ActiveSlice {
                    identity: bundle_identity,
                    entry_state,
                    initial_memory,
                    code: program.code,
                    bitmask: program.bitmask,
                    jump_table: program.jump_table,
                    program_location: ProgramLocation::of(machine),
                    initial_regs: machine.registers,
                    last_regs: machine.registers,
                    next_timestamp: timestamp,
                    steps: Vec::new(),
                    blake2b_calls: Vec::new(),
                    blake2b_mem_ops: Vec::new(),
                });
            }
            RefineObservation::Instruction {
                identity,
                instruction,
            } => {
                #[cfg(test)]
                {
                    self.static_location_checks += 1;
                }
                let Some(expected) = self.machine_id(identity) else {
                    self.fail("instruction has no machine program identity");
                    return;
                };
                let Some(active) = self.active.as_mut() else {
                    self.fail("instruction observed outside a machine slice");
                    return;
                };
                if active.identity != expected {
                    self.fail("instruction machine identity differs from active slice");
                    return;
                }
                match observed_step(active, &instruction) {
                    Ok(step) => {
                        active.last_regs = step.regs_after;
                        active.next_timestamp += 1;
                        active.steps.push(step);
                    }
                    Err(error) => self.fail(error),
                }
            }
            RefineObservation::Precompile { identity, call } => {
                let Some(expected) = self.machine_id(identity) else {
                    self.fail("precompile has no machine program identity");
                    return;
                };
                let Some(active) = self.active.as_mut() else {
                    self.fail("precompile observed outside a machine slice");
                    return;
                };
                if active.identity != expected {
                    self.fail("precompile machine identity differs from active slice");
                    return;
                }
                // The cause is the slice's last row: an ECALLI recorded as a
                // host exit. The proof runtime acknowledges it and the row
                // continues at the successor, as `TracingPvm` does.
                let Some(step) = active.steps.last_mut() else {
                    self.fail("precompile without a cause instruction");
                    return;
                };
                if step.opcode != Opcode::Ecalli || !step.exit {
                    self.fail("precompile cause is not an ECALLI host exit");
                    return;
                }
                let vos_pvm::precompile::PrecompileCall::Blake2bCompress {
                    h_ptr,
                    m_ptr,
                    h,
                    m,
                    t,
                    f,
                    h_bytes,
                    m_bytes,
                    out_bytes,
                } = call.clone();
                step.next_pc = step.pc.wrapping_add(1).wrapping_add(step.skip_len);
                step.host_call_acknowledged = true;
                let ts = step.timestamp;
                active
                    .blake2b_calls
                    .push(crate::chips::blake2b::Blake2bCall { h, m, t, f });
                active
                    .blake2b_mem_ops
                    .push(crate::core::tracing::Blake2bMemOp {
                        h_ptr,
                        m_ptr,
                        ts,
                        h_bytes,
                        m_bytes,
                        out_bytes,
                    });
            }
            RefineObservation::MachineExit {
                identity,
                exit,
                machine,
            } => {
                let Some(expected) = self.machine_id(identity) else {
                    self.fail("machine exit has no program identity");
                    return;
                };
                let Some(active) = self.active.take() else {
                    self.fail("machine exited without an active slice");
                    return;
                };
                if active.identity != expected
                    || active.steps.is_empty()
                    || !active.program_location.matches(machine)
                {
                    self.fail("machine exit identity/trace does not match active slice");
                    return;
                }
                if self.slices.len() >= MAX_REFINE_PROOF_SLICES {
                    self.fail("Refine machine-slice limit exceeded");
                    return;
                }
                self.timestamps.insert(identity, active.next_timestamp);
                // A refine machine's permissions are any runs of pages its
                // program sets, committed in its state, not four regions;
                // its slice proofs bind the exact replayed trace, whose
                // machine faults where the program's pages forbid.
                let mut side_note = SideNote::new_shared(active.steps, active.code, active.bitmask)
                    .with_shared_jump_table(active.jump_table)
                    .with_initial_regs(active.initial_regs)
                    .with_sparse_memory(active.initial_memory)
                    .with_memory_layout(crate::chips::memory_page::MemoryLayout::writable());
                side_note.blake2b_calls = active.blake2b_calls;
                side_note.blake2b_mem_ops = active.blake2b_mem_ops;
                let observed_exit_state = self.machine_state_commitment(active.identity, machine);
                self.slices.push(RefineTraceSlice {
                    order: self.slices.len() as u32,
                    identity: active.identity,
                    entry_state: active.entry_state,
                    observed_exit_state,
                    exit: exit_kind(&exit),
                    side_note,
                });
            }
            RefineObservation::HostCall {
                phase,
                id,
                outer,
                inner,
            } => {
                self.update_programs(inner);
                if self.error.is_some() {
                    return;
                }
                let Ok(call) = u8::try_from(id) else {
                    self.fail("host boundary identifier exceeds u8");
                    return;
                };
                if !(9..=14).contains(&call) {
                    self.fail("observed non-standard Refine host boundary");
                    return;
                }
                let Some(state) = self.context_state_commitment(outer.interpreter(), inner) else {
                    self.fail("inner dictionary has no cached program identity");
                    return;
                };
                match phase {
                    RefineHostPhase::Before => {
                        if self.boundaries.len() >= MAX_REFINE_HOST_BOUNDARIES {
                            self.fail("Refine host-boundary limit exceeded");
                            return;
                        }
                        if self.pending_boundary.is_some() {
                            self.fail("nested Before host boundary");
                            return;
                        }
                        self.pending_boundary = Some(PendingBoundary {
                            call,
                            slices_before: self.slices.len() as u32,
                            state_before: state,
                            registers_before: *outer.registers(),
                        });
                    }
                    RefineHostPhase::After => {
                        let Some(before) = self.pending_boundary.take() else {
                            self.fail("After host boundary without Before");
                            return;
                        };
                        if before.call != call {
                            self.fail("host Before/After identifiers differ");
                            return;
                        }
                        self.boundaries.push(RefineHostBoundary {
                            call,
                            slices_before: before.slices_before,
                            slices_after: self.slices.len() as u32,
                            state_before: before.state_before,
                            state_after: state,
                            registers_before: before.registers_before,
                            registers_after: *outer.registers(),
                        });
                    }
                }
            }
        }
    }
}

#[cfg(test)]
#[derive(Clone, Copy, Debug)]
pub(super) struct CollectorMetrics {
    pub full_value_scans: usize,
    pub full_permission_scans: usize,
    pub static_program_copies: usize,
    pub program_identity_hashes: usize,
    pub static_location_checks: usize,
}

fn run_refine_collector(
    outer_program: &[u8],
    args: &[u8],
    gas: Gas,
) -> Result<(Collector, vos_pvm::refine::Invocation), RefineTraceError> {
    let outer_id = refine_program_id(outer_program);
    let context = RefineContext::load_with(outer_program, args, gas, MemoryModel::Sparse)?;
    let mut collector = Collector::new(outer_id);
    let invocation = context.run_observed(|event| collector.observe(event));
    if let Some(error) = collector.error.take() {
        return Err(RefineTraceError::Observation(error));
    }
    if collector.active.is_some() || collector.pending_boundary.is_some() {
        return Err(RefineTraceError::Observation(
            "unterminated machine or host boundary".to_string(),
        ));
    }
    Ok((collector, invocation))
}

#[cfg(test)]
pub(super) fn collector_metrics_for(
    outer_program: &[u8],
    args: &[u8],
    gas: Gas,
) -> Result<CollectorMetrics, RefineTraceError> {
    let (collector, _) = run_refine_collector(outer_program, args, gas)?;
    Ok(CollectorMetrics {
        full_value_scans: collector.full_value_scans,
        full_permission_scans: collector.full_permission_scans,
        static_program_copies: collector.static_program_copies,
        program_identity_hashes: collector.program_identity_hashes,
        static_location_checks: collector.static_location_checks,
    })
}

/// Execute and trace a complete standard Refine invocation once.
///
/// `MemoryModel::Sparse` is forced even on 64-bit hosts. Every witness row
/// comes from `InstructionObservation` emitted by that sole execution.
pub fn trace_refine(
    outer_program: &[u8],
    args: &[u8],
    gas: Gas,
) -> Result<RefineTraceBundle, RefineTraceError> {
    let outer_id = refine_program_id(outer_program);
    let (collector, invocation) = run_refine_collector(outer_program, args, gas)?;
    Ok(RefineTraceBundle {
        outer_program: outer_id,
        arguments_commitment: refine_arguments_commitment(args),
        gas_limit: gas,
        slices: collector.slices,
        host_boundaries: collector.boundaries,
        result: exit_kind(&invocation.exit),
    })
}

/// Execute and trace one complete standard Refine invocation, returning
/// the exact halted output from that same observed run.
///
/// The guest-controlled output length is rejected before allocation when
/// it exceeds `maximum_output_bytes`.
///
/// `None` means the invocation did not reach a normal halt with a fully
/// readable, bounded output window. Callers must reject it when a
/// canonical output is required; no second unobserved execution is needed
/// to recover the tentative transition.
pub fn trace_refine_with_output(
    outer_program: &[u8],
    args: &[u8],
    gas: Gas,
    maximum_output_bytes: usize,
) -> Result<(RefineTraceBundle, Option<Vec<u8>>), RefineTraceError> {
    let outer_id = refine_program_id(outer_program);
    let (collector, invocation) = run_refine_collector(outer_program, args, gas)?;
    let output = invocation.output_bounded(maximum_output_bytes);
    Ok((
        RefineTraceBundle {
            outer_program: outer_id,
            arguments_commitment: refine_arguments_commitment(args),
            gas_limit: gas,
            slices: collector.slices,
            host_boundaries: collector.boundaries,
            result: exit_kind(&invocation.exit),
        },
        output,
    ))
}

/// Execute and trace one complete standard Refine invocation exactly
/// once, requiring its bounded halted output and public-I/O registers.
///
/// This is the production preparation seam for a tentative transition.
/// Output length and readability are validated by
/// [`vos_pvm::refine::Invocation::output_bounded`] before allocation.
pub fn trace_refine_observed(
    outer_program: &[u8],
    args: &[u8],
    gas: Gas,
    maximum_output_bytes: usize,
) -> Result<RefineObservedRun, RefineTraceError> {
    let outer_id = refine_program_id(outer_program);
    let (collector, invocation) = run_refine_collector(outer_program, args, gas)?;
    let output = invocation
        .output_bounded(maximum_output_bytes)
        .ok_or(RefineTraceError::OutputUnavailable)?;
    let public_io = crate::proof::public_io_hash_from_registers(&invocation.registers);
    Ok(RefineObservedRun {
        trace: RefineTraceBundle {
            outer_program: outer_id,
            arguments_commitment: refine_arguments_commitment(args),
            gas_limit: gas,
            slices: collector.slices,
            host_boundaries: collector.boundaries,
            result: exit_kind(&invocation.exit),
        },
        output,
        public_io,
    })
}

/// Pre-proof commitment to the exact execution metadata observed in a
/// [`RefineTraceBundle`]. This equals
/// [`refine_bundle_execution_commitment`] for the proof produced from the
/// trace.
pub fn refine_trace_execution_commitment(trace: &RefineTraceBundle) -> [u8; 32] {
    refine_execution_commitment(
        trace.outer_program,
        trace.arguments_commitment,
        trace.gas_limit,
        trace.result,
        trace.slices.len(),
        trace.slices.iter().map(|slice| RefineExecutionSlice {
            order: slice.order,
            identity: slice.identity,
            entry_state: slice.entry_state,
            observed_exit_state: slice.observed_exit_state,
            exit: slice.exit,
        }),
        &trace.host_boundaries,
    )
}

/// Prove every directly observed machine slice and authenticate the
/// complete boundary transcript.
pub fn prove_refine(trace: RefineTraceBundle) -> Result<RefineProofBundle, RefineTraceError> {
    if trace.slices.is_empty()
        || trace.slices.len() > MAX_REFINE_PROOF_SLICES
        || trace.host_boundaries.len() > MAX_REFINE_HOST_BOUNDARIES
        || trace.host_boundaries.len() > trace.slices.len()
    {
        return Err(RefineTraceError::Observation(
            "Refine closure cardinality is noncanonical".to_string(),
        ));
    }
    let mut slices = Vec::with_capacity(trace.slices.len());
    let mut child_proof_bytes = 0usize;
    for mut slice in trace.slices {
        let proof = crate::prove(&mut slice.side_note).map_err(RefineTraceError::Prove)?;
        if proof.log_sizes.len() > MAX_REFINE_CHILD_COMPONENTS
            || proof.claimed_sums.len() > MAX_REFINE_CHILD_COMPONENTS
            || proof.num_components > MAX_REFINE_CHILD_COMPONENTS
            || proof.stark_proof.commitment_count() != REFINE_CHILD_COMMITMENT_COUNT
        {
            return Err(RefineTraceError::Observation(format!(
                "Refine child proof cardinality is noncanonical: logs={}, sums={}, components={}, commitments={}",
                proof.log_sizes.len(),
                proof.claimed_sums.len(),
                proof.num_components,
                proof.stark_proof.commitment_count(),
            )));
        }
        let proof_bytes = crate::proof::proof_owned_bytes(&proof).ok_or_else(|| {
            RefineTraceError::Observation(
                "Refine child proof exceeds the per-proof payload bound".to_string(),
            )
        })?;
        child_proof_bytes = child_proof_bytes
            .checked_add(proof_bytes)
            .filter(|&total| total <= MAX_REFINE_CHILD_PROOF_BYTES)
            .ok_or_else(|| {
                RefineTraceError::Observation(
                    "Refine child-proof aggregate payload limit exceeded".to_string(),
                )
            })?;
        slices.push(RefineProofSlice {
            order: slice.order,
            identity: slice.identity,
            entry_state: slice.entry_state,
            observed_exit_state: slice.observed_exit_state,
            exit: slice.exit,
            proof,
        });
    }
    let mut bundle = RefineProofBundle {
        format_version: REFINE_BUNDLE_FORMAT_VERSION,
        outer_program: trace.outer_program,
        arguments_commitment: trace.arguments_commitment,
        gas_limit: trace.gas_limit,
        slices,
        host_boundaries: trace.host_boundaries,
        result: trace.result,
        transcript_commitment: [0; 32],
    };
    bundle.transcript_commitment = refine_bundle_commitment(&bundle);
    Ok(bundle)
}

/// Close the native-host semantic boundary by replaying exact committed
/// inputs and verifying every child proof against the newly observed
/// program/slice side note.
pub fn verify_refine_bundle_replayed(
    bundle: &RefineProofBundle,
    outer_program: &[u8],
    args: &[u8],
    gas: Gas,
) -> Result<(), RefineTraceError> {
    if !refine_bundle_cardinality_is_valid(bundle) {
        return Err(RefineTraceError::ReplayMismatch("bundle cardinality"));
    }
    if bundle.format_version != REFINE_BUNDLE_FORMAT_VERSION {
        return Err(RefineTraceError::ReplayMismatch("bundle format version"));
    }
    if refine_program_id(outer_program) != bundle.outer_program {
        return Err(RefineTraceError::ReplayMismatch("outer program identity"));
    }
    if refine_arguments_commitment(args) != bundle.arguments_commitment || gas != bundle.gas_limit {
        return Err(RefineTraceError::ReplayMismatch("arguments/gas"));
    }
    if refine_bundle_commitment(bundle) != bundle.transcript_commitment {
        return Err(RefineTraceError::ReplayMismatch("transcript commitment"));
    }
    // Reject hostile PCS amplification before deterministic replay or any
    // prover-side commitment constructor. The final child verifier repeats
    // these policy checks after exact trace binding.
    for slice in &bundle.slices {
        crate::proof::check_min_security(&slice.proof.pcs_config)
            .map_err(|_| RefineTraceError::ReplayMismatch("child PCS security"))?;
        if slice.proof.pcs_config.fri_config.log_blowup_factor
            > crate::proof::MAX_RECOMMIT_LOG_BLOWUP
        {
            return Err(RefineTraceError::ReplayMismatch(
                "child PCS recommitment amplification",
            ));
        }
    }
    let trace = trace_refine(outer_program, args, gas)?;
    if trace.outer_program != bundle.outer_program {
        return Err(RefineTraceError::ReplayMismatch("outer program"));
    }
    if trace.arguments_commitment != bundle.arguments_commitment
        || trace.gas_limit != bundle.gas_limit
    {
        return Err(RefineTraceError::ReplayMismatch("invocation inputs"));
    }
    if trace.host_boundaries != bundle.host_boundaries {
        return Err(RefineTraceError::ReplayMismatch("host boundaries"));
    }
    if trace.result != bundle.result || trace.slices.len() != bundle.slices.len() {
        return Err(RefineTraceError::ReplayMismatch("slice/result shape"));
    }
    for (observed, proven) in trace.slices.iter().zip(&bundle.slices) {
        if observed.order != proven.order
            || observed.identity != proven.identity
            || observed.entry_state != proven.entry_state
            || observed.observed_exit_state != proven.observed_exit_state
            || observed.exit != proven.exit
        {
            return Err(RefineTraceError::ReplayMismatch("machine slice"));
        }
    }
    for (mut observed, proven) in trace.slices.into_iter().zip(&bundle.slices) {
        let mut child = proven.proof.clone();
        let format =
            crate::proof::preflight_proof_structure(&mut child, crate::DEFAULT_MAX_LOG_SIZE)
                .map_err(|_| RefineTraceError::ReplayMismatch("child proof structure"))?;
        let target = crate::prove::Target {
            format,
            config: child.pcs_config,
        };
        let binding = crate::prove::replay_trace_binding(&mut observed.side_note, target)
            .map_err(RefineTraceError::Prove)?;
        if child.component_mask != binding.component_mask
            || child.num_components != binding.log_sizes.len()
            || child.log_sizes != binding.log_sizes
            || child.stark_proof.commitment(0) != Some(binding.preprocessed_commitment)
            || child.stark_proof.commitment(1) != Some(binding.main_commitment)
            || child.initial_state != binding.initial_state
            || child.final_state != binding.final_state
        {
            return Err(RefineTraceError::ReplayMismatch(
                "child proof does not bind exact replay trace",
            ));
        }
        crate::verify(child, &observed.side_note)
            .map_err(|error| RefineTraceError::Verify(error.to_string()))?;
    }
    Ok(())
}

fn observed_step(
    active: &ActiveSlice,
    observation: &InstructionObservation<'_>,
) -> Result<PvmStep, String> {
    let machine = observation.machine_after;
    if !active.program_location.matches(machine) || observation.registers_before != active.last_regs
    {
        return Err("instruction observation changed static program or continuity".to_string());
    }
    let opcode_byte = active
        .code
        .get(observation.pc_before as usize)
        .copied()
        .unwrap_or(0);
    if opcode_byte != observation.opcode_byte {
        return Err("instruction observation opcode differs from program".to_string());
    }
    let opcode = Opcode::from_byte(opcode_byte).unwrap_or(Opcode::Trap);
    let skip_len = compute_skip(&active.bitmask, observation.pc_before as usize);
    let decoded = args::decode_args(
        &active.code,
        observation.pc_before as usize,
        skip_len as usize,
        opcode.category(),
    );
    let (reg_a, reg_b, reg_d) = decode_reg_indices(opcode, &decoded);
    let regs_after = machine.registers;
    let reg_write = crate::core::tracing::recorded_write(
        opcode,
        (reg_a, reg_b, reg_d),
        &observation.registers_before,
        &regs_after,
        observation.exit,
    )?;
    let gas_charged = if observation.need_gas_charge_before {
        observation
            .gas_before
            .checked_sub(machine.gas)
            .ok_or_else(|| "instruction increased gas".to_string())?
    } else {
        0
    };
    let sequential_next_pc = observation.pc_before.wrapping_add(1).wrapping_add(skip_len);
    let exited = observation.exit.is_some();
    let (mem_read, mem_write) = if exited {
        (None, None)
    } else {
        decode_mem_access(opcode, &decoded, &observation.registers_before, &regs_after)
    };
    Ok(PvmStep {
        timestamp: active.next_timestamp,
        pc: observation.pc_before,
        opcode,
        skip_len,
        regs_before: observation.registers_before,
        regs_after,
        reg_write,
        reg_a,
        reg_b,
        reg_d,
        imm: decode_immediate(&decoded),
        imm_y: decode_imm_y(&decoded),
        branch_target: decode_branch_target(&decoded),
        branch_taken: !exited && machine.pc != sequential_next_pc,
        mem_read,
        mem_write,
        gas_after: machine.gas,
        gas_charged,
        // A halting step continues at the halt address, as the tracer
        // records it.
        next_pc: if observation.exit == Some(&ExitReason::Halt) {
            vos_pvm::PVM_HALT_ADDR as u32
        } else {
            machine.pc
        },
        host_call_acknowledged: false,
        witness: None,
        exit: exited,
    })
}

fn sparse_value_commitment(image: &crate::SparseMemoryImage) -> [u8; 32] {
    let mut bytes = Vec::new();
    bytes.extend_from_slice(b"vos/pvm/refine-memory-values/v1\0");
    put_u64(&mut bytes, image.span());
    put_u32(&mut bytes, image.pages().len() as u32);
    for page in image.pages() {
        put_u32(&mut bytes, page.page_index);
        bytes.extend_from_slice(&page.bytes);
    }
    crate::page_merkle::blake2b256(&bytes)
}

/// Commits the permission map through its canonical maximal runs, so the
/// cost follows the map's permission changes rather than its span.
fn permission_commitment(memory: &vos_pvm::interpreter::Memory) -> [u8; 32] {
    let runs = memory.permission_runs();
    let mut bytes = Vec::new();
    bytes.extend_from_slice(b"vos/pvm/refine-memory-permissions/v2\0");
    put_u64(&mut bytes, memory.pages() as u64);
    put_u64(&mut bytes, runs.len() as u64);
    for (_, count, permission) in runs {
        put_u64(&mut bytes, count as u64);
        bytes.push(permission);
    }
    crate::page_merkle::blake2b256(&bytes)
}

fn architectural_state_commitment(
    machine: &Interpreter,
    program: RefineProgramId,
    value_commitment: [u8; 32],
    permission_commitment: [u8; 32],
) -> [u8; 32] {
    let mut bytes = Vec::new();
    bytes.extend_from_slice(b"vos/pvm/refine-machine-state/v3\0");
    // Collector hashes each exact canonical program blob once per
    // installed identity. The ID transitively binds decoded code,
    // bitmask, and jump table without re-hashing MiB-scale static bytes at
    // every native host boundary.
    bytes.extend_from_slice(&program.0);
    put_u32(&mut bytes, machine.pc);
    put_u64(&mut bytes, machine.gas);
    for &register in &machine.registers {
        put_u64(&mut bytes, register);
    }
    bytes.push(machine.gas_charged as u8);
    bytes.push(machine.need_gas_charge as u8);
    match machine.pending_host_call() {
        Some(call) => {
            bytes.push(1);
            put_u64(&mut bytes, call.id);
            put_u32(&mut bytes, call.cause_pc);
            put_u32(&mut bytes, call.resume_pc);
        }
        None => bytes.push(0),
    }
    bytes.extend_from_slice(&value_commitment);
    bytes.extend_from_slice(&permission_commitment);
    crate::page_merkle::blake2b256(&bytes)
}

fn exit_kind(exit: &ExitReason) -> RefineSliceExit {
    match exit {
        ExitReason::Halt => RefineSliceExit::Halt,
        ExitReason::Panic => RefineSliceExit::Panic,
        ExitReason::OutOfGas => RefineSliceExit::OutOfGas,
        ExitReason::PageFault(address) => RefineSliceExit::PageFault(*address),
        ExitReason::HostCall(call) => RefineSliceExit::HostCall(*call),
    }
}

#[cfg(test)]
mod cache_tests {
    use super::*;
    use vos_pvm::interpreter::Memory;

    fn machine() -> Interpreter {
        Interpreter::with_memory(
            vec![50, 0],
            vec![1, 0],
            Vec::new(),
            [0; PVM_REGISTER_COUNT],
            Memory::sparse(vos_pvm::PVM_PAGE_SIZE as u64),
            10_000,
        )
    }

    #[test]
    fn unchanged_63_machine_1024_boundary_scan_cost_is_revision_bounded() {
        let program = RefineProgramId([7; 32]);
        let mut collector = Collector::new(program);
        let mut machines = (0..63).map(|_| machine()).collect::<Vec<_>>();

        for boundary in 0..1_024 {
            for (slot, machine) in machines.iter().enumerate() {
                let identity = RefineMachineId::Inner {
                    slot: slot as u32,
                    generation: slot as u64,
                    program,
                };
                let commitment = collector.machine_state_commitment(identity, machine);
                if boundary == 0 {
                    assert_ne!(commitment, [0; 32]);
                }
            }
        }
        assert_eq!(collector.full_value_scans, 63);
        assert_eq!(collector.full_permission_scans, 63);

        machines[0].memory_mut().write_u8(0, 1).unwrap();
        let identity = RefineMachineId::Inner {
            slot: 0,
            generation: 0,
            program,
        };
        collector.machine_state_commitment(identity, &machines[0]);
        assert_eq!(collector.full_value_scans, 64);
        assert_eq!(collector.full_permission_scans, 63);

        assert!(
            machines[0]
                .memory_mut()
                .set_page_range(0, 1, vos_pvm::interpreter::PERM_NONE)
        );
        collector.machine_state_commitment(identity, &machines[0]);
        assert_eq!(collector.full_value_scans, 64);
        assert_eq!(collector.full_permission_scans, 64);
    }

    #[test]
    fn context_commitment_binds_next_generation_with_no_live_slots() {
        let program = RefineProgramId([9; 32]);
        let outer = machine();
        let mut collector = Collector::new(program);
        let empty = vos_pvm::inner::InnerMachines::new();
        let before = collector
            .context_state_commitment(&outer, &empty)
            .expect("empty context commits");

        let mut cycled = vos_pvm::inner::InnerMachines::new();
        let id = cycled
            .create(&[0, 1, 3, 10, 42, 0, 0b0000_0101], 0)
            .expect("valid compact program");
        cycled.expunge(id).expect("live slot expunges");
        assert!(cycled.is_empty());
        assert_eq!(cycled.next_generation(), 1);
        let after = collector
            .context_state_commitment(&outer, &cycled)
            .expect("cycled empty context commits");
        assert_ne!(before, after);
    }
}
