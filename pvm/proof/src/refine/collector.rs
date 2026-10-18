//! The observer that collects a standard Refine invocation's machine
//! slices, their boundaries and their witnesses from its one execution.

use alloc::collections::BTreeMap;
use alloc::string::{String, ToString};
use alloc::sync::Arc;

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

use super::prover::{RefineTraceError, RefineTraceSlice};
use super::*;

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

pub(super) struct Collector {
    outer_program: RefineProgramId,
    active: Option<ActiveSlice>,
    pub(super) slices: Vec<RefineTraceSlice>,
    pub(super) boundaries: Vec<RefineHostBoundary>,
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
        Some(vos_pvm_precompiles::blake2b_256(&bytes))
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

pub(super) fn run_refine_collector(
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
    vos_pvm_precompiles::blake2b_256(&bytes)
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
    vos_pvm_precompiles::blake2b_256(&bytes)
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
    vos_pvm_precompiles::blake2b_256(&bytes)
}

pub(super) fn exit_kind(exit: &ExitReason) -> RefineSliceExit {
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
