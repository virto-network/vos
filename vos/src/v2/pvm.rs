//! Local driver for the protocol-pinned generic VOS service PVM.
//!
//! This is a conformance boundary, not a native implementation of Refine.
//! The transition bytes are produced by the service program itself. During
//! Refine the host surface is read-only and persistent JAM protocol calls are
//! rejected before a handler can observe them.

use alloc::collections::{BTreeMap, BTreeSet};
use alloc::vec::Vec;

use javm::cap::{Access, CallableCap, Cap, DataCap, ProtocolCap};
use javm::kernel::{
    DispatchResult, DormantProgram, InvocationKernel, KernelInstructionObservation, KernelResult,
};
use javm::program::{CapEntryType, cap_data, parse_blob, parse_code_blob};
use javm::snapshot::KernelSnapshot;
use javm::vm_pool::VmState;

use super::{
    ACCUMULATE_ENTRY_IC, ACTOR_EFFECT_BATCH_MAX_BYTES, ACTOR_IPC_BASE_PAGE, ACTOR_IPC_CAP_SLOT,
    ACTOR_PRIVATE_INPUT_MAX_BYTES, AccumulatedRoleAssertionV2, AccumulationResultV2,
    ActorEffectBatchV2, ActorPrivateInputV2, ActorSliceInputV2, ActorSliceOutputV2,
    ActorStorageKeyV2, ActorTreeImportV2, AuthorizationEvidenceV2, AwaitResumeV2, BlobRefV2,
    CheckpointTokenV2, ContinuationSnapshotV2, CrdtChangeV2, CrdtDispatchV2, Hash, ImportedBlobV2,
    MAX_ROOT_TREE_ACTORS, Origin, ProgramId, REFINE_ENTRY_IC, RefineImportsV2, RoleCredentialV2,
    TARGET_ACTOR_HANDLE_SLOT, V2Wire, WorkEnvelopeV2,
};

const MAX_ACTOR_IPC_PAGES: u32 = 1024;
const MIN_ACTOR_OUTPUT_HEADROOM: usize = super::MAX_ATTESTATION_PROOF_BYTES;
const MAX_PRODUCER_RECORDS_PER_SLICE: usize = 16;
const MAX_PRODUCER_RECORD_BYTES_PER_SLICE: usize = 1024 * 1024;
const RESULT_WHAT: u64 = u64::MAX - 1;
const ACTOR_STACK_OBJECT_CAP: u64 = 65;

/// Canonical generic-service argument window. Refine inputs and guest-owned
/// Accumulate requests may contain a complete continuation or CRDT batch, so
/// the infrastructure PVM deliberately opts into more than the transpiler's
/// one-page application default while retaining the standard slot-0 DATA ABI.
pub const SERVICE_ARGUMENT_PAGES_V2: u32 = 2048;

/// Transpile the protocol infrastructure ELF with the v2 standard argument
/// window. Application actor ELFs continue to use `grey_transpiler::link_elf`.
pub fn transpile_service_elf(elf: &[u8]) -> Result<Vec<u8>, grey_transpiler::TranspileError> {
    grey_transpiler::link_elf_with_argument_pages(elf, SERVICE_ARGUMENT_PAGES_V2)
}

/// Result of one completed service-PVM execution slice.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ServicePvmOutputV2 {
    pub bytes: Vec<u8>,
    pub gas_used: u64,
    /// Content-addressed artifacts produced purely during Refine. Callers must
    /// make these bytes available before submitting the transition to
    /// Accumulate; publication still occurs only after commit.
    pub exported_blobs: Vec<ImportedBlobV2>,
    /// Producer-private Task records captured while Refine executed. These
    /// bytes are host output, never part of the service transition or a Raft
    /// request. The root driver must make them durable locally before it may
    /// propose the corresponding transition.
    pub producer_records: Vec<ProducedProvableRecordV2>,
    /// Exact canonical-interpreter commitment for a traced Refine slice.
    /// Ordinary Refine and every Accumulate execution leave this absent.
    pub trace: Option<RefineTraceV2>,
}

/// One completed provable Task record owned by the physical producer which
/// executed Refine. `tag` is scoped by the parent actor; the entry contains
/// the exact secret witness and therefore must never enter replicated state.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ProducedProvableRecordV2 {
    pub actor: super::ActorId,
    pub tag: [u8; 32],
    pub entry: crate::provable::ProofRecordEntry,
}

/// Compact commitment to one complete nested Refine execution slice.
///
/// The commitment follows every service and actor instruction across JAR
/// CALL/REPLY VM switches and binds host protocol-call requests and injected
/// results. A prover can reproduce the full witness by replaying the canonical
/// work/import bytes under the pinned execution-semantics identifier.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RefineTraceV2 {
    pub commitment: Hash,
    pub instruction_count: u64,
    pub protocol_call_count: u64,
    pub vm_switch_count: u64,
    /// Canonical JAR CODE-sub-blob hashes observed during this slice.
    pub code_hashes: Vec<Hash>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ServicePvmErrorV2 {
    InvalidProgram,
    /// Local allocation or JIT setup failed before guest execution began.
    /// Replaying on this or another replica may succeed, so Raft must not
    /// classify the entry as a deterministic guest no-op.
    KernelResourceUnavailable,
    ProgramIdMismatch,
    InvalidServiceEntries,
    InvalidActorCapabilityLayout,
    Panic {
        vm: u16,
        pc: u32,
    },
    OutOfGas {
        vm: u16,
        pc: u32,
    },
    PageFault {
        vm: u16,
        address: u32,
    },
    UnreadableOutput,
    ForbiddenRefineProtocolCall(u8),
    RefineHostRejected(u8),
    AccumulateHostRejected(u8),
    AccumulateCommitRejected,
    InvalidAccumulateOutput,
    InvalidProtocolResume,
    TraceBackendRequired,
    InvalidWorkEnvelope,
    InvalidRefineImports,
    InvalidAuthorization,
    TooManyImportedActors,
    InvalidContinuation,
    ContinuationMismatch,
    SnapshotFailed,
    CheckpointTokenWriteFailed,
    ActorInputTooLarge,
    ActorIpcExhausted,
    ActorIpcSetupFailed,
    /// Speculative Refine discovered actor-local point reads which must be
    /// authenticated against the work base before execution is restarted.
    ActorStorageWitnessRequired(Vec<ActorStorageKeyV2>),
    InvalidVmLifecycle,
}

struct RefineTraceRecorderV2 {
    state: blake2b_simd::State,
    instruction_count: u64,
    protocol_call_count: u64,
    vm_switch_count: u64,
    previous_vm: Option<u16>,
    code_hashes: BTreeSet<[u8; 32]>,
}

impl RefineTraceRecorderV2 {
    fn new(service_program: ProgramId, work: &WorkEnvelopeV2, imports: &RefineImportsV2) -> Self {
        let mut recorder = Self {
            state: blake2b_simd::Params::new().hash_length(32).to_state(),
            instruction_count: 0,
            protocol_call_count: 0,
            vm_switch_count: 0,
            previous_vm: None,
            code_hashes: BTreeSet::new(),
        };
        recorder.bytes(b"vos/refine-trace/v2");
        recorder.bytes(&super::EXECUTION_SEMANTICS_ID.0);
        recorder.bytes(&service_program.0);
        recorder.bytes(&work.hash().0);
        recorder.bytes(&Hash::digest(b"vos/refine-imports/v2", &[&imports.encode()]).0);
        recorder
    }

    fn instruction(&mut self, event: KernelInstructionObservation<'_>) {
        self.state.update(&[0]);
        self.u64(self.instruction_count);
        self.instruction_count = self.instruction_count.saturating_add(1);
        if self.previous_vm != Some(event.active_vm) {
            if self.previous_vm.is_some() {
                self.vm_switch_count = self.vm_switch_count.saturating_add(1);
            }
            self.previous_vm = Some(event.active_vm);
        }
        self.code_hashes.insert(event.program_hash);
        self.u16(event.active_vm);
        self.u16(event.code_cap_id);
        self.bytes(&event.program_hash);
        self.u64(event.call_depth as u64);
        self.u32(event.instruction.pc_before);
        self.state.update(&[event.instruction.opcode_byte]);
        for register in event.instruction.registers_before {
            self.u64(register);
        }
        self.u64(event.instruction.gas_before);
        self.state
            .update(&[u8::from(event.instruction.need_gas_charge_before)]);
        self.exit(event.instruction.exit);
        for register in event.instruction.machine_after.registers {
            self.u64(register);
        }
        self.u64(event.instruction.machine_after.gas);
        self.u32(event.instruction.machine_after.pc);
        self.u32(event.instruction.machine_after.heap_base);
        self.u32(event.instruction.machine_after.heap_top);
        self.state
            .update(&[u8::from(event.instruction.machine_after.need_gas_charge)]);
    }

    fn protocol_call(&mut self, slot: u8, kernel: &InvocationKernel) {
        self.state.update(&[1, slot]);
        self.protocol_call_count = self.protocol_call_count.saturating_add(1);
        self.u16(kernel.active_vm);
        self.u64(kernel.call_stack.len() as u64);
        for index in 0..13 {
            self.u64(kernel.active_reg(index));
        }
        self.u64(kernel.active_gas());
    }

    fn protocol_resume(&mut self, slot: u8, result0: u64, result1: u64) {
        self.state.update(&[2, slot]);
        self.u64(result0);
        self.u64(result1);
    }

    fn checkpoint(&mut self, artifact: &ImportedBlobV2) {
        self.state.update(&[3]);
        self.bytes(&artifact.reference.hash.0);
        self.u64(artifact.reference.len);
    }

    fn task_begin(
        &mut self,
        actor: super::ActorId,
        task: Hash,
        input: &[u8],
        tag: Option<[u8; 32]>,
    ) {
        self.state.update(&[4]);
        self.bytes(&actor.0);
        self.bytes(&task.0);
        self.bytes(&Hash::digest(b"vos/task-input/v2", &[input]).0);
        match tag {
            Some(tag) => {
                self.state.update(&[1]);
                self.bytes(&tag);
            }
            None => {
                self.state.update(&[0]);
            }
        }
        // A separately instantiated Task VM has its own VM-0 namespace. The
        // explicit begin/end markers make that namespace unambiguous in the
        // enclosing trace and force a switch at the next observed program.
        self.previous_vm = None;
    }

    fn task_end(&mut self, output: &[u8]) {
        self.state.update(&[5]);
        self.bytes(output);
        self.previous_vm = None;
    }

    fn output(&mut self, bytes: &[u8], gas_used: u64, exported_blobs: &[ImportedBlobV2]) {
        self.state.update(&[6]);
        self.bytes(bytes);
        self.u64(gas_used);
        self.u64(exported_blobs.len() as u64);
        for artifact in exported_blobs {
            self.bytes(&artifact.reference.hash.0);
            self.u64(artifact.reference.len);
        }
    }

    fn finish(self) -> RefineTraceV2 {
        let digest = self.state.finalize();
        let mut commitment = [0; 32];
        commitment.copy_from_slice(digest.as_bytes());
        RefineTraceV2 {
            commitment: Hash(commitment),
            instruction_count: self.instruction_count,
            protocol_call_count: self.protocol_call_count,
            vm_switch_count: self.vm_switch_count,
            code_hashes: self.code_hashes.into_iter().map(Hash).collect(),
        }
    }

    fn exit(&mut self, exit: Option<&javm::ExitReason>) {
        match exit {
            None => {
                self.state.update(&[0]);
            }
            Some(javm::ExitReason::Halt) => {
                self.state.update(&[1]);
            }
            Some(javm::ExitReason::Trap) => {
                self.state.update(&[2]);
            }
            Some(javm::ExitReason::Panic) => {
                self.state.update(&[3]);
            }
            Some(javm::ExitReason::OutOfGas) => {
                self.state.update(&[4]);
            }
            Some(javm::ExitReason::PageFault(address)) => {
                self.state.update(&[5]);
                self.u32(*address);
            }
            Some(javm::ExitReason::HostCall(id)) => {
                self.state.update(&[6]);
                self.u32(*id);
            }
            Some(javm::ExitReason::Ecall) => {
                self.state.update(&[7]);
            }
        }
    }

    fn bytes(&mut self, bytes: &[u8]) {
        self.u64(bytes.len() as u64);
        self.state.update(bytes);
    }

    fn u16(&mut self, value: u16) {
        self.state.update(&value.to_le_bytes());
    }

    fn u32(&mut self, value: u32) {
        self.state.update(&value.to_le_bytes());
    }

    fn u64(&mut self, value: u64) {
        self.state.update(&value.to_le_bytes());
    }
}

impl core::fmt::Display for ServicePvmErrorV2 {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        write!(f, "VOS service PVM failed: {self:?}")
    }
}

impl core::error::Error for ServicePvmErrorV2 {}

/// Read-only import/cache host exposed while the service PVM is refining.
///
/// The receiver is immutable by design. Implementations provide imported work
/// data, canonical code, content-addressed blobs, or deterministic compilation
/// products. Persistent service state is deliberately absent from this API.
pub trait RefineProtocolHostV2 {
    fn handle(
        &self,
        slot: u8,
        registers: &[u64; 13],
        kernel: &mut InvocationKernel,
    ) -> Result<[u64; 2], ServicePvmErrorV2>;
}

/// Private staging area for one Accumulate execution.
///
/// Implementations buffer storage mutations, receipts, dedup rows, messages,
/// replies, and publications here. Dropping the transaction must discard all
/// of them; only [`AccumulateProtocolHostV2::commit`] may make them visible.
pub trait AccumulateTransactionV2 {
    fn handle(
        &mut self,
        slot: u8,
        registers: &[u64; 13],
        kernel: &mut InvocationKernel,
    ) -> Result<[u64; 2], ServicePvmErrorV2>;
}

/// Atomic host boundary exposed to the physical IC-5 Accumulate entry.
pub trait AccumulateProtocolHostV2 {
    type Transaction: AccumulateTransactionV2;

    fn begin(&mut self) -> Result<Self::Transaction, ServicePvmErrorV2>;

    /// Begin one transaction with an authenticated ambient JAM timeslot.
    /// Hosts which do not implement the consensus-time seam reject attempts
    /// to use it instead of silently dropping the observation.
    fn begin_at(
        &mut self,
        logical_timeslot: Option<u64>,
    ) -> Result<Self::Transaction, ServicePvmErrorV2> {
        if logical_timeslot.is_some() {
            Err(ServicePvmErrorV2::AccumulateHostRejected(
                crate::abi::hostcall::ACCUMULATION_TIMESLOT as u8,
            ))
        } else {
            self.begin()
        }
    }

    /// Begin one transaction with canonical availability artifacts ordered by
    /// the same authority as the Accumulate request. Implementations must
    /// stage these bytes inside the transaction; dropping it discards them.
    fn begin_at_with_availability(
        &mut self,
        logical_timeslot: Option<u64>,
        programs: &[super::ImportedProgramV2],
        blobs: &[super::ImportedBlobV2],
    ) -> Result<Self::Transaction, ServicePvmErrorV2> {
        if !programs.is_empty() || !blobs.is_empty() {
            return Err(ServicePvmErrorV2::AccumulateHostRejected(
                crate::abi::hostcall::PROGRAM_LOOKUP as u8,
            ));
        }
        self.begin_at(logical_timeslot)
    }

    fn commit(&mut self, transaction: Self::Transaction) -> Result<(), ServicePvmErrorV2>;
}

/// Host authority which can make one exact finalized receipt-verification
/// decision available to physical guest Accumulate.
///
/// Local services use this as process policy. Replicated services call it
/// only for decisions carried by the same committed Raft entry as the
/// request, so every replica exposes the identical verifier result before
/// executing IC-5.
pub trait ReceiptVerificationHostV2 {
    fn make_receipt_available(&mut self, request: &super::ReceiptVerificationRequestV2) -> bool;
}

/// Host used by pure service programs that need no protocol imports.
#[derive(Debug, Clone, Copy, Default)]
pub struct NoRefineProtocolHostV2;

impl RefineProtocolHostV2 for NoRefineProtocolHostV2 {
    fn handle(
        &self,
        slot: u8,
        _registers: &[u64; 13],
        _kernel: &mut InvocationKernel,
    ) -> Result<[u64; 2], ServicePvmErrorV2> {
        Err(ServicePvmErrorV2::RefineHostRejected(slot))
    }
}

/// Canonical generic-service program plus its verified identity.
pub struct ServicePvmV2 {
    program: Vec<u8>,
    program_id: ProgramId,
}

/// Pure invocation-local bridge between isolated actor VMs and the generic
/// service guest.
///
/// Actor materializations never enter the shared CALL IPC window. The bridge
/// selects private input from the active JAR VM and authenticates nested
/// `Origin::Actor` from the live call stack. Actor outputs are retained as
/// opaque canonical wires until VM 0 fetches the batch and constructs the
/// transition itself.
struct ActorRefineRuntimeV2 {
    target: super::ActorId,
    program_layout: Vec<super::ContinuationProgramV2>,
    actor_by_vm: Vec<Option<super::ActorId>>,
    private_inputs: BTreeMap<super::ActorId, ActorPrivateInputV2>,
    task_programs: BTreeMap<(super::ActorId, Hash), TaskProgramV2>,
    task_code_cache: javm::CodeCache,
    task_gas_used: u64,
    record_intents: BTreeMap<super::ActorId, u32>,
    record_attempts: BTreeMap<super::ActorId, u32>,
    record_successes: BTreeMap<super::ActorId, u32>,
    staged_records: BTreeMap<(super::ActorId, [u8; 32]), crate::provable::ProvableRecord>,
    storage_rows: BTreeMap<(super::ActorId, Vec<u8>), Option<Vec<u8>>>,
    missing_storage_rows: BTreeSet<ActorStorageKeyV2>,
    producer_records: Vec<ProducedProvableRecordV2>,
    producer_record_bytes: usize,
    outputs: Vec<ActorSliceOutputV2>,
    encoded_outputs_len: usize,
}

struct TaskProgramV2 {
    pvm: Vec<u8>,
    witness_address: u32,
    witness_capacity: u32,
}

impl ActorRefineRuntimeV2 {
    fn new(
        work: &WorkEnvelopeV2,
        imports: &RefineImportsV2,
        space_role: Option<u8>,
        actor_role: Option<u8>,
        captured_programs: Option<&[super::ContinuationProgramV2]>,
    ) -> Result<Self, ServicePvmErrorV2> {
        let program_layout = captured_programs.map_or_else(
            || {
                work.imported_actors
                    .iter()
                    .map(|actor| super::ContinuationProgramV2 {
                        actor: actor.actor,
                        deployment: actor.deployment,
                        program: actor.program,
                    })
                    .collect()
            },
            <[super::ContinuationProgramV2]>::to_vec,
        );
        let actor_tree = actor_tree_from_work(work)
            .into_iter()
            .filter(|actor| {
                program_layout
                    .binary_search_by_key(&actor.actor, |binding| binding.actor)
                    .is_ok()
            })
            .collect::<Vec<_>>();
        let mut actor_by_vm = Vec::with_capacity(program_layout.len() + 1);
        actor_by_vm.push(None);
        actor_by_vm.push(Some(work.target));
        actor_by_vm.extend(
            program_layout
                .iter()
                .filter(|actor| actor.actor != work.target)
                .map(|actor| Some(actor.actor)),
        );

        let mut private_inputs = BTreeMap::new();
        let mut task_programs = BTreeMap::new();
        let mut storage_rows = BTreeMap::new();
        for actor in work.imported_actors.iter().filter(|actor| {
            program_layout
                .binary_search_by_key(&actor.actor, |binding| binding.actor)
                .is_ok()
        }) {
            let state = imported_blob_bytes(imports, &actor.state)?.to_vec();
            let causal_states = actor
                .causal_states
                .iter()
                .map(|reference| imported_blob_bytes(imports, reference).map(<[u8]>::to_vec))
                .collect::<Result<Vec<_>, _>>()?;
            let private = ActorPrivateInputV2 {
                actor: actor.actor,
                actor_tree: actor_tree.clone(),
                external_actors: work.external_actors.clone(),
                input: work.input_id(),
                change: crdt_dispatch(work, 0),
                state,
                causal_states,
                active_actor_mask: 0,
                origin: work.origin,
                space_role,
                actor_role,
            };
            if private.encode().len() > ACTOR_PRIVATE_INPUT_MAX_BYTES {
                return Err(ServicePvmErrorV2::ActorInputTooLarge);
            }
            private_inputs.insert(actor.actor, private);
            for row in &actor.storage_rows {
                let value = row.value.clone();
                if storage_rows
                    .insert((actor.actor, row.key.clone()), value)
                    .is_some()
                {
                    return Err(ServicePvmErrorV2::InvalidRefineImports);
                }
            }
            for dependency in &actor.task_dependencies {
                let imported = imports
                    .programs
                    .binary_search_by_key(&dependency.program, |program| program.program)
                    .ok()
                    .map(|index| &imports.programs[index])
                    .ok_or(ServicePvmErrorV2::InvalidRefineImports)?;
                if Hash(crate::provable::task_blob_hash(&imported.pvm)) != dependency.task
                    || ProgramId::of_pvm(&imported.pvm) != dependency.program
                {
                    return Err(ServicePvmErrorV2::InvalidRefineImports);
                }
                task_programs.insert(
                    (actor.actor, dependency.task),
                    TaskProgramV2 {
                        pvm: imported.pvm.clone(),
                        witness_address: dependency.witness_address,
                        witness_capacity: dependency.witness_capacity,
                    },
                );
            }
        }
        Ok(Self {
            target: work.target,
            program_layout,
            actor_by_vm,
            private_inputs,
            task_programs,
            task_code_cache: javm::CodeCache::new(),
            task_gas_used: 0,
            record_intents: BTreeMap::new(),
            record_attempts: BTreeMap::new(),
            record_successes: BTreeMap::new(),
            staged_records: BTreeMap::new(),
            storage_rows,
            missing_storage_rows: BTreeSet::new(),
            producer_records: Vec::new(),
            producer_record_bytes: 0,
            outputs: Vec::new(),
            // V2 header plus the effect-batch list length.
            encoded_outputs_len: 10,
        })
    }

    fn take_producer_records(&mut self) -> Vec<ProducedProvableRecordV2> {
        core::mem::take(&mut self.producer_records)
    }

    fn take_missing_storage_rows(&mut self) -> Vec<ActorStorageKeyV2> {
        core::mem::take(&mut self.missing_storage_rows)
            .into_iter()
            .collect()
    }

    fn has_record_activity(&self) -> bool {
        self.record_intents.values().any(|value| *value != 0)
            || self.record_attempts.values().any(|value| *value != 0)
    }

    fn actor_for_vm(&self, vm: u16) -> Option<super::ActorId> {
        self.actor_by_vm.get(vm as usize).copied().flatten()
    }

    fn write_task_result(
        kernel: &mut InvocationKernel,
        output: &[u8],
    ) -> Result<[u64; 2], ServicePvmErrorV2> {
        let packed = kernel.active_reg(11);
        let address = packed as u32;
        let capacity = (packed >> 32) as u32 as usize;
        let bytes = if capacity != 0 && output.len() > capacity {
            &[crate::actors::run::STATUS_TOO_BIG][..]
        } else {
            output
        };
        if !kernel.write_data_cap_window(address, bytes) {
            return Err(ServicePvmErrorV2::RefineHostRejected(
                crate::abi::hostcall::INVOKE as u8,
            ));
        }
        Ok([bytes.len() as u64, 0])
    }

    fn handle_task_invoke(
        &mut self,
        kernel: &mut InvocationKernel,
        mut trace: Option<&mut RefineTraceRecorderV2>,
    ) -> Result<[u64; 2], ServicePvmErrorV2> {
        use crate::actors::run::{STATUS_DONE, STATUS_OOG, STATUS_PANICKED, STATUS_YIELDED};

        const DEFAULT_TASK_GAS: u64 = 100_000_000;
        const MAX_TASK_OUTPUT_BYTES: usize = 1 << 20;

        let actor =
            self.actor_for_vm(kernel.active_vm)
                .ok_or(ServicePvmErrorV2::RefineHostRejected(
                    crate::abi::hostcall::INVOKE as u8,
                ))?;
        let hash_address = u32::try_from(kernel.active_reg(7)).map_err(|_| {
            ServicePvmErrorV2::RefineHostRejected(crate::abi::hostcall::INVOKE as u8)
        })?;
        let input_address = u32::try_from(kernel.active_reg(8)).map_err(|_| {
            ServicePvmErrorV2::RefineHostRejected(crate::abi::hostcall::INVOKE as u8)
        })?;
        let input_len = u32::try_from(kernel.active_reg(9)).map_err(|_| {
            ServicePvmErrorV2::RefineHostRejected(crate::abi::hostcall::INVOKE as u8)
        })?;
        let hash_bytes = kernel.read_data_cap_window(hash_address, 32).ok_or(
            ServicePvmErrorV2::RefineHostRejected(crate::abi::hostcall::INVOKE as u8),
        )?;
        let input = kernel
            .read_data_cap_window(input_address, input_len)
            .ok_or(ServicePvmErrorV2::RefineHostRejected(
                crate::abi::hostcall::INVOKE as u8,
            ))?;
        let task = Hash(hash_bytes.try_into().map_err(|_| {
            ServicePvmErrorV2::RefineHostRejected(crate::abi::hostcall::INVOKE as u8)
        })?);
        let (state, row_keys, tag, message) = crate::runtime::split_invoke_input(&input);
        if !row_keys.is_empty() {
            // Parent-row imports need their own base-authenticated witness
            // channel. The first production Task surface is intentionally
            // witness-self-contained; never guess row values here.
            return Self::write_task_result(kernel, &[STATUS_PANICKED]);
        }
        if tag.is_some() {
            let intents = self.record_intents.entry(actor).or_default();
            if *intents == 0 {
                return Self::write_task_result(kernel, &[STATUS_PANICKED]);
            }
            *intents -= 1;
            let attempts = self.record_attempts.entry(actor).or_default();
            *attempts = attempts
                .checked_add(1)
                .ok_or(ServicePvmErrorV2::RefineHostRejected(
                    crate::abi::hostcall::INVOKE as u8,
                ))?;
        }
        let Some(program) = self.task_programs.get(&(actor, task)) else {
            return Self::write_task_result(kernel, &[crate::actors::run::STATUS_NOT_FOUND]);
        };
        let task_input = crate::task_abi::encode_task_input(state, message);
        if task_input.len() > program.witness_capacity as usize {
            return Self::write_task_result(kernel, &[crate::actors::run::STATUS_TOO_BIG]);
        }
        if let Some(recorder) = trace.as_deref_mut() {
            recorder.task_begin(actor, task, &task_input, tag);
        }
        let requested_gas = match kernel.active_reg(10) {
            0 => DEFAULT_TASK_GAS,
            requested => requested.min(DEFAULT_TASK_GAS),
        };
        // JAR does not expose a backend-neutral setter for the live parent's
        // gas while a recompiled VM is suspended at a protocol boundary.
        // Maintain the nested charge separately and never let Tasks spend
        // more than the parent slice's currently unclaimed budget. The two
        // charges are combined and bounded before Refine can return.
        let gas_limit = requested_gas.min(kernel.active_gas().saturating_sub(self.task_gas_used));
        if gas_limit == 0 {
            let result = Self::write_task_result(kernel, &[STATUS_OOG])?;
            if let Some(recorder) = trace {
                recorder.task_end(&[STATUS_OOG]);
            }
            return Ok(result);
        }
        // Signed Task execution is part of the proof contract. Use the
        // canonical interpreter in both ordinary Refine and traced replay so
        // instruction charging and the near-budget outcome cannot depend on
        // which backend happened to run the enclosing service VM.
        let task_backend = javm::PvmBackend::ForceInterpreter;
        let Some(mut child) = crate::runtime::build_task_kernel_with_backend(
            &program.pvm,
            program.witness_address,
            &task_input,
            gas_limit,
            &mut self.task_code_cache,
            task_backend,
        ) else {
            let result = Self::write_task_result(kernel, &[STATUS_PANICKED])?;
            if let Some(recorder) = trace {
                recorder.task_end(&[STATUS_PANICKED]);
            }
            return Ok(result);
        };

        let failure = loop {
            let result = if let Some(recorder) = trace.as_deref_mut() {
                child
                    .run_observed(|event| recorder.instruction(event))
                    .map_err(|_| ServicePvmErrorV2::TraceBackendRequired)?
            } else {
                child.run()
            };
            match result {
                KernelResult::Halt => break None,
                KernelResult::Panic | KernelResult::PageFault(_) => break Some(STATUS_PANICKED),
                KernelResult::OutOfGas => break Some(STATUS_OOG),
                KernelResult::ProtocolCall { slot } => {
                    if let Some(recorder) = trace.as_deref_mut() {
                        recorder.protocol_call(slot, &child);
                    }
                    if !crate::runtime::handle_task_hostcall(&mut child, slot as u32, tag.is_none())
                    {
                        break Some(STATUS_PANICKED);
                    }
                    if let Some(recorder) = trace.as_deref_mut() {
                        recorder.protocol_resume(slot, child.active_reg(7), child.active_reg(8));
                    }
                }
            }
        };
        let task_gas_used = gas_limit.saturating_sub(child.active_gas());
        self.task_gas_used = self.task_gas_used.saturating_add(task_gas_used);
        if let Some(status) = failure {
            let result = Self::write_task_result(kernel, &[status])?;
            if let Some(recorder) = trace {
                recorder.task_end(&[status]);
            }
            return Ok(result);
        }

        let output_address = u32::try_from(child.active_reg(7)).map_err(|_| {
            ServicePvmErrorV2::RefineHostRejected(crate::abi::hostcall::INVOKE as u8)
        })?;
        let output_len = usize::try_from(child.active_reg(8))
            .ok()
            .filter(|len| *len <= MAX_TASK_OUTPUT_BYTES)
            .ok_or(ServicePvmErrorV2::RefineHostRejected(
                crate::abi::hostcall::INVOKE as u8,
            ))?;
        let raw_output = child
            .read_data_cap_window(output_address, output_len as u32)
            .ok_or(ServicePvmErrorV2::RefineHostRejected(
                crate::abi::hostcall::INVOKE as u8,
            ))?;
        let mut payload = crate::refine_payload::RefinePayload::decode(&raw_output)
            .filter(|payload| {
                payload.version == crate::refine_payload::REFINE_PAYLOAD_VERSION
                    && !payload.forbidden
            })
            .ok_or(ServicePvmErrorV2::RefineHostRejected(
                crate::abi::hostcall::INVOKE as u8,
            ))?;
        let expected = crate::refine_payload::anchor_for(Some(state));
        if (payload.anchor_kind, payload.anchor) != expected {
            return Self::write_task_result(kernel, &[STATUS_PANICKED]);
        }
        let transition_digest = tag.map(|_| payload.transition_digest());
        let child_state = payload.take_state_write().unwrap_or_else(|| state.to_vec());
        if !payload.effects.is_empty() {
            // A producer-local record must not smuggle application effects
            // around guest Accumulate. The Clerk verifier Task is pure; later
            // effectful Task support needs an explicit typed transition.
            return Self::write_task_result(kernel, &[STATUS_PANICKED]);
        }
        let status = if payload.continue_next {
            STATUS_YIELDED
        } else {
            STATUS_DONE
        };
        let mut output = Vec::with_capacity(5 + child_state.len() + payload.reply.len());
        output.push(status);
        output.extend_from_slice(&(child_state.len() as u32).to_le_bytes());
        output.extend_from_slice(&child_state);
        output.extend_from_slice(&payload.reply);
        if tag.is_some() && payload.continue_next {
            return Self::write_task_result(kernel, &[STATUS_PANICKED]);
        }
        let result = Self::write_task_result(kernel, &output)?;
        if result[0] != output.len() as u64 {
            if let Some(recorder) = trace {
                recorder.task_end(&[crate::actors::run::STATUS_TOO_BIG]);
            }
            return Ok(result);
        }
        if let Some(tag) = tag {
            let mut io_hash = [0u8; 32];
            for (index, register) in (9usize..13).enumerate() {
                io_hash[index * 8..index * 8 + 8]
                    .copy_from_slice(&child.active_reg(register).to_le_bytes());
            }
            let record = crate::provable::ProvableRecord {
                task_hash: task.0,
                anchor_kind: payload.anchor_kind,
                anchor: payload.anchor,
                transition_digest: transition_digest.expect("tag computes digest"),
                reply: payload.reply,
                io_hash,
                app_public: payload.app_public,
                catalog_name: alloc::string::String::new(),
                catalog_version: 0,
            };
            let entry = crate::provable::ProofRecordEntry {
                input: crate::provable::ProvableInput {
                    task_hash: task.0,
                    witness_bytes: task_input,
                },
                record: record.clone(),
            };
            let encoded_len = entry.encode().len();
            let Some(total_record_bytes) = self
                .producer_record_bytes
                .checked_add(encoded_len)
                .filter(|total| *total <= MAX_PRODUCER_RECORD_BYTES_PER_SLICE)
            else {
                return Err(ServicePvmErrorV2::RefineHostRejected(
                    crate::abi::hostcall::INVOKE as u8,
                ));
            };
            if self.producer_records.len() >= MAX_PRODUCER_RECORDS_PER_SLICE
                || !entry.record.io_consistent()
                || self.staged_records.contains_key(&(actor, tag))
            {
                return Err(ServicePvmErrorV2::RefineHostRejected(
                    crate::abi::hostcall::INVOKE as u8,
                ));
            }
            self.staged_records.insert((actor, tag), record);
            self.producer_records
                .push(ProducedProvableRecordV2 { actor, tag, entry });
            self.producer_record_bytes = total_record_bytes;
            let successes = self.record_successes.entry(actor).or_default();
            *successes = successes
                .checked_add(1)
                .ok_or(ServicePvmErrorV2::RefineHostRejected(
                    crate::abi::hostcall::INVOKE as u8,
                ))?;
        }
        if let Some(recorder) = trace {
            recorder.task_end(&output);
        }
        Ok(result)
    }

    fn handle(
        &mut self,
        slot: u8,
        kernel: &mut InvocationKernel,
        trace: Option<&mut RefineTraceRecorderV2>,
    ) -> Result<Option<[u64; 2]>, ServicePvmErrorV2> {
        match slot as u32 {
            crate::abi::hostcall::PROVABLE_RECORD_INTENT => {
                let actor = self
                    .actor_for_vm(kernel.active_vm)
                    .ok_or(ServicePvmErrorV2::RefineHostRejected(slot))?;
                let intents = self.record_intents.entry(actor).or_default();
                *intents = intents
                    .checked_add(1)
                    .ok_or(ServicePvmErrorV2::RefineHostRejected(slot))?;
                Ok(Some([crate::abi::error::HOST_OK, 0]))
            }
            crate::abi::hostcall::INVOKE => {
                if kernel.active_vm == 0 {
                    return Err(ServicePvmErrorV2::RefineHostRejected(slot));
                }
                self.handle_task_invoke(kernel, trace).map(Some)
            }
            crate::abi::hostcall::STORAGE_R => {
                let actor = self
                    .actor_for_vm(kernel.active_vm)
                    .ok_or(ServicePvmErrorV2::RefineHostRejected(slot))?;
                let key_address = u32::try_from(kernel.active_reg(7))
                    .map_err(|_| ServicePvmErrorV2::RefineHostRejected(slot))?;
                let key_len = u32::try_from(kernel.active_reg(8))
                    .map_err(|_| ServicePvmErrorV2::RefineHostRejected(slot))?;
                let key = kernel
                    .read_data_cap_window(key_address, key_len)
                    .ok_or(ServicePvmErrorV2::RefineHostRejected(slot))?;
                let Some(tag) = key
                    .strip_prefix(crate::provable::PROOFREC_PREFIX)
                    .and_then(|tag| <[u8; 32]>::try_from(tag).ok())
                else {
                    if key.is_empty() || key.len() > super::MAX_ACTOR_STORAGE_KEY_BYTES {
                        return Err(ServicePvmErrorV2::RefineHostRejected(slot));
                    }
                    let lookup = (actor, key.clone());
                    let Some(value) = self.storage_rows.get(&lookup) else {
                        if self.missing_storage_rows.len() >= super::MAX_ACTOR_STORAGE_WITNESSES {
                            return Err(ServicePvmErrorV2::ActorInputTooLarge);
                        }
                        self.missing_storage_rows
                            .insert(ActorStorageKeyV2 { actor, key });
                        return Ok(Some([crate::abi::error::HOST_NONE, 0]));
                    };
                    let Some(bytes) = value.as_ref() else {
                        return Ok(Some([crate::abi::error::HOST_NONE, 0]));
                    };
                    let output_address = u32::try_from(kernel.active_reg(9))
                        .map_err(|_| ServicePvmErrorV2::RefineHostRejected(slot))?;
                    let capacity = usize::try_from(kernel.active_reg(10))
                        .map_err(|_| ServicePvmErrorV2::RefineHostRejected(slot))?;
                    let copy_len = bytes.len().min(capacity);
                    if !kernel.write_data_cap_window(output_address, &bytes[..copy_len]) {
                        return Err(ServicePvmErrorV2::RefineHostRejected(slot));
                    }
                    return Ok(Some([bytes.len() as u64, 0]));
                };
                let Some(record) = self.staged_records.get(&(actor, tag)) else {
                    return Ok(Some([crate::abi::error::HOST_NONE, 0]));
                };
                // Actor memory receives only the verifier-facing record. The
                // exact witness remains exclusively in producer_records and
                // is persisted through the host-private sidecar.
                let bytes = record.encode();
                let output_address = u32::try_from(kernel.active_reg(9))
                    .map_err(|_| ServicePvmErrorV2::RefineHostRejected(slot))?;
                let capacity = usize::try_from(kernel.active_reg(10))
                    .map_err(|_| ServicePvmErrorV2::RefineHostRejected(slot))?;
                let copy_len = bytes.len().min(capacity);
                if !kernel.write_data_cap_window(output_address, &bytes[..copy_len]) {
                    return Err(ServicePvmErrorV2::RefineHostRejected(slot));
                }
                Ok(Some([bytes.len() as u64, 0]))
            }
            crate::abi::hostcall::ACTOR_PRIVATE_FETCH => {
                let bytes = if kernel.active_vm == 0 {
                    if !kernel.call_stack.is_empty() {
                        return Err(ServicePvmErrorV2::RefineHostRejected(slot));
                    }
                    ActorEffectBatchV2 {
                        outputs: self.outputs.clone(),
                    }
                    .encode()
                } else {
                    let actor = self
                        .actor_for_vm(kernel.active_vm)
                        .ok_or(ServicePvmErrorV2::RefineHostRejected(slot))?;
                    let caller_vm = kernel
                        .call_stack
                        .last()
                        .map(|frame| frame.caller_vm_id)
                        .ok_or(ServicePvmErrorV2::RefineHostRejected(slot))?;
                    let mut private = self
                        .private_inputs
                        .get(&actor)
                        .cloned()
                        .ok_or(ServicePvmErrorV2::RefineHostRejected(slot))?;
                    let mut active_actor_mask = 0u64;
                    for vm in kernel
                        .call_stack
                        .iter()
                        .map(|frame| frame.caller_vm_id)
                        .chain(core::iter::once(kernel.active_vm))
                        .filter(|vm| *vm != 0)
                    {
                        let active_actor = self
                            .actor_for_vm(vm)
                            .ok_or(ServicePvmErrorV2::RefineHostRejected(slot))?;
                        let index = private
                            .actor_tree
                            .binary_search_by_key(&active_actor, |candidate| candidate.actor)
                            .map_err(|_| ServicePvmErrorV2::RefineHostRejected(slot))?;
                        active_actor_mask |= 1u64 << index;
                    }
                    if active_actor_mask == 0 {
                        return Err(ServicePvmErrorV2::RefineHostRejected(slot));
                    }
                    private.active_actor_mask = active_actor_mask;
                    if caller_vm == 0 {
                        if actor != self.target {
                            return Err(ServicePvmErrorV2::RefineHostRejected(slot));
                        }
                    } else {
                        let caller = self
                            .actor_for_vm(caller_vm)
                            .ok_or(ServicePvmErrorV2::RefineHostRejected(slot))?;
                        private.origin = Origin::Actor(caller);
                        private.space_role = None;
                        private.actor_role = None;
                    }
                    private.encode()
                };
                if bytes.is_empty()
                    || bytes.len()
                        > if kernel.active_vm == 0 {
                            ACTOR_EFFECT_BATCH_MAX_BYTES
                        } else {
                            ACTOR_PRIVATE_INPUT_MAX_BYTES
                        }
                {
                    return Err(ServicePvmErrorV2::RefineHostRejected(slot));
                }
                write_refine_protocol_bytes(kernel, &bytes)
                    .map(Some)
                    .ok_or(ServicePvmErrorV2::RefineHostRejected(slot))
            }
            crate::abi::hostcall::ACTOR_EFFECT_EXPORT => {
                if kernel.active_vm == 0 {
                    return Err(ServicePvmErrorV2::RefineHostRejected(slot));
                }
                let actor = self
                    .actor_for_vm(kernel.active_vm)
                    .ok_or(ServicePvmErrorV2::RefineHostRejected(slot))?;
                let address = u32::try_from(kernel.active_reg(7))
                    .map_err(|_| ServicePvmErrorV2::RefineHostRejected(slot))?;
                let len = u32::try_from(kernel.active_reg(8))
                    .map_err(|_| ServicePvmErrorV2::RefineHostRejected(slot))?;
                if len == 0 || len as usize > ACTOR_PRIVATE_INPUT_MAX_BYTES {
                    return Err(ServicePvmErrorV2::RefineHostRejected(slot));
                }
                let bytes = kernel
                    .read_data_cap_window(address, len)
                    .ok_or(ServicePvmErrorV2::RefineHostRejected(slot))?;
                let mut output = ActorSliceOutputV2::decode(&bytes)
                    .map_err(|_| ServicePvmErrorV2::RefineHostRejected(slot))?;
                if output.actor != actor {
                    return Err(ServicePvmErrorV2::RefineHostRejected(slot));
                }
                if self.record_intents.get(&actor).copied().unwrap_or(0) != 0
                    || self.record_attempts.get(&actor).copied().unwrap_or(0)
                        != self.record_successes.get(&actor).copied().unwrap_or(0)
                    || output
                        .writes
                        .iter()
                        .any(|write| write.key.starts_with(crate::provable::PROOFREC_PREFIX))
                {
                    // A queued TaskRecord contains its complete proving
                    // witness. It must be consumed during this exact Refine
                    // slice, and its record is emitted only through the
                    // producer-local host channel above.
                    return Err(ServicePvmErrorV2::RefineHostRejected(slot));
                }
                self.encoded_outputs_len = self
                    .encoded_outputs_len
                    .checked_add(4)
                    .and_then(|len| len.checked_add(bytes.len()))
                    .filter(|len| *len <= ACTOR_EFFECT_BATCH_MAX_BYTES)
                    .ok_or(ServicePvmErrorV2::RefineHostRejected(slot))?;
                let private = self
                    .private_inputs
                    .get_mut(&actor)
                    .ok_or(ServicePvmErrorV2::RefineHostRejected(slot))?;
                match private.change {
                    Some(_) if output.forbidden => {
                        if !output.writes.is_empty()
                            || !output.crdt_operations.is_empty()
                            || !output.crdt_states.is_empty()
                        {
                            return Err(ServicePvmErrorV2::RefineHostRejected(slot));
                        }
                    }
                    Some(dispatch) => {
                        let [state] = output.crdt_states.as_slice() else {
                            return Err(ServicePvmErrorV2::RefineHostRejected(slot));
                        };
                        let next_dispatch_ordinal = dispatch
                            .ordinal
                            .checked_add(1)
                            .ok_or(ServicePvmErrorV2::RefineHostRejected(slot))?;
                        if !output.writes.is_empty()
                            || state.actor != actor
                            || state.next_dispatch_ordinal != next_dispatch_ordinal
                            || output.crdt_operations.iter().any(|operation| {
                                operation.actor != actor
                                    || operation.dispatch_ordinal != dispatch.ordinal
                                    || operation.id
                                        != dispatch.change.operation(
                                            actor,
                                            dispatch.ordinal,
                                            operation.field,
                                            operation.ordinal,
                                        )
                            })
                        {
                            return Err(ServicePvmErrorV2::RefineHostRejected(slot));
                        }
                        private.state = state.state.clone();
                        private.causal_states.clear();
                        private.change = Some(CrdtDispatchV2 {
                            change: dispatch.change,
                            ordinal: next_dispatch_ordinal,
                        });
                    }
                    None => {
                        if !output.crdt_operations.is_empty() || !output.crdt_states.is_empty() {
                            return Err(ServicePvmErrorV2::RefineHostRejected(slot));
                        }
                        if let Some(write) = output
                            .writes
                            .iter()
                            .find(|write| write.key.as_slice() == crate::lifecycle::STATE_KEY_BYTES)
                        {
                            let state = write
                                .value
                                .as_ref()
                                .ok_or(ServicePvmErrorV2::RefineHostRejected(slot))?;
                            private.state = state.clone();
                            private.causal_states.clear();
                        }
                    }
                }
                if actor != self.target && !output.yielded {
                    if output
                        .checkpoint
                        .as_ref()
                        .is_some_and(|checkpoint| checkpoint.replacement.is_some())
                    {
                        return Err(ServicePvmErrorV2::RefineHostRejected(slot));
                    }
                    // Completion control flows upward through the direct CALL
                    // result. Only the entry actor exports it into the service
                    // transition, so an older child's deletion token cannot
                    // conflict with a later await in the same resumed slice.
                    output.checkpoint = None;
                }
                self.outputs.push(output);
                Ok(Some([crate::abi::error::HOST_OK, 0]))
            }
            _ => Ok(None),
        }
    }
}

impl ServicePvmV2 {
    pub fn new(program: Vec<u8>, expected: ProgramId) -> Result<Self, ServicePvmErrorV2> {
        validate_service_entries(&program)?;
        let actual = ProgramId::of_pvm(&program);
        if actual != expected {
            return Err(ServicePvmErrorV2::ProgramIdMismatch);
        }
        Ok(Self {
            program,
            program_id: actual,
        })
    }

    pub const fn program_id(&self) -> ProgramId {
        self.program_id
    }

    /// Exact protocol-pinned service bytes used for both live scheduling and
    /// attestation replay.
    pub fn canonical_pvm(&self) -> &[u8] {
        &self.program
    }

    /// Execute the physical IC-0 Refine entry.
    ///
    /// Identical program bytes, arguments, gas, and import-host responses reach
    /// the same PVM path. No mutable service store is passed to this function.
    pub fn refine<H: RefineProtocolHostV2>(
        &self,
        arguments: &[u8],
        gas_limit: u64,
        host: &H,
    ) -> Result<ServicePvmOutputV2, ServicePvmErrorV2> {
        let mut kernel = InvocationKernel::new(&self.program, arguments, gas_limit)
            .map_err(map_kernel_initialization_error)?;
        install_refine_scheduler_caps(&mut kernel);
        run_refine_kernel(
            kernel,
            host,
            javm::PvmBackend::Default,
            true,
            None,
            None,
            None,
            Vec::new(),
            Vec::new(),
            None,
        )
    }

    /// Execute Refine with every declared actor instantiated as a dormant JAR
    /// VM owned by this service invocation.
    ///
    /// The target actor is always installed at
    /// [`super::TARGET_ACTOR_HANDLE_SLOT`]. Other imported actors follow in
    /// canonical actor-ID order. No `INVOKE` protocol capability is installed:
    /// nested execution must use the ordinary JAR HANDLE/CALL/REPLY path.
    pub fn refine_actor_tree<H: RefineProtocolHostV2>(
        &self,
        arguments: &[u8],
        imports: &RefineImportsV2,
        gas_limit: u64,
        host: &H,
    ) -> Result<ServicePvmOutputV2, ServicePvmErrorV2> {
        self.refine_actor_tree_with_backend(
            arguments,
            imports,
            gas_limit,
            host,
            javm::PvmBackend::Default,
        )
    }

    /// Conformance variant of [`Self::refine_actor_tree`] selecting a JAR
    /// backend explicitly. Consensus outputs must be identical across the
    /// interpreter and recompiler.
    pub fn refine_actor_tree_with_backend<H: RefineProtocolHostV2>(
        &self,
        arguments: &[u8],
        imports: &RefineImportsV2,
        gas_limit: u64,
        host: &H,
        backend: javm::PvmBackend,
    ) -> Result<ServicePvmOutputV2, ServicePvmErrorV2> {
        self.refine_actor_tree_internal(arguments, imports, gas_limit, host, backend, false)
    }

    /// Execute the exact live actor-tree Refine path while committing every
    /// canonical interpreter instruction and scheduler protocol boundary.
    /// The returned transition is byte-identical to an ordinary interpreter
    /// or recompiler execution for the same input.
    pub fn refine_actor_tree_traced<H: RefineProtocolHostV2>(
        &self,
        arguments: &[u8],
        imports: &RefineImportsV2,
        gas_limit: u64,
        host: &H,
    ) -> Result<ServicePvmOutputV2, ServicePvmErrorV2> {
        self.refine_actor_tree_internal(
            arguments,
            imports,
            gas_limit,
            host,
            javm::PvmBackend::ForceInterpreter,
            true,
        )
    }

    fn refine_actor_tree_internal<H: RefineProtocolHostV2>(
        &self,
        arguments: &[u8],
        imports: &RefineImportsV2,
        gas_limit: u64,
        host: &H,
        backend: javm::PvmBackend,
        traced: bool,
    ) -> Result<ServicePvmOutputV2, ServicePvmErrorV2> {
        let work = WorkEnvelopeV2::decode(arguments)
            .map_err(|_| ServicePvmErrorV2::InvalidWorkEnvelope)?;
        imports
            .validate_for(&work)
            .map_err(|_| ServicePvmErrorV2::InvalidRefineImports)?;
        if work.imported_actors.len() > MAX_ROOT_TREE_ACTORS {
            return Err(ServicePvmErrorV2::TooManyImportedActors);
        }
        let trace = traced.then(|| RefineTraceRecorderV2::new(self.program_id, &work, imports));

        let mut actors = Vec::with_capacity(work.imported_actors.len());
        let target = work
            .imported_actors
            .iter()
            .find(|actor| actor.actor == work.target)
            .ok_or(ServicePvmErrorV2::InvalidRefineImports)?;
        actors.push(target);
        actors.extend(
            work.imported_actors
                .iter()
                .filter(|actor| actor.actor != work.target),
        );

        let mut dormant = Vec::with_capacity(actors.len());
        for (ordinal, actor) in actors.into_iter().enumerate() {
            let imported = imports
                .programs
                .binary_search_by_key(&actor.program, |program| program.program)
                .ok()
                .map(|index| &imports.programs[index])
                .ok_or(ServicePvmErrorV2::InvalidRefineImports)?;
            validate_actor_program_layout(&imported.pvm)?;
            let handle_slot = TARGET_ACTOR_HANDLE_SLOT
                .checked_add(ordinal as u8)
                .ok_or(ServicePvmErrorV2::TooManyImportedActors)?;
            dormant.push(DormantProgram {
                blob: &imported.pvm,
                handle_slot,
            });
        }
        let (space_role, actor_role) = authorization_roles(&work, imports)?;

        if let Some(reference) = target.continuation.as_ref() {
            let bytes = imported_blob_bytes(imports, reference)?;
            let continuation = ContinuationSnapshotV2::decode(bytes)
                .map_err(|_| ServicePvmErrorV2::InvalidContinuation)?;
            continuation
                .validate_resume_for(&work)
                .map_err(|_| ServicePvmErrorV2::ContinuationMismatch)?;
            let actor_runtime = ActorRefineRuntimeV2::new(
                &work,
                imports,
                space_role,
                actor_role,
                Some(&continuation.programs),
            )?;
            let snapshot = KernelSnapshot::from_bytes(&continuation.kernel_snapshot)
                .map_err(|_| ServicePvmErrorV2::InvalidContinuation)?;
            if snapshot.pending_call.slot != crate::abi::hostcall::SUSPEND as u8 {
                return Err(ServicePvmErrorV2::InvalidContinuation);
            }
            // Restore the exact dormant-program layout captured by this
            // continuation. The current service directory may contain actors
            // spawned after the checkpoint, but adding their handles would
            // change JAR's invocation-layout commitment.
            let mut pinned = Vec::with_capacity(continuation.programs.len());
            let target_binding = continuation
                .programs
                .binary_search_by_key(&work.target, |binding| binding.actor)
                .ok()
                .map(|index| &continuation.programs[index])
                .ok_or(ServicePvmErrorV2::ContinuationMismatch)?;
            pinned.push(target_binding);
            pinned.extend(
                continuation
                    .programs
                    .iter()
                    .filter(|binding| binding.actor != work.target),
            );
            let mut dormant = Vec::with_capacity(pinned.len());
            for (ordinal, binding) in pinned.into_iter().enumerate() {
                let imported = imports
                    .programs
                    .binary_search_by_key(&binding.program, |program| program.program)
                    .ok()
                    .map(|index| &imports.programs[index])
                    .ok_or(ServicePvmErrorV2::InvalidRefineImports)?;
                let handle_slot = TARGET_ACTOR_HANDLE_SLOT
                    .checked_add(ordinal as u8)
                    .ok_or(ServicePvmErrorV2::TooManyImportedActors)?;
                dormant.push(DormantProgram {
                    blob: &imported.pvm,
                    handle_slot,
                });
            }
            let mut kernel = InvocationKernel::restore_with_dormant_programs(
                &self.program,
                &dormant,
                &snapshot,
                backend,
            )
            .map_err(|_| ServicePvmErrorV2::ContinuationMismatch)?;
            reconcile_actor_callables(&mut kernel, &work, &continuation.programs)?;
            let checkpoint = CheckpointTokenV2 {
                input: work.input_id(),
                base: work.base.clone(),
                work_hash: work.hash(),
                resume_work: Some(alloc::boxed::Box::new(work.clone())),
                base_causal_height: work.base_causal_height,
                change: crdt_dispatch(&work, 0),
                expected: Some(reference.hash),
                replacement: None,
                pending_call: continuation.pending_call,
                pending_actor: continuation.pending_actor,
                previously_suspended: continuation.suspended_actors.clone(),
                suspended: Vec::new(),
            };
            let (resume_kind, payload_len) = match (
                continuation.pending_call,
                work.awaited_reply.as_ref(),
                work.awaited_timeout.as_ref(),
            ) {
                (None, None, None) => (1, write_checkpoint_token(&mut kernel, &checkpoint)?),
                (Some(call), Some(awaited), None) if awaited.reply.call_id == call => {
                    let attestation = awaited
                        .attestation
                        .as_ref()
                        .map(|attestation| {
                            let proof_bytes =
                                imported_blob_bytes(imports, &attestation.proof.proof_blob)?;
                            let (proof_offset, proof_len) =
                                stage_attestation_proof(&mut kernel, proof_bytes)?;
                            Ok(alloc::boxed::Box::new(super::AttestationResumeV2 {
                                producer_name: attestation.producer_name.clone(),
                                producer: attestation.producer,
                                statement: attestation.statement.clone(),
                                proof: attestation.proof.clone(),
                                proof_offset,
                                proof_len,
                            }))
                        })
                        .transpose()?;
                    (
                        2,
                        write_await_resume(
                            &mut kernel,
                            &AwaitResumeV2 {
                                checkpoint,
                                reply: awaited.reply.clone(),
                                attestation,
                            },
                        )?,
                    )
                }
                (Some(call), None, Some(timeout)) if timeout.expiration.timeout.call_id == call => {
                    (3, write_checkpoint_token(&mut kernel, &checkpoint)?)
                }
                _ => return Err(ServicePvmErrorV2::ContinuationMismatch),
            };
            kernel
                .resume_protocol_call(resume_kind, payload_len)
                .map_err(|_| ServicePvmErrorV2::InvalidProtocolResume)?;
            return run_refine_kernel(
                kernel,
                host,
                backend,
                false,
                Some(&work),
                Some((&self.program, &dormant)),
                Some(actor_runtime),
                continuation.suspended_actors,
                Vec::new(),
                trace,
            );
        }

        let actor_input = ActorSliceInputV2 {
            actor: work.target,
            first_await_ordinal: 0,
            message: work.arguments.clone(),
        }
        .encode();
        if actor_input.len() > super::ACTOR_SLICE_INPUT_MAX_BYTES {
            return Err(ServicePvmErrorV2::ActorInputTooLarge);
        }
        let actor_runtime =
            ActorRefineRuntimeV2::new(&work, imports, space_role, actor_role, None)?;
        let mut kernel = InvocationKernel::new_with_dormant_programs(
            &self.program,
            arguments,
            gas_limit,
            &dormant,
            backend,
        )
        .map_err(map_kernel_initialization_error)?;
        let (actor_input_len, actor_ipc_capacity) = install_actor_ipc(&mut kernel, &actor_input)?;
        // The GP argument registers remain phi[7]/phi[8]. These two additional
        // invocation-setup values arrive as the third/fourth Rust ABI
        // arguments and describe the ordinary DATA capability in slot 90.
        kernel.set_active_reg(9, actor_input_len as u64);
        kernel.set_active_reg(10, actor_ipc_capacity as u64);
        install_refine_scheduler_caps(&mut kernel);
        install_actor_scheduler_caps(&mut kernel, dormant.len());
        run_refine_kernel(
            kernel,
            host,
            backend,
            true,
            Some(&work),
            Some((&self.program, &dormant)),
            Some(actor_runtime),
            Vec::new(),
            Vec::new(),
            trace,
        )
    }

    /// Execute the physical IC-5 Accumulate entry against an isolated staging
    /// transaction. The service output becomes observable only after the host
    /// commits that transaction successfully.
    pub fn accumulate<H: AccumulateProtocolHostV2>(
        &self,
        arguments: &[u8],
        gas_limit: u64,
        host: &mut H,
    ) -> Result<ServicePvmOutputV2, ServicePvmErrorV2> {
        self.accumulate_at_with_backend(
            arguments,
            gas_limit,
            host,
            None,
            &[],
            &[],
            javm::PvmBackend::Default,
        )
    }

    /// Execute Accumulate while staging canonical program/blob availability
    /// in the same transaction as the guest result.
    pub fn accumulate_with_availability<H: AccumulateProtocolHostV2>(
        &self,
        arguments: &[u8],
        gas_limit: u64,
        host: &mut H,
        programs: &[super::ImportedProgramV2],
        blobs: &[super::ImportedBlobV2],
    ) -> Result<ServicePvmOutputV2, ServicePvmErrorV2> {
        self.accumulate_at_with_backend(
            arguments,
            gas_limit,
            host,
            None,
            programs,
            blobs,
            javm::PvmBackend::Default,
        )
    }

    /// Execute Accumulate with the consensus-authenticated JAM timeslot for
    /// time-dependent requests such as durable call expiration.
    pub fn accumulate_at<H: AccumulateProtocolHostV2>(
        &self,
        arguments: &[u8],
        gas_limit: u64,
        host: &mut H,
        logical_timeslot: u64,
    ) -> Result<ServicePvmOutputV2, ServicePvmErrorV2> {
        self.accumulate_at_with_backend(
            arguments,
            gas_limit,
            host,
            Some(logical_timeslot),
            &[],
            &[],
            javm::PvmBackend::Default,
        )
    }

    pub fn accumulate_at_with_availability<H: AccumulateProtocolHostV2>(
        &self,
        arguments: &[u8],
        gas_limit: u64,
        host: &mut H,
        logical_timeslot: u64,
        programs: &[super::ImportedProgramV2],
        blobs: &[super::ImportedBlobV2],
    ) -> Result<ServicePvmOutputV2, ServicePvmErrorV2> {
        self.accumulate_at_with_backend(
            arguments,
            gas_limit,
            host,
            Some(logical_timeslot),
            programs,
            blobs,
            javm::PvmBackend::Default,
        )
    }

    /// Conformance variant of [`Self::accumulate`] selecting a JAR backend.
    /// Guest-owned state transitions must be identical under both engines.
    pub fn accumulate_with_backend<H: AccumulateProtocolHostV2>(
        &self,
        arguments: &[u8],
        gas_limit: u64,
        host: &mut H,
        backend: javm::PvmBackend,
    ) -> Result<ServicePvmOutputV2, ServicePvmErrorV2> {
        self.accumulate_at_with_backend(arguments, gas_limit, host, None, &[], &[], backend)
    }

    fn accumulate_at_with_backend<H: AccumulateProtocolHostV2>(
        &self,
        arguments: &[u8],
        gas_limit: u64,
        host: &mut H,
        logical_timeslot: Option<u64>,
        programs: &[super::ImportedProgramV2],
        blobs: &[super::ImportedBlobV2],
        backend: javm::PvmBackend,
    ) -> Result<ServicePvmOutputV2, ServicePvmErrorV2> {
        let mut kernel =
            InvocationKernel::new_with_backend(&self.program, arguments, gas_limit, backend)
                .map_err(map_kernel_initialization_error)?;
        kernel
            .vm_arena
            .vm_mut(kernel.active_vm)
            .transition(VmState::Running)
            .map_err(|_| ServicePvmErrorV2::InvalidVmLifecycle)?;
        install_accumulate_scheduler_caps(&mut kernel);
        kernel.set_entry_ic(ACCUMULATE_ENTRY_IC);
        let mut transaction = host.begin_at_with_availability(logical_timeslot, programs, blobs)?;

        loop {
            match kernel.run() {
                KernelResult::Halt => {
                    let bytes = read_output(&kernel)?;
                    let gas_used = gas_limit.saturating_sub(kernel.active_gas());
                    let result = AccumulationResultV2::decode(&bytes)
                        .map_err(|_| ServicePvmErrorV2::InvalidAccumulateOutput)?;
                    if matches!(
                        result,
                        AccumulationResultV2::Installed(_)
                            | AccumulationResultV2::IngressAdmitted {
                                duplicate: false,
                                ..
                            }
                            | AccumulationResultV2::Accepted {
                                duplicate: false,
                                ..
                            }
                            | AccumulationResultV2::PublicationAcknowledged {
                                duplicate: false,
                                ..
                            }
                            | AccumulationResultV2::CallExpired {
                                duplicate: false,
                                ..
                            }
                            | AccumulationResultV2::InboxRetired {
                                duplicate: false,
                                ..
                            }
                            | AccumulationResultV2::ActorUpgraded {
                                duplicate: false,
                                ..
                            }
                    ) {
                        host.commit(transaction)?;
                    }
                    return Ok(ServicePvmOutputV2 {
                        bytes,
                        gas_used,
                        exported_blobs: Vec::new(),
                        producer_records: Vec::new(),
                        trace: None,
                    });
                }
                KernelResult::Panic => {
                    return Err(ServicePvmErrorV2::Panic {
                        vm: kernel.active_vm,
                        pc: kernel.vm_arena.vm(kernel.active_vm).pc,
                    });
                }
                KernelResult::OutOfGas => {
                    return Err(ServicePvmErrorV2::OutOfGas {
                        vm: kernel.active_vm,
                        pc: kernel.vm_arena.vm(kernel.active_vm).pc,
                    });
                }
                KernelResult::PageFault(address) => {
                    return Err(ServicePvmErrorV2::PageFault {
                        vm: kernel.active_vm,
                        address,
                    });
                }
                KernelResult::ProtocolCall { slot } => {
                    if let Some([result0, result1]) = handle_mechanical_call(slot, &mut kernel) {
                        kernel
                            .resume_protocol_call(result0, result1)
                            .map_err(|_| ServicePvmErrorV2::InvalidProtocolResume)?;
                        continue;
                    }
                    let mut registers = [0; 13];
                    for (index, register) in registers.iter_mut().enumerate() {
                        *register = kernel.active_reg(index);
                    }
                    let [result0, result1] = transaction.handle(slot, &registers, &mut kernel)?;
                    kernel
                        .resume_protocol_call(result0, result1)
                        .map_err(|_| ServicePvmErrorV2::InvalidProtocolResume)?;
                }
            }
        }
    }
}

fn map_kernel_initialization_error(error: javm::kernel::KernelError) -> ServicePvmErrorV2 {
    match error {
        javm::kernel::KernelError::MemoryError
        | javm::kernel::KernelError::OutOfMemory
        | javm::kernel::KernelError::CompileError => ServicePvmErrorV2::KernelResourceUnavailable,
        javm::kernel::KernelError::InvalidBlob
        | javm::kernel::KernelError::OutOfGas
        | javm::kernel::KernelError::TooManyCodeCaps
        | javm::kernel::KernelError::CapTableFull
        | javm::kernel::KernelError::ImportHandleUnavailable(_)
        | javm::kernel::KernelError::TooManyVms => ServicePvmErrorV2::InvalidProgram,
    }
}

fn write_refine_protocol_bytes(kernel: &mut InvocationKernel, bytes: &[u8]) -> Option<[u64; 2]> {
    let address = u32::try_from(kernel.active_reg(7)).ok()?;
    let capacity = usize::try_from(kernel.active_reg(8)).ok()?;
    let len = u64::try_from(bytes.len()).ok()?;
    if bytes.len() > capacity || !kernel.write_data_cap_window(address, bytes) {
        return None;
    }
    Some([len, 0])
}

fn actor_tree_from_work(work: &WorkEnvelopeV2) -> Vec<ActorTreeImportV2> {
    work.imported_actors
        .iter()
        .map(|actor| ActorTreeImportV2 {
            actor: actor.actor,
            name: actor.name.clone(),
            parent: actor.parent,
            deployment: actor.deployment,
            program: actor.program,
        })
        .collect()
}

fn continued_actor_vm_index(
    programs: &[super::ContinuationProgramV2],
    target: super::ActorId,
    actor: super::ActorId,
) -> Option<u16> {
    if actor == target {
        return Some(1);
    }
    programs
        .iter()
        .filter(|candidate| candidate.actor != target)
        .position(|candidate| candidate.actor == actor)
        .and_then(|index| u16::try_from(index).ok())
        .and_then(|index| index.checked_add(2))
}

/// Restore reconstructs the exact captured CNodes, but actor availability is
/// committed service state and may have changed while this workflow slept.
/// Remove every snapshot-frozen CALLABLE and rebuild only the routes admitted
/// by the current canonical actor directory.
fn reconcile_actor_callables(
    kernel: &mut InvocationKernel,
    work: &WorkEnvelopeV2,
    programs: &[super::ContinuationProgramV2],
) -> Result<(), ServicePvmErrorV2> {
    let owned_continuation = work
        .imported_actors
        .iter()
        .find(|actor| actor.actor == work.target)
        .and_then(|actor| actor.continuation.as_ref());
    // Only actors captured in the restored kernel have VMs and HANDLEs.
    // Newly spawned directory members remain part of the authoritative work
    // import, but cannot be retrofitted into an older JAR invocation layout.
    for destination in programs {
        let destination_vm = continued_actor_vm_index(programs, work.target, destination.actor)
            .ok_or(ServicePvmErrorV2::InvalidContinuation)?;
        for index in 0..MAX_ROOT_TREE_ACTORS {
            let slot = super::ACTOR_CALLABLE_BASE_SLOT
                .checked_add(index as u8)
                .ok_or(ServicePvmErrorV2::InvalidContinuation)?;
            kernel
                .vm_arena
                .vm_mut(destination_vm)
                .cap_table
                .drop_cap(slot);
        }
    }

    for destination in programs {
        let destination_vm = continued_actor_vm_index(programs, work.target, destination.actor)
            .ok_or(ServicePvmErrorV2::InvalidContinuation)?;
        for (source_index, source_binding) in programs.iter().enumerate() {
            let source = work
                .imported_actors
                .binary_search_by_key(&source_binding.actor, |actor| actor.actor)
                .ok()
                .map(|index| &work.imported_actors[index])
                .ok_or(ServicePvmErrorV2::InvalidContinuation)?;
            if source_binding.actor == destination.actor
                || source
                    .continuation
                    .as_ref()
                    .is_some_and(|continuation| Some(continuation) != owned_continuation)
            {
                continue;
            }
            let source_vm = continued_actor_vm_index(programs, work.target, source_binding.actor)
                .ok_or(ServicePvmErrorV2::InvalidContinuation)?;
            let source_handle = TARGET_ACTOR_HANDLE_SLOT
                .checked_add(
                    u8::try_from(
                        source_vm
                            .checked_sub(1)
                            .ok_or(ServicePvmErrorV2::InvalidContinuation)?,
                    )
                    .map_err(|_| ServicePvmErrorV2::InvalidContinuation)?,
                )
                .ok_or(ServicePvmErrorV2::InvalidContinuation)?;
            let (vm_id, max_gas) = match kernel.vm_arena.vm(0).cap_table.get(source_handle) {
                Some(Cap::Handle(handle)) => (handle.vm_id, handle.max_gas),
                _ => return Err(ServicePvmErrorV2::InvalidContinuation),
            };
            let callable_slot = super::ACTOR_CALLABLE_BASE_SLOT
                .checked_add(source_index as u8)
                .ok_or(ServicePvmErrorV2::InvalidContinuation)?;
            if kernel
                .vm_arena
                .vm_mut(destination_vm)
                .cap_table
                .set(callable_slot, Cap::Callable(CallableCap { vm_id, max_gas }))
                .is_some()
            {
                return Err(ServicePvmErrorV2::InvalidContinuation);
            }
        }
    }
    Ok(())
}

fn install_actor_ipc(
    kernel: &mut InvocationKernel,
    input: &[u8],
) -> Result<(u32, u32), ServicePvmErrorV2> {
    if input.len() > super::ACTOR_SLICE_INPUT_MAX_BYTES {
        return Err(ServicePvmErrorV2::ActorInputTooLarge);
    }
    let input_len = u32::try_from(input.len()).map_err(|_| ServicePvmErrorV2::ActorIpcExhausted)?;
    let minimum_capacity = input
        .len()
        .checked_add(MIN_ACTOR_OUTPUT_HEADROOM)
        .ok_or(ServicePvmErrorV2::ActorIpcExhausted)?;
    let page_count = u32::try_from(minimum_capacity.div_ceil(javm::PVM_PAGE_SIZE as usize))
        .map_err(|_| ServicePvmErrorV2::ActorIpcExhausted)?;
    let capacity = page_count
        .checked_mul(javm::PVM_PAGE_SIZE)
        .ok_or(ServicePvmErrorV2::ActorIpcExhausted)?;
    if page_count == 0
        || page_count > MAX_ACTOR_IPC_PAGES
        || page_count > kernel.untyped.remaining()
        || !kernel
            .vm_arena
            .vm(kernel.active_vm)
            .cap_table
            .is_empty(ACTOR_IPC_CAP_SLOT)
    {
        return Err(ServicePvmErrorV2::ActorIpcExhausted);
    }

    let backing_offset = kernel
        .untyped
        .retype(page_count)
        .ok_or(ServicePvmErrorV2::ActorIpcExhausted)?;
    if !kernel.backing.write_init_data(backing_offset, input) {
        return Err(ServicePvmErrorV2::ActorIpcSetupFailed);
    }
    kernel.vm_arena.vm_mut(kernel.active_vm).cap_table.set(
        ACTOR_IPC_CAP_SLOT,
        Cap::Data(DataCap::new(backing_offset, page_count)),
    );

    // Exercise the ordinary JAR MAP operation instead of reaching around the
    // capability model to synthesize a mapped address. Preserve the guest's
    // invocation registers around this host-owned setup call.
    let saved = core::array::from_fn::<_, 6, _>(|offset| kernel.active_reg(7 + offset));
    kernel.set_active_reg(7, ACTOR_IPC_BASE_PAGE as u64);
    kernel.set_active_reg(8, 0);
    kernel.set_active_reg(9, page_count as u64);
    kernel.set_active_reg(10, 1); // RW
    kernel.set_active_reg(12, (ACTOR_IPC_CAP_SLOT as u64) << 32);
    let result = kernel.dispatch_ecall(0x02);
    let mapped = kernel.active_reg(7) != RESULT_WHAT
        && matches!(result, DispatchResult::Continue)
        && matches!(
            kernel
                .vm_arena
                .vm(kernel.active_vm)
                .cap_table
                .get(ACTOR_IPC_CAP_SLOT),
            Some(Cap::Data(data))
                if data.base_offset == Some(ACTOR_IPC_BASE_PAGE)
                    && data.access == Some(Access::RW)
                    && data.mapped_page_count() == page_count
        );
    for (offset, value) in saved.into_iter().enumerate() {
        kernel.set_active_reg(7 + offset, value);
    }
    if !mapped {
        return Err(ServicePvmErrorV2::ActorIpcSetupFailed);
    }
    Ok((input_len, capacity))
}

fn crdt_dispatch(work: &WorkEnvelopeV2, ordinal: u32) -> Option<CrdtDispatchV2> {
    CrdtChangeV2::derive_operation_scope(work).map(|change| CrdtDispatchV2 { change, ordinal })
}

fn imported_blob_bytes<'a>(
    imports: &'a RefineImportsV2,
    reference: &BlobRefV2,
) -> Result<&'a [u8], ServicePvmErrorV2> {
    imports
        .blobs
        .binary_search_by_key(&reference.hash, |blob| blob.reference.hash)
        .ok()
        .map(|index| imports.blobs[index].bytes.as_slice())
        .ok_or(ServicePvmErrorV2::InvalidRefineImports)
}

fn imported_private_blob_bytes<'a>(
    imports: &'a RefineImportsV2,
    reference: &BlobRefV2,
) -> Result<&'a [u8], ServicePvmErrorV2> {
    imports
        .private_blobs
        .binary_search_by_key(&reference.hash, |blob| blob.reference.hash)
        .ok()
        .map(|index| imports.private_blobs[index].bytes.as_slice())
        .ok_or(ServicePvmErrorV2::InvalidRefineImports)
}

fn authorization_roles(
    work: &WorkEnvelopeV2,
    imports: &RefineImportsV2,
) -> Result<(Option<u8>, Option<u8>), ServicePvmErrorV2> {
    let (commitment, bytes) = match &work.authorization {
        AuthorizationEvidenceV2::Public | AuthorizationEvidenceV2::SystemCapability { .. } => {
            return Ok((None, None));
        }
        AuthorizationEvidenceV2::Credential {
            credential_commitment,
            bytes,
            ..
        } => {
            let bytes = if bytes.is_empty()
                && work.consistency == super::ConsistencyModeV2::Crdt
                && work.parent_call.is_none()
            {
                imports
                    .blobs
                    .iter()
                    .find(|blob| {
                        Hash::digest(b"vos/credential-commitment/v2", &[&blob.bytes])
                            == *credential_commitment
                    })
                    .map(|blob| blob.bytes.as_slice())
                    .ok_or(ServicePvmErrorV2::InvalidAuthorization)?
            } else {
                bytes.as_slice()
            };
            (*credential_commitment, bytes)
        }
        AuthorizationEvidenceV2::PrivateCredential {
            credential_commitment,
            witness,
            ..
        } => (
            *credential_commitment,
            imported_private_blob_bytes(imports, witness)?,
        ),
    };
    let credential =
        RoleCredentialV2::decode(bytes).map_err(|_| ServicePvmErrorV2::InvalidAuthorization)?;
    // Initial admission binds the credential to the call arguments. Resume
    // work deliberately carries no arguments; its unchanged authorization
    // evidence is instead pinned by the committed workflow identity and exact
    // continuation before this function is reached.
    if credential.holder != work.origin
        || (work.workflow_step == 0 && credential.scope != work.authorization_scope())
        || commitment != Hash::digest(b"vos/credential-commitment/v2", &[bytes])
        // Space-authority assertions do not authenticate actor-local roles.
        // Reject the mixed shape before it can influence caller_role() in
        // the provisional actor execution; guest Accumulate independently
        // enforces the same rule at the commit boundary.
        || (credential.actor_role.is_some()
            && AccumulatedRoleAssertionV2::decode(&credential.authenticator).is_ok())
    {
        return Err(ServicePvmErrorV2::InvalidAuthorization);
    }
    Ok((
        credential.space_role.map(crate::SpaceRole::as_u8),
        credential.actor_role,
    ))
}

fn write_checkpoint_token(
    kernel: &mut InvocationKernel,
    token: &CheckpointTokenV2,
) -> Result<u64, ServicePvmErrorV2> {
    write_suspension_payload(kernel, &token.encode())
}

fn write_await_resume(
    kernel: &mut InvocationKernel,
    resume: &AwaitResumeV2,
) -> Result<u64, ServicePvmErrorV2> {
    write_suspension_payload(kernel, &resume.encode())
}

fn stage_attestation_proof(
    kernel: &mut InvocationKernel,
    proof: &[u8],
) -> Result<(u32, u32), ServicePvmErrorV2> {
    let capacity = match kernel.vm_arena.vm(kernel.active_vm).cap_table.get(0) {
        Some(Cap::Data(data))
            if data.base_offset == Some(ACTOR_IPC_BASE_PAGE) && data.access == Some(Access::RW) =>
        {
            data.mapped_page_count() as usize * javm::PVM_PAGE_SIZE as usize
        }
        _ => return Err(ServicePvmErrorV2::ActorIpcSetupFailed),
    };
    if proof.is_empty()
        || proof.len() > super::MAX_ATTESTATION_PROOF_BYTES
        || proof.len() > capacity
    {
        return Err(ServicePvmErrorV2::ActorIpcExhausted);
    }
    let offset = capacity - proof.len();
    let address = ACTOR_IPC_BASE_PAGE as usize * javm::PVM_PAGE_SIZE as usize + offset;
    let address = u32::try_from(address).map_err(|_| ServicePvmErrorV2::ActorIpcExhausted)?;
    if !kernel.write_data_cap_window(address, proof) {
        return Err(ServicePvmErrorV2::ActorIpcSetupFailed);
    }
    Ok((
        u32::try_from(offset).map_err(|_| ServicePvmErrorV2::ActorIpcExhausted)?,
        u32::try_from(proof.len()).map_err(|_| ServicePvmErrorV2::ActorIpcExhausted)?,
    ))
}

fn write_suspension_payload(
    kernel: &mut InvocationKernel,
    encoded: &[u8],
) -> Result<u64, ServicePvmErrorV2> {
    let address = u32::try_from(kernel.active_reg(7))
        .map_err(|_| ServicePvmErrorV2::CheckpointTokenWriteFailed)?;
    let capacity = usize::try_from(kernel.active_reg(8))
        .map_err(|_| ServicePvmErrorV2::CheckpointTokenWriteFailed)?;
    let cap = u8::try_from(kernel.active_reg(12))
        .map_err(|_| ServicePvmErrorV2::CheckpointTokenWriteFailed)?;
    if cap as u64 != ACTOR_STACK_OBJECT_CAP
        || encoded.len() > capacity
        || !kernel.write_data_cap_window(address, &encoded)
    {
        return Err(ServicePvmErrorV2::CheckpointTokenWriteFailed);
    }
    u64::try_from(encoded.len()).map_err(|_| ServicePvmErrorV2::CheckpointTokenWriteFailed)
}

fn capture_checkpoint(
    kernel: &mut InvocationKernel,
    work: &WorkEnvelopeV2,
    actor_runtime: &ActorRefineRuntimeV2,
) -> Result<
    (
        ImportedBlobV2,
        KernelSnapshot,
        Option<super::CallId>,
        Option<super::ActorId>,
        Vec<super::ActorId>,
    ),
    ServicePvmErrorV2,
> {
    let awaited = kernel.active_reg(10) == super::AWAIT_SUSPEND_MAGIC;
    let await_ordinal = if awaited {
        kernel.active_reg(9)
    } else {
        work.workflow_step
    };
    let pending_call = awaited.then(|| work.invocation.call_id(await_ordinal));
    let snapshot = kernel
        .snapshot()
        .map_err(|_| ServicePvmErrorV2::SnapshotFailed)?;
    if snapshot.pending_call.slot != crate::abi::hostcall::SUSPEND as u8 {
        return Err(ServicePvmErrorV2::SnapshotFailed);
    }
    let suspended_actors = suspended_actor_stack(&snapshot, actor_runtime)?;
    let pending_actor = awaited
        .then(|| {
            actor_runtime
                .actor_for_vm(snapshot.active_vm)
                .ok_or(ServicePvmErrorV2::SnapshotFailed)
        })
        .transpose()?;
    let continuation = ContinuationSnapshotV2 {
        snapshot_version: super::SNAPSHOT_VERSION,
        jar_semantics: super::EXECUTION_SEMANTICS_ID,
        vos_abi: super::ABI_VERSION,
        service: work.service.clone(),
        invocation: work.invocation,
        checkpoint_step: work.workflow_step,
        actor: work.target,
        actor_deployment: work.target_deployment,
        actor_program: work.target_program,
        programs: actor_runtime.program_layout.clone(),
        await_ordinal,
        pending_call,
        pending_actor,
        causal_context: work.causal_context.clone(),
        suspended_actors: suspended_actors.clone(),
        kernel_snapshot: snapshot.to_bytes(),
    };
    let bytes = continuation.encode();
    let reference = BlobRefV2::of_bytes(&bytes);
    Ok((
        ImportedBlobV2 { reference, bytes },
        snapshot,
        pending_call,
        pending_actor,
        suspended_actors,
    ))
}

fn suspended_actor_stack(
    snapshot: &KernelSnapshot,
    actor_runtime: &ActorRefineRuntimeV2,
) -> Result<Vec<super::ActorId>, ServicePvmErrorV2> {
    let mut suspended = snapshot
        .call_stack
        .iter()
        .map(|frame| frame.caller_vm_id)
        .chain(core::iter::once(snapshot.active_vm))
        .filter(|vm| *vm != 0)
        .map(|vm| {
            actor_runtime
                .actor_for_vm(vm)
                .ok_or(ServicePvmErrorV2::SnapshotFailed)
        })
        .collect::<Result<Vec<_>, _>>()?;
    suspended.sort_unstable();
    suspended.dedup();
    if suspended.is_empty() || suspended.binary_search(&actor_runtime.target).is_err() {
        return Err(ServicePvmErrorV2::SnapshotFailed);
    }
    Ok(suspended)
}

fn run_refine_kernel<H: RefineProtocolHostV2>(
    mut kernel: InvocationKernel,
    host: &H,
    backend: javm::PvmBackend,
    fresh: bool,
    suspension_work: Option<&WorkEnvelopeV2>,
    invocation_layout: Option<(&[u8], &[DormantProgram<'_>])>,
    mut actor_runtime: Option<ActorRefineRuntimeV2>,
    previously_suspended: Vec<super::ActorId>,
    mut exported_blobs: Vec<ImportedBlobV2>,
    mut trace: Option<RefineTraceRecorderV2>,
) -> Result<ServicePvmOutputV2, ServicePvmErrorV2> {
    if fresh {
        kernel
            .vm_arena
            .vm_mut(kernel.active_vm)
            .transition(VmState::Running)
            .map_err(|_| ServicePvmErrorV2::InvalidVmLifecycle)?;
        kernel.set_entry_ic(REFINE_ENTRY_IC);
    }
    let starting_gas = kernel.active_gas();

    loop {
        let result = if let Some(recorder) = trace.as_mut() {
            kernel
                .run_observed(|event| recorder.instruction(event))
                .map_err(|_| ServicePvmErrorV2::TraceBackendRequired)?
        } else {
            kernel.run()
        };
        match result {
            KernelResult::Halt => {
                if let Some(runtime) = actor_runtime.as_mut() {
                    let missing = runtime.take_missing_storage_rows();
                    if !missing.is_empty() {
                        return Err(ServicePvmErrorV2::ActorStorageWitnessRequired(missing));
                    }
                }
                let bytes = read_output(&kernel)?;
                let task_gas_used = actor_runtime
                    .as_ref()
                    .map(|runtime| runtime.task_gas_used)
                    .unwrap_or(0);
                let parent_gas_used = starting_gas.saturating_sub(kernel.active_gas());
                let Some(gas_used) = parent_gas_used
                    .checked_add(task_gas_used)
                    .filter(|used| *used <= starting_gas)
                else {
                    return Err(ServicePvmErrorV2::OutOfGas {
                        vm: kernel.active_vm,
                        pc: kernel.vm_arena.vm(kernel.active_vm).pc,
                    });
                };
                if actor_runtime.as_ref().is_some_and(|runtime| {
                    runtime.record_intents.values().any(|intents| *intents != 0)
                }) {
                    return Err(ServicePvmErrorV2::RefineHostRejected(
                        crate::abi::hostcall::PROVABLE_RECORD_INTENT as u8,
                    ));
                }
                let producer_records = actor_runtime
                    .as_mut()
                    .map(ActorRefineRuntimeV2::take_producer_records)
                    .unwrap_or_default();
                let trace = trace.map(|mut recorder| {
                    recorder.output(&bytes, gas_used, &exported_blobs);
                    recorder.finish()
                });
                return Ok(ServicePvmOutputV2 {
                    bytes,
                    gas_used,
                    exported_blobs,
                    producer_records,
                    trace,
                });
            }
            KernelResult::Panic => {
                if let Some(runtime) = actor_runtime.as_mut() {
                    let missing = runtime.take_missing_storage_rows();
                    if !missing.is_empty() {
                        return Err(ServicePvmErrorV2::ActorStorageWitnessRequired(missing));
                    }
                }
                return Err(ServicePvmErrorV2::Panic {
                    vm: kernel.active_vm,
                    pc: kernel.vm_arena.vm(kernel.active_vm).pc,
                });
            }
            KernelResult::OutOfGas => {
                if let Some(runtime) = actor_runtime.as_mut() {
                    let missing = runtime.take_missing_storage_rows();
                    if !missing.is_empty() {
                        return Err(ServicePvmErrorV2::ActorStorageWitnessRequired(missing));
                    }
                }
                return Err(ServicePvmErrorV2::OutOfGas {
                    vm: kernel.active_vm,
                    pc: kernel.vm_arena.vm(kernel.active_vm).pc,
                });
            }
            KernelResult::PageFault(address) => {
                if let Some(runtime) = actor_runtime.as_mut() {
                    let missing = runtime.take_missing_storage_rows();
                    if !missing.is_empty() {
                        return Err(ServicePvmErrorV2::ActorStorageWitnessRequired(missing));
                    }
                }
                return Err(ServicePvmErrorV2::PageFault {
                    vm: kernel.active_vm,
                    address,
                });
            }
            KernelResult::ProtocolCall { slot } => {
                if let Some(recorder) = trace.as_mut() {
                    recorder.protocol_call(slot, &kernel);
                }
                if let Some(runtime) = actor_runtime.as_mut() {
                    match runtime.handle(slot, &mut kernel, trace.as_mut()) {
                        Ok(Some([result0, result1])) => {
                            kernel
                                .resume_protocol_call(result0, result1)
                                .map_err(|_| ServicePvmErrorV2::InvalidProtocolResume)?;
                            if let Some(recorder) = trace.as_mut() {
                                recorder.protocol_resume(slot, result0, result1);
                            }
                            continue;
                        }
                        Ok(None) => {}
                        Err(error) => {
                            let missing = runtime.take_missing_storage_rows();
                            if !missing.is_empty() {
                                return Err(ServicePvmErrorV2::ActorStorageWitnessRequired(
                                    missing,
                                ));
                            }
                            return Err(error);
                        }
                    }
                }
                if let Some(runtime) = actor_runtime.as_mut() {
                    let missing = runtime.take_missing_storage_rows();
                    if !missing.is_empty() {
                        return Err(ServicePvmErrorV2::ActorStorageWitnessRequired(missing));
                    }
                }
                if !refine_protocol_call_is_pure(slot) {
                    return Err(ServicePvmErrorV2::ForbiddenRefineProtocolCall(slot));
                }
                if slot == crate::abi::hostcall::SUSPEND as u8 {
                    if let Some(work) = suspension_work {
                        if work.private_arguments.is_some() {
                            // The hydrated plaintext exists only in this
                            // Local invocation. A kernel snapshot would copy
                            // it back into the consensus service image.
                            return Err(ServicePvmErrorV2::RefineHostRejected(slot));
                        }
                        let runtime = actor_runtime
                            .as_ref()
                            .ok_or(ServicePvmErrorV2::InvalidContinuation)?;
                        if runtime.has_record_activity() {
                            // A kernel snapshot contains the complete parent
                            // address space. Once a recorded Task was even
                            // attempted, that memory may contain its private
                            // invoke buffer; no continuation may export it.
                            return Err(ServicePvmErrorV2::RefineHostRejected(slot));
                        }
                        let (artifact, snapshot, pending_call, pending_actor, suspended) =
                            capture_checkpoint(&mut kernel, work, runtime)?;
                        let (service_program, dormant) =
                            invocation_layout.ok_or(ServicePvmErrorV2::InvalidContinuation)?;
                        let mut finalization = InvocationKernel::restore_with_dormant_programs(
                            service_program,
                            dormant,
                            &snapshot,
                            backend,
                        )
                        .map_err(|_| ServicePvmErrorV2::ContinuationMismatch)?;
                        let expected = work
                            .imported_actors
                            .iter()
                            .find(|actor| actor.actor == work.target)
                            .and_then(|actor| actor.continuation.as_ref())
                            .map(|continuation| continuation.hash);
                        let token_len = write_checkpoint_token(
                            &mut finalization,
                            &CheckpointTokenV2 {
                                input: work.input_id(),
                                base: work.base.clone(),
                                work_hash: work.hash(),
                                resume_work: (work.workflow_step != 0)
                                    .then(|| alloc::boxed::Box::new(work.clone())),
                                base_causal_height: work.base_causal_height,
                                change: crdt_dispatch(work, 0),
                                expected,
                                replacement: Some(artifact.reference.clone()),
                                pending_call,
                                pending_actor,
                                previously_suspended: previously_suspended.clone(),
                                suspended,
                            },
                        )?;
                        finalization
                            .resume_protocol_call(0, token_len)
                            .map_err(|_| ServicePvmErrorV2::InvalidProtocolResume)?;
                        if let Some(recorder) = trace.as_mut() {
                            recorder.checkpoint(&artifact);
                            recorder.protocol_resume(slot, 0, token_len);
                        }
                        kernel = finalization;
                        exported_blobs.push(artifact);
                        continue;
                    }
                }
                let mechanical_result = handle_mechanical_call(slot, &mut kernel);
                if let Some([result0, result1]) = mechanical_result {
                    kernel
                        .resume_protocol_call(result0, result1)
                        .map_err(|_| ServicePvmErrorV2::InvalidProtocolResume)?;
                    if let Some(recorder) = trace.as_mut() {
                        recorder.protocol_resume(slot, result0, result1);
                    }
                    continue;
                }
                let mut registers = [0; 13];
                for (index, register) in registers.iter_mut().enumerate() {
                    *register = kernel.active_reg(index);
                }
                let [result0, result1] = host.handle(slot, &registers, &mut kernel)?;
                kernel
                    .resume_protocol_call(result0, result1)
                    .map_err(|_| ServicePvmErrorV2::InvalidProtocolResume)?;
                if let Some(recorder) = trace.as_mut() {
                    recorder.protocol_resume(slot, result0, result1);
                }
            }
        }
    }
}

fn install_refine_scheduler_caps(kernel: &mut InvocationKernel) {
    // These are VOS scheduler capabilities, not JAM protocol slots. The
    // nondeterministic BOOT_CONTEXT/NOW_MS seams are intentionally absent from
    // v2 Refine.
    for slot in [
        crate::abi::hostcall::ACTOR_PRIVATE_FETCH as u8,
        crate::crypto::ECALL_BLAKE2B_COMPRESS as u8,
        crate::abi::hostcall::GROW_HEAP as u8,
        crate::abi::hostcall::DEBUG_WRITE as u8,
        crate::abi::hostcall::SUSPEND as u8,
    ] {
        kernel
            .vm_arena
            .vm_mut(kernel.active_vm)
            .cap_table
            .set(slot, Cap::Protocol(ProtocolCap { id: slot }));
    }
}

fn install_actor_scheduler_caps(kernel: &mut InvocationKernel, actor_count: usize) {
    for vm in 1..=actor_count {
        for slot in [
            crate::abi::hostcall::ACTOR_PRIVATE_FETCH as u8,
            crate::abi::hostcall::ACTOR_EFFECT_EXPORT as u8,
            crate::abi::hostcall::STORAGE_R as u8,
            crate::abi::hostcall::INVOKE as u8,
            crate::abi::hostcall::PROVABLE_RECORD_INTENT as u8,
            crate::crypto::ECALL_BLAKE2B_COMPRESS as u8,
            crate::abi::hostcall::GROW_HEAP as u8,
            crate::abi::hostcall::DEBUG_WRITE as u8,
            crate::abi::hostcall::SUSPEND as u8,
        ] {
            kernel
                .vm_arena
                .vm_mut(vm as u16)
                .cap_table
                .set(slot, Cap::Protocol(ProtocolCap { id: slot }));
        }
    }
}

fn install_accumulate_scheduler_caps(kernel: &mut InvocationKernel) {
    // Accumulate never executes actor calls or suspension. These supplied
    // capabilities are deterministic hashing, mechanical VM support,
    // consensus-bound availability/finality lookups, and diagnostics.
    for slot in [
        crate::crypto::ECALL_BLAKE2B_COMPRESS as u8,
        crate::abi::hostcall::GROW_HEAP as u8,
        crate::abi::hostcall::DEBUG_WRITE as u8,
        crate::abi::hostcall::PROOF_VERIFY as u8,
        crate::abi::hostcall::ROLE_CREDENTIAL_VERIFY as u8,
        crate::abi::hostcall::RECEIPT_VERIFY as u8,
        crate::abi::hostcall::INSTALL_AUTH_VERIFY as u8,
        crate::abi::hostcall::PROGRAM_LOOKUP as u8,
        crate::abi::hostcall::ACCUMULATION_TIMESLOT as u8,
    ] {
        kernel
            .vm_arena
            .vm_mut(kernel.active_vm)
            .cap_table
            .set(slot, Cap::Protocol(ProtocolCap { id: slot }));
    }
}

fn handle_mechanical_call(slot: u8, kernel: &mut InvocationKernel) -> Option<[u64; 2]> {
    use crate::abi::error;

    match slot as u32 {
        crate::abi::hostcall::GAS => Some([kernel.active_gas(), 0]),
        crate::abi::hostcall::GROW_HEAP => Some([error::HOST_OK, 0]),
        // Debugging is deliberately non-observable to consensus execution.
        // The guest only observes that its complete input was accepted.
        crate::abi::hostcall::DEBUG_WRITE => Some([kernel.active_reg(8), 0]),
        crate::crypto::ECALL_BLAKE2B_COMPRESS => {
            let h_address = u32::try_from(kernel.active_reg(7)).ok()?;
            let m_address = u32::try_from(kernel.active_reg(8)).ok()?;
            let h = kernel.read_data_cap_window(h_address, 64)?;
            let m = kernel.read_data_cap_window(m_address, 128)?;
            let mut h: [u8; 64] = h.try_into().ok()?;
            let m: [u8; 128] = m.try_into().ok()?;
            crate::crypto::blake2b::host_compress_block(
                &mut h,
                &m,
                kernel.active_reg(9) as u128,
                kernel.active_reg(10) != 0,
            );
            kernel
                .write_data_cap_window(h_address, &h)
                .then_some([error::HOST_OK, 0])
        }
        _ => None,
    }
}

fn validate_service_entries(program: &[u8]) -> Result<(), ServicePvmErrorV2> {
    let parsed = parse_blob(program).ok_or(ServicePvmErrorV2::InvalidProgram)?;
    let argument_cap = parsed
        .caps
        .iter()
        .find(|cap| cap.cap_index == 0 && cap.cap_type == CapEntryType::Data)
        .ok_or(ServicePvmErrorV2::InvalidServiceEntries)?;
    if argument_cap.page_count < SERVICE_ARGUMENT_PAGES_V2 {
        return Err(ServicePvmErrorV2::InvalidServiceEntries);
    }
    let code_cap = parsed
        .caps
        .iter()
        .find(|cap| cap.cap_index == parsed.header.invoke_cap && cap.cap_type == CapEntryType::Code)
        .ok_or(ServicePvmErrorV2::InvalidProgram)?;
    let code = parse_code_blob(cap_data(code_cap, parsed.data_section))
        .ok_or(ServicePvmErrorV2::InvalidProgram)?;

    // The transpiler emits one five-byte GP jump at IC 0 and another at IC 5.
    // Requiring both prevents an actor/refine-only blob (whose second entry is
    // a trap) from being installed as infrastructure by mistake.
    if code.code.get(REFINE_ENTRY_IC as usize) != Some(&40)
        || code.code.get(super::ACCUMULATE_ENTRY_IC as usize) != Some(&40)
        || code.bitmask.get(REFINE_ENTRY_IC as usize) != Some(&1)
        || code.bitmask.get(super::ACCUMULATE_ENTRY_IC as usize) != Some(&1)
    {
        return Err(ServicePvmErrorV2::InvalidServiceEntries);
    }
    Ok(())
}

/// Reject actor manifests that occupy capability-table slots supplied by the
/// VOS root-tree scheduler.
///
/// Slot 0 remains the actor's canonical argument DATA cap and is temporarily
/// moved by the service around a nested CALL. The per-peer CALLABLE window and
/// that temporary save slot must be empty in every application manifest.
pub fn validate_actor_program_layout(program: &[u8]) -> Result<(), ServicePvmErrorV2> {
    let parsed = parse_blob(program).ok_or(ServicePvmErrorV2::InvalidProgram)?;
    let callable_end = super::ACTOR_CALLABLE_BASE_SLOT
        .checked_add(MAX_ROOT_TREE_ACTORS as u8)
        .ok_or(ServicePvmErrorV2::InvalidActorCapabilityLayout)?;
    if parsed.caps.iter().any(|cap| {
        (super::ACTOR_CALLABLE_BASE_SLOT..callable_end).contains(&cap.cap_index)
            || cap.cap_index == super::ACTOR_SAVED_ARGS_CAP_SLOT
            || cap.cap_index == super::ACTOR_NESTED_IPC_CAP_SLOT
            || cap.cap_index == crate::abi::hostcall::ACTOR_PRIVATE_FETCH as u8
            || cap.cap_index == crate::abi::hostcall::ACTOR_EFFECT_EXPORT as u8
            || cap.cap_index == crate::abi::hostcall::STORAGE_R as u8
            || cap.cap_index == crate::abi::hostcall::INVOKE as u8
            || cap.cap_index == crate::abi::hostcall::PROVABLE_RECORD_INTENT as u8
    }) {
        return Err(ServicePvmErrorV2::InvalidActorCapabilityLayout);
    }
    Ok(())
}

fn read_output(kernel: &InvocationKernel) -> Result<Vec<u8>, ServicePvmErrorV2> {
    let address =
        u32::try_from(kernel.active_reg(7)).map_err(|_| ServicePvmErrorV2::UnreadableOutput)?;
    let len =
        u32::try_from(kernel.active_reg(8)).map_err(|_| ServicePvmErrorV2::UnreadableOutput)?;
    kernel
        .read_data_cap_window(address, len)
        .ok_or(ServicePvmErrorV2::UnreadableOutput)
}

/// Protocol capabilities that can be implemented without access to mutable
/// service state. Every state-changing JAM capability (including storage
/// writes, transfers, service management, output publication, and preimage
/// provision) is absent from this list.
fn refine_protocol_call_is_pure(slot: u8) -> bool {
    matches!(
        slot as u32,
        crate::abi::hostcall::GAS
            | crate::abi::hostcall::ACTOR_PRIVATE_FETCH
            | crate::abi::hostcall::ACTOR_EFFECT_EXPORT
            | crate::crypto::ECALL_BLAKE2B_COMPRESS
            | crate::abi::hostcall::FETCH
            | crate::abi::hostcall::COMPILE
            | crate::abi::hostcall::PREIMAGE_LOOKUP
            | crate::abi::hostcall::GROW_HEAP
            | crate::abi::hostcall::DEBUG_WRITE
            | crate::abi::hostcall::SUSPEND
    )
}

#[cfg(test)]
mod tests {
    use super::*;

    const SYNTHETIC_SERVICE_GAS: u64 = 10_000_000;
    use grey_transpiler::assembler::Reg;

    #[test]
    fn continued_vm_indices_ignore_later_directory_insertions() {
        let target = super::super::ActorId([5; 32]);
        let child = super::super::ActorId([9; 32]);
        let programs = vec![
            super::super::ContinuationProgramV2 {
                actor: target,
                deployment: super::super::DeploymentId([6; 32]),
                program: ProgramId([7; 32]),
            },
            super::super::ContinuationProgramV2 {
                actor: child,
                deployment: super::super::DeploymentId([10; 32]),
                program: ProgramId([11; 32]),
            },
        ];

        assert_eq!(continued_actor_vm_index(&programs, target, target), Some(1));
        assert_eq!(continued_actor_vm_index(&programs, target, child), Some(2));
        assert_eq!(
            continued_actor_vm_index(&programs, target, super::super::ActorId([3; 32])),
            None,
            "an actor inserted before the target in the current directory has no VM in the frozen kernel"
        );
    }

    #[test]
    fn disclosed_and_private_role_credentials_feed_the_same_actor_role() {
        let origin = super::super::Origin::Member(super::super::SubjectId([41; 32]));
        let mut work = WorkEnvelopeV2 {
            external_actors: vec![],
            service: super::super::ServiceIdentityV2 {
                space: super::super::SpaceId([1; 32]),
                root_service: super::super::RootServiceId([2; 32]),
                deployment: super::super::DeploymentId([3; 32]),
                service_program: ProgramId([4; 32]),
                service_abi: super::super::ABI_VERSION,
                execution_semantics: super::super::EXECUTION_SEMANTICS_ID,
                gas_schedule: super::super::GasScheduleV2::new(1_000_000_000, 5_000_000_000),
            },
            invocation: super::super::InvocationId([5; 32]),
            workflow_step: 0,
            logical_timeslot: 1,
            target: super::super::ActorId([6; 32]),
            target_deployment: super::super::DeploymentId([3; 32]),
            target_program: ProgramId([7; 32]),
            method: "check".into(),
            arguments: vec![8],
            private_arguments: None,
            origin,
            authorization: AuthorizationEvidenceV2::Public,
            causal_parent: None,
            parent_call: None,
            causal_context: None,
            awaited_reply: None,
            awaited_timeout: None,
            consistency: super::super::ConsistencyModeV2::Local,
            base: super::super::ConsistencyBaseV2::Linear {
                revision: 0,
                state_root: Hash([9; 32]),
            },
            base_causal_height: None,
            imported_actors: vec![],
            imported_blobs: vec![],
            proof_requested: true,
        };
        let credential = RoleCredentialV2 {
            holder: origin,
            scope: work.authorization_scope(),
            space_role: Some(crate::SpaceRole::Developer),
            actor_role: Some(2),
            authenticator: b"signed space grant".to_vec(),
        };
        let policy =
            super::super::space_role_policy_hash(crate::SpaceRole::Member.as_u8()).unwrap();
        let disclosed = credential.disclosed_evidence(policy);
        work.authorization = disclosed.clone();
        assert_eq!(
            authorization_roles(&work, &RefineImportsV2::default()),
            Ok((Some(crate::SpaceRole::Developer.as_u8()), Some(2)))
        );
        work.arguments = vec![9];
        assert_eq!(
            authorization_roles(&work, &RefineImportsV2::default()),
            Err(ServicePvmErrorV2::InvalidAuthorization),
            "the initial credential scope binds the application arguments"
        );
        work.workflow_step = 1;
        work.arguments.clear();
        assert_eq!(
            authorization_roles(&work, &RefineImportsV2::default()),
            Ok((Some(crate::SpaceRole::Developer.as_u8()), Some(2))),
            "an exact continuation omits dead arguments but retains the authenticated evidence"
        );
        work.workflow_step = 0;
        work.arguments = vec![8];

        let authority_actor = super::super::ActorId([10; 32]);
        let claim = super::super::RoleAuthorizationClaimV2 {
            space: work.service.space,
            holder: origin,
            role: crate::SpaceRole::Developer,
            audience: work.service.clone(),
            invocation: work.invocation,
            scope: credential.scope,
            target: work.target,
            method: work.method.clone(),
            policy,
        };
        let authority_service = super::super::ServiceIdentityV2 {
            root_service: super::super::RootServiceId([11; 32]),
            deployment: super::super::DeploymentId([12; 32]),
            service_program: ProgramId([13; 32]),
            ..work.service.clone()
        };
        let assertion = AccumulatedRoleAssertionV2 {
            receipt: super::super::AccumulationReceiptV2 {
                service: authority_service,
                accepted_transition: Hash([14; 32]),
                reply_commitment: Some(claim.authority_reply(authority_actor).commitment()),
                outbox_commitment: None,
                resulting_state_root: Some(Hash([15; 32])),
                resulting_crdt_heads: vec![],
                sequence: 1,
                checkpoint: 0,
                consistency: super::super::ConsistencyModeV2::Local,
            },
            claim,
        };
        let mut forged_actor_role = credential.clone();
        forged_actor_role.authenticator = assertion.encode();
        work.authorization = forged_actor_role.disclosed_evidence(policy);
        assert_eq!(
            authorization_roles(&work, &RefineImportsV2::default()),
            Err(ServicePvmErrorV2::InvalidAuthorization),
            "a space assertion must not populate handler-side caller_role()"
        );

        let (private, witness) = credential.private_evidence(policy);
        work.authorization = private;
        let imports = RefineImportsV2 {
            programs: vec![],
            blobs: vec![],
            private_blobs: vec![witness],
        };
        assert_eq!(
            authorization_roles(&work, &imports),
            Ok((Some(crate::SpaceRole::Developer.as_u8()), Some(2)))
        );

        work.origin = super::super::Origin::Member(super::super::SubjectId([42; 32]));
        assert_eq!(
            authorization_roles(&work, &imports),
            Err(ServicePvmErrorV2::InvalidAuthorization)
        );
    }

    fn emit_instruction(code: &mut Vec<u8>, bitmask: &mut Vec<u8>, bytes: &[u8]) {
        code.extend_from_slice(bytes);
        bitmask.push(1);
        bitmask.resize(code.len(), 0);
    }

    fn emit_halt(code: &mut Vec<u8>, bitmask: &mut Vec<u8>) {
        let mut load = vec![20, Reg::T0 as u8];
        load.extend_from_slice(&(javm::PVM_HALT_ADDR as u64).to_le_bytes());
        emit_instruction(code, bitmask, &load);
        let mut jump = vec![50, Reg::T0 as u8];
        jump.extend_from_slice(&0u32.to_le_bytes());
        emit_instruction(code, bitmask, &jump);
    }

    fn service_program(
        refine_call: Option<u32>,
        accumulate_call: Option<u32>,
        accumulate_panics: bool,
    ) -> Vec<u8> {
        let mut code = vec![40, 0, 0, 0, 0, 40, 0, 0, 0, 0];
        let mut bitmask = vec![1, 0, 0, 0, 0, 1, 0, 0, 0, 0];

        let refine_body = code.len();
        if let Some(slot) = refine_call {
            let mut call = vec![10];
            call.extend_from_slice(&slot.to_le_bytes());
            emit_instruction(&mut code, &mut bitmask, &call);
        }
        emit_halt(&mut code, &mut bitmask);

        let accumulate_body = code.len();
        if let Some(slot) = accumulate_call {
            emit_instruction(
                &mut code,
                &mut bitmask,
                &[100, (Reg::S0 as u8) | ((Reg::A0 as u8) << 4)],
            );
            emit_instruction(
                &mut code,
                &mut bitmask,
                &[100, (Reg::S1 as u8) | ((Reg::A1 as u8) << 4)],
            );
            let mut call = vec![10];
            call.extend_from_slice(&slot.to_le_bytes());
            emit_instruction(&mut code, &mut bitmask, &call);
            emit_instruction(
                &mut code,
                &mut bitmask,
                &[100, (Reg::A0 as u8) | ((Reg::S0 as u8) << 4)],
            );
            emit_instruction(
                &mut code,
                &mut bitmask,
                &[100, (Reg::A1 as u8) | ((Reg::S1 as u8) << 4)],
            );
        }
        if accumulate_panics {
            emit_instruction(&mut code, &mut bitmask, &[0]);
        } else {
            emit_halt(&mut code, &mut bitmask);
        }

        code[1..5].copy_from_slice(&(refine_body as i32).to_le_bytes());
        code[6..10].copy_from_slice(&((accumulate_body as i32) - 5).to_le_bytes());

        let program = grey_transpiler::emitter::build_service_program_with_args_pages(
            &code,
            &bitmask,
            &[],
            &[],
            &[],
            1,
            0,
            4,
            SERVICE_ARGUMENT_PAGES_V2,
        );
        assert!(
            parse_blob(&program).is_some(),
            "synthetic service blob must remain parseable"
        );
        program
    }

    fn two_entry_program(refine_call: Option<u32>) -> Vec<u8> {
        service_program(refine_call, None, false)
    }

    #[derive(Default)]
    struct RecordingAccumulateHost {
        committed_calls: usize,
        reject_commit: bool,
    }

    #[derive(Default)]
    struct RecordingTransaction {
        staged_calls: usize,
    }

    impl AccumulateTransactionV2 for RecordingTransaction {
        fn handle(
            &mut self,
            slot: u8,
            _registers: &[u64; 13],
            _kernel: &mut InvocationKernel,
        ) -> Result<[u64; 2], ServicePvmErrorV2> {
            if slot != crate::abi::hostcall::STORAGE_W as u8 {
                return Err(ServicePvmErrorV2::AccumulateHostRejected(slot));
            }
            self.staged_calls += 1;
            Ok([0, 0])
        }
    }

    impl AccumulateProtocolHostV2 for RecordingAccumulateHost {
        type Transaction = RecordingTransaction;

        fn begin(&mut self) -> Result<Self::Transaction, ServicePvmErrorV2> {
            Ok(RecordingTransaction::default())
        }

        fn commit(&mut self, transaction: Self::Transaction) -> Result<(), ServicePvmErrorV2> {
            if self.reject_commit {
                return Err(ServicePvmErrorV2::AccumulateCommitRejected);
            }
            self.committed_calls += transaction.staged_calls;
            Ok(())
        }
    }

    fn accumulate_result(commit: bool) -> Vec<u8> {
        use crate::v2::{
            AccumulationReceiptV2, ConsistencyModeV2, DeploymentId, Hash, RootServiceId,
            ServiceIdentityV2,
        };

        let mut receipt = AccumulationReceiptV2 {
            service: ServiceIdentityV2 {
                space: crate::v2::SpaceId([0; 32]),
                root_service: RootServiceId([1; 32]),
                deployment: DeploymentId([2; 32]),
                service_program: ProgramId([3; 32]),
                service_abi: crate::v2::ABI_VERSION,
                execution_semantics: crate::v2::EXECUTION_SEMANTICS_ID,
                gas_schedule: crate::v2::GasScheduleV2::new(1_000_000_000, 5_000_000_000),
            },
            accepted_transition: Hash([4; 32]),
            reply_commitment: None,
            outbox_commitment: None,
            resulting_state_root: Some(Hash([5; 32])),
            resulting_crdt_heads: Vec::new(),
            sequence: 1,
            checkpoint: 0,
            consistency: ConsistencyModeV2::Local,
        };
        if commit {
            AccumulationResultV2::Accepted {
                receipt,
                published: crate::v2::PublishedEffectsV2::default(),
                duplicate: false,
            }
        } else {
            let actor = crate::v2::ActorId([6; 32]);
            let invocation = crate::v2::InvocationId([9; 32]);
            let reply = crate::v2::ReplyRecordV2 {
                call_id: invocation.root_reply_id(),
                producer: actor,
                result: vec![11; 4],
            };
            receipt.reply_commitment = Some(reply.commitment());
            let statement = crate::attestation::AttestationStatementV3 {
                statement_version: crate::v2::ATTESTATION_STATEMENT_VERSION,
                space: receipt.service.space,
                actor,
                producer_name: "attested".into(),
                producer: crate::v2::ProducerId([6; 32]),
                deployment: receipt.service.deployment,
                actor_program: ProgramId([7; 32]),
                method: "attested".into(),
                schema: Hash([8; 32]),
                invocation,
                reply_call: reply.call_id,
                before: crate::attestation::StateCommitmentV3::Linear(Hash([10; 32])),
                after: crate::attestation::StateCommitmentV3::Linear(Hash([5; 32])),
                claim_commitment: Hash::digest(b"vos/attestation-claim/v3", &[&reply.result]),
                input_commitment: Hash([12; 32]),
                authorization_policy: Hash([13; 32]),
                accumulation_receipt: receipt.clone(),
            };
            AccumulationResultV2::Prepared(crate::attestation::AttestationPreparationV2 {
                receipt,
                statement,
                committed_proof: None,
            })
        }
        .encode()
    }

    #[test]
    fn physical_refine_entry_is_deterministic_and_uses_gp_arguments() {
        let program = two_entry_program(None);
        let service = ServicePvmV2::new(program.clone(), ProgramId::of_pvm(&program)).unwrap();
        let first = service
            .refine(
                b"work-envelope",
                SYNTHETIC_SERVICE_GAS,
                &NoRefineProtocolHostV2,
            )
            .unwrap();
        let second = service
            .refine(
                b"work-envelope",
                SYNTHETIC_SERVICE_GAS,
                &NoRefineProtocolHostV2,
            )
            .unwrap();
        assert_eq!(first, second);
        assert_eq!(first.bytes, b"work-envelope");
    }

    #[test]
    fn refine_rejects_persistent_protocol_calls_before_host_dispatch() {
        let program = two_entry_program(Some(crate::abi::hostcall::STORAGE_W));
        let service = ServicePvmV2::new(program.clone(), ProgramId::of_pvm(&program)).unwrap();
        assert_eq!(
            service.refine(&[], SYNTHETIC_SERVICE_GAS, &NoRefineProtocolHostV2),
            Err(ServicePvmErrorV2::ForbiddenRefineProtocolCall(
                crate::abi::hostcall::STORAGE_W as u8,
            ))
        );
    }

    #[test]
    fn service_identity_and_both_physical_entries_are_mandatory() {
        let program = two_entry_program(None);
        assert!(matches!(
            ServicePvmV2::new(program.clone(), ProgramId([0; 32])),
            Err(ServicePvmErrorV2::ProgramIdMismatch)
        ));

        let actor = grey_transpiler::assembler::Assembler::new().build();
        assert!(matches!(
            ServicePvmV2::new(actor.clone(), ProgramId::of_pvm(&actor)),
            Err(ServicePvmErrorV2::InvalidServiceEntries)
        ));
    }

    #[test]
    fn root_tree_actor_limit_matches_the_pinned_jar_kernel() {
        assert_eq!(
            MAX_ROOT_TREE_ACTORS + 1,
            javm::vm_pool::MAX_CODE_CAPS,
            "one shared JAR code-capability entry is consumed by the service",
        );

        let service = two_entry_program(None);
        let actor = grey_transpiler::assembler::Assembler::new().build();
        let actors = (0..MAX_ROOT_TREE_ACTORS)
            .map(|ordinal| DormantProgram {
                blob: actor.as_slice(),
                handle_slot: TARGET_ACTOR_HANDLE_SLOT + ordinal as u8,
            })
            .collect::<Vec<_>>();
        assert!(
            InvocationKernel::new_with_dormant_programs(
                &service,
                &[],
                SYNTHETIC_SERVICE_GAS,
                &actors,
                javm::PvmBackend::ForceInterpreter,
            )
            .is_ok()
        );

        let mut too_many = actors;
        too_many.push(DormantProgram {
            blob: actor.as_slice(),
            handle_slot: TARGET_ACTOR_HANDLE_SLOT + MAX_ROOT_TREE_ACTORS as u8,
        });
        assert!(
            InvocationKernel::new_with_dormant_programs(
                &service,
                &[],
                SYNTHETIC_SERVICE_GAS,
                &too_many,
                javm::PvmBackend::ForceInterpreter,
            )
            .is_err()
        );
    }

    #[test]
    fn actor_manifests_cannot_occupy_scheduler_capability_slots() {
        use javm::program::{CapManifestEntry, build_blob};

        let actor = grey_transpiler::assembler::Assembler::new().build();
        validate_actor_program_layout(&actor).unwrap();
        let parsed = parse_blob(&actor).unwrap();
        let mut caps = parsed.caps.clone();
        caps.push(CapManifestEntry {
            cap_index: super::super::ACTOR_CALLABLE_BASE_SLOT,
            cap_type: CapEntryType::Data,
            base_page: 0,
            page_count: 0,
            init_access: Access::RW,
            data_offset: 0,
            data_len: 0,
        });
        let invalid = build_blob(
            parsed.header.memory_pages,
            parsed.header.invoke_cap,
            parsed.header.stack_top,
            &caps,
            parsed.data_section,
        );
        assert_eq!(
            validate_actor_program_layout(&invalid),
            Err(ServicePvmErrorV2::InvalidActorCapabilityLayout)
        );
    }

    #[test]
    fn service_rejects_an_argument_window_too_small_for_v2_wires() {
        let mut code = vec![40, 10, 0, 0, 0, 40, 15, 0, 0, 0];
        let mut bitmask = vec![1, 0, 0, 0, 0, 1, 0, 0, 0, 0];
        emit_halt(&mut code, &mut bitmask);
        emit_halt(&mut code, &mut bitmask);
        let program = grey_transpiler::emitter::build_service_program(
            &code,
            &bitmask,
            &[],
            &[],
            &[],
            1,
            0,
            4,
        );
        assert!(matches!(
            ServicePvmV2::new(program.clone(), ProgramId::of_pvm(&program)),
            Err(ServicePvmErrorV2::InvalidServiceEntries)
        ));
    }

    #[test]
    fn accumulate_commits_staged_calls_only_after_ic5_halts() {
        let program = service_program(None, Some(crate::abi::hostcall::STORAGE_W), false);
        let service = ServicePvmV2::new(program.clone(), ProgramId::of_pvm(&program)).unwrap();
        let mut host = RecordingAccumulateHost::default();

        let expected = accumulate_result(true);
        let output = service
            .accumulate(&expected, SYNTHETIC_SERVICE_GAS, &mut host)
            .unwrap();
        assert_eq!(output.bytes, expected);
        assert_eq!(host.committed_calls, 1);
    }

    #[test]
    fn accumulate_is_identical_under_interpreter_and_recompiler() {
        let program = service_program(None, Some(crate::abi::hostcall::STORAGE_W), false);
        let service = ServicePvmV2::new(program.clone(), ProgramId::of_pvm(&program)).unwrap();
        let input = accumulate_result(true);
        let mut interpreted_host = RecordingAccumulateHost::default();
        let mut recompiled_host = RecordingAccumulateHost::default();

        let interpreted = service
            .accumulate_with_backend(
                &input,
                SYNTHETIC_SERVICE_GAS,
                &mut interpreted_host,
                javm::PvmBackend::ForceInterpreter,
            )
            .unwrap();
        let recompiled = service
            .accumulate_with_backend(
                &input,
                SYNTHETIC_SERVICE_GAS,
                &mut recompiled_host,
                javm::PvmBackend::ForceRecompiler,
            )
            .unwrap();

        assert_eq!(interpreted, recompiled);
        assert_eq!(interpreted_host.committed_calls, 1);
        assert_eq!(recompiled_host.committed_calls, 1);
    }

    #[test]
    fn accumulate_discards_staging_for_prepared_and_rejected_results() {
        let program = service_program(None, Some(crate::abi::hostcall::STORAGE_W), false);
        let service = ServicePvmV2::new(program.clone(), ProgramId::of_pvm(&program)).unwrap();
        let mut host = RecordingAccumulateHost::default();

        let prepared = accumulate_result(false);
        assert_eq!(
            service
                .accumulate(&prepared, SYNTHETIC_SERVICE_GAS, &mut host)
                .unwrap()
                .bytes,
            prepared,
        );
        let rejected =
            AccumulationResultV2::Rejected(crate::v2::AccumulationRejectionV2::Unauthorized)
                .encode();
        assert_eq!(
            service
                .accumulate(&rejected, SYNTHETIC_SERVICE_GAS, &mut host)
                .unwrap()
                .bytes,
            rejected,
        );
        assert_eq!(host.committed_calls, 0);
    }

    #[test]
    fn accumulate_discards_staging_on_panic_or_commit_failure() {
        let panicking = service_program(None, Some(crate::abi::hostcall::STORAGE_W), true);
        let service = ServicePvmV2::new(panicking.clone(), ProgramId::of_pvm(&panicking)).unwrap();
        let mut host = RecordingAccumulateHost::default();
        assert!(matches!(
            service.accumulate(&[], SYNTHETIC_SERVICE_GAS, &mut host),
            Err(ServicePvmErrorV2::Panic { vm: 0, .. })
        ));
        assert_eq!(host.committed_calls, 0);

        let committing = service_program(None, Some(crate::abi::hostcall::STORAGE_W), false);
        let service =
            ServicePvmV2::new(committing.clone(), ProgramId::of_pvm(&committing)).unwrap();
        host.reject_commit = true;
        assert_eq!(
            service.accumulate(&accumulate_result(true), SYNTHETIC_SERVICE_GAS, &mut host),
            Err(ServicePvmErrorV2::AccumulateCommitRejected)
        );
        assert_eq!(host.committed_calls, 0);
    }
}
