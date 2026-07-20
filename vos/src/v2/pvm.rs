//! Local driver for the protocol-pinned generic VOS service PVM.
//!
//! This is a conformance boundary, not a native implementation of Refine.
//! The transition bytes are produced by the service program itself. During
//! Refine the host surface is read-only and persistent JAM protocol calls are
//! rejected before a handler can observe them.

use alloc::vec::Vec;

use javm::cap::{Access, Cap, DataCap, ProtocolCap};
use javm::kernel::{DispatchResult, DormantProgram, InvocationKernel, KernelResult};
use javm::program::{CapEntryType, cap_data, parse_blob, parse_code_blob};
use javm::snapshot::KernelSnapshot;
use javm::vm_pool::VmState;

use super::{
    ACCUMULATE_ENTRY_IC, ACTOR_IPC_BASE_PAGE, ACTOR_IPC_CAP_SLOT, AccumulationResultV2,
    ActorSliceInputV2, ActorTreeImportV2, AuthorizationEvidenceV2, AwaitResumeV2, BlobRefV2,
    CheckpointTokenV2, ContinuationSnapshotV2, CrdtChangeV2, Hash, ImportedBlobV2,
    MAX_ROOT_TREE_ACTORS, ProgramId, REFINE_ENTRY_IC, RefineImportsV2, SpaceRoleCredentialV2,
    TARGET_ACTOR_HANDLE_SLOT, V2Wire, WorkEnvelopeV2, space_role_for_policy,
};

const MAX_ACTOR_IPC_PAGES: u32 = 1024;
const MIN_ACTOR_OUTPUT_HEADROOM: usize = 16 * javm::PVM_PAGE_SIZE as usize;
const RESULT_WHAT: u64 = u64::MAX - 1;
const ACTOR_STACK_OBJECT_CAP: u64 = 65;

/// Result of one completed service-PVM execution slice.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ServicePvmOutputV2 {
    pub bytes: Vec<u8>,
    pub gas_used: u64,
    /// Content-addressed artifacts produced purely during Refine. Callers must
    /// make these bytes available before submitting the transition to
    /// Accumulate; publication still occurs only after commit.
    pub exported_blobs: Vec<ImportedBlobV2>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ServicePvmErrorV2 {
    InvalidProgram,
    ProgramIdMismatch,
    InvalidServiceEntries,
    Panic { vm: u16, pc: u32 },
    OutOfGas { vm: u16, pc: u32 },
    PageFault { vm: u16, address: u32 },
    UnreadableOutput,
    ForbiddenRefineProtocolCall(u8),
    RefineHostRejected(u8),
    AccumulateHostRejected(u8),
    AccumulateCommitRejected,
    InvalidAccumulateOutput,
    InvalidProtocolResume,
    InvalidWorkEnvelope,
    InvalidRefineImports,
    InvalidAuthorization,
    TooManyImportedActors,
    InvalidContinuation,
    ContinuationMismatch,
    SnapshotFailed,
    CheckpointTokenWriteFailed,
    ActorIpcExhausted,
    ActorIpcSetupFailed,
    InvalidVmLifecycle,
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

    fn commit(&mut self, transaction: Self::Transaction) -> Result<(), ServicePvmErrorV2>;
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
            .map_err(|_| ServicePvmErrorV2::InvalidProgram)?;
        install_refine_scheduler_caps(&mut kernel);
        run_refine_kernel(
            kernel,
            host,
            javm::PvmBackend::Default,
            true,
            None,
            None,
            Vec::new(),
            Vec::new(),
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
        let work = WorkEnvelopeV2::decode(arguments)
            .map_err(|_| ServicePvmErrorV2::InvalidWorkEnvelope)?;
        imports
            .validate_for(&work)
            .map_err(|_| ServicePvmErrorV2::InvalidRefineImports)?;
        if work.imported_actors.len() > MAX_ROOT_TREE_ACTORS {
            return Err(ServicePvmErrorV2::TooManyImportedActors);
        }

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
            let handle_slot = TARGET_ACTOR_HANDLE_SLOT
                .checked_add(ordinal as u8)
                .ok_or(ServicePvmErrorV2::TooManyImportedActors)?;
            dormant.push(DormantProgram {
                blob: &imported.pvm,
                handle_slot,
            });
        }

        if let Some(reference) = target.continuation.as_ref() {
            let bytes = imported_blob_bytes(imports, reference)?;
            let continuation = ContinuationSnapshotV2::decode(bytes)
                .map_err(|_| ServicePvmErrorV2::InvalidContinuation)?;
            continuation
                .validate_resume_for(&work)
                .map_err(|_| ServicePvmErrorV2::ContinuationMismatch)?;
            let snapshot = KernelSnapshot::from_bytes(&continuation.kernel_snapshot)
                .map_err(|_| ServicePvmErrorV2::InvalidContinuation)?;
            if snapshot.pending_call.slot != crate::abi::hostcall::SUSPEND as u8 {
                return Err(ServicePvmErrorV2::InvalidContinuation);
            }
            let mut kernel = InvocationKernel::restore_with_dormant_programs(
                &self.program,
                &dormant,
                &snapshot,
                backend,
            )
            .map_err(|_| ServicePvmErrorV2::ContinuationMismatch)?;
            let checkpoint = CheckpointTokenV2 {
                input: work.input_id(),
                base: work.base.clone(),
                base_causal_height: work.base_causal_height,
                expected: Some(reference.hash),
                replacement: None,
                pending_call: continuation.pending_call,
                previously_suspended: continuation.suspended_actors.clone(),
                suspended: Vec::new(),
            };
            let (resume_kind, payload_len) =
                match (continuation.pending_call, work.awaited_reply.as_ref()) {
                    (None, None) => (1, write_checkpoint_token(&mut kernel, &checkpoint)?),
                    (Some(call), Some(awaited)) if awaited.reply.call_id == call => (
                        2,
                        write_await_resume(
                            &mut kernel,
                            &AwaitResumeV2 {
                                checkpoint,
                                reply: awaited.reply.clone(),
                            },
                        )?,
                    ),
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
                continuation.suspended_actors,
                Vec::new(),
            );
        }

        let target_state = imported_blob_bytes(imports, &target.state)?;
        let causal_states = target
            .causal_states
            .iter()
            .map(|reference| imported_blob_bytes(imports, reference).map(<[u8]>::to_vec))
            .collect::<Result<Vec<_>, _>>()?;
        let actor_tree = work
            .imported_actors
            .iter()
            .map(|actor| {
                Ok(ActorTreeImportV2 {
                    actor: actor.actor,
                    name: actor.name.clone(),
                    parent: actor.parent,
                    program: actor.program,
                    state: imported_blob_bytes(imports, &actor.state)?.to_vec(),
                    causal_states: actor
                        .causal_states
                        .iter()
                        .map(|reference| {
                            imported_blob_bytes(imports, reference).map(<[u8]>::to_vec)
                        })
                        .collect::<Result<Vec<_>, ServicePvmErrorV2>>()?,
                    suspended: actor.continuation.is_some(),
                })
            })
            .collect::<Result<Vec<_>, ServicePvmErrorV2>>()?;
        let active_actor_index = actor_tree
            .binary_search_by_key(&work.target, |actor| actor.actor)
            .map_err(|_| ServicePvmErrorV2::InvalidRefineImports)?;
        let actor_input = ActorSliceInputV2 {
            actor: work.target,
            change: CrdtChangeV2::derive_id(&work),
            state: target_state.to_vec(),
            causal_states,
            actor_tree,
            active_actor_mask: 1u64 << active_actor_index,
            first_await_ordinal: 0,
            message: work.arguments.clone(),
            origin: work.origin,
            space_role: authorization_space_role(work.origin, &work.authorization, imports)?,
        }
        .encode();
        let mut kernel = InvocationKernel::new_with_dormant_programs(
            &self.program,
            arguments,
            gas_limit,
            &dormant,
            backend,
        )
        .map_err(|_| ServicePvmErrorV2::InvalidProgram)?;
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
            Vec::new(),
            Vec::new(),
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
        let mut kernel = InvocationKernel::new(&self.program, arguments, gas_limit)
            .map_err(|_| ServicePvmErrorV2::InvalidProgram)?;
        kernel
            .vm_arena
            .vm_mut(kernel.active_vm)
            .transition(VmState::Running)
            .map_err(|_| ServicePvmErrorV2::InvalidVmLifecycle)?;
        install_accumulate_scheduler_caps(&mut kernel);
        kernel.set_entry_ic(ACCUMULATE_ENTRY_IC);
        let mut transaction = host.begin()?;

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
                            | AccumulationResultV2::Accepted {
                                duplicate: false,
                                ..
                            }
                            | AccumulationResultV2::PublicationAcknowledged {
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

fn install_actor_ipc(
    kernel: &mut InvocationKernel,
    input: &[u8],
) -> Result<(u32, u32), ServicePvmErrorV2> {
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

fn authorization_space_role(
    origin: super::Origin,
    authorization: &AuthorizationEvidenceV2,
    imports: &RefineImportsV2,
) -> Result<Option<u8>, ServicePvmErrorV2> {
    let (policy, commitment, bytes) = match authorization {
        AuthorizationEvidenceV2::Public | AuthorizationEvidenceV2::SystemCapability { .. } => {
            return Ok(None);
        }
        AuthorizationEvidenceV2::Credential {
            policy,
            credential_commitment,
            bytes,
        } => (*policy, *credential_commitment, bytes.as_slice()),
        AuthorizationEvidenceV2::PrivateCredential {
            policy,
            credential_commitment,
            witness,
        } => (
            *policy,
            *credential_commitment,
            imported_blob_bytes(imports, witness)?,
        ),
    };
    let credential = SpaceRoleCredentialV2::decode(bytes)
        .map_err(|_| ServicePvmErrorV2::InvalidAuthorization)?;
    let required = space_role_for_policy(policy).ok_or(ServicePvmErrorV2::InvalidAuthorization)?;
    if credential.holder != origin
        || credential.role < required
        || commitment != Hash::digest(b"vos/credential-commitment/v2", &[bytes])
    {
        return Err(ServicePvmErrorV2::InvalidAuthorization);
    }
    Ok(Some(credential.role.as_u8()))
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
) -> Result<
    (
        ImportedBlobV2,
        KernelSnapshot,
        Option<super::CallId>,
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
    let suspended_actors = suspended_actor_stack(&snapshot, work)?;
    let continuation = ContinuationSnapshotV2 {
        snapshot_version: super::SNAPSHOT_VERSION,
        jar_semantics: super::EXECUTION_SEMANTICS_ID,
        vos_abi: super::ABI_VERSION,
        service: work.service.clone(),
        invocation: work.invocation,
        checkpoint_step: work.workflow_step,
        actor: work.target,
        actor_program: work.target_program,
        await_ordinal,
        pending_call,
        suspended_actors: suspended_actors.clone(),
        kernel_snapshot: snapshot.to_bytes(),
    };
    let bytes = continuation.encode();
    let reference = BlobRefV2::of_bytes(&bytes);
    Ok((
        ImportedBlobV2 { reference, bytes },
        snapshot,
        pending_call,
        suspended_actors,
    ))
}

fn suspended_actor_stack(
    snapshot: &KernelSnapshot,
    work: &WorkEnvelopeV2,
) -> Result<Vec<super::ActorId>, ServicePvmErrorV2> {
    let mut actors = Vec::with_capacity(work.imported_actors.len());
    actors.push(work.target);
    actors.extend(
        work.imported_actors
            .iter()
            .filter(|actor| actor.actor != work.target)
            .map(|actor| actor.actor),
    );
    let mut suspended = snapshot
        .call_stack
        .iter()
        .map(|frame| frame.caller_vm_id)
        .chain(core::iter::once(snapshot.active_vm))
        .filter(|vm| *vm != 0)
        .map(|vm| actors.get(vm.checked_sub(1)? as usize).copied())
        .collect::<Option<Vec<_>>>()
        .ok_or(ServicePvmErrorV2::SnapshotFailed)?;
    suspended.sort_unstable();
    suspended.dedup();
    if suspended.is_empty() || suspended.binary_search(&work.target).is_err() {
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
    previously_suspended: Vec<super::ActorId>,
    mut exported_blobs: Vec<ImportedBlobV2>,
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
        match kernel.run() {
            KernelResult::Halt => {
                let bytes = read_output(&kernel)?;
                return Ok(ServicePvmOutputV2 {
                    bytes,
                    gas_used: starting_gas.saturating_sub(kernel.active_gas()),
                    exported_blobs,
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
                if !refine_protocol_call_is_pure(slot) {
                    return Err(ServicePvmErrorV2::ForbiddenRefineProtocolCall(slot));
                }
                if slot == crate::abi::hostcall::SUSPEND as u8 {
                    if let Some(work) = suspension_work {
                        let (artifact, snapshot, pending_call, suspended) =
                            capture_checkpoint(&mut kernel, work)?;
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
                                base_causal_height: work.base_causal_height,
                                expected,
                                replacement: Some(artifact.reference.clone()),
                                pending_call,
                                previously_suspended: previously_suspended.clone(),
                                suspended,
                            },
                        )?;
                        finalization
                            .resume_protocol_call(0, token_len)
                            .map_err(|_| ServicePvmErrorV2::InvalidProtocolResume)?;
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
            }
        }
    }
}

fn install_refine_scheduler_caps(kernel: &mut InvocationKernel) {
    // These are VOS scheduler capabilities, not JAM protocol slots. The
    // nondeterministic BOOT_CONTEXT/NOW_MS seams are intentionally absent from
    // v2 Refine.
    for slot in [
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
    // capabilities are deterministic hashing, mechanical VM support, and
    // diagnostics only.
    for slot in [
        crate::crypto::ECALL_BLAKE2B_COMPRESS as u8,
        crate::abi::hostcall::GROW_HEAP as u8,
        crate::abi::hostcall::DEBUG_WRITE as u8,
        crate::abi::hostcall::PROOF_VERIFY as u8,
        crate::abi::hostcall::INSTALL_AUTH_VERIFY as u8,
        crate::abi::hostcall::RECEIPT_VERIFY as u8,
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
    use grey_transpiler::assembler::Reg;

    #[test]
    fn disclosed_and_private_role_credentials_feed_the_same_actor_role() {
        let origin = super::super::Origin::Member(super::super::SubjectId([41; 32]));
        let credential = SpaceRoleCredentialV2 {
            holder: origin,
            role: crate::SpaceRole::Developer,
            authenticator: b"signed space grant".to_vec(),
        };
        let policy =
            super::super::space_role_policy_hash(crate::SpaceRole::Member.as_u8()).unwrap();
        let disclosed = credential.disclosed_evidence(policy);
        assert_eq!(
            authorization_space_role(origin, &disclosed, &RefineImportsV2::default()),
            Ok(Some(crate::SpaceRole::Developer.as_u8()))
        );

        let (private, witness) = credential.private_evidence(policy);
        let imports = RefineImportsV2 {
            programs: vec![],
            blobs: vec![witness],
        };
        assert_eq!(
            authorization_space_role(origin, &private, &imports),
            Ok(Some(crate::SpaceRole::Developer.as_u8()))
        );

        let other = super::super::Origin::Member(super::super::SubjectId([42; 32]));
        assert_eq!(
            authorization_space_role(other, &private, &imports),
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

        grey_transpiler::emitter::build_service_program(&code, &bitmask, &[], &[], &[], 1, 0, 4)
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

        let receipt = AccumulationReceiptV2 {
            service: ServiceIdentityV2 {
                space: crate::v2::SpaceId([0; 32]),
                root_service: RootServiceId([1; 32]),
                deployment: DeploymentId([2; 32]),
                service_program: ProgramId([3; 32]),
                service_abi: crate::v2::ABI_VERSION,
                execution_semantics: crate::v2::EXECUTION_SEMANTICS_ID,
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
            let statement = crate::attestation::AttestationStatementV3 {
                statement_version: crate::v2::ATTESTATION_STATEMENT_VERSION,
                space: receipt.service.space,
                actor: crate::v2::ActorId([6; 32]),
                deployment: receipt.service.deployment,
                actor_program: ProgramId([7; 32]),
                method: "attested".into(),
                schema: Hash([8; 32]),
                invocation: crate::v2::InvocationId([9; 32]),
                before: crate::attestation::StateCommitmentV3::Linear(Hash([10; 32])),
                after: crate::attestation::StateCommitmentV3::Linear(Hash([5; 32])),
                claim_commitment: Hash([11; 32]),
                input_commitment: Hash([12; 32]),
                authorization_policy: Hash([13; 32]),
                accumulation_receipt: receipt.clone(),
            };
            AccumulationResultV2::Prepared(crate::attestation::AttestationPreparationV2 {
                receipt,
                statement,
            })
        }
        .encode()
    }

    #[test]
    fn physical_refine_entry_is_deterministic_and_uses_gp_arguments() {
        let program = two_entry_program(None);
        let service = ServicePvmV2::new(program.clone(), ProgramId::of_pvm(&program)).unwrap();
        let first = service
            .refine(b"work-envelope", 1_000_000, &NoRefineProtocolHostV2)
            .unwrap();
        let second = service
            .refine(b"work-envelope", 1_000_000, &NoRefineProtocolHostV2)
            .unwrap();
        assert_eq!(first, second);
        assert_eq!(first.bytes, b"work-envelope");
    }

    #[test]
    fn refine_rejects_persistent_protocol_calls_before_host_dispatch() {
        let program = two_entry_program(Some(crate::abi::hostcall::STORAGE_W));
        let service = ServicePvmV2::new(program.clone(), ProgramId::of_pvm(&program)).unwrap();
        assert_eq!(
            service.refine(&[], 1_000_000, &NoRefineProtocolHostV2),
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
    fn accumulate_commits_staged_calls_only_after_ic5_halts() {
        let program = service_program(None, Some(crate::abi::hostcall::STORAGE_W), false);
        let service = ServicePvmV2::new(program.clone(), ProgramId::of_pvm(&program)).unwrap();
        let mut host = RecordingAccumulateHost::default();

        let expected = accumulate_result(true);
        let output = service.accumulate(&expected, 1_000_000, &mut host).unwrap();
        assert_eq!(output.bytes, expected);
        assert_eq!(host.committed_calls, 1);
    }

    #[test]
    fn accumulate_discards_staging_for_prepared_and_rejected_results() {
        let program = service_program(None, Some(crate::abi::hostcall::STORAGE_W), false);
        let service = ServicePvmV2::new(program.clone(), ProgramId::of_pvm(&program)).unwrap();
        let mut host = RecordingAccumulateHost::default();

        let prepared = accumulate_result(false);
        assert_eq!(
            service
                .accumulate(&prepared, 1_000_000, &mut host)
                .unwrap()
                .bytes,
            prepared,
        );
        let rejected =
            AccumulationResultV2::Rejected(crate::v2::AccumulationRejectionV2::Unauthorized)
                .encode();
        assert_eq!(
            service
                .accumulate(&rejected, 1_000_000, &mut host)
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
            service.accumulate(&[], 1_000_000, &mut host),
            Err(ServicePvmErrorV2::Panic { vm: 0, .. })
        ));
        assert_eq!(host.committed_calls, 0);

        let committing = service_program(None, Some(crate::abi::hostcall::STORAGE_W), false);
        let service =
            ServicePvmV2::new(committing.clone(), ProgramId::of_pvm(&committing)).unwrap();
        host.reject_commit = true;
        assert_eq!(
            service.accumulate(&accumulate_result(true), 1_000_000, &mut host),
            Err(ServicePvmErrorV2::AccumulateCommitRejected)
        );
        assert_eq!(host.committed_calls, 0);
    }
}
