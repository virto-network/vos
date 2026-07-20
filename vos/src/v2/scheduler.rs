//! Read-only construction of linear Refine work from guest-committed state.
//!
//! The scheduler selects work and imports. It never interprets a transition or
//! mutates service rows: successful output must still return to the canonical
//! service PVM's physical IC-5 Accumulate entry.

use alloc::collections::BTreeMap;
use alloc::string::String;
use alloc::vec::Vec;

use super::{
    ActorGenesisV2, ActorId, AuthorizationEvidenceV2, BlobRefV2, CallId, ConsistencyBaseV2,
    ConsistencyModeV2, ContinuationSnapshotV2, DecodeError, ImportedActorV2, ImportedBlobV2,
    ImportedProgramV2, InvocationId, LocalJamStoreV2, LocalStoreReadErrorV2, Origin,
    RefineImportsV2, StateKeyV2, V2Wire, WorkEnvelopeV2, WorkflowCheckpointV2,
};

/// Caller-controlled portion of one local work item. The scheduler supplies
/// service identity, program identity, consistency base, actor state, and an
/// exact continuation from the committed service account.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct LocalWorkRequestV2 {
    pub invocation: InvocationId,
    pub workflow_step: u64,
    pub target: ActorId,
    pub method: String,
    pub arguments: Vec<u8>,
    pub origin: Origin,
    pub authorization: AuthorizationEvidenceV2,
    pub causal_parent: Option<InvocationId>,
    pub parent_call: Option<CallId>,
    pub imported_blobs: Vec<BlobRefV2>,
    pub proof_requested: bool,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PreparedWorkV2 {
    pub work: WorkEnvelopeV2,
    pub imports: RefineImportsV2,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ScheduleErrorV2 {
    Store(LocalStoreReadErrorV2),
    StoreUninitialized,
    UnsupportedConsistency(ConsistencyModeV2),
    MissingActor(ActorId),
    InvalidActorDescriptor(ActorId),
    CrdtActorInLinearService(ActorId),
    MissingProgram(super::ProgramId),
    MissingState(ActorId),
    MissingBlob(super::Hash),
    InvalidRow(StateKeyV2, DecodeError),
    EmptyMethod,
    ActorBusy(ActorId),
    MissingContinuation(ActorId),
    InvalidContinuation(ActorId),
    InvocationAlreadyCommitted(InvocationId),
    InvalidWorkflowStep(InvocationId),
    NonCanonicalImports,
}

impl core::fmt::Display for ScheduleErrorV2 {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        write!(f, "cannot schedule VOS v2 work: {self:?}")
    }
}

impl core::error::Error for ScheduleErrorV2 {}

impl From<LocalStoreReadErrorV2> for ScheduleErrorV2 {
    fn from(value: LocalStoreReadErrorV2) -> Self {
        Self::Store(value)
    }
}

pub struct LocalWorkSchedulerV2;

impl LocalWorkSchedulerV2 {
    /// Prepare one Ephemeral/Local/Raft slice from the current committed root.
    /// CRDT work uses causal frontier materializations and is intentionally a
    /// separate path rather than pretending that one current row is a DAG.
    pub fn prepare(
        store: &LocalJamStoreV2,
        request: LocalWorkRequestV2,
    ) -> Result<PreparedWorkV2, ScheduleErrorV2> {
        if request.method.is_empty() {
            return Err(ScheduleErrorV2::EmptyMethod);
        }
        let header = store.header()?.ok_or(ScheduleErrorV2::StoreUninitialized)?;
        if header.consistency == ConsistencyModeV2::Crdt {
            return Err(ScheduleErrorV2::UnsupportedConsistency(header.consistency));
        }

        let descriptor_key = StateKeyV2::ActorDescriptor(request.target);
        let descriptor = decode_row::<ActorGenesisV2>(store, header.service_root, &descriptor_key)?
            .ok_or(ScheduleErrorV2::MissingActor(request.target))?;
        if descriptor.actor != request.target {
            return Err(ScheduleErrorV2::InvalidActorDescriptor(request.target));
        }
        if descriptor.crdt {
            return Err(ScheduleErrorV2::CrdtActorInLinearService(request.target));
        }

        let program_bytes = store
            .program(descriptor.program)
            .ok_or(ScheduleErrorV2::MissingProgram(descriptor.program))?
            .to_vec();
        let state_key = StateKeyV2::ActorRow {
            actor: request.target,
            key: crate::actors::lifecycle::STATE_KEY_BYTES.to_vec(),
        };
        let state = decode_row::<BlobRefV2>(store, header.service_root, &state_key)?
            .ok_or(ScheduleErrorV2::MissingState(request.target))?;
        let continuation_key = StateKeyV2::Continuation(request.target);
        let continuation = decode_row::<BlobRefV2>(store, header.service_root, &continuation_key)?;
        let workflow_key = StateKeyV2::Workflow(request.invocation);
        let workflow =
            decode_row::<WorkflowCheckpointV2>(store, header.service_root, &workflow_key)?;

        match (
            request.workflow_step,
            continuation.as_ref(),
            workflow.as_ref(),
        ) {
            (0, Some(_), _) => return Err(ScheduleErrorV2::ActorBusy(request.target)),
            (0, None, Some(_)) => {
                return Err(ScheduleErrorV2::InvocationAlreadyCommitted(
                    request.invocation,
                ));
            }
            (0, None, None) => {}
            (_, None, _) => {
                return Err(ScheduleErrorV2::MissingContinuation(request.target));
            }
            (step, Some(_), Some(checkpoint))
                if checkpoint.input.invocation == request.invocation
                    && checkpoint.input.workflow_step.checked_add(1) == Some(step) => {}
            (_, Some(_), _) => {
                return Err(ScheduleErrorV2::InvalidWorkflowStep(request.invocation));
            }
        }

        let state_root = header
            .state_root
            .ok_or(ScheduleErrorV2::UnsupportedConsistency(header.consistency))?;
        let mut work = WorkEnvelopeV2 {
            service: header.service.clone(),
            invocation: request.invocation,
            workflow_step: request.workflow_step,
            target: request.target,
            target_program: descriptor.program,
            method: request.method,
            arguments: request.arguments,
            origin: request.origin,
            authorization: request.authorization,
            causal_parent: request.causal_parent,
            parent_call: request.parent_call,
            consistency: header.consistency,
            base: ConsistencyBaseV2::Linear {
                revision: header.revision,
                state_root,
            },
            base_causal_height: None,
            imported_actors: Vec::new(),
            imported_blobs: request.imported_blobs,
            proof_requested: request.proof_requested,
        };
        if request.workflow_step != 0
            && workflow
                .as_ref()
                .is_none_or(|checkpoint| checkpoint.workflow_identity != work.workflow_identity())
        {
            return Err(ScheduleErrorV2::InvalidWorkflowStep(request.invocation));
        }
        work.imported_actors.push(ImportedActorV2 {
            actor: request.target,
            program: descriptor.program,
            state: state.clone(),
            causal_states: Vec::new(),
            continuation: continuation.clone(),
        });
        work.imported_blobs.sort_by_key(|blob| blob.hash);
        if work
            .imported_blobs
            .windows(2)
            .any(|pair| pair[0].hash == pair[1].hash)
        {
            return Err(ScheduleErrorV2::NonCanonicalImports);
        }

        let mut blobs = BTreeMap::new();
        import_blob(store, &mut blobs, &state)?;
        if let Some(reference) = continuation.as_ref() {
            import_blob(store, &mut blobs, reference)?;
        }
        for reference in &work.imported_blobs {
            import_blob(store, &mut blobs, reference)?;
        }
        let imports = RefineImportsV2 {
            programs: alloc::vec![ImportedProgramV2 {
                program: descriptor.program,
                pvm: program_bytes,
            }],
            blobs: blobs.into_values().collect(),
        };

        if let Some(reference) = continuation.as_ref() {
            let bytes = imports
                .blobs
                .binary_search_by_key(&reference.hash, |blob| blob.reference.hash)
                .ok()
                .map(|index| imports.blobs[index].bytes.as_slice())
                .ok_or(ScheduleErrorV2::MissingBlob(reference.hash))?;
            let snapshot = ContinuationSnapshotV2::decode(bytes)
                .map_err(|_| ScheduleErrorV2::InvalidContinuation(request.target))?;
            snapshot
                .validate_resume_for(&work)
                .map_err(|_| ScheduleErrorV2::InvalidContinuation(request.target))?;
        }
        imports
            .validate_for(&work)
            .map_err(|_| ScheduleErrorV2::NonCanonicalImports)?;
        Ok(PreparedWorkV2 { work, imports })
    }
}

fn decode_row<T: V2Wire>(
    store: &LocalJamStoreV2,
    root: super::Hash,
    key: &StateKeyV2,
) -> Result<Option<T>, ScheduleErrorV2> {
    store
        .state_row(root, key)?
        .map(|bytes| {
            T::decode(&bytes).map_err(|error| ScheduleErrorV2::InvalidRow(key.clone(), error))
        })
        .transpose()
}

fn import_blob(
    store: &LocalJamStoreV2,
    imports: &mut BTreeMap<super::Hash, ImportedBlobV2>,
    reference: &BlobRefV2,
) -> Result<(), ScheduleErrorV2> {
    let bytes = store
        .blob(reference)
        .ok_or(ScheduleErrorV2::MissingBlob(reference.hash))?
        .to_vec();
    imports.insert(
        reference.hash,
        ImportedBlobV2 {
            reference: reference.clone(),
            bytes,
        },
    );
    Ok(())
}
