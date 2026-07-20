//! Read-only construction of linear Refine work from guest-committed state.
//!
//! The scheduler selects work and imports. It never interprets a transition or
//! mutates service rows: successful output must still return to the canonical
//! service PVM's physical IC-5 Accumulate entry.

use alloc::collections::BTreeMap;
use alloc::string::String;
use alloc::vec::Vec;
use core::convert::Infallible;

use super::causal::{CausalFrontierError, load_causal_frontier};
use super::{
    AccumulatedReplyV2, ActorGenesisV2, ActorId, AuthorizationEvidenceV2, BlobRefV2, CallId,
    ConsistencyBaseV2, ConsistencyModeV2, ContinuationSnapshotV2, DecodeError, ImportedActorV2,
    ImportedBlobV2, ImportedProgramV2, InvocationId, LocalJamStoreV2, LocalStoreReadErrorV2,
    Origin, RefineImportsV2, StateKeyV2, V2Wire, WorkEnvelopeV2, WorkflowCheckpointV2,
    crdt_node_storage_key,
};

/// Caller-controlled portion of one local work item. The scheduler supplies
/// service identity, program identity, consistency base, actor state, and an
/// exact continuation from the committed service account.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct LocalWorkRequestV2 {
    pub invocation: InvocationId,
    pub workflow_step: u64,
    pub logical_timeslot: u64,
    pub target: ActorId,
    pub method: String,
    pub arguments: Vec<u8>,
    pub origin: Origin,
    pub authorization: AuthorizationEvidenceV2,
    pub causal_parent: Option<InvocationId>,
    pub parent_call: Option<CallId>,
    pub awaited_reply: Option<AccumulatedReplyV2>,
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
    EmptyActorName,
    CorruptActorDirectory,
    ActorConsistencyMismatch(ActorId),
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
    MissingInbox(super::CallId),
    InvalidInbox(super::CallId),
    DeadlineExpired(super::CallId),
    MissingCausalDependency(super::Hash),
    CorruptCausalDag,
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
    pub fn resolve_root(
        store: &LocalJamStoreV2,
        name: &str,
    ) -> Result<Option<ActorId>, ScheduleErrorV2> {
        Self::resolve_owned(store, None, name)
    }

    pub fn resolve_child(
        store: &LocalJamStoreV2,
        parent: ActorId,
        name: &str,
    ) -> Result<Option<ActorId>, ScheduleErrorV2> {
        Self::resolve_owned(store, Some(parent), name)
    }

    fn resolve_owned(
        store: &LocalJamStoreV2,
        parent: Option<ActorId>,
        name: &str,
    ) -> Result<Option<ActorId>, ScheduleErrorV2> {
        if name.is_empty() {
            return Err(ScheduleErrorV2::EmptyActorName);
        }
        let header = store.header()?.ok_or(ScheduleErrorV2::StoreUninitialized)?;
        let directory_key = StateKeyV2::ActorName {
            parent,
            name: name.into(),
        };
        let Some(bytes) = store.state_row(header.service_root, &directory_key)? else {
            return Ok(None);
        };
        let actor = ActorId(
            bytes
                .try_into()
                .map_err(|_| ScheduleErrorV2::CorruptActorDirectory)?,
        );
        let descriptor = decode_row::<ActorGenesisV2>(
            store,
            header.service_root,
            &StateKeyV2::ActorDescriptor(actor),
        )?
        .ok_or(ScheduleErrorV2::CorruptActorDirectory)?;
        if descriptor.parent != parent || descriptor.name != name {
            return Err(ScheduleErrorV2::CorruptActorDirectory);
        }
        Ok(Some(actor))
    }

    /// Reconstruct a target workflow directly from one committed durable inbox
    /// row. The row carries the original actor identity and authorization;
    /// neither is synthesized by the host scheduler.
    pub fn prepare_inbox(
        store: &LocalJamStoreV2,
        call: CallId,
        logical_timeslot: u64,
    ) -> Result<PreparedWorkV2, ScheduleErrorV2> {
        let header = store.header()?.ok_or(ScheduleErrorV2::StoreUninitialized)?;
        let key = StateKeyV2::Inbox(call);
        let message = decode_row::<super::MessageRecordV2>(store, header.service_root, &key)?
            .ok_or(ScheduleErrorV2::MissingInbox(call))?;
        if message.call_id != call {
            return Err(ScheduleErrorV2::InvalidInbox(call));
        }
        if message
            .deadline_timeslot
            .is_some_and(|deadline| logical_timeslot >= deadline)
        {
            return Err(ScheduleErrorV2::DeadlineExpired(call));
        }
        let method = dynamic_method(&message.payload)
            .ok_or(ScheduleErrorV2::InvalidInbox(message.call_id))?;
        Self::prepare(
            store,
            LocalWorkRequestV2 {
                invocation: InvocationId::for_call(message.call_id),
                workflow_step: 0,
                logical_timeslot,
                target: message.to,
                method,
                arguments: message.payload,
                origin: Origin::Actor(message.from),
                authorization: message.authorization,
                causal_parent: Some(message.caller_invocation),
                parent_call: Some(message.call_id),
                awaited_reply: None,
                imported_blobs: Vec::new(),
                proof_requested: false,
            },
        )
    }

    /// Prepare one slice from the current committed linear revision or CRDT
    /// frontier. Both paths use the same guest-owned header and actor rows.
    pub fn prepare(
        store: &LocalJamStoreV2,
        request: LocalWorkRequestV2,
    ) -> Result<PreparedWorkV2, ScheduleErrorV2> {
        if request.method.is_empty() {
            return Err(ScheduleErrorV2::EmptyMethod);
        }
        let header = store.header()?.ok_or(ScheduleErrorV2::StoreUninitialized)?;
        let descriptor_key = StateKeyV2::ActorDescriptor(request.target);
        let descriptor = decode_row::<ActorGenesisV2>(store, header.service_root, &descriptor_key)?
            .ok_or(ScheduleErrorV2::MissingActor(request.target))?;
        if descriptor.crdt != (header.consistency == ConsistencyModeV2::Crdt) {
            return Err(ScheduleErrorV2::ActorConsistencyMismatch(request.target));
        }

        let program_bytes = store
            .program(descriptor.program)
            .ok_or(ScheduleErrorV2::MissingProgram(descriptor.program))?
            .to_vec();
        let (base, base_causal_height, mut states) =
            if header.consistency == ConsistencyModeV2::Crdt {
                let heads = header.crdt_heads.clone();
                let frontier = load_causal_frontier(&heads, |cid| {
                    Ok::<_, Infallible>(store.row(&crdt_node_storage_key(cid)).map(<[u8]>::to_vec))
                });
                let frontier = match frontier {
                    Ok(frontier) => frontier,
                    Err(CausalFrontierError::Missing(cid)) => {
                        return Err(ScheduleErrorV2::MissingCausalDependency(cid));
                    }
                    Err(CausalFrontierError::Corrupt) => {
                        return Err(ScheduleErrorV2::CorruptCausalDag);
                    }
                    Err(CausalFrontierError::Storage(error)) => match error {},
                };
                let height = frontier.max_head_height;
                let states = frontier
                    .actor_materializations::<Infallible>(&descriptor, request.target)
                    .map_err(|error| match error {
                        CausalFrontierError::Corrupt => ScheduleErrorV2::CorruptCausalDag,
                        CausalFrontierError::Storage(error) => match error {},
                        CausalFrontierError::Missing(_) => ScheduleErrorV2::CorruptCausalDag,
                    })?;
                (ConsistencyBaseV2::Crdt { heads }, Some(height), states)
            } else {
                let state_root = header
                    .state_root
                    .ok_or(ScheduleErrorV2::UnsupportedConsistency(header.consistency))?;
                let state_key = StateKeyV2::ActorRow {
                    actor: request.target,
                    key: crate::actors::lifecycle::STATE_KEY_BYTES.to_vec(),
                };
                let state = decode_row::<BlobRefV2>(store, header.service_root, &state_key)?
                    .ok_or(ScheduleErrorV2::MissingState(request.target))?;
                (
                    ConsistencyBaseV2::Linear {
                        revision: header.revision,
                        state_root,
                    },
                    None,
                    alloc::vec![state],
                )
            };
        if states.is_empty() {
            return Err(ScheduleErrorV2::CorruptCausalDag);
        }
        let state = states.remove(0);
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

        let mut work = WorkEnvelopeV2 {
            service: header.service.clone(),
            invocation: request.invocation,
            workflow_step: request.workflow_step,
            logical_timeslot: request.logical_timeslot,
            target: request.target,
            target_program: descriptor.program,
            method: request.method,
            arguments: request.arguments,
            origin: request.origin,
            authorization: request.authorization,
            causal_parent: request.causal_parent,
            parent_call: request.parent_call,
            awaited_reply: request.awaited_reply,
            consistency: header.consistency,
            base,
            base_causal_height,
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
            causal_states: states.clone(),
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
        for reference in &states {
            import_blob(store, &mut blobs, reference)?;
        }
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

fn dynamic_method(payload: &[u8]) -> Option<String> {
    if payload.first() != Some(&crate::value::TAG_DYNAMIC) {
        return None;
    }
    <crate::value::Msg as crate::Decode>::try_decode(&payload[1..]).map(|message| message.name)
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
