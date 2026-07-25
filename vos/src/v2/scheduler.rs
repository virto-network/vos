//! Read-only construction of Refine work from guest-committed state.
//!
//! The scheduler selects work and imports. It never interprets a transition or
//! mutates service rows: successful output must still return to the canonical
//! service PVM's physical IC-5 Accumulate entry.

use alloc::collections::BTreeMap;
use alloc::string::String;
use alloc::vec::Vec;
use core::convert::Infallible;

use super::causal::{CausalFrontierError, CausalSelectionError, load_causal_frontier};
use super::{
    AccumulatedReplyV2, ActorGenesisV2, ActorId, AuthorizationEvidenceV2, BlobRefV2, CallId,
    CausalCallContextV2, ConsistencyBaseV2, ConsistencyModeV2, ContinuationSnapshotV2, DecodeError,
    DeliveryEnvelopeV2, ImportedActorV2, ImportedBlobV2, ImportedProgramV2, InvocationId,
    LocalJamStoreV2, LocalStoreReadErrorV2, MessageRecordV2, Origin, RefineImportsV2, StateKeyV2,
    V2Wire, WorkEnvelopeV2, WorkflowCheckpointV2, crdt_node_storage_key,
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
    pub causal_context: Option<CausalCallContextV2>,
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
    InvalidActorDescriptor(ActorId),
    ActorConsistencyMismatch(ActorId),
    MissingProgram(super::ProgramId),
    MissingState(ActorId),
    MissingBlob(super::Hash),
    InvalidRow(StateKeyV2, DecodeError),
    EmptyMethod,
    ActorBusy(ActorId),
    MissingContinuation(ActorId),
    InvalidContinuation(ActorId),
    MissingAwaitedReply(CallId),
    UnexpectedAwaitedReply(CallId),
    CrdtAwaitUnsupported(CallId),
    InvocationAlreadyCommitted(InvocationId),
    InvalidWorkflowStep(InvocationId),
    MissingInbox(CallId),
    InvalidInbox(CallId),
    DeadlineExpired(CallId),
    InvalidCausalContext,
    InvalidDelivery,
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
    /// Build the exact destination Accumulate input for one finalized
    /// cross-root outbox record. This is read-only scheduling: the physical
    /// service PVM independently verifies and commits the inbox.
    pub fn prepare_delivery(
        store: &LocalJamStoreV2,
        logical_timeslot: u64,
        message: MessageRecordV2,
        source_outbox: Vec<MessageRecordV2>,
        source_receipt: super::AccumulationReceiptV2,
    ) -> Result<DeliveryEnvelopeV2, ScheduleErrorV2> {
        let header = store.header()?.ok_or(ScheduleErrorV2::StoreUninitialized)?;
        if header.consistency == ConsistencyModeV2::Crdt {
            return Err(ScheduleErrorV2::UnsupportedConsistency(header.consistency));
        }
        let state_root = header
            .state_root
            .ok_or(ScheduleErrorV2::UnsupportedConsistency(header.consistency))?;
        let envelope = DeliveryEnvelopeV2 {
            service: header.service,
            logical_timeslot,
            base: ConsistencyBaseV2::Linear {
                revision: header.revision,
                state_root,
            },
            message,
            source_outbox,
            source_receipt,
        };
        DeliveryEnvelopeV2::decode(&envelope.encode()).map_err(|_| ScheduleErrorV2::InvalidDelivery)
    }

    /// Reconstruct the next exact continuation slice from guest-committed
    /// workflow state. The host supplies only the consensus timeslot and, for
    /// an awaited call, the accumulated remote reply it received for
    /// admission. No process-local copy of the original request is required.
    pub fn prepare_resume(
        store: &LocalJamStoreV2,
        invocation: InvocationId,
        logical_timeslot: u64,
        awaited_reply: Option<AccumulatedReplyV2>,
    ) -> Result<PreparedWorkV2, ScheduleErrorV2> {
        let header = store.header()?.ok_or(ScheduleErrorV2::StoreUninitialized)?;
        let workflow = decode_row::<WorkflowCheckpointV2>(
            store,
            header.service_root,
            &StateKeyV2::Workflow(invocation),
        )?
        .ok_or(ScheduleErrorV2::InvalidWorkflowStep(invocation))?;
        let workflow_step = workflow
            .input
            .workflow_step
            .checked_add(1)
            .ok_or(ScheduleErrorV2::InvalidWorkflowStep(invocation))?;
        let template = workflow.resume_work;
        Self::prepare(
            store,
            LocalWorkRequestV2 {
                invocation,
                workflow_step,
                logical_timeslot,
                target: template.target,
                method: template.method,
                arguments: Vec::new(),
                origin: template.origin,
                authorization: template.authorization,
                causal_parent: template.causal_parent,
                parent_call: template.parent_call,
                causal_context: template.causal_context,
                awaited_reply,
                imported_blobs: template.imported_blobs,
                proof_requested: template.proof_requested,
            },
        )
    }

    /// Reconstruct initial target work from one committed durable inbox row.
    ///
    /// Actor identity, authorization, arguments, and causal identity all come
    /// from the guest-committed message. The scheduler supplies only the
    /// consensus-supplied logical timeslot used to enforce its deadline.
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
        let causal_context = CausalCallContextV2::from(&message);
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
                causal_context: Some(causal_context),
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
        if descriptor.actor != request.target {
            return Err(ScheduleErrorV2::InvalidActorDescriptor(request.target));
        }
        validate_actor_consistency(descriptor.crdt, header.consistency, request.target)?;

        let program_bytes = store
            .program(descriptor.program)
            .ok_or(ScheduleErrorV2::MissingProgram(descriptor.program))?
            .to_vec();
        let (base, base_causal_height, mut states) =
            if header.consistency == ConsistencyModeV2::Crdt {
                let heads = header.crdt_heads.clone();
                let frontier = load_causal_frontier(&heads, |cid| {
                    Ok::<_, Infallible>(store.row(&crdt_node_storage_key(cid)).map(<[u8]>::to_vec))
                })
                .map_err(schedule_causal_error)?;
                let height = frontier.max_head_height;
                let states = frontier
                    .actor_materializations(&descriptor)
                    .map_err(|error| match error {
                        CausalSelectionError::Corrupt => ScheduleErrorV2::CorruptCausalDag,
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
            arguments: if request.workflow_step == 0 {
                request.arguments
            } else {
                Vec::new()
            },
            origin: request.origin,
            authorization: request.authorization,
            causal_parent: request.causal_parent,
            parent_call: request.parent_call,
            causal_context: request.causal_context,
            awaited_reply: request.awaited_reply,
            consistency: header.consistency,
            base,
            base_causal_height,
            imported_actors: Vec::new(),
            imported_blobs: request.imported_blobs,
            proof_requested: request.proof_requested,
        };
        match (
            work.causal_context.as_ref(),
            work.parent_call,
            work.causal_parent,
            work.origin,
        ) {
            (Some(context), Some(call), Some(parent), Origin::Actor(from))
                if context.call_id == call
                    && context.caller_invocation == parent
                    && context.from == from
                    && context.to == work.target => {}
            (None, None, _, _) => {}
            _ => return Err(ScheduleErrorV2::InvalidCausalContext),
        }
        if let Some(context) = work.causal_context.as_ref()
            && context
                .deadline_timeslot
                .is_some_and(|deadline| work.logical_timeslot >= deadline)
        {
            return Err(ScheduleErrorV2::DeadlineExpired(context.call_id));
        }
        if request.workflow_step != 0
            && workflow
                .as_ref()
                .is_none_or(|checkpoint| !checkpoint.matches_resume_work(&work))
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
            validate_await_boundary(
                header.consistency,
                snapshot.pending_call,
                work.awaited_reply.as_ref(),
            )?;
        }
        imports
            .validate_for(&work)
            .map_err(|_| ScheduleErrorV2::NonCanonicalImports)?;
        Ok(PreparedWorkV2 { work, imports })
    }
}

fn validate_actor_consistency(
    actor_crdt: bool,
    consistency: ConsistencyModeV2,
    actor: ActorId,
) -> Result<(), ScheduleErrorV2> {
    if actor_crdt == (consistency == ConsistencyModeV2::Crdt) {
        Ok(())
    } else {
        Err(ScheduleErrorV2::ActorConsistencyMismatch(actor))
    }
}

fn schedule_causal_error(error: CausalFrontierError<Infallible>) -> ScheduleErrorV2 {
    match error {
        CausalFrontierError::Missing(cid) => ScheduleErrorV2::MissingCausalDependency(cid),
        CausalFrontierError::Corrupt => ScheduleErrorV2::CorruptCausalDag,
        CausalFrontierError::Storage(error) => match error {},
    }
}

fn validate_await_boundary(
    consistency: ConsistencyModeV2,
    pending_call: Option<CallId>,
    awaited_reply: Option<&AccumulatedReplyV2>,
) -> Result<(), ScheduleErrorV2> {
    if consistency == ConsistencyModeV2::Crdt
        && let Some(call) = pending_call
    {
        return Err(ScheduleErrorV2::CrdtAwaitUnsupported(call));
    }
    match (pending_call, awaited_reply) {
        (None, None) => Ok(()),
        (Some(call), None) => Err(ScheduleErrorV2::MissingAwaitedReply(call)),
        (Some(call), Some(reply)) if reply.reply.call_id == call => Ok(()),
        (_, Some(reply)) => Err(ScheduleErrorV2::UnexpectedAwaitedReply(reply.reply.call_id)),
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

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn scheduler_maps_consistency_causal_and_crdt_await_boundaries() {
        let actor = ActorId([1; 32]);
        assert_eq!(
            validate_actor_consistency(false, ConsistencyModeV2::Crdt, actor),
            Err(ScheduleErrorV2::ActorConsistencyMismatch(actor))
        );
        assert_eq!(
            validate_actor_consistency(true, ConsistencyModeV2::Local, actor),
            Err(ScheduleErrorV2::ActorConsistencyMismatch(actor))
        );
        assert!(validate_actor_consistency(true, ConsistencyModeV2::Crdt, actor).is_ok());
        assert!(validate_actor_consistency(false, ConsistencyModeV2::Local, actor).is_ok());

        let missing = super::super::Hash([2; 32]);
        assert_eq!(
            schedule_causal_error(CausalFrontierError::Missing(missing)),
            ScheduleErrorV2::MissingCausalDependency(missing)
        );
        assert_eq!(
            schedule_causal_error(CausalFrontierError::Corrupt),
            ScheduleErrorV2::CorruptCausalDag
        );

        let call = CallId([3; 32]);
        assert_eq!(
            validate_await_boundary(ConsistencyModeV2::Crdt, Some(call), None),
            Err(ScheduleErrorV2::CrdtAwaitUnsupported(call))
        );
        assert_eq!(
            validate_await_boundary(ConsistencyModeV2::Local, Some(call), None),
            Err(ScheduleErrorV2::MissingAwaitedReply(call))
        );
    }
}
