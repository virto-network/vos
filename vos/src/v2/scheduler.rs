//! Read-only construction of Refine work from guest-committed state.
//!
//! The scheduler selects work and imports. It never interprets a transition or
//! mutates service rows: successful output must still return to the canonical
//! service PVM's physical IC-5 Accumulate entry.

use alloc::boxed::Box;
use alloc::collections::{BTreeMap, BTreeSet};
use alloc::string::String;
use alloc::vec::Vec;
use core::convert::Infallible;

use super::causal::{
    CausalFrontierError, CausalFrontierV2, CausalSelectionError, load_causal_frontier,
};
use super::contracts::crdt_change_blob_references;
use super::guest_accumulate::materialized_continuations;
use super::{
    AccumulatedReplyV2, AccumulatedTimeoutV2, ActorDirectoryV2, ActorGenesisV2, ActorId,
    AuthorizationEvidenceV2, BlobRefV2, CallExpirationEnvelopeV2, CallId, CallTimeoutV2,
    CausalCallContextV2, ConsistencyBaseV2, ConsistencyModeV2, ContinuationSnapshotV2,
    CrdtChangeV2, CrdtSyncEnvelopeV2, CrdtSyncNodeV2, DecodeError, DeliveryEnvelopeV2,
    DirectIngressV2, ExternalActorDirectoryV2, ImportedActorV2, ImportedBlobV2, ImportedProgramV2,
    InvocationId, LocalJamStoreV2, LocalStoreReadErrorV2, MessageRecordV2, Origin, RefineImportsV2,
    ServiceIdentityV2, StateKeyV2, V2Wire, WorkEnvelopeV2, WorkflowCheckpointV2,
    WorkflowOperationV2, crdt_node_receipt_storage_key, crdt_node_storage_key,
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
    pub awaited_timeout: Option<AccumulatedTimeoutV2>,
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
    MissingAwaitedReply(CallId),
    UnexpectedAwaitedReply(CallId),
    InvocationAlreadyCommitted(InvocationId),
    InvalidWorkflowStep(InvocationId),
    MissingInbox(CallId),
    InvalidInbox(CallId),
    DeadlineExpired(CallId),
    InvalidCausalContext,
    InvalidDelivery,
    MissingCausalDependency(super::Hash),
    MissingNodeReceipt(super::Hash),
    InvalidNodeReceipt(super::Hash),
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
    /// Bind stable caller input to the service's exact current linear revision
    /// or causal frontier. CRDT admission becomes a workflow DAG node before
    /// Refine runs; constructing this input is read-only.
    pub fn prepare_direct_ingress(
        store: &LocalJamStoreV2,
        service: &ServiceIdentityV2,
        request: &LocalWorkRequestV2,
    ) -> Result<DirectIngressV2, ScheduleErrorV2> {
        if request.workflow_step != 0
            || request.causal_parent.is_some()
            || request.parent_call.is_some()
            || request.causal_context.is_some()
            || request.awaited_reply.is_some()
            || request.awaited_timeout.is_some()
        {
            return Err(ScheduleErrorV2::InvalidWorkflowStep(request.invocation));
        }
        let header = store.header()?.ok_or(ScheduleErrorV2::StoreUninitialized)?;
        if header.service != *service {
            return Err(ScheduleErrorV2::StoreUninitialized);
        }
        let initial_base = if header.consistency == ConsistencyModeV2::Crdt {
            ConsistencyBaseV2::Crdt {
                heads: header.crdt_heads.clone(),
            }
        } else {
            ConsistencyBaseV2::Linear {
                revision: header.revision,
                state_root: header
                    .state_root
                    .ok_or(ScheduleErrorV2::UnsupportedConsistency(header.consistency))?,
            }
        };
        let mut ingress = DirectIngressV2 {
            service: service.clone(),
            invocation: request.invocation,
            logical_timeslot: request.logical_timeslot,
            target: request.target,
            method: request.method.clone(),
            arguments: request.arguments.clone(),
            origin: request.origin,
            authorization: request.authorization.clone(),
            imported_blobs: request.imported_blobs.clone(),
            proof_requested: request.proof_requested,
            base: initial_base,
            base_causal_height: None,
            crdt_change: None,
        };
        if header.consistency == ConsistencyModeV2::Crdt {
            let heads = header.crdt_heads;
            let frontier = match load_causal_frontier(&heads, |cid| {
                Ok::<_, Infallible>(store.row(&crdt_node_storage_key(cid)).map(Vec::from))
            }) {
                Ok(frontier) => frontier,
                Err(CausalFrontierError::Missing(dependency)) => {
                    return Err(ScheduleErrorV2::MissingCausalDependency(dependency));
                }
                Err(CausalFrontierError::Corrupt) => {
                    return Err(ScheduleErrorV2::CorruptCausalDag);
                }
                Err(CausalFrontierError::Storage(error)) => match error {},
            };
            let height = frontier.max_head_height;
            ingress.base = ConsistencyBaseV2::Crdt {
                heads: heads.clone(),
            };
            ingress.base_causal_height = Some(height);
            let operation = ingress.crdt_operation();
            ingress.crdt_change = Some(CrdtChangeV2 {
                id: CrdtChangeV2::derive_ingress_id(&operation, &heads),
                work_hash: operation.commitment(),
                causal_dependencies: heads,
                causal_height: height
                    .checked_add(1)
                    .ok_or(ScheduleErrorV2::CorruptCausalDag)?,
                operations: Vec::new(),
                workflow: alloc::vec![WorkflowOperationV2::Ingress(operation)],
                materializations: Vec::new(),
                awaited_reply: None,
                exported_blobs: Vec::new(),
            });
        } else if !matches!(
            header.consistency,
            ConsistencyModeV2::Local | ConsistencyModeV2::Raft
        ) {
            return Err(ScheduleErrorV2::UnsupportedConsistency(header.consistency));
        }
        DirectIngressV2::decode(&ingress.encode()).map_err(|_| ScheduleErrorV2::NonCanonicalImports)
    }

    /// Export the complete authenticated causal DAG for another replica. This
    /// is a read-only transport helper: the destination still submits the
    /// envelope to physical IC-5, where guest Accumulate verifies every node
    /// receipt, dependency, blob, and workflow operation before committing.
    pub fn prepare_crdt_sync(
        store: &LocalJamStoreV2,
    ) -> Result<CrdtSyncEnvelopeV2, ScheduleErrorV2> {
        let header = store.header()?.ok_or(ScheduleErrorV2::StoreUninitialized)?;
        if header.consistency != ConsistencyModeV2::Crdt {
            return Err(ScheduleErrorV2::UnsupportedConsistency(header.consistency));
        }
        if header.crdt_heads.is_empty() {
            return Err(ScheduleErrorV2::CorruptCausalDag);
        }
        let frontier = match load_causal_frontier(&header.crdt_heads, |cid| {
            Ok::<_, Infallible>(store.row(&crdt_node_storage_key(cid)).map(Vec::from))
        }) {
            Ok(frontier) => frontier,
            Err(CausalFrontierError::Missing(cid)) => {
                return Err(ScheduleErrorV2::MissingCausalDependency(cid));
            }
            Err(CausalFrontierError::Corrupt) => {
                return Err(ScheduleErrorV2::CorruptCausalDag);
            }
            Err(CausalFrontierError::Storage(error)) => match error {},
        };
        let mut blobs = BTreeMap::new();
        let mut nodes = Vec::new();
        for (cid, change) in frontier.nodes_in_causal_order() {
            let receipt_bytes = store
                .row(&crdt_node_receipt_storage_key(cid))
                .ok_or(ScheduleErrorV2::MissingNodeReceipt(cid))?;
            let receipt = super::AccumulationReceiptV2::decode(receipt_bytes)
                .map_err(|_| ScheduleErrorV2::InvalidNodeReceipt(cid))?;
            for reference in crdt_change_blob_references(change) {
                import_blob(store, &mut blobs, reference)?;
            }
            nodes.push(CrdtSyncNodeV2 {
                change: change.clone(),
                receipt,
            });
        }
        nodes.sort_by_key(|node| node.change.cid());
        let envelope = CrdtSyncEnvelopeV2 {
            service: header.service,
            advertised_heads: header.crdt_heads,
            nodes,
            provided_blobs: blobs.into_values().collect(),
        };
        CrdtSyncEnvelopeV2::decode(&envelope.encode())
            .map_err(|_| ScheduleErrorV2::CorruptCausalDag)
    }

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

    /// Construct the canonical guest Accumulate request for one due outbound
    /// call. `logical_timeslot` is consensus scheduler input; the committed
    /// outcome itself uses the deadline as its deterministic effective time.
    pub fn prepare_call_expiration(
        store: &LocalJamStoreV2,
        invocation: InvocationId,
        logical_timeslot: u64,
    ) -> Result<Option<CallExpirationEnvelopeV2>, ScheduleErrorV2> {
        let header = store.header()?.ok_or(ScheduleErrorV2::StoreUninitialized)?;
        let Some(workflow) = decode_row::<WorkflowCheckpointV2>(
            store,
            header.service_root,
            &StateKeyV2::Workflow(invocation),
        )?
        else {
            return Ok(None);
        };
        let Some(continuation) = decode_row::<BlobRefV2>(
            store,
            header.service_root,
            &StateKeyV2::Continuation(workflow.resume_work.target),
        )?
        else {
            return Ok(None);
        };
        let bytes = store
            .blob(&continuation)
            .ok_or(ScheduleErrorV2::MissingBlob(continuation.hash))?;
        let snapshot = ContinuationSnapshotV2::decode(bytes)
            .map_err(|_| ScheduleErrorV2::InvalidContinuation(workflow.resume_work.target))?;
        snapshot
            .validate_checkpoint_for(&workflow.resume_work)
            .map_err(|_| ScheduleErrorV2::InvalidContinuation(workflow.resume_work.target))?;
        let Some(call) = snapshot.pending_call else {
            return Ok(None);
        };
        if store.call_expiration(call)?.is_some() {
            return Ok(None);
        }
        let message = store
            .outbox_message(call)?
            .ok_or(ScheduleErrorV2::MissingAwaitedReply(call))?;
        let Some(deadline_timeslot) = message.deadline_timeslot else {
            return Ok(None);
        };
        if logical_timeslot < deadline_timeslot {
            return Ok(None);
        }
        if message.caller_invocation != invocation
            || message.await_ordinal != snapshot.await_ordinal
            || Some(message.from) != snapshot.pending_actor
        {
            return Err(ScheduleErrorV2::InvalidContinuation(
                workflow.resume_work.target,
            ));
        }
        let timeout = CallTimeoutV2 {
            call_id: call,
            caller_invocation: invocation,
            caller_actor: message.from,
            checkpoint_step: workflow.input.workflow_step,
            await_ordinal: snapshot.await_ordinal,
            deadline_timeslot,
            expired_at: deadline_timeslot,
        };
        let (base, base_causal_height, crdt_change) =
            if header.consistency == ConsistencyModeV2::Crdt {
                let heads = header.crdt_heads.clone();
                let frontier = load_causal_frontier(&heads, |cid| {
                    Ok::<_, Infallible>(store.row(&crdt_node_storage_key(cid)).map(Vec::from))
                })
                .map_err(schedule_causal_error)?;
                let height = frontier.max_head_height;
                let change = CrdtChangeV2 {
                    id: CrdtChangeV2::derive_expiration_id(&header.service, &timeout, &heads),
                    work_hash: timeout.commitment(),
                    causal_dependencies: heads.clone(),
                    causal_height: height
                        .checked_add(1)
                        .ok_or(ScheduleErrorV2::CorruptCausalDag)?,
                    operations: Vec::new(),
                    workflow: alloc::vec![WorkflowOperationV2::ExpireCall(timeout.clone())],
                    materializations: Vec::new(),
                    awaited_reply: None,
                    exported_blobs: Vec::new(),
                };
                (
                    ConsistencyBaseV2::Crdt { heads },
                    Some(height),
                    Some(change),
                )
            } else {
                (
                    ConsistencyBaseV2::Linear {
                        revision: header.revision,
                        state_root: header
                            .state_root
                            .ok_or(ScheduleErrorV2::UnsupportedConsistency(header.consistency))?,
                    },
                    None,
                    None,
                )
            };
        Ok(Some(CallExpirationEnvelopeV2 {
            service: header.service,
            timeout,
            base,
            base_causal_height,
            crdt_change,
        }))
    }

    /// Rediscover every due timeout solely from guest-owned durable rows.
    /// The returned envelopes remain read-only proposals until physical IC-5
    /// Accumulate validates them against its trusted ambient JAM slot.
    pub fn prepare_due_call_expirations(
        store: &LocalJamStoreV2,
        logical_timeslot: u64,
    ) -> Result<Vec<CallExpirationEnvelopeV2>, ScheduleErrorV2> {
        let mut due = Vec::new();
        for deadline in store.pending_call_deadlines()? {
            if logical_timeslot < deadline.deadline_timeslot {
                continue;
            }
            let expiration =
                Self::prepare_call_expiration(store, deadline.caller_invocation, logical_timeslot)?
                    .ok_or(ScheduleErrorV2::InvalidWorkflowStep(
                        deadline.caller_invocation,
                    ))?;
            if expiration.timeout.call_id != deadline.call_id
                || expiration.timeout.deadline_timeslot != deadline.deadline_timeslot
            {
                return Err(ScheduleErrorV2::InvalidContinuation(
                    expiration.timeout.caller_actor,
                ));
            }
            due.push(expiration);
        }
        Ok(due)
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
        Self::prepare_resume_outcome(store, invocation, logical_timeslot, awaited_reply, None)
    }

    /// Reconstruct a timed-out continuation solely from guest-owned workflow
    /// and expiration rows. No host-created error payload is accepted.
    pub fn prepare_timeout_resume(
        store: &LocalJamStoreV2,
        invocation: InvocationId,
        logical_timeslot: u64,
    ) -> Result<Option<PreparedWorkV2>, ScheduleErrorV2> {
        let header = store.header()?.ok_or(ScheduleErrorV2::StoreUninitialized)?;
        let Some(workflow) = decode_row::<WorkflowCheckpointV2>(
            store,
            header.service_root,
            &StateKeyV2::Workflow(invocation),
        )?
        else {
            return Ok(None);
        };
        let Some(continuation) = decode_row::<BlobRefV2>(
            store,
            header.service_root,
            &StateKeyV2::Continuation(workflow.resume_work.target),
        )?
        else {
            return Ok(None);
        };
        let bytes = store
            .blob(&continuation)
            .ok_or(ScheduleErrorV2::MissingBlob(continuation.hash))?;
        let snapshot = ContinuationSnapshotV2::decode(bytes)
            .map_err(|_| ScheduleErrorV2::InvalidContinuation(workflow.resume_work.target))?;
        snapshot
            .validate_checkpoint_for(&workflow.resume_work)
            .map_err(|_| ScheduleErrorV2::InvalidContinuation(workflow.resume_work.target))?;
        let Some(call) = snapshot.pending_call else {
            return Ok(None);
        };
        let Some(timeout) = store.call_expiration(call)? else {
            return Ok(None);
        };
        Self::prepare_resume_outcome(store, invocation, logical_timeslot, None, Some(timeout))
            .map(Some)
    }

    /// Rediscover workflows whose durable timeout outcome has committed but
    /// whose exact continuation has not consumed it yet. This deliberately
    /// walks expiration rows rather than deadline rows: expiration removes
    /// the deadline atomically before host orchestration can resume the VM.
    pub fn pending_timeout_resumes(
        store: &LocalJamStoreV2,
    ) -> Result<Vec<InvocationId>, ScheduleErrorV2> {
        let mut pending = BTreeSet::new();
        for timeout in store.call_expirations()? {
            let invocation = timeout.expiration.timeout.caller_invocation;
            if !pending.contains(&invocation)
                && Self::prepare_timeout_resume(store, invocation, 0)?.is_some()
            {
                pending.insert(invocation);
            }
        }
        Ok(pending.into_iter().collect())
    }

    fn prepare_resume_outcome(
        store: &LocalJamStoreV2,
        invocation: InvocationId,
        logical_timeslot: u64,
        awaited_reply: Option<AccumulatedReplyV2>,
        awaited_timeout: Option<AccumulatedTimeoutV2>,
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
                awaited_timeout,
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
                awaited_timeout: None,
                imported_blobs: Vec::new(),
                proof_requested: message.proof_requested,
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
        let directory = decode_row::<ActorDirectoryV2>(
            store,
            header.service_root,
            &StateKeyV2::ActorDirectory,
        )?
        .ok_or(ScheduleErrorV2::CorruptActorDirectory)?;
        let external_directory = decode_row::<ExternalActorDirectoryV2>(
            store,
            header.service_root,
            &StateKeyV2::ExternalActorDirectory,
        )?
        .ok_or(ScheduleErrorV2::CorruptActorDirectory)?;
        if directory.actors.binary_search(&request.target).is_err() {
            return Err(ScheduleErrorV2::CorruptActorDirectory);
        }
        let descriptor_key = StateKeyV2::ActorDescriptor(request.target);
        let descriptor = decode_row::<ActorGenesisV2>(store, header.service_root, &descriptor_key)?
            .ok_or(ScheduleErrorV2::MissingActor(request.target))?;
        if descriptor.actor != request.target {
            return Err(ScheduleErrorV2::InvalidActorDescriptor(request.target));
        }
        validate_actor_consistency(descriptor.crdt, header.consistency, request.target)?;
        let root_continuation = if header.consistency == ConsistencyModeV2::Crdt {
            None
        } else {
            decode_row::<BlobRefV2>(
                store,
                header.service_root,
                &StateKeyV2::Continuation(request.target),
            )?
        };
        let workflow_key = StateKeyV2::Workflow(request.invocation);
        let workflow =
            decode_row::<WorkflowCheckpointV2>(store, header.service_root, &workflow_key)?;

        let program_bytes = store
            .program(descriptor.program)
            .ok_or(ScheduleErrorV2::MissingProgram(descriptor.program))?
            .to_vec();
        let (base, base_causal_height, mut states, causal_frontier, causal_continuations) =
            if header.consistency == ConsistencyModeV2::Crdt {
                let current = load_causal_frontier(&header.crdt_heads, |cid| {
                    Ok::<_, Infallible>(store.row(&crdt_node_storage_key(cid)).map(<[u8]>::to_vec))
                })
                .map_err(schedule_causal_error)?;
                let timeout_heads = request
                    .awaited_timeout
                    .as_ref()
                    .map(|timeout| timeout.receipt.resulting_crdt_heads.as_slice());
                let heads = selected_crdt_resume_heads(
                    &header.crdt_heads,
                    request.workflow_step,
                    request.invocation,
                    workflow
                        .as_ref()
                        .map(|checkpoint| checkpoint.transition_hash),
                    timeout_heads,
                )?;
                if request.workflow_step != 0
                    && heads.iter().any(|selected| {
                        !header
                            .crdt_heads
                            .iter()
                            .any(|head| current.contains_ancestor(*head, *selected))
                    })
                {
                    return Err(ScheduleErrorV2::CorruptCausalDag);
                }
                let frontier = if heads == header.crdt_heads {
                    current
                } else {
                    current
                        .at_heads(&heads)
                        .ok_or(ScheduleErrorV2::CorruptCausalDag)?
                };
                let height = frontier.max_head_height;
                let states = frontier
                    .actor_materializations(&descriptor)
                    .map_err(|error| match error {
                        CausalSelectionError::Corrupt => ScheduleErrorV2::CorruptCausalDag,
                    })?;
                let continuations = materialized_continuations(&frontier, &header.service)
                    .map_err(|_| ScheduleErrorV2::CorruptCausalDag)?;
                (
                    ConsistencyBaseV2::Crdt { heads },
                    Some(height),
                    states,
                    Some(frontier),
                    Some(continuations),
                )
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
                    None,
                    None,
                )
            };
        let state = states.remove(0);
        let continuation = selected_continuation(
            causal_continuations.as_ref(),
            request.target,
            root_continuation,
        );

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
            target_deployment: descriptor.deployment,
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
            awaited_timeout: request.awaited_timeout.map(Box::new),
            consistency: header.consistency,
            base,
            base_causal_height,
            imported_actors: Vec::new(),
            external_actors: external_directory.actors,
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
            name: descriptor.name.clone(),
            parent: descriptor.parent,
            deployment: descriptor.deployment,
            program: descriptor.program,
            state: state.clone(),
            causal_states: states.clone(),
            continuation: continuation.clone(),
        });

        let mut programs = BTreeMap::new();
        programs.insert(
            descriptor.program,
            ImportedProgramV2 {
                program: descriptor.program,
                pvm: program_bytes,
            },
        );
        let mut blobs = BTreeMap::new();
        import_blob(store, &mut blobs, &state)?;
        for reference in &states {
            import_blob(store, &mut blobs, reference)?;
        }
        if let Some(reference) = continuation.as_ref() {
            import_blob(store, &mut blobs, reference)?;
        }

        // Refine owns the complete root tree. Every sibling's exact code,
        // state frontier, and continuation is imported even when this slice
        // initially targets only one actor. CRDT siblings reuse the one
        // already validated causal frontier above.
        for actor in directory
            .actors
            .iter()
            .copied()
            .filter(|actor| *actor != request.target)
        {
            let descriptor = decode_row::<ActorGenesisV2>(
                store,
                header.service_root,
                &StateKeyV2::ActorDescriptor(actor),
            )?
            .ok_or(ScheduleErrorV2::CorruptActorDirectory)?;
            if descriptor.actor != actor {
                return Err(ScheduleErrorV2::CorruptActorDirectory);
            }
            validate_actor_consistency(descriptor.crdt, header.consistency, actor)?;
            let mut sibling_states =
                actor_states(store, &header, &descriptor, causal_frontier.as_ref())?;
            let sibling_state = sibling_states.remove(0);
            let root_sibling_continuation = if causal_continuations.is_some() {
                None
            } else {
                decode_row::<BlobRefV2>(
                    store,
                    header.service_root,
                    &StateKeyV2::Continuation(actor),
                )?
            };
            let sibling_continuation = selected_continuation(
                causal_continuations.as_ref(),
                actor,
                root_sibling_continuation,
            );
            work.imported_actors.push(ImportedActorV2 {
                actor,
                name: descriptor.name.clone(),
                parent: descriptor.parent,
                deployment: descriptor.deployment,
                program: descriptor.program,
                state: sibling_state.clone(),
                causal_states: sibling_states.clone(),
                continuation: sibling_continuation.clone(),
            });
            let pvm = store
                .program(descriptor.program)
                .ok_or(ScheduleErrorV2::MissingProgram(descriptor.program))?
                .to_vec();
            programs
                .entry(descriptor.program)
                .or_insert(ImportedProgramV2 {
                    program: descriptor.program,
                    pvm,
                });
            import_blob(store, &mut blobs, &sibling_state)?;
            for reference in &sibling_states {
                import_blob(store, &mut blobs, reference)?;
            }
            if let Some(reference) = sibling_continuation.as_ref() {
                import_blob(store, &mut blobs, reference)?;
            }
        }
        work.imported_actors.sort_by_key(|actor| actor.actor);
        work.imported_blobs.sort_by_key(|blob| blob.hash);
        if work
            .imported_blobs
            .windows(2)
            .any(|pair| pair[0].hash == pair[1].hash)
        {
            return Err(ScheduleErrorV2::NonCanonicalImports);
        }
        for reference in &work.imported_blobs {
            import_blob(store, &mut blobs, reference)?;
        }
        if let Some(proof) = work
            .awaited_reply
            .as_ref()
            .and_then(|reply| reply.attestation.as_ref())
            .map(|attestation| &attestation.proof.proof_blob)
        {
            import_blob(store, &mut blobs, proof)?;
        }
        let private_blobs = match &work.authorization {
            AuthorizationEvidenceV2::PrivateCredential { witness, .. } => {
                let bytes = store
                    .private_witness(witness)
                    .ok_or(ScheduleErrorV2::MissingBlob(witness.hash))?
                    .to_vec();
                alloc::vec![ImportedBlobV2 {
                    reference: witness.clone(),
                    bytes,
                }]
            }
            _ => Vec::new(),
        };
        let imports = RefineImportsV2 {
            programs: programs.into_values().collect(),
            blobs: blobs.into_values().collect(),
            private_blobs,
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
                snapshot.pending_call,
                work.awaited_reply.as_ref(),
                work.awaited_timeout.as_deref(),
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

fn selected_continuation(
    causal_continuations: Option<&BTreeMap<ActorId, Option<BlobRefV2>>>,
    actor: ActorId,
    root_continuation: Option<BlobRefV2>,
) -> Option<BlobRefV2> {
    match causal_continuations {
        Some(continuations) => continuations.get(&actor).cloned().flatten(),
        None => root_continuation,
    }
}

fn selected_crdt_resume_heads(
    current_heads: &[super::Hash],
    workflow_step: u64,
    invocation: InvocationId,
    checkpoint_head: Option<super::Hash>,
    timeout_heads: Option<&[super::Hash]>,
) -> Result<Vec<super::Hash>, ScheduleErrorV2> {
    if workflow_step == 0 {
        return Ok(current_heads.to_vec());
    }
    if let Some(heads) = timeout_heads {
        if heads.is_empty() {
            return Err(ScheduleErrorV2::CorruptCausalDag);
        }
        return Ok(heads.to_vec());
    }
    checkpoint_head
        .map(|head| alloc::vec![head])
        .ok_or(ScheduleErrorV2::InvalidWorkflowStep(invocation))
}

fn schedule_causal_error(error: CausalFrontierError<Infallible>) -> ScheduleErrorV2 {
    match error {
        CausalFrontierError::Missing(cid) => ScheduleErrorV2::MissingCausalDependency(cid),
        CausalFrontierError::Corrupt => ScheduleErrorV2::CorruptCausalDag,
        CausalFrontierError::Storage(error) => match error {},
    }
}

fn validate_await_boundary(
    pending_call: Option<CallId>,
    awaited_reply: Option<&AccumulatedReplyV2>,
    awaited_timeout: Option<&AccumulatedTimeoutV2>,
) -> Result<(), ScheduleErrorV2> {
    match (pending_call, awaited_reply, awaited_timeout) {
        (None, None, None) => Ok(()),
        (Some(call), Some(reply), None) if reply.reply.call_id == call => Ok(()),
        (Some(call), None, Some(timeout)) if timeout.expiration.timeout.call_id == call => Ok(()),
        (Some(call), None, None) => Err(ScheduleErrorV2::MissingAwaitedReply(call)),
        (_, Some(reply), _) => Err(ScheduleErrorV2::UnexpectedAwaitedReply(reply.reply.call_id)),
        (_, _, Some(timeout)) => Err(ScheduleErrorV2::UnexpectedAwaitedReply(
            timeout.expiration.timeout.call_id,
        )),
    }
}

fn actor_states(
    store: &LocalJamStoreV2,
    header: &super::StoreHeaderV2,
    descriptor: &ActorGenesisV2,
    causal_frontier: Option<&CausalFrontierV2>,
) -> Result<Vec<BlobRefV2>, ScheduleErrorV2> {
    if header.consistency != ConsistencyModeV2::Crdt {
        let state_key = StateKeyV2::ActorRow {
            actor: descriptor.actor,
            key: crate::actors::lifecycle::STATE_KEY_BYTES.to_vec(),
        };
        return decode_row(store, header.service_root, &state_key)?
            .map(|state| alloc::vec![state])
            .ok_or(ScheduleErrorV2::MissingState(descriptor.actor));
    }

    causal_frontier
        .ok_or(ScheduleErrorV2::CorruptCausalDag)?
        .actor_materializations(descriptor)
        .map_err(|error| match error {
            CausalSelectionError::Corrupt => ScheduleErrorV2::CorruptCausalDag,
        })
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
            validate_await_boundary(Some(call), None, None),
            Err(ScheduleErrorV2::MissingAwaitedReply(call))
        );
        assert_eq!(
            validate_await_boundary(Some(call), None, None),
            Err(ScheduleErrorV2::MissingAwaitedReply(call))
        );
    }

    #[test]
    fn selected_causal_continuations_override_the_later_merged_root() {
        let actor = ActorId([4; 32]);
        let branch = BlobRefV2::of_bytes(b"branch checkpoint");
        let merged = BlobRefV2::of_bytes(b"later merged checkpoint");
        let selected = BTreeMap::from([(actor, Some(branch.clone()))]);

        assert_eq!(
            selected_continuation(Some(&selected), actor, Some(merged.clone())),
            Some(branch),
            "a resumed slice imports the continuation from its selected causal branch"
        );

        let completed = BTreeMap::from([(actor, None)]);
        assert_eq!(
            selected_continuation(Some(&completed), actor, Some(merged.clone())),
            None,
            "branch-local completion must not resurrect a later root continuation"
        );
        assert_eq!(
            selected_continuation(None, actor, Some(merged.clone())),
            Some(merged),
            "linear scheduling continues to read the current service root"
        );
    }

    #[test]
    fn timeout_resume_descends_from_the_expiration_head() {
        let invocation = InvocationId([9; 32]);
        let checkpoint = super::super::Hash([10; 32]);
        let expiration = super::super::Hash([11; 32]);
        let merged = super::super::Hash([12; 32]);

        assert_eq!(
            selected_crdt_resume_heads(
                &[merged],
                1,
                invocation,
                Some(checkpoint),
                Some(&[expiration]),
            ),
            Ok(vec![expiration]),
            "the pre-expiration checkpoint still contains the outbox"
        );
        assert_eq!(
            selected_crdt_resume_heads(&[merged], 1, invocation, Some(checkpoint), None),
            Ok(vec![checkpoint]),
            "ordinary reply resumes remain bound to their captured checkpoint"
        );
    }
}
