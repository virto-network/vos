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
    CausalFrontier, CausalFrontierError, CausalSelectionError, load_causal_frontier,
};
use super::contracts::crdt_change_blob_references;
use super::guest_accumulate::materialized_continuations;
use super::{
    AccumulatedReply, AccumulatedTimeout, ActorDirectory, ActorGenesis, ActorId, ActorStorageKey,
    ActorStorageRow, AuthorizationEvidence, BlobRef, CallExpirationEnvelope, CallId, CallTimeout,
    CausalCallContext, ConsistencyBase, ConsistencyMode, ContinuationSnapshot, CrdtChange,
    CrdtSyncEnvelope, CrdtSyncNode, DecodeError, DeliveryEnvelope, DeliveryRecord, DirectIngress,
    ExternalActorDirectory, ImportedActor, ImportedBlob, ImportedProgram, InboxRetirement,
    InvocationId, LocalJamStore, LocalStoreReadError, MessageRecord, Origin, RefineImports,
    ServiceIdentity, ServiceWire, StateKey, WorkEnvelope, WorkflowCheckpoint, WorkflowOperation,
    crdt_node_receipt_storage_key, crdt_node_storage_key, delivery_storage_key,
};

/// Caller-controlled portion of one local work item. The scheduler supplies
/// service identity, program identity, consistency base, actor state, and an
/// exact continuation from the committed service account.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct LocalWorkRequest {
    pub invocation: InvocationId,
    pub workflow_step: u64,
    pub logical_timeslot: u64,
    pub target: ActorId,
    pub method: String,
    pub arguments: Vec<u8>,
    pub origin: Origin,
    pub authorization: AuthorizationEvidence,
    pub causal_parent: Option<InvocationId>,
    pub parent_call: Option<CallId>,
    pub causal_context: Option<CausalCallContext>,
    pub awaited_reply: Option<AccumulatedReply>,
    pub awaited_timeout: Option<AccumulatedTimeout>,
    pub imported_blobs: Vec<BlobRef>,
    pub proof_requested: bool,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PreparedWork {
    pub work: WorkEnvelope,
    pub imports: RefineImports,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ScheduleError {
    Store(LocalStoreReadError),
    StoreUninitialized,
    UnsupportedConsistency(ConsistencyMode),
    MissingActor(ActorId),
    InvalidActorDescriptor(ActorId),
    CorruptActorDirectory,
    ActorConsistencyMismatch(ActorId),
    MissingProgram(super::ProgramId),
    MissingState(ActorId),
    MissingBlob(super::Hash),
    InvalidRow(StateKey, DecodeError),
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
    ActorStorageWitnessLimit,
}

impl core::fmt::Display for ScheduleError {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        write!(f, "cannot schedule VOS service work: {self:?}")
    }
}

impl core::error::Error for ScheduleError {}

impl From<LocalStoreReadError> for ScheduleError {
    fn from(value: LocalStoreReadError) -> Self {
        Self::Store(value)
    }
}

pub struct LocalWorkScheduler;

impl LocalWorkScheduler {
    /// Extend a prepared linear slice with the exact actor rows discovered by
    /// a speculative Refine run. Every value is read at the work's committed
    /// base root; absence is explicit. Refine is then restarted from its
    /// original machine state, so actors never observe the provisional
    /// HOST_NONE results.
    pub fn hydrate_actor_storage_rows(
        store: &LocalJamStore,
        prepared: &mut PreparedWork,
        requests: &[ActorStorageKey],
    ) -> Result<(), ScheduleError> {
        let ConsistencyBase::Linear { state_root, .. } = &prepared.work.base else {
            return Err(ScheduleError::UnsupportedConsistency(
                prepared.work.consistency,
            ));
        };
        if requests.is_empty()
            || requests.len() > super::MAX_ACTOR_STORAGE_WITNESSES
            || requests.windows(2).any(|pair| pair[0] >= pair[1])
        {
            return Err(ScheduleError::NonCanonicalImports);
        }

        let existing_count = prepared
            .work
            .imported_actors
            .iter()
            .map(|actor| actor.storage_rows.len())
            .sum::<usize>();
        if existing_count.saturating_add(requests.len()) > super::MAX_ACTOR_STORAGE_WITNESSES {
            return Err(ScheduleError::NonCanonicalImports);
        }
        let mut value_bytes = prepared
            .work
            .imported_actors
            .iter()
            .flat_map(|actor| &actor.storage_rows)
            .filter_map(|row| row.value.as_ref())
            .try_fold(0usize, |total, value| {
                usize::try_from(value.len)
                    .ok()
                    .and_then(|len| total.checked_add(len))
            })
            .ok_or(ScheduleError::NonCanonicalImports)?;

        for request in requests {
            if request.key.is_empty() || request.key.len() > super::MAX_ACTOR_STORAGE_KEY_BYTES {
                return Err(ScheduleError::NonCanonicalImports);
            }
            let actor = prepared
                .work
                .imported_actors
                .iter_mut()
                .find(|actor| actor.actor == request.actor)
                .ok_or(ScheduleError::MissingActor(request.actor))?;
            if actor
                .storage_rows
                .binary_search_by(|row| row.key.cmp(&request.key))
                .is_ok()
            {
                return Err(ScheduleError::NonCanonicalImports);
            }
            let key = StateKey::ActorRow {
                actor: request.actor,
                key: request.key.clone(),
            };
            let value = store.state_row(*state_root, &key)?;
            let value = if let Some(bytes) = value {
                value_bytes = value_bytes
                    .checked_add(bytes.len())
                    .filter(|total| *total <= super::MAX_ACTOR_STORAGE_WITNESS_BYTES)
                    .ok_or(ScheduleError::NonCanonicalImports)?;
                let reference = BlobRef::of_bytes(&bytes);
                match prepared
                    .imports
                    .blobs
                    .binary_search_by_key(&reference.hash, |blob| blob.reference.hash)
                {
                    Ok(index)
                        if prepared.imports.blobs[index].reference == reference
                            && prepared.imports.blobs[index].bytes == bytes => {}
                    Ok(_) => return Err(ScheduleError::NonCanonicalImports),
                    Err(index) => prepared.imports.blobs.insert(
                        index,
                        ImportedBlob {
                            reference: reference.clone(),
                            bytes,
                        },
                    ),
                }
                Some(reference)
            } else {
                None
            };
            let index = actor
                .storage_rows
                .binary_search_by(|row| row.key.cmp(&request.key))
                .unwrap_err();
            actor.storage_rows.insert(
                index,
                ActorStorageRow {
                    key: request.key.clone(),
                    value,
                },
            );
        }
        Ok(())
    }

    /// Bind stable caller input to the service's exact current linear revision
    /// or causal frontier. CRDT admission becomes a workflow DAG node before
    /// Refine runs; constructing this input is read-only.
    pub fn prepare_direct_ingress(
        store: &LocalJamStore,
        service: &ServiceIdentity,
        request: &LocalWorkRequest,
    ) -> Result<DirectIngress, ScheduleError> {
        if request.workflow_step != 0
            || request.causal_parent.is_some()
            || request.parent_call.is_some()
            || request.causal_context.is_some()
            || request.awaited_reply.is_some()
            || request.awaited_timeout.is_some()
        {
            return Err(ScheduleError::InvalidWorkflowStep(request.invocation));
        }
        let header = store.header()?.ok_or(ScheduleError::StoreUninitialized)?;
        if header.service != *service {
            return Err(ScheduleError::StoreUninitialized);
        }
        let initial_base = if header.consistency == ConsistencyMode::Crdt {
            ConsistencyBase::Crdt {
                heads: header.crdt_heads.clone(),
            }
        } else {
            ConsistencyBase::Linear {
                revision: header.revision,
                state_root: header
                    .state_root
                    .ok_or(ScheduleError::UnsupportedConsistency(header.consistency))?,
            }
        };
        let mut ingress = DirectIngress {
            service: service.clone(),
            invocation: request.invocation,
            logical_timeslot: request.logical_timeslot,
            target: request.target,
            method: request.method.clone(),
            arguments: request.arguments.clone(),
            private_arguments: None,
            origin: request.origin,
            authorization: request.authorization.clone(),
            imported_blobs: request.imported_blobs.clone(),
            proof_requested: request.proof_requested,
            base: initial_base,
            base_causal_height: None,
            crdt_change: None,
        };
        if header.consistency == ConsistencyMode::Crdt {
            let heads = header.crdt_heads;
            let frontier = match load_causal_frontier(&heads, |cid| {
                Ok::<_, Infallible>(store.row(&crdt_node_storage_key(cid)).map(Vec::from))
            }) {
                Ok(frontier) => frontier,
                Err(CausalFrontierError::Missing(dependency)) => {
                    return Err(ScheduleError::MissingCausalDependency(dependency));
                }
                Err(CausalFrontierError::Corrupt) => {
                    return Err(ScheduleError::CorruptCausalDag);
                }
                Err(CausalFrontierError::Storage(error)) => match error {},
            };
            let height = frontier.max_head_height;
            ingress.base = ConsistencyBase::Crdt {
                heads: heads.clone(),
            };
            ingress.base_causal_height = Some(height);
            let operation = ingress.crdt_operation();
            ingress.crdt_change = Some(CrdtChange {
                id: CrdtChange::derive_ingress_id(&operation, &heads),
                work_hash: operation.commitment(),
                causal_dependencies: heads,
                causal_height: height
                    .checked_add(1)
                    .ok_or(ScheduleError::CorruptCausalDag)?,
                operations: Vec::new(),
                workflow: alloc::vec![WorkflowOperation::Ingress(operation)],
                materializations: Vec::new(),
                awaited_reply: None,
                exported_blobs: Vec::new(),
            });
        } else if !matches!(
            header.consistency,
            ConsistencyMode::Local | ConsistencyMode::Raft
        ) {
            return Err(ScheduleError::UnsupportedConsistency(header.consistency));
        }
        DirectIngress::decode(&ingress.encode()).map_err(|_| ScheduleError::NonCanonicalImports)
    }

    /// Export the complete authenticated causal DAG for another replica. This
    /// is a read-only transport helper: the destination still submits the
    /// envelope to physical IC-5, where guest Accumulate verifies every node
    /// receipt, dependency, blob, and workflow operation before committing.
    pub fn prepare_crdt_sync(store: &LocalJamStore) -> Result<CrdtSyncEnvelope, ScheduleError> {
        let header = store.header()?.ok_or(ScheduleError::StoreUninitialized)?;
        if header.consistency != ConsistencyMode::Crdt {
            return Err(ScheduleError::UnsupportedConsistency(header.consistency));
        }
        if header.crdt_heads.is_empty() {
            return Err(ScheduleError::CorruptCausalDag);
        }
        let frontier = match load_causal_frontier(&header.crdt_heads, |cid| {
            Ok::<_, Infallible>(store.row(&crdt_node_storage_key(cid)).map(Vec::from))
        }) {
            Ok(frontier) => frontier,
            Err(CausalFrontierError::Missing(cid)) => {
                return Err(ScheduleError::MissingCausalDependency(cid));
            }
            Err(CausalFrontierError::Corrupt) => {
                return Err(ScheduleError::CorruptCausalDag);
            }
            Err(CausalFrontierError::Storage(error)) => match error {},
        };
        let mut blobs = BTreeMap::new();
        let mut nodes = Vec::new();
        for (cid, change) in frontier.nodes_in_causal_order() {
            let receipt_bytes = store
                .row(&crdt_node_receipt_storage_key(cid))
                .ok_or(ScheduleError::MissingNodeReceipt(cid))?;
            let receipt = super::AccumulationReceipt::decode(receipt_bytes)
                .map_err(|_| ScheduleError::InvalidNodeReceipt(cid))?;
            for reference in crdt_change_blob_references(change) {
                import_blob(store, &mut blobs, reference)?;
            }
            nodes.push(CrdtSyncNode {
                change: change.clone(),
                receipt,
            });
        }
        nodes.sort_by_key(|node| node.change.cid());
        let envelope = CrdtSyncEnvelope {
            service: header.service,
            advertised_heads: header.crdt_heads,
            nodes,
            provided_blobs: blobs.into_values().collect(),
        };
        // Do not round-trip the complete export through the bounded wire
        // decoder: histories may legitimately contain more nodes than one
        // network frame/list. The frontier loader, receipt decoders, blob
        // importer, BTree ordering and header validation above establish the
        // same invariants; the node transport subsequently emits canonical,
        // independently decoded bounded deltas.
        Ok(envelope)
    }

    /// Build the exact destination Accumulate input for one finalized
    /// cross-root outbox record. This is read-only scheduling: the physical
    /// service PVM independently verifies and commits the inbox.
    pub fn prepare_delivery(
        store: &LocalJamStore,
        logical_timeslot: u64,
        message: MessageRecord,
        source_outbox: Vec<MessageRecord>,
        source_receipt: super::AccumulationReceipt,
    ) -> Result<DeliveryEnvelope, ScheduleError> {
        Self::prepare_authorized_delivery(
            store,
            logical_timeslot,
            AuthorizationEvidence::Public,
            message,
            source_outbox,
            source_receipt,
        )
    }

    /// Build a delivery whose source bytes remain public while the
    /// destination commits separately authenticated authorization evidence.
    pub fn prepare_authorized_delivery(
        store: &LocalJamStore,
        logical_timeslot: u64,
        authorization: AuthorizationEvidence,
        message: MessageRecord,
        source_outbox: Vec<MessageRecord>,
        source_receipt: super::AccumulationReceipt,
    ) -> Result<DeliveryEnvelope, ScheduleError> {
        let header = store.header()?.ok_or(ScheduleError::StoreUninitialized)?;
        let base = if header.consistency == ConsistencyMode::Crdt {
            ConsistencyBase::Crdt {
                heads: header.crdt_heads,
            }
        } else {
            ConsistencyBase::Linear {
                revision: header.revision,
                state_root: header
                    .state_root
                    .ok_or(ScheduleError::UnsupportedConsistency(header.consistency))?,
            }
        };
        let envelope = DeliveryEnvelope {
            service: header.service,
            logical_timeslot,
            base,
            authorization,
            message,
            source_outbox,
            source_receipt,
        };
        DeliveryEnvelope::decode(&envelope.encode()).map_err(|_| ScheduleError::InvalidDelivery)
    }

    /// Construct the canonical guest Accumulate request for one due outbound
    /// call. `logical_timeslot` is consensus scheduler input; the committed
    /// outcome itself uses the deadline as its deterministic effective time.
    pub fn prepare_call_expiration(
        store: &LocalJamStore,
        invocation: InvocationId,
        logical_timeslot: u64,
    ) -> Result<Option<CallExpirationEnvelope>, ScheduleError> {
        let header = store.header()?.ok_or(ScheduleError::StoreUninitialized)?;
        let Some(workflow) = decode_row::<WorkflowCheckpoint>(
            store,
            header.service_root,
            &StateKey::Workflow(invocation),
        )?
        else {
            return Ok(None);
        };
        let Some(continuation) = decode_row::<BlobRef>(
            store,
            header.service_root,
            &StateKey::Continuation(workflow.resume_work.target),
        )?
        else {
            return Ok(None);
        };
        let bytes = store
            .blob(&continuation)
            .ok_or(ScheduleError::MissingBlob(continuation.hash))?;
        let snapshot = ContinuationSnapshot::decode(bytes)
            .map_err(|_| ScheduleError::InvalidContinuation(workflow.resume_work.target))?;
        snapshot
            .validate_checkpoint_for(&workflow.resume_work)
            .map_err(|_| ScheduleError::InvalidContinuation(workflow.resume_work.target))?;
        let Some(call) = snapshot.pending_call else {
            return Ok(None);
        };
        if store.call_expiration(call)?.is_some() {
            return Ok(None);
        }
        let message = store
            .outbox_message(call)?
            .ok_or(ScheduleError::MissingAwaitedReply(call))?;
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
            return Err(ScheduleError::InvalidContinuation(
                workflow.resume_work.target,
            ));
        }
        let timeout = CallTimeout {
            call_id: call,
            caller_invocation: invocation,
            caller_actor: message.from,
            checkpoint_step: workflow.input.workflow_step,
            await_ordinal: snapshot.await_ordinal,
            deadline_timeslot,
            expired_at: deadline_timeslot,
        };
        let (base, base_causal_height, crdt_change) = if header.consistency == ConsistencyMode::Crdt
        {
            let heads = header.crdt_heads.clone();
            let frontier = load_causal_frontier(&heads, |cid| {
                Ok::<_, Infallible>(store.row(&crdt_node_storage_key(cid)).map(Vec::from))
            })
            .map_err(schedule_causal_error)?;
            let height = frontier.max_head_height;
            let change = CrdtChange {
                id: CrdtChange::derive_expiration_id(&header.service, &timeout, &heads),
                work_hash: timeout.commitment(),
                causal_dependencies: heads.clone(),
                causal_height: height
                    .checked_add(1)
                    .ok_or(ScheduleError::CorruptCausalDag)?,
                operations: Vec::new(),
                workflow: alloc::vec![WorkflowOperation::ExpireCall(timeout.clone())],
                materializations: Vec::new(),
                awaited_reply: None,
                exported_blobs: Vec::new(),
            };
            (ConsistencyBase::Crdt { heads }, Some(height), Some(change))
        } else {
            (
                ConsistencyBase::Linear {
                    revision: header.revision,
                    state_root: header
                        .state_root
                        .ok_or(ScheduleError::UnsupportedConsistency(header.consistency))?,
                },
                None,
                None,
            )
        };
        Ok(Some(CallExpirationEnvelope {
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
        store: &LocalJamStore,
        logical_timeslot: u64,
    ) -> Result<Vec<CallExpirationEnvelope>, ScheduleError> {
        let mut due = Vec::new();
        for deadline in store.pending_call_deadlines()? {
            if logical_timeslot < deadline.deadline_timeslot {
                continue;
            }
            let expiration =
                Self::prepare_call_expiration(store, deadline.caller_invocation, logical_timeslot)?
                    .ok_or(ScheduleError::InvalidWorkflowStep(
                        deadline.caller_invocation,
                    ))?;
            if expiration.timeout.call_id != deadline.call_id
                || expiration.timeout.deadline_timeslot != deadline.deadline_timeslot
            {
                return Err(ScheduleError::InvalidContinuation(
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
        store: &LocalJamStore,
        invocation: InvocationId,
        logical_timeslot: u64,
        awaited_reply: Option<AccumulatedReply>,
    ) -> Result<PreparedWork, ScheduleError> {
        Self::prepare_resume_outcome(store, invocation, logical_timeslot, awaited_reply, None)
    }

    /// Reconstruct a timed-out continuation solely from guest-owned workflow
    /// and expiration rows. No host-created error payload is accepted.
    pub fn prepare_timeout_resume(
        store: &LocalJamStore,
        invocation: InvocationId,
        logical_timeslot: u64,
    ) -> Result<Option<PreparedWork>, ScheduleError> {
        let header = store.header()?.ok_or(ScheduleError::StoreUninitialized)?;
        let Some(workflow) = decode_row::<WorkflowCheckpoint>(
            store,
            header.service_root,
            &StateKey::Workflow(invocation),
        )?
        else {
            return Ok(None);
        };
        let Some(continuation) = decode_row::<BlobRef>(
            store,
            header.service_root,
            &StateKey::Continuation(workflow.resume_work.target),
        )?
        else {
            return Ok(None);
        };
        let bytes = store
            .blob(&continuation)
            .ok_or(ScheduleError::MissingBlob(continuation.hash))?;
        let snapshot = ContinuationSnapshot::decode(bytes)
            .map_err(|_| ScheduleError::InvalidContinuation(workflow.resume_work.target))?;
        snapshot
            .validate_checkpoint_for(&workflow.resume_work)
            .map_err(|_| ScheduleError::InvalidContinuation(workflow.resume_work.target))?;
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
        store: &LocalJamStore,
    ) -> Result<Vec<InvocationId>, ScheduleError> {
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
        store: &LocalJamStore,
        invocation: InvocationId,
        logical_timeslot: u64,
        awaited_reply: Option<AccumulatedReply>,
        awaited_timeout: Option<AccumulatedTimeout>,
    ) -> Result<PreparedWork, ScheduleError> {
        let header = store.header()?.ok_or(ScheduleError::StoreUninitialized)?;
        let workflow = decode_row::<WorkflowCheckpoint>(
            store,
            header.service_root,
            &StateKey::Workflow(invocation),
        )?
        .ok_or(ScheduleError::InvalidWorkflowStep(invocation))?;
        let workflow_step = workflow
            .input
            .workflow_step
            .checked_add(1)
            .ok_or(ScheduleError::InvalidWorkflowStep(invocation))?;
        let template = workflow.resume_work;
        Self::prepare(
            store,
            LocalWorkRequest {
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
        store: &LocalJamStore,
        call: CallId,
        logical_timeslot: u64,
    ) -> Result<PreparedWork, ScheduleError> {
        let header = store.header()?.ok_or(ScheduleError::StoreUninitialized)?;
        let key = StateKey::Inbox(call);
        let message = decode_row::<super::MessageRecord>(store, header.service_root, &key)?
            .ok_or(ScheduleError::MissingInbox(call))?;
        if message.call_id != call {
            return Err(ScheduleError::InvalidInbox(call));
        }
        if message
            .deadline_timeslot
            .is_some_and(|deadline| logical_timeslot >= deadline)
        {
            return Err(ScheduleError::DeadlineExpired(call));
        }
        let method =
            dynamic_method(&message.payload).ok_or(ScheduleError::InvalidInbox(message.call_id))?;
        let causal_context = CausalCallContext::from(&message);
        Self::prepare(
            store,
            LocalWorkRequest {
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

    /// Construct the terminal guest request for one deadline-bearing linear
    /// inbox. The physical Accumulate host independently authenticates the
    /// observation slot; this read-only step binds the exact current base and
    /// admitted deadline.
    pub fn prepare_inbox_retirement(
        store: &LocalJamStore,
        call: CallId,
        logical_timeslot: u64,
    ) -> Result<Option<InboxRetirement>, ScheduleError> {
        let header = store.header()?.ok_or(ScheduleError::StoreUninitialized)?;
        if header.consistency == ConsistencyMode::Crdt {
            return Err(ScheduleError::UnsupportedConsistency(header.consistency));
        }
        let Some(bytes) = store.row(&delivery_storage_key(call)) else {
            return Err(ScheduleError::InvalidDelivery);
        };
        let delivery =
            DeliveryRecord::decode(&bytes).map_err(|_| ScheduleError::InvalidDelivery)?;
        if delivery.call_id != call {
            return Err(ScheduleError::InvalidDelivery);
        }
        if delivery.consumed || delivery.retired_at.is_some() {
            return Ok(None);
        }
        let message =
            decode_row::<MessageRecord>(store, header.service_root, &StateKey::Inbox(call))?
                .ok_or(ScheduleError::MissingInbox(call))?;
        let Some(deadline_timeslot) = message.deadline_timeslot else {
            return Ok(None);
        };
        if message.call_id != call || message.authorization != delivery.authorization {
            return Err(ScheduleError::InvalidDelivery);
        }
        if logical_timeslot < deadline_timeslot {
            return Ok(None);
        }
        Ok(Some(InboxRetirement {
            service: header.service,
            call_id: call,
            deadline_timeslot,
            base: ConsistencyBase::Linear {
                revision: header.revision,
                state_root: header
                    .state_root
                    .ok_or(ScheduleError::UnsupportedConsistency(header.consistency))?,
            },
        }))
    }

    /// Prepare one slice from the current committed linear revision or CRDT
    /// frontier. Both paths use the same guest-owned header and actor rows.
    pub fn prepare(
        store: &LocalJamStore,
        request: LocalWorkRequest,
    ) -> Result<PreparedWork, ScheduleError> {
        if request.method.is_empty() {
            return Err(ScheduleError::EmptyMethod);
        }
        let header = store.header()?.ok_or(ScheduleError::StoreUninitialized)?;
        let directory =
            decode_row::<ActorDirectory>(store, header.service_root, &StateKey::ActorDirectory)?
                .ok_or(ScheduleError::CorruptActorDirectory)?;
        let external_directory = decode_row::<ExternalActorDirectory>(
            store,
            header.service_root,
            &StateKey::ExternalActorDirectory,
        )?
        .ok_or(ScheduleError::CorruptActorDirectory)?;
        if directory.actors.binary_search(&request.target).is_err() {
            return Err(ScheduleError::CorruptActorDirectory);
        }
        let descriptor_key = StateKey::ActorDescriptor(request.target);
        let descriptor = decode_row::<ActorGenesis>(store, header.service_root, &descriptor_key)?
            .ok_or(ScheduleError::MissingActor(request.target))?;
        if descriptor.actor != request.target {
            return Err(ScheduleError::InvalidActorDescriptor(request.target));
        }
        validate_actor_consistency(descriptor.crdt, header.consistency, request.target)?;
        let root_continuation = if header.consistency == ConsistencyMode::Crdt {
            None
        } else {
            decode_row::<BlobRef>(
                store,
                header.service_root,
                &StateKey::Continuation(request.target),
            )?
        };
        let workflow_key = StateKey::Workflow(request.invocation);
        let workflow = decode_row::<WorkflowCheckpoint>(store, header.service_root, &workflow_key)?;

        let program_bytes = store
            .program(descriptor.program)
            .ok_or(ScheduleError::MissingProgram(descriptor.program))?
            .to_vec();
        let (base, base_causal_height, mut states, causal_frontier, causal_continuations) =
            if header.consistency == ConsistencyMode::Crdt {
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
                    return Err(ScheduleError::CorruptCausalDag);
                }
                let frontier = if heads == header.crdt_heads {
                    current
                } else {
                    current
                        .at_heads(&heads)
                        .ok_or(ScheduleError::CorruptCausalDag)?
                };
                let height = frontier.max_head_height;
                let states = frontier
                    .actor_materializations(&descriptor)
                    .map_err(|error| match error {
                        CausalSelectionError::Corrupt => ScheduleError::CorruptCausalDag,
                    })?;
                let continuations = materialized_continuations(&frontier, &header.service)
                    .map_err(|_| ScheduleError::CorruptCausalDag)?;
                (
                    ConsistencyBase::Crdt { heads },
                    Some(height),
                    states,
                    Some(frontier),
                    Some(continuations),
                )
            } else {
                let state_root = header
                    .state_root
                    .ok_or(ScheduleError::UnsupportedConsistency(header.consistency))?;
                let state_key = StateKey::ActorRow {
                    actor: request.target,
                    key: crate::actors::lifecycle::STATE_KEY_BYTES.to_vec(),
                };
                let state = decode_row::<BlobRef>(store, header.service_root, &state_key)?
                    .ok_or(ScheduleError::MissingState(request.target))?;
                (
                    ConsistencyBase::Linear {
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
            (0, Some(_), _) => return Err(ScheduleError::ActorBusy(request.target)),
            (0, None, Some(_)) => {
                return Err(ScheduleError::InvocationAlreadyCommitted(
                    request.invocation,
                ));
            }
            (0, None, None) => {}
            (_, None, _) => {
                return Err(ScheduleError::MissingContinuation(request.target));
            }
            (step, Some(_), Some(checkpoint))
                if checkpoint.input.invocation == request.invocation
                    && checkpoint.input.workflow_step.checked_add(1) == Some(step) => {}
            (_, Some(_), _) => {
                return Err(ScheduleError::InvalidWorkflowStep(request.invocation));
            }
        }

        let mut work = WorkEnvelope {
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
            private_arguments: None,
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
            _ => return Err(ScheduleError::InvalidCausalContext),
        }
        if let Some(context) = work.causal_context.as_ref()
            && context
                .deadline_timeslot
                .is_some_and(|deadline| work.logical_timeslot >= deadline)
        {
            return Err(ScheduleError::DeadlineExpired(context.call_id));
        }
        if request.workflow_step != 0
            && workflow
                .as_ref()
                .is_none_or(|checkpoint| !checkpoint.matches_resume_work(&work))
        {
            return Err(ScheduleError::InvalidWorkflowStep(request.invocation));
        }
        let task_dependencies = super::PackageRolePolicies::decode(&descriptor.role_policies)
            .map_err(|_| ScheduleError::InvalidActorDescriptor(request.target))?
            .task_dependencies;
        work.imported_actors.push(ImportedActor {
            actor: request.target,
            name: descriptor.name.clone(),
            parent: descriptor.parent,
            deployment: descriptor.deployment,
            program: descriptor.program,
            task_dependencies: task_dependencies.clone(),
            state: state.clone(),
            causal_states: states.clone(),
            continuation: continuation.clone(),
            storage_rows: Vec::new(),
        });

        let mut programs = BTreeMap::new();
        programs.insert(
            descriptor.program,
            ImportedProgram {
                program: descriptor.program,
                pvm: program_bytes,
            },
        );
        for dependency in &task_dependencies {
            let pvm = store
                .program(dependency.program)
                .ok_or(ScheduleError::MissingProgram(dependency.program))?
                .to_vec();
            programs
                .entry(dependency.program)
                .or_insert(ImportedProgram {
                    program: dependency.program,
                    pvm,
                });
        }
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
            let descriptor = decode_row::<ActorGenesis>(
                store,
                header.service_root,
                &StateKey::ActorDescriptor(actor),
            )?
            .ok_or(ScheduleError::CorruptActorDirectory)?;
            if descriptor.actor != actor {
                return Err(ScheduleError::CorruptActorDirectory);
            }
            validate_actor_consistency(descriptor.crdt, header.consistency, actor)?;
            let mut sibling_states =
                actor_states(store, &header, &descriptor, causal_frontier.as_ref())?;
            let sibling_state = sibling_states.remove(0);
            let root_sibling_continuation = if causal_continuations.is_some() {
                None
            } else {
                decode_row::<BlobRef>(store, header.service_root, &StateKey::Continuation(actor))?
            };
            let sibling_continuation = selected_continuation(
                causal_continuations.as_ref(),
                actor,
                root_sibling_continuation,
            );
            let task_dependencies = super::PackageRolePolicies::decode(&descriptor.role_policies)
                .map_err(|_| ScheduleError::CorruptActorDirectory)?
                .task_dependencies;
            work.imported_actors.push(ImportedActor {
                actor,
                name: descriptor.name.clone(),
                parent: descriptor.parent,
                deployment: descriptor.deployment,
                program: descriptor.program,
                task_dependencies: task_dependencies.clone(),
                state: sibling_state.clone(),
                causal_states: sibling_states.clone(),
                continuation: sibling_continuation.clone(),
                storage_rows: Vec::new(),
            });
            let pvm = store
                .program(descriptor.program)
                .ok_or(ScheduleError::MissingProgram(descriptor.program))?
                .to_vec();
            programs
                .entry(descriptor.program)
                .or_insert(ImportedProgram {
                    program: descriptor.program,
                    pvm,
                });
            for dependency in &task_dependencies {
                let pvm = store
                    .program(dependency.program)
                    .ok_or(ScheduleError::MissingProgram(dependency.program))?
                    .to_vec();
                programs
                    .entry(dependency.program)
                    .or_insert(ImportedProgram {
                        program: dependency.program,
                        pvm,
                    });
            }
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
            return Err(ScheduleError::NonCanonicalImports);
        }
        for reference in &work.imported_blobs {
            import_blob(store, &mut blobs, reference)?;
        }
        if matches!(&work.authorization,
            AuthorizationEvidence::Credential { bytes, .. } if bytes.is_empty())
            && work.consistency == ConsistencyMode::Crdt
            && work.parent_call.is_none()
        {
            let record = store
                .ingress_record(work.invocation)?
                .ok_or(ScheduleError::InvalidWorkflowStep(work.invocation))?;
            let reference = record
                .ingress
                .crdt_ingress()
                .filter(|_| record.ingress.authorization_matches(&work.authorization))
                .and_then(|ingress| ingress.authorization_blob.as_ref())
                .ok_or(ScheduleError::InvalidWorkflowStep(work.invocation))?;
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
            AuthorizationEvidence::PrivateCredential { witness, .. } => {
                let bytes = store
                    .private_witness(witness)
                    .ok_or(ScheduleError::MissingBlob(witness.hash))?
                    .to_vec();
                alloc::vec![ImportedBlob {
                    reference: witness.clone(),
                    bytes,
                }]
            }
            _ => Vec::new(),
        };
        let imports = RefineImports {
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
                .ok_or(ScheduleError::MissingBlob(reference.hash))?;
            let snapshot = ContinuationSnapshot::decode(bytes)
                .map_err(|_| ScheduleError::InvalidContinuation(request.target))?;
            snapshot
                .validate_resume_for(&work)
                .map_err(|_| ScheduleError::InvalidContinuation(request.target))?;
            validate_await_boundary(
                snapshot.pending_call,
                work.awaited_reply.as_ref(),
                work.awaited_timeout.as_deref(),
            )?;
        }
        imports
            .validate_for(&work)
            .map_err(|_| ScheduleError::NonCanonicalImports)?;
        Ok(PreparedWork { work, imports })
    }
}

fn validate_actor_consistency(
    actor_crdt: bool,
    consistency: ConsistencyMode,
    actor: ActorId,
) -> Result<(), ScheduleError> {
    if actor_crdt == (consistency == ConsistencyMode::Crdt) {
        Ok(())
    } else {
        Err(ScheduleError::ActorConsistencyMismatch(actor))
    }
}

fn selected_continuation(
    causal_continuations: Option<&BTreeMap<ActorId, Option<BlobRef>>>,
    actor: ActorId,
    root_continuation: Option<BlobRef>,
) -> Option<BlobRef> {
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
) -> Result<Vec<super::Hash>, ScheduleError> {
    if workflow_step == 0 {
        return Ok(current_heads.to_vec());
    }
    if let Some(heads) = timeout_heads {
        if heads.is_empty() {
            return Err(ScheduleError::CorruptCausalDag);
        }
        return Ok(heads.to_vec());
    }
    checkpoint_head
        .map(|head| alloc::vec![head])
        .ok_or(ScheduleError::InvalidWorkflowStep(invocation))
}

fn schedule_causal_error(error: CausalFrontierError<Infallible>) -> ScheduleError {
    match error {
        CausalFrontierError::Missing(cid) => ScheduleError::MissingCausalDependency(cid),
        CausalFrontierError::Corrupt => ScheduleError::CorruptCausalDag,
        CausalFrontierError::Storage(error) => match error {},
    }
}

fn validate_await_boundary(
    pending_call: Option<CallId>,
    awaited_reply: Option<&AccumulatedReply>,
    awaited_timeout: Option<&AccumulatedTimeout>,
) -> Result<(), ScheduleError> {
    match (pending_call, awaited_reply, awaited_timeout) {
        (None, None, None) => Ok(()),
        (Some(call), Some(reply), None) if reply.reply.call_id == call => Ok(()),
        (Some(call), None, Some(timeout)) if timeout.expiration.timeout.call_id == call => Ok(()),
        (Some(call), None, None) => Err(ScheduleError::MissingAwaitedReply(call)),
        (_, Some(reply), _) => Err(ScheduleError::UnexpectedAwaitedReply(reply.reply.call_id)),
        (_, _, Some(timeout)) => Err(ScheduleError::UnexpectedAwaitedReply(
            timeout.expiration.timeout.call_id,
        )),
    }
}

fn actor_states(
    store: &LocalJamStore,
    header: &super::StoreHeader,
    descriptor: &ActorGenesis,
    causal_frontier: Option<&CausalFrontier>,
) -> Result<Vec<BlobRef>, ScheduleError> {
    if header.consistency != ConsistencyMode::Crdt {
        let state_key = StateKey::ActorRow {
            actor: descriptor.actor,
            key: crate::actors::lifecycle::STATE_KEY_BYTES.to_vec(),
        };
        return decode_row(store, header.service_root, &state_key)?
            .map(|state| alloc::vec![state])
            .ok_or(ScheduleError::MissingState(descriptor.actor));
    }

    causal_frontier
        .ok_or(ScheduleError::CorruptCausalDag)?
        .actor_materializations(descriptor)
        .map_err(|error| match error {
            CausalSelectionError::Corrupt => ScheduleError::CorruptCausalDag,
        })
}

fn dynamic_method(payload: &[u8]) -> Option<String> {
    if payload.first() != Some(&crate::value::TAG_DYNAMIC) {
        return None;
    }
    <crate::value::Msg as crate::Decode>::try_decode(&payload[1..]).map(|message| message.name)
}

fn decode_row<T: ServiceWire>(
    store: &LocalJamStore,
    root: super::Hash,
    key: &StateKey,
) -> Result<Option<T>, ScheduleError> {
    store
        .state_row(root, key)?
        .map(|bytes| {
            T::decode(&bytes).map_err(|error| ScheduleError::InvalidRow(key.clone(), error))
        })
        .transpose()
}

fn import_blob(
    store: &LocalJamStore,
    imports: &mut BTreeMap<super::Hash, ImportedBlob>,
    reference: &BlobRef,
) -> Result<(), ScheduleError> {
    let bytes = store
        .blob(reference)
        .ok_or(ScheduleError::MissingBlob(reference.hash))?
        .to_vec();
    imports.insert(
        reference.hash,
        ImportedBlob {
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
            validate_actor_consistency(false, ConsistencyMode::Crdt, actor),
            Err(ScheduleError::ActorConsistencyMismatch(actor))
        );
        assert_eq!(
            validate_actor_consistency(true, ConsistencyMode::Local, actor),
            Err(ScheduleError::ActorConsistencyMismatch(actor))
        );
        assert!(validate_actor_consistency(true, ConsistencyMode::Crdt, actor).is_ok());
        assert!(validate_actor_consistency(false, ConsistencyMode::Local, actor).is_ok());

        let missing = super::super::Hash([2; 32]);
        assert_eq!(
            schedule_causal_error(CausalFrontierError::Missing(missing)),
            ScheduleError::MissingCausalDependency(missing)
        );
        assert_eq!(
            schedule_causal_error(CausalFrontierError::Corrupt),
            ScheduleError::CorruptCausalDag
        );

        let call = CallId([3; 32]);
        assert_eq!(
            validate_await_boundary(Some(call), None, None),
            Err(ScheduleError::MissingAwaitedReply(call))
        );
        assert_eq!(
            validate_await_boundary(Some(call), None, None),
            Err(ScheduleError::MissingAwaitedReply(call))
        );
    }

    #[test]
    fn selected_causal_continuations_override_the_later_merged_root() {
        let actor = ActorId([4; 32]);
        let branch = BlobRef::of_bytes(b"branch checkpoint");
        let merged = BlobRef::of_bytes(b"later merged checkpoint");
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
