//! Read-only construction of linear Refine work from guest-committed state.
//!
//! The scheduler selects work and imports. It never interprets a transition or
//! mutates service rows: successful output must still return to the canonical
//! service PVM's physical IC-5 Accumulate entry.

use alloc::collections::BTreeMap;
use alloc::string::String;
use alloc::vec::Vec;
use core::convert::Infallible;

use super::causal::{CausalFrontierError, CausalFrontierV2, load_causal_frontier};
use super::contracts::crdt_change_blob_references;
use super::{
    AccumulatedReplyV2, ActorDirectoryV2, ActorGenesisV2, ActorId, AuthorizationEvidenceV2,
    BlobRefV2, CallId, ConsistencyBaseV2, ConsistencyModeV2, ContinuationSnapshotV2, CrdtChangeV2,
    CrdtSyncEnvelopeV2, CrdtSyncNodeV2, DecodeError, DeliveryEnvelopeV2, ImportedActorV2,
    ImportedBlobV2, ImportedProgramV2, InvocationId, LocalJamStoreV2, LocalStoreReadErrorV2,
    MessageRecordV2, Origin, RefineImportsV2, StateKeyV2, V2Wire, WorkEnvelopeV2,
    WorkflowCheckpointV2, WorkflowOperationV2, crdt_node_receipt_storage_key,
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
    MissingAwaitedReply(CallId),
    UnexpectedAwaitedReply(CallId),
    InvocationAlreadyCommitted(InvocationId),
    InvalidWorkflowStep(InvocationId),
    MissingInbox(super::CallId),
    InvalidInbox(super::CallId),
    DeadlineExpired(super::CallId),
    MissingCausalDependency(super::Hash),
    MissingNodeReceipt(super::Hash),
    InvalidNodeReceipt(super::Hash),
    CorruptCausalDag,
    InvalidDelivery,
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
    /// cross-root outbox record. This is read-only scheduling: only the
    /// physical service PVM may verify the source receipt and commit the inbox.
    pub fn prepare_delivery(
        store: &LocalJamStoreV2,
        logical_timeslot: u64,
        message: MessageRecordV2,
        source_outbox: Vec<MessageRecordV2>,
        source_receipt: super::AccumulationReceiptV2,
    ) -> Result<DeliveryEnvelopeV2, ScheduleErrorV2> {
        let header = store.header()?.ok_or(ScheduleErrorV2::StoreUninitialized)?;
        let (base, base_causal_height, crdt_change) =
            if header.consistency == ConsistencyModeV2::Crdt {
                let heads = header.crdt_heads.clone();
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
                let change = CrdtChangeV2 {
                    id: CrdtChangeV2::derive_delivery_id(&header.service, message.call_id, &heads),
                    causal_dependencies: heads.clone(),
                    causal_height: height
                        .checked_add(1)
                        .ok_or(ScheduleErrorV2::InvalidDelivery)?,
                    operations: Vec::new(),
                    workflow: alloc::vec![WorkflowOperationV2::Inbox(message.clone())],
                    materializations: Vec::new(),
                };
                (
                    ConsistencyBaseV2::Crdt { heads },
                    Some(height),
                    Some(change),
                )
            } else {
                let state_root = header
                    .state_root
                    .ok_or(ScheduleErrorV2::UnsupportedConsistency(header.consistency))?;
                (
                    ConsistencyBaseV2::Linear {
                        revision: header.revision,
                        state_root,
                    },
                    None,
                    None,
                )
            };
        let envelope = DeliveryEnvelopeV2 {
            service: header.service,
            logical_timeslot,
            base,
            base_causal_height,
            message,
            source_outbox,
            source_receipt,
            crdt_change,
        };
        DeliveryEnvelopeV2::decode(&envelope.encode()).map_err(|_| ScheduleErrorV2::InvalidDelivery)
    }

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
                arguments: template.arguments,
                origin: template.origin,
                authorization: template.authorization,
                causal_parent: template.causal_parent,
                parent_call: template.parent_call,
                awaited_reply,
                imported_blobs: template.imported_blobs,
                proof_requested: template.proof_requested,
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
        if directory.actors.binary_search(&request.target).is_err() {
            return Err(ScheduleErrorV2::CorruptActorDirectory);
        }
        let descriptor_key = StateKeyV2::ActorDescriptor(request.target);
        let descriptor = decode_row::<ActorGenesisV2>(store, header.service_root, &descriptor_key)?
            .ok_or(ScheduleErrorV2::MissingActor(request.target))?;
        if descriptor.crdt != (header.consistency == ConsistencyModeV2::Crdt) {
            return Err(ScheduleErrorV2::ActorConsistencyMismatch(request.target));
        }
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

        let program_bytes = store
            .program(descriptor.program)
            .ok_or(ScheduleErrorV2::MissingProgram(descriptor.program))?
            .to_vec();
        let (base, base_causal_height, mut states) =
            if header.consistency == ConsistencyModeV2::Crdt {
                let current = load_store_causal_frontier(store, &header.crdt_heads)?;
                let heads = if request.workflow_step == 0 {
                    header.crdt_heads.clone()
                } else {
                    let checkpoint = workflow
                        .as_ref()
                        .expect("validated continuation has a workflow checkpoint");
                    if !header.crdt_heads.iter().any(|head| {
                        current.contains_ancestor(*head, checkpoint.transition_commitment)
                    }) {
                        return Err(ScheduleErrorV2::CorruptCausalDag);
                    }
                    alloc::vec![checkpoint.transition_commitment]
                };
                let frontier = if heads == header.crdt_heads {
                    current
                } else {
                    load_store_causal_frontier(store, &heads)?
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
                .is_none_or(|checkpoint| !checkpoint.matches_resume_work(&work))
        {
            return Err(ScheduleErrorV2::InvalidWorkflowStep(request.invocation));
        }
        work.imported_actors.push(ImportedActorV2 {
            actor: request.target,
            name: descriptor.name.clone(),
            parent: descriptor.parent,
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

        // Refine owns the whole root tree. Import every sibling's exact code,
        // state frontier, and continuation reference even when this message
        // initially targets only one actor. Guest Accumulate independently
        // checks this list against the installation directory.
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
            if descriptor.crdt != (header.consistency == ConsistencyModeV2::Crdt) {
                return Err(ScheduleErrorV2::ActorConsistencyMismatch(actor));
            }
            let crdt_heads = match &work.base {
                ConsistencyBaseV2::Crdt { heads } => Some(heads.as_slice()),
                ConsistencyBaseV2::Linear { .. } => None,
            };
            let mut actor_states = actor_states(store, &header, &descriptor, crdt_heads)?;
            if actor_states.is_empty() {
                return Err(ScheduleErrorV2::CorruptCausalDag);
            }
            let actor_state = actor_states.remove(0);
            let actor_continuation = decode_row::<BlobRefV2>(
                store,
                header.service_root,
                &StateKeyV2::Continuation(actor),
            )?;
            work.imported_actors.push(ImportedActorV2 {
                actor,
                name: descriptor.name.clone(),
                parent: descriptor.parent,
                program: descriptor.program,
                state: actor_state.clone(),
                causal_states: actor_states.clone(),
                continuation: actor_continuation.clone(),
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
            import_blob(store, &mut blobs, &actor_state)?;
            for reference in &actor_states {
                import_blob(store, &mut blobs, reference)?;
            }
            if let Some(reference) = actor_continuation.as_ref() {
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
        let imports = RefineImportsV2 {
            programs: programs.into_values().collect(),
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
            match (snapshot.pending_call, work.awaited_reply.as_ref()) {
                (None, None) => {}
                (Some(call), None) => return Err(ScheduleErrorV2::MissingAwaitedReply(call)),
                (Some(call), Some(reply)) if reply.reply.call_id == call => {}
                (_, Some(reply)) => {
                    return Err(ScheduleErrorV2::UnexpectedAwaitedReply(reply.reply.call_id));
                }
            }
        }
        imports
            .validate_for(&work)
            .map_err(|_| ScheduleErrorV2::NonCanonicalImports)?;
        Ok(PreparedWorkV2 { work, imports })
    }
}

fn actor_states(
    store: &LocalJamStoreV2,
    header: &super::StoreHeaderV2,
    descriptor: &ActorGenesisV2,
    crdt_heads: Option<&[super::Hash]>,
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

    let frontier =
        load_store_causal_frontier(store, crdt_heads.ok_or(ScheduleErrorV2::CorruptCausalDag)?)?;
    frontier
        .actor_materializations::<Infallible>(descriptor, descriptor.actor)
        .map_err(|error| match error {
            CausalFrontierError::Corrupt | CausalFrontierError::Missing(_) => {
                ScheduleErrorV2::CorruptCausalDag
            }
            CausalFrontierError::Storage(error) => match error {},
        })
}

fn load_store_causal_frontier(
    store: &LocalJamStoreV2,
    heads: &[super::Hash],
) -> Result<CausalFrontierV2, ScheduleErrorV2> {
    match load_causal_frontier(heads, |cid| {
        Ok::<_, Infallible>(store.row(&crdt_node_storage_key(cid)).map(<[u8]>::to_vec))
    }) {
        Ok(frontier) => Ok(frontier),
        Err(CausalFrontierError::Missing(cid)) => {
            Err(ScheduleErrorV2::MissingCausalDependency(cid))
        }
        Err(CausalFrontierError::Corrupt) => Err(ScheduleErrorV2::CorruptCausalDag),
        Err(CausalFrontierError::Storage(error)) => match error {},
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
