//! Consensus Accumulate implementation executed by the generic service guest.
//!
//! The store passed here is one invocation-scoped JAM transaction: writes are
//! visible to later reads, but the host publishes none of them unless the
//! physical IC-5 entry halts successfully. Storage errors are therefore fatal
//! rather than encoded rejections; trapping makes the host discard staging.

use alloc::collections::{BTreeMap, BTreeSet};
use alloc::vec::Vec;

use super::causal::{CausalFrontierError, load_causal_frontier};
use super::{
    ABI_VERSION, AccumulateRequestV2, AccumulationEnvelopeV2, AccumulationReceiptV2,
    AccumulationRejectionV2, AccumulationResultV2, ActorGenesisV2, ActorId,
    AuthorizationEvidenceV2, BlobRefV2, ConsistencyBaseV2, ConsistencyModeV2, CrdtChangeV2,
    DedupRecordV2, EXECUTION_SEMANTICS_ID, Hash, MessageRecordV2, MethodPolicyV2,
    PublishedEffectsV2, ServiceGenesisV2, ServiceInstallReceiptV2, ServiceStateTreeV2, StateKeyV2,
    StateTreeError, StateTreeStore, StoreHeaderV2, StoreOpenError, V2Wire, WorkflowCheckpointV2,
    crdt_change_storage_key, crdt_node_storage_key, dedup_storage_key, header_storage_key,
    receipt_storage_key,
};

/// Extra content-addressed operations needed by guest Accumulate in addition
/// to ordinary JAM service storage.
pub trait GuestAccumulateStoreV2: StateTreeStore {
    fn blob_available(&self, reference: &BlobRefV2) -> Result<bool, Self::Error>;

    /// Stage bytes in the content-addressed store and return their canonical
    /// VOS reference. The staged blob becomes visible only with this same
    /// Accumulate transaction.
    fn provide_blob(&mut self, bytes: &[u8]) -> Result<BlobRefV2, Self::Error>;
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum GuestAccumulateError<E> {
    Storage(E),
    StateTree(StateTreeError<E>),
    CorruptStore,
}

impl<E: core::fmt::Debug> core::fmt::Display for GuestAccumulateError<E> {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        write!(f, "guest Accumulate failed: {self:?}")
    }
}

impl<E: core::fmt::Debug> core::error::Error for GuestAccumulateError<E> {}

type GuestResult<T, E> = Result<T, GuestAccumulateError<E>>;

/// Validate and stage one install/apply request. A successful return may be
/// committed by the physical Accumulate driver. An error must trap so partial
/// staging is discarded.
pub fn execute_guest_accumulate<S: GuestAccumulateStoreV2>(
    store: &mut S,
    request: &AccumulateRequestV2,
) -> GuestResult<AccumulationResultV2, S::Error> {
    let request = match AccumulateRequestV2::decode(&request.encode()) {
        Ok(request) => request,
        Err(_) => return Ok(rejected(AccumulationRejectionV2::NonCanonical)),
    };
    match request {
        AccumulateRequestV2::Install(genesis) => install(store, &genesis),
        AccumulateRequestV2::Apply(envelope) => apply(store, &envelope),
        AccumulateRequestV2::PrepareAttested(_) => {
            Ok(rejected(AccumulationRejectionV2::ProofUnavailable))
        }
    }
}

fn install<S: GuestAccumulateStoreV2>(
    store: &mut S,
    genesis: &ServiceGenesisV2,
) -> GuestResult<AccumulationResultV2, S::Error> {
    if read(store, header_storage_key())?.is_some() {
        return Ok(rejected(AccumulationRejectionV2::StoreAlreadyInitialized));
    }
    if genesis.service.service_abi != ABI_VERSION {
        return Ok(rejected(AccumulationRejectionV2::WrongAbi));
    }
    if genesis.service.execution_semantics != EXECUTION_SEMANTICS_ID {
        return Ok(rejected(AccumulationRejectionV2::WrongExecutionSemantics));
    }
    for actor in &genesis.actors {
        if !blob_available(store, &actor.initial_state)? {
            return Ok(rejected(AccumulationRejectionV2::MissingBlob(
                actor.initial_state.hash,
            )));
        }
    }

    let mut header = StoreHeaderV2::current(genesis.service.clone(), genesis.consistency);
    {
        let mut tree = ServiceStateTreeV2::new(store, header.service_root);
        for actor in &genesis.actors {
            tree_apply(
                &mut tree,
                &StateKeyV2::ActorDescriptor(actor.actor),
                Some(&actor.encode()),
            )?;
            for method in &actor.methods {
                tree_apply(
                    &mut tree,
                    &StateKeyV2::MethodPolicy {
                        actor: actor.actor,
                        method: method.method.clone(),
                    },
                    Some(&method.encode()),
                )?;
            }
            let state_key = actor_state_key(genesis.consistency, actor.actor);
            tree_apply(&mut tree, &state_key, Some(&actor.initial_state.encode()))?;
        }
        header.service_root = tree.root();
    }
    if genesis.consistency != ConsistencyModeV2::Crdt {
        header.state_root = Some(header.service_root);
    }
    write(store, header_storage_key(), Some(&header.encode()))?;

    Ok(AccumulationResultV2::Installed(ServiceInstallReceiptV2 {
        service: genesis.service.clone(),
        consistency: genesis.consistency,
        resulting_state_root: (genesis.consistency != ConsistencyModeV2::Crdt)
            .then_some(header.service_root),
        resulting_crdt_heads: Vec::new(),
    }))
}

fn apply<S: GuestAccumulateStoreV2>(
    store: &mut S,
    envelope: &AccumulationEnvelopeV2,
) -> GuestResult<AccumulationResultV2, S::Error> {
    let Some(header_bytes) = read(store, header_storage_key())? else {
        return Ok(rejected(AccumulationRejectionV2::StoreUninitialized));
    };
    let mut header = match StoreHeaderV2::open(&header_bytes) {
        Ok(header) => header,
        Err(StoreOpenError::WrongService) => {
            return Ok(rejected(AccumulationRejectionV2::WrongService));
        }
        Err(StoreOpenError::IncompatibleSemantics) => {
            return Ok(rejected(AccumulationRejectionV2::WrongExecutionSemantics));
        }
        Err(StoreOpenError::LegacyStore | StoreOpenError::InvalidHeader(_)) => {
            return Ok(rejected(AccumulationRejectionV2::NonCanonical));
        }
    };
    let work = &envelope.work;
    let transition = &envelope.transition;
    if work.service != header.service || transition.service != header.service {
        return Ok(rejected(AccumulationRejectionV2::WrongService));
    }
    if header.service.service_abi != ABI_VERSION {
        return Ok(rejected(AccumulationRejectionV2::WrongAbi));
    }
    if header.service.execution_semantics != EXECUTION_SEMANTICS_ID {
        return Ok(rejected(AccumulationRejectionV2::WrongExecutionSemantics));
    }
    if work.consistency != header.consistency
        || !work.base.mode_compatible(work.consistency)
        || !transition.base.mode_compatible(work.consistency)
    {
        return Ok(rejected(AccumulationRejectionV2::InvalidConsistency));
    }

    let work_hash = work.hash();
    let transition_hash = transition.hash();
    if let Some(bytes) = read(store, &dedup_storage_key(work.input_id()))? {
        let record =
            DedupRecordV2::decode(&bytes).map_err(|_| GuestAccumulateError::CorruptStore)?;
        return if record.input == work.input_id()
            && record.work_hash == work_hash
            && record.transition_hash == transition_hash
        {
            Ok(AccumulationResultV2::Accepted {
                receipt: record.receipt,
                published: PublishedEffectsV2::default(),
                duplicate: true,
            })
        } else {
            Ok(rejected(AccumulationRejectionV2::DivergentDuplicate))
        };
    }

    let mut tree = ServiceStateTreeV2::new(store, header.service_root);
    let Some(actor) =
        tree_get_wire::<_, ActorGenesisV2>(&tree, &StateKeyV2::ActorDescriptor(work.target))?
    else {
        return Ok(rejected(AccumulationRejectionV2::WrongProgram));
    };
    if actor.program != work.target_program || transition.target_program != actor.program {
        return Ok(rejected(AccumulationRejectionV2::WrongProgram));
    }
    if actor.crdt != (header.consistency == ConsistencyModeV2::Crdt) {
        return Ok(rejected(AccumulationRejectionV2::InvalidConsistency));
    }
    let Some(policy) = tree_get_wire::<_, MethodPolicyV2>(
        &tree,
        &StateKeyV2::MethodPolicy {
            actor: work.target,
            method: work.method.clone(),
        },
    )?
    else {
        return Ok(rejected(AccumulationRejectionV2::Unauthorized));
    };
    if !authorized(work, &policy) {
        return Ok(rejected(AccumulationRejectionV2::Unauthorized));
    }
    if !work_matches_durable_inbox(&tree, work)? {
        return Ok(rejected(AccumulationRejectionV2::InvalidWorkflowTransition));
    }
    if policy.attested || work.proof_requested {
        return Ok(rejected(if transition.proof.is_none() {
            AccumulationRejectionV2::MissingProof
        } else {
            AccumulationRejectionV2::ProofUnavailable
        }));
    }
    if transition.proof.is_some() {
        return Ok(rejected(AccumulationRejectionV2::ProofUnavailable));
    }

    if transition.consumed_input != work.input_id() {
        return Ok(rejected(AccumulationRejectionV2::TransitionInputMismatch));
    }
    if transition.base != work.base {
        return Ok(rejected(AccumulationRejectionV2::TransitionBaseMismatch));
    }
    if !canonical_transition_shape(work.target, transition) {
        return Ok(rejected(AccumulationRejectionV2::InvalidWorkflowTransition));
    }
    if let Some(rejection) = validate_base(tree.store_ref(), &header, &work.base)? {
        return Ok(rejected(rejection));
    }
    if let Some(rejection) = validate_crdt(tree.store_ref(), &header, work, transition)? {
        return Ok(rejected(rejection));
    }
    if header.consistency != ConsistencyModeV2::Crdt && header.revision == u64::MAX {
        return Ok(rejected(AccumulationRejectionV2::SequenceOverflow));
    }

    for imported in &work.imported_actors {
        let Some(descriptor) = tree_get_wire::<_, ActorGenesisV2>(
            &tree,
            &StateKeyV2::ActorDescriptor(imported.actor),
        )?
        else {
            return Ok(rejected(AccumulationRejectionV2::WrongProgram));
        };
        if descriptor.program != imported.program {
            return Ok(rejected(AccumulationRejectionV2::WrongProgram));
        }
        let committed_continuation =
            tree_get_wire::<_, BlobRefV2>(&tree, &StateKeyV2::Continuation(imported.actor))?;
        if committed_continuation != imported.continuation {
            return Ok(rejected(AccumulationRejectionV2::ContinuationConflict(
                imported.actor,
            )));
        }
        if header.consistency == ConsistencyModeV2::Crdt {
            let ConsistencyBaseV2::Crdt { heads } = &work.base else {
                return Ok(rejected(AccumulationRejectionV2::InvalidConsistency));
            };
            let Some(expected) =
                crdt_base_materializations(tree.store_ref(), &descriptor, imported.actor, heads)?
            else {
                return Ok(rejected(AccumulationRejectionV2::InvalidWorkflowTransition));
            };
            let actual = core::iter::once(&imported.state)
                .chain(imported.causal_states.iter())
                .cloned()
                .collect::<Vec<_>>();
            if expected != actual {
                return Ok(rejected(AccumulationRejectionV2::InvalidWorkflowTransition));
            }
        } else {
            if !imported.causal_states.is_empty() {
                return Ok(rejected(AccumulationRejectionV2::InvalidWorkflowTransition));
            }
            let Some(committed_state) = tree_get_wire::<_, BlobRefV2>(
                &tree,
                &actor_state_key(header.consistency, imported.actor),
            )?
            else {
                return Ok(rejected(AccumulationRejectionV2::InvalidWorkflowTransition));
            };
            if committed_state != imported.state {
                return Ok(rejected(AccumulationRejectionV2::StaleStateRoot));
            }
        }
    }

    if let Some(rejection) = validate_durable_messages(&tree, work, transition)? {
        return Ok(rejected(rejection));
    }
    if contains_cycle(&transition.outbox) {
        return Ok(rejected(AccumulationRejectionV2::MessageCycle));
    }
    for change in &transition.continuations {
        if tree_get_wire::<_, ActorGenesisV2>(&tree, &StateKeyV2::ActorDescriptor(change.actor))?
            .is_none()
        {
            return Ok(rejected(AccumulationRejectionV2::InvalidWorkflowTransition));
        }
        let actual = tree_get_wire::<_, BlobRefV2>(&tree, &StateKeyV2::Continuation(change.actor))?;
        if actual.as_ref().map(|blob| blob.hash) != change.expected {
            return Ok(rejected(AccumulationRejectionV2::ContinuationConflict(
                change.actor,
            )));
        }
    }
    for message in &transition.inbox {
        if tree_get_wire::<_, ActorGenesisV2>(&tree, &StateKeyV2::ActorDescriptor(message.to))?
            .is_none()
        {
            return Ok(rejected(AccumulationRejectionV2::InvalidWorkflowTransition));
        }
    }
    for message in &transition.outbox {
        if tree_get_wire::<_, ActorGenesisV2>(&tree, &StateKeyV2::ActorDescriptor(message.from))?
            .is_none()
        {
            return Ok(rejected(AccumulationRejectionV2::InvalidWorkflowTransition));
        }
    }
    if let Some(change) = transition.crdt_change.as_ref() {
        for materialization in &change.materializations {
            if tree_get_wire::<_, ActorGenesisV2>(
                &tree,
                &StateKeyV2::ActorDescriptor(materialization.actor),
            )?
            .is_none()
            {
                return Ok(rejected(AccumulationRejectionV2::InvalidWorkflowTransition));
            }
        }
    }
    for reference in referenced_blobs(work, transition) {
        let supplied = envelope
            .provided_blobs
            .binary_search_by_key(&reference.hash, |blob| blob.reference.hash)
            .ok()
            .is_some_and(|index| envelope.provided_blobs[index].reference == *reference);
        if !supplied && !blob_available(tree.store_ref(), reference)? {
            return Ok(rejected(AccumulationRejectionV2::MissingBlob(
                reference.hash,
            )));
        }
    }
    for candidate in &envelope.provided_blobs {
        let actual = tree
            .store_mut()
            .provide_blob(&candidate.bytes)
            .map_err(GuestAccumulateError::Storage)?;
        if actual != candidate.reference {
            return Err(GuestAccumulateError::CorruptStore);
        }
    }

    if header.consistency == ConsistencyModeV2::Crdt {
        let change = transition
            .crdt_change
            .as_ref()
            .expect("validated CRDT transition");
        for materialization in &change.materializations {
            tree_apply(
                &mut tree,
                &StateKeyV2::CrdtMaterialization(materialization.actor),
                Some(&materialization.state.encode()),
            )?;
        }
    } else {
        for actor_write in &transition.writes {
            let key = StateKeyV2::ActorRow {
                actor: actor_write.actor,
                key: actor_write.key.clone(),
            };
            if actor_write.key.as_slice() == crate::actors::lifecycle::STATE_KEY_BYTES {
                let Some(state) = actor_write.value.as_deref() else {
                    return Ok(rejected(AccumulationRejectionV2::InvalidWorkflowTransition));
                };
                let reference = tree
                    .store_mut()
                    .provide_blob(state)
                    .map_err(GuestAccumulateError::Storage)?;
                tree_apply(&mut tree, &key, Some(&reference.encode()))?;
            } else {
                tree_apply(&mut tree, &key, actor_write.value.as_deref())?;
            }
        }
    }
    for continuation in &transition.continuations {
        tree_apply(
            &mut tree,
            &StateKeyV2::Continuation(continuation.actor),
            continuation
                .replacement
                .as_ref()
                .map(V2Wire::encode)
                .as_deref(),
        )?;
    }
    for message in &transition.inbox {
        tree_apply(
            &mut tree,
            &StateKeyV2::Inbox(message.call_id),
            Some(&message.encode()),
        )?;
    }
    for message in &transition.outbox {
        tree_apply(
            &mut tree,
            &StateKeyV2::Outbox(message.call_id),
            Some(&message.encode()),
        )?;
    }
    let workflow = WorkflowCheckpointV2 {
        input: work.input_id(),
        work_hash,
        transition_hash,
    };
    tree_apply(
        &mut tree,
        &StateKeyV2::Workflow(work.invocation),
        Some(&workflow.encode()),
    )?;
    header.service_root = tree.root();
    drop(tree);

    let (resulting_state_root, resulting_crdt_heads, sequence) =
        if header.consistency == ConsistencyModeV2::Crdt {
            let change = transition
                .crdt_change
                .as_ref()
                .expect("validated CRDT transition");
            let cid = change.cid();
            write_crdt_change(store, change, cid)?;
            let mut heads = BTreeSet::from_iter(header.crdt_heads.iter().copied());
            for dependency in &change.causal_dependencies {
                heads.remove(dependency);
            }
            heads.insert(cid);
            header.crdt_heads = heads.into_iter().collect();
            (None, header.crdt_heads.clone(), change.causal_height)
        } else {
            header.revision = header
                .revision
                .checked_add(1)
                .expect("linear sequence overflow was validated before staging");
            header.state_root = Some(header.service_root);
            (Some(header.service_root), Vec::new(), header.revision)
        };

    let receipt = AccumulationReceiptV2 {
        service: header.service.clone(),
        accepted_transition: transition_hash,
        resulting_state_root,
        resulting_crdt_heads,
        sequence,
        checkpoint: work.workflow_step,
        consistency: header.consistency,
    };
    let record = DedupRecordV2 {
        input: work.input_id(),
        work_hash,
        transition_hash,
        receipt: receipt.clone(),
    };
    write(store, header_storage_key(), Some(&header.encode()))?;
    write(
        store,
        &receipt_storage_key(work.input_id()),
        Some(&receipt.encode()),
    )?;
    write(
        store,
        &dedup_storage_key(work.input_id()),
        Some(&record.encode()),
    )?;

    Ok(AccumulationResultV2::Accepted {
        receipt,
        published: PublishedEffectsV2 {
            reply: transition.reply.clone(),
            outbox: transition.outbox.clone(),
            exported_blobs: transition.exported_blobs.clone(),
            proof: transition.proof.clone(),
        },
        duplicate: false,
    })
}

fn validate_base<S: GuestAccumulateStoreV2>(
    store: &S,
    header: &StoreHeaderV2,
    base: &ConsistencyBaseV2,
) -> GuestResult<Option<AccumulationRejectionV2>, S::Error> {
    Ok(match base {
        ConsistencyBaseV2::Linear {
            revision,
            state_root,
        } => {
            if *revision != header.revision {
                Some(AccumulationRejectionV2::StaleLinearWork {
                    expected_revision: *revision,
                    actual_revision: header.revision,
                })
            } else if Some(*state_root) != header.state_root {
                Some(AccumulationRejectionV2::StaleStateRoot)
            } else {
                None
            }
        }
        ConsistencyBaseV2::Crdt { heads } => {
            for dependency in heads {
                if read(store, &crdt_node_storage_key(*dependency))?.is_none() {
                    return Ok(Some(AccumulationRejectionV2::MissingCausalDependency(
                        *dependency,
                    )));
                }
            }
            None
        }
    })
}

fn validate_crdt<S: GuestAccumulateStoreV2>(
    store: &S,
    header: &StoreHeaderV2,
    work: &super::WorkEnvelopeV2,
    transition: &super::TransitionV2,
) -> GuestResult<Option<AccumulationRejectionV2>, S::Error> {
    if header.consistency != ConsistencyModeV2::Crdt {
        return Ok(transition
            .crdt_change
            .is_some()
            .then_some(AccumulationRejectionV2::InvalidConsistency));
    }
    let Some(change) = transition.crdt_change.as_ref() else {
        return Ok(Some(AccumulationRejectionV2::InvalidConsistency));
    };
    let ConsistencyBaseV2::Crdt { heads } = &work.base else {
        return Ok(Some(AccumulationRejectionV2::InvalidConsistency));
    };
    if !transition.writes.is_empty()
        || Some(change.id) != CrdtChangeV2::derive_id(work)
        || change.causal_dependencies.as_slice() != heads.as_slice()
        || change.workflow != transition.workflow_operations()
    {
        return Ok(Some(AccumulationRejectionV2::InvalidWorkflowTransition));
    }
    if let Some(existing) = read(store, &crdt_change_storage_key(change.id))? {
        if existing.as_slice() != change.cid().0 {
            return Ok(Some(AccumulationRejectionV2::DivergentDuplicate));
        }
    }
    let frontier = match load_causal_frontier(heads, |cid| store.read(&crdt_node_storage_key(cid)))
    {
        Ok(frontier) => frontier,
        Err(CausalFrontierError::Storage(error)) => {
            return Err(GuestAccumulateError::Storage(error));
        }
        Err(CausalFrontierError::Missing(cid)) => {
            return Ok(Some(AccumulationRejectionV2::MissingCausalDependency(cid)));
        }
        Err(CausalFrontierError::Corrupt) => return Err(GuestAccumulateError::CorruptStore),
    };
    let max_height = frontier.max_head_height;
    if work.base_causal_height != Some(max_height)
        || max_height.checked_add(1) != Some(change.causal_height)
    {
        return Ok(Some(AccumulationRejectionV2::InvalidWorkflowTransition));
    }
    Ok(None)
}

fn crdt_base_materializations<S: StateTreeStore>(
    store: &S,
    descriptor: &ActorGenesisV2,
    actor: ActorId,
    heads: &[Hash],
) -> GuestResult<Option<Vec<BlobRefV2>>, S::Error> {
    let frontier = match load_causal_frontier(heads, |cid| store.read(&crdt_node_storage_key(cid)))
    {
        Ok(frontier) => frontier,
        Err(CausalFrontierError::Storage(error)) => {
            return Err(GuestAccumulateError::Storage(error));
        }
        Err(CausalFrontierError::Missing(_)) => return Ok(None),
        Err(CausalFrontierError::Corrupt) => return Err(GuestAccumulateError::CorruptStore),
    };
    match frontier.actor_materializations::<S::Error>(descriptor, actor) {
        Ok(states) => Ok(Some(states)),
        Err(CausalFrontierError::Corrupt) => Err(GuestAccumulateError::CorruptStore),
        Err(CausalFrontierError::Storage(_) | CausalFrontierError::Missing(_)) => {
            unreachable!("materialization selection performs no storage reads")
        }
    }
}

fn write_crdt_change<S: GuestAccumulateStoreV2>(
    store: &mut S,
    change: &CrdtChangeV2,
    cid: Hash,
) -> GuestResult<(), S::Error> {
    let node_key = crdt_node_storage_key(cid);
    let encoded = change.encode();
    if let Some(existing) = read(store, &node_key)? {
        if existing != encoded {
            return Err(GuestAccumulateError::CorruptStore);
        }
    } else {
        write(store, &node_key, Some(&encoded))?;
    }
    write(store, &crdt_change_storage_key(change.id), Some(&cid.0))
}

fn canonical_transition_shape(target: ActorId, transition: &super::TransitionV2) -> bool {
    let writes = transition.writes.iter().map(|write| {
        let mut key = write.actor.0.to_vec();
        key.extend_from_slice(&write.key);
        let valid = write.actor == target
            && !write.key.is_empty()
            && (write.key.as_slice() != crate::actors::lifecycle::STATE_KEY_BYTES
                || write.value.is_some());
        (valid, key)
    });
    let mut previous = None;
    for (valid, key) in writes {
        if !valid || previous.as_ref().is_some_and(|previous| previous >= &key) {
            return false;
        }
        previous = Some(key);
    }
    is_sorted_unique_by(&transition.continuations, |change| change.actor.0)
        && is_sorted_unique_by(&transition.inbox, |message| message.call_id.0)
        && is_sorted_unique_by(&transition.outbox, |message| message.call_id.0)
        && transition
            .reply
            .as_ref()
            .is_none_or(|reply| reply.producer == target)
}

fn authorized(work: &super::WorkEnvelopeV2, policy: &MethodPolicyV2) -> bool {
    match &work.authorization {
        AuthorizationEvidenceV2::Public => policy.public,
        AuthorizationEvidenceV2::Credential {
            policy: supplied_policy,
            credential_commitment,
            bytes,
        } => {
            !bytes.is_empty()
                && matches!(
                    work.origin,
                    super::Origin::Member(_) | super::Origin::Actor(_)
                )
                && *supplied_policy == policy.policy
                && *credential_commitment == Hash::digest(b"vos/credential-commitment/v2", &[bytes])
                && policy.policy == Hash::digest(b"vos/bearer-policy/v2", &[bytes])
        }
        // A future statement version will bind platform authority keys. Until
        // then System is an identity class, never an authorization bypass.
        AuthorizationEvidenceV2::SystemCapability { .. } => false,
    }
}

fn work_matches_durable_inbox<S: StateTreeStore>(
    tree: &ServiceStateTreeV2<'_, S>,
    work: &super::WorkEnvelopeV2,
) -> GuestResult<bool, S::Error> {
    let Some(call) = work.parent_call else {
        return Ok(work.causal_parent.is_none());
    };
    let Some(message) = tree_get_wire::<_, MessageRecordV2>(tree, &StateKeyV2::Inbox(call))? else {
        return Ok(false);
    };
    let method = if message.payload.first() == Some(&crate::value::TAG_DYNAMIC) {
        <crate::value::Msg as crate::Decode>::try_decode(&message.payload[1..])
            .map(|message| message.name)
    } else {
        None
    };
    Ok(message.call_id == call
        && message.to == work.target
        && work.invocation == super::InvocationId::for_call(call)
        && work.causal_parent == Some(message.caller_invocation)
        && work.origin == super::Origin::Actor(message.from)
        && work.authorization == message.authorization
        && work.arguments == message.payload
        && message
            .deadline_timeslot
            .is_none_or(|deadline| work.logical_timeslot < deadline)
        && method.as_deref() == Some(work.method.as_str()))
}

fn referenced_blobs<'a>(
    work: &'a super::WorkEnvelopeV2,
    transition: &'a super::TransitionV2,
) -> impl Iterator<Item = &'a BlobRefV2> {
    work.imported_blobs
        .iter()
        .chain(work.imported_actors.iter().flat_map(|actor| {
            core::iter::once(&actor.state)
                .chain(actor.causal_states.iter())
                .chain(actor.continuation.iter())
        }))
        .chain(transition.exported_blobs.iter())
        .chain(
            transition
                .continuations
                .iter()
                .filter_map(|change| change.replacement.as_ref()),
        )
        .chain(
            transition
                .crdt_change
                .iter()
                .flat_map(|change| change.materializations.iter())
                .map(|materialization| &materialization.state),
        )
}

fn actor_state_key(consistency: ConsistencyModeV2, actor: ActorId) -> StateKeyV2 {
    if consistency == ConsistencyModeV2::Crdt {
        StateKeyV2::CrdtMaterialization(actor)
    } else {
        StateKeyV2::ActorRow {
            actor,
            key: crate::actors::lifecycle::STATE_KEY_BYTES.to_vec(),
        }
    }
}

fn contains_cycle(messages: &[MessageRecordV2]) -> bool {
    let mut edges: BTreeMap<ActorId, BTreeSet<ActorId>> = BTreeMap::new();
    for message in messages {
        if message.from == message.to {
            return true;
        }
        edges.entry(message.from).or_default().insert(message.to);
    }
    fn visit(
        actor: ActorId,
        edges: &BTreeMap<ActorId, BTreeSet<ActorId>>,
        visiting: &mut BTreeSet<ActorId>,
        visited: &mut BTreeSet<ActorId>,
    ) -> bool {
        if visited.contains(&actor) {
            return false;
        }
        if !visiting.insert(actor) {
            return true;
        }
        if edges.get(&actor).is_some_and(|targets| {
            targets
                .iter()
                .any(|target| visit(*target, edges, visiting, visited))
        }) {
            return true;
        }
        visiting.remove(&actor);
        visited.insert(actor);
        false
    }
    let mut visiting = BTreeSet::new();
    let mut visited = BTreeSet::new();
    edges
        .keys()
        .any(|actor| visit(*actor, &edges, &mut visiting, &mut visited))
}

/// Validate stable call IDs against both new and committed workflow rows, then
/// walk each new outbound call through its causal parents. A child call must
/// originate at its parent's recipient, cannot extend a parent deadline, and
/// cannot target an actor already present in its causal caller chain.
fn validate_durable_messages<S: StateTreeStore>(
    tree: &ServiceStateTreeV2<'_, S>,
    work: &super::WorkEnvelopeV2,
    transition: &super::TransitionV2,
) -> GuestResult<Option<AccumulationRejectionV2>, S::Error> {
    let mut staged = BTreeMap::<super::CallId, MessageRecordV2>::new();
    for message in transition.inbox.iter().chain(&transition.outbox) {
        if message
            .deadline_timeslot
            .is_some_and(|deadline| work.logical_timeslot >= deadline)
        {
            return Ok(Some(AccumulationRejectionV2::InvalidWorkflowTransition));
        }
        if staged.insert(message.call_id, message.clone()).is_some() {
            return Ok(Some(AccumulationRejectionV2::InvalidWorkflowTransition));
        }
        if tree_get_wire::<_, MessageRecordV2>(tree, &StateKeyV2::Inbox(message.call_id))?.is_some()
            || tree_get_wire::<_, MessageRecordV2>(tree, &StateKeyV2::Outbox(message.call_id))?
                .is_some()
        {
            // Exact work retries were handled by the input dedup row before
            // reaching this point. Reusing a call ID in different work is an
            // invalid workflow transition even when the bytes are identical.
            return Ok(Some(AccumulationRejectionV2::InvalidWorkflowTransition));
        }
    }

    for message in &transition.outbox {
        let mut current = message.clone();
        let mut visited = BTreeSet::new();
        while let Some(parent_id) = current.parent {
            if !visited.insert(parent_id) || parent_id == message.call_id {
                return Ok(Some(AccumulationRejectionV2::MessageCycle));
            }
            let Some(parent) = lookup_message(tree, &staged, parent_id)? else {
                return Ok(Some(AccumulationRejectionV2::InvalidWorkflowTransition));
            };
            if parent.to != current.from {
                return Ok(Some(AccumulationRejectionV2::InvalidWorkflowTransition));
            }
            if let Some(parent_deadline) = parent.deadline_timeslot
                && current
                    .deadline_timeslot
                    .is_none_or(|deadline| deadline > parent_deadline)
            {
                return Ok(Some(AccumulationRejectionV2::InvalidWorkflowTransition));
            }
            if parent.from == message.to {
                return Ok(Some(AccumulationRejectionV2::MessageCycle));
            }
            current = parent;
        }
    }
    Ok(None)
}

fn lookup_message<S: StateTreeStore>(
    tree: &ServiceStateTreeV2<'_, S>,
    staged: &BTreeMap<super::CallId, MessageRecordV2>,
    call: super::CallId,
) -> GuestResult<Option<MessageRecordV2>, S::Error> {
    if let Some(message) = staged.get(&call) {
        return Ok(Some(message.clone()));
    }
    let inbox = tree_get_wire::<_, MessageRecordV2>(tree, &StateKeyV2::Inbox(call))?;
    let outbox = tree_get_wire::<_, MessageRecordV2>(tree, &StateKeyV2::Outbox(call))?;
    match (inbox, outbox) {
        (Some(_), Some(_)) => Err(GuestAccumulateError::CorruptStore),
        (Some(message), None) | (None, Some(message)) => Ok(Some(message)),
        (None, None) => Ok(None),
    }
}

fn is_sorted_unique_by<T, K: Ord>(values: &[T], mut key: impl FnMut(&T) -> K) -> bool {
    values.windows(2).all(|pair| key(&pair[0]) < key(&pair[1]))
}

fn tree_get_wire<S: StateTreeStore, T: V2Wire>(
    tree: &ServiceStateTreeV2<'_, S>,
    key: &StateKeyV2,
) -> GuestResult<Option<T>, S::Error> {
    tree.get(key)
        .map_err(GuestAccumulateError::StateTree)?
        .map(|bytes| T::decode(&bytes).map_err(|_| GuestAccumulateError::CorruptStore))
        .transpose()
}

fn tree_apply<S: StateTreeStore>(
    tree: &mut ServiceStateTreeV2<'_, S>,
    key: &StateKeyV2,
    value: Option<&[u8]>,
) -> GuestResult<(), S::Error> {
    tree.apply(key, value)
        .map(|_| ())
        .map_err(GuestAccumulateError::StateTree)
}

fn read<S: StateTreeStore>(store: &S, key: &[u8]) -> GuestResult<Option<Vec<u8>>, S::Error> {
    store.read(key).map_err(GuestAccumulateError::Storage)
}

fn write<S: StateTreeStore>(
    store: &mut S,
    key: &[u8],
    value: Option<&[u8]>,
) -> GuestResult<(), S::Error> {
    store
        .write(key, value)
        .map_err(GuestAccumulateError::Storage)
}

fn blob_available<S: GuestAccumulateStoreV2>(
    store: &S,
    reference: &BlobRefV2,
) -> GuestResult<bool, S::Error> {
    store
        .blob_available(reference)
        .map_err(GuestAccumulateError::Storage)
}

fn rejected(rejection: AccumulationRejectionV2) -> AccumulationResultV2 {
    AccumulationResultV2::Rejected(rejection)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::v2::{
        ActorWriteV2, CrdtMaterializationV2, CrdtOperationV2, DeploymentId, GasAccountingV2,
        ImportedActorV2, ImportedBlobV2, InvocationId, OperationId, Origin, ProgramId,
        ReplyRecordV2, RootServiceId, ServiceIdentityV2, TransitionV2, WorkEnvelopeV2,
    };

    #[derive(Debug, Clone, Copy, PartialEq, Eq)]
    enum MemError {
        Injected,
    }

    #[derive(Debug, Clone, Default, PartialEq, Eq)]
    struct MemStore {
        rows: BTreeMap<Vec<u8>, Vec<u8>>,
        blobs: BTreeMap<Hash, Vec<u8>>,
        writes_before_failure: Option<usize>,
    }

    impl StateTreeStore for MemStore {
        type Error = MemError;

        fn read(&self, key: &[u8]) -> Result<Option<Vec<u8>>, Self::Error> {
            Ok(self.rows.get(key).cloned())
        }

        fn write(&mut self, key: &[u8], value: Option<&[u8]>) -> Result<(), Self::Error> {
            if let Some(remaining) = self.writes_before_failure.as_mut() {
                if *remaining == 0 {
                    return Err(MemError::Injected);
                }
                *remaining -= 1;
            }
            match value {
                Some(value) => {
                    self.rows.insert(key.to_vec(), value.to_vec());
                }
                None => {
                    self.rows.remove(key);
                }
            }
            Ok(())
        }
    }

    impl GuestAccumulateStoreV2 for MemStore {
        fn blob_available(&self, reference: &BlobRefV2) -> Result<bool, Self::Error> {
            Ok(self
                .blobs
                .get(&reference.hash)
                .is_some_and(|bytes| reference.matches(bytes)))
        }

        fn provide_blob(&mut self, bytes: &[u8]) -> Result<BlobRefV2, Self::Error> {
            let reference = BlobRefV2::of_bytes(bytes);
            self.blobs.insert(reference.hash, bytes.to_vec());
            Ok(reference)
        }
    }

    fn identity() -> ServiceIdentityV2 {
        ServiceIdentityV2 {
            root_service: RootServiceId([1; 32]),
            deployment: DeploymentId([2; 32]),
            service_program: ProgramId([3; 32]),
            service_abi: ABI_VERSION,
            execution_semantics: EXECUTION_SEMANTICS_ID,
        }
    }

    fn actor() -> ActorId {
        ActorId([4; 32])
    }

    fn program() -> ProgramId {
        ProgramId([5; 32])
    }

    fn install_fixture(
        store: &mut MemStore,
        consistency: ConsistencyModeV2,
        initial: &[u8],
    ) -> (BlobRefV2, ServiceInstallReceiptV2) {
        let initial = store.provide_blob(initial).unwrap();
        let request = AccumulateRequestV2::Install(ServiceGenesisV2 {
            service: identity(),
            consistency,
            actors: vec![ActorGenesisV2 {
                actor: actor(),
                parent: None,
                program: program(),
                initial_state: initial.clone(),
                crdt: consistency == ConsistencyModeV2::Crdt,
                methods: vec![MethodPolicyV2 {
                    method: "set".into(),
                    schema: Hash([6; 32]),
                    policy: Hash([7; 32]),
                    public: true,
                    attested: false,
                }],
            }],
            authorization: AuthorizationEvidenceV2::SystemCapability {
                capability: super::super::SystemCapabilityId([8; 32]),
                authenticator: vec![9],
            },
        });
        let AccumulationResultV2::Installed(receipt) =
            execute_guest_accumulate(store, &request).unwrap()
        else {
            panic!("install rejected")
        };
        (initial, receipt)
    }

    fn linear_work(initial: BlobRefV2, base_root: Hash) -> WorkEnvelopeV2 {
        WorkEnvelopeV2 {
            service: identity(),
            invocation: InvocationId([10; 32]),
            workflow_step: 0,
            logical_timeslot: 1,
            target: actor(),
            target_program: program(),
            method: "set".into(),
            arguments: vec![1],
            origin: Origin::Anonymous,
            authorization: AuthorizationEvidenceV2::Public,
            causal_parent: None,
            parent_call: None,
            consistency: ConsistencyModeV2::Local,
            base: ConsistencyBaseV2::Linear {
                revision: 0,
                state_root: base_root,
            },
            base_causal_height: None,
            imported_actors: vec![ImportedActorV2 {
                actor: actor(),
                program: program(),
                state: initial,
                causal_states: vec![],
                continuation: None,
            }],
            imported_blobs: Vec::new(),
            proof_requested: false,
        }
    }

    fn linear_transition(work: &WorkEnvelopeV2, state: &[u8]) -> TransitionV2 {
        TransitionV2 {
            service: work.service.clone(),
            consumed_input: work.input_id(),
            target_program: work.target_program,
            base: work.base.clone(),
            writes: vec![ActorWriteV2 {
                actor: actor(),
                key: crate::actors::lifecycle::STATE_KEY_BYTES.to_vec(),
                value: Some(state.to_vec()),
            }],
            crdt_change: None,
            continuations: Vec::new(),
            inbox: Vec::new(),
            outbox: Vec::new(),
            reply: Some(ReplyRecordV2 {
                call_id: work.invocation.root_reply_id(),
                producer: actor(),
                result: b"ok".to_vec(),
            }),
            exported_blobs: Vec::new(),
            gas: GasAccountingV2::default(),
            proof: None,
        }
    }

    #[test]
    fn install_and_linear_apply_are_guest_owned_and_exactly_once() {
        let mut store = MemStore::default();
        let (initial, install) = install_fixture(&mut store, ConsistencyModeV2::Local, b"before");
        let root = install.resulting_state_root.unwrap();
        let work = linear_work(initial, root);
        let transition = linear_transition(&work, b"after");
        let request = AccumulateRequestV2::Apply(AccumulationEnvelopeV2 {
            work: work.clone(),
            transition: transition.clone(),
            provided_blobs: Vec::new(),
        });

        let accepted = execute_guest_accumulate(&mut store, &request).unwrap();
        let AccumulationResultV2::Accepted {
            receipt,
            published,
            duplicate,
        } = accepted
        else {
            panic!("transition rejected")
        };
        assert!(!duplicate);
        assert_eq!(receipt.sequence, 1);
        assert_eq!(published.reply, transition.reply);
        let header = StoreHeaderV2::open(store.rows.get(header_storage_key()).unwrap()).unwrap();
        assert_eq!(header.revision, 1);
        assert_eq!(header.state_root, receipt.resulting_state_root);
        assert_eq!(header.service_root, receipt.resulting_state_root.unwrap());
        assert!(store.blobs.values().any(|bytes| bytes == b"after"));

        let rows_after_commit = store.rows.clone();
        let blobs_after_commit = store.blobs.clone();
        let duplicate = execute_guest_accumulate(&mut store, &request).unwrap();
        let AccumulationResultV2::Accepted {
            published,
            duplicate,
            ..
        } = duplicate
        else {
            panic!("retry rejected")
        };
        assert!(duplicate);
        assert_eq!(published, PublishedEffectsV2::default());
        assert_eq!(store.rows, rows_after_commit);
        assert_eq!(store.blobs, blobs_after_commit);

        let mut divergent = request;
        let AccumulateRequestV2::Apply(envelope) = &mut divergent else {
            unreachable!()
        };
        envelope.transition.reply.as_mut().unwrap().result = b"different".to_vec();
        assert_eq!(
            execute_guest_accumulate(&mut store, &divergent).unwrap(),
            rejected(AccumulationRejectionV2::DivergentDuplicate)
        );
        assert_eq!(store.rows, rows_after_commit);
    }

    #[test]
    fn stale_or_unauthorized_linear_work_stages_nothing() {
        let mut store = MemStore::default();
        let (initial, install) = install_fixture(&mut store, ConsistencyModeV2::Local, b"before");
        let root = install.resulting_state_root.unwrap();
        let work = linear_work(initial, root);
        let first = AccumulateRequestV2::Apply(AccumulationEnvelopeV2 {
            transition: linear_transition(&work, b"after"),
            work,
            provided_blobs: Vec::new(),
        });
        execute_guest_accumulate(&mut store, &first).unwrap();

        let current_state = BlobRefV2::of_bytes(b"after");
        let mut stale_work = linear_work(current_state, root);
        stale_work.invocation = InvocationId([11; 32]);
        let candidate = ImportedBlobV2 {
            reference: BlobRefV2::of_bytes(b"must-not-stage"),
            bytes: b"must-not-stage".to_vec(),
        };
        let mut stale_transition = linear_transition(&stale_work, b"late");
        stale_transition
            .exported_blobs
            .push(candidate.reference.clone());
        let stale = AccumulateRequestV2::Apply(AccumulationEnvelopeV2 {
            transition: stale_transition,
            work: stale_work,
            provided_blobs: vec![candidate.clone()],
        });
        let before = store.clone();
        assert!(matches!(
            execute_guest_accumulate(&mut store, &stale).unwrap(),
            AccumulationResultV2::Rejected(AccumulationRejectionV2::StaleLinearWork { .. })
        ));
        assert_eq!(store, before);
        assert!(!store.blobs.contains_key(&candidate.reference.hash));

        let AccumulateRequestV2::Apply(mut unauthorized) = stale else {
            unreachable!()
        };
        unauthorized.work.invocation = InvocationId([12; 32]);
        unauthorized.work.authorization = AuthorizationEvidenceV2::Credential {
            policy: Hash([99; 32]),
            credential_commitment: Hash([98; 32]),
            bytes: vec![1],
        };
        unauthorized.transition.consumed_input = unauthorized.work.input_id();
        assert_eq!(
            execute_guest_accumulate(&mut store, &AccumulateRequestV2::Apply(unauthorized))
                .unwrap(),
            rejected(AccumulationRejectionV2::Unauthorized)
        );
        assert_eq!(store, before);
    }

    fn message(
        call: u8,
        from: ActorId,
        to: ActorId,
        parent: Option<super::super::CallId>,
        deadline_timeslot: Option<u64>,
    ) -> MessageRecordV2 {
        let caller_invocation = InvocationId([call; 32]);
        let await_ordinal = u64::from(call);
        let mut payload = vec![crate::value::TAG_DYNAMIC];
        payload.extend_from_slice(&crate::Encode::encode(&crate::value::Msg::new("set")));
        MessageRecordV2 {
            call_id: caller_invocation.call_id(await_ordinal),
            caller_invocation,
            await_ordinal,
            from,
            to,
            parent,
            payload,
            authorization: AuthorizationEvidenceV2::Public,
            deadline_timeslot,
        }
    }

    #[test]
    fn durable_messages_validate_parent_cycles_deadlines_and_call_ids() {
        let mut installed = MemStore::default();
        let (initial, receipt) =
            install_fixture(&mut installed, ConsistencyModeV2::Local, b"before");
        let root = receipt.resulting_state_root.unwrap();
        let caller = ActorId([40; 32]);
        let peer = ActorId([41; 32]);
        let incoming = message(42, caller, actor(), None, Some(10));

        let mut valid_work = linear_work(initial.clone(), root);
        valid_work.invocation = InvocationId([43; 32]);
        let mut valid = linear_transition(&valid_work, b"valid");
        valid.inbox.push(incoming.clone());
        valid
            .outbox
            .push(message(44, actor(), peer, Some(incoming.call_id), Some(9)));
        let accepted = execute_guest_accumulate(
            &mut installed,
            &AccumulateRequestV2::Apply(AccumulationEnvelopeV2 {
                work: valid_work,
                transition: valid,
                provided_blobs: vec![],
            }),
        )
        .unwrap();
        assert!(matches!(accepted, AccumulationResultV2::Accepted { .. }));

        let committed_header =
            StoreHeaderV2::open(installed.rows.get(header_storage_key()).unwrap()).unwrap();
        let mut inbox_work = linear_work(
            BlobRefV2::of_bytes(b"valid"),
            committed_header.state_root.unwrap(),
        );
        inbox_work.invocation = InvocationId::for_call(incoming.call_id);
        inbox_work.causal_parent = Some(incoming.caller_invocation);
        inbox_work.parent_call = Some(incoming.call_id);
        inbox_work.arguments = incoming.payload.clone();
        inbox_work.origin = Origin::Actor(incoming.from);
        inbox_work.authorization = incoming.authorization.clone();
        inbox_work.base = ConsistencyBaseV2::Linear {
            revision: 1,
            state_root: committed_header.state_root.unwrap(),
        };
        let mut forged = inbox_work.clone();
        forged.origin = Origin::Anonymous;
        let before_forged = installed.clone();
        assert_eq!(
            execute_guest_accumulate(
                &mut installed,
                &AccumulateRequestV2::Apply(AccumulationEnvelopeV2 {
                    transition: linear_transition(&forged, b"forged"),
                    work: forged,
                    provided_blobs: vec![],
                }),
            )
            .unwrap(),
            rejected(AccumulationRejectionV2::InvalidWorkflowTransition)
        );
        assert_eq!(installed, before_forged);
        let mut expired = inbox_work.clone();
        expired.logical_timeslot = 10;
        assert_eq!(
            execute_guest_accumulate(
                &mut installed,
                &AccumulateRequestV2::Apply(AccumulationEnvelopeV2 {
                    transition: linear_transition(&expired, b"expired"),
                    work: expired,
                    provided_blobs: vec![],
                }),
            )
            .unwrap(),
            rejected(AccumulationRejectionV2::InvalidWorkflowTransition)
        );
        assert_eq!(installed, before_forged);
        let delivered = execute_guest_accumulate(
            &mut installed,
            &AccumulateRequestV2::Apply(AccumulationEnvelopeV2 {
                transition: linear_transition(&inbox_work, b"delivered"),
                work: inbox_work,
                provided_blobs: vec![],
            }),
        )
        .unwrap();
        assert!(matches!(delivered, AccumulationResultV2::Accepted { .. }));

        let reject = |outgoing: MessageRecordV2| {
            let mut store = MemStore::default();
            let (initial, receipt) =
                install_fixture(&mut store, ConsistencyModeV2::Local, b"before");
            let work = linear_work(initial, receipt.resulting_state_root.unwrap());
            let mut transition = linear_transition(&work, b"must-not-commit");
            transition.inbox.push(incoming.clone());
            transition.outbox.push(outgoing);
            let before = store.clone();
            let result = execute_guest_accumulate(
                &mut store,
                &AccumulateRequestV2::Apply(AccumulationEnvelopeV2 {
                    work,
                    transition,
                    provided_blobs: vec![],
                }),
            )
            .unwrap();
            assert_eq!(store, before);
            result
        };

        assert_eq!(
            reject(message(
                45,
                actor(),
                caller,
                Some(incoming.call_id),
                Some(9),
            )),
            rejected(AccumulationRejectionV2::MessageCycle)
        );
        assert_eq!(
            reject(message(46, actor(), peer, Some(incoming.call_id), Some(11),)),
            rejected(AccumulationRejectionV2::InvalidWorkflowTransition)
        );
        assert_eq!(
            reject(message(
                47,
                actor(),
                peer,
                Some(InvocationId([99; 32]).call_id(99)),
                Some(9),
            )),
            rejected(AccumulationRejectionV2::InvalidWorkflowTransition)
        );

        let mut store = MemStore::default();
        let (initial, receipt) = install_fixture(&mut store, ConsistencyModeV2::Local, b"before");
        let work = linear_work(initial, receipt.resulting_state_root.unwrap());
        let mut collision = linear_transition(&work, b"must-not-commit");
        collision.inbox.push(incoming.clone());
        collision.outbox.push(incoming);
        assert_eq!(
            execute_guest_accumulate(
                &mut store,
                &AccumulateRequestV2::Apply(AccumulationEnvelopeV2 {
                    work,
                    transition: collision,
                    provided_blobs: vec![],
                }),
            )
            .unwrap(),
            rejected(AccumulationRejectionV2::InvalidWorkflowTransition)
        );
    }

    fn crdt_work(initial: BlobRefV2, invocation: u8, heads: Vec<Hash>) -> WorkEnvelopeV2 {
        let base_causal_height = Some(u64::from(!heads.is_empty()));
        WorkEnvelopeV2 {
            service: identity(),
            invocation: InvocationId([invocation; 32]),
            workflow_step: 0,
            logical_timeslot: 1,
            target: actor(),
            target_program: program(),
            method: "set".into(),
            arguments: vec![2],
            origin: Origin::Anonymous,
            authorization: AuthorizationEvidenceV2::Public,
            causal_parent: None,
            parent_call: None,
            consistency: ConsistencyModeV2::Crdt,
            base: ConsistencyBaseV2::Crdt { heads },
            base_causal_height,
            imported_actors: vec![ImportedActorV2 {
                actor: actor(),
                program: program(),
                state: initial,
                causal_states: vec![],
                continuation: None,
            }],
            imported_blobs: Vec::new(),
            proof_requested: false,
        }
    }

    fn crdt_transition(
        work: &WorkEnvelopeV2,
        materialization: BlobRefV2,
        height: u64,
    ) -> TransitionV2 {
        let change_id = CrdtChangeV2::derive_id(work).unwrap();
        let field = Hash([14; 32]);
        let mut transition = TransitionV2 {
            service: work.service.clone(),
            consumed_input: work.input_id(),
            target_program: work.target_program,
            base: work.base.clone(),
            writes: Vec::new(),
            crdt_change: Some(CrdtChangeV2 {
                id: change_id,
                causal_dependencies: match &work.base {
                    ConsistencyBaseV2::Crdt { heads } => heads.clone(),
                    _ => unreachable!(),
                },
                causal_height: height,
                operations: vec![CrdtOperationV2 {
                    actor: actor(),
                    field,
                    ordinal: 0,
                    id: OperationId(change_id.operation(actor(), field, 0).0),
                    payload: vec![1],
                }],
                workflow: Vec::new(),
                materializations: vec![CrdtMaterializationV2 {
                    actor: actor(),
                    state: materialization,
                }],
            }),
            continuations: Vec::new(),
            inbox: Vec::new(),
            outbox: Vec::new(),
            reply: None,
            exported_blobs: Vec::new(),
            gas: GasAccountingV2::default(),
            proof: None,
        };
        let workflow = transition.workflow_operations();
        transition.crdt_change.as_mut().unwrap().workflow = workflow;
        transition
    }

    #[test]
    fn crdt_nodes_heads_and_materializations_are_committed_by_the_guest() {
        let mut store = MemStore::default();
        let (initial, _) = install_fixture(&mut store, ConsistencyModeV2::Crdt, b"initial");
        let materialized = BlobRefV2::of_bytes(b"one");
        let work = crdt_work(initial, 20, Vec::new());
        let transition = crdt_transition(&work, materialized.clone(), 1);
        let cid = transition.crdt_change.as_ref().unwrap().cid();
        let accepted = execute_guest_accumulate(
            &mut store,
            &AccumulateRequestV2::Apply(AccumulationEnvelopeV2 {
                work,
                transition: transition.clone(),
                provided_blobs: vec![ImportedBlobV2 {
                    reference: materialized.clone(),
                    bytes: b"one".to_vec(),
                }],
            }),
        )
        .unwrap();
        let AccumulationResultV2::Accepted { receipt, .. } = accepted else {
            panic!("CRDT transition rejected")
        };
        assert_eq!(receipt.resulting_crdt_heads, vec![cid]);
        assert_eq!(receipt.sequence, 1);
        assert_eq!(store.blobs.get(&materialized.hash), Some(&b"one".to_vec()));
        assert_eq!(
            CrdtChangeV2::decode(store.rows.get(&crdt_node_storage_key(cid)).unwrap()).unwrap(),
            transition.crdt_change.clone().unwrap()
        );

        let next_materialized = BlobRefV2::of_bytes(b"two");
        let next_work = crdt_work(materialized, 21, vec![cid]);
        let next = crdt_transition(&next_work, next_materialized.clone(), 2);
        let next_cid = next.crdt_change.as_ref().unwrap().cid();
        let accepted = execute_guest_accumulate(
            &mut store,
            &AccumulateRequestV2::Apply(AccumulationEnvelopeV2 {
                work: next_work,
                transition: next,
                provided_blobs: vec![ImportedBlobV2 {
                    reference: next_materialized,
                    bytes: b"two".to_vec(),
                }],
            }),
        )
        .unwrap();
        let AccumulationResultV2::Accepted { receipt, .. } = accepted else {
            panic!("causal CRDT transition rejected")
        };
        assert_eq!(receipt.resulting_crdt_heads, vec![next_cid]);
        assert_eq!(receipt.sequence, 2);
    }

    #[test]
    fn crdt_work_binds_complete_multi_head_materialization_frontier() {
        let mut store = MemStore::default();
        let (initial, _) = install_fixture(&mut store, ConsistencyModeV2::Crdt, b"initial");

        let mut branches = Vec::new();
        for (invocation, bytes) in [(30, b"left".as_slice()), (31, b"right".as_slice())] {
            let materialization = BlobRefV2::of_bytes(bytes);
            let work = crdt_work(initial.clone(), invocation, Vec::new());
            let transition = crdt_transition(&work, materialization.clone(), 1);
            let cid = transition.crdt_change.as_ref().unwrap().cid();
            let result = execute_guest_accumulate(
                &mut store,
                &AccumulateRequestV2::Apply(AccumulationEnvelopeV2 {
                    work,
                    transition,
                    provided_blobs: vec![ImportedBlobV2 {
                        reference: materialization.clone(),
                        bytes: bytes.to_vec(),
                    }],
                }),
            )
            .unwrap();
            assert!(matches!(result, AccumulationResultV2::Accepted { .. }));
            branches.push((cid, materialization));
        }

        branches.sort_by_key(|(cid, _)| *cid);
        let heads = branches.iter().map(|(cid, _)| *cid).collect::<Vec<_>>();
        let mut states = branches
            .iter()
            .map(|(_, state)| state.clone())
            .collect::<Vec<_>>();
        states.sort_by_key(|state| state.hash);
        let state = states.remove(0);
        let mut work = crdt_work(state, 32, heads.clone());
        work.imported_actors[0].causal_states = states;
        work.base_causal_height = Some(1);
        let merged = BlobRefV2::of_bytes(b"merged");
        let transition = crdt_transition(&work, merged.clone(), 2);
        let merged_cid = transition.crdt_change.as_ref().unwrap().cid();
        let accepted = execute_guest_accumulate(
            &mut store,
            &AccumulateRequestV2::Apply(AccumulationEnvelopeV2 {
                work,
                transition,
                provided_blobs: vec![ImportedBlobV2 {
                    reference: merged,
                    bytes: b"merged".to_vec(),
                }],
            }),
        )
        .unwrap();
        let AccumulationResultV2::Accepted { receipt, .. } = accepted else {
            panic!("multi-head CRDT transition rejected")
        };
        assert_eq!(receipt.resulting_crdt_heads, vec![merged_cid]);

        // A present head cannot hide an unavailable ancestor during activation.
        let mut incomplete = store.clone();
        incomplete
            .rows
            .remove(&crdt_node_storage_key(branches[0].0));
        let mut work = crdt_work(BlobRefV2::of_bytes(b"merged"), 33, vec![merged_cid]);
        work.base_causal_height = Some(2);
        let next = crdt_transition(&work, BlobRefV2::of_bytes(b"next"), 3);
        assert_eq!(
            execute_guest_accumulate(
                &mut incomplete,
                &AccumulateRequestV2::Apply(AccumulationEnvelopeV2 {
                    work,
                    transition: next,
                    provided_blobs: vec![ImportedBlobV2 {
                        reference: BlobRefV2::of_bytes(b"next"),
                        bytes: b"next".to_vec(),
                    }],
                }),
            )
            .unwrap(),
            rejected(AccumulationRejectionV2::MissingCausalDependency(
                branches[0].0,
            ))
        );
    }

    #[test]
    fn storage_failure_requires_discarding_the_whole_staging_transaction() {
        let mut committed = MemStore::default();
        let (initial, install) =
            install_fixture(&mut committed, ConsistencyModeV2::Local, b"before");
        let work = linear_work(initial, install.resulting_state_root.unwrap());
        let request = AccumulateRequestV2::Apply(AccumulationEnvelopeV2 {
            transition: linear_transition(&work, b"after"),
            work,
            provided_blobs: Vec::new(),
        });
        let mut staging = committed.clone();
        staging.writes_before_failure = Some(3);
        assert!(matches!(
            execute_guest_accumulate(&mut staging, &request),
            Err(GuestAccumulateError::StateTree(StateTreeError::Storage(
                MemError::Injected
            )))
        ));
        assert_ne!(
            staging.rows, committed.rows,
            "staging was partially mutated"
        );
        assert_eq!(
            StoreHeaderV2::open(committed.rows.get(header_storage_key()).unwrap())
                .unwrap()
                .revision,
            0,
            "the committed transaction remains untouched"
        );
    }
}
