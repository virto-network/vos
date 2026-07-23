//! Consensus Accumulate implementation executed by the generic service guest.
//!
//! The store passed here is one invocation-scoped JAM transaction: writes are
//! visible to later reads, but the host publishes none of them unless the
//! physical IC-5 entry halts successfully. Storage errors are therefore fatal
//! rather than encoded rejections; trapping makes the host discard staging.

use alloc::collections::{BTreeMap, BTreeSet};
use alloc::vec::Vec;

use super::{
    ABI_VERSION, AccumulateRequestV2, AccumulationEnvelopeV2, AccumulationReceiptV2,
    AccumulationRejectionV2, AccumulationResultV2, ActorGenesisV2, ActorId,
    AuthorizationEvidenceV2, BlobRefV2, ConsistencyBaseV2, ConsistencyModeV2,
    ContinuationSnapshotV2, CrdtChangeV2, DedupRecordV2, EXECUTION_SEMANTICS_ID, Hash,
    MessageRecordV2, MethodPolicyV2, ProgramId, PublishedEffectsV2, ServiceGenesisV2,
    ServiceInstallReceiptV2, ServiceStateTreeV2, StateKeyV2, StateTreeError, StateTreeStore,
    StoreHeaderV2, StoreOpenError, V2Wire, WorkflowCheckpointV2, crdt_change_storage_key,
    crdt_node_storage_key, dedup_storage_key, header_storage_key, receipt_storage_key,
};

/// Extra content-addressed operations needed by guest Accumulate in addition
/// to ordinary JAM service storage.
pub trait GuestAccumulateStoreV2: StateTreeStore {
    fn blob_available(&self, reference: &BlobRefV2) -> Result<bool, Self::Error>;

    /// Whether exact canonical actor PVM bytes are available to this service.
    fn program_available(&self, program: ProgramId) -> Result<bool, Self::Error>;

    /// Load and verify an already available content-addressed blob. Guest
    /// Accumulate uses this for semantic validation of continuation headers;
    /// the host never interprets them.
    fn load_blob(&self, reference: &BlobRefV2) -> Result<Option<Vec<u8>>, Self::Error>;

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
        if !store
            .program_available(actor.program)
            .map_err(GuestAccumulateError::Storage)?
        {
            return Ok(rejected(AccumulationRejectionV2::WrongProgram));
        }
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
    if !valid_workflow_input(&tree, work)? {
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
    if !canonical_transition_shape(work, transition) {
        return Ok(rejected(AccumulationRejectionV2::InvalidWorkflowTransition));
    }
    if let Some(rejection) = validate_base(tree.store_ref(), &header, &work.base)? {
        return Ok(rejected(rejection));
    }
    if let Some(rejection) = validate_crdt(tree.store_ref(), &header, work, transition)? {
        return Ok(rejected(rejection));
    }

    for imported in &work.imported_actors {
        if !tree
            .store_ref()
            .program_available(imported.program)
            .map_err(GuestAccumulateError::Storage)?
        {
            return Ok(rejected(AccumulationRejectionV2::WrongProgram));
        }
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
                crdt_base_materialization(tree.store_ref(), &descriptor, imported.actor, heads)?
            else {
                // Multi-head materialization is enabled with the generated
                // field-delta merger; never accept a host-invented heap in the
                // meantime.
                return Ok(rejected(AccumulationRejectionV2::InvalidWorkflowTransition));
            };
            if expected != imported.state {
                return Ok(rejected(AccumulationRejectionV2::InvalidWorkflowTransition));
            }
        } else {
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

    if let Some(rejection) = validate_continuation_change(tree.store_ref(), envelope)? {
        return Ok(rejected(rejection));
    }

    if let Some(rejection) = validate_durable_messages(&tree, transition)? {
        return Ok(rejected(rejection));
    }
    if contains_cycle(&transition.outbox) {
        return Ok(rejected(AccumulationRejectionV2::MessageCycle));
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
        if !blob_available(tree.store_ref(), reference)? {
            return Ok(rejected(AccumulationRejectionV2::MissingBlob(
                reference.hash,
            )));
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
        workflow_identity: work.workflow_identity(),
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
            header.revision = match header.revision.checked_add(1) {
                Some(revision) => revision,
                None => return Ok(rejected(AccumulationRejectionV2::SequenceOverflow)),
            };
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
        || change.work_hash != work.hash()
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
    let mut max_height = 0;
    for dependency in heads {
        let Some(bytes) = read(store, &crdt_node_storage_key(*dependency))? else {
            return Ok(Some(AccumulationRejectionV2::MissingCausalDependency(
                *dependency,
            )));
        };
        let parent =
            CrdtChangeV2::decode(&bytes).map_err(|_| GuestAccumulateError::CorruptStore)?;
        if parent.cid() != *dependency {
            return Err(GuestAccumulateError::CorruptStore);
        }
        max_height = max_height.max(parent.causal_height);
    }
    if max_height.checked_add(1) != Some(change.causal_height) {
        return Ok(Some(AccumulationRejectionV2::InvalidWorkflowTransition));
    }
    Ok(None)
}

fn crdt_base_materialization<S: StateTreeStore>(
    store: &S,
    descriptor: &ActorGenesisV2,
    actor: ActorId,
    heads: &[Hash],
) -> GuestResult<Option<BlobRefV2>, S::Error> {
    match heads {
        [] => Ok(Some(descriptor.initial_state.clone())),
        [head] => {
            let Some(bytes) = read(store, &crdt_node_storage_key(*head))? else {
                return Ok(None);
            };
            let change =
                CrdtChangeV2::decode(&bytes).map_err(|_| GuestAccumulateError::CorruptStore)?;
            if change.cid() != *head {
                return Err(GuestAccumulateError::CorruptStore);
            }
            Ok(change
                .materializations
                .iter()
                .find(|materialization| materialization.actor == actor)
                .map(|materialization| materialization.state.clone()))
        }
        _ => Ok(None),
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

fn canonical_transition_shape(
    work: &super::WorkEnvelopeV2,
    transition: &super::TransitionV2,
) -> bool {
    let writes = transition.writes.iter().map(|write| {
        let mut key = write.actor.0.to_vec();
        key.extend_from_slice(&write.key);
        (write.actor == work.target && !write.key.is_empty(), key)
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
        && transition.reply.as_ref().is_none_or(|reply| {
            reply.producer == work.target
                && reply.call_id
                    == work
                        .parent_call
                        .unwrap_or_else(|| work.invocation.root_reply_id())
        })
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

fn valid_workflow_input<S: StateTreeStore>(
    tree: &ServiceStateTreeV2<'_, S>,
    work: &super::WorkEnvelopeV2,
) -> GuestResult<bool, S::Error> {
    let checkpoint =
        tree_get_wire::<_, WorkflowCheckpointV2>(tree, &StateKeyV2::Workflow(work.invocation))?;
    let continuation = tree_get_wire::<_, BlobRefV2>(tree, &StateKeyV2::Continuation(work.target))?;
    Ok(match (work.workflow_step, checkpoint, continuation) {
        (0, None, None) => true,
        (0, _, _) => false,
        (step, Some(checkpoint), Some(_)) => {
            checkpoint.input.invocation == work.invocation
                && checkpoint.input.workflow_step.checked_add(1) == Some(step)
                && checkpoint.workflow_identity == work.workflow_identity()
        }
        _ => false,
    })
}

fn validate_continuation_change<S: GuestAccumulateStoreV2>(
    store: &S,
    envelope: &AccumulationEnvelopeV2,
) -> GuestResult<Option<AccumulationRejectionV2>, S::Error> {
    let work = &envelope.work;
    let current = work
        .imported_actors
        .iter()
        .find(|actor| actor.actor == work.target)
        .and_then(|actor| actor.continuation.as_ref());
    let change = match envelope.transition.continuations.as_slice() {
        [] if current.is_none() => return Ok(None),
        [] => {
            return Ok(Some(AccumulationRejectionV2::InvalidWorkflowTransition));
        }
        [change] if change.actor == work.target => change,
        _ => {
            return Ok(Some(AccumulationRejectionV2::InvalidWorkflowTransition));
        }
    };
    if current.map(|reference| reference.hash) != change.expected {
        return Ok(Some(AccumulationRejectionV2::ContinuationConflict(
            work.target,
        )));
    }
    let Some(replacement) = change.replacement.as_ref() else {
        return Ok(None);
    };
    let bytes = match store
        .load_blob(replacement)
        .map_err(GuestAccumulateError::Storage)?
    {
        Some(bytes) => bytes,
        None => {
            return Ok(Some(AccumulationRejectionV2::MissingBlob(replacement.hash)));
        }
    };
    if BlobRefV2::of_bytes(&bytes) != *replacement {
        return Err(GuestAccumulateError::CorruptStore);
    }
    let snapshot = match ContinuationSnapshotV2::decode(&bytes) {
        Ok(snapshot) => snapshot,
        Err(_) => {
            return Ok(Some(AccumulationRejectionV2::InvalidWorkflowTransition));
        }
    };
    if snapshot.validate_checkpoint_for(work).is_err() {
        return Ok(Some(AccumulationRejectionV2::InvalidWorkflowTransition));
    }
    if let Some(call) = snapshot.pending_call {
        let matching = envelope
            .transition
            .outbox
            .iter()
            .filter(|message| message.call_id == call && message.from == work.target)
            .count();
        if matching != 1 {
            return Ok(Some(AccumulationRejectionV2::InvalidWorkflowTransition));
        }
    }
    Ok(None)
}

fn referenced_blobs<'a>(
    work: &'a super::WorkEnvelopeV2,
    transition: &'a super::TransitionV2,
) -> impl Iterator<Item = &'a BlobRefV2> {
    work.imported_blobs
        .iter()
        .chain(
            work.imported_actors
                .iter()
                .flat_map(|actor| core::iter::once(&actor.state).chain(actor.continuation.iter())),
        )
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
    transition: &super::TransitionV2,
) -> GuestResult<Option<AccumulationRejectionV2>, S::Error> {
    let mut staged = BTreeMap::<super::CallId, MessageRecordV2>::new();
    for message in transition.inbox.iter().chain(&transition.outbox) {
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
        ActorWriteV2, ContinuationChangeV2, CrdtMaterializationV2, CrdtOperationV2, DeploymentId,
        GasAccountingV2, ImportedActorV2, InvocationId, OperationId, Origin, ProgramId,
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
        programs: BTreeMap<ProgramId, Vec<u8>>,
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

        fn load_blob(&self, reference: &BlobRefV2) -> Result<Option<Vec<u8>>, Self::Error> {
            Ok(self
                .blobs
                .get(&reference.hash)
                .filter(|bytes| reference.matches(bytes))
                .cloned())
        }

        fn provide_blob(&mut self, bytes: &[u8]) -> Result<BlobRefV2, Self::Error> {
            let reference = BlobRefV2::of_bytes(bytes);
            self.blobs.insert(reference.hash, bytes.to_vec());
            Ok(reference)
        }

        fn program_available(&self, program: ProgramId) -> Result<bool, Self::Error> {
            Ok(self
                .programs
                .get(&program)
                .is_some_and(|pvm| ProgramId::of_pvm(pvm) == program))
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

    const FIXTURE_ACTOR_PVM: &[u8] = b"fixture actor pvm";

    fn program() -> ProgramId {
        ProgramId::of_pvm(FIXTURE_ACTOR_PVM)
    }

    fn install_fixture(
        store: &mut MemStore,
        consistency: ConsistencyModeV2,
        initial: &[u8],
    ) -> (BlobRefV2, ServiceInstallReceiptV2) {
        let initial = store.provide_blob(initial).unwrap();
        store.programs.insert(program(), FIXTURE_ACTOR_PVM.to_vec());
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

    #[test]
    fn install_requires_every_actor_program_to_be_available() {
        let mut store = MemStore::default();
        let initial = store.provide_blob(b"state").unwrap();
        let genesis = ServiceGenesisV2 {
            service: identity(),
            consistency: ConsistencyModeV2::Local,
            actors: vec![ActorGenesisV2 {
                actor: actor(),
                parent: None,
                program: program(),
                initial_state: initial,
                crdt: false,
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
        };
        let before = store.clone();

        assert_eq!(
            execute_guest_accumulate(&mut store, &AccumulateRequestV2::Install(genesis)).unwrap(),
            rejected(AccumulationRejectionV2::WrongProgram)
        );
        assert_eq!(store, before, "missing code must not initialize the store");
    }

    fn linear_work(initial: BlobRefV2, base_root: Hash) -> WorkEnvelopeV2 {
        WorkEnvelopeV2 {
            service: identity(),
            invocation: InvocationId([10; 32]),
            workflow_step: 0,
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
            imported_actors: vec![ImportedActorV2 {
                actor: actor(),
                program: program(),
                state: initial,
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
        });
        execute_guest_accumulate(&mut store, &first).unwrap();

        let current_state = BlobRefV2::of_bytes(b"after");
        let mut stale_work = linear_work(current_state, root);
        stale_work.invocation = InvocationId([11; 32]);
        let stale = AccumulateRequestV2::Apply(AccumulationEnvelopeV2 {
            transition: linear_transition(&stale_work, b"late"),
            work: stale_work,
        });
        let before = store.clone();
        assert!(matches!(
            execute_guest_accumulate(&mut store, &stale).unwrap(),
            AccumulationResultV2::Rejected(AccumulationRejectionV2::StaleLinearWork { .. })
        ));
        assert_eq!(store, before);

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

    #[test]
    fn apply_requires_every_imported_actor_program_to_remain_available() {
        let mut store = MemStore::default();
        let (initial, install) = install_fixture(&mut store, ConsistencyModeV2::Local, b"before");
        let work = linear_work(initial, install.resulting_state_root.unwrap());
        let transition = linear_transition(&work, b"after");
        store.programs.remove(&program());
        let before = store.clone();

        assert_eq!(
            execute_guest_accumulate(
                &mut store,
                &AccumulateRequestV2::Apply(AccumulationEnvelopeV2 { work, transition }),
            )
            .unwrap(),
            rejected(AccumulationRejectionV2::WrongProgram)
        );
        assert_eq!(
            store, before,
            "missing canonical actor code must stage no service changes"
        );
    }

    #[test]
    fn reply_is_bound_to_the_invocation_call_id() {
        let mut store = MemStore::default();
        let (initial, install) = install_fixture(&mut store, ConsistencyModeV2::Local, b"before");
        let work = linear_work(initial, install.resulting_state_root.unwrap());
        let mut transition = linear_transition(&work, b"after");
        transition.reply.as_mut().unwrap().call_id = super::super::CallId([200; 32]);
        let before = store.clone();

        assert_eq!(
            execute_guest_accumulate(
                &mut store,
                &AccumulateRequestV2::Apply(AccumulationEnvelopeV2 { work, transition }),
            )
            .unwrap(),
            rejected(AccumulationRejectionV2::InvalidWorkflowTransition)
        );
        assert_eq!(store, before);
    }

    #[test]
    fn continuation_slices_are_guest_bound_to_one_workflow_identity_and_next_step() {
        let mut store = MemStore::default();
        let (initial, install) = install_fixture(&mut store, ConsistencyModeV2::Local, b"before");
        let first_work = linear_work(initial, install.resulting_state_root.unwrap());
        let continuation_bytes = ContinuationSnapshotV2 {
            snapshot_version: super::super::SNAPSHOT_VERSION,
            jar_semantics: super::super::EXECUTION_SEMANTICS_ID,
            vos_abi: super::super::ABI_VERSION,
            service: first_work.service.clone(),
            invocation: first_work.invocation,
            checkpoint_step: first_work.workflow_step,
            actor: first_work.target,
            actor_program: first_work.target_program,
            await_ordinal: 0,
            pending_call: None,
            kernel_snapshot: vec![1],
        }
        .encode();
        let continuation = store.provide_blob(&continuation_bytes).unwrap();
        let mut checkpoint = linear_transition(&first_work, b"checkpoint");
        checkpoint.reply = None;
        checkpoint.continuations.push(ContinuationChangeV2 {
            actor: first_work.target,
            expected: None,
            replacement: Some(continuation.clone()),
        });
        checkpoint.exported_blobs.push(continuation.clone());
        let mut wrong_snapshot = ContinuationSnapshotV2::decode(&continuation_bytes).unwrap();
        wrong_snapshot.invocation = InvocationId([200; 32]);
        let wrong_bytes = wrong_snapshot.encode();
        let wrong = store.provide_blob(&wrong_bytes).unwrap();
        let mut wrong_transition = checkpoint.clone();
        wrong_transition.continuations[0].replacement = Some(wrong.clone());
        wrong_transition.exported_blobs[0] = wrong.clone();
        let before_wrong = store.clone();
        assert_eq!(
            execute_guest_accumulate(
                &mut store,
                &AccumulateRequestV2::Apply(AccumulationEnvelopeV2 {
                    work: first_work.clone(),
                    transition: wrong_transition,
                }),
            )
            .unwrap(),
            rejected(AccumulationRejectionV2::InvalidWorkflowTransition)
        );
        assert_eq!(store, before_wrong);

        let mut waiting_snapshot = ContinuationSnapshotV2::decode(&continuation_bytes).unwrap();
        waiting_snapshot.pending_call = Some(first_work.invocation.call_id(0));
        let waiting_bytes = waiting_snapshot.encode();
        let waiting = store.provide_blob(&waiting_bytes).unwrap();
        let mut missing_outbox = checkpoint.clone();
        missing_outbox.continuations[0].replacement = Some(waiting.clone());
        missing_outbox.exported_blobs[0] = waiting;
        let before_missing_outbox = store.clone();
        assert_eq!(
            execute_guest_accumulate(
                &mut store,
                &AccumulateRequestV2::Apply(AccumulationEnvelopeV2 {
                    work: first_work.clone(),
                    transition: missing_outbox,
                }),
            )
            .unwrap(),
            rejected(AccumulationRejectionV2::InvalidWorkflowTransition)
        );
        assert_eq!(store, before_missing_outbox);

        let first = execute_guest_accumulate(
            &mut store,
            &AccumulateRequestV2::Apply(AccumulationEnvelopeV2 {
                work: first_work.clone(),
                transition: checkpoint,
            }),
        )
        .unwrap();
        let AccumulationResultV2::Accepted { receipt, .. } = first else {
            panic!("checkpoint rejected")
        };

        let mut resume = first_work;
        resume.workflow_step = 1;
        resume.base = ConsistencyBaseV2::Linear {
            revision: receipt.sequence,
            state_root: receipt.resulting_state_root.unwrap(),
        };
        resume.imported_actors[0].state = BlobRefV2::of_bytes(b"checkpoint");
        resume.imported_actors[0].continuation = Some(continuation.clone());
        let mut completed = linear_transition(&resume, b"done");
        completed.continuations.push(ContinuationChangeV2 {
            actor: resume.target,
            expected: Some(continuation.hash),
            replacement: None,
        });

        let mut reentrant = resume.clone();
        reentrant.invocation = InvocationId([99; 32]);
        reentrant.workflow_step = 0;
        let before = store.clone();
        assert_eq!(
            execute_guest_accumulate(
                &mut store,
                &AccumulateRequestV2::Apply(AccumulationEnvelopeV2 {
                    transition: linear_transition(&reentrant, b"reentrant"),
                    work: reentrant,
                }),
            )
            .unwrap(),
            rejected(AccumulationRejectionV2::InvalidWorkflowTransition)
        );
        assert_eq!(
            store, before,
            "a fresh invocation cannot enter a suspended actor"
        );

        let mut changed_origin = resume.clone();
        changed_origin.origin = Origin::Actor(ActorId([99; 32]));
        assert_eq!(
            execute_guest_accumulate(
                &mut store,
                &AccumulateRequestV2::Apply(AccumulationEnvelopeV2 {
                    transition: {
                        let mut transition = completed.clone();
                        transition.consumed_input = changed_origin.input_id();
                        transition
                    },
                    work: changed_origin,
                }),
            )
            .unwrap(),
            rejected(AccumulationRejectionV2::InvalidWorkflowTransition)
        );
        assert_eq!(store, before);

        let mut skipped = resume.clone();
        skipped.workflow_step = 2;
        let mut skipped_transition = completed.clone();
        skipped_transition.consumed_input = skipped.input_id();
        assert_eq!(
            execute_guest_accumulate(
                &mut store,
                &AccumulateRequestV2::Apply(AccumulationEnvelopeV2 {
                    work: skipped,
                    transition: skipped_transition,
                }),
            )
            .unwrap(),
            rejected(AccumulationRejectionV2::InvalidWorkflowTransition)
        );
        assert_eq!(store, before);

        assert!(matches!(
            execute_guest_accumulate(
                &mut store,
                &AccumulateRequestV2::Apply(AccumulationEnvelopeV2 {
                    work: resume,
                    transition: completed,
                }),
            )
            .unwrap(),
            AccumulationResultV2::Accepted {
                duplicate: false,
                ..
            }
        ));
    }

    fn message(
        call: u8,
        from: ActorId,
        to: ActorId,
        parent: Option<super::super::CallId>,
        deadline_timeslot: Option<u64>,
    ) -> MessageRecordV2 {
        MessageRecordV2 {
            call_id: super::super::CallId([call; 32]),
            from,
            to,
            parent,
            payload: vec![call],
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
            }),
        )
        .unwrap();
        assert!(matches!(accepted, AccumulationResultV2::Accepted { .. }));

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
                &AccumulateRequestV2::Apply(AccumulationEnvelopeV2 { work, transition }),
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
                Some(super::super::CallId([99; 32])),
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
                }),
            )
            .unwrap(),
            rejected(AccumulationRejectionV2::InvalidWorkflowTransition)
        );
    }

    fn crdt_work(initial: BlobRefV2, invocation: u8, heads: Vec<Hash>) -> WorkEnvelopeV2 {
        WorkEnvelopeV2 {
            service: identity(),
            invocation: InvocationId([invocation; 32]),
            workflow_step: 0,
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
            imported_actors: vec![ImportedActorV2 {
                actor: actor(),
                program: program(),
                state: initial,
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
                work_hash: work.hash(),
                causal_dependencies: match &work.base {
                    ConsistencyBaseV2::Crdt { heads } => heads.clone(),
                    _ => unreachable!(),
                },
                causal_height: height,
                operations: vec![CrdtOperationV2 {
                    actor: actor(),
                    dispatch_ordinal: 0,
                    field,
                    ordinal: 0,
                    id: OperationId(change_id.operation(actor(), 0, field, 0).0),
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
        let materialized = store.provide_blob(b"one").unwrap();
        let work = crdt_work(initial, 20, Vec::new());
        let transition = crdt_transition(&work, materialized.clone(), 1);
        let cid = transition.crdt_change.as_ref().unwrap().cid();
        let accepted = execute_guest_accumulate(
            &mut store,
            &AccumulateRequestV2::Apply(AccumulationEnvelopeV2 {
                work,
                transition: transition.clone(),
            }),
        )
        .unwrap();
        let AccumulationResultV2::Accepted { receipt, .. } = accepted else {
            panic!("CRDT transition rejected")
        };
        assert_eq!(receipt.resulting_crdt_heads, vec![cid]);
        assert_eq!(receipt.sequence, 1);
        assert_eq!(
            CrdtChangeV2::decode(store.rows.get(&crdt_node_storage_key(cid)).unwrap()).unwrap(),
            transition.crdt_change.clone().unwrap()
        );

        let next_materialized = store.provide_blob(b"two").unwrap();
        let next_work = crdt_work(materialized, 21, vec![cid]);
        let next = crdt_transition(&next_work, next_materialized, 2);
        let next_cid = next.crdt_change.as_ref().unwrap().cid();
        let accepted = execute_guest_accumulate(
            &mut store,
            &AccumulateRequestV2::Apply(AccumulationEnvelopeV2 {
                work: next_work,
                transition: next,
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
    fn storage_failure_requires_discarding_the_whole_staging_transaction() {
        let mut committed = MemStore::default();
        let (initial, install) =
            install_fixture(&mut committed, ConsistencyModeV2::Local, b"before");
        let work = linear_work(initial, install.resulting_state_root.unwrap());
        let request = AccumulateRequestV2::Apply(AccumulationEnvelopeV2 {
            transition: linear_transition(&work, b"after"),
            work,
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
