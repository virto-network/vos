//! Consensus Accumulate implementation executed by the generic service guest.
//!
//! The store passed here is one invocation-scoped JAM transaction: writes are
//! visible to later reads, but the host publishes none of them unless the
//! physical IC-5 entry halts successfully. Storage errors are therefore fatal
//! rather than encoded rejections; trapping makes the host discard staging.

use alloc::collections::{BTreeMap, BTreeSet};
use alloc::vec::Vec;

use crate::attestation::AttestationPreparationV2;

use super::causal::{CausalFrontierError, load_causal_frontier};
use super::contracts::crdt_change_blob_references;
use super::{
    ABI_VERSION, AccumulateRequestV2, AccumulationEnvelopeV2, AccumulationReceiptV2,
    AccumulationRejectionV2, AccumulationResultV2, ActorGenesisV2, ActorId,
    AuthorizationEvidenceV2, BlobRefV2, ConsistencyBaseV2, ConsistencyModeV2,
    ContinuationSnapshotV2, CrdtChangeV2, CrdtSyncEnvelopeV2, DedupRecordV2, DeliveryEnvelopeV2,
    DeliveryRecordV2, EXECUTION_SEMANTICS_ID, Hash, MessageRecordV2, MethodPolicyV2,
    ProofVerificationRequestV2, PublicationAckV2, PublicationRecordV2, PublishedEffectsV2,
    ReceiptVerificationRequestV2, ServiceGenesisV2, ServiceInstallReceiptV2, ServiceStateTreeV2,
    SpaceRoleCredentialV2, StateKeyV2, StateTreeError, StateTreeStore, StoreHeaderV2,
    StoreOpenError, V2Wire, WorkflowCheckpointV2, WorkflowOperationV2, crdt_change_storage_key,
    crdt_node_receipt_storage_key, crdt_node_storage_key, dedup_storage_key, delivery_storage_key,
    header_storage_key, public_policy_hash, publication_storage_key, receipt_storage_key,
    space_role_for_policy,
};

/// Extra content-addressed operations needed by guest Accumulate in addition
/// to ordinary JAM service storage.
pub trait GuestAccumulateStoreV2: StateTreeStore {
    /// Authenticate the exact initial service tree against platform/deployment
    /// authority before the store has a header to bind its identity.
    fn authorize_install(&self, genesis: &ServiceGenesisV2) -> Result<bool, Self::Error>;

    fn blob_available(&self, reference: &BlobRefV2) -> Result<bool, Self::Error>;

    /// Load and verify an already available content-addressed blob. Guest
    /// Accumulate uses this for semantic validation of continuation headers;
    /// the host never interprets them.
    fn load_blob(&self, reference: &BlobRefV2) -> Result<Option<Vec<u8>>, Self::Error>;

    /// Stage bytes in the content-addressed store and return their canonical
    /// VOS reference. The staged blob becomes visible only with this same
    /// Accumulate transaction.
    fn provide_blob(&mut self, bytes: &[u8]) -> Result<BlobRefV2, Self::Error>;

    /// Validate the proof against the exact public inputs derived by guest
    /// Accumulate. Implementations must fail closed when the verifier or proof
    /// blob is unavailable.
    fn verify_proof(
        &self,
        request: &ProofVerificationRequestV2,
    ) -> Result<ProofVerificationV2, Self::Error>;

    /// Validate that an external accumulation receipt is finalized and belongs
    /// to the service identity encoded in it.
    fn verify_receipt(
        &self,
        request: &ReceiptVerificationRequestV2,
    ) -> Result<ReceiptVerificationV2, Self::Error>;
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ProofVerificationV2 {
    Valid,
    Invalid,
    Unavailable,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ReceiptVerificationV2 {
    Valid,
    Invalid,
    Unavailable,
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
        AccumulateRequestV2::Apply(envelope) => apply(store, &envelope, ApplyMode::Commit),
        AccumulateRequestV2::PrepareAttested(envelope) => {
            apply(store, &envelope, ApplyMode::PrepareAttested)
        }
        AccumulateRequestV2::Deliver(envelope) => deliver(store, &envelope),
        AccumulateRequestV2::SyncCrdt(envelope) => sync_crdt(store, &envelope),
        AccumulateRequestV2::AcknowledgePublication(acknowledgement) => {
            acknowledge_publication(store, &acknowledgement)
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum ApplyMode {
    Commit,
    PrepareAttested,
}

fn acknowledge_publication<S: GuestAccumulateStoreV2>(
    store: &mut S,
    acknowledgement: &PublicationAckV2,
) -> GuestResult<AccumulationResultV2, S::Error> {
    let Some(header_bytes) = read(store, header_storage_key())? else {
        return Ok(rejected(AccumulationRejectionV2::StoreUninitialized));
    };
    let header = match StoreHeaderV2::open(&header_bytes) {
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
    if acknowledgement.service != header.service {
        return Ok(rejected(AccumulationRejectionV2::WrongService));
    }
    let key = publication_storage_key(acknowledgement.input);
    let Some(bytes) = read(store, &key)? else {
        return Ok(AccumulationResultV2::PublicationAcknowledged {
            input: acknowledgement.input,
            duplicate: true,
        });
    };
    let publication =
        PublicationRecordV2::decode(&bytes).map_err(|_| GuestAccumulateError::CorruptStore)?;
    if publication.input != acknowledgement.input
        || publication.commitment() != acknowledgement.publication
        || publication.receipt.service != header.service
    {
        return Ok(rejected(AccumulationRejectionV2::DivergentDuplicate));
    }
    write(store, &key, None)?;
    Ok(AccumulationResultV2::PublicationAcknowledged {
        input: acknowledgement.input,
        duplicate: false,
    })
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
    if !store
        .authorize_install(genesis)
        .map_err(GuestAccumulateError::Storage)?
    {
        return Ok(rejected(AccumulationRejectionV2::Unauthorized));
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
        let directory = super::ActorDirectoryV2 {
            actors: genesis.actors.iter().map(|actor| actor.actor).collect(),
        };
        tree_apply(
            &mut tree,
            &StateKeyV2::ActorDirectory,
            Some(&directory.encode()),
        )?;
        for actor in &genesis.actors {
            tree_apply(
                &mut tree,
                &StateKeyV2::ActorDescriptor(actor.actor),
                Some(&actor.encode()),
            )?;
            tree_apply(
                &mut tree,
                &StateKeyV2::ActorName {
                    parent: actor.parent,
                    name: actor.name.clone(),
                },
                Some(&actor.actor.0),
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

fn deliver<S: GuestAccumulateStoreV2>(
    store: &mut S,
    envelope: &DeliveryEnvelopeV2,
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
    if envelope.service != header.service {
        return Ok(rejected(AccumulationRejectionV2::WrongService));
    }
    if header.service.service_abi != ABI_VERSION {
        return Ok(rejected(AccumulationRejectionV2::WrongAbi));
    }
    if header.service.execution_semantics != EXECUTION_SEMANTICS_ID {
        return Ok(rejected(AccumulationRejectionV2::WrongExecutionSemantics));
    }
    if !envelope.base.mode_compatible(header.consistency)
        || (header.consistency == ConsistencyModeV2::Crdt) != envelope.crdt_change.is_some()
    {
        return Ok(rejected(AccumulationRejectionV2::InvalidConsistency));
    }

    let delivery_commitment = envelope.commitment();
    let delivery_key = delivery_storage_key(envelope.message.call_id);
    if let Some(bytes) = read(store, &delivery_key)? {
        let record =
            DeliveryRecordV2::decode(&bytes).map_err(|_| GuestAccumulateError::CorruptStore)?;
        return if record.call_id == envelope.message.call_id
            && record.delivery_commitment == delivery_commitment
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

    let source = &envelope.source_receipt.service;
    if source.space != header.service.space
        || source.root_service == header.service.root_service
        || source.service_abi != ABI_VERSION
        || source.execution_semantics != EXECUTION_SEMANTICS_ID
    {
        return Ok(rejected(AccumulationRejectionV2::InvalidReceipt));
    }
    match store
        .verify_receipt(&ReceiptVerificationRequestV2 {
            receipt: envelope.source_receipt.clone(),
        })
        .map_err(GuestAccumulateError::Storage)?
    {
        ReceiptVerificationV2::Invalid => {
            return Ok(rejected(AccumulationRejectionV2::InvalidReceipt));
        }
        ReceiptVerificationV2::Unavailable => {
            return Ok(rejected(AccumulationRejectionV2::ReceiptUnavailable));
        }
        ReceiptVerificationV2::Valid => {}
    }
    if envelope
        .message
        .deadline_timeslot
        .is_some_and(|deadline| envelope.logical_timeslot >= deadline)
    {
        return Ok(rejected(AccumulationRejectionV2::InvalidWorkflowTransition));
    }
    if let Some(rejection) = validate_base(store, &header, &envelope.base)? {
        return Ok(rejected(rejection));
    }
    if header.consistency != ConsistencyModeV2::Crdt && header.revision == u64::MAX {
        return Ok(rejected(AccumulationRejectionV2::SequenceOverflow));
    }
    if let Some(change) = envelope.crdt_change.as_ref() {
        let ConsistencyBaseV2::Crdt { heads } = &envelope.base else {
            unreachable!("delivery wire validation binds CRDT change to CRDT base")
        };
        let frontier = match load_causal_frontier(heads, |cid| {
            store.read(&crdt_node_storage_key(cid))
        }) {
            Ok(frontier) => frontier,
            Err(CausalFrontierError::Storage(error)) => {
                return Err(GuestAccumulateError::Storage(error));
            }
            Err(CausalFrontierError::Missing(cid)) => {
                return Ok(rejected(AccumulationRejectionV2::MissingCausalDependency(
                    cid,
                )));
            }
            Err(CausalFrontierError::Corrupt) => return Err(GuestAccumulateError::CorruptStore),
        };
        if envelope.base_causal_height != Some(frontier.max_head_height)
            || frontier.max_head_height.checked_add(1) != Some(change.causal_height)
        {
            return Ok(rejected(AccumulationRejectionV2::InvalidWorkflowTransition));
        }
        if let Some(existing) = read(store, &crdt_change_storage_key(change.id))?
            && existing.as_slice() != change.cid().0
        {
            return Ok(rejected(AccumulationRejectionV2::DivergentDuplicate));
        }
    }

    let mut tree = ServiceStateTreeV2::new(store, header.service_root);
    if tree_get_wire::<_, ActorGenesisV2>(&tree, &StateKeyV2::ActorDescriptor(envelope.message.to))?
        .is_none()
    {
        return Ok(rejected(AccumulationRejectionV2::InvalidWorkflowTransition));
    }
    if tree_get_wire::<_, MessageRecordV2>(&tree, &StateKeyV2::Inbox(envelope.message.call_id))?
        .is_some()
        || tree_get_wire::<_, MessageRecordV2>(
            &tree,
            &StateKeyV2::Outbox(envelope.message.call_id),
        )?
        .is_some()
    {
        return Err(GuestAccumulateError::CorruptStore);
    }
    tree_apply(
        &mut tree,
        &StateKeyV2::Inbox(envelope.message.call_id),
        Some(&envelope.message.encode()),
    )?;
    header.service_root = tree.root();
    drop(tree);

    let (resulting_state_root, resulting_crdt_heads, sequence) =
        if let Some(change) = envelope.crdt_change.as_ref() {
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
            header.revision += 1;
            header.state_root = Some(header.service_root);
            (Some(header.service_root), Vec::new(), header.revision)
        };
    if header.consistency == ConsistencyModeV2::Crdt {
        rematerialize_crdt_service(store, &mut header)?;
    }
    let receipt = AccumulationReceiptV2 {
        service: header.service.clone(),
        accepted_transition: delivery_commitment,
        reply_commitment: None,
        outbox_commitment: None,
        resulting_state_root,
        resulting_crdt_heads,
        sequence,
        checkpoint: 0,
        consistency: header.consistency,
    };
    let record = DeliveryRecordV2 {
        call_id: envelope.message.call_id,
        delivery_commitment,
        receipt: receipt.clone(),
    };
    write(store, header_storage_key(), Some(&header.encode()))?;
    write(store, &delivery_key, Some(&record.encode()))?;
    if let Some(change) = envelope.crdt_change.as_ref() {
        write_crdt_node_receipt(store, change.cid(), &receipt)?;
    }
    Ok(AccumulationResultV2::Accepted {
        receipt,
        published: PublishedEffectsV2::default(),
        duplicate: false,
    })
}

#[derive(Debug, Clone)]
struct CausalValueV2<T> {
    cid: Hash,
    value: T,
}

#[derive(Default)]
struct WorkflowMaterializationV2 {
    workflows: BTreeMap<super::InvocationId, Vec<CausalValueV2<WorkflowCheckpointV2>>>,
    continuations: BTreeMap<ActorId, Vec<CausalValueV2<Option<BlobRefV2>>>>,
    inbox: BTreeMap<super::CallId, Vec<CausalValueV2<Option<MessageRecordV2>>>>,
    outbox: BTreeMap<super::CallId, Vec<CausalValueV2<Option<MessageRecordV2>>>>,
    replies: BTreeMap<super::CallId, Vec<CausalValueV2<super::ReplyRecordV2>>>,
    actor_states: BTreeMap<ActorId, Vec<CausalValueV2<BlobRefV2>>>,
}

fn sync_crdt<S: GuestAccumulateStoreV2>(
    store: &mut S,
    envelope: &CrdtSyncEnvelopeV2,
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
    if envelope.service != header.service {
        return Ok(rejected(AccumulationRejectionV2::WrongService));
    }
    if header.consistency != ConsistencyModeV2::Crdt {
        return Ok(rejected(AccumulationRejectionV2::InvalidConsistency));
    }

    let supplied_nodes = envelope
        .nodes
        .iter()
        .map(|node| (node.change.cid(), &node.change))
        .collect::<BTreeMap<_, _>>();
    let mut changed = false;
    for node in &envelope.nodes {
        let cid = node.change.cid();
        if let Some(existing) = read(store, &crdt_node_storage_key(cid))? {
            if existing != node.change.encode() {
                return Err(GuestAccumulateError::CorruptStore);
            }
        } else {
            changed = true;
            match store
                .verify_receipt(&ReceiptVerificationRequestV2 {
                    receipt: node.receipt.clone(),
                })
                .map_err(GuestAccumulateError::Storage)?
            {
                ReceiptVerificationV2::Valid => {}
                ReceiptVerificationV2::Invalid => {
                    return Ok(rejected(AccumulationRejectionV2::InvalidReceipt));
                }
                ReceiptVerificationV2::Unavailable => {
                    return Ok(rejected(AccumulationRejectionV2::ReceiptUnavailable));
                }
            }
        }
        if let Some(existing) = read(store, &crdt_change_storage_key(node.change.id))?
            && existing.as_slice() != cid.0
        {
            return Ok(rejected(AccumulationRejectionV2::DivergentDuplicate));
        }
    }

    for reference in envelope
        .nodes
        .iter()
        .flat_map(|node| crdt_change_blob_references(&node.change))
    {
        let supplied = envelope
            .provided_blobs
            .binary_search_by_key(&reference.hash, |blob| blob.reference.hash)
            .ok()
            .is_some_and(|index| envelope.provided_blobs[index].reference == *reference);
        if !supplied && !blob_available(store, reference)? {
            return Ok(rejected(AccumulationRejectionV2::MissingBlob(
                reference.hash,
            )));
        }
    }
    for blob in &envelope.provided_blobs {
        if !blob_available(store, &blob.reference)? {
            changed = true;
        }
    }

    let mut combined_heads = header.crdt_heads.clone();
    combined_heads.extend(envelope.advertised_heads.iter().copied());
    combined_heads.sort();
    combined_heads.dedup();
    let frontier = match load_causal_frontier(&combined_heads, |cid| {
        if let Some(change) = supplied_nodes.get(&cid) {
            Ok(Some(change.encode()))
        } else {
            store.read(&crdt_node_storage_key(cid))
        }
    }) {
        Ok(frontier) => frontier,
        Err(CausalFrontierError::Storage(error)) => {
            return Err(GuestAccumulateError::Storage(error));
        }
        Err(CausalFrontierError::Missing(cid)) => {
            return Ok(rejected(AccumulationRejectionV2::MissingCausalDependency(
                cid,
            )));
        }
        Err(CausalFrontierError::Corrupt) => {
            return Ok(rejected(AccumulationRejectionV2::InvalidWorkflowTransition));
        }
    };
    let resulting_heads = frontier.canonical_heads();
    changed |= resulting_heads != header.crdt_heads;
    let materialized = match materialize_workflow_crdt(&frontier, &header.service) {
        Ok(materialized) => materialized,
        Err(rejection) => return Ok(rejected(rejection)),
    };
    {
        let tree = ServiceStateTreeV2::new(store, header.service_root);
        if !materialized_actors_exist(&tree, &materialized)? {
            return Ok(rejected(AccumulationRejectionV2::InvalidWorkflowTransition));
        }
    }

    let sync_commitment = envelope.commitment();
    let receipt = AccumulationReceiptV2 {
        service: header.service.clone(),
        accepted_transition: sync_commitment,
        reply_commitment: None,
        outbox_commitment: None,
        resulting_state_root: None,
        resulting_crdt_heads: resulting_heads.clone(),
        sequence: frontier.max_head_height,
        checkpoint: 0,
        consistency: ConsistencyModeV2::Crdt,
    };
    if !changed {
        return Ok(AccumulationResultV2::Accepted {
            receipt,
            published: PublishedEffectsV2::default(),
            duplicate: true,
        });
    }

    for blob in &envelope.provided_blobs {
        let actual = store
            .provide_blob(&blob.bytes)
            .map_err(GuestAccumulateError::Storage)?;
        if actual != blob.reference {
            return Err(GuestAccumulateError::CorruptStore);
        }
    }
    for node in &envelope.nodes {
        write_crdt_change(store, &node.change, node.change.cid())?;
        write_crdt_node_receipt(store, node.change.cid(), &node.receipt)?;
    }

    let mut tree = ServiceStateTreeV2::new(store, header.service_root);
    apply_workflow_materialization(&mut tree, materialized)?;
    header.service_root = tree.root();
    header.crdt_heads = resulting_heads;
    drop(tree);
    write(store, header_storage_key(), Some(&header.encode()))?;
    Ok(AccumulationResultV2::Accepted {
        receipt,
        published: PublishedEffectsV2::default(),
        duplicate: false,
    })
}

fn materialize_workflow_crdt(
    frontier: &super::causal::CausalFrontierV2,
    service: &super::ServiceIdentityV2,
) -> Result<WorkflowMaterializationV2, AccumulationRejectionV2> {
    let mut result = WorkflowMaterializationV2::default();
    for (cid, change) in frontier.nodes_in_causal_order() {
        let checkpoints = change
            .workflow
            .iter()
            .filter_map(|operation| match operation {
                WorkflowOperationV2::Checkpoint(work) => Some(work),
                _ => None,
            })
            .collect::<Vec<_>>();
        match checkpoints.as_slice() {
            [work]
                if work.service == *service
                    && work.consistency == ConsistencyModeV2::Crdt
                    && matches!(&work.base, ConsistencyBaseV2::Crdt { heads } if *heads == change.causal_dependencies)
                    && work.base_causal_height == Some(change.causal_height - 1)
                    && Some(change.id) == CrdtChangeV2::derive_id(work)
                    && change.operations.iter().all(|operation| {
                        work.imported_actors
                            .binary_search_by_key(&operation.actor, |actor| actor.actor)
                            .is_ok()
                    })
                    && change.materializations.iter().all(|materialization| {
                        work.imported_actors
                            .binary_search_by_key(&materialization.actor, |actor| actor.actor)
                            .is_ok()
                    }) =>
            {
                let observed = result
                    .workflows
                    .get(&work.invocation)
                    .into_iter()
                    .flatten()
                    .filter(|event| frontier.contains_ancestor(cid, event.cid))
                    .collect::<Vec<_>>();
                let valid_step = match (work.workflow_step, observed.as_slice()) {
                    (0, []) => true,
                    (step, [previous]) => {
                        previous.value.input.workflow_step.checked_add(1) == Some(step)
                            && previous.value.matches_resume_work(work)
                    }
                    _ => false,
                };
                if !valid_step {
                    return Err(AccumulationRejectionV2::InvalidWorkflowTransition);
                }
                let checkpoint = WorkflowCheckpointV2 {
                    input: work.input_id(),
                    workflow_identity: work.workflow_identity(),
                    resume_work: (*work).clone(),
                    work_hash: work.hash(),
                    // CRDT workflow rows must be reconstructible from the DAG
                    // without the outer Transition wire. The authenticated
                    // node CID is their canonical slice commitment.
                    transition_commitment: cid,
                };
                insert_causal_value(
                    frontier,
                    result.workflows.entry(work.invocation).or_default(),
                    cid,
                    checkpoint,
                );
            }
            [] if change.operations.is_empty()
                && change.materializations.is_empty()
                && matches!(change.workflow.as_slice(), [WorkflowOperationV2::Inbox(message)]
                    if change.id == CrdtChangeV2::derive_delivery_id(service, message.call_id, &change.causal_dependencies)) =>
                {}
            _ => return Err(AccumulationRejectionV2::InvalidWorkflowTransition),
        }

        for materialization in &change.materializations {
            insert_causal_value(
                frontier,
                result
                    .actor_states
                    .entry(materialization.actor)
                    .or_default(),
                cid,
                materialization.state.clone(),
            );
        }
        for operation in &change.workflow {
            match operation {
                WorkflowOperationV2::Checkpoint(work) => {
                    if let Some(call) = work.parent_call {
                        insert_causal_value(
                            frontier,
                            result.inbox.entry(call).or_default(),
                            cid,
                            None,
                        );
                    }
                }
                WorkflowOperationV2::Continuation(change) => {
                    let values = result.continuations.entry(change.actor).or_default();
                    let mut observed = values
                        .iter()
                        .filter(|event| frontier.contains_ancestor(cid, event.cid))
                        .map(|event| event.value.as_ref().map(|reference| reference.hash));
                    let expected = observed.next().unwrap_or(None);
                    if observed.any(|value| value != expected) || change.expected != expected {
                        return Err(AccumulationRejectionV2::InvalidWorkflowTransition);
                    }
                    insert_causal_value(frontier, values, cid, change.replacement.clone());
                }
                WorkflowOperationV2::Inbox(message) => insert_causal_value(
                    frontier,
                    result.inbox.entry(message.call_id).or_default(),
                    cid,
                    Some(message.clone()),
                ),
                WorkflowOperationV2::Outbox(message) => insert_causal_value(
                    frontier,
                    result.outbox.entry(message.call_id).or_default(),
                    cid,
                    Some(message.clone()),
                ),
                WorkflowOperationV2::ConsumeOutbox(call) => insert_causal_value(
                    frontier,
                    result.outbox.entry(*call).or_default(),
                    cid,
                    None,
                ),
                WorkflowOperationV2::Reply(reply) => insert_causal_value(
                    frontier,
                    result.replies.entry(reply.call_id).or_default(),
                    cid,
                    reply.clone(),
                ),
            }
        }
    }
    validate_strict_frontiers(result.workflows.values())?;
    validate_strict_frontiers(result.continuations.values())?;
    validate_strict_frontiers(result.replies.values())?;
    for messages in result.inbox.values().chain(result.outbox.values()) {
        let mut visible = messages.iter().filter_map(|event| event.value.as_ref());
        if let Some(first) = visible.next()
            && visible.any(|message| message != first)
        {
            return Err(AccumulationRejectionV2::DivergentDuplicate);
        }
    }
    Ok(result)
}

fn insert_causal_value<T>(
    frontier: &super::causal::CausalFrontierV2,
    values: &mut Vec<CausalValueV2<T>>,
    cid: Hash,
    value: T,
) {
    if values
        .iter()
        .any(|existing| frontier.contains_ancestor(existing.cid, cid))
    {
        return;
    }
    values.retain(|existing| !frontier.contains_ancestor(cid, existing.cid));
    values.push(CausalValueV2 { cid, value });
    values.sort_by_key(|event| event.cid);
}

fn validate_strict_frontiers<'a, T: PartialEq + 'a>(
    frontiers: impl Iterator<Item = &'a Vec<CausalValueV2<T>>>,
) -> Result<(), AccumulationRejectionV2> {
    for values in frontiers {
        if let Some(first) = values.first()
            && values
                .iter()
                .skip(1)
                .any(|value| value.value != first.value)
        {
            return Err(AccumulationRejectionV2::DivergentDuplicate);
        }
    }
    Ok(())
}

fn apply_workflow_materialization<S: StateTreeStore>(
    tree: &mut ServiceStateTreeV2<'_, S>,
    materialized: WorkflowMaterializationV2,
) -> GuestResult<(), S::Error> {
    for (invocation, values) in materialized.workflows {
        let value = values
            .first()
            .expect("workflow frontier is never empty")
            .value
            .encode();
        tree_apply(tree, &StateKeyV2::Workflow(invocation), Some(&value))?;
    }
    for (actor, values) in materialized.continuations {
        require_actor(tree, actor)?;
        let value = values
            .first()
            .expect("continuation frontier is never empty")
            .value
            .as_ref()
            .map(V2Wire::encode);
        tree_apply(tree, &StateKeyV2::Continuation(actor), value.as_deref())?;
    }
    for (call, values) in materialized.inbox {
        let visible = values.iter().find_map(|event| event.value.as_ref());
        if let Some(message) = visible {
            require_actor(tree, message.to)?;
        }
        let value = visible.map(V2Wire::encode);
        tree_apply(tree, &StateKeyV2::Inbox(call), value.as_deref())?;
    }
    for (call, values) in materialized.outbox {
        let visible = values.iter().find_map(|event| event.value.as_ref());
        if let Some(message) = visible {
            require_actor(tree, message.from)?;
        }
        let value = visible.map(V2Wire::encode);
        tree_apply(tree, &StateKeyV2::Outbox(call), value.as_deref())?;
    }
    for (actor, values) in materialized.actor_states {
        require_actor(tree, actor)?;
        let value = values
            .iter()
            .map(|event| &event.value)
            .max_by_key(|reference| (reference.hash, reference.len))
            .expect("actor-state frontier is never empty")
            .encode();
        tree_apply(tree, &StateKeyV2::CrdtMaterialization(actor), Some(&value))?;
    }
    Ok(())
}

fn materialized_actors_exist<S: StateTreeStore>(
    tree: &ServiceStateTreeV2<'_, S>,
    materialized: &WorkflowMaterializationV2,
) -> GuestResult<bool, S::Error> {
    let mut actors = materialized
        .workflows
        .values()
        .flatten()
        .map(|event| event.value.resume_work.target)
        .chain(materialized.continuations.keys().copied())
        .chain(materialized.actor_states.keys().copied())
        .chain(
            materialized
                .inbox
                .values()
                .flatten()
                .filter_map(|event| event.value.as_ref())
                .map(|message| message.to),
        )
        .chain(
            materialized
                .outbox
                .values()
                .flatten()
                .filter_map(|event| event.value.as_ref())
                .map(|message| message.from),
        )
        .chain(
            materialized
                .replies
                .values()
                .flatten()
                .map(|event| event.value.producer),
        )
        .collect::<Vec<_>>();
    actors.sort();
    actors.dedup();
    for actor in actors {
        if tree_get_wire::<_, ActorGenesisV2>(tree, &StateKeyV2::ActorDescriptor(actor))?.is_none()
        {
            return Ok(false);
        }
    }
    Ok(true)
}

fn require_actor<S: StateTreeStore>(
    tree: &ServiceStateTreeV2<'_, S>,
    actor: ActorId,
) -> GuestResult<(), S::Error> {
    if tree_get_wire::<_, ActorGenesisV2>(tree, &StateKeyV2::ActorDescriptor(actor))?.is_none() {
        return Err(GuestAccumulateError::CorruptStore);
    }
    Ok(())
}

fn apply<S: GuestAccumulateStoreV2>(
    store: &mut S,
    envelope: &AccumulationEnvelopeV2,
    mode: ApplyMode,
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
    let attached_proof = envelope.transition.proof.as_ref();
    let proofless_transition = envelope.transition.proofless_clone();
    let transition = &proofless_transition;
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
    let transition_commitment = transition.commitment();
    let duplicate_receipt = if let Some(bytes) = read(store, &dedup_storage_key(work.input_id()))? {
        let record =
            DedupRecordV2::decode(&bytes).map_err(|_| GuestAccumulateError::CorruptStore)?;
        if record.input == work.input_id()
            && record.work_hash == work_hash
            && record.transition_commitment == transition_commitment
        {
            Some(record.receipt)
        } else {
            return Ok(rejected(AccumulationRejectionV2::DivergentDuplicate));
        }
    } else {
        None
    };

    let mut tree = ServiceStateTreeV2::new(store, header.service_root);
    let Some(directory) =
        tree_get_wire::<_, super::ActorDirectoryV2>(&tree, &StateKeyV2::ActorDirectory)?
    else {
        return Ok(rejected(AccumulationRejectionV2::WrongProgram));
    };
    if !directory
        .actors
        .iter()
        .copied()
        .eq(work.imported_actors.iter().map(|actor| actor.actor))
    {
        return Ok(rejected(AccumulationRejectionV2::WrongProgram));
    }
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
    let proof_required = policy.attested || work.proof_requested;
    if proof_required
        && (!transition.continuations.is_empty()
            || !transition.outbox.is_empty()
            || transition.reply.is_none())
    {
        return Ok(rejected(AccumulationRejectionV2::InvalidWorkflowTransition));
    }
    match mode {
        ApplyMode::PrepareAttested => {
            if !proof_required || attached_proof.is_some() {
                return Ok(rejected(AccumulationRejectionV2::InvalidProof));
            }
        }
        ApplyMode::Commit => {
            if proof_required {
                if attached_proof.is_none() {
                    return Ok(rejected(AccumulationRejectionV2::MissingProof));
                }
            }
            if attached_proof.is_some() {
                if !proof_required {
                    return Ok(rejected(AccumulationRejectionV2::InvalidProof));
                }
            }
        }
    }

    if let Some(receipt) = duplicate_receipt {
        return Ok(match mode {
            ApplyMode::Commit => AccumulationResultV2::Accepted {
                receipt,
                published: PublishedEffectsV2::default(),
                duplicate: true,
            },
            ApplyMode::PrepareAttested => {
                let preparation = match AttestationPreparationV2::for_transition(
                    work, transition, &policy, receipt,
                ) {
                    Ok(preparation) => preparation,
                    Err(_) => return Ok(rejected(AccumulationRejectionV2::InvalidProof)),
                };
                AccumulationResultV2::Prepared(preparation)
            }
        });
    }

    let base_workflow = if let ConsistencyBaseV2::Crdt { heads } = &work.base {
        match crdt_workflow_at_heads(tree.store_ref(), &header.service, heads)? {
            Ok(materialized) => Some(materialized),
            Err(missing) => {
                return Ok(rejected(AccumulationRejectionV2::MissingCausalDependency(
                    missing,
                )));
            }
        }
    } else {
        None
    };
    if !valid_workflow_input(&tree, work, base_workflow.as_ref())? {
        return Ok(rejected(AccumulationRejectionV2::InvalidWorkflowTransition));
    }
    if !work_matches_durable_inbox(&tree, work)? {
        return Ok(rejected(AccumulationRejectionV2::InvalidWorkflowTransition));
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
        if descriptor.name != imported.name || descriptor.parent != imported.parent {
            return Ok(rejected(AccumulationRejectionV2::WrongProgram));
        }
        let committed_continuation = match base_workflow.as_ref() {
            Some(materialized) => materialized
                .continuations
                .get(&imported.actor)
                .and_then(|values| values.first())
                .and_then(|value| value.value.clone()),
            None => {
                tree_get_wire::<_, BlobRefV2>(&tree, &StateKeyV2::Continuation(imported.actor))?
            }
        };
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

    if let Some(rejection) = validate_continuation_change(tree.store_ref(), envelope)? {
        return Ok(rejected(rejection));
    }
    if let Some(rejection) = validate_awaited_reply(&tree, work)? {
        return Ok(rejected(rejection));
    }

    if let Some(rejection) = validate_durable_messages(&tree, work, transition)? {
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
    let proof_blob = attached_proof.map(|proof| &proof.proof_blob);
    for candidate in &envelope.provided_blobs {
        // Proof availability is an acceptance precondition, not an input to
        // actor/workflow state transition construction. Stage it only after
        // deriving the exact receipt which the proof statement binds, so
        // PrepareAttested and Apply execute the same consensus transition.
        if proof_blob == Some(&candidate.reference) {
            continue;
        }
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
    // The durable inbox row is the authority for a cross-root invocation.
    // Consume it in the same guest-owned state-tree update as the actor
    // writes, continuation, reply, and dedup record. Exact retries return via
    // the dedup row before reaching this point; divergent replays can no
    // longer reuse a delivered call.
    if let Some(call) = work.parent_call {
        tree_apply(&mut tree, &StateKeyV2::Inbox(call), None)?;
    }
    if let Some(awaited) = work.awaited_reply.as_ref() {
        tree_apply(&mut tree, &StateKeyV2::Outbox(awaited.reply.call_id), None)?;
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
    // `WorkEnvelopeV2` is intentionally complete and therefore large. Keep
    // the durable workflow value off the bounded service-PVM stack while its
    // nested wire encoder is active.
    let workflow = alloc::boxed::Box::new(WorkflowCheckpointV2 {
        input: work.input_id(),
        workflow_identity: work.workflow_identity(),
        resume_work: work.clone(),
        work_hash,
        transition_commitment: transition
            .crdt_change
            .as_ref()
            .map(CrdtChangeV2::cid)
            .unwrap_or(transition_commitment),
    });
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
    if header.consistency == ConsistencyModeV2::Crdt {
        rematerialize_crdt_service(store, &mut header)?;
    }

    let receipt = AccumulationReceiptV2 {
        service: header.service.clone(),
        accepted_transition: transition_commitment,
        reply_commitment: transition
            .reply
            .as_ref()
            .map(super::ReplyRecordV2::commitment),
        outbox_commitment: MessageRecordV2::outbox_commitment(&transition.outbox),
        resulting_state_root,
        resulting_crdt_heads,
        sequence,
        checkpoint: work.workflow_step,
        consistency: header.consistency,
    };
    let preparation = if proof_required {
        let preparation = match AttestationPreparationV2::for_transition(
            work,
            transition,
            &policy,
            receipt.clone(),
        ) {
            Ok(preparation) => preparation,
            Err(_) => return Ok(rejected(AccumulationRejectionV2::InvalidProof)),
        };
        Some(preparation)
    } else {
        None
    };
    if mode == ApplyMode::Commit && proof_required {
        let proof = attached_proof.expect("proof presence was validated");
        if proof.statement
            != preparation
                .as_ref()
                .expect("proof preparation was constructed")
                .statement
                .commitment()
        {
            return Ok(rejected(AccumulationRejectionV2::InvalidProof));
        }
        if !blob_available(store, &proof.proof_blob)? {
            let candidate = envelope
                .provided_blobs
                .binary_search_by_key(&proof.proof_blob.hash, |blob| blob.reference.hash)
                .ok()
                .map(|index| &envelope.provided_blobs[index])
                .filter(|candidate| candidate.reference == proof.proof_blob)
                .expect("proof blob availability was validated before staging");
            let actual = store
                .provide_blob(&candidate.bytes)
                .map_err(GuestAccumulateError::Storage)?;
            if actual != proof.proof_blob {
                return Err(GuestAccumulateError::CorruptStore);
            }
        }
        let verification = ProofVerificationRequestV2 {
            actor_program: work.target_program,
            execution_semantics: work.service.execution_semantics,
            statement: proof.statement,
            trace: proof.trace,
            proof_blob: proof.proof_blob.clone(),
        };
        match store
            .verify_proof(&verification)
            .map_err(GuestAccumulateError::Storage)?
        {
            ProofVerificationV2::Valid => {}
            ProofVerificationV2::Invalid => {
                return Ok(rejected(AccumulationRejectionV2::InvalidProof));
            }
            ProofVerificationV2::Unavailable => {
                return Ok(rejected(AccumulationRejectionV2::ProofUnavailable));
            }
        }
    }
    let record = DedupRecordV2 {
        input: work.input_id(),
        work_hash,
        transition_commitment,
        receipt: receipt.clone(),
    };
    let published = PublishedEffectsV2 {
        reply: transition.reply.clone(),
        outbox: transition.outbox.clone(),
        exported_blobs: transition.exported_blobs.clone(),
        proof: attached_proof.cloned(),
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
    if let Some(change) = transition.crdt_change.as_ref() {
        write_crdt_node_receipt(store, change.cid(), &receipt)?;
    }
    if mode == ApplyMode::Commit && published != PublishedEffectsV2::default() {
        let publication = PublicationRecordV2 {
            input: work.input_id(),
            receipt: receipt.clone(),
            published: published.clone(),
        };
        write(
            store,
            &publication_storage_key(work.input_id()),
            Some(&publication.encode()),
        )?;
    }

    Ok(match mode {
        ApplyMode::PrepareAttested => {
            AccumulationResultV2::Prepared(preparation.expect("attested preparation was required"))
        }
        ApplyMode::Commit => AccumulationResultV2::Accepted {
            receipt,
            published,
            duplicate: false,
        },
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
        || change.workflow != transition.workflow_operations(work)
        || change.operations.iter().any(|operation| {
            work.imported_actors
                .binary_search_by_key(&operation.actor, |actor| actor.actor)
                .is_err()
                || change
                    .materializations
                    .binary_search_by_key(&operation.actor, |state| state.actor)
                    .is_err()
        })
        || change.materializations.iter().any(|materialization| {
            work.imported_actors
                .binary_search_by_key(&materialization.actor, |actor| actor.actor)
                .is_err()
        })
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

fn write_crdt_node_receipt<S: StateTreeStore>(
    store: &mut S,
    cid: Hash,
    receipt: &AccumulationReceiptV2,
) -> GuestResult<(), S::Error> {
    let key = crdt_node_receipt_storage_key(cid);
    let encoded = receipt.encode();
    if let Some(existing) = read(store, &key)? {
        if existing != encoded {
            return Err(GuestAccumulateError::CorruptStore);
        }
        return Ok(());
    }
    write(store, &key, Some(&encoded))
}

fn rematerialize_crdt_service<S: GuestAccumulateStoreV2>(
    store: &mut S,
    header: &mut StoreHeaderV2,
) -> GuestResult<(), S::Error> {
    let frontier = match load_causal_frontier(&header.crdt_heads, |cid| {
        store.read(&crdt_node_storage_key(cid))
    }) {
        Ok(frontier) => frontier,
        Err(CausalFrontierError::Storage(error)) => {
            return Err(GuestAccumulateError::Storage(error));
        }
        Err(CausalFrontierError::Missing(_) | CausalFrontierError::Corrupt) => {
            return Err(GuestAccumulateError::CorruptStore);
        }
    };
    let materialized = materialize_workflow_crdt(&frontier, &header.service)
        .map_err(|_| GuestAccumulateError::CorruptStore)?;
    let mut tree = ServiceStateTreeV2::new(store, header.service_root);
    if !materialized_actors_exist(&tree, &materialized)? {
        return Err(GuestAccumulateError::CorruptStore);
    }
    apply_workflow_materialization(&mut tree, materialized)?;
    header.service_root = tree.root();
    Ok(())
}

fn canonical_transition_shape(
    work: &super::WorkEnvelopeV2,
    transition: &super::TransitionV2,
) -> bool {
    let writes = transition.writes.iter().map(|write| {
        let mut key = write.actor.0.to_vec();
        key.extend_from_slice(&write.key);
        let valid = work
            .imported_actors
            .binary_search_by_key(&write.actor, |actor| actor.actor)
            .is_ok()
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
            .is_none_or(|reply| reply.producer == work.target)
}

fn authorized(work: &super::WorkEnvelopeV2, policy: &MethodPolicyV2) -> bool {
    match &work.authorization {
        AuthorizationEvidenceV2::Public => policy.public && policy.policy == public_policy_hash(),
        AuthorizationEvidenceV2::Credential {
            policy: supplied_policy,
            credential_commitment,
            bytes,
        } => SpaceRoleCredentialV2::decode(bytes)
            .ok()
            .is_some_and(|credential| {
                !policy.public
                    && credential.holder == work.origin
                    && space_role_for_policy(policy.policy)
                        .is_some_and(|required| credential.role >= required)
                    && *supplied_policy == policy.policy
                    && *credential_commitment == credential.commitment()
            }),
        AuthorizationEvidenceV2::PrivateCredential {
            policy: supplied_policy,
            credential_commitment,
            witness,
        } => {
            !policy.public
                && (policy.attested || work.proof_requested)
                && space_role_for_policy(policy.policy).is_some()
                && matches!(
                    work.origin,
                    super::Origin::Member(_) | super::Origin::Actor(_)
                )
                && *supplied_policy == policy.policy
                && *credential_commitment != Hash::ZERO
                && work
                    .imported_blobs
                    .binary_search_by_key(&witness.hash, |blob| blob.hash)
                    .ok()
                    .is_some_and(|index| work.imported_blobs[index] == *witness)
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
    // The initial inbox was consumed atomically with the preceding checkpoint.
    // Later slices are authorized by the continuation plus the durable
    // workflow-identity row checked immediately before this function.
    if work.workflow_step != 0 {
        return Ok(true);
    }
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

fn valid_workflow_input<S: StateTreeStore>(
    tree: &ServiceStateTreeV2<'_, S>,
    work: &super::WorkEnvelopeV2,
    crdt_base: Option<&WorkflowMaterializationV2>,
) -> GuestResult<bool, S::Error> {
    let (checkpoint, continuation) = match crdt_base {
        Some(materialized) => (
            materialized
                .workflows
                .get(&work.invocation)
                .and_then(|values| values.first())
                .map(|value| value.value.clone()),
            materialized
                .continuations
                .get(&work.target)
                .and_then(|values| values.first())
                .and_then(|value| value.value.clone()),
        ),
        None => (
            tree_get_wire::<_, WorkflowCheckpointV2>(tree, &StateKeyV2::Workflow(work.invocation))?,
            tree_get_wire::<_, BlobRefV2>(tree, &StateKeyV2::Continuation(work.target))?,
        ),
    };
    Ok(match (work.workflow_step, checkpoint, continuation) {
        (0, None, None) => true,
        (0, _, _) => false,
        (step, Some(checkpoint), Some(_)) => {
            checkpoint.input.invocation == work.invocation
                && checkpoint.input.workflow_step.checked_add(1) == Some(step)
                && checkpoint.matches_resume_work(work)
        }
        _ => false,
    })
}

fn crdt_workflow_at_heads<S: StateTreeStore>(
    store: &S,
    service: &super::ServiceIdentityV2,
    heads: &[Hash],
) -> GuestResult<Result<WorkflowMaterializationV2, Hash>, S::Error> {
    let frontier = match load_causal_frontier(heads, |cid| store.read(&crdt_node_storage_key(cid)))
    {
        Ok(frontier) => frontier,
        Err(CausalFrontierError::Storage(error)) => {
            return Err(GuestAccumulateError::Storage(error));
        }
        Err(CausalFrontierError::Missing(cid)) => return Ok(Err(cid)),
        Err(CausalFrontierError::Corrupt) => return Err(GuestAccumulateError::CorruptStore),
    };
    materialize_workflow_crdt(&frontier, service)
        .map(Ok)
        .map_err(|_| GuestAccumulateError::CorruptStore)
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
    let changes = &envelope.transition.continuations;
    if changes.is_empty() {
        return Ok(current
            .is_some()
            .then_some(AccumulationRejectionV2::InvalidWorkflowTransition));
    }
    let Some(target_change) = changes
        .binary_search_by_key(&work.target, |change| change.actor)
        .ok()
        .map(|index| &changes[index])
    else {
        return Ok(Some(AccumulationRejectionV2::InvalidWorkflowTransition));
    };
    if current.map(|reference| reference.hash) != target_change.expected {
        return Ok(Some(AccumulationRejectionV2::ContinuationConflict(
            work.target,
        )));
    }

    let replacement = target_change.replacement.as_ref();
    let next = if let Some(reference) = replacement {
        let candidate = envelope
            .provided_blobs
            .binary_search_by_key(&reference.hash, |blob| blob.reference.hash)
            .ok()
            .filter(|index| envelope.provided_blobs[*index].reference == *reference)
            .map(|index| envelope.provided_blobs[index].bytes.clone());
        let bytes = match candidate {
            Some(bytes) => bytes,
            None => match store
                .load_blob(reference)
                .map_err(GuestAccumulateError::Storage)?
            {
                Some(bytes) => bytes,
                None => {
                    return Ok(Some(AccumulationRejectionV2::MissingBlob(reference.hash)));
                }
            },
        };
        if BlobRefV2::of_bytes(&bytes) != *reference {
            return Err(GuestAccumulateError::CorruptStore);
        }
        let snapshot = match ContinuationSnapshotV2::decode_metadata(&bytes) {
            Ok(snapshot) if snapshot.validate_checkpoint_for(work).is_ok() => snapshot,
            _ => {
                return Ok(Some(AccumulationRejectionV2::InvalidWorkflowTransition));
            }
        };
        Some(snapshot)
    } else {
        None
    };

    // The complete work import was already checked byte-for-byte against the
    // guest-owned tree. Actors carrying the target's current continuation are
    // therefore the authenticated previous lock set. The awaited-reply check
    // below validates that old continuation envelope once; avoid decoding its
    // multi-megabyte kernel snapshot a second time here.
    let previous_actors = current
        .map(|current| {
            work.imported_actors
                .iter()
                .filter(|actor| actor.continuation.as_ref() == Some(current))
                .map(|actor| actor.actor)
                .collect::<Vec<_>>()
        })
        .unwrap_or_default();
    let next_actors = next
        .as_ref()
        .map(|snapshot| snapshot.suspended_actors.as_slice())
        .unwrap_or_default();
    let mut changed = previous_actors.clone();
    changed.extend_from_slice(next_actors);
    changed.sort_unstable();
    changed.dedup();
    if changed.len() != changes.len() {
        return Ok(Some(AccumulationRejectionV2::InvalidWorkflowTransition));
    }
    for (actor, change) in changed.iter().zip(changes) {
        let imported = work
            .imported_actors
            .binary_search_by_key(actor, |candidate| candidate.actor)
            .ok()
            .map(|index| &work.imported_actors[index]);
        let expected = previous_actors
            .binary_search(actor)
            .ok()
            .and_then(|_| current.map(|reference| reference.hash));
        let replacement = next_actors
            .binary_search(actor)
            .ok()
            .and_then(|_| replacement.cloned());
        let imported_continuation = imported
            .and_then(|actor| actor.continuation.as_ref())
            .map(|reference| reference.hash);
        if change.actor != *actor
            || change.expected != expected
            || change.replacement != replacement
            || imported.is_none()
            || imported_continuation != expected
        {
            return Ok(Some(AccumulationRejectionV2::InvalidWorkflowTransition));
        }
    }

    if let Some(call) = next.as_ref().and_then(|snapshot| snapshot.pending_call) {
        let matching = envelope
            .transition
            .outbox
            .iter()
            .filter(|message| {
                message.call_id == call
                    && work
                        .imported_actors
                        .binary_search_by_key(&message.from, |actor| actor.actor)
                        .is_ok()
            })
            .count();
        if matching != 1 {
            return Ok(Some(AccumulationRejectionV2::InvalidWorkflowTransition));
        }
    }
    Ok(None)
}

fn validate_awaited_reply<S: GuestAccumulateStoreV2>(
    tree: &ServiceStateTreeV2<'_, S>,
    work: &super::WorkEnvelopeV2,
) -> GuestResult<Option<AccumulationRejectionV2>, S::Error> {
    let current = work
        .imported_actors
        .iter()
        .find(|actor| actor.actor == work.target)
        .and_then(|actor| actor.continuation.as_ref());
    let Some(current) = current else {
        return Ok(work
            .awaited_reply
            .is_some()
            .then_some(AccumulationRejectionV2::InvalidWorkflowTransition));
    };
    let Some(bytes) = tree
        .store_ref()
        .load_blob(current)
        .map_err(GuestAccumulateError::Storage)?
    else {
        return Ok(Some(AccumulationRejectionV2::MissingBlob(current.hash)));
    };
    if BlobRefV2::of_bytes(&bytes) != *current {
        return Err(GuestAccumulateError::CorruptStore);
    }
    let snapshot = match ContinuationSnapshotV2::decode_metadata(&bytes) {
        Ok(snapshot) if snapshot.validate_resume_for(work).is_ok() => snapshot,
        _ => {
            return Ok(Some(AccumulationRejectionV2::InvalidWorkflowTransition));
        }
    };
    let (call, awaited) = match (snapshot.pending_call, work.awaited_reply.as_ref()) {
        (None, None) => return Ok(None),
        (Some(call), Some(awaited)) if awaited.reply.call_id == call => (call, awaited),
        _ => {
            return Ok(Some(AccumulationRejectionV2::InvalidWorkflowTransition));
        }
    };
    let Some(message) = tree_get_wire::<_, MessageRecordV2>(tree, &StateKeyV2::Outbox(call))?
    else {
        return Ok(Some(AccumulationRejectionV2::InvalidWorkflowTransition));
    };
    if message.call_id != call
        || message.caller_invocation != work.invocation
        || message.await_ordinal != snapshot.await_ordinal
        || work
            .imported_actors
            .binary_search_by_key(&message.from, |actor| actor.actor)
            .is_err()
        || message.to != awaited.reply.producer
        || message.proof_requested != awaited.attestation.is_some()
        || message
            .deadline_timeslot
            .is_some_and(|deadline| work.logical_timeslot >= deadline)
        || awaited.receipt.reply_commitment != Some(awaited.reply.commitment())
        || awaited.receipt.service.service_abi != ABI_VERSION
        || awaited.receipt.service.execution_semantics != EXECUTION_SEMANTICS_ID
        || awaited.receipt.service.root_service == work.service.root_service
    {
        return Ok(Some(AccumulationRejectionV2::InvalidReceipt));
    }
    let request = ReceiptVerificationRequestV2 {
        receipt: awaited.receipt.clone(),
    };
    Ok(
        match tree
            .store_ref()
            .verify_receipt(&request)
            .map_err(GuestAccumulateError::Storage)?
        {
            ReceiptVerificationV2::Valid => None,
            ReceiptVerificationV2::Invalid => Some(AccumulationRejectionV2::InvalidReceipt),
            ReceiptVerificationV2::Unavailable => Some(AccumulationRejectionV2::ReceiptUnavailable),
        },
    )
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
        .chain(transition.proof.iter().map(|proof| &proof.proof_blob))
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
    use core::convert::Infallible;

    use super::*;
    use crate::v2::{
        ActorWriteV2, ContinuationChangeV2, CrdtMaterializationV2, CrdtOperationV2, DeploymentId,
        GasAccountingV2, ImportedActorV2, ImportedBlobV2, InvocationId, OperationId, Origin,
        ProgramId, ReplyRecordV2, RootServiceId, ServiceIdentityV2, TransitionV2, WorkEnvelopeV2,
    };

    #[derive(Debug, Clone, Copy, PartialEq, Eq)]
    enum MemError {
        Injected,
    }

    #[derive(Debug, Clone, Default, PartialEq, Eq)]
    struct MemStore {
        rows: BTreeMap<Vec<u8>, Vec<u8>>,
        blobs: BTreeMap<Hash, Vec<u8>>,
        receipt_allowlist: BTreeSet<Hash>,
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
        fn authorize_install(&self, _genesis: &ServiceGenesisV2) -> Result<bool, Self::Error> {
            Ok(true)
        }

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

        fn verify_proof(
            &self,
            _request: &ProofVerificationRequestV2,
        ) -> Result<ProofVerificationV2, Self::Error> {
            Ok(ProofVerificationV2::Unavailable)
        }

        fn verify_receipt(
            &self,
            request: &ReceiptVerificationRequestV2,
        ) -> Result<ReceiptVerificationV2, Self::Error> {
            Ok(if self.receipt_allowlist.contains(&request.hash()) {
                ReceiptVerificationV2::Valid
            } else {
                ReceiptVerificationV2::Unavailable
            })
        }
    }

    fn identity() -> ServiceIdentityV2 {
        ServiceIdentityV2 {
            space: super::super::SpaceId([0; 32]),
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
                name: "root".into(),
                parent: None,
                program: program(),
                initial_state: initial.clone(),
                crdt: consistency == ConsistencyModeV2::Crdt,
                methods: vec![MethodPolicyV2 {
                    method: "set".into(),
                    schema: Hash([6; 32]),
                    policy: public_policy_hash(),
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
            awaited_reply: None,
            consistency: ConsistencyModeV2::Local,
            base: ConsistencyBaseV2::Linear {
                revision: 0,
                state_root: base_root,
            },
            base_causal_height: None,
            imported_actors: vec![ImportedActorV2 {
                actor: actor(),
                name: "root".into(),
                parent: None,
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
    fn attestation_preparation_is_guest_derived_and_read_only() {
        let mut store = MemStore::default();
        let (initial, install) = install_fixture(&mut store, ConsistencyModeV2::Local, b"before");
        let mut work = linear_work(initial, install.resulting_state_root.unwrap());
        work.proof_requested = true;
        let transition = linear_transition(&work, b"after");
        let before = store.clone();
        let mut staging = store.clone();

        let result = execute_guest_accumulate(
            &mut staging,
            &AccumulateRequestV2::PrepareAttested(AccumulationEnvelopeV2 {
                work: work.clone(),
                transition: transition.clone(),
                provided_blobs: vec![],
            }),
        )
        .unwrap();
        let AccumulationResultV2::Prepared(preparation) = result else {
            panic!("attested transition was not prepared")
        };
        let policy = MethodPolicyV2 {
            method: "set".into(),
            schema: Hash([6; 32]),
            policy: public_policy_hash(),
            public: true,
            attested: false,
        };
        assert_eq!(
            preparation,
            AttestationPreparationV2::for_transition(
                &work,
                &transition,
                &policy,
                preparation.receipt.clone(),
            )
            .unwrap()
        );
        assert_eq!(store, before, "preparation must not commit guest state");
        assert_ne!(
            staging, before,
            "receipt prediction executes against an isolated staging transaction"
        );
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
        let publication_key = publication_storage_key(work.input_id());
        let publication = PublicationRecordV2::decode(
            store
                .rows
                .get(&publication_key)
                .expect("reply publication is durable in guest storage"),
        )
        .unwrap();
        assert_eq!(publication.receipt, receipt);
        assert_eq!(publication.published, published);

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

        let mut wrong_acknowledgement = PublicationAckV2 {
            service: identity(),
            input: work.input_id(),
            publication: publication.commitment(),
        };
        wrong_acknowledgement.publication = Hash([99; 32]);
        assert_eq!(
            execute_guest_accumulate(
                &mut store,
                &AccumulateRequestV2::AcknowledgePublication(wrong_acknowledgement),
            )
            .unwrap(),
            rejected(AccumulationRejectionV2::DivergentDuplicate)
        );
        assert!(store.rows.contains_key(&publication_key));

        let acknowledgement = AccumulateRequestV2::AcknowledgePublication(PublicationAckV2 {
            service: identity(),
            input: work.input_id(),
            publication: publication.commitment(),
        });
        assert_eq!(
            execute_guest_accumulate(&mut store, &acknowledgement).unwrap(),
            AccumulationResultV2::PublicationAcknowledged {
                input: work.input_id(),
                duplicate: false,
            }
        );
        assert!(!store.rows.contains_key(&publication_key));
        assert_eq!(
            execute_guest_accumulate(&mut store, &acknowledgement).unwrap(),
            AccumulationResultV2::PublicationAcknowledged {
                input: work.input_id(),
                duplicate: true,
            }
        );
    }

    #[test]
    fn accumulate_rejects_a_partial_root_tree_import() {
        let mut store = MemStore::default();
        let initial = store.provide_blob(b"before").unwrap();
        let child = ActorId([7; 32]);
        let request = AccumulateRequestV2::Install(ServiceGenesisV2 {
            service: identity(),
            consistency: ConsistencyModeV2::Local,
            actors: vec![
                ActorGenesisV2 {
                    actor: actor(),
                    name: "root".into(),
                    parent: None,
                    program: program(),
                    initial_state: initial.clone(),
                    crdt: false,
                    methods: vec![MethodPolicyV2 {
                        method: "set".into(),
                        schema: Hash([6; 32]),
                        policy: public_policy_hash(),
                        public: true,
                        attested: false,
                    }],
                },
                ActorGenesisV2 {
                    actor: child,
                    name: "child".into(),
                    parent: Some(actor()),
                    program: program(),
                    initial_state: initial.clone(),
                    crdt: false,
                    methods: Vec::new(),
                },
            ],
            authorization: AuthorizationEvidenceV2::SystemCapability {
                capability: super::super::SystemCapabilityId([8; 32]),
                authenticator: vec![9],
            },
        });
        let AccumulationResultV2::Installed(installed) =
            execute_guest_accumulate(&mut store, &request).unwrap()
        else {
            panic!("install rejected")
        };
        let work = linear_work(initial, installed.resulting_state_root.unwrap());
        let transition = linear_transition(&work, b"after");
        let before = store.clone();
        let result = execute_guest_accumulate(
            &mut store,
            &AccumulateRequestV2::Apply(AccumulationEnvelopeV2 {
                work,
                transition,
                provided_blobs: Vec::new(),
            }),
        )
        .unwrap();
        assert_eq!(
            result,
            AccumulationResultV2::Rejected(AccumulationRejectionV2::WrongProgram)
        );
        assert_eq!(store, before, "partial-tree work must stage no writes");
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

    #[test]
    fn disclosed_space_role_credentials_satisfy_generated_thresholds() {
        let mut store = MemStore::default();
        let initial = store.provide_blob(b"before").unwrap();
        let required_policy =
            super::super::space_role_policy_hash(crate::SpaceRole::Member.as_u8()).unwrap();
        let install = AccumulateRequestV2::Install(ServiceGenesisV2 {
            service: identity(),
            consistency: ConsistencyModeV2::Local,
            actors: vec![ActorGenesisV2 {
                actor: actor(),
                name: "root".into(),
                parent: None,
                program: program(),
                initial_state: initial.clone(),
                crdt: false,
                methods: vec![MethodPolicyV2 {
                    method: "set".into(),
                    schema: Hash([6; 32]),
                    policy: required_policy,
                    public: false,
                    attested: false,
                }],
            }],
            authorization: AuthorizationEvidenceV2::SystemCapability {
                capability: super::super::SystemCapabilityId([8; 32]),
                authenticator: vec![9],
            },
        });
        let AccumulationResultV2::Installed(receipt) =
            execute_guest_accumulate(&mut store, &install).unwrap()
        else {
            panic!("install rejected")
        };
        let base = receipt.resulting_state_root.unwrap();
        let origin = super::super::Origin::Member(super::super::SubjectId([40; 32]));

        let developer = SpaceRoleCredentialV2 {
            holder: origin,
            role: crate::SpaceRole::Developer,
            authenticator: b"developer grant".to_vec(),
        };
        let mut admitted_work = linear_work(initial.clone(), base);
        admitted_work.origin = origin;
        admitted_work.authorization = developer.disclosed_evidence(required_policy);
        let admitted = AccumulateRequestV2::Apply(AccumulationEnvelopeV2 {
            transition: linear_transition(&admitted_work, b"admitted"),
            work: admitted_work,
            provided_blobs: vec![],
        });
        let mut admitted_store = store.clone();
        assert!(matches!(
            execute_guest_accumulate(&mut admitted_store, &admitted).unwrap(),
            AccumulationResultV2::Accepted {
                duplicate: false,
                ..
            }
        ));

        let guest = SpaceRoleCredentialV2 {
            holder: origin,
            role: crate::SpaceRole::Guest,
            authenticator: b"guest grant".to_vec(),
        };
        let mut denied_work = linear_work(initial, base);
        denied_work.origin = origin;
        denied_work.authorization = guest.disclosed_evidence(required_policy);
        let denied = AccumulateRequestV2::Apply(AccumulationEnvelopeV2 {
            transition: linear_transition(&denied_work, b"denied"),
            work: denied_work,
            provided_blobs: vec![],
        });
        let before = store.clone();
        assert_eq!(
            execute_guest_accumulate(&mut store, &denied).unwrap(),
            rejected(AccumulationRejectionV2::Unauthorized)
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
            suspended_actors: vec![first_work.target],
            kernel_snapshot: vec![1],
        }
        .encode();
        let continuation = BlobRefV2::of_bytes(&continuation_bytes);
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
        let wrong = BlobRefV2::of_bytes(&wrong_bytes);
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
                    provided_blobs: vec![ImportedBlobV2 {
                        reference: wrong,
                        bytes: wrong_bytes,
                    }],
                }),
            )
            .unwrap(),
            rejected(AccumulationRejectionV2::InvalidWorkflowTransition)
        );
        assert_eq!(store, before_wrong);

        let first = execute_guest_accumulate(
            &mut store,
            &AccumulateRequestV2::Apply(AccumulationEnvelopeV2 {
                work: first_work.clone(),
                transition: checkpoint,
                provided_blobs: vec![ImportedBlobV2 {
                    reference: continuation.clone(),
                    bytes: continuation_bytes,
                }],
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

        let mut changed_origin = resume.clone();
        changed_origin.origin = Origin::Actor(ActorId([99; 32]));
        let before = store.clone();
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
                    provided_blobs: vec![],
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
                    provided_blobs: vec![],
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
                    provided_blobs: vec![],
                }),
            )
            .unwrap(),
            AccumulationResultV2::Accepted {
                duplicate: false,
                ..
            }
        ));
    }

    #[test]
    fn awaited_reply_requires_a_finalized_receipt_and_consumes_the_outbox() {
        let mut store = MemStore::default();
        let (initial, install) = install_fixture(&mut store, ConsistencyModeV2::Local, b"before");
        let first_work = linear_work(initial, install.resulting_state_root.unwrap());
        let peer = ActorId([44; 32]);
        let call = first_work.invocation.call_id(0);
        let mut payload = vec![crate::value::TAG_DYNAMIC];
        payload.extend_from_slice(&crate::Encode::encode(&crate::value::Msg::new("set")));
        let outbound = MessageRecordV2 {
            call_id: call,
            caller_invocation: first_work.invocation,
            await_ordinal: 0,
            from: first_work.target,
            to: peer,
            parent: None,
            payload,
            authorization: AuthorizationEvidenceV2::Public,
            proof_requested: false,
            deadline_timeslot: Some(10),
        };
        let continuation_bytes = ContinuationSnapshotV2 {
            snapshot_version: super::super::SNAPSHOT_VERSION,
            jar_semantics: super::super::EXECUTION_SEMANTICS_ID,
            vos_abi: super::super::ABI_VERSION,
            service: first_work.service.clone(),
            invocation: first_work.invocation,
            checkpoint_step: 0,
            actor: first_work.target,
            actor_program: first_work.target_program,
            await_ordinal: 0,
            pending_call: Some(call),
            suspended_actors: vec![first_work.target],
            kernel_snapshot: vec![1],
        }
        .encode();
        let continuation = BlobRefV2::of_bytes(&continuation_bytes);
        let mut checkpoint = linear_transition(&first_work, b"checkpoint");
        checkpoint.reply = None;
        checkpoint.continuations.push(ContinuationChangeV2 {
            actor: first_work.target,
            expected: None,
            replacement: Some(continuation.clone()),
        });
        checkpoint.outbox.push(outbound);
        checkpoint.exported_blobs.push(continuation.clone());
        let first = execute_guest_accumulate(
            &mut store,
            &AccumulateRequestV2::Apply(AccumulationEnvelopeV2 {
                work: first_work.clone(),
                transition: checkpoint,
                provided_blobs: vec![ImportedBlobV2 {
                    reference: continuation.clone(),
                    bytes: continuation_bytes,
                }],
            }),
        )
        .unwrap();
        let AccumulationResultV2::Accepted { receipt, .. } = first else {
            panic!("await checkpoint rejected")
        };

        let remote_reply = ReplyRecordV2 {
            call_id: call,
            producer: peer,
            result: b"peer result".to_vec(),
        };
        let mut remote_service = first_work.service.clone();
        remote_service.root_service = super::super::RootServiceId([45; 32]);
        remote_service.deployment = super::super::DeploymentId([46; 32]);
        let remote_receipt = AccumulationReceiptV2 {
            service: remote_service,
            accepted_transition: Hash([47; 32]),
            reply_commitment: Some(remote_reply.commitment()),
            outbox_commitment: None,
            resulting_state_root: Some(Hash([48; 32])),
            resulting_crdt_heads: vec![],
            sequence: 3,
            checkpoint: 0,
            consistency: ConsistencyModeV2::Local,
        };
        let awaited = super::super::AccumulatedReplyV2 {
            reply: remote_reply,
            receipt: remote_receipt,
            attestation: None,
        };
        let mut resume = first_work;
        resume.workflow_step = 1;
        resume.logical_timeslot = 2;
        resume.base = ConsistencyBaseV2::Linear {
            revision: receipt.sequence,
            state_root: receipt.resulting_state_root.unwrap(),
        };
        resume.imported_actors[0].state = BlobRefV2::of_bytes(b"checkpoint");
        resume.imported_actors[0].continuation = Some(continuation.clone());
        resume.awaited_reply = Some(awaited.clone());
        let mut completed = linear_transition(&resume, b"done");
        completed.continuations.push(ContinuationChangeV2 {
            actor: resume.target,
            expected: Some(continuation.hash),
            replacement: None,
        });

        let mut wrong_producer = resume.clone();
        let wrong = wrong_producer.awaited_reply.as_mut().unwrap();
        wrong.reply.producer = ActorId([49; 32]);
        wrong.receipt.reply_commitment = Some(wrong.reply.commitment());
        let before = store.clone();
        assert_eq!(
            execute_guest_accumulate(
                &mut store,
                &AccumulateRequestV2::Apply(AccumulationEnvelopeV2 {
                    work: wrong_producer,
                    transition: completed.clone(),
                    provided_blobs: vec![],
                }),
            )
            .unwrap(),
            rejected(AccumulationRejectionV2::InvalidReceipt)
        );
        assert_eq!(store, before);

        assert_eq!(
            execute_guest_accumulate(
                &mut store,
                &AccumulateRequestV2::Apply(AccumulationEnvelopeV2 {
                    work: resume.clone(),
                    transition: completed.clone(),
                    provided_blobs: vec![],
                }),
            )
            .unwrap(),
            rejected(AccumulationRejectionV2::ReceiptUnavailable)
        );
        assert_eq!(store, before);

        let request = ReceiptVerificationRequestV2 {
            receipt: awaited.receipt,
        };
        store.receipt_allowlist.insert(request.hash());
        assert!(matches!(
            execute_guest_accumulate(
                &mut store,
                &AccumulateRequestV2::Apply(AccumulationEnvelopeV2 {
                    work: resume,
                    transition: completed,
                    provided_blobs: vec![],
                }),
            )
            .unwrap(),
            AccumulationResultV2::Accepted {
                duplicate: false,
                ..
            }
        ));
        let header = StoreHeaderV2::open(store.rows.get(header_storage_key()).unwrap()).unwrap();
        let tree = ServiceStateTreeV2::new(&mut store, header.service_root);
        assert_eq!(tree.get(&StateKeyV2::Outbox(call)).unwrap(), None);
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
            proof_requested: false,
            deadline_timeslot,
        }
    }

    fn source_receipt(outbox: &[MessageRecordV2]) -> AccumulationReceiptV2 {
        let mut service = identity();
        service.root_service = RootServiceId([90; 32]);
        service.deployment = DeploymentId([91; 32]);
        AccumulationReceiptV2 {
            service,
            accepted_transition: Hash([92; 32]),
            reply_commitment: None,
            outbox_commitment: MessageRecordV2::outbox_commitment(outbox),
            resulting_state_root: Some(Hash([93; 32])),
            resulting_crdt_heads: vec![],
            sequence: 7,
            checkpoint: 0,
            consistency: ConsistencyModeV2::Local,
        }
    }

    fn delivery(
        header: &StoreHeaderV2,
        message: MessageRecordV2,
        source_receipt: AccumulationReceiptV2,
    ) -> DeliveryEnvelopeV2 {
        let source_outbox = vec![message.clone()];
        let base = if header.consistency == ConsistencyModeV2::Crdt {
            ConsistencyBaseV2::Crdt {
                heads: header.crdt_heads.clone(),
            }
        } else {
            ConsistencyBaseV2::Linear {
                revision: header.revision,
                state_root: header.state_root.unwrap(),
            }
        };
        let base_causal_height = (header.consistency == ConsistencyModeV2::Crdt).then_some(0);
        let crdt_change = match &base {
            ConsistencyBaseV2::Crdt { heads } => Some(CrdtChangeV2 {
                id: CrdtChangeV2::derive_delivery_id(&header.service, message.call_id, heads),
                causal_dependencies: heads.clone(),
                causal_height: base_causal_height.unwrap() + 1,
                operations: vec![],
                workflow: vec![super::super::WorkflowOperationV2::Inbox(message.clone())],
                materializations: vec![],
            }),
            ConsistencyBaseV2::Linear { .. } => None,
        };
        DeliveryEnvelopeV2 {
            service: header.service.clone(),
            logical_timeslot: 2,
            base,
            base_causal_height,
            message,
            source_outbox,
            source_receipt,
            crdt_change,
        }
    }

    #[test]
    fn finalized_cross_root_delivery_is_guest_owned_atomic_and_deduplicated() {
        let mut store = MemStore::default();
        install_fixture(&mut store, ConsistencyModeV2::Local, b"before");
        let header = StoreHeaderV2::open(store.rows.get(header_storage_key()).unwrap()).unwrap();
        let incoming = message(70, ActorId([71; 32]), actor(), None, Some(10));
        let outbox = vec![incoming.clone()];
        let source_receipt = source_receipt(&outbox);
        let envelope = delivery(&header, incoming.clone(), source_receipt.clone());
        let request = AccumulateRequestV2::Deliver(envelope.clone());

        let before = store.clone();
        assert_eq!(
            execute_guest_accumulate(&mut store, &request).unwrap(),
            rejected(AccumulationRejectionV2::ReceiptUnavailable)
        );
        assert_eq!(store, before);

        store.receipt_allowlist.insert(
            ReceiptVerificationRequestV2 {
                receipt: source_receipt,
            }
            .hash(),
        );
        let mut stale = envelope.clone();
        let ConsistencyBaseV2::Linear { revision, .. } = &mut stale.base else {
            unreachable!()
        };
        *revision += 1;
        let before_stale = store.clone();
        assert_eq!(
            execute_guest_accumulate(&mut store, &AccumulateRequestV2::Deliver(stale)).unwrap(),
            rejected(AccumulationRejectionV2::StaleLinearWork {
                expected_revision: 1,
                actual_revision: 0,
            })
        );
        assert_eq!(store, before_stale);

        let mut tampered = envelope.clone();
        tampered.source_outbox[0].payload.push(0);
        assert_eq!(
            execute_guest_accumulate(&mut store, &AccumulateRequestV2::Deliver(tampered)).unwrap(),
            rejected(AccumulationRejectionV2::NonCanonical)
        );
        assert_eq!(store, before_stale);

        let accepted = execute_guest_accumulate(&mut store, &request).unwrap();
        let AccumulationResultV2::Accepted {
            receipt,
            published,
            duplicate: false,
        } = accepted
        else {
            panic!("finalized delivery was rejected")
        };
        assert_eq!(receipt.accepted_transition, envelope.commitment());
        assert_eq!(receipt.sequence, 1);
        assert_eq!(published, PublishedEffectsV2::default());
        let committed = StoreHeaderV2::open(store.rows.get(header_storage_key()).unwrap()).unwrap();
        let tree = ServiceStateTreeV2::new(&mut store, committed.service_root);
        assert_eq!(
            tree.get(&StateKeyV2::Inbox(incoming.call_id)).unwrap(),
            Some(incoming.encode())
        );
        drop(tree);

        assert!(matches!(
            execute_guest_accumulate(&mut store, &request).unwrap(),
            AccumulationResultV2::Accepted {
                duplicate: true,
                published,
                ..
            } if published == PublishedEffectsV2::default()
        ));
        let after_duplicate =
            StoreHeaderV2::open(store.rows.get(header_storage_key()).unwrap()).unwrap();
        assert_eq!(after_duplicate, committed);

        let mut divergent = envelope;
        divergent.logical_timeslot += 1;
        assert_eq!(
            execute_guest_accumulate(&mut store, &AccumulateRequestV2::Deliver(divergent),)
                .unwrap(),
            rejected(AccumulationRejectionV2::DivergentDuplicate)
        );
    }

    #[test]
    fn cross_root_delivery_is_a_workflow_crdt_change() {
        let mut store = MemStore::default();
        install_fixture(&mut store, ConsistencyModeV2::Crdt, b"before");
        let header = StoreHeaderV2::open(store.rows.get(header_storage_key()).unwrap()).unwrap();
        let incoming = message(72, ActorId([73; 32]), actor(), None, None);
        let outbox = vec![incoming.clone()];
        let source_receipt = source_receipt(&outbox);
        store.receipt_allowlist.insert(
            ReceiptVerificationRequestV2 {
                receipt: source_receipt.clone(),
            }
            .hash(),
        );
        let envelope = delivery(&header, incoming.clone(), source_receipt);
        let change = envelope.crdt_change.clone().unwrap();
        let accepted =
            execute_guest_accumulate(&mut store, &AccumulateRequestV2::Deliver(envelope)).unwrap();
        let AccumulationResultV2::Accepted {
            receipt,
            duplicate: false,
            ..
        } = accepted
        else {
            panic!("CRDT delivery was rejected")
        };
        assert_eq!(receipt.resulting_crdt_heads, vec![change.cid()]);
        assert_eq!(receipt.sequence, 1);
        assert_eq!(
            store.rows.get(&crdt_node_storage_key(change.cid())),
            Some(&change.encode())
        );
        let committed = StoreHeaderV2::open(store.rows.get(header_storage_key()).unwrap()).unwrap();
        let tree = ServiceStateTreeV2::new(&mut store, committed.service_root);
        assert_eq!(
            tree.get(&StateKeyV2::Inbox(incoming.call_id)).unwrap(),
            Some(incoming.encode())
        );
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
                work: inbox_work.clone(),
                provided_blobs: vec![],
            }),
        )
        .unwrap();
        assert!(matches!(delivered, AccumulationResultV2::Accepted { .. }));
        let delivered_header =
            StoreHeaderV2::open(installed.rows.get(header_storage_key()).unwrap()).unwrap();
        let delivered_tree = ServiceStateTreeV2::new(&mut installed, delivered_header.service_root);
        assert_eq!(
            delivered_tree
                .get(&StateKeyV2::Inbox(incoming.call_id))
                .unwrap(),
            None,
            "accepted delivery consumes its durable inbox row atomically"
        );
        assert!(matches!(
            execute_guest_accumulate(
                &mut installed,
                &AccumulateRequestV2::Apply(AccumulationEnvelopeV2 {
                    transition: linear_transition(&inbox_work, b"delivered"),
                    work: inbox_work,
                    provided_blobs: vec![],
                }),
            )
            .unwrap(),
            AccumulationResultV2::Accepted {
                duplicate: true,
                ..
            }
        ));

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
            awaited_reply: None,
            consistency: ConsistencyModeV2::Crdt,
            base: ConsistencyBaseV2::Crdt { heads },
            base_causal_height,
            imported_actors: vec![ImportedActorV2 {
                actor: actor(),
                name: "root".into(),
                parent: None,
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
        let workflow = transition.workflow_operations(&work);
        transition.crdt_change.as_mut().unwrap().workflow = workflow;
        transition
    }

    #[test]
    fn workflow_dag_reconstructs_an_awaited_outbox_consumption() {
        let initial = BlobRefV2::of_bytes(b"initial");
        let first_state = BlobRefV2::of_bytes(b"checkpoint");
        let first_work = crdt_work(initial, 19, vec![]);
        let call = first_work.invocation.call_id(0);
        let mut first = crdt_transition(&first_work, first_state.clone(), 1);
        first.outbox.push(MessageRecordV2 {
            call_id: call,
            caller_invocation: first_work.invocation,
            await_ordinal: 0,
            from: actor(),
            to: ActorId([44; 32]),
            parent: None,
            payload: vec![1],
            authorization: AuthorizationEvidenceV2::Public,
            proof_requested: false,
            deadline_timeslot: None,
        });
        let workflow = first.workflow_operations(&first_work);
        first.crdt_change.as_mut().unwrap().workflow = workflow;
        let first_change = first.crdt_change.unwrap();
        let first_cid = first_change.cid();

        let mut resumed_work = first_work;
        resumed_work.workflow_step = 1;
        resumed_work.base = ConsistencyBaseV2::Crdt {
            heads: vec![first_cid],
        };
        resumed_work.base_causal_height = Some(1);
        resumed_work.imported_actors[0].state = first_state;
        let mut resumed = crdt_transition(&resumed_work, BlobRefV2::of_bytes(b"done"), 2);
        let workflow = resumed.workflow_operations_with_consumed_outbox(&resumed_work, Some(call));
        resumed.crdt_change.as_mut().unwrap().workflow = workflow;
        let resumed_change = resumed.crdt_change.unwrap();
        assert!(
            resumed_change
                .workflow
                .contains(&WorkflowOperationV2::ConsumeOutbox(call))
        );
        let resumed_cid = resumed_change.cid();

        let nodes = BTreeMap::from([
            (first_cid, first_change.encode()),
            (resumed_cid, resumed_change.encode()),
        ]);
        let frontier = load_causal_frontier(&[resumed_cid], |cid| {
            Ok::<_, Infallible>(nodes.get(&cid).cloned())
        })
        .unwrap();
        let materialized = materialize_workflow_crdt(&frontier, &identity()).unwrap();
        assert_eq!(materialized.outbox[&call].len(), 1);
        assert!(materialized.outbox[&call][0].value.is_none());
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
    fn concurrent_crdt_commit_order_converges_the_guest_service_root() {
        let mut left_first = MemStore::default();
        let mut right_first = MemStore::default();
        let (initial, _) = install_fixture(&mut left_first, ConsistencyModeV2::Crdt, b"before");
        install_fixture(&mut right_first, ConsistencyModeV2::Crdt, b"before");

        let left_work = crdt_work(initial.clone(), 70, vec![]);
        let right_work = crdt_work(initial, 71, vec![]);
        let left_state = BlobRefV2::of_bytes(b"left-branch");
        let right_state = BlobRefV2::of_bytes(b"right-branch");
        let left = AccumulateRequestV2::Apply(AccumulationEnvelopeV2 {
            work: left_work.clone(),
            transition: crdt_transition(&left_work, left_state.clone(), 1),
            provided_blobs: vec![ImportedBlobV2 {
                reference: left_state,
                bytes: b"left-branch".to_vec(),
            }],
        });
        let right = AccumulateRequestV2::Apply(AccumulationEnvelopeV2 {
            work: right_work.clone(),
            transition: crdt_transition(&right_work, right_state.clone(), 1),
            provided_blobs: vec![ImportedBlobV2 {
                reference: right_state,
                bytes: b"right-branch".to_vec(),
            }],
        });
        for request in [&left, &right] {
            assert!(matches!(
                execute_guest_accumulate(&mut left_first, request).unwrap(),
                AccumulationResultV2::Accepted {
                    duplicate: false,
                    ..
                }
            ));
        }
        for request in [&right, &left] {
            assert!(matches!(
                execute_guest_accumulate(&mut right_first, request).unwrap(),
                AccumulationResultV2::Accepted {
                    duplicate: false,
                    ..
                }
            ));
        }
        let left_header =
            StoreHeaderV2::open(left_first.rows.get(header_storage_key()).unwrap()).unwrap();
        let right_header =
            StoreHeaderV2::open(right_first.rows.get(header_storage_key()).unwrap()).unwrap();
        assert_eq!(left_header.crdt_heads, right_header.crdt_heads);
        assert_eq!(left_header.service_root, right_header.service_root);
    }

    #[test]
    fn every_three_replica_sync_order_converges() {
        let mut envelopes = Vec::new();
        for (invocation, state_bytes) in [
            (80, b"alice".as_slice()),
            (81, b"bob".as_slice()),
            (82, b"carol".as_slice()),
        ] {
            let mut source = MemStore::default();
            let (initial, _) = install_fixture(&mut source, ConsistencyModeV2::Crdt, b"before");
            let work = crdt_work(initial, invocation, vec![]);
            let materialized = BlobRefV2::of_bytes(state_bytes);
            let transition = crdt_transition(&work, materialized.clone(), 1);
            let change = transition.crdt_change.clone().unwrap();
            let accepted = execute_guest_accumulate(
                &mut source,
                &AccumulateRequestV2::Apply(AccumulationEnvelopeV2 {
                    work,
                    transition,
                    provided_blobs: vec![ImportedBlobV2 {
                        reference: materialized.clone(),
                        bytes: state_bytes.to_vec(),
                    }],
                }),
            )
            .unwrap();
            let AccumulationResultV2::Accepted { receipt, .. } = accepted else {
                panic!("source branch was rejected")
            };
            envelopes.push(CrdtSyncEnvelopeV2 {
                service: identity(),
                advertised_heads: vec![change.cid()],
                nodes: vec![super::super::CrdtSyncNodeV2 { change, receipt }],
                provided_blobs: vec![ImportedBlobV2 {
                    reference: materialized,
                    bytes: state_bytes.to_vec(),
                }],
            });
        }

        let orders = [
            [0, 1, 2],
            [0, 2, 1],
            [1, 0, 2],
            [1, 2, 0],
            [2, 0, 1],
            [2, 1, 0],
        ];
        let mut expected = None;
        for order in orders {
            let mut replica = MemStore::default();
            install_fixture(&mut replica, ConsistencyModeV2::Crdt, b"before");
            for envelope in &envelopes {
                replica.receipt_allowlist.insert(
                    ReceiptVerificationRequestV2 {
                        receipt: envelope.nodes[0].receipt.clone(),
                    }
                    .hash(),
                );
            }
            for index in order {
                assert!(matches!(
                    execute_guest_accumulate(
                        &mut replica,
                        &AccumulateRequestV2::SyncCrdt(envelopes[index].clone()),
                    )
                    .unwrap(),
                    AccumulationResultV2::Accepted {
                        duplicate: false,
                        ..
                    }
                ));
            }
            let header =
                StoreHeaderV2::open(replica.rows.get(header_storage_key()).unwrap()).unwrap();
            assert_eq!(header.crdt_heads.len(), 3);
            match expected {
                None => expected = Some((header.crdt_heads, header.service_root)),
                Some((ref heads, root)) => {
                    assert_eq!(&header.crdt_heads, heads);
                    assert_eq!(header.service_root, root);
                }
            }
        }
    }

    #[test]
    fn sync_rejects_divergent_results_for_the_same_workflow_step() {
        let mut destination = MemStore::default();
        let (initial, _) = install_fixture(&mut destination, ConsistencyModeV2::Crdt, b"before");
        let work = crdt_work(initial, 83, vec![]);
        let mut nodes = [b"left".as_slice(), b"right".as_slice()]
            .into_iter()
            .enumerate()
            .map(|(index, bytes)| {
                let state = BlobRefV2::of_bytes(bytes);
                let change = crdt_transition(&work, state.clone(), 1)
                    .crdt_change
                    .unwrap();
                let cid = change.cid();
                let receipt = AccumulationReceiptV2 {
                    service: identity(),
                    accepted_transition: Hash([90 + index as u8; 32]),
                    reply_commitment: None,
                    outbox_commitment: None,
                    resulting_state_root: None,
                    resulting_crdt_heads: vec![cid],
                    sequence: 1,
                    checkpoint: 0,
                    consistency: ConsistencyModeV2::Crdt,
                };
                (
                    super::super::CrdtSyncNodeV2 { change, receipt },
                    ImportedBlobV2 {
                        reference: state,
                        bytes: bytes.to_vec(),
                    },
                )
            })
            .collect::<Vec<_>>();
        nodes.sort_by_key(|(node, _)| node.change.cid());
        let mut advertised_heads = nodes
            .iter()
            .map(|(node, _)| node.change.cid())
            .collect::<Vec<_>>();
        advertised_heads.sort();
        let mut provided_blobs = nodes
            .iter()
            .map(|(_, blob)| blob.clone())
            .collect::<Vec<_>>();
        provided_blobs.sort_by_key(|blob| blob.reference.hash);
        for (node, _) in &nodes {
            destination.receipt_allowlist.insert(
                ReceiptVerificationRequestV2 {
                    receipt: node.receipt.clone(),
                }
                .hash(),
            );
        }
        let envelope = CrdtSyncEnvelopeV2 {
            service: identity(),
            advertised_heads,
            nodes: nodes.into_iter().map(|(node, _)| node).collect(),
            provided_blobs,
        };
        let before = destination.clone();
        assert_eq!(
            execute_guest_accumulate(&mut destination, &AccumulateRequestV2::SyncCrdt(envelope),)
                .unwrap(),
            rejected(AccumulationRejectionV2::DivergentDuplicate)
        );
        assert_eq!(destination, before);
    }

    #[test]
    fn guest_sync_authenticates_nodes_and_reconstructs_workflow_rows() {
        let mut source = MemStore::default();
        let mut destination = MemStore::default();
        let (initial, _) = install_fixture(&mut source, ConsistencyModeV2::Crdt, b"before");
        install_fixture(&mut destination, ConsistencyModeV2::Crdt, b"before");

        let work = crdt_work(initial, 61, vec![]);
        let materialized = BlobRefV2::of_bytes(b"synced-state");
        let transition = crdt_transition(&work, materialized.clone(), 1);
        let change = transition.crdt_change.clone().unwrap();
        let cid = change.cid();
        let accepted = execute_guest_accumulate(
            &mut source,
            &AccumulateRequestV2::Apply(AccumulationEnvelopeV2 {
                work: work.clone(),
                transition,
                provided_blobs: vec![ImportedBlobV2 {
                    reference: materialized.clone(),
                    bytes: b"synced-state".to_vec(),
                }],
            }),
        )
        .unwrap();
        let AccumulationResultV2::Accepted { receipt, .. } = accepted else {
            panic!("source CRDT transition was rejected")
        };
        let sync = CrdtSyncEnvelopeV2 {
            service: identity(),
            advertised_heads: vec![cid],
            nodes: vec![super::super::CrdtSyncNodeV2 {
                change,
                receipt: receipt.clone(),
            }],
            provided_blobs: vec![ImportedBlobV2 {
                reference: materialized.clone(),
                bytes: b"synced-state".to_vec(),
            }],
        };

        let before = destination.clone();
        assert_eq!(
            execute_guest_accumulate(
                &mut destination,
                &AccumulateRequestV2::SyncCrdt(sync.clone()),
            )
            .unwrap(),
            rejected(AccumulationRejectionV2::ReceiptUnavailable)
        );
        assert_eq!(destination, before);

        destination.receipt_allowlist.insert(
            ReceiptVerificationRequestV2 {
                receipt: receipt.clone(),
            }
            .hash(),
        );
        let synced = execute_guest_accumulate(
            &mut destination,
            &AccumulateRequestV2::SyncCrdt(sync.clone()),
        )
        .unwrap();
        assert!(matches!(
            synced,
            AccumulationResultV2::Accepted {
                duplicate: false,
                ..
            }
        ));
        let header =
            StoreHeaderV2::open(destination.rows.get(header_storage_key()).unwrap()).unwrap();
        assert_eq!(header.crdt_heads, vec![cid]);
        assert_eq!(
            destination.blobs.get(&materialized.hash),
            Some(&b"synced-state".to_vec())
        );
        let tree = ServiceStateTreeV2::new(&mut destination, header.service_root);
        let checkpoint = WorkflowCheckpointV2::decode(
            &tree
                .get(&StateKeyV2::Workflow(work.invocation))
                .unwrap()
                .unwrap(),
        )
        .unwrap();
        assert_eq!(checkpoint.resume_work, work.workflow_checkpoint());
        assert_eq!(checkpoint.transition_commitment, cid);
        assert_eq!(
            BlobRefV2::decode(
                &tree
                    .get(&StateKeyV2::CrdtMaterialization(actor()))
                    .unwrap()
                    .unwrap(),
            )
            .unwrap(),
            materialized
        );
        drop(tree);

        let snapshot = destination.clone();
        assert!(matches!(
            execute_guest_accumulate(&mut destination, &AccumulateRequestV2::SyncCrdt(sync))
                .unwrap(),
            AccumulationResultV2::Accepted {
                duplicate: true,
                ..
            }
        ));
        assert_eq!(destination, snapshot);

        let missing_parent = Hash([99; 32]);
        let mut child_work = crdt_work(materialized, 62, vec![missing_parent]);
        child_work.base_causal_height = Some(1);
        let child_state = BlobRefV2::of_bytes(b"unavailable-child");
        let child = crdt_transition(&child_work, child_state.clone(), 2)
            .crdt_change
            .unwrap();
        let child_cid = child.cid();
        let child_receipt = AccumulationReceiptV2 {
            service: identity(),
            accepted_transition: Hash([98; 32]),
            reply_commitment: None,
            outbox_commitment: None,
            resulting_state_root: None,
            resulting_crdt_heads: vec![child_cid],
            sequence: 2,
            checkpoint: 0,
            consistency: ConsistencyModeV2::Crdt,
        };
        destination.receipt_allowlist.insert(
            ReceiptVerificationRequestV2 {
                receipt: child_receipt.clone(),
            }
            .hash(),
        );
        let incomplete = CrdtSyncEnvelopeV2 {
            service: identity(),
            advertised_heads: vec![child_cid],
            nodes: vec![super::super::CrdtSyncNodeV2 {
                change: child,
                receipt: child_receipt,
            }],
            provided_blobs: vec![ImportedBlobV2 {
                reference: child_state,
                bytes: b"unavailable-child".to_vec(),
            }],
        };
        let before_incomplete = destination.clone();
        assert_eq!(
            execute_guest_accumulate(&mut destination, &AccumulateRequestV2::SyncCrdt(incomplete),)
                .unwrap(),
            rejected(AccumulationRejectionV2::MissingCausalDependency(
                missing_parent,
            ))
        );
        assert_eq!(destination, before_incomplete);
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
