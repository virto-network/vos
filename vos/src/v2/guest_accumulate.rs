//! Consensus Accumulate implementation executed by the generic service guest.
//!
//! The store passed here is one invocation-scoped JAM transaction: writes are
//! visible to later reads, but the host publishes none of them unless the
//! physical IC-5 entry halts successfully. Storage errors are therefore fatal
//! rather than encoded rejections; trapping makes the host discard staging.

use alloc::boxed::Box;
use alloc::collections::{BTreeMap, BTreeSet};
use alloc::vec::Vec;

use crate::attestation::AttestationPreparationV2;

use super::causal::{
    CausalFrontierError, CausalFrontierV2, CausalSelectionError, load_causal_frontier,
};
use super::contracts::crdt_change_blob_references;
use super::{
    ABI_VERSION, AccumulateRequestV2, AccumulatedTimeoutV2, AccumulationEnvelopeV2,
    AccumulationReceiptV2, AccumulationRejectionV2, AccumulationResultV2, ActorGenesisV2, ActorId,
    ActorUpgradeRecordV2, ActorUpgradeV2, AuthorizationEvidenceV2, AwaitResumeV2, BlobRefV2,
    CHECKPOINT_TOKEN_CAPACITY, CallExpirationEnvelopeV2, CallTimeoutV2, CheckpointTokenV2,
    ConsistencyBaseV2, ConsistencyModeV2, ContinuationSnapshotV2, CrdtChangeV2, CrdtDispatchV2,
    CrdtSyncEnvelopeV2, DedupRecordV2, DeliveryEnvelopeV2, DeliveryRecordV2, DirectIngressV2,
    EXECUTION_SEMANTICS_ID, ExternalActorDirectoryV2, Hash, IngressRecordV2, MessageRecordV2,
    MethodPolicyV2, PendingCallDeadlineV2, ProgramId, ProofVerificationRequestV2, PublicationAckV2,
    PublicationRecordV2, PublishedEffectsV2, ReceiptVerificationRequestV2, ReplyAdmissionRecordV2,
    RoleCredentialV2, RoleCredentialVerificationRequestV2, ServiceGenesisV2,
    ServiceInstallReceiptV2, ServiceStateTreeV2, StateKeyV2, StateTreeError, StateTreeStore,
    StoreHeaderV2, StoreOpenError, V2Wire, WorkInputIdV2, WorkflowCheckpointV2,
    WorkflowOperationV2, actor_upgrade_storage_key, call_expiration_storage_key,
    crdt_change_storage_key, crdt_node_receipt_storage_key, crdt_node_storage_key,
    dedup_storage_key, delivery_storage_key, header_storage_key, ingress_storage_key,
    method_role_policy_hash, pending_call_deadline_storage_key, public_policy_hash,
    publication_storage_key, receipt_storage_key, reply_admission_storage_key,
};

/// Extra content-addressed operations needed by guest Accumulate in addition
/// to ordinary JAM service storage.
pub trait GuestAccumulateStoreV2: StateTreeStore {
    /// Consensus-authenticated ambient JAM slot for this Accumulate
    /// invocation. `None` means time-dependent transitions are unavailable.
    fn logical_timeslot(&self) -> Result<Option<u64>, Self::Error>;

    /// Authenticate the exact initial service tree and its supplied evidence
    /// against platform deployment authority before a header exists.
    fn authorize_install(&self, genesis: &ServiceGenesisV2) -> Result<bool, Self::Error>;

    /// Authenticate one exact program/policy replacement against platform
    /// package authority. A successful host response also asserts that the
    /// replacement canonical PVM bytes are available by `ProgramId`.
    fn authorize_upgrade(&self, upgrade: &ActorUpgradeV2) -> Result<bool, Self::Error>;

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

    /// Validate the proof against the exact public inputs derived by guest
    /// Accumulate. Implementations must fail closed when the verifier or proof
    /// blob is unavailable.
    fn verify_proof(
        &self,
        request: &ProofVerificationRequestV2,
    ) -> Result<ProofVerificationV2, Self::Error>;

    /// Verify the authority authenticator on one disclosed role credential.
    /// The request is bound to the exact service, actor, policy, and
    /// invocation-specific scope checked again by guest Accumulate.
    fn verify_role_credential(
        &self,
        request: &RoleCredentialVerificationRequestV2,
    ) -> Result<bool, Self::Error>;

    /// Validate that an external accumulation receipt is finalized and that
    /// its service owns `request.expected_producer`.
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
    execute_canonical_guest_accumulate(store, &request)
}

/// Execute a request already accepted by the canonical v2 wire decoder.
///
/// The service guest owns that decoded value and transfers it here directly,
/// avoiding a second full request allocation inside its bounded PVM heap.
#[doc(hidden)]
pub fn execute_canonical_guest_accumulate<S: GuestAccumulateStoreV2>(
    store: &mut S,
    request: &AccumulateRequestV2,
) -> GuestResult<AccumulationResultV2, S::Error> {
    match request {
        AccumulateRequestV2::Install(genesis) => install(store, genesis),
        AccumulateRequestV2::AdmitIngress(ingress) => admit_ingress(store, ingress),
        AccumulateRequestV2::Apply(envelope) => apply(store, envelope, ApplyMode::Commit),
        AccumulateRequestV2::PrepareAttested(envelope) => {
            apply(store, envelope, ApplyMode::PrepareAttested)
        }
        AccumulateRequestV2::Deliver(envelope) => deliver(store, envelope),
        AccumulateRequestV2::ExpireCall(envelope) => expire_call(store, envelope),
        AccumulateRequestV2::AcknowledgePublication(acknowledgement) => {
            acknowledge_publication(store, acknowledgement)
        }
        AccumulateRequestV2::SyncCrdt(envelope) => sync_crdt(store, envelope),
        AccumulateRequestV2::UpgradeActor(upgrade) => upgrade_actor(store, upgrade),
    }
}

#[inline(never)]
fn upgrade_actor<S: GuestAccumulateStoreV2>(
    store: &mut S,
    upgrade: &ActorUpgradeV2,
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
    if upgrade.service != header.service {
        return Ok(rejected(AccumulationRejectionV2::WrongService));
    }
    if header.service.service_abi != ABI_VERSION {
        return Ok(rejected(AccumulationRejectionV2::WrongAbi));
    }
    if header.service.execution_semantics != EXECUTION_SEMANTICS_ID {
        return Ok(rejected(AccumulationRejectionV2::WrongExecutionSemantics));
    }
    if header.consistency == ConsistencyModeV2::Crdt
        || !matches!(&upgrade.base, ConsistencyBaseV2::Linear { .. })
        || !upgrade.base.mode_compatible(header.consistency)
    {
        // Program metadata needs its own causal operation before CRDT peers
        // can merge upgrades safely. Linear services use exact-base commit.
        return Ok(rejected(AccumulationRejectionV2::InvalidConsistency));
    }
    if !store
        .authorize_upgrade(upgrade)
        .map_err(GuestAccumulateError::Storage)?
    {
        return Ok(rejected(AccumulationRejectionV2::Unauthorized));
    }
    let upgrade_hash = upgrade.hash();
    let upgrade_key = actor_upgrade_storage_key(upgrade_hash);
    if let Some(bytes) = read(store, &upgrade_key)? {
        let record =
            ActorUpgradeRecordV2::decode(&bytes).map_err(|_| GuestAccumulateError::CorruptStore)?;
        if record.upgrade != upgrade_hash
            || record.actor != upgrade.actor
            || record.previous_deployment != upgrade.expected_deployment
            || record.previous_program != upgrade.expected_program
            || record.deployment != upgrade.replacement_deployment
            || record.program != upgrade.replacement_program
            || record.receipt.service != header.service
        {
            return Ok(rejected(AccumulationRejectionV2::DivergentDuplicate));
        }
        return Ok(AccumulationResultV2::ActorUpgraded {
            actor: record.actor,
            previous_deployment: record.previous_deployment,
            previous_program: record.previous_program,
            deployment: record.deployment,
            program: record.program,
            receipt: record.receipt,
            duplicate: true,
        });
    }
    if let Some(rejection) = validate_base(store, &header, &upgrade.base)? {
        return Ok(rejected(rejection));
    }
    if header.revision == u64::MAX {
        return Ok(rejected(AccumulationRejectionV2::SequenceOverflow));
    }

    let mut tree = ServiceStateTreeV2::new(store, header.service_root);
    let Some(directory) =
        tree_get_wire::<_, super::ActorDirectoryV2>(&tree, &StateKeyV2::ActorDirectory)?
    else {
        return Err(GuestAccumulateError::CorruptStore);
    };
    let Some(mut descriptor) =
        tree_get_wire::<_, ActorGenesisV2>(&tree, &StateKeyV2::ActorDescriptor(upgrade.actor))?
    else {
        return Ok(rejected(AccumulationRejectionV2::WrongProgram));
    };
    if descriptor.deployment != upgrade.expected_deployment
        || descriptor.program != upgrade.expected_program
    {
        return Ok(rejected(AccumulationRejectionV2::WrongProgram));
    }
    // A JAR continuation binds every dormant actor program in its invocation
    // layout, not only the actor whose message produced the checkpoint. Do
    // not activate replacement code while any durable kernel can still call
    // the old package through one of those handles.
    for suspended in directory.actors {
        let Some(reference) =
            tree_get_wire::<_, BlobRefV2>(&tree, &StateKeyV2::Continuation(suspended))?
        else {
            continue;
        };
        let bytes = tree
            .store_ref()
            .load_blob(&reference)
            .map_err(GuestAccumulateError::Storage)?
            .ok_or(GuestAccumulateError::CorruptStore)?;
        let continuation = ContinuationSnapshotV2::decode_metadata(&bytes)
            .map_err(|_| GuestAccumulateError::CorruptStore)?;
        if continuation.programs.iter().any(|binding| {
            binding.actor == upgrade.actor
                && binding.deployment == upgrade.expected_deployment
                && binding.program == upgrade.expected_program
        }) {
            return Ok(rejected(AccumulationRejectionV2::ActorBusy(upgrade.actor)));
        }
    }

    let previous_deployment = descriptor.deployment;
    let previous_program = descriptor.program;
    let current_policies = super::PackageRolePoliciesV2::decode(&descriptor.role_policies)
        .map_err(|_| GuestAccumulateError::CorruptStore)?;
    let replacement_policies = match super::PackageRolePoliciesV2::decode(&upgrade.role_policies) {
        Ok(policies) => policies,
        Err(_) => return Ok(rejected(AccumulationRejectionV2::NonCanonical)),
    };
    for policy in &current_policies.methods {
        tree_apply(
            &mut tree,
            &StateKeyV2::MethodPolicy {
                actor: upgrade.actor,
                method: policy.method.clone(),
            },
            None,
        )?;
    }
    for policy in &replacement_policies.methods {
        tree_apply(
            &mut tree,
            &StateKeyV2::MethodPolicy {
                actor: upgrade.actor,
                method: policy.method.clone(),
            },
            Some(&policy.encode()),
        )?;
    }
    descriptor.deployment = upgrade.replacement_deployment;
    descriptor.program = upgrade.replacement_program;
    descriptor.producer = upgrade.producer;
    descriptor.role_policies = upgrade.role_policies.clone();
    tree_apply(
        &mut tree,
        &StateKeyV2::ActorDescriptor(upgrade.actor),
        Some(&descriptor.encode()),
    )?;
    header.service_root = tree.root();
    drop(tree);
    header.revision = header
        .revision
        .checked_add(1)
        .expect("linear upgrade sequence overflow was validated before staging");
    header.state_root = Some(header.service_root);

    let receipt = AccumulationReceiptV2 {
        service: header.service.clone(),
        accepted_transition: upgrade_hash,
        reply_commitment: None,
        outbox_commitment: None,
        resulting_state_root: Some(header.service_root),
        resulting_crdt_heads: Vec::new(),
        sequence: header.revision,
        checkpoint: 0,
        consistency: header.consistency,
    };
    let record = ActorUpgradeRecordV2 {
        upgrade: upgrade_hash,
        actor: upgrade.actor,
        previous_deployment,
        previous_program,
        deployment: upgrade.replacement_deployment,
        program: upgrade.replacement_program,
        receipt: receipt.clone(),
    };
    write(store, header_storage_key(), Some(&header.encode()))?;
    write(store, &upgrade_key, Some(&record.encode()))?;
    Ok(AccumulationResultV2::ActorUpgraded {
        actor: upgrade.actor,
        previous_deployment,
        previous_program,
        deployment: upgrade.replacement_deployment,
        program: upgrade.replacement_program,
        receipt,
        duplicate: false,
    })
}
fn admit_ingress<S: GuestAccumulateStoreV2>(
    store: &mut S,
    ingress: &DirectIngressV2,
) -> GuestResult<AccumulationResultV2, S::Error> {
    let Some(header_bytes) = read(store, header_storage_key())? else {
        return Ok(rejected(AccumulationRejectionV2::StoreUninitialized));
    };
    let mut header = match StoreHeaderV2::open(&header_bytes) {
        Ok(header) => header,
        Err(StoreOpenError::IncompatibleSemantics) => {
            return Ok(rejected(AccumulationRejectionV2::WrongExecutionSemantics));
        }
        Err(StoreOpenError::WrongService) => {
            return Ok(rejected(AccumulationRejectionV2::WrongService));
        }
        Err(StoreOpenError::LegacyStore | StoreOpenError::InvalidHeader(_)) => {
            return Ok(rejected(AccumulationRejectionV2::NonCanonical));
        }
    };
    if ingress.service != header.service {
        return Ok(rejected(AccumulationRejectionV2::WrongService));
    }
    if header.service.service_abi != ABI_VERSION {
        return Ok(rejected(AccumulationRejectionV2::WrongAbi));
    }
    if header.service.execution_semantics != EXECUTION_SEMANTICS_ID {
        return Ok(rejected(AccumulationRejectionV2::WrongExecutionSemantics));
    }
    let key = ingress_storage_key(ingress.invocation);
    if let Some(bytes) = read(store, &key)? {
        let record =
            IngressRecordV2::decode(&bytes).map_err(|_| GuestAccumulateError::CorruptStore)?;
        return if record.ingress.matches_retry(ingress) {
            Ok(AccumulationResultV2::IngressAdmitted {
                invocation: ingress.invocation,
                receipt: record.receipt,
                duplicate: true,
            })
        } else {
            Ok(rejected(AccumulationRejectionV2::DivergentDuplicate))
        };
    }

    if !ingress.base.mode_compatible(header.consistency)
        || (header.consistency == ConsistencyModeV2::Crdt) != ingress.crdt_change.is_some()
    {
        return Ok(rejected(AccumulationRejectionV2::InvalidConsistency));
    }
    if let Some(rejection) = validate_base(store, &header, &ingress.base)? {
        return Ok(rejected(rejection));
    }
    if let Some(change) = ingress.crdt_change.as_ref() {
        let ConsistencyBaseV2::Crdt { heads } = &ingress.base else {
            unreachable!("canonical ingress binds its CRDT change to a CRDT base")
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
        if ingress.base_causal_height != Some(frontier.max_head_height)
            || frontier.max_head_height.checked_add(1) != Some(change.causal_height)
            || change.id != CrdtChangeV2::derive_ingress_id(&ingress.crdt_operation(), heads)
            || change.work_hash != ingress.crdt_operation().commitment()
            || change.causal_dependencies != *heads
            || !change.operations.is_empty()
            || !change.materializations.is_empty()
            || change.workflow != [WorkflowOperationV2::Ingress(ingress.crdt_operation())]
        {
            return Ok(rejected(AccumulationRejectionV2::InvalidWorkflowTransition));
        }
        if let Some(existing) = read(store, &crdt_change_storage_key(change.id))?
            && existing.as_slice() != change.cid().0
        {
            return Ok(rejected(AccumulationRejectionV2::DivergentDuplicate));
        }
    } else if ingress.base_causal_height.is_some() {
        return Ok(rejected(AccumulationRejectionV2::InvalidConsistency));
    }

    let tree = ServiceStateTreeV2::new(store, header.service_root);
    let Some(actor) =
        tree_get_wire::<_, ActorGenesisV2>(&tree, &StateKeyV2::ActorDescriptor(ingress.target))?
    else {
        return Ok(rejected(AccumulationRejectionV2::WrongProgram));
    };
    if actor.crdt != (header.consistency == ConsistencyModeV2::Crdt) {
        return Ok(rejected(AccumulationRejectionV2::InvalidConsistency));
    }
    let Some(policy) = tree_get_wire::<_, MethodPolicyV2>(
        &tree,
        &StateKeyV2::MethodPolicy {
            actor: ingress.target,
            method: ingress.method.clone(),
        },
    )?
    else {
        return Ok(rejected(AccumulationRejectionV2::Unauthorized));
    };
    let authorization_work = super::WorkEnvelopeV2 {
        service: ingress.service.clone(),
        invocation: ingress.invocation,
        workflow_step: 0,
        logical_timeslot: ingress.logical_timeslot,
        target: ingress.target,
        target_deployment: actor.deployment,
        target_program: actor.program,
        method: ingress.method.clone(),
        arguments: ingress.arguments.clone(),
        origin: ingress.origin,
        authorization: ingress.authorization.clone(),
        causal_parent: None,
        parent_call: None,
        causal_context: None,
        awaited_reply: None,
        awaited_timeout: None,
        consistency: header.consistency,
        base: ingress.base.clone(),
        base_causal_height: ingress.base_causal_height,
        imported_actors: Vec::new(),
        external_actors: Vec::new(),
        imported_blobs: ingress.imported_blobs.clone(),
        proof_requested: ingress.proof_requested,
    };
    if policy.attested != ingress.proof_requested
        || !authorized(&authorization_work, &policy, tree.store_ref())?
    {
        return Ok(rejected(AccumulationRejectionV2::Unauthorized));
    }
    drop(tree);
    for reference in &ingress.imported_blobs {
        if !blob_available(store, reference)? {
            return Ok(rejected(AccumulationRejectionV2::MissingBlob(
                reference.hash,
            )));
        }
    }
    let (resulting_state_root, resulting_crdt_heads, sequence) =
        if let Some(change) = ingress.crdt_change.as_ref() {
            let cid = change.cid();
            let mut heads = BTreeSet::from_iter(header.crdt_heads.iter().copied());
            for dependency in &change.causal_dependencies {
                heads.remove(dependency);
            }
            heads.insert(cid);
            header.crdt_heads = heads.into_iter().collect();
            (None, header.crdt_heads.clone(), change.causal_height)
        } else {
            (header.state_root, Vec::new(), header.revision)
        };
    let receipt = AccumulationReceiptV2 {
        service: header.service.clone(),
        accepted_transition: ingress
            .crdt_change
            .as_ref()
            .map_or_else(|| ingress.commitment(), CrdtChangeV2::receipt_commitment),
        reply_commitment: None,
        outbox_commitment: None,
        resulting_state_root,
        resulting_crdt_heads,
        sequence,
        checkpoint: 0,
        consistency: header.consistency,
    };
    if let Some(change) = ingress.crdt_change.as_ref() {
        write_crdt_change(store, change, change.cid())?;
        write_crdt_node_receipt(store, change.cid(), &receipt)?;
    }
    header.admission_timeslot_high_water = header
        .admission_timeslot_high_water
        .max(ingress.logical_timeslot);
    write(store, header_storage_key(), Some(&header.encode()))?;
    write(
        store,
        &key,
        Some(
            &IngressRecordV2 {
                ingress: ingress.clone(),
                consumed: false,
                receipt: receipt.clone(),
            }
            .encode(),
        ),
    )?;
    Ok(AccumulationResultV2::IngressAdmitted {
        invocation: ingress.invocation,
        receipt,
        duplicate: false,
    })
}
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum ApplyMode {
    Commit,
    PrepareAttested,
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
    if genesis.validate().is_err() {
        return Ok(rejected(AccumulationRejectionV2::NonCanonical));
    }
    if !store
        .authorize_install(genesis)
        .map_err(GuestAccumulateError::Storage)?
    {
        return Ok(rejected(AccumulationRejectionV2::Unauthorized));
    }
    for actor in &genesis.actors {
        if super::PackageRolePoliciesV2::decode(&actor.role_policies).is_err() {
            return Ok(rejected(AccumulationRejectionV2::NonCanonical));
        }
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
        let directory = super::ActorDirectoryV2 {
            actors: genesis.actors.iter().map(|actor| actor.actor).collect(),
        };
        tree_apply(
            &mut tree,
            &StateKeyV2::ActorDirectory,
            Some(&directory.encode()),
        )?;
        tree_apply(
            &mut tree,
            &StateKeyV2::ExternalActorDirectory,
            Some(
                &ExternalActorDirectoryV2 {
                    actors: genesis.external_actors.clone(),
                }
                .encode(),
            ),
        )?;
        for actor in &genesis.actors {
            tree_apply(
                &mut tree,
                &StateKeyV2::ActorDescriptor(actor.actor),
                Some(&actor.encode()),
            )?;
            let policies = super::PackageRolePoliciesV2::decode(&actor.role_policies)
                .map_err(|_| GuestAccumulateError::CorruptStore)?;
            for method in &policies.methods {
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

fn expire_call<S: GuestAccumulateStoreV2>(
    store: &mut S,
    envelope: &CallExpirationEnvelopeV2,
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

    let observed_timeslot = store
        .logical_timeslot()
        .map_err(GuestAccumulateError::Storage)?;
    if !observed_timeslot.is_some_and(|slot| slot >= envelope.timeout.deadline_timeslot) {
        return Ok(rejected(AccumulationRejectionV2::InvalidWorkflowTransition));
    }

    let expiration_key = call_expiration_storage_key(envelope.timeout.call_id);
    if let Some(bytes) = read(store, &expiration_key)? {
        let accumulated =
            AccumulatedTimeoutV2::decode(&bytes).map_err(|_| GuestAccumulateError::CorruptStore)?;
        return if accumulated.expiration == *envelope {
            Ok(AccumulationResultV2::CallExpired {
                timeout: accumulated,
                duplicate: true,
            })
        } else {
            Ok(rejected(AccumulationRejectionV2::DivergentDuplicate))
        };
    }
    if let Some(rejection) = validate_base(store, &header, &envelope.base)? {
        return Ok(rejected(rejection));
    }
    if header.consistency != ConsistencyModeV2::Crdt && header.revision == u64::MAX {
        return Ok(rejected(AccumulationRejectionV2::SequenceOverflow));
    }
    if let Some(change) = envelope.crdt_change.as_ref() {
        let ConsistencyBaseV2::Crdt { heads } = &envelope.base else {
            unreachable!("expiration wire binds a CRDT change to a CRDT base")
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

    let (message, workflow, continuation_ref) = {
        let tree = ServiceStateTreeV2::new(store, header.service_root);
        let Some(message) = tree_get_wire::<_, MessageRecordV2>(
            &tree,
            &StateKeyV2::Outbox(envelope.timeout.call_id),
        )?
        else {
            return Ok(rejected(AccumulationRejectionV2::InvalidWorkflowTransition));
        };
        let Some(workflow) = tree_get_wire::<_, WorkflowCheckpointV2>(
            &tree,
            &StateKeyV2::Workflow(envelope.timeout.caller_invocation),
        )?
        else {
            return Ok(rejected(AccumulationRejectionV2::InvalidWorkflowTransition));
        };
        let Some(continuation_ref) = tree_get_wire::<_, BlobRefV2>(
            &tree,
            &StateKeyV2::Continuation(workflow.resume_work.target),
        )?
        else {
            return Ok(rejected(AccumulationRejectionV2::InvalidWorkflowTransition));
        };
        (message, workflow, continuation_ref)
    };
    if message.caller_invocation != envelope.timeout.caller_invocation
        || message.from != envelope.timeout.caller_actor
        || message.await_ordinal != envelope.timeout.await_ordinal
        || message.deadline_timeslot != Some(envelope.timeout.deadline_timeslot)
        || workflow.input.invocation != envelope.timeout.caller_invocation
        || workflow.input.workflow_step != envelope.timeout.checkpoint_step
    {
        return Ok(rejected(AccumulationRejectionV2::InvalidWorkflowTransition));
    }
    let Some(continuation_bytes) = store
        .load_blob(&continuation_ref)
        .map_err(GuestAccumulateError::Storage)?
    else {
        return Ok(rejected(AccumulationRejectionV2::MissingBlob(
            continuation_ref.hash,
        )));
    };
    if !continuation_ref.matches(&continuation_bytes) {
        return Err(GuestAccumulateError::CorruptStore);
    }
    let continuation = ContinuationSnapshotV2::decode_metadata(&continuation_bytes)
        .map_err(|_| GuestAccumulateError::CorruptStore)?;
    if continuation
        .validate_checkpoint_for(&workflow.resume_work)
        .is_err()
        || continuation.pending_call != Some(envelope.timeout.call_id)
        || continuation.pending_actor != Some(envelope.timeout.caller_actor)
        || continuation.await_ordinal != envelope.timeout.await_ordinal
    {
        return Ok(rejected(AccumulationRejectionV2::InvalidWorkflowTransition));
    }

    header.service_root = {
        let mut tree = ServiceStateTreeV2::new(store, header.service_root);
        for actor in &continuation.suspended_actors {
            if tree_get_wire::<_, BlobRefV2>(&tree, &StateKeyV2::Continuation(*actor))?
                != Some(continuation_ref.clone())
            {
                return Ok(rejected(AccumulationRejectionV2::InvalidWorkflowTransition));
            }
        }
        tree_apply(
            &mut tree,
            &StateKeyV2::Outbox(envelope.timeout.call_id),
            None,
        )?;
        tree.root()
    };
    write(
        store,
        &pending_call_deadline_storage_key(envelope.timeout.call_id),
        None,
    )?;
    write(store, &publication_storage_key(workflow.input), None)?;

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
    header.admission_timeslot_high_water = header
        .admission_timeslot_high_water
        .max(observed_timeslot.expect("expiration timeslot was validated"));
    let receipt = AccumulationReceiptV2 {
        service: header.service.clone(),
        accepted_transition: envelope
            .crdt_change
            .as_ref()
            .map_or_else(|| envelope.commitment(), CrdtChangeV2::receipt_commitment),
        reply_commitment: None,
        outbox_commitment: None,
        resulting_state_root,
        resulting_crdt_heads,
        sequence,
        checkpoint: envelope.timeout.checkpoint_step,
        consistency: header.consistency,
    };
    if let Some(change) = envelope.crdt_change.as_ref() {
        write_crdt_node_receipt(store, change.cid(), &receipt)?;
        let frontier = load_causal_frontier(&header.crdt_heads, |cid| {
            store.read(&crdt_node_storage_key(cid))
        })
        .map_err(|error| match error {
            CausalFrontierError::Storage(error) => GuestAccumulateError::Storage(error),
            CausalFrontierError::Missing(_) | CausalFrontierError::Corrupt => {
                GuestAccumulateError::CorruptStore
            }
        })?;
        rematerialize_crdt_service(store, &mut header, &frontier)?;
    }
    let accumulated = AccumulatedTimeoutV2 {
        expiration: envelope.clone(),
        receipt,
    };
    write(store, header_storage_key(), Some(&header.encode()))?;
    write(store, &expiration_key, Some(&accumulated.encode()))?;
    Ok(AccumulationResultV2::CallExpired {
        timeout: accumulated,
        duplicate: false,
    })
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
    if envelope.message.to_service != header.service {
        return Ok(rejected(AccumulationRejectionV2::WrongService));
    }
    if header.service.service_abi != ABI_VERSION {
        return Ok(rejected(AccumulationRejectionV2::WrongAbi));
    }
    if header.service.execution_semantics != EXECUTION_SEMANTICS_ID {
        return Ok(rejected(AccumulationRejectionV2::WrongExecutionSemantics));
    }
    if header.consistency == ConsistencyModeV2::Crdt
        || !envelope.base.mode_compatible(header.consistency)
    {
        return Ok(rejected(AccumulationRejectionV2::InvalidConsistency));
    }

    let retry_identity = envelope.retry_identity();
    let delivery_key = delivery_storage_key(envelope.message.call_id);
    if let Some(bytes) = read(store, &delivery_key)? {
        let record =
            DeliveryRecordV2::decode(&bytes).map_err(|_| GuestAccumulateError::CorruptStore)?;
        if record.receipt.service != header.service
            || record.receipt.consistency != header.consistency
        {
            return Err(GuestAccumulateError::CorruptStore);
        }
        return if record.call_id == envelope.message.call_id
            && record.retry_identity == retry_identity
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
    if envelope.message.from_service != *source
        || source.root_service == header.service.root_service
        || source.service_abi != ABI_VERSION
        || source.execution_semantics != EXECUTION_SEMANTICS_ID
    {
        return Ok(rejected(AccumulationRejectionV2::InvalidReceipt));
    }
    if envelope.source_receipt.consistency == ConsistencyModeV2::Crdt {
        return Ok(rejected(AccumulationRejectionV2::InvalidConsistency));
    }
    match store
        .verify_receipt(&ReceiptVerificationRequestV2 {
            expected_producer: envelope.message.from,
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
    if header.revision == u64::MAX {
        return Ok(rejected(AccumulationRejectionV2::SequenceOverflow));
    }

    let mut tree = ServiceStateTreeV2::new(store, header.service_root);
    if tree_get_wire::<_, ActorGenesisV2>(&tree, &StateKeyV2::ActorDescriptor(envelope.message.to))?
        .is_none()
        || tree_get_wire::<_, MessageRecordV2>(&tree, &StateKeyV2::Inbox(envelope.message.call_id))?
            .is_some()
        || tree_get_wire::<_, MessageRecordV2>(
            &tree,
            &StateKeyV2::Outbox(envelope.message.call_id),
        )?
        .is_some()
    {
        return Ok(rejected(AccumulationRejectionV2::InvalidWorkflowTransition));
    }
    tree_apply(
        &mut tree,
        &StateKeyV2::Inbox(envelope.message.call_id),
        Some(&envelope.message.encode()),
    )?;
    header.service_root = tree.root();
    drop(tree);

    header.revision += 1;
    header.state_root = Some(header.service_root);
    let delivery_commitment = envelope.commitment();
    let receipt = AccumulationReceiptV2 {
        service: header.service.clone(),
        accepted_transition: delivery_commitment,
        reply_commitment: None,
        outbox_commitment: None,
        resulting_state_root: Some(header.service_root),
        resulting_crdt_heads: Vec::new(),
        sequence: header.revision,
        checkpoint: 0,
        consistency: header.consistency,
    };
    let record = DeliveryRecordV2 {
        call_id: envelope.message.call_id,
        logical_timeslot: envelope.logical_timeslot,
        consumed: false,
        retry_identity,
        delivery_commitment,
        receipt: receipt.clone(),
    };
    header.admission_timeslot_high_water = header
        .admission_timeslot_high_water
        .max(envelope.logical_timeslot);
    write(store, header_storage_key(), Some(&header.encode()))?;
    write(store, &delivery_key, Some(&record.encode()))?;
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
    ingresses: BTreeMap<super::InvocationId, Vec<CausalValueV2<super::CrdtIngressV2>>>,
    consumed_ingresses: BTreeSet<super::InvocationId>,
    workflows: BTreeMap<super::InvocationId, Vec<CausalValueV2<WorkflowCheckpointV2>>>,
    dedup_workflows: Vec<CausalValueV2<WorkflowCheckpointV2>>,
    continuations: BTreeMap<ActorId, Vec<CausalValueV2<Option<BlobRefV2>>>>,
    inbox: BTreeMap<super::CallId, Vec<CausalValueV2<Option<MessageRecordV2>>>>,
    outbox: BTreeMap<super::CallId, Vec<CausalValueV2<Option<MessageRecordV2>>>>,
    expirations: BTreeMap<super::CallId, Vec<CausalValueV2<CallTimeoutV2>>>,
    replies: BTreeMap<super::CallId, Vec<CausalValueV2<super::ReplyRecordV2>>>,
    reply_admissions: BTreeMap<super::CallId, Vec<CausalValueV2<ReplyAdmissionRecordV2>>>,
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
    let mut imported_nodes = BTreeSet::new();
    let mut changed = false;
    for node in &envelope.nodes {
        let cid = node.change.cid();
        let Some(expected_producer) = crdt_change_producer(&node.change) else {
            return Ok(rejected(AccumulationRejectionV2::InvalidWorkflowTransition));
        };
        if !crdt_receipt_matches_change(&header.service, &node.change, &node.receipt) {
            return Ok(rejected(AccumulationRejectionV2::InvalidReceipt));
        }
        if let Some(existing) = read(store, &crdt_node_storage_key(cid))? {
            if existing != node.change.encode() {
                return Err(GuestAccumulateError::CorruptStore);
            }
            let receipt = read(store, &crdt_node_receipt_storage_key(cid))?
                .ok_or(GuestAccumulateError::CorruptStore)?;
            AccumulationReceiptV2::decode(&receipt)
                .map_err(|_| GuestAccumulateError::CorruptStore)?;
        } else {
            changed = true;
            imported_nodes.insert(cid);
            match store
                .verify_receipt(&ReceiptVerificationRequestV2 {
                    expected_producer,
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
        let cid = node.change.cid();
        if imported_nodes.contains(&cid) {
            write_crdt_change(store, &node.change, cid)?;
            write_crdt_node_receipt(store, cid, &node.receipt)?;
        }
    }

    apply_expiration_materialization(store, &header.service, &materialized)?;
    apply_ingress_materialization(store, &materialized)?;
    apply_dedup_materialization(store, &header.service, &materialized)?;
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

fn crdt_change_producer(change: &CrdtChangeV2) -> Option<ActorId> {
    change.expected_producer()
}

fn crdt_receipt_matches_change(
    service: &super::ServiceIdentityV2,
    change: &CrdtChangeV2,
    receipt: &AccumulationReceiptV2,
) -> bool {
    let checkpoints = change
        .workflow
        .iter()
        .filter_map(|operation| match operation {
            WorkflowOperationV2::Checkpoint(work) => Some(work.workflow_step),
            WorkflowOperationV2::ExpireCall(timeout) => Some(timeout.checkpoint_step),
            WorkflowOperationV2::Ingress(_) => Some(0),
            _ => None,
        });
    let mut checkpoints = checkpoints;
    let Some(checkpoint) = checkpoints.next() else {
        return false;
    };
    if checkpoints.any(|candidate| candidate != checkpoint) {
        return false;
    }
    let replies = change
        .workflow
        .iter()
        .filter_map(|operation| match operation {
            WorkflowOperationV2::Reply(reply) => Some(reply),
            _ => None,
        });
    let mut replies = replies;
    let reply_commitment = replies.next().map(super::ReplyRecordV2::commitment);
    if replies.next().is_some() {
        return false;
    }
    let outbox = change
        .workflow
        .iter()
        .filter_map(|operation| match operation {
            WorkflowOperationV2::Outbox(message) => Some(message.clone()),
            _ => None,
        })
        .collect::<Vec<_>>();
    receipt.service == *service
        && receipt.accepted_transition == change.receipt_commitment()
        && receipt.reply_commitment == reply_commitment
        && receipt.outbox_commitment == MessageRecordV2::outbox_commitment(&outbox)
        && receipt.resulting_state_root.is_none()
        && receipt
            .resulting_crdt_heads
            .binary_search(&change.cid())
            .is_ok()
        && receipt.sequence == change.causal_height
        && receipt.checkpoint == checkpoint
        && receipt.consistency == ConsistencyModeV2::Crdt
}

fn materialize_workflow_crdt(
    frontier: &super::causal::CausalFrontierV2,
    service: &super::ServiceIdentityV2,
) -> Result<WorkflowMaterializationV2, AccumulationRejectionV2> {
    let mut result = WorkflowMaterializationV2::default();
    let mut ingress_identities = BTreeMap::<super::InvocationId, super::CrdtIngressV2>::new();
    let duplicate_executions = duplicate_crdt_executions(frontier)?;

    // Reply admissions must retain every physical retry alternative so an
    // already-materialized admission can be checked against the selected
    // logical execution below. Do this before discarding retry losers from
    // the materialization order.
    for (cid, change) in frontier.nodes_in_causal_order() {
        if let Some(awaited_reply) = change.awaited_reply.as_ref() {
            let Some(work) = change
                .workflow
                .iter()
                .find_map(|operation| match operation {
                    WorkflowOperationV2::Checkpoint(work) => Some(work),
                    _ => None,
                })
            else {
                return Err(AccumulationRejectionV2::InvalidWorkflowTransition);
            };
            let admission = ReplyAdmissionRecordV2 {
                call_id: awaited_reply.reply.call_id,
                input: work.input_id(),
                awaited_reply: awaited_reply.clone(),
                work_hash: change.work_hash,
            };
            result
                .reply_admissions
                .entry(admission.call_id)
                .or_default()
                .push(CausalValueV2 {
                    cid,
                    value: admission,
                });
        }
    }

    // Physical causal height cannot be used directly after retry collapse.
    // A descendant may name the losing physical retry while the canonical
    // winner sits on a taller concurrent base. Redirect that dependency to
    // the winner and process the resulting logical DAG topologically.
    for (cid, change) in duplicate_executions.materialization_order(frontier)? {
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
                    && change.id == CrdtChangeV2::derive_id_from_work_hash(change.work_hash)
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
                    .filter(|event| {
                        duplicate_executions.contains_ancestor(frontier, cid, event.cid)
                    })
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
                    transition_hash: cid,
                };
                result.dedup_workflows.push(CausalValueV2 {
                    cid,
                    value: checkpoint.clone(),
                });
                insert_causal_value(
                    frontier,
                    &duplicate_executions,
                    result.workflows.entry(work.invocation).or_default(),
                    cid,
                    checkpoint,
                );
                if work.workflow_step == 0 && work.parent_call.is_none() {
                    result.consumed_ingresses.insert(work.invocation);
                }
            }
            [] if change.operations.is_empty()
                && change.materializations.is_empty()
                && matches!(change.workflow.as_slice(), [WorkflowOperationV2::ExpireCall(timeout)]
                if change.id == CrdtChangeV2::derive_expiration_id(
                    service,
                    timeout,
                    &change.causal_dependencies,
                )) => {}
            [] if change.operations.is_empty()
                && change.materializations.is_empty()
                && matches!(change.workflow.as_slice(), [WorkflowOperationV2::Ingress(ingress)]
                if ingress.service == *service
                    && change.work_hash == ingress.commitment()
                    && change.id == CrdtChangeV2::derive_ingress_id(
                        ingress,
                        &change.causal_dependencies,
                    )) => {}
            _ => return Err(AccumulationRejectionV2::InvalidWorkflowTransition),
        }

        for materialization in &change.materializations {
            insert_causal_value(
                frontier,
                &duplicate_executions,
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
                            &duplicate_executions,
                            result.inbox.entry(call).or_default(),
                            cid,
                            None,
                        );
                    }
                }
                WorkflowOperationV2::Continuation(change) => {
                    let values = result.continuations.entry(change.actor).or_default();
                    // Keep the first causal continuation explicit. Besides
                    // avoiding an unnecessary ancestry walk, this preserves
                    // the exact `None` predecessor required by a first
                    // checkpoint before any branch can exist.
                    if values.is_empty() {
                        if change.expected.is_some() {
                            return Err(AccumulationRejectionV2::InvalidWorkflowTransition);
                        }
                    } else {
                        let mut observed = values
                            .iter()
                            .filter(|event| {
                                duplicate_executions.contains_ancestor(frontier, cid, event.cid)
                            })
                            .map(|event| event.value.as_ref().map(|reference| reference.hash));
                        let expected = observed.next().unwrap_or(None);
                        if observed.any(|value| value != expected) {
                            return Err(AccumulationRejectionV2::InvalidWorkflowTransition);
                        }
                        if duplicate_executions
                            .canonical_continuation(change.actor, change.expected)
                            != expected
                        {
                            return Err(AccumulationRejectionV2::InvalidWorkflowTransition);
                        }
                    }
                    insert_causal_value(
                        frontier,
                        &duplicate_executions,
                        values,
                        cid,
                        change.replacement.clone(),
                    );
                }
                WorkflowOperationV2::Inbox(message) => insert_causal_value(
                    frontier,
                    &duplicate_executions,
                    result.inbox.entry(message.call_id).or_default(),
                    cid,
                    Some(message.clone()),
                ),
                WorkflowOperationV2::Outbox(message) => insert_causal_value(
                    frontier,
                    &duplicate_executions,
                    result.outbox.entry(message.call_id).or_default(),
                    cid,
                    Some(message.clone()),
                ),
                WorkflowOperationV2::ConsumeOutbox(call) => insert_causal_value(
                    frontier,
                    &duplicate_executions,
                    result.outbox.entry(*call).or_default(),
                    cid,
                    None,
                ),
                WorkflowOperationV2::ExpireCall(timeout) => {
                    let mut workflows = result
                        .workflows
                        .get(&timeout.caller_invocation)
                        .into_iter()
                        .flatten()
                        .filter(|event| {
                            duplicate_executions.contains_ancestor(frontier, cid, event.cid)
                        });
                    let Some(workflow) = workflows.next() else {
                        return Err(AccumulationRejectionV2::InvalidWorkflowTransition);
                    };
                    if workflows.any(|candidate| candidate.value != workflow.value)
                        || workflow.value.input.workflow_step != timeout.checkpoint_step
                    {
                        return Err(AccumulationRejectionV2::InvalidWorkflowTransition);
                    }
                    let values = result.outbox.entry(timeout.call_id).or_default();
                    let mut observed = values
                        .iter()
                        .filter(|event| {
                            duplicate_executions.contains_ancestor(frontier, cid, event.cid)
                        })
                        .filter_map(|event| event.value.as_ref());
                    let Some(message) = observed.next() else {
                        return Err(AccumulationRejectionV2::InvalidWorkflowTransition);
                    };
                    if observed.any(|candidate| candidate != message)
                        || message.caller_invocation != timeout.caller_invocation
                        || message.from != timeout.caller_actor
                        || message.await_ordinal != timeout.await_ordinal
                        || message.deadline_timeslot != Some(timeout.deadline_timeslot)
                    {
                        return Err(AccumulationRejectionV2::InvalidWorkflowTransition);
                    }
                    insert_causal_value(frontier, &duplicate_executions, values, cid, None);
                    insert_causal_value(
                        frontier,
                        &duplicate_executions,
                        result.expirations.entry(timeout.call_id).or_default(),
                        cid,
                        timeout.clone(),
                    );
                }
                WorkflowOperationV2::Reply(reply) => insert_causal_value(
                    frontier,
                    &duplicate_executions,
                    result.replies.entry(reply.call_id).or_default(),
                    cid,
                    reply.clone(),
                ),
                WorkflowOperationV2::Ingress(ingress) => {
                    if let Some(existing) = ingress_identities.get(&ingress.invocation) {
                        if !existing.matches_retry(ingress) {
                            return Err(AccumulationRejectionV2::DivergentDuplicate);
                        }
                    } else {
                        ingress_identities.insert(ingress.invocation, ingress.clone());
                    }
                    insert_causal_value(
                        frontier,
                        &duplicate_executions,
                        result.ingresses.entry(ingress.invocation).or_default(),
                        cid,
                        ingress.clone(),
                    );
                }
            }
        }
    }
    // Concurrent admissions of the same stable InvocationId may have been
    // stamped at different trusted slots or observed different causal bases.
    // Preserve both causal branches, but never let CID order choose between
    // different caller-controlled inputs.
    validate_ingress_retry_frontiers(result.ingresses.values())?;
    validate_strict_frontiers(result.workflows.values())?;
    validate_strict_frontiers(result.continuations.values())?;
    validate_strict_frontiers(result.replies.values())?;
    validate_strict_frontiers(result.expirations.values())?;
    for admissions in result.reply_admissions.values_mut() {
        admissions.sort_by_key(|event| (duplicate_executions.is_loser(event.cid), event.cid));
        let Some(canonical) = admissions.first() else {
            continue;
        };
        if duplicate_executions.is_loser(canonical.cid)
            || admissions.iter().skip(1).any(|candidate| {
                candidate.value.call_id != canonical.value.call_id
                    || candidate.value.input != canonical.value.input
                    || candidate.value.awaited_reply != canonical.value.awaited_reply
            })
        {
            return Err(AccumulationRejectionV2::InvalidWorkflowTransition);
        }
    }
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

fn validate_ingress_retry_frontiers<'a>(
    frontiers: impl Iterator<Item = &'a Vec<CausalValueV2<super::CrdtIngressV2>>>,
) -> Result<(), AccumulationRejectionV2> {
    for values in frontiers {
        let Some(first) = values.first() else {
            continue;
        };
        if values
            .iter()
            .skip(1)
            .any(|candidate| !first.value.matches_retry(&candidate.value))
        {
            return Err(AccumulationRejectionV2::DivergentDuplicate);
        }
    }
    Ok(())
}

/// Select one physical branch for independently scheduled executions of the
/// same logical workflow step. The DAG retains every branch, but duplicate
/// application operations and workflow effects materialize only once. Any
/// caller-input or execution-result difference remains an invalid workflow
/// transition rather than being hidden behind the CID tie-break.
#[derive(Default)]
struct DuplicateCrdtExecutionsV2 {
    canonical_by_loser: BTreeMap<Hash, Hash>,
    continuation_aliases: BTreeMap<(ActorId, Hash), BlobRefV2>,
}

impl DuplicateCrdtExecutionsV2 {
    fn is_loser(&self, cid: Hash) -> bool {
        self.canonical_by_loser.contains_key(&cid)
    }

    /// Treat every physical retry loser as an alias of the selected node.
    /// A later slice may have been refined before synchronization and hence
    /// descend from that loser even though only the winner materializes.
    fn contains_ancestor(
        &self,
        frontier: &super::causal::CausalFrontierV2,
        descendant: Hash,
        ancestor: Hash,
    ) -> bool {
        frontier.contains_ancestor(descendant, ancestor)
            || self.canonical_by_loser.iter().any(|(loser, winner)| {
                *winner == ancestor && frontier.contains_ancestor(descendant, *loser)
            })
    }

    fn canonical_continuation(&self, actor: ActorId, expected: Option<Hash>) -> Option<Hash> {
        expected.map(|hash| {
            self.continuation_aliases
                .get(&(actor, hash))
                .map_or(hash, |reference| reference.hash)
        })
    }

    fn canonical_cid(&self, cid: Hash) -> Hash {
        self.canonical_by_loser.get(&cid).copied().unwrap_or(cid)
    }

    /// Return the selected physical nodes in logical causal order.
    ///
    /// Collapsing concurrent retries rewrites every edge to a discarded node
    /// so it instead depends on the canonical winner. That winner can have a
    /// greater physical causal height than the dependent node, so the normal
    /// height order is insufficient after this rewrite.
    fn materialization_order<'a>(
        &self,
        frontier: &'a super::causal::CausalFrontierV2,
    ) -> Result<Vec<(Hash, &'a CrdtChangeV2)>, AccumulationRejectionV2> {
        let physical_order = frontier.nodes_in_causal_order();
        let physical_nodes = physical_order
            .iter()
            .map(|(cid, change)| (*cid, *change))
            .collect::<BTreeMap<_, _>>();
        let selected = physical_order
            .into_iter()
            .filter(|(cid, _)| !self.is_loser(*cid))
            .collect::<Vec<_>>();
        let ranks = selected
            .iter()
            .enumerate()
            .map(|(rank, (cid, _))| (*cid, rank))
            .collect::<BTreeMap<_, _>>();
        let selected_cids = ranks.keys().copied().collect::<BTreeSet<_>>();
        let mut indegrees = BTreeMap::<Hash, usize>::new();
        let mut dependents = BTreeMap::<Hash, Vec<Hash>>::new();

        for (cid, change) in &selected {
            let mut dependencies = BTreeSet::new();
            let mut pending = change.causal_dependencies.clone();
            let mut visited = BTreeSet::new();
            while let Some(dependency) = pending.pop() {
                if !visited.insert(dependency) {
                    continue;
                }
                let canonical = self.canonical_cid(dependency);
                dependencies.insert(canonical);
                if self.is_loser(dependency) {
                    // Contracting the loser edge must not discard the branch
                    // that led to it. Lift every one of its physical causal
                    // prerequisites into the selected logical DAG as well as
                    // depending on its canonical retry representative.
                    let discarded = physical_nodes
                        .get(&dependency)
                        .ok_or(AccumulationRejectionV2::InvalidWorkflowTransition)?;
                    pending.extend(discarded.causal_dependencies.iter().copied());
                }
            }
            if dependencies.contains(cid)
                || dependencies
                    .iter()
                    .any(|dependency| !selected_cids.contains(dependency))
            {
                return Err(AccumulationRejectionV2::InvalidWorkflowTransition);
            }
            indegrees.insert(*cid, dependencies.len());
            for dependency in dependencies {
                dependents.entry(dependency).or_default().push(*cid);
            }
        }

        let mut ready = indegrees
            .iter()
            .filter(|(_, degree)| **degree == 0)
            .map(|(cid, _)| (ranks[cid], *cid))
            .collect::<BTreeSet<_>>();
        let mut ordered = Vec::with_capacity(selected.len());
        while let Some((rank, cid)) = ready.pop_first() {
            ordered.push(selected[rank]);
            for dependent in dependents.get(&cid).into_iter().flatten() {
                let degree = indegrees
                    .get_mut(dependent)
                    .ok_or(AccumulationRejectionV2::InvalidWorkflowTransition)?;
                *degree = degree
                    .checked_sub(1)
                    .ok_or(AccumulationRejectionV2::InvalidWorkflowTransition)?;
                if *degree == 0 {
                    ready.insert((ranks[dependent], *dependent));
                }
            }
        }
        if ordered.len() != selected.len() {
            // The physical DAG was already validated. Failure here means
            // retry aliasing introduced a logical cycle.
            return Err(AccumulationRejectionV2::InvalidWorkflowTransition);
        }
        Ok(ordered)
    }
}

fn duplicate_crdt_executions(
    frontier: &super::causal::CausalFrontierV2,
) -> Result<DuplicateCrdtExecutionsV2, AccumulationRejectionV2> {
    let mut groups = BTreeMap::<WorkInputIdV2, Vec<(Hash, &CrdtChangeV2)>>::new();
    for (cid, change) in frontier.nodes_in_causal_order() {
        let mut checkpoints = change
            .workflow
            .iter()
            .filter_map(|operation| match operation {
                WorkflowOperationV2::Checkpoint(work) => Some(work),
                _ => None,
            });
        let Some(work) = checkpoints.next() else {
            continue;
        };
        if checkpoints.next().is_some() {
            return Err(AccumulationRejectionV2::InvalidWorkflowTransition);
        }
        groups
            .entry(work.input_id())
            .or_default()
            .push((cid, change));
    }

    let mut result = DuplicateCrdtExecutionsV2::default();
    for candidates in groups.values_mut() {
        candidates.sort_by_key(|(cid, _)| *cid);
        let Some(&(winner_cid, winner)) = candidates.first() else {
            continue;
        };
        for (index, &(loser_cid, loser)) in candidates.iter().enumerate().skip(1) {
            if candidates[..index].iter().any(|(other_cid, _)| {
                frontier.contains_ancestor(*other_cid, loser_cid)
                    || frontier.contains_ancestor(loser_cid, *other_cid)
            }) {
                // A logical input is consumed once on any causal branch.
                // Retry aliases are only meaningful for concurrent physical
                // executions, never for a descendant replay of that input.
                return Err(AccumulationRejectionV2::InvalidWorkflowTransition);
            }
            let proof_requested = winner
                .workflow
                .iter()
                .find_map(|operation| match operation {
                    WorkflowOperationV2::Checkpoint(work) => Some(work.proof_requested),
                    _ => None,
                });
            if proof_requested != Some(false) || !crdt_retry_execution_matches(winner, loser) {
                // A proof and portable attestation bind one exact physical
                // receipt. Until the CRDT sync envelope carries the canonical
                // publication/proof pair, independently proved retry branches
                // cannot be collapsed without losing that binding.
                return Err(AccumulationRejectionV2::InvalidWorkflowTransition);
            }
            result.canonical_by_loser.insert(loser_cid, winner_cid);
            for (winner_change, loser_change) in winner.workflow.iter().zip(&loser.workflow) {
                let (
                    WorkflowOperationV2::Continuation(winner_change),
                    WorkflowOperationV2::Continuation(loser_change),
                ) = (winner_change, loser_change)
                else {
                    continue;
                };
                if let (Some(winner), Some(loser)) =
                    (&winner_change.replacement, &loser_change.replacement)
                    && winner != loser
                {
                    let key = (loser_change.actor, loser.hash);
                    if result
                        .continuation_aliases
                        .insert(key, winner.clone())
                        .is_some_and(|existing| existing != *winner)
                    {
                        return Err(AccumulationRejectionV2::InvalidWorkflowTransition);
                    }
                }
            }
        }
    }
    Ok(result)
}

fn crdt_retry_execution_matches(left: &CrdtChangeV2, right: &CrdtChangeV2) -> bool {
    left.awaited_reply == right.awaited_reply
        && left.operations.len() == right.operations.len()
        && left
            .operations
            .iter()
            .zip(&right.operations)
            .all(|(left, right)| {
                left.actor == right.actor
                    && left.dispatch_ordinal == right.dispatch_ordinal
                    && left.field == right.field
                    && left.ordinal == right.ordinal
                    && left.payload == right.payload
            })
        // Materializations are branch-local snapshots of the causal state
        // each replica observed. The stable operation payloads above are the
        // idempotent logical effect; requiring the resulting blob references
        // to match would reject a valid retry executed over another frontier.
        && left.workflow.len() == right.workflow.len()
        && left
            .workflow
            .iter()
            .zip(&right.workflow)
            .all(|(left, right)| match (left, right) {
                (WorkflowOperationV2::Checkpoint(left), WorkflowOperationV2::Checkpoint(right)) => {
                    left.matches_crdt_retry(right)
                }
                (
                    WorkflowOperationV2::Continuation(left),
                    WorkflowOperationV2::Continuation(right),
                ) => {
                    left.actor == right.actor
                        && left.expected.is_some() == right.expected.is_some()
                        && left.replacement.is_some() == right.replacement.is_some()
                }
                _ => left == right,
            })
}

#[cfg(feature = "std")]
pub(super) fn materialized_continuations(
    frontier: &super::causal::CausalFrontierV2,
    service: &super::ServiceIdentityV2,
) -> Result<BTreeMap<ActorId, Option<BlobRefV2>>, AccumulationRejectionV2> {
    materialize_workflow_crdt(frontier, service).map(|materialized| {
        materialized
            .continuations
            .into_iter()
            .map(|(actor, values)| {
                (
                    actor,
                    values
                        .first()
                        .expect("continuation frontier is never empty")
                        .value
                        .clone(),
                )
            })
            .collect()
    })
}

fn insert_causal_value<T>(
    frontier: &super::causal::CausalFrontierV2,
    duplicate_executions: &DuplicateCrdtExecutionsV2,
    values: &mut Vec<CausalValueV2<T>>,
    cid: Hash,
    value: T,
) {
    if values
        .iter()
        .any(|existing| duplicate_executions.contains_ancestor(frontier, existing.cid, cid))
    {
        return;
    }
    values.retain(|existing| !duplicate_executions.contains_ancestor(frontier, cid, existing.cid));
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
        let deadline = visible.and_then(|message| {
            message
                .deadline_timeslot
                .map(|deadline_timeslot| PendingCallDeadlineV2 {
                    call_id: call,
                    caller_invocation: message.caller_invocation,
                    deadline_timeslot,
                })
        });
        write(
            tree.store_mut(),
            &pending_call_deadline_storage_key(call),
            deadline.as_ref().map(V2Wire::encode).as_deref(),
        )?;
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

fn apply_expiration_materialization<S: GuestAccumulateStoreV2>(
    store: &mut S,
    service: &super::ServiceIdentityV2,
    materialized: &WorkflowMaterializationV2,
) -> GuestResult<(), S::Error> {
    for (call, values) in &materialized.expirations {
        let event = values.first().expect("expiration frontier is never empty");
        let change_bytes = read(store, &crdt_node_storage_key(event.cid))?
            .ok_or(GuestAccumulateError::CorruptStore)?;
        let change =
            CrdtChangeV2::decode(&change_bytes).map_err(|_| GuestAccumulateError::CorruptStore)?;
        if change.cid() != event.cid
            || change.workflow != [WorkflowOperationV2::ExpireCall(event.value.clone())]
        {
            return Err(GuestAccumulateError::CorruptStore);
        }
        let receipt_bytes = read(store, &crdt_node_receipt_storage_key(event.cid))?
            .ok_or(GuestAccumulateError::CorruptStore)?;
        let receipt = AccumulationReceiptV2::decode(&receipt_bytes)
            .map_err(|_| GuestAccumulateError::CorruptStore)?;
        let expiration = CallExpirationEnvelopeV2 {
            service: service.clone(),
            timeout: event.value.clone(),
            base: ConsistencyBaseV2::Crdt {
                heads: change.causal_dependencies.clone(),
            },
            base_causal_height: change.causal_height.checked_sub(1),
            crdt_change: Some(change),
        };
        let accumulated = AccumulatedTimeoutV2 {
            expiration,
            receipt,
        };
        accumulated
            .validate()
            .map_err(|_| GuestAccumulateError::CorruptStore)?;
        write(
            store,
            &call_expiration_storage_key(*call),
            Some(&accumulated.encode()),
        )?;
        write(store, &pending_call_deadline_storage_key(*call), None)?;
        // An expiration remains in every descendant CRDT materialization.
        // Retire the publication for the checkpoint it actually consumed,
        // never whichever later workflow value happens to be visible now.
        let expired_input = WorkInputIdV2 {
            invocation: event.value.caller_invocation,
            workflow_step: event.value.checkpoint_step,
        };
        write(store, &publication_storage_key(expired_input), None)?;
    }
    Ok(())
}

fn apply_ingress_materialization<S: GuestAccumulateStoreV2>(
    store: &mut S,
    materialized: &WorkflowMaterializationV2,
) -> GuestResult<(), S::Error> {
    for (invocation, values) in &materialized.ingresses {
        let event = values.first().expect("ingress frontier is never empty");
        let change_bytes = read(store, &crdt_node_storage_key(event.cid))?
            .ok_or(GuestAccumulateError::CorruptStore)?;
        let change =
            CrdtChangeV2::decode(&change_bytes).map_err(|_| GuestAccumulateError::CorruptStore)?;
        if change.cid() != event.cid
            || change.workflow != [WorkflowOperationV2::Ingress(event.value.clone())]
        {
            return Err(GuestAccumulateError::CorruptStore);
        }
        let receipt_bytes = read(store, &crdt_node_receipt_storage_key(event.cid))?
            .ok_or(GuestAccumulateError::CorruptStore)?;
        let receipt = AccumulationReceiptV2::decode(&receipt_bytes)
            .map_err(|_| GuestAccumulateError::CorruptStore)?;
        let ingress = DirectIngressV2 {
            service: event.value.service.clone(),
            invocation: event.value.invocation,
            logical_timeslot: event.value.logical_timeslot,
            target: event.value.target,
            method: event.value.method.clone(),
            arguments: event.value.arguments.clone(),
            origin: event.value.origin,
            authorization: event.value.authorization.clone(),
            imported_blobs: event.value.imported_blobs.clone(),
            proof_requested: event.value.proof_requested,
            base: ConsistencyBaseV2::Crdt {
                heads: change.causal_dependencies.clone(),
            },
            base_causal_height: change.causal_height.checked_sub(1),
            crdt_change: Some(change),
        };
        let record = IngressRecordV2 {
            ingress,
            consumed: materialized.consumed_ingresses.contains(invocation),
            receipt,
        };
        write(
            store,
            &ingress_storage_key(*invocation),
            Some(&record.encode()),
        )?;
    }
    Ok(())
}

/// Reconstruct the service-level retry bridge for workflow checkpoints
/// imported from the causal DAG. These rows are excluded from the state tree,
/// so synchronizing only the checkpoint would leave failover unable to
/// authenticate the already-committed result.
fn apply_dedup_materialization<S: StateTreeStore>(
    store: &mut S,
    service: &super::ServiceIdentityV2,
    materialized: &WorkflowMaterializationV2,
) -> GuestResult<(), S::Error> {
    for event in &materialized.dedup_workflows {
        let checkpoint = &event.value;
        let change_bytes = read(store, &crdt_node_storage_key(event.cid))?
            .ok_or(GuestAccumulateError::CorruptStore)?;
        let change =
            CrdtChangeV2::decode(&change_bytes).map_err(|_| GuestAccumulateError::CorruptStore)?;
        let receipt_bytes = read(store, &crdt_node_receipt_storage_key(event.cid))?
            .ok_or(GuestAccumulateError::CorruptStore)?;
        let receipt = AccumulationReceiptV2::decode(&receipt_bytes)
            .map_err(|_| GuestAccumulateError::CorruptStore)?;
        if change.cid() != event.cid
            || checkpoint.transition_hash != event.cid
            || !crdt_receipt_matches_change(service, &change, &receipt)
        {
            return Err(GuestAccumulateError::CorruptStore);
        }
        let dedup = DedupRecordV2 {
            input: checkpoint.input,
            // The DAG checkpoint normalizes scheduling-only imports, while
            // the node itself retains the exact Refine work hash used by the
            // source's dedup record.
            work_hash: change.work_hash,
            transition_commitment: receipt.accepted_transition,
            receipt: receipt.clone(),
        };
        let dedup_key = dedup_storage_key(checkpoint.input);
        if let Some(existing) = read(store, &dedup_key)? {
            let existing =
                DedupRecordV2::decode(&existing).map_err(|_| GuestAccumulateError::CorruptStore)?;
            if existing != dedup {
                // A newly synchronized branch can precede the locally
                // materialized retry by canonical CID order. Both branches
                // were authenticated above; replace the retry bridge with
                // the deterministic winner instead of treating convergence
                // as store corruption.
                write(store, &dedup_key, Some(&dedup.encode()))?;
            }
        } else {
            write(store, &dedup_key, Some(&dedup.encode()))?;
        }
        let receipt_key = receipt_storage_key(checkpoint.input);
        if let Some(existing) = read(store, &receipt_key)? {
            let existing = AccumulationReceiptV2::decode(&existing)
                .map_err(|_| GuestAccumulateError::CorruptStore)?;
            if existing != receipt {
                write(store, &receipt_key, Some(&receipt.encode()))?;
            }
        } else {
            write(store, &receipt_key, Some(&receipt.encode()))?;
        }

        let publication_key = publication_storage_key(checkpoint.input);
        if let Some(existing) = read(store, &publication_key)? {
            let existing = PublicationRecordV2::decode(&existing)
                .map_err(|_| GuestAccumulateError::CorruptStore)?;
            let expected_published = crdt_published_effects(&change)?;
            if existing.input != checkpoint.input
                || !crdt_publication_matches_receipt(store, service, &existing)?
            {
                return Err(GuestAccumulateError::CorruptStore);
            }
            if existing.receipt != receipt || existing.published != expected_published {
                write(
                    store,
                    &publication_key,
                    Some(
                        &PublicationRecordV2 {
                            input: checkpoint.input,
                            receipt,
                            published: expected_published,
                        }
                        .encode(),
                    ),
                )?;
            }
        }
    }
    for admissions in materialized.reply_admissions.values() {
        let canonical = &admissions
            .first()
            .expect("reply-admission candidates are never empty")
            .value;
        let key = reply_admission_storage_key(canonical.call_id);
        if let Some(existing) = read(store, &key)? {
            let existing = ReplyAdmissionRecordV2::decode(&existing)
                .map_err(|_| GuestAccumulateError::CorruptStore)?;
            if !admissions
                .iter()
                .any(|candidate| candidate.value == existing)
            {
                return Err(GuestAccumulateError::CorruptStore);
            }
            if existing != *canonical {
                write(store, &key, Some(&canonical.encode()))?;
            }
        } else {
            write(store, &key, Some(&canonical.encode()))?;
        }
    }
    Ok(())
}

fn crdt_publication_matches_receipt<S: StateTreeStore>(
    store: &S,
    service: &super::ServiceIdentityV2,
    publication: &PublicationRecordV2,
) -> GuestResult<bool, S::Error> {
    for cid in &publication.receipt.resulting_crdt_heads {
        let Some(bytes) = read(store, &crdt_node_storage_key(*cid))? else {
            continue;
        };
        let Ok(change) = CrdtChangeV2::decode(&bytes) else {
            return Err(GuestAccumulateError::CorruptStore);
        };
        if change.cid() == *cid
            && crdt_receipt_matches_change(service, &change, &publication.receipt)
            && crdt_published_effects(&change)? == publication.published
        {
            return Ok(true);
        }
    }
    Ok(false)
}

fn crdt_published_effects<E>(
    change: &CrdtChangeV2,
) -> Result<PublishedEffectsV2, GuestAccumulateError<E>> {
    let mut reply = None;
    let mut outbox = Vec::new();
    for operation in &change.workflow {
        match operation {
            WorkflowOperationV2::Reply(candidate) if reply.is_none() => {
                reply = Some(candidate.clone());
            }
            WorkflowOperationV2::Reply(_) => return Err(GuestAccumulateError::CorruptStore),
            WorkflowOperationV2::Outbox(message) => outbox.push(message.clone()),
            _ => {}
        }
    }
    outbox.sort_by_key(|message| message.call_id);
    Ok(PublishedEffectsV2 {
        reply,
        outbox,
        exported_blobs: change.exported_blobs.clone(),
        proof: None,
        attestation: None,
    })
}

fn materialized_actors_exist<S: StateTreeStore>(
    tree: &ServiceStateTreeV2<'_, S>,
    materialized: &WorkflowMaterializationV2,
) -> GuestResult<bool, S::Error> {
    let mut actors = materialized
        .ingresses
        .values()
        .flatten()
        .map(|event| event.value.target)
        .chain(
            materialized
                .workflows
                .values()
                .flatten()
                .map(|event| event.value.resume_work.target),
        )
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
            if let Some(awaited_reply) = work.awaited_reply.as_ref() {
                let admission_bytes = read(
                    store,
                    &reply_admission_storage_key(awaited_reply.reply.call_id),
                )?
                .ok_or(GuestAccumulateError::CorruptStore)?;
                let admission = ReplyAdmissionRecordV2::decode(&admission_bytes)
                    .map_err(|_| GuestAccumulateError::CorruptStore)?;
                if admission.call_id != awaited_reply.reply.call_id
                    || admission.input != record.input
                    || admission.awaited_reply != *awaited_reply
                    || admission.work_hash != record.work_hash
                {
                    return Err(GuestAccumulateError::CorruptStore);
                }
            }
            Some(record.receipt)
        } else {
            return Ok(rejected(AccumulationRejectionV2::DivergentDuplicate));
        }
    } else {
        None
    };
    if duplicate_receipt.is_none()
        && let Some(awaited_reply) = work.awaited_reply.as_ref()
        && let Some(admission_bytes) = read(
            store,
            &reply_admission_storage_key(awaited_reply.reply.call_id),
        )?
    {
        let admission = ReplyAdmissionRecordV2::decode(&admission_bytes)
            .map_err(|_| GuestAccumulateError::CorruptStore)?;
        if admission.input == work.input_id()
            && admission.awaited_reply == *awaited_reply
            && admission.work_hash == work_hash
        {
            // This admission and its work-input dedup row are one atomic
            // bookkeeping unit. An exact orphan indicates corrupt storage.
            return Err(GuestAccumulateError::CorruptStore);
        }
        return Ok(rejected(AccumulationRejectionV2::DivergentDuplicate));
    }
    if mode == ApplyMode::Commit
        && let Some(receipt) = duplicate_receipt.clone()
    {
        // The accepted transition may itself have grown the actor directory.
        // Its guest-authenticated dedup row binds the complete old work and
        // transition, so an exact retry must return before comparing those
        // imports with the now-current tree.
        return Ok(AccumulationResultV2::Accepted {
            receipt,
            published: PublishedEffectsV2::default(),
            duplicate: true,
        });
    }

    let mut tree = ServiceStateTreeV2::new(store, header.service_root);
    let Some(mut directory) =
        tree_get_wire::<_, super::ActorDirectoryV2>(&tree, &StateKeyV2::ActorDirectory)?
    else {
        return Ok(rejected(AccumulationRejectionV2::WrongProgram));
    };
    if duplicate_receipt.is_none()
        && !directory
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
    if actor.deployment != work.target_deployment
        || transition.target_deployment != actor.deployment
        || actor.program != work.target_program
        || transition.target_program != actor.program
    {
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
    if !authorized(work, &policy, tree.store_ref())? {
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
        if mode != ApplyMode::PrepareAttested {
            return Err(GuestAccumulateError::CorruptStore);
        }
        let mut preparation = match AttestationPreparationV2::for_transition(
            work,
            transition,
            &policy,
            &actor.name,
            actor.producer,
            receipt,
        ) {
            Ok(preparation) => preparation,
            Err(_) => return Ok(rejected(AccumulationRejectionV2::InvalidProof)),
        };
        let Some(bytes) = read(store, &publication_storage_key(work.input_id()))? else {
            return Err(GuestAccumulateError::CorruptStore);
        };
        let publication =
            PublicationRecordV2::decode(&bytes).map_err(|_| GuestAccumulateError::CorruptStore)?;
        let Some(proof) = publication.published.proof.clone() else {
            return Err(GuestAccumulateError::CorruptStore);
        };
        let Some(delivery) = publication.published.attestation.as_ref() else {
            return Err(GuestAccumulateError::CorruptStore);
        };
        if publication.input != work.input_id()
            || publication.receipt != preparation.receipt
            || publication.published.reply != transition.reply
            || publication.published.outbox != transition.outbox
            || publication.published.exported_blobs != transition.exported_blobs
            || proof.statement != preparation.statement.commitment()
            || delivery.producer_name != actor.name
            || delivery.producer != actor.producer
            || delivery.statement != preparation.statement
            || delivery.proof != proof
        {
            return Err(GuestAccumulateError::CorruptStore);
        }
        preparation.committed_proof = Some(proof);
        return Ok(AccumulationResultV2::Prepared(preparation));
    }
    if !work_matches_durable_ingress(tree.store_ref(), work)? {
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
    let mut crdt_frontiers = match validate_crdt(tree.store_ref(), &header, work, transition)? {
        CrdtValidationV2::Linear => None,
        CrdtValidationV2::Frontiers(frontiers) => Some(frontiers),
        CrdtValidationV2::Rejected(rejection) => return Ok(rejected(rejection)),
    };
    let base_workflow = crdt_frontiers
        .as_ref()
        .map(|frontiers| materialize_workflow_crdt(&frontiers.base, &header.service))
        .transpose()
        .map_err(|_| GuestAccumulateError::CorruptStore)?;
    if !valid_workflow_input(&tree, work, base_workflow.as_ref())? {
        return Ok(rejected(AccumulationRejectionV2::InvalidWorkflowTransition));
    }
    if !work_matches_durable_inbox(&tree, work)? {
        return Ok(rejected(AccumulationRejectionV2::InvalidWorkflowTransition));
    }
    if header.consistency != ConsistencyModeV2::Crdt && header.revision == u64::MAX {
        return Ok(rejected(AccumulationRejectionV2::SequenceOverflow));
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
        if descriptor.deployment != imported.deployment || descriptor.program != imported.program {
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
            let frontier = &crdt_frontiers
                .as_ref()
                .ok_or(GuestAccumulateError::CorruptStore)?
                .base;
            let expected = frontier
                .actor_materializations(&descriptor)
                .map_err(|CausalSelectionError::Corrupt| GuestAccumulateError::CorruptStore)?;
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
    let external_directory =
        tree_get_wire::<_, ExternalActorDirectoryV2>(&tree, &StateKeyV2::ExternalActorDirectory)?
            .ok_or(GuestAccumulateError::CorruptStore)?;
    if external_directory.actors != work.external_actors {
        return Ok(rejected(AccumulationRejectionV2::InvalidWorkflowTransition));
    }

    if header.consistency == ConsistencyModeV2::Crdt && !transition.spawns.is_empty() {
        // Tree membership and package metadata need explicit causal
        // operations before replicas may merge child creation safely.
        return Ok(rejected(AccumulationRejectionV2::InvalidConsistency));
    }
    if directory
        .actors
        .len()
        .saturating_add(transition.spawns.len())
        > super::MAX_ROOT_TREE_ACTORS
    {
        return Ok(rejected(AccumulationRejectionV2::InvalidWorkflowTransition));
    }
    let mut spawned_names = BTreeSet::new();
    let mut spawn_descriptors = Vec::with_capacity(transition.spawns.len());
    for spawn in &transition.spawns {
        let Some(parent) =
            tree_get_wire::<_, ActorGenesisV2>(&tree, &StateKeyV2::ActorDescriptor(spawn.parent))?
        else {
            return Ok(rejected(AccumulationRejectionV2::InvalidWorkflowTransition));
        };
        let existing_name = directory.actors.iter().try_fold(false, |found, actor| {
            if found {
                return Ok(true);
            }
            let descriptor =
                tree_get_wire::<_, ActorGenesisV2>(&tree, &StateKeyV2::ActorDescriptor(*actor))?
                    .ok_or(GuestAccumulateError::CorruptStore)?;
            Ok::<_, GuestAccumulateError<S::Error>>(
                descriptor.parent == Some(spawn.parent) && descriptor.name == spawn.name,
            )
        })?;
        if spawn.actor != ActorId::owned_child(spawn.parent, &spawn.name)
            || directory.actors.binary_search(&spawn.actor).is_ok()
            || existing_name
            || !spawned_names.insert((spawn.parent, spawn.name.clone()))
        {
            return Ok(rejected(AccumulationRejectionV2::InvalidWorkflowTransition));
        }
        let mut child = parent;
        child.actor = spawn.actor;
        child.name = spawn.name.clone();
        child.parent = Some(spawn.parent);
        child.initial_state = spawn.initial_state.clone();
        child.crdt = false;
        spawn_descriptors.push(child);
    }

    if let Some(rejection) = validate_continuation_change(tree.store_ref(), envelope)? {
        return Ok(rejected(rejection));
    }
    if let Some(rejection) = validate_awaited_outcome(&tree, work, base_workflow.as_ref())? {
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
            || external_directory
                .actors
                .iter()
                .all(|binding| binding.actor != message.to || binding.service != message.to_service)
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
        if proof_blob == Some(&candidate.reference) {
            // Proof artifacts are verifier/CAS inputs rather than service
            // state. Their content identity is checked here, while the host's
            // PROOF_VERIFY capability reads the same bytes from its external
            // proof store. They must never enter the recoverable service image.
            if !candidate.reference.matches(&candidate.bytes) {
                return Ok(rejected(AccumulationRejectionV2::InvalidProof));
            }
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
    for (spawn, descriptor) in transition.spawns.iter().zip(&spawn_descriptors) {
        let insert_at = match directory.actors.binary_search(&spawn.actor) {
            Err(index) => index,
            Ok(_) => {
                return Ok(rejected(AccumulationRejectionV2::InvalidWorkflowTransition));
            }
        };
        directory.actors.insert(insert_at, spawn.actor);
        tree_apply(
            &mut tree,
            &StateKeyV2::ActorDescriptor(spawn.actor),
            Some(&descriptor.encode()),
        )?;
        let policies = super::PackageRolePoliciesV2::decode(&descriptor.role_policies)
            .map_err(|_| GuestAccumulateError::CorruptStore)?;
        for policy in policies.methods {
            tree_apply(
                &mut tree,
                &StateKeyV2::MethodPolicy {
                    actor: spawn.actor,
                    method: policy.method.clone(),
                },
                Some(&policy.encode()),
            )?;
        }
        tree_apply(
            &mut tree,
            &actor_state_key(header.consistency, spawn.actor),
            Some(&spawn.initial_state.encode()),
        )?;
    }
    if !transition.spawns.is_empty() {
        tree_apply(
            &mut tree,
            &StateKeyV2::ActorDirectory,
            Some(&directory.encode()),
        )?;
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
    // The inbox row authorizes only the initial callee slice. Consume it in
    // the same guest-owned update as actor writes, the continuation, effects,
    // and dedup record. Later slices are authorized by the workflow checkpoint
    // plus continuation and do not require the already-consumed inbox.
    if work.workflow_step == 0
        && let Some(call) = work.parent_call
    {
        tree_apply(&mut tree, &StateKeyV2::Inbox(call), None)?;
    }
    // A finalized reply consumes the caller's matching durable request in the
    // same guest-owned transaction as the resumed actor state and dedup row.
    if let Some(awaited) = work.awaited_reply.as_ref() {
        tree_apply(&mut tree, &StateKeyV2::Outbox(awaited.reply.call_id), None)?;
        write(
            tree.store_mut(),
            &pending_call_deadline_storage_key(awaited.reply.call_id),
            None,
        )?;
    }
    if let Some(awaited) = work.awaited_timeout.as_ref() {
        write(
            tree.store_mut(),
            &pending_call_deadline_storage_key(awaited.expiration.timeout.call_id),
            None,
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
        if let Some(deadline_timeslot) = message.deadline_timeslot {
            let deadline = PendingCallDeadlineV2 {
                call_id: message.call_id,
                caller_invocation: message.caller_invocation,
                deadline_timeslot,
            };
            write(
                tree.store_mut(),
                &pending_call_deadline_storage_key(message.call_id),
                Some(&deadline.encode()),
            )?;
        }
    }
    // `WorkEnvelopeV2` is intentionally complete and therefore large. Keep
    // the durable workflow value off the bounded service-PVM stack while its
    // nested wire encoder is active.
    let workflow = alloc::boxed::Box::new(WorkflowCheckpointV2 {
        input: work.input_id(),
        workflow_identity: work.workflow_identity(),
        resume_work: work.clone(),
        work_hash,
        // A CRDT workflow checkpoint must be reconstructible from the causal
        // DAG without importing the outer Transition wire. Its authenticated
        // node CID is therefore the portable slice commitment.
        transition_hash: if header.consistency == ConsistencyModeV2::Crdt {
            transition
                .crdt_change
                .as_ref()
                .expect("validated CRDT transition")
                .cid()
        } else {
            transition_commitment
        },
    });
    tree_apply(
        &mut tree,
        &StateKeyV2::Workflow(work.invocation),
        Some(&workflow.encode()),
    )?;
    header.service_root = tree.root();
    drop(tree);

    if work.workflow_step == 0
        && let Some(call) = work.parent_call
    {
        let key = delivery_storage_key(call);
        if let Some(bytes) = read(store, &key)? {
            let mut delivery =
                DeliveryRecordV2::decode(&bytes).map_err(|_| GuestAccumulateError::CorruptStore)?;
            if delivery.call_id != call || delivery.consumed {
                return Err(GuestAccumulateError::CorruptStore);
            }
            delivery.consumed = true;
            write(store, &key, Some(&delivery.encode()))?;
        }
    }
    if work.workflow_step == 0 && work.parent_call.is_none() {
        let key = ingress_storage_key(work.invocation);
        if let Some(bytes) = read(store, &key)? {
            let mut ingress =
                IngressRecordV2::decode(&bytes).map_err(|_| GuestAccumulateError::CorruptStore)?;
            if ingress.consumed || !ingress.ingress.matches_work(work) {
                return Err(GuestAccumulateError::CorruptStore);
            }
            ingress.consumed = true;
            write(store, &key, Some(&ingress.encode()))?;
        }
    }

    let mut resulting_frontier = None;
    let (resulting_state_root, resulting_crdt_heads, sequence) =
        if header.consistency == ConsistencyModeV2::Crdt {
            let change = transition
                .crdt_change
                .as_ref()
                .expect("validated CRDT transition");
            let cid = change.cid();
            write_crdt_change(store, change, cid)?;
            let frontier = crdt_frontiers
                .take()
                .ok_or(GuestAccumulateError::CorruptStore)?
                .union
                .with_change(&header.crdt_heads, change.clone())
                .ok_or(GuestAccumulateError::CorruptStore)?;
            header.crdt_heads = frontier.canonical_heads();
            resulting_frontier = Some(frontier);
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
        rematerialize_crdt_service(
            store,
            &mut header,
            resulting_frontier
                .as_ref()
                .ok_or(GuestAccumulateError::CorruptStore)?,
        )?;
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
            &actor.name,
            actor.producer,
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
        let statement = &preparation
            .as_ref()
            .expect("attested preparation was required")
            .statement;
        if proof.statement != statement.commitment() {
            return Ok(rejected(AccumulationRejectionV2::InvalidProof));
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
    header.admission_timeslot_high_water = header
        .admission_timeslot_high_water
        .max(work.logical_timeslot);
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
    if let Some(awaited_reply) = work.awaited_reply.as_ref() {
        let admission = ReplyAdmissionRecordV2 {
            call_id: awaited_reply.reply.call_id,
            input: work.input_id(),
            awaited_reply: awaited_reply.clone(),
            work_hash,
        };
        write(
            store,
            &reply_admission_storage_key(admission.call_id),
            Some(&admission.encode()),
        )?;
    }
    if let Some(change) = transition.crdt_change.as_ref() {
        write_crdt_node_receipt(store, change.cid(), &receipt)?;
    }

    let published_attestation = match (preparation.as_ref(), attached_proof) {
        (Some(preparation), Some(proof)) if mode == ApplyMode::Commit => {
            Some(Box::new(super::AttestationDeliveryV2 {
                producer_name: actor.name.clone(),
                producer: actor.producer,
                statement: preparation.statement.clone(),
                proof: proof.clone(),
            }))
        }
        _ => None,
    };
    let published = PublishedEffectsV2 {
        reply: transition.reply.clone(),
        outbox: transition.outbox.clone(),
        exported_blobs: transition.exported_blobs.clone(),
        proof: attached_proof.cloned(),
        attestation: published_attestation,
    };
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

struct ValidatedCrdtFrontiersV2 {
    base: CausalFrontierV2,
    union: CausalFrontierV2,
}

enum CrdtValidationV2 {
    Linear,
    Frontiers(ValidatedCrdtFrontiersV2),
    Rejected(AccumulationRejectionV2),
}

fn validate_crdt<S: GuestAccumulateStoreV2>(
    store: &S,
    header: &StoreHeaderV2,
    work: &super::WorkEnvelopeV2,
    transition: &super::TransitionV2,
) -> GuestResult<CrdtValidationV2, S::Error> {
    if header.consistency != ConsistencyModeV2::Crdt {
        return Ok(if transition.crdt_change.is_some() {
            CrdtValidationV2::Rejected(AccumulationRejectionV2::InvalidConsistency)
        } else {
            CrdtValidationV2::Linear
        });
    }
    let Some(change) = transition.crdt_change.as_ref() else {
        return Ok(CrdtValidationV2::Rejected(
            AccumulationRejectionV2::InvalidConsistency,
        ));
    };
    let ConsistencyBaseV2::Crdt { heads } = &work.base else {
        return Ok(CrdtValidationV2::Rejected(
            AccumulationRejectionV2::InvalidConsistency,
        ));
    };
    if !transition.writes.is_empty()
        || Some(change.id) != CrdtChangeV2::derive_id(work)
        || change.work_hash != work.hash()
        || change.causal_dependencies.as_slice() != heads.as_slice()
        || change.workflow != transition.workflow_operations(work)
        || change.awaited_reply != work.awaited_reply
        || change.exported_blobs != transition.exported_blobs
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
        return Ok(CrdtValidationV2::Rejected(
            AccumulationRejectionV2::InvalidWorkflowTransition,
        ));
    }
    if let Some(existing) = read(store, &crdt_change_storage_key(change.id))? {
        if existing.as_slice() != change.cid().0 {
            return Ok(CrdtValidationV2::Rejected(
                AccumulationRejectionV2::DivergentDuplicate,
            ));
        }
    }
    let mut union_heads = header.crdt_heads.clone();
    union_heads.extend(heads.iter().copied());
    union_heads.sort();
    union_heads.dedup();
    let union =
        match load_causal_frontier(&union_heads, |cid| store.read(&crdt_node_storage_key(cid))) {
            Ok(frontier) => frontier,
            Err(CausalFrontierError::Storage(error)) => {
                return Err(GuestAccumulateError::Storage(error));
            }
            Err(CausalFrontierError::Missing(cid)) => {
                return Ok(CrdtValidationV2::Rejected(
                    AccumulationRejectionV2::MissingCausalDependency(cid),
                ));
            }
            Err(CausalFrontierError::Corrupt) => return Err(GuestAccumulateError::CorruptStore),
        };
    let base = union
        .at_heads(heads)
        .ok_or(GuestAccumulateError::CorruptStore)?;
    let max_height = base.max_head_height;
    if work.base_causal_height != Some(max_height)
        || max_height.checked_add(1) != Some(change.causal_height)
    {
        return Ok(CrdtValidationV2::Rejected(
            AccumulationRejectionV2::InvalidWorkflowTransition,
        ));
    }
    Ok(CrdtValidationV2::Frontiers(ValidatedCrdtFrontiersV2 {
        base,
        union,
    }))
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
    frontier: &CausalFrontierV2,
) -> GuestResult<(), S::Error> {
    let materialized = materialize_workflow_crdt(frontier, &header.service)
        .map_err(|_| GuestAccumulateError::CorruptStore)?;
    apply_expiration_materialization(store, &header.service, &materialized)?;
    apply_ingress_materialization(store, &materialized)?;
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
    is_sorted_unique_by(&transition.spawns, |spawn| spawn.actor.0)
        && transition.spawns.iter().all(|spawn| {
            spawn.actor == ActorId::owned_child(spawn.parent, &spawn.name)
                && work
                    .imported_actors
                    .binary_search_by_key(&spawn.parent, |actor| actor.actor)
                    .is_ok()
                && work
                    .imported_actors
                    .binary_search_by_key(&spawn.actor, |actor| actor.actor)
                    .is_err()
        })
        && is_sorted_unique_by(&transition.continuations, |change| change.actor.0)
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

fn authorized<S: GuestAccumulateStoreV2>(
    work: &super::WorkEnvelopeV2,
    policy: &MethodPolicyV2,
    store: &S,
) -> GuestResult<bool, S::Error> {
    if method_role_policy_hash(policy.space_role, policy.actor_role) != Some(policy.policy)
        || policy.public != (policy.space_role.is_none() && policy.actor_role.is_none())
    {
        return Ok(false);
    }
    Ok(match &work.authorization {
        AuthorizationEvidenceV2::Public => policy.public && policy.policy == public_policy_hash(),
        AuthorizationEvidenceV2::Credential {
            policy: supplied_policy,
            credential_commitment,
            bytes,
        } => {
            let Ok(credential) = RoleCredentialV2::decode(bytes) else {
                return Ok(false);
            };
            let Some(verification) = RoleCredentialVerificationRequestV2::for_work(work) else {
                return Ok(false);
            };
            !policy.public
                && credential.holder == work.origin
                // Step zero binds the credential to the original arguments.
                // Later slices omit those dead bytes; their unchanged
                // authorization is pinned by the committed workflow identity
                // and exact continuation checks below.
                && (work.workflow_step != 0
                    || credential.scope == work.authorization_scope())
                && policy.space_role.is_none_or(|required| {
                    credential
                        .space_role
                        .is_some_and(|actual| actual.as_u8() >= required)
                })
                && policy.actor_role.is_none_or(|required| {
                    credential
                        .actor_role
                        .is_some_and(|actual| actual >= required)
                })
                && *supplied_policy == policy.policy
                && *credential_commitment == credential.commitment()
                && store
                    .verify_role_credential(&verification)
                    .map_err(GuestAccumulateError::Storage)?
        }
        AuthorizationEvidenceV2::PrivateCredential {
            policy: supplied_policy,
            credential_commitment,
            witness,
        } => {
            !policy.public
                && (policy.attested || work.proof_requested)
                && (policy.space_role.is_some() || policy.actor_role.is_some())
                && matches!(
                    work.origin,
                    super::Origin::Member(_) | super::Origin::Actor(_)
                )
                && *supplied_policy == policy.policy
                && *credential_commitment != Hash::ZERO
                && witness.len != 0
        }
        // A future statement version will bind platform authority keys. Until
        // then System is an identity class, never an authorization bypass.
        AuthorizationEvidenceV2::SystemCapability { .. } => false,
    })
}

fn work_matches_durable_inbox<S: StateTreeStore>(
    tree: &ServiceStateTreeV2<'_, S>,
    work: &super::WorkEnvelopeV2,
) -> GuestResult<bool, S::Error> {
    // Accumulate consumed the initial inbox atomically with the preceding
    // checkpoint. Workflow identity and the continuation bind later slices.
    if work.workflow_step != 0 {
        return Ok(work
            .causal_context
            .as_ref()
            .and_then(|context| context.deadline_timeslot)
            .is_none_or(|deadline| work.logical_timeslot < deadline));
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
        && work.causal_context == Some(super::CausalCallContextV2::from(&message))
        && work.origin == super::Origin::Actor(message.from)
        && work.authorization == message.authorization
        && work.arguments == message.payload
        && message
            .deadline_timeslot
            .is_none_or(|deadline| work.logical_timeslot < deadline)
        && method.as_deref() == Some(work.method.as_str()))
}

fn work_matches_durable_ingress<S: StateTreeStore>(
    store: &S,
    work: &super::WorkEnvelopeV2,
) -> GuestResult<bool, S::Error> {
    if work.workflow_step != 0 || work.parent_call.is_some() {
        return Ok(true);
    }
    let Some(bytes) = read(store, &ingress_storage_key(work.invocation))? else {
        return Ok(false);
    };
    let record = IngressRecordV2::decode(&bytes).map_err(|_| GuestAccumulateError::CorruptStore)?;
    Ok(!record.consumed && record.ingress.matches_work(work))
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
        return Ok(
            (current.is_some() || !envelope.transition.outbox.is_empty())
                .then_some(AccumulationRejectionV2::InvalidWorkflowTransition),
        );
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

    if let (Some(current), Some(next)) = (current, next.as_ref()) {
        let Some(bytes) = store
            .load_blob(current)
            .map_err(GuestAccumulateError::Storage)?
        else {
            return Ok(Some(AccumulationRejectionV2::MissingBlob(current.hash)));
        };
        if BlobRefV2::of_bytes(&bytes) != *current {
            return Err(GuestAccumulateError::CorruptStore);
        }
        let previous = match ContinuationSnapshotV2::decode_metadata(&bytes) {
            Ok(snapshot) if snapshot.validate_resume_for(work).is_ok() => snapshot,
            _ => {
                return Ok(Some(AccumulationRejectionV2::InvalidWorkflowTransition));
            }
        };
        if previous.programs != next.programs {
            // Restoring and checkpointing again cannot add, drop, reorder, or
            // replace a VM in the invocation layout frozen by the old JAR
            // snapshot, even if the complete current directory has changed.
            return Ok(Some(AccumulationRejectionV2::InvalidWorkflowTransition));
        }
    }

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

    match next.as_ref().and_then(|snapshot| snapshot.pending_call) {
        Some(call)
            if envelope.transition.outbox.len() == 1
                && envelope.transition.outbox[0].call_id == call
                && next.as_ref().and_then(|snapshot| snapshot.pending_actor)
                    == Some(envelope.transition.outbox[0].from) => {}
        None if envelope.transition.outbox.is_empty() => {}
        _ => {
            return Ok(Some(AccumulationRejectionV2::InvalidWorkflowTransition));
        }
    }
    Ok(None)
}

fn validate_awaited_outcome<S: GuestAccumulateStoreV2>(
    tree: &ServiceStateTreeV2<'_, S>,
    work: &super::WorkEnvelopeV2,
    crdt_base: Option<&WorkflowMaterializationV2>,
) -> GuestResult<Option<AccumulationRejectionV2>, S::Error> {
    let current = work
        .imported_actors
        .iter()
        .find(|actor| actor.actor == work.target)
        .and_then(|actor| actor.continuation.as_ref());
    let Some(current) = current else {
        return Ok(
            (work.awaited_reply.is_some() || work.awaited_timeout.is_some())
                .then_some(AccumulationRejectionV2::InvalidWorkflowTransition),
        );
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
    let call = match (
        snapshot.pending_call,
        work.awaited_reply.as_ref(),
        work.awaited_timeout.as_ref(),
    ) {
        (None, None, None) => return Ok(None),
        (Some(call), Some(awaited), None) if awaited.reply.call_id == call => call,
        (Some(call), None, Some(awaited)) if awaited.expiration.timeout.call_id == call => {
            let Some(bytes) = tree
                .store_ref()
                .read(&call_expiration_storage_key(call))
                .map_err(GuestAccumulateError::Storage)?
            else {
                return Ok(Some(AccumulationRejectionV2::InvalidWorkflowTransition));
            };
            let committed = AccumulatedTimeoutV2::decode(&bytes)
                .map_err(|_| GuestAccumulateError::CorruptStore)?;
            let pending_outbox = match crdt_base {
                Some(materialized) => materialized
                    .outbox
                    .get(&call)
                    .is_some_and(|values| values.iter().any(|value| value.value.is_some())),
                None => {
                    tree_get_wire::<_, MessageRecordV2>(tree, &StateKeyV2::Outbox(call))?.is_some()
                }
            };
            if committed != **awaited
                || awaited.validate().is_err()
                || awaited.expiration.service != work.service
                || awaited.expiration.timeout.caller_invocation != work.invocation
                || awaited.expiration.timeout.checkpoint_step.checked_add(1)
                    != Some(work.workflow_step)
                || awaited.expiration.timeout.await_ordinal != snapshot.await_ordinal
                || Some(awaited.expiration.timeout.caller_actor) != snapshot.pending_actor
                || pending_outbox
            {
                return Ok(Some(AccumulationRejectionV2::InvalidWorkflowTransition));
            }
            return Ok(None);
        }
        _ => {
            return Ok(Some(AccumulationRejectionV2::InvalidWorkflowTransition));
        }
    };
    let awaited = work
        .awaited_reply
        .as_ref()
        .expect("reply outcome was selected above");
    let message = match crdt_base {
        Some(materialized) => materialized
            .outbox
            .get(&call)
            .and_then(|values| values.iter().find_map(|value| value.value.clone())),
        None => tree_get_wire::<_, MessageRecordV2>(tree, &StateKeyV2::Outbox(call))?,
    };
    let Some(message) = message else {
        return Ok(Some(AccumulationRejectionV2::InvalidWorkflowTransition));
    };
    let Some(external) =
        tree_get_wire::<_, ExternalActorDirectoryV2>(tree, &StateKeyV2::ExternalActorDirectory)?
            .and_then(|directory| {
                directory
                    .actors
                    .into_iter()
                    .find(|binding| binding.actor == message.to)
            })
    else {
        return Ok(Some(AccumulationRejectionV2::InvalidReceipt));
    };
    let attestation_matches_binding = awaited.attestation.as_ref().is_none_or(|attestation| {
        attestation.producer_name == external.name
            && attestation.producer == external.producer
            && attestation.statement.actor == external.actor
            && attestation.statement.deployment == external.actor_deployment
            && attestation.statement.actor_program == external.program
            && attestation.statement.accumulation_receipt.service == external.service
            && awaited.validate().is_ok()
    });
    if message.call_id != call
        || message.caller_invocation != work.invocation
        || message.await_ordinal != snapshot.await_ordinal
        || snapshot.pending_actor != Some(message.from)
        || message.to != awaited.reply.producer
        || message.proof_requested != awaited.attestation.is_some()
        || message
            .deadline_timeslot
            .is_some_and(|deadline| work.logical_timeslot >= deadline)
        || awaited.receipt.reply_commitment != Some(awaited.reply.commitment())
        || awaited.receipt.service.service_abi != ABI_VERSION
        || awaited.receipt.service.execution_semantics != EXECUTION_SEMANTICS_ID
        || awaited.receipt.service.root_service == work.service.root_service
        || awaited.receipt.service != external.service
        || !attestation_matches_binding
    {
        return Ok(Some(AccumulationRejectionV2::InvalidReceipt));
    }
    // Reject obviously oversized inline results before cloning or encoding
    // attacker-controlled bytes. The full envelope carries additional fixed
    // fields, so a result this large can never fit the injection window.
    if awaited.reply.result.len() >= CHECKPOINT_TOKEN_CAPACITY {
        return Ok(Some(AccumulationRejectionV2::InvalidReceipt));
    }
    let injection = AwaitResumeV2 {
        checkpoint: CheckpointTokenV2 {
            input: work.input_id(),
            base: work.base.clone(),
            work_hash: work.hash(),
            resume_work: Some(work.clone()),
            base_causal_height: work.base_causal_height,
            change: CrdtChangeV2::derive_operation_scope(work)
                .map(|change| CrdtDispatchV2 { change, ordinal: 0 }),
            expected: Some(current.hash),
            replacement: None,
            pending_call: Some(call),
            pending_actor: snapshot.pending_actor,
            previously_suspended: snapshot.suspended_actors.clone(),
            suspended: Vec::new(),
        },
        reply: awaited.reply.clone(),
        // Accumulate validates only the fixed suspension buffer bound here.
        // Refine resolves and stages an attestation proof from its imported
        // blob, then supplies the concrete proof window in this descriptor.
        attestation: None,
    };
    if injection.encode().len() > CHECKPOINT_TOKEN_CAPACITY {
        return Ok(Some(AccumulationRejectionV2::InvalidReceipt));
    }
    let request = ReceiptVerificationRequestV2 {
        expected_producer: awaited.reply.producer,
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
        .chain(transition.spawns.iter().map(|spawn| &spawn.initial_state))
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
/// walk each new outbound call through its causal parents. A locally staged
/// inbox row identifies the root slice as its sender; an outbound awaited call
/// is separately bound to the exact active actor recorded by the JAR
/// checkpoint. A nested sender may extend the root's exact authenticated
/// parent call, but older child edges must originate at their parent recipient.
/// No call may extend a parent deadline or target an actor already present in
/// its causal caller chain.
fn validate_durable_messages<S: StateTreeStore>(
    tree: &ServiceStateTreeV2<'_, S>,
    work: &super::WorkEnvelopeV2,
    transition: &super::TransitionV2,
) -> GuestResult<Option<AccumulationRejectionV2>, S::Error> {
    if transition
        .inbox
        .iter()
        .any(|message| message.from != work.target || message.from_service != work.service)
        || transition.outbox.iter().any(|message| {
            message.from_service != work.service
                || work
                    .imported_actors
                    .binary_search_by_key(&message.from, |actor| actor.actor)
                    .is_err()
        })
    {
        return Ok(Some(AccumulationRejectionV2::InvalidWorkflowTransition));
    }
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
        let mut current = super::CausalCallContextV2::from(message);
        let mut visited = BTreeSet::new();
        let mut first_parent = true;
        while let Some(parent_id) = current.parent {
            if !visited.insert(parent_id) || parent_id == message.call_id {
                return Ok(Some(AccumulationRejectionV2::MessageCycle));
            }
            let Some(parent) =
                lookup_message(tree, &staged, work.causal_context.as_ref(), parent_id)?
            else {
                return Ok(Some(AccumulationRejectionV2::InvalidWorkflowTransition));
            };
            let crosses_inline_tree = first_parent
                && work.parent_call == Some(parent_id)
                && parent.to == work.target
                && current.call_id == message.call_id;
            if parent.to != current.from && !crosses_inline_tree {
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
            first_parent = false;
        }
    }
    Ok(None)
}

fn lookup_message<S: StateTreeStore>(
    tree: &ServiceStateTreeV2<'_, S>,
    staged: &BTreeMap<super::CallId, MessageRecordV2>,
    retained: Option<&super::CausalCallContextV2>,
    call: super::CallId,
) -> GuestResult<Option<super::CausalCallContextV2>, S::Error> {
    if let Some(message) = staged.get(&call) {
        return Ok(Some(super::CausalCallContextV2::from(message)));
    }
    if let Some(context) = retained.filter(|context| context.call_id == call) {
        return Ok(Some(context.clone()));
    }
    let inbox = tree_get_wire::<_, MessageRecordV2>(tree, &StateKeyV2::Inbox(call))?;
    let outbox = tree_get_wire::<_, MessageRecordV2>(tree, &StateKeyV2::Outbox(call))?;
    match (inbox, outbox) {
        (Some(_), Some(_)) => Err(GuestAccumulateError::CorruptStore),
        (Some(message), None) | (None, Some(message)) => {
            Ok(Some(super::CausalCallContextV2::from(&message)))
        }
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

    fn role_policies(methods: Vec<MethodPolicyV2>) -> Vec<u8> {
        crate::v2::PackageRolePoliciesV2 { methods }.encode()
    }

    #[derive(Debug, Clone, Copy, PartialEq, Eq)]
    enum MemError {
        Injected,
    }

    #[derive(Debug, Clone, Default, PartialEq, Eq)]
    struct MemStore {
        rows: BTreeMap<Vec<u8>, Vec<u8>>,
        blobs: BTreeMap<Hash, Vec<u8>>,
        proof_blobs: BTreeMap<Hash, Vec<u8>>,
        programs: BTreeMap<ProgramId, Vec<u8>>,
        proof_allowlist: BTreeSet<Hash>,
        role_credential_allowlist: BTreeSet<Hash>,
        receipt_allowlist: BTreeSet<Hash>,
        upgrade_allowlist: BTreeSet<Hash>,
        writes_before_failure: Option<usize>,
        deny_install: bool,
        logical_timeslot: Option<u64>,
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
        fn logical_timeslot(&self) -> Result<Option<u64>, Self::Error> {
            Ok(self.logical_timeslot)
        }

        fn authorize_install(&self, _genesis: &ServiceGenesisV2) -> Result<bool, Self::Error> {
            Ok(!self.deny_install)
        }

        fn authorize_upgrade(&self, upgrade: &ActorUpgradeV2) -> Result<bool, Self::Error> {
            Ok(self.upgrade_allowlist.contains(&upgrade.hash()))
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
            request: &ProofVerificationRequestV2,
        ) -> Result<ProofVerificationV2, Self::Error> {
            Ok(
                if self.proof_allowlist.contains(&request.hash())
                    && self
                        .proof_blobs
                        .get(&request.proof_blob.hash)
                        .is_some_and(|bytes| request.proof_blob.matches(bytes))
                {
                    ProofVerificationV2::Valid
                } else {
                    ProofVerificationV2::Unavailable
                },
            )
        }

        fn verify_role_credential(
            &self,
            request: &RoleCredentialVerificationRequestV2,
        ) -> Result<bool, Self::Error> {
            Ok(self.role_credential_allowlist.contains(&request.hash()))
        }

        fn program_available(&self, program: ProgramId) -> Result<bool, Self::Error> {
            Ok(self
                .programs
                .get(&program)
                .is_some_and(|pvm| ProgramId::of_pvm(pvm) == program))
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

    const FIXTURE_ACTOR_PVM: &[u8] = b"fixture actor pvm";

    fn program() -> ProgramId {
        ProgramId::of_pvm(FIXTURE_ACTOR_PVM)
    }

    fn external_bindings() -> Vec<super::super::ExternalActorBindingV2> {
        [
            ("peer-41", ActorId([41; 32]), 42u8),
            ("peer-44", ActorId([44; 32]), 45u8),
        ]
        .into_iter()
        .map(|(name, actor, byte)| {
            let mut service = identity();
            service.root_service = RootServiceId([byte; 32]);
            service.deployment = DeploymentId([byte.wrapping_add(1); 32]);
            super::super::ExternalActorBindingV2 {
                name: name.into(),
                service,
                actor,
                producer: super::super::ProducerId([byte; 32]),
                actor_deployment: DeploymentId([byte.wrapping_add(1); 32]),
                program: program(),
            }
        })
        .collect()
    }

    fn install_fixture(
        store: &mut MemStore,
        consistency: ConsistencyModeV2,
        initial: &[u8],
    ) -> (BlobRefV2, ServiceInstallReceiptV2) {
        let initial = store.provide_blob(initial).unwrap();
        store.programs.insert(program(), FIXTURE_ACTOR_PVM.to_vec());
        let request = AccumulateRequestV2::Install(ServiceGenesisV2 {
            external_actors: external_bindings(),
            service: identity(),
            consistency,
            actors: vec![ActorGenesisV2 {
                actor: actor(),
                name: "root".into(),
                parent: None,
                producer: super::super::ProducerId([4; 32]),
                deployment: identity().deployment,
                program: program(),
                initial_state: initial.clone(),
                crdt: consistency == ConsistencyModeV2::Crdt,
                role_policies: role_policies(vec![MethodPolicyV2 {
                    method: "set".into(),
                    schema: Hash([6; 32]),
                    policy: public_policy_hash(),
                    public: true,
                    attested: false,
                    space_role: None,
                    actor_role: None,
                }]),
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
    fn install_authorization_is_checked_before_availability_or_state_writes() {
        let mut store = MemStore {
            deny_install: true,
            ..MemStore::default()
        };
        let initial = BlobRefV2::of_bytes(b"unavailable state");
        let genesis = ServiceGenesisV2 {
            external_actors: vec![],
            service: identity(),
            consistency: ConsistencyModeV2::Local,
            actors: vec![ActorGenesisV2 {
                actor: actor(),
                name: "root".into(),
                parent: None,
                producer: super::super::ProducerId([4; 32]),
                deployment: identity().deployment,
                program: program(),
                initial_state: initial,
                crdt: false,
                role_policies: role_policies(vec![]),
            }],
            authorization: AuthorizationEvidenceV2::SystemCapability {
                capability: super::super::SystemCapabilityId([8; 32]),
                authenticator: vec![9],
            },
        };
        let before = store.clone();

        assert_eq!(
            execute_guest_accumulate(&mut store, &AccumulateRequestV2::Install(genesis.clone()),)
                .unwrap(),
            rejected(AccumulationRejectionV2::Unauthorized)
        );
        assert_eq!(store, before, "unauthorized genesis must stage nothing");

        store.deny_install = false;
        assert_eq!(
            execute_guest_accumulate(&mut store, &AccumulateRequestV2::Install(genesis)).unwrap(),
            rejected(AccumulationRejectionV2::WrongProgram),
            "availability is consulted only after authorization succeeds"
        );
    }

    #[test]
    fn typed_install_rejects_invalid_genesis_before_authority_or_availability() {
        let mut store = MemStore {
            deny_install: true,
            ..MemStore::default()
        };
        let genesis = ServiceGenesisV2 {
            external_actors: vec![],
            service: identity(),
            consistency: ConsistencyModeV2::Local,
            actors: vec![ActorGenesisV2 {
                actor: actor(),
                name: String::new(),
                parent: None,
                producer: super::super::ProducerId([4; 32]),
                deployment: identity().deployment,
                program: program(),
                initial_state: BlobRefV2::of_bytes(b"unavailable state"),
                crdt: false,
                role_policies: role_policies(vec![]),
            }],
            authorization: AuthorizationEvidenceV2::SystemCapability {
                capability: super::super::SystemCapabilityId([8; 32]),
                authenticator: vec![9],
            },
        };
        let before = store.clone();
        assert_eq!(
            execute_guest_accumulate(&mut store, &AccumulateRequestV2::Install(genesis)).unwrap(),
            rejected(AccumulationRejectionV2::NonCanonical)
        );
        assert_eq!(store, before);
    }

    #[test]
    fn install_requires_every_actor_program_to_be_available() {
        let mut store = MemStore::default();
        let initial = store.provide_blob(b"state").unwrap();
        let genesis = ServiceGenesisV2 {
            external_actors: vec![],
            service: identity(),
            consistency: ConsistencyModeV2::Local,
            actors: vec![ActorGenesisV2 {
                actor: actor(),
                name: "root".into(),
                parent: None,
                producer: super::super::ProducerId([4; 32]),
                deployment: identity().deployment,
                program: program(),
                initial_state: initial,
                crdt: false,
                role_policies: role_policies(vec![MethodPolicyV2 {
                    method: "set".into(),
                    schema: Hash([6; 32]),
                    policy: public_policy_hash(),
                    public: true,
                    attested: false,
                    space_role: None,
                    actor_role: None,
                }]),
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

    fn store_header(store: &MemStore) -> StoreHeaderV2 {
        StoreHeaderV2::open(store.rows.get(header_storage_key()).unwrap()).unwrap()
    }

    fn upgrade_fixture(base_root: Hash) -> ActorUpgradeV2 {
        ActorUpgradeV2 {
            service: identity(),
            actor: actor(),
            expected_deployment: identity().deployment,
            expected_program: program(),
            replacement_deployment: DeploymentId([14; 32]),
            replacement_program: ProgramId([15; 32]),
            producer: super::super::ProducerId([16; 32]),
            role_policies: role_policies(vec![MethodPolicyV2 {
                method: "get".into(),
                schema: Hash([17; 32]),
                policy: public_policy_hash(),
                public: true,
                attested: false,
                space_role: None,
                actor_role: None,
            }]),
            base: ConsistencyBaseV2::Linear {
                revision: 0,
                state_root: base_root,
            },
            authorization: AuthorizationEvidenceV2::SystemCapability {
                capability: super::super::SystemCapabilityId([18; 32]),
                authenticator: vec![19],
            },
        }
    }

    #[test]
    fn idle_actor_upgrade_is_atomic_exactly_once_and_preserves_state() {
        let mut store = MemStore::default();
        let (initial, install) = install_fixture(&mut store, ConsistencyModeV2::Local, b"state");
        let upgrade = upgrade_fixture(install.resulting_state_root.unwrap());
        store.upgrade_allowlist.insert(upgrade.hash());

        let result = execute_guest_accumulate(
            &mut store,
            &AccumulateRequestV2::UpgradeActor(upgrade.clone()),
        )
        .unwrap();
        let AccumulationResultV2::ActorUpgraded {
            actor: upgraded_actor,
            previous_deployment,
            previous_program,
            deployment,
            program: replacement,
            receipt,
            duplicate,
        } = result
        else {
            panic!("idle actor upgrade was rejected")
        };
        assert_eq!(upgraded_actor, actor());
        assert_eq!(previous_deployment, upgrade.expected_deployment);
        assert_eq!(previous_program, program());
        assert_eq!(deployment, upgrade.replacement_deployment);
        assert_eq!(replacement, upgrade.replacement_program);
        assert!(!duplicate);
        assert_eq!(receipt.accepted_transition, upgrade.hash());
        assert_eq!(receipt.sequence, 1);

        let header = store_header(&store);
        assert_eq!(header.revision, 1);
        assert_eq!(header.state_root, Some(header.service_root));
        let tree = ServiceStateTreeV2::new(&mut store, header.service_root);
        let descriptor =
            tree_get_wire::<_, ActorGenesisV2>(&tree, &StateKeyV2::ActorDescriptor(actor()))
                .unwrap()
                .unwrap();
        assert_eq!(descriptor.program, upgrade.replacement_program);
        assert_eq!(descriptor.deployment, upgrade.replacement_deployment);
        assert_eq!(descriptor.producer, upgrade.producer);
        assert_eq!(descriptor.role_policies, upgrade.role_policies);
        assert_eq!(
            tree_get_wire::<_, BlobRefV2>(
                &tree,
                &StateKeyV2::ActorRow {
                    actor: actor(),
                    key: crate::actors::lifecycle::STATE_KEY_BYTES.to_vec(),
                },
            )
            .unwrap(),
            Some(initial)
        );
        assert!(
            tree.get(&StateKeyV2::MethodPolicy {
                actor: actor(),
                method: "set".into(),
            })
            .unwrap()
            .is_none()
        );
        assert_eq!(
            tree_get_wire::<_, MethodPolicyV2>(
                &tree,
                &StateKeyV2::MethodPolicy {
                    actor: actor(),
                    method: "get".into(),
                },
            )
            .unwrap(),
            Some(
                super::super::PackageRolePoliciesV2::decode(&upgrade.role_policies)
                    .unwrap()
                    .methods[0]
                    .clone()
            )
        );
        drop(tree);

        let before_retry = store.clone();
        let duplicate =
            execute_guest_accumulate(&mut store, &AccumulateRequestV2::UpgradeActor(upgrade))
                .unwrap();
        assert!(matches!(
            duplicate,
            AccumulationResultV2::ActorUpgraded {
                duplicate: true,
                ..
            }
        ));
        assert_eq!(store, before_retry, "an exact retry must stage no writes");
    }

    #[test]
    fn package_only_actor_upgrade_commits_a_new_deployment_identity() {
        let mut store = MemStore::default();
        let (_, install) = install_fixture(&mut store, ConsistencyModeV2::Local, b"state");
        let mut upgrade = upgrade_fixture(install.resulting_state_root.unwrap());
        upgrade.replacement_program = upgrade.expected_program;
        store.upgrade_allowlist.insert(upgrade.hash());

        let result = execute_guest_accumulate(
            &mut store,
            &AccumulateRequestV2::UpgradeActor(upgrade.clone()),
        )
        .unwrap();
        assert!(matches!(
            result,
            AccumulationResultV2::ActorUpgraded {
                previous_deployment,
                previous_program,
                deployment,
                program: replacement_program,
                duplicate: false,
                ..
            } if previous_deployment == upgrade.expected_deployment
                && previous_program == upgrade.expected_program
                && deployment == upgrade.replacement_deployment
                && replacement_program == upgrade.replacement_program
        ));
        let header = store_header(&store);
        let tree = ServiceStateTreeV2::new(&mut store, header.service_root);
        let descriptor =
            tree_get_wire::<_, ActorGenesisV2>(&tree, &StateKeyV2::ActorDescriptor(actor()))
                .unwrap()
                .unwrap();
        assert_eq!(descriptor.deployment, upgrade.replacement_deployment);
        assert_eq!(descriptor.program, program());
    }

    #[test]
    fn actor_upgrade_rejects_suspended_actor_without_mutation() {
        let mut store = MemStore::default();
        let (initial, install) = install_fixture(&mut store, ConsistencyModeV2::Local, b"state");
        let mut header = store_header(&store);
        let work = linear_work(initial, install.resulting_state_root.unwrap());
        let continuation_bytes = ContinuationSnapshotV2 {
            snapshot_version: super::super::SNAPSHOT_VERSION,
            jar_semantics: super::super::EXECUTION_SEMANTICS_ID,
            vos_abi: super::super::ABI_VERSION,
            service: work.service.clone(),
            invocation: work.invocation,
            checkpoint_step: work.workflow_step,
            actor: work.target,
            actor_deployment: work.target_deployment,
            actor_program: work.target_program,
            programs: continuation_programs(&work),
            await_ordinal: 0,
            pending_call: None,
            pending_actor: None,
            causal_context: work.causal_context.clone(),
            suspended_actors: vec![work.target],
            kernel_snapshot: vec![1],
        }
        .encode();
        let continuation = BlobRefV2::of_bytes(&continuation_bytes);
        store.blobs.insert(continuation.hash, continuation_bytes);
        let mut tree = ServiceStateTreeV2::new(&mut store, header.service_root);
        tree_apply(
            &mut tree,
            &StateKeyV2::Continuation(actor()),
            Some(&continuation.encode()),
        )
        .unwrap();
        header.service_root = tree.root();
        header.state_root = Some(header.service_root);
        drop(tree);
        store
            .rows
            .insert(header_storage_key().to_vec(), header.encode());

        let upgrade = upgrade_fixture(header.service_root);
        store.upgrade_allowlist.insert(upgrade.hash());
        let before = store.clone();
        assert_eq!(
            execute_guest_accumulate(&mut store, &AccumulateRequestV2::UpgradeActor(upgrade))
                .unwrap(),
            rejected(AccumulationRejectionV2::ActorBusy(actor()))
        );
        assert_eq!(store, before);
        assert_ne!(header.service_root, install.resulting_state_root.unwrap());
    }

    #[test]
    fn actor_upgrade_waits_for_peer_continuations_that_pin_its_program() {
        let mut store = MemStore::default();
        store.programs.insert(program(), FIXTURE_ACTOR_PVM.to_vec());
        let root_state = store.provide_blob(b"root").unwrap();
        let child_state = store.provide_blob(b"child").unwrap();
        let child = ActorId([7; 32]);
        let policy = MethodPolicyV2 {
            method: "set".into(),
            schema: Hash([6; 32]),
            policy: public_policy_hash(),
            public: true,
            attested: false,
            space_role: None,
            actor_role: None,
        };
        let genesis = ServiceGenesisV2 {
            service: identity(),
            consistency: ConsistencyModeV2::Local,
            actors: vec![
                ActorGenesisV2 {
                    actor: actor(),
                    name: "root".into(),
                    parent: None,
                    producer: super::super::ProducerId([4; 32]),
                    deployment: identity().deployment,
                    program: program(),
                    initial_state: root_state,
                    crdt: false,
                    role_policies: role_policies(vec![policy.clone()]),
                },
                ActorGenesisV2 {
                    actor: child,
                    name: "child".into(),
                    parent: Some(actor()),
                    producer: super::super::ProducerId([4; 32]),
                    deployment: identity().deployment,
                    program: program(),
                    initial_state: child_state,
                    crdt: false,
                    role_policies: role_policies(vec![policy]),
                },
            ],
            external_actors: external_bindings(),
            authorization: AuthorizationEvidenceV2::SystemCapability {
                capability: super::super::SystemCapabilityId([8; 32]),
                authenticator: vec![9],
            },
        };
        assert!(matches!(
            execute_guest_accumulate(&mut store, &AccumulateRequestV2::Install(genesis)).unwrap(),
            AccumulationResultV2::Installed(_)
        ));

        let continuation_bytes = ContinuationSnapshotV2 {
            snapshot_version: super::super::SNAPSHOT_VERSION,
            jar_semantics: super::super::EXECUTION_SEMANTICS_ID,
            vos_abi: super::super::ABI_VERSION,
            service: identity(),
            invocation: InvocationId([22; 32]),
            checkpoint_step: 0,
            actor: actor(),
            actor_deployment: identity().deployment,
            actor_program: program(),
            programs: vec![
                super::super::ContinuationProgramV2 {
                    actor: actor(),
                    deployment: identity().deployment,
                    program: program(),
                },
                super::super::ContinuationProgramV2 {
                    actor: child,
                    deployment: identity().deployment,
                    program: program(),
                },
            ],
            await_ordinal: 0,
            pending_call: None,
            pending_actor: None,
            causal_context: None,
            suspended_actors: vec![actor()],
            kernel_snapshot: vec![1],
        }
        .encode();
        let continuation = store.provide_blob(&continuation_bytes).unwrap();
        let mut header = store_header(&store);
        let mut tree = ServiceStateTreeV2::new(&mut store, header.service_root);
        tree_apply(
            &mut tree,
            &StateKeyV2::Continuation(actor()),
            Some(&continuation.encode()),
        )
        .unwrap();
        header.service_root = tree.root();
        header.state_root = Some(header.service_root);
        drop(tree);
        store
            .rows
            .insert(header_storage_key().to_vec(), header.encode());

        let mut upgrade = upgrade_fixture(header.service_root);
        upgrade.actor = child;
        store.upgrade_allowlist.insert(upgrade.hash());
        let before = store.clone();
        assert_eq!(
            execute_guest_accumulate(&mut store, &AccumulateRequestV2::UpgradeActor(upgrade))
                .unwrap(),
            rejected(AccumulationRejectionV2::ActorBusy(child))
        );
        assert_eq!(store, before);
    }

    #[test]
    fn actor_upgrade_rejects_unauthorized_stale_and_wrong_package_inputs() {
        let mut store = MemStore::default();
        let (_, install) = install_fixture(&mut store, ConsistencyModeV2::Local, b"state");
        let base_root = install.resulting_state_root.unwrap();
        let upgrade = upgrade_fixture(base_root);

        let before = store.clone();
        assert_eq!(
            execute_guest_accumulate(
                &mut store,
                &AccumulateRequestV2::UpgradeActor(upgrade.clone()),
            )
            .unwrap(),
            rejected(AccumulationRejectionV2::Unauthorized)
        );
        assert_eq!(store, before);

        store.upgrade_allowlist.insert(upgrade.hash());
        let mut stale = upgrade.clone();
        stale.base = ConsistencyBaseV2::Linear {
            revision: 1,
            state_root: base_root,
        };
        store.upgrade_allowlist.insert(stale.hash());
        let before = store.clone();
        assert_eq!(
            execute_guest_accumulate(&mut store, &AccumulateRequestV2::UpgradeActor(stale))
                .unwrap(),
            rejected(AccumulationRejectionV2::StaleLinearWork {
                expected_revision: 1,
                actual_revision: 0,
            })
        );
        assert_eq!(store, before);

        let mut wrong = upgrade.clone();
        wrong.expected_deployment = DeploymentId([21; 32]);
        store.upgrade_allowlist.insert(wrong.hash());
        let before = store.clone();
        assert_eq!(
            execute_guest_accumulate(&mut store, &AccumulateRequestV2::UpgradeActor(wrong))
                .unwrap(),
            rejected(AccumulationRejectionV2::WrongProgram)
        );
        assert_eq!(store, before);

        let mut wrong = upgrade;
        wrong.expected_program = ProgramId([20; 32]);
        store.upgrade_allowlist.insert(wrong.hash());
        let before = store.clone();
        assert_eq!(
            execute_guest_accumulate(&mut store, &AccumulateRequestV2::UpgradeActor(wrong))
                .unwrap(),
            rejected(AccumulationRejectionV2::WrongProgram)
        );
        assert_eq!(store, before);
    }

    #[test]
    fn crdt_actor_upgrade_fails_closed_until_metadata_operations_exist() {
        let mut store = MemStore::default();
        install_fixture(&mut store, ConsistencyModeV2::Crdt, b"state");
        let mut upgrade = upgrade_fixture(Hash::ZERO);
        upgrade.base = ConsistencyBaseV2::Crdt { heads: vec![] };
        let before = store.clone();
        assert_eq!(
            execute_guest_accumulate(&mut store, &AccumulateRequestV2::UpgradeActor(upgrade))
                .unwrap(),
            rejected(AccumulationRejectionV2::InvalidConsistency)
        );
        assert_eq!(store, before);
    }

    fn linear_work(initial: BlobRefV2, base_root: Hash) -> WorkEnvelopeV2 {
        WorkEnvelopeV2 {
            external_actors: external_bindings(),
            service: identity(),
            invocation: InvocationId([10; 32]),
            workflow_step: 0,
            logical_timeslot: 1,
            target: actor(),
            target_deployment: identity().deployment,
            target_program: program(),
            method: "set".into(),
            arguments: vec![1],
            origin: Origin::Anonymous,
            authorization: AuthorizationEvidenceV2::Public,
            causal_parent: None,
            parent_call: None,
            causal_context: None,
            awaited_reply: None,
            awaited_timeout: None,
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
                deployment: identity().deployment,
                program: program(),
                state: initial,
                causal_states: vec![],
                continuation: None,
            }],
            imported_blobs: Vec::new(),
            proof_requested: false,
        }
    }

    /// Legacy unit fixtures construct complete work envelopes directly so
    /// they can focus on a particular Apply rejection. Seed the exact
    /// guest-owned admission prerequisite without advancing the causal base;
    /// dedicated admission and physical-PVM tests exercise AdmitIngress.
    fn seed_direct_ingress(store: &mut MemStore, work: &WorkEnvelopeV2) {
        if work.workflow_step != 0 || work.parent_call.is_some() {
            return;
        }
        let mut ingress = DirectIngressV2 {
            service: work.service.clone(),
            invocation: work.invocation,
            logical_timeslot: work.logical_timeslot,
            target: work.target,
            method: work.method.clone(),
            arguments: work.arguments.clone(),
            origin: work.origin,
            authorization: work.authorization.clone(),
            imported_blobs: work.imported_blobs.clone(),
            proof_requested: work.proof_requested,
            base: work.base.clone(),
            base_causal_height: work.base_causal_height,
            crdt_change: None,
        };
        let (resulting_state_root, resulting_crdt_heads, sequence) = match &work.base {
            ConsistencyBaseV2::Linear {
                revision,
                state_root,
            } => (Some(*state_root), Vec::new(), *revision),
            ConsistencyBaseV2::Crdt { heads } => {
                let operation = ingress.crdt_operation();
                let height = work.base_causal_height.unwrap_or(0) + 1;
                let change = CrdtChangeV2 {
                    id: CrdtChangeV2::derive_ingress_id(&operation, heads),
                    work_hash: operation.commitment(),
                    causal_dependencies: heads.clone(),
                    causal_height: height,
                    operations: Vec::new(),
                    workflow: vec![WorkflowOperationV2::Ingress(operation)],
                    materializations: Vec::new(),
                    awaited_reply: None,
                    exported_blobs: Vec::new(),
                };
                let cid = change.cid();
                ingress.crdt_change = Some(change);
                (None, vec![cid], height)
            }
        };
        let receipt = AccumulationReceiptV2 {
            service: work.service.clone(),
            accepted_transition: ingress
                .crdt_change
                .as_ref()
                .map_or_else(|| ingress.commitment(), CrdtChangeV2::receipt_commitment),
            reply_commitment: None,
            outbox_commitment: None,
            resulting_state_root,
            resulting_crdt_heads,
            sequence,
            checkpoint: 0,
            consistency: work.consistency,
        };
        store.rows.insert(
            ingress_storage_key(work.invocation),
            IngressRecordV2 {
                ingress,
                consumed: false,
                receipt,
            }
            .encode(),
        );
    }

    fn continuation_programs(work: &WorkEnvelopeV2) -> Vec<super::super::ContinuationProgramV2> {
        work.imported_actors
            .iter()
            .map(|actor| super::super::ContinuationProgramV2 {
                actor: actor.actor,
                deployment: actor.deployment,
                program: actor.program,
            })
            .collect()
    }

    fn linear_transition(work: &WorkEnvelopeV2, state: &[u8]) -> TransitionV2 {
        TransitionV2 {
            service: work.service.clone(),
            consumed_input: work.input_id(),
            target_deployment: work.target_deployment,
            target_program: work.target_program,
            base: work.base.clone(),
            writes: vec![ActorWriteV2 {
                actor: actor(),
                key: crate::actors::lifecycle::STATE_KEY_BYTES.to_vec(),
                value: Some(state.to_vec()),
            }],
            crdt_change: None,
            spawns: Vec::new(),
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
    fn owned_child_spawn_is_atomic_deduplicated_and_guest_materialized() {
        let mut store = MemStore::default();
        let (initial, install) = install_fixture(&mut store, ConsistencyModeV2::Local, b"before");
        let work = linear_work(initial, install.resulting_state_root.unwrap());
        let child = ActorId::owned_child(actor(), "child");
        let child_bytes = b"child-state".to_vec();
        let child_state = BlobRefV2::of_bytes(&child_bytes);
        let mut transition = linear_transition(&work, b"after");
        transition.spawns.push(super::super::ActorSpawnV2 {
            actor: child,
            name: "child".into(),
            parent: actor(),
            initial_state: child_state.clone(),
        });
        let envelope = AccumulationEnvelopeV2 {
            work: work.clone(),
            transition,
            provided_blobs: vec![ImportedBlobV2 {
                reference: child_state.clone(),
                bytes: child_bytes,
            }],
        };
        seed_direct_ingress(&mut store, &work);

        let before = store.clone();
        let mut missing = envelope.clone();
        missing.provided_blobs.clear();
        assert_eq!(
            execute_guest_accumulate(&mut store, &AccumulateRequestV2::Apply(missing)).unwrap(),
            rejected(AccumulationRejectionV2::MissingBlob(child_state.hash))
        );
        assert_eq!(store, before, "a missing child state must stage nothing");

        assert!(matches!(
            execute_guest_accumulate(&mut store, &AccumulateRequestV2::Apply(envelope.clone()))
                .unwrap(),
            AccumulationResultV2::Accepted {
                duplicate: false,
                ..
            }
        ));
        let header = store_header(&store);
        let tree = ServiceStateTreeV2::new(&mut store, header.service_root);
        let directory =
            tree_get_wire::<_, super::super::ActorDirectoryV2>(&tree, &StateKeyV2::ActorDirectory)
                .unwrap()
                .unwrap();
        assert_eq!(directory.actors, {
            let mut actors = vec![actor(), child];
            actors.sort();
            actors
        });
        let parent =
            tree_get_wire::<_, ActorGenesisV2>(&tree, &StateKeyV2::ActorDescriptor(actor()))
                .unwrap()
                .unwrap();
        let descriptor =
            tree_get_wire::<_, ActorGenesisV2>(&tree, &StateKeyV2::ActorDescriptor(child))
                .unwrap()
                .unwrap();
        assert_eq!(descriptor.actor, child);
        assert_eq!(descriptor.parent, Some(actor()));
        assert_eq!(descriptor.name, "child");
        assert_eq!(descriptor.initial_state, child_state);
        assert_eq!(descriptor.program, parent.program);
        assert_eq!(descriptor.deployment, parent.deployment);
        assert_eq!(descriptor.producer, parent.producer);
        assert_eq!(descriptor.role_policies, parent.role_policies);
        assert_eq!(
            tree_get_wire::<_, BlobRefV2>(
                &tree,
                &StateKeyV2::ActorRow {
                    actor: child,
                    key: crate::actors::lifecycle::STATE_KEY_BYTES.to_vec(),
                },
            )
            .unwrap(),
            Some(child_state)
        );
        assert!(
            tree_get_wire::<_, MethodPolicyV2>(
                &tree,
                &StateKeyV2::MethodPolicy {
                    actor: child,
                    method: "set".into(),
                },
            )
            .unwrap()
            .is_some()
        );
        drop(tree);

        let before_retry = store.clone();
        assert!(matches!(
            execute_guest_accumulate(&mut store, &AccumulateRequestV2::Apply(envelope)).unwrap(),
            AccumulationResultV2::Accepted {
                duplicate: true,
                ..
            }
        ));
        assert_eq!(store, before_retry, "an exact retry must stage no writes");
    }

    #[test]
    fn crdt_child_spawn_wire_is_rejected_without_mutation() {
        let mut store = MemStore::default();
        let (initial, install) = install_fixture(&mut store, ConsistencyModeV2::Crdt, b"before");
        assert!(install.resulting_crdt_heads.is_empty());
        let work = crdt_work(initial, 11, vec![]);
        let child_bytes = b"child-state".to_vec();
        let child_state = BlobRefV2::of_bytes(&child_bytes);
        let materialization_bytes = b"after".to_vec();
        let materialization = BlobRefV2::of_bytes(&materialization_bytes);
        let mut transition = crdt_transition(&work, materialization.clone(), 1);
        transition.spawns.push(super::super::ActorSpawnV2 {
            actor: ActorId::owned_child(actor(), "child"),
            name: "child".into(),
            parent: actor(),
            initial_state: child_state.clone(),
        });
        let request = AccumulateRequestV2::Apply(AccumulationEnvelopeV2 {
            work,
            transition,
            provided_blobs: vec![
                ImportedBlobV2 {
                    reference: child_state,
                    bytes: child_bytes,
                },
                ImportedBlobV2 {
                    reference: materialization,
                    bytes: materialization_bytes,
                },
            ],
        });
        let before = store.clone();
        assert_eq!(
            execute_guest_accumulate(&mut store, &request).unwrap(),
            rejected(AccumulationRejectionV2::NonCanonical)
        );
        assert_eq!(store, before);
    }

    #[test]
    fn child_spawn_rejects_the_pinned_jar_tree_ceiling_atomically() {
        let mut store = MemStore::default();
        let initial = store.provide_blob(b"state").unwrap();
        store.programs.insert(program(), FIXTURE_ACTOR_PVM.to_vec());
        let policies = role_policies(vec![MethodPolicyV2 {
            method: "set".into(),
            schema: Hash([6; 32]),
            policy: public_policy_hash(),
            public: true,
            attested: false,
            space_role: None,
            actor_role: None,
        }]);
        let actors = [
            actor(),
            ActorId([5; 32]),
            ActorId([6; 32]),
            ActorId([7; 32]),
        ];
        assert_eq!(actors.len(), super::super::MAX_ROOT_TREE_ACTORS);
        let install = AccumulateRequestV2::Install(ServiceGenesisV2 {
            external_actors: external_bindings(),
            service: identity(),
            consistency: ConsistencyModeV2::Local,
            actors: actors
                .iter()
                .enumerate()
                .map(|(index, child)| ActorGenesisV2 {
                    actor: *child,
                    name: if index == 0 {
                        "root".into()
                    } else {
                        alloc::format!("child-{index}")
                    },
                    parent: (index != 0).then_some(actor()),
                    producer: super::super::ProducerId([4; 32]),
                    deployment: identity().deployment,
                    program: program(),
                    initial_state: initial.clone(),
                    crdt: false,
                    role_policies: policies.clone(),
                })
                .collect(),
            authorization: AuthorizationEvidenceV2::SystemCapability {
                capability: super::super::SystemCapabilityId([8; 32]),
                authenticator: vec![9],
            },
        });
        let AccumulationResultV2::Installed(receipt) =
            execute_guest_accumulate(&mut store, &install).unwrap()
        else {
            panic!("four-actor fixture install rejected")
        };
        let mut work = linear_work(initial.clone(), receipt.resulting_state_root.unwrap());
        work.imported_actors
            .extend(
                actors[1..]
                    .iter()
                    .enumerate()
                    .map(|(index, child)| ImportedActorV2 {
                        actor: *child,
                        name: alloc::format!("child-{}", index + 1),
                        parent: Some(actor()),
                        deployment: identity().deployment,
                        program: program(),
                        state: initial.clone(),
                        causal_states: vec![],
                        continuation: None,
                    }),
            );
        let child_bytes = b"overflow-state".to_vec();
        let child_state = BlobRefV2::of_bytes(&child_bytes);
        let mut transition = linear_transition(&work, b"after");
        transition.spawns.push(super::super::ActorSpawnV2 {
            actor: ActorId::owned_child(actor(), "overflow"),
            name: "overflow".into(),
            parent: actor(),
            initial_state: child_state.clone(),
        });
        let request = AccumulateRequestV2::Apply(AccumulationEnvelopeV2 {
            work,
            transition,
            provided_blobs: vec![ImportedBlobV2 {
                reference: child_state,
                bytes: child_bytes,
            }],
        });
        let before = store.clone();
        assert_eq!(
            execute_guest_accumulate(&mut store, &request).unwrap(),
            rejected(AccumulationRejectionV2::InvalidWorkflowTransition)
        );
        assert_eq!(store, before);
    }

    fn awaiting_transition(
        work: &WorkEnvelopeV2,
        state: &[u8],
        outgoing: MessageRecordV2,
    ) -> (TransitionV2, ImportedBlobV2) {
        assert_eq!(outgoing.call_id, work.invocation.call_id(0));
        assert_eq!(outgoing.caller_invocation, work.invocation);
        assert_eq!(outgoing.await_ordinal, 0);
        let continuation_bytes = ContinuationSnapshotV2 {
            snapshot_version: super::super::SNAPSHOT_VERSION,
            jar_semantics: super::super::EXECUTION_SEMANTICS_ID,
            vos_abi: super::super::ABI_VERSION,
            service: work.service.clone(),
            invocation: work.invocation,
            checkpoint_step: work.workflow_step,
            actor: work.target,
            actor_deployment: work.target_deployment,
            actor_program: work.target_program,
            programs: continuation_programs(work),
            await_ordinal: 0,
            pending_call: Some(outgoing.call_id),
            pending_actor: Some(outgoing.from),
            causal_context: work.causal_context.clone(),
            suspended_actors: vec![work.target],
            kernel_snapshot: vec![1],
        }
        .encode();
        let continuation = BlobRefV2::of_bytes(&continuation_bytes);
        let mut transition = linear_transition(work, state);
        transition.reply = None;
        transition.continuations.push(ContinuationChangeV2 {
            actor: work.target,
            expected: None,
            replacement: Some(continuation.clone()),
        });
        transition.outbox.push(outgoing);
        transition.exported_blobs.push(continuation.clone());
        (
            transition,
            ImportedBlobV2 {
                reference: continuation,
                bytes: continuation_bytes,
            },
        )
    }

    fn awaited_message(
        work: &WorkEnvelopeV2,
        to: ActorId,
        parent: Option<super::super::CallId>,
        deadline_timeslot: Option<u64>,
    ) -> MessageRecordV2 {
        let mut outgoing = message(0, work.target, to, parent, deadline_timeslot);
        outgoing.call_id = work.invocation.call_id(0);
        outgoing.caller_invocation = work.invocation;
        outgoing.await_ordinal = 0;
        outgoing
    }

    #[test]
    fn direct_ingress_is_guest_admitted_deduplicated_and_consumed_atomically() {
        let mut store = MemStore::default();
        let (initial, install) = install_fixture(&mut store, ConsistencyModeV2::Local, b"before");
        let work = linear_work(initial, install.resulting_state_root.unwrap());
        let ingress = DirectIngressV2 {
            service: work.service.clone(),
            invocation: work.invocation,
            logical_timeslot: work.logical_timeslot,
            target: work.target,
            method: work.method.clone(),
            arguments: work.arguments.clone(),
            origin: work.origin,
            authorization: work.authorization.clone(),
            imported_blobs: work.imported_blobs.clone(),
            proof_requested: work.proof_requested,
            base: work.base.clone(),
            base_causal_height: None,
            crdt_change: None,
        };
        let header_before = store_header(&store);
        let admitted = execute_guest_accumulate(
            &mut store,
            &AccumulateRequestV2::AdmitIngress(ingress.clone()),
        )
        .unwrap();
        let AccumulationResultV2::IngressAdmitted {
            invocation,
            receipt,
            duplicate,
        } = admitted
        else {
            panic!("ingress was not admitted")
        };
        assert_eq!(invocation, work.invocation);
        assert!(!duplicate);
        let header_after = store_header(&store);
        assert_eq!(header_after.service_root, header_before.service_root);
        assert_eq!(header_after.revision, header_before.revision);
        assert_eq!(
            header_after.admission_timeslot_high_water,
            header_before
                .admission_timeslot_high_water
                .max(ingress.logical_timeslot)
        );
        let record = IngressRecordV2::decode(
            store
                .rows
                .get(&ingress_storage_key(work.invocation))
                .unwrap(),
        )
        .unwrap();
        assert_eq!(record.ingress, ingress);
        assert!(!record.consumed);
        assert_eq!(record.receipt, receipt);

        let mut retry = record.ingress.clone();
        retry.logical_timeslot += 10;
        assert_eq!(
            execute_guest_accumulate(&mut store, &AccumulateRequestV2::AdmitIngress(retry))
                .unwrap(),
            AccumulationResultV2::IngressAdmitted {
                invocation: work.invocation,
                receipt,
                duplicate: true,
            }
        );
        let mut divergent = record.ingress;
        divergent.method = "other".into();
        assert_eq!(
            execute_guest_accumulate(&mut store, &AccumulateRequestV2::AdmitIngress(divergent),)
                .unwrap(),
            rejected(AccumulationRejectionV2::DivergentDuplicate)
        );

        let transition = linear_transition(&work, b"after");
        assert!(matches!(
            execute_guest_accumulate(
                &mut store,
                &AccumulateRequestV2::Apply(AccumulationEnvelopeV2 {
                    work: work.clone(),
                    transition,
                    provided_blobs: vec![],
                }),
            )
            .unwrap(),
            AccumulationResultV2::Accepted {
                duplicate: false,
                ..
            }
        ));
        let consumed = IngressRecordV2::decode(
            store
                .rows
                .get(&ingress_storage_key(work.invocation))
                .unwrap(),
        )
        .unwrap();
        assert!(consumed.consumed);
    }

    #[test]
    fn direct_step_zero_apply_requires_a_guest_owned_ingress() {
        let mut store = MemStore::default();
        let (initial, install) = install_fixture(&mut store, ConsistencyModeV2::Local, b"before");
        let work = linear_work(initial, install.resulting_state_root.unwrap());
        let request = AccumulateRequestV2::Apply(AccumulationEnvelopeV2 {
            transition: linear_transition(&work, b"must not execute"),
            work,
            provided_blobs: Vec::new(),
        });
        let before = store.clone();

        assert_eq!(
            execute_guest_accumulate(&mut store, &request).unwrap(),
            rejected(AccumulationRejectionV2::InvalidWorkflowTransition)
        );
        assert_eq!(store, before, "unadmitted work must stage no state");
    }

    #[test]
    fn crdt_direct_ingress_is_an_authenticated_syncable_workflow_node() {
        let mut source = MemStore::default();
        let mut destination = MemStore::default();
        let (initial, _) = install_fixture(&mut source, ConsistencyModeV2::Crdt, b"before");
        install_fixture(&mut destination, ConsistencyModeV2::Crdt, b"before");
        let work = crdt_work(initial, 67, vec![]);
        let mut ingress = DirectIngressV2 {
            service: work.service.clone(),
            invocation: work.invocation,
            logical_timeslot: work.logical_timeslot,
            target: work.target,
            method: work.method.clone(),
            arguments: work.arguments.clone(),
            origin: work.origin,
            authorization: work.authorization.clone(),
            imported_blobs: work.imported_blobs.clone(),
            proof_requested: work.proof_requested,
            base: ConsistencyBaseV2::Crdt { heads: vec![] },
            base_causal_height: Some(0),
            crdt_change: None,
        };
        let operation = ingress.crdt_operation();
        let change = CrdtChangeV2 {
            id: CrdtChangeV2::derive_ingress_id(&operation, &[]),
            work_hash: operation.commitment(),
            causal_dependencies: vec![],
            causal_height: 1,
            operations: vec![],
            workflow: vec![WorkflowOperationV2::Ingress(operation)],
            materializations: vec![],
            awaited_reply: None,
            exported_blobs: vec![],
        };
        let cid = change.cid();
        ingress.crdt_change = Some(change.clone());

        let AccumulationResultV2::IngressAdmitted {
            receipt,
            duplicate: false,
            ..
        } = execute_guest_accumulate(
            &mut source,
            &AccumulateRequestV2::AdmitIngress(ingress.clone()),
        )
        .unwrap()
        else {
            panic!("CRDT ingress was not admitted")
        };
        assert_eq!(receipt.resulting_crdt_heads, vec![cid]);
        assert_eq!(receipt.sequence, 1);
        assert!(
            !IngressRecordV2::decode(
                source
                    .rows
                    .get(&ingress_storage_key(work.invocation))
                    .unwrap()
            )
            .unwrap()
            .consumed
        );

        destination.receipt_allowlist.insert(
            ReceiptVerificationRequestV2 {
                expected_producer: work.target,
                receipt: receipt.clone(),
            }
            .hash(),
        );
        let synced = execute_guest_accumulate(
            &mut destination,
            &AccumulateRequestV2::SyncCrdt(CrdtSyncEnvelopeV2 {
                service: identity(),
                advertised_heads: vec![cid],
                nodes: vec![super::super::CrdtSyncNodeV2 { change, receipt }],
                provided_blobs: vec![],
            }),
        )
        .unwrap();
        assert!(matches!(
            synced,
            AccumulationResultV2::Accepted {
                duplicate: false,
                ..
            }
        ));
        let restored = IngressRecordV2::decode(
            destination
                .rows
                .get(&ingress_storage_key(work.invocation))
                .unwrap(),
        )
        .unwrap();
        assert_eq!(restored.ingress, ingress);
        assert!(!restored.consumed);
    }

    #[test]
    fn concurrent_crdt_ingress_retries_have_distinct_ids_and_converge() {
        let mut left = MemStore::default();
        let mut right = MemStore::default();
        let mut destination = MemStore::default();
        let mut divergent_source = MemStore::default();
        let mut conflict_destination = MemStore::default();
        let (initial, _) = install_fixture(&mut left, ConsistencyModeV2::Crdt, b"before");
        install_fixture(&mut right, ConsistencyModeV2::Crdt, b"before");
        install_fixture(&mut destination, ConsistencyModeV2::Crdt, b"before");
        install_fixture(&mut divergent_source, ConsistencyModeV2::Crdt, b"before");
        install_fixture(
            &mut conflict_destination,
            ConsistencyModeV2::Crdt,
            b"before",
        );
        let work = crdt_work(initial, 68, vec![]);

        let make_ingress = |logical_timeslot| {
            let mut ingress = DirectIngressV2 {
                service: work.service.clone(),
                invocation: work.invocation,
                logical_timeslot,
                target: work.target,
                method: work.method.clone(),
                arguments: work.arguments.clone(),
                origin: work.origin,
                authorization: work.authorization.clone(),
                imported_blobs: work.imported_blobs.clone(),
                proof_requested: work.proof_requested,
                base: ConsistencyBaseV2::Crdt { heads: vec![] },
                base_causal_height: Some(0),
                crdt_change: None,
            };
            let operation = ingress.crdt_operation();
            let change = CrdtChangeV2 {
                id: CrdtChangeV2::derive_ingress_id(&operation, &[]),
                work_hash: operation.commitment(),
                causal_dependencies: vec![],
                causal_height: 1,
                operations: vec![],
                workflow: vec![WorkflowOperationV2::Ingress(operation)],
                materializations: vec![],
                awaited_reply: None,
                exported_blobs: vec![],
            };
            ingress.crdt_change = Some(change);
            ingress
        };
        let left_ingress = make_ingress(11);
        let right_ingress = make_ingress(12);
        let left_change = left_ingress.crdt_change.clone().unwrap();
        let right_change = right_ingress.crdt_change.clone().unwrap();
        assert_ne!(left_change.id, right_change.id);
        assert_ne!(left_change.cid(), right_change.cid());
        assert_ne!(
            CrdtChangeV2::derive_ingress_id(&left_ingress.crdt_operation(), &[]),
            CrdtChangeV2::derive_ingress_id(&left_ingress.crdt_operation(), &[Hash([0x44; 32])]),
            "the causal base is part of the ingress operation identity"
        );

        let admit = |store: &mut MemStore, ingress: DirectIngressV2| {
            let AccumulationResultV2::IngressAdmitted {
                receipt,
                duplicate: false,
                ..
            } = execute_guest_accumulate(
                store,
                &AccumulateRequestV2::AdmitIngress(ingress.clone()),
            )
            .unwrap()
            else {
                panic!("CRDT ingress branch was not admitted")
            };
            (ingress.crdt_change.unwrap(), receipt)
        };
        let mut nodes = [
            admit(&mut left, left_ingress),
            admit(&mut right, right_ingress),
        ]
        .map(|(change, receipt)| super::super::CrdtSyncNodeV2 { change, receipt });
        nodes.sort_by_key(|node| node.change.cid());
        for node in &nodes {
            destination.receipt_allowlist.insert(
                ReceiptVerificationRequestV2 {
                    expected_producer: actor(),
                    receipt: node.receipt.clone(),
                }
                .hash(),
            );
        }
        let advertised_heads = nodes.iter().map(|node| node.change.cid()).collect();
        assert!(matches!(
            execute_guest_accumulate(
                &mut destination,
                &AccumulateRequestV2::SyncCrdt(CrdtSyncEnvelopeV2 {
                    service: identity(),
                    advertised_heads,
                    nodes: nodes.to_vec(),
                    provided_blobs: vec![],
                }),
            )
            .unwrap(),
            AccumulationResultV2::Accepted {
                duplicate: false,
                ..
            }
        ));
        let restored = IngressRecordV2::decode(
            destination
                .rows
                .get(&ingress_storage_key(work.invocation))
                .unwrap(),
        )
        .unwrap();
        let WorkflowOperationV2::Ingress(expected) = &nodes[0].change.workflow[0] else {
            unreachable!()
        };
        assert_eq!(restored.ingress.logical_timeslot, expected.logical_timeslot);
        assert!(!restored.consumed);

        let mut divergent_ingress = make_ingress(13);
        divergent_ingress.arguments = vec![99];
        let divergent_operation = divergent_ingress.crdt_operation();
        divergent_ingress.crdt_change = Some(CrdtChangeV2 {
            id: CrdtChangeV2::derive_ingress_id(&divergent_operation, &[]),
            work_hash: divergent_operation.commitment(),
            causal_dependencies: vec![],
            causal_height: 1,
            operations: vec![],
            workflow: vec![WorkflowOperationV2::Ingress(divergent_operation)],
            materializations: vec![],
            awaited_reply: None,
            exported_blobs: vec![],
        });
        let (divergent_change, divergent_receipt) = admit(&mut divergent_source, divergent_ingress);
        let mut conflict_nodes = vec![
            nodes[0].clone(),
            super::super::CrdtSyncNodeV2 {
                change: divergent_change,
                receipt: divergent_receipt,
            },
        ];
        conflict_nodes.sort_by_key(|node| node.change.cid());
        for node in &conflict_nodes {
            conflict_destination.receipt_allowlist.insert(
                ReceiptVerificationRequestV2 {
                    expected_producer: actor(),
                    receipt: node.receipt.clone(),
                }
                .hash(),
            );
        }
        let before_conflict = conflict_destination.clone();
        assert_eq!(
            execute_guest_accumulate(
                &mut conflict_destination,
                &AccumulateRequestV2::SyncCrdt(CrdtSyncEnvelopeV2 {
                    service: identity(),
                    advertised_heads: conflict_nodes
                        .iter()
                        .map(|node| node.change.cid())
                        .collect(),
                    nodes: conflict_nodes,
                    provided_blobs: vec![],
                }),
            )
            .unwrap(),
            rejected(AccumulationRejectionV2::DivergentDuplicate)
        );
        assert_eq!(conflict_destination, before_conflict);
    }

    #[test]
    fn attestation_preparation_is_guest_derived_and_read_only() {
        let mut store = MemStore::default();
        let (initial, install) = install_fixture(&mut store, ConsistencyModeV2::Local, b"before");
        let mut work = linear_work(initial, install.resulting_state_root.unwrap());
        work.proof_requested = true;
        seed_direct_ingress(&mut store, &work);
        let child = ActorId::owned_child(actor(), "attested-child");
        let child_bytes = b"attested-child-state".to_vec();
        let child_state = BlobRefV2::of_bytes(&child_bytes);
        let child_blob = ImportedBlobV2 {
            reference: child_state.clone(),
            bytes: child_bytes,
        };
        let mut transition = linear_transition(&work, b"after");
        transition.spawns.push(super::super::ActorSpawnV2 {
            actor: child,
            name: "attested-child".into(),
            parent: actor(),
            initial_state: child_state,
        });
        let before = store.clone();
        let mut staging = store.clone();

        let result = execute_guest_accumulate(
            &mut staging,
            &AccumulateRequestV2::PrepareAttested(AccumulationEnvelopeV2 {
                work: work.clone(),
                transition: transition.clone(),
                provided_blobs: vec![child_blob.clone()],
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
            space_role: None,
            actor_role: None,
        };
        assert_eq!(
            preparation,
            AttestationPreparationV2::for_transition(
                &work,
                &transition,
                &policy,
                "root",
                super::super::ProducerId([4; 32]),
                preparation.receipt.clone(),
            )
            .unwrap()
        );
        assert_eq!(store, before, "preparation must not commit guest state");
        assert_ne!(
            staging, before,
            "receipt prediction executes against an isolated staging transaction"
        );

        let proof_bytes = b"proof bytes".to_vec();
        let proof_blob = BlobRefV2::of_bytes(&proof_bytes);
        let proof = super::super::ProofCommitmentV2 {
            statement: preparation.statement.commitment(),
            trace: Hash([12; 32]),
            proof_blob: proof_blob.clone(),
            statement_version: super::super::ATTESTATION_STATEMENT_VERSION,
        };
        let verification = ProofVerificationRequestV2 {
            actor_program: work.target_program,
            execution_semantics: work.service.execution_semantics,
            statement: proof.statement,
            trace: proof.trace,
            proof_blob: proof_blob.clone(),
        };
        let mut proved_transition = transition.clone();
        proved_transition.proof = Some(proof.clone());
        let mut provided_blobs = vec![
            child_blob.clone(),
            ImportedBlobV2 {
                reference: proof_blob.clone(),
                bytes: proof_bytes.clone(),
            },
        ];
        provided_blobs.sort_by_key(|blob| blob.reference.hash);
        let request = AccumulateRequestV2::Apply(AccumulationEnvelopeV2 {
            work: work.clone(),
            transition: proved_transition.clone(),
            provided_blobs,
        });
        let unavailable = execute_guest_accumulate(&mut store.clone(), &request).unwrap();
        assert_eq!(
            unavailable,
            AccumulationResultV2::Rejected(AccumulationRejectionV2::ProofUnavailable)
        );

        store
            .proof_blobs
            .insert(proof_blob.hash, proof_bytes.clone());
        store.proof_allowlist.insert(verification.hash());
        let accepted = execute_guest_accumulate(&mut store, &request).unwrap();
        let AccumulationResultV2::Accepted {
            receipt,
            published,
            duplicate: false,
        } = accepted
        else {
            panic!("valid proof was not accepted")
        };
        assert_eq!(receipt, preparation.receipt);
        assert_eq!(published.proof, Some(proof.clone()));

        let recovered = execute_guest_accumulate(
            &mut store,
            &AccumulateRequestV2::PrepareAttested(AccumulationEnvelopeV2 {
                work: work.clone(),
                transition: transition.clone(),
                provided_blobs: vec![child_blob.clone()],
            }),
        )
        .unwrap();
        let AccumulationResultV2::Prepared(recovered) = recovered else {
            panic!("the exact attested retry was not recovered after its child spawn")
        };
        assert_eq!(recovered.receipt, preparation.receipt);
        assert_eq!(recovered.committed_proof, Some(proof.clone()));

        let mut tampered = proved_transition;
        tampered.proof.as_mut().unwrap().statement = Hash([13; 32]);
        let tampered = execute_guest_accumulate(
            &mut before.clone(),
            &AccumulateRequestV2::Apply(AccumulationEnvelopeV2 {
                work,
                transition: tampered,
                provided_blobs: {
                    let mut blobs = vec![
                        child_blob,
                        ImportedBlobV2 {
                            reference: proof_blob,
                            bytes: proof_bytes,
                        },
                    ];
                    blobs.sort_by_key(|blob| blob.reference.hash);
                    blobs
                },
            }),
        )
        .unwrap();
        assert_eq!(
            tampered,
            AccumulationResultV2::Rejected(AccumulationRejectionV2::InvalidProof)
        );
    }

    #[test]
    fn install_and_linear_apply_are_guest_owned_and_exactly_once() {
        let mut store = MemStore::default();
        let (initial, install) = install_fixture(&mut store, ConsistencyModeV2::Local, b"before");
        let root = install.resulting_state_root.unwrap();
        let work = linear_work(initial, root);
        let transition = linear_transition(&work, b"after");
        seed_direct_ingress(&mut store, &work);
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
                .expect("published reply is durable before host exposure"),
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
    fn apply_rejects_a_forged_external_actor_binding_without_state_trace() {
        let mut store = MemStore::default();
        let (initial, install) = install_fixture(&mut store, ConsistencyModeV2::Local, b"before");
        let mut work = linear_work(initial, install.resulting_state_root.unwrap());
        work.external_actors[1].producer = super::super::ProducerId([99; 32]);
        let transition = linear_transition(&work, b"forged");
        let request = AccumulateRequestV2::Apply(AccumulationEnvelopeV2 {
            work,
            transition,
            provided_blobs: Vec::new(),
        });
        let before = store.clone();

        assert_eq!(
            execute_guest_accumulate(&mut store, &request).unwrap(),
            rejected(AccumulationRejectionV2::InvalidWorkflowTransition)
        );
        assert_eq!(store, before);
    }

    #[test]
    fn accumulate_rejects_a_partial_root_tree_import() {
        let mut store = MemStore::default();
        let initial = store.provide_blob(b"before").unwrap();
        store.programs.insert(program(), FIXTURE_ACTOR_PVM.to_vec());
        let child = ActorId([7; 32]);
        let request = AccumulateRequestV2::Install(ServiceGenesisV2 {
            external_actors: vec![],
            service: identity(),
            consistency: ConsistencyModeV2::Local,
            actors: vec![
                ActorGenesisV2 {
                    actor: actor(),
                    name: "root".into(),
                    parent: None,
                    producer: super::super::ProducerId([4; 32]),
                    deployment: identity().deployment,
                    program: program(),
                    initial_state: initial.clone(),
                    crdt: false,
                    role_policies: role_policies(vec![MethodPolicyV2 {
                        method: "set".into(),
                        schema: Hash([6; 32]),
                        policy: public_policy_hash(),
                        public: true,
                        attested: false,
                        space_role: None,
                        actor_role: None,
                    }]),
                },
                ActorGenesisV2 {
                    actor: child,
                    name: "child".into(),
                    parent: Some(actor()),
                    producer: super::super::ProducerId([4; 32]),
                    deployment: identity().deployment,
                    program: program(),
                    initial_state: initial.clone(),
                    crdt: false,
                    role_policies: role_policies(vec![]),
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
        let root = installed.resulting_state_root.unwrap();
        let work = linear_work(initial.clone(), root);
        seed_direct_ingress(&mut store, &work);
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

        let mut misnamed = linear_work(initial.clone(), root);
        misnamed.imported_actors.push(ImportedActorV2 {
            actor: child,
            name: "forged-child".into(),
            parent: Some(actor()),
            deployment: misnamed.target_deployment,
            program: program(),
            state: initial,
            causal_states: Vec::new(),
            continuation: None,
        });
        let transition = linear_transition(&misnamed, b"after");
        let result = execute_guest_accumulate(
            &mut store,
            &AccumulateRequestV2::Apply(AccumulationEnvelopeV2 {
                work: misnamed,
                transition,
                provided_blobs: Vec::new(),
            }),
        )
        .unwrap();
        assert_eq!(
            result,
            AccumulationResultV2::Rejected(AccumulationRejectionV2::WrongProgram)
        );
        assert_eq!(
            store, before,
            "a forged actor name must stage no service writes"
        );
    }

    #[test]
    fn stale_or_unauthorized_linear_work_stages_nothing() {
        let mut store = MemStore::default();
        let (initial, install) = install_fixture(&mut store, ConsistencyModeV2::Local, b"before");
        let root = install.resulting_state_root.unwrap();
        let work = linear_work(initial, root);
        seed_direct_ingress(&mut store, &work);
        let first = AccumulateRequestV2::Apply(AccumulationEnvelopeV2 {
            transition: linear_transition(&work, b"after"),
            work,
            provided_blobs: Vec::new(),
        });
        execute_guest_accumulate(&mut store, &first).unwrap();

        let current_state = BlobRefV2::of_bytes(b"after");
        let mut stale_work = linear_work(current_state, root);
        stale_work.invocation = InvocationId([11; 32]);
        seed_direct_ingress(&mut store, &stale_work);
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
        seed_direct_ingress(&mut store, &unauthorized.work);
        let before_unauthorized = store.clone();
        assert_eq!(
            execute_guest_accumulate(&mut store, &AccumulateRequestV2::Apply(unauthorized))
                .unwrap(),
            rejected(AccumulationRejectionV2::Unauthorized)
        );
        assert_eq!(store, before_unauthorized);
    }

    #[test]
    fn apply_requires_every_imported_actor_program_to_remain_available() {
        let mut store = MemStore::default();
        let (initial, install) = install_fixture(&mut store, ConsistencyModeV2::Local, b"before");
        let work = linear_work(initial, install.resulting_state_root.unwrap());
        let transition = linear_transition(&work, b"after");
        seed_direct_ingress(&mut store, &work);
        store.programs.remove(&program());
        let before = store.clone();

        assert_eq!(
            execute_guest_accumulate(
                &mut store,
                &AccumulateRequestV2::Apply(AccumulationEnvelopeV2 {
                    work,
                    transition,
                    provided_blobs: Vec::new(),
                }),
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
                &AccumulateRequestV2::Apply(AccumulationEnvelopeV2 {
                    work,
                    transition,
                    provided_blobs: Vec::new(),
                }),
            )
            .unwrap(),
            rejected(AccumulationRejectionV2::InvalidWorkflowTransition)
        );
        assert_eq!(store, before);
    }

    #[test]
    fn disclosed_space_role_credentials_satisfy_generated_thresholds() {
        let mut store = MemStore::default();
        let initial = store.provide_blob(b"before").unwrap();
        store.programs.insert(program(), FIXTURE_ACTOR_PVM.to_vec());
        let required_policy =
            super::super::space_role_policy_hash(crate::SpaceRole::Member.as_u8()).unwrap();
        let install = AccumulateRequestV2::Install(ServiceGenesisV2 {
            external_actors: external_bindings(),
            service: identity(),
            consistency: ConsistencyModeV2::Local,
            actors: vec![ActorGenesisV2 {
                actor: actor(),
                name: "root".into(),
                parent: None,
                producer: super::super::ProducerId([4; 32]),
                deployment: identity().deployment,
                program: program(),
                initial_state: initial.clone(),
                crdt: false,
                role_policies: role_policies(vec![MethodPolicyV2 {
                    method: "set".into(),
                    schema: Hash([6; 32]),
                    policy: required_policy,
                    public: false,
                    attested: false,
                    space_role: Some(crate::SpaceRole::Member.as_u8()),
                    actor_role: None,
                }]),
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

        let mut admitted_work = linear_work(initial.clone(), base);
        admitted_work.origin = origin;
        let developer = RoleCredentialV2 {
            holder: origin,
            scope: admitted_work.authorization_scope(),
            space_role: Some(crate::SpaceRole::Developer),
            actor_role: None,
            authenticator: b"developer grant".to_vec(),
        };
        admitted_work.authorization = developer.disclosed_evidence(required_policy);
        seed_direct_ingress(&mut store, &admitted_work);
        store.role_credential_allowlist.insert(
            RoleCredentialVerificationRequestV2::for_work(&admitted_work)
                .unwrap()
                .hash(),
        );
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

        let mut replayed_work = linear_work(initial.clone(), base);
        replayed_work.origin = origin;
        replayed_work.invocation = super::super::InvocationId([0x52; 32]);
        replayed_work.authorization = developer.disclosed_evidence(required_policy);
        seed_direct_ingress(&mut store, &replayed_work);
        let replayed = AccumulateRequestV2::Apply(AccumulationEnvelopeV2 {
            transition: linear_transition(&replayed_work, b"replayed"),
            work: replayed_work,
            provided_blobs: vec![],
        });
        let before_replay = store.clone();
        assert_eq!(
            execute_guest_accumulate(&mut store, &replayed).unwrap(),
            rejected(AccumulationRejectionV2::Unauthorized),
            "a valid credential for one invocation cannot authorize another"
        );
        assert_eq!(store, before_replay);

        let mut denied_work = linear_work(initial.clone(), base);
        denied_work.origin = origin;
        let guest = RoleCredentialV2 {
            holder: origin,
            scope: denied_work.authorization_scope(),
            space_role: Some(crate::SpaceRole::Guest),
            actor_role: None,
            authenticator: b"guest grant".to_vec(),
        };
        denied_work.authorization = guest.disclosed_evidence(required_policy);
        seed_direct_ingress(&mut store, &denied_work);
        store.role_credential_allowlist.insert(
            RoleCredentialVerificationRequestV2::for_work(&denied_work)
                .unwrap()
                .hash(),
        );
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

        let mut malformed_resume = linear_work(initial, base);
        malformed_resume.workflow_step = 1;
        malformed_resume.origin = origin;
        let zero_scope = RoleCredentialV2 {
            holder: origin,
            scope: Hash::ZERO,
            space_role: Some(crate::SpaceRole::Developer),
            actor_role: None,
            authenticator: b"malformed grant".to_vec(),
        };
        malformed_resume.authorization = zero_scope.disclosed_evidence(required_policy);
        let malformed = AccumulateRequestV2::Apply(AccumulationEnvelopeV2 {
            transition: linear_transition(&malformed_resume, b"must not execute"),
            work: malformed_resume,
            provided_blobs: vec![],
        });
        let before = store.clone();
        assert_eq!(
            execute_guest_accumulate(&mut store, &malformed).unwrap(),
            rejected(AccumulationRejectionV2::Unauthorized),
            "a malformed resumed credential is a deterministic denial, not a host error"
        );
        assert_eq!(store, before);
    }

    #[test]
    fn continuation_slices_are_guest_bound_to_one_workflow_identity_and_next_step() {
        let mut store = MemStore::default();
        let (initial, install) = install_fixture(&mut store, ConsistencyModeV2::Local, b"before");
        let first_work = linear_work(initial, install.resulting_state_root.unwrap());
        seed_direct_ingress(&mut store, &first_work);
        let continuation_bytes = ContinuationSnapshotV2 {
            snapshot_version: super::super::SNAPSHOT_VERSION,
            jar_semantics: super::super::EXECUTION_SEMANTICS_ID,
            vos_abi: super::super::ABI_VERSION,
            service: first_work.service.clone(),
            invocation: first_work.invocation,
            checkpoint_step: first_work.workflow_step,
            actor: first_work.target,
            actor_deployment: first_work.target_deployment,
            actor_program: first_work.target_program,
            programs: continuation_programs(&first_work),
            await_ordinal: 0,
            pending_call: None,
            pending_actor: None,
            causal_context: first_work.causal_context.clone(),
            suspended_actors: vec![first_work.target],
            kernel_snapshot: vec![1],
        }
        .encode();
        let continuation = BlobRefV2::of_bytes(&continuation_bytes);
        assert!(
            !store.blobs.contains_key(&continuation.hash),
            "candidate continuation must not already exist in service storage"
        );
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
                    provided_blobs: Vec::new(),
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
                    provided_blobs: Vec::new(),
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
                    provided_blobs: Vec::new(),
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
                    provided_blobs: Vec::new(),
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
                    provided_blobs: Vec::new(),
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
                    provided_blobs: Vec::new(),
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
        seed_direct_ingress(&mut store, &first_work);
        let peer = ActorId([44; 32]);
        let call = first_work.invocation.call_id(0);
        let mut payload = vec![crate::value::TAG_DYNAMIC];
        payload.extend_from_slice(&crate::Encode::encode(&crate::value::Msg::new("set")));
        let outbound = MessageRecordV2 {
            call_id: call,
            caller_invocation: first_work.invocation,
            await_ordinal: 0,
            from_service: first_work.service.clone(),
            from: first_work.target,
            to_service: external_bindings()
                .into_iter()
                .find(|binding| binding.actor == peer)
                .unwrap()
                .service,
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
            actor_deployment: first_work.target_deployment,
            actor_program: first_work.target_program,
            programs: continuation_programs(&first_work),
            await_ordinal: 0,
            pending_call: Some(call),
            pending_actor: Some(first_work.target),
            causal_context: first_work.causal_context.clone(),
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

        let mut orphaned_outbox = checkpoint.clone();
        orphaned_outbox.outbox.push(message(
            9,
            first_work.target,
            ActorId([45; 32]),
            None,
            Some(9),
        ));
        orphaned_outbox
            .outbox
            .sort_by_key(|message| message.call_id);
        let before = store.clone();
        assert_eq!(
            execute_guest_accumulate(
                &mut store,
                &AccumulateRequestV2::Apply(AccumulationEnvelopeV2 {
                    work: first_work.clone(),
                    transition: orphaned_outbox,
                    provided_blobs: vec![ImportedBlobV2 {
                        reference: continuation.clone(),
                        bytes: continuation_bytes.clone(),
                    }],
                }),
            )
            .unwrap(),
            rejected(AccumulationRejectionV2::InvalidWorkflowTransition)
        );
        assert_eq!(store, before);

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

        let mut expired = resume.clone();
        expired.logical_timeslot = 10;
        let mut expired_transition = completed.clone();
        expired_transition.consumed_input = expired.input_id();
        assert_eq!(
            execute_guest_accumulate(
                &mut store,
                &AccumulateRequestV2::Apply(AccumulationEnvelopeV2 {
                    work: expired,
                    transition: expired_transition,
                    provided_blobs: vec![],
                }),
            )
            .unwrap(),
            rejected(AccumulationRejectionV2::InvalidReceipt)
        );
        assert_eq!(store, before);

        let mut oversized = resume.clone();
        {
            let oversized_awaited = oversized.awaited_reply.as_mut().unwrap();
            oversized_awaited.reply.result = vec![0; super::super::CHECKPOINT_TOKEN_CAPACITY - 1];
            oversized_awaited.receipt.reply_commitment = Some(oversized_awaited.reply.commitment());
        }
        let injection = super::super::AwaitResumeV2 {
            checkpoint: super::super::CheckpointTokenV2 {
                input: oversized.input_id(),
                base: oversized.base.clone(),
                work_hash: oversized.hash(),
                resume_work: Some(oversized.clone()),
                base_causal_height: oversized.base_causal_height,
                change: None,
                expected: Some(continuation.hash),
                replacement: None,
                pending_call: Some(call),
                pending_actor: Some(resume.target),
                previously_suspended: vec![resume.target],
                suspended: Vec::new(),
            },
            reply: oversized.awaited_reply.as_ref().unwrap().reply.clone(),
            attestation: None,
        };
        assert!(injection.encode().len() > super::super::CHECKPOINT_TOKEN_CAPACITY);
        assert_eq!(
            execute_guest_accumulate(
                &mut store,
                &AccumulateRequestV2::Apply(AccumulationEnvelopeV2 {
                    work: oversized,
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
            expected_producer: awaited.reply.producer,
            receipt: awaited.receipt,
        };
        store.receipt_allowlist.insert(request.hash());
        let apply = AccumulateRequestV2::Apply(AccumulationEnvelopeV2 {
            work: resume,
            transition: completed,
            provided_blobs: vec![],
        });
        let AccumulateRequestV2::Apply(expected) = &apply else {
            unreachable!()
        };
        let expected_awaited = expected.work.awaited_reply.clone().unwrap();
        let expected_input = expected.work.input_id();
        let expected_work_hash = expected.work.hash();
        let accepted = execute_guest_accumulate(&mut store, &apply).unwrap();
        assert!(matches!(
            accepted,
            AccumulationResultV2::Accepted {
                duplicate: false,
                ..
            }
        ));
        let header = StoreHeaderV2::open(store.rows.get(header_storage_key()).unwrap()).unwrap();
        let tree = ServiceStateTreeV2::new(&mut store, header.service_root);
        assert_eq!(tree.get(&StateKeyV2::Outbox(call)).unwrap(), None);
        drop(tree);
        let admission = ReplyAdmissionRecordV2::decode(
            store
                .rows
                .get(&reply_admission_storage_key(call))
                .expect("reply admission commits with the resumed slice"),
        )
        .unwrap();
        assert_eq!(admission.call_id, call);
        assert_eq!(admission.input, expected_input);
        assert_eq!(admission.awaited_reply, expected_awaited);
        assert_eq!(admission.work_hash, expected_work_hash);

        assert!(matches!(
            execute_guest_accumulate(&mut store, &apply).unwrap(),
            AccumulationResultV2::Accepted {
                duplicate: true,
                ..
            }
        ));

        let mut missing_admission = store.clone();
        missing_admission
            .rows
            .remove(&reply_admission_storage_key(call));
        assert_eq!(
            execute_guest_accumulate(&mut missing_admission, &apply),
            Err(GuestAccumulateError::CorruptStore)
        );

        let mut orphaned_admission = store;
        orphaned_admission
            .rows
            .remove(&dedup_storage_key(expected_input));
        assert_eq!(
            execute_guest_accumulate(&mut orphaned_admission, &apply),
            Err(GuestAccumulateError::CorruptStore)
        );
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
        let to_service = external_bindings()
            .into_iter()
            .find(|binding| binding.actor == to)
            .map(|binding| binding.service)
            .unwrap_or_else(identity);
        MessageRecordV2 {
            call_id: caller_invocation.call_id(await_ordinal),
            caller_invocation,
            await_ordinal,
            from_service: identity(),
            from,
            to_service,
            to,
            parent,
            payload,
            authorization: AuthorizationEvidenceV2::Public,
            proof_requested: false,
            deadline_timeslot,
        }
    }

    fn source_receipt(outbox: &[MessageRecordV2]) -> AccumulationReceiptV2 {
        AccumulationReceiptV2 {
            service: outbox
                .first()
                .expect("source receipt requires one message")
                .from_service
                .clone(),
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

    #[test]
    fn logical_timeout_is_guest_committed_atomic_and_deduplicated() {
        let mut store = MemStore::default();
        let (initial, install) = install_fixture(&mut store, ConsistencyModeV2::Local, b"before");
        let work = linear_work(initial, install.resulting_state_root.unwrap());
        seed_direct_ingress(&mut store, &work);
        let peer = ActorId([44; 32]);
        let call = work.invocation.call_id(0);
        let mut payload = vec![crate::value::TAG_DYNAMIC];
        payload.extend_from_slice(&crate::Encode::encode(&crate::value::Msg::new("set")));
        let message = MessageRecordV2 {
            call_id: call,
            caller_invocation: work.invocation,
            await_ordinal: 0,
            from_service: work.service.clone(),
            from: work.target,
            to_service: external_bindings()
                .into_iter()
                .find(|binding| binding.actor == peer)
                .unwrap()
                .service,
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
            service: work.service.clone(),
            invocation: work.invocation,
            checkpoint_step: 0,
            actor: work.target,
            actor_deployment: work.target_deployment,
            actor_program: work.target_program,
            programs: continuation_programs(&work),
            await_ordinal: 0,
            pending_call: Some(call),
            pending_actor: Some(work.target),
            causal_context: work.causal_context.clone(),
            suspended_actors: vec![work.target],
            kernel_snapshot: vec![1],
        }
        .encode();
        let continuation = BlobRefV2::of_bytes(&continuation_bytes);
        let mut transition = linear_transition(&work, b"checkpoint");
        transition.reply = None;
        transition.continuations.push(ContinuationChangeV2 {
            actor: work.target,
            expected: None,
            replacement: Some(continuation.clone()),
        });
        transition.outbox.push(message);
        transition.exported_blobs.push(continuation.clone());
        let AccumulationResultV2::Accepted { receipt, .. } = execute_guest_accumulate(
            &mut store,
            &AccumulateRequestV2::Apply(AccumulationEnvelopeV2 {
                work: work.clone(),
                transition,
                provided_blobs: vec![ImportedBlobV2 {
                    reference: continuation.clone(),
                    bytes: continuation_bytes,
                }],
            }),
        )
        .unwrap() else {
            panic!("await checkpoint rejected")
        };
        let expiration = CallExpirationEnvelopeV2 {
            service: work.service.clone(),
            timeout: CallTimeoutV2 {
                call_id: call,
                caller_invocation: work.invocation,
                caller_actor: work.target,
                checkpoint_step: 0,
                await_ordinal: 0,
                deadline_timeslot: 10,
                expired_at: 10,
            },
            base: ConsistencyBaseV2::Linear {
                revision: receipt.sequence,
                state_root: receipt.resulting_state_root.unwrap(),
            },
            base_causal_height: None,
            crdt_change: None,
        };

        let before_untrusted = store.clone();
        assert_eq!(
            execute_guest_accumulate(
                &mut store,
                &AccumulateRequestV2::ExpireCall(expiration.clone())
            )
            .unwrap(),
            rejected(AccumulationRejectionV2::InvalidWorkflowTransition)
        );
        assert_eq!(store, before_untrusted);
        store.logical_timeslot = Some(9);
        assert_eq!(
            execute_guest_accumulate(
                &mut store,
                &AccumulateRequestV2::ExpireCall(expiration.clone())
            )
            .unwrap(),
            rejected(AccumulationRejectionV2::InvalidWorkflowTransition)
        );
        store.logical_timeslot = Some(10);

        let mut stale = expiration.clone();
        stale.base = work.base.clone();
        let before = store.clone();
        assert!(matches!(
            execute_guest_accumulate(&mut store, &AccumulateRequestV2::ExpireCall(stale)).unwrap(),
            AccumulationResultV2::Rejected(AccumulationRejectionV2::StaleLinearWork { .. })
        ));
        assert_eq!(store, before);

        let AccumulationResultV2::CallExpired {
            timeout,
            duplicate: false,
        } = execute_guest_accumulate(
            &mut store,
            &AccumulateRequestV2::ExpireCall(expiration.clone()),
        )
        .unwrap()
        else {
            panic!("logical timeout was not committed")
        };
        timeout.validate().unwrap();
        let header = StoreHeaderV2::open(store.rows.get(header_storage_key()).unwrap()).unwrap();
        assert_eq!(header.admission_timeslot_high_water, 10);
        let tree = ServiceStateTreeV2::new(&mut store, header.service_root);
        assert_eq!(tree.get(&StateKeyV2::Outbox(call)).unwrap(), None);
        assert_eq!(
            tree_get_wire::<_, BlobRefV2>(&tree, &StateKeyV2::Continuation(work.target)).unwrap(),
            Some(continuation.clone())
        );
        drop(tree);

        let committed = store.clone();
        assert!(matches!(
            execute_guest_accumulate(
                &mut store,
                &AccumulateRequestV2::ExpireCall(expiration.clone())
            )
            .unwrap(),
            AccumulationResultV2::CallExpired {
                duplicate: true,
                ..
            }
        ));
        assert_eq!(store, committed);
        let mut divergent = expiration;
        divergent.timeout.deadline_timeslot = 11;
        divergent.timeout.expired_at = 11;
        store.logical_timeslot = Some(11);
        assert_eq!(
            execute_guest_accumulate(&mut store, &AccumulateRequestV2::ExpireCall(divergent))
                .unwrap(),
            rejected(AccumulationRejectionV2::DivergentDuplicate)
        );
        store.logical_timeslot = Some(10);
        assert_eq!(store, committed);

        let mut resume = work.clone();
        resume.workflow_step = 1;
        resume.logical_timeslot = 10;
        resume.base = ConsistencyBaseV2::Linear {
            revision: timeout.receipt.sequence,
            state_root: timeout.receipt.resulting_state_root.unwrap(),
        };
        resume.imported_actors[0].state = BlobRefV2::of_bytes(b"checkpoint");
        resume.imported_actors[0].continuation = Some(continuation.clone());
        resume.awaited_timeout = Some(Box::new(timeout));
        let mut completed = linear_transition(&resume, b"after timeout");
        completed.continuations.push(ContinuationChangeV2 {
            actor: resume.target,
            expected: Some(continuation.hash),
            replacement: None,
        });
        assert!(matches!(
            execute_guest_accumulate(
                &mut store,
                &AccumulateRequestV2::Apply(AccumulationEnvelopeV2 {
                    work: resume,
                    transition: completed,
                    provided_blobs: vec![],
                })
            )
            .unwrap(),
            AccumulationResultV2::Accepted {
                duplicate: false,
                ..
            }
        ));
        let header = StoreHeaderV2::open(store.rows.get(header_storage_key()).unwrap()).unwrap();
        let tree = ServiceStateTreeV2::new(&mut store, header.service_root);
        assert_eq!(
            tree.get(&StateKeyV2::Continuation(work.target)).unwrap(),
            None
        );
    }

    #[test]
    fn crdt_timeout_sync_reconstructs_outbox_removal_and_durable_outcome() {
        let mut source = MemStore::default();
        let mut destination = MemStore::default();
        let (initial, _) = install_fixture(&mut source, ConsistencyModeV2::Crdt, b"before");
        install_fixture(&mut destination, ConsistencyModeV2::Crdt, b"before");
        let work = crdt_work(initial, 29, vec![]);
        seed_direct_ingress(&mut source, &work);
        let peer = ActorId([44; 32]);
        let call = work.invocation.call_id(0);
        let message = awaited_message(&work, peer, None, Some(20));
        let continuation_bytes = ContinuationSnapshotV2 {
            snapshot_version: super::super::SNAPSHOT_VERSION,
            jar_semantics: super::super::EXECUTION_SEMANTICS_ID,
            vos_abi: super::super::ABI_VERSION,
            service: work.service.clone(),
            invocation: work.invocation,
            checkpoint_step: 0,
            actor: work.target,
            actor_deployment: work.target_deployment,
            actor_program: work.target_program,
            programs: continuation_programs(&work),
            await_ordinal: 0,
            pending_call: Some(call),
            pending_actor: Some(work.target),
            causal_context: None,
            suspended_actors: vec![work.target],
            kernel_snapshot: vec![2],
        }
        .encode();
        let continuation = BlobRefV2::of_bytes(&continuation_bytes);
        let state_bytes = b"crdt checkpoint".to_vec();
        let state = BlobRefV2::of_bytes(&state_bytes);
        let mut transition = crdt_transition(&work, state.clone(), 1);
        transition.continuations.push(ContinuationChangeV2 {
            actor: work.target,
            expected: None,
            replacement: Some(continuation.clone()),
        });
        transition.outbox.push(message);
        transition.exported_blobs.push(continuation.clone());
        transition.crdt_change.as_mut().unwrap().workflow = transition.workflow_operations(&work);
        transition.crdt_change.as_mut().unwrap().exported_blobs = transition.exported_blobs.clone();
        let checkpoint_change = transition.crdt_change.clone().unwrap();
        let mut checkpoint_blobs = vec![
            ImportedBlobV2 {
                reference: continuation.clone(),
                bytes: continuation_bytes,
            },
            ImportedBlobV2 {
                reference: state.clone(),
                bytes: state_bytes,
            },
        ];
        checkpoint_blobs.sort_by_key(|blob| blob.reference.hash);
        let AccumulationResultV2::Accepted {
            receipt: checkpoint_receipt,
            ..
        } = execute_guest_accumulate(
            &mut source,
            &AccumulateRequestV2::Apply(AccumulationEnvelopeV2 {
                work: work.clone(),
                transition,
                provided_blobs: checkpoint_blobs.clone(),
            }),
        )
        .unwrap()
        else {
            panic!("CRDT await checkpoint rejected")
        };
        let heads = checkpoint_receipt.resulting_crdt_heads.clone();
        let timeout = CallTimeoutV2 {
            call_id: call,
            caller_invocation: work.invocation,
            caller_actor: work.target,
            checkpoint_step: 0,
            await_ordinal: 0,
            deadline_timeslot: 20,
            expired_at: 20,
        };
        let expiration_change = CrdtChangeV2 {
            id: CrdtChangeV2::derive_expiration_id(&work.service, &timeout, &heads),
            work_hash: timeout.commitment(),
            causal_dependencies: heads.clone(),
            causal_height: 2,
            operations: vec![],
            workflow: vec![WorkflowOperationV2::ExpireCall(timeout.clone())],
            materializations: vec![],
            awaited_reply: None,
            exported_blobs: vec![],
        };
        let expiration = CallExpirationEnvelopeV2 {
            service: work.service.clone(),
            timeout,
            base: ConsistencyBaseV2::Crdt { heads },
            base_causal_height: Some(1),
            crdt_change: Some(expiration_change.clone()),
        };
        source.logical_timeslot = Some(20);
        let AccumulationResultV2::CallExpired {
            timeout: accumulated,
            duplicate: false,
        } = execute_guest_accumulate(&mut source, &AccumulateRequestV2::ExpireCall(expiration))
            .unwrap()
        else {
            panic!("CRDT timeout rejected")
        };
        let expiration_receipt = accumulated.receipt.clone();
        let expiration_cid = expiration_change.cid();
        assert_eq!(
            expiration_receipt.resulting_crdt_heads,
            vec![expiration_cid]
        );

        destination.receipt_allowlist.insert(
            ReceiptVerificationRequestV2 {
                expected_producer: work.target,
                receipt: checkpoint_receipt.clone(),
            }
            .hash(),
        );
        destination.receipt_allowlist.insert(
            ReceiptVerificationRequestV2 {
                expected_producer: work.target,
                receipt: expiration_receipt.clone(),
            }
            .hash(),
        );
        let mut nodes = vec![
            super::super::CrdtSyncNodeV2 {
                change: checkpoint_change,
                receipt: checkpoint_receipt,
            },
            super::super::CrdtSyncNodeV2 {
                change: expiration_change,
                receipt: expiration_receipt,
            },
        ];
        nodes.sort_by_key(|node| node.change.cid());
        assert!(matches!(
            execute_guest_accumulate(
                &mut destination,
                &AccumulateRequestV2::SyncCrdt(CrdtSyncEnvelopeV2 {
                    service: work.service.clone(),
                    advertised_heads: vec![expiration_cid],
                    nodes,
                    provided_blobs: checkpoint_blobs,
                })
            )
            .unwrap(),
            AccumulationResultV2::Accepted {
                duplicate: false,
                ..
            }
        ));
        let header =
            StoreHeaderV2::open(destination.rows.get(header_storage_key()).unwrap()).unwrap();
        let tree = ServiceStateTreeV2::new(&mut destination, header.service_root);
        assert_eq!(tree.get(&StateKeyV2::Outbox(call)).unwrap(), None);
        drop(tree);
        assert_eq!(
            AccumulatedTimeoutV2::decode(
                destination
                    .rows
                    .get(&call_expiration_storage_key(call))
                    .unwrap()
            )
            .unwrap(),
            accumulated
        );

        let completed_bytes = b"after CRDT timeout".to_vec();
        let completed_state = BlobRefV2::of_bytes(&completed_bytes);
        let mut resumed = work;
        resumed.workflow_step = 1;
        resumed.logical_timeslot = 20;
        resumed.base = ConsistencyBaseV2::Crdt {
            heads: vec![expiration_cid],
        };
        resumed.base_causal_height = Some(2);
        resumed.imported_actors[0].state = state;
        resumed.imported_actors[0].continuation = Some(continuation.clone());
        resumed.awaited_timeout = Some(Box::new(accumulated));
        let resumed_input = resumed.input_id();
        let mut completed = crdt_transition(&resumed, completed_state.clone(), 3);
        completed.continuations.push(ContinuationChangeV2 {
            actor: resumed.target,
            expected: Some(continuation.hash),
            replacement: None,
        });
        completed.reply = Some(ReplyRecordV2 {
            call_id: resumed.invocation.root_reply_id(),
            producer: resumed.target,
            result: vec![23],
        });
        completed.crdt_change.as_mut().unwrap().workflow = completed.workflow_operations(&resumed);
        let completed_cid = completed.crdt_change.as_ref().unwrap().cid();
        let completed_result = execute_guest_accumulate(
            &mut destination,
            &AccumulateRequestV2::Apply(AccumulationEnvelopeV2 {
                work: resumed,
                transition: completed,
                provided_blobs: vec![ImportedBlobV2 {
                    reference: completed_state.clone(),
                    bytes: completed_bytes,
                }],
            }),
        )
        .unwrap();
        assert!(
            matches!(
                completed_result,
                AccumulationResultV2::Accepted {
                    duplicate: false,
                    ..
                }
            ),
            "unexpected CRDT timeout-resume result: {completed_result:?}"
        );

        // Apply a descendant after the resumed reply publication already
        // exists. This rematerializes the historical expiration; the old
        // implementation incorrectly selected the now-visible step-1
        // workflow and deleted this publication during the descendant apply.
        let later_bytes = b"later CRDT change".to_vec();
        let later_state = BlobRefV2::of_bytes(&later_bytes);
        let mut later_work = crdt_work(completed_state, 30, vec![completed_cid]);
        later_work.base_causal_height = Some(3);
        seed_direct_ingress(&mut destination, &later_work);
        let later = crdt_transition(&later_work, later_state.clone(), 4);
        assert!(matches!(
            execute_guest_accumulate(
                &mut destination,
                &AccumulateRequestV2::Apply(AccumulationEnvelopeV2 {
                    work: later_work,
                    transition: later,
                    provided_blobs: vec![ImportedBlobV2 {
                        reference: later_state,
                        bytes: later_bytes,
                    }],
                })
            )
            .unwrap(),
            AccumulationResultV2::Accepted {
                duplicate: false,
                ..
            }
        ));
        assert!(
            read(&destination, &publication_storage_key(resumed_input))
                .unwrap()
                .is_some(),
            "rematerializing the historical timeout must not delete the resumed slice publication"
        );
    }

    fn delivery(
        header: &StoreHeaderV2,
        logical_timeslot: u64,
        message: MessageRecordV2,
        source_receipt: AccumulationReceiptV2,
    ) -> DeliveryEnvelopeV2 {
        DeliveryEnvelopeV2 {
            service: header.service.clone(),
            logical_timeslot,
            base: ConsistencyBaseV2::Linear {
                revision: header.revision,
                state_root: header.state_root.unwrap(),
            },
            source_outbox: vec![message.clone()],
            message,
            source_receipt,
        }
    }

    #[test]
    fn finalized_delivery_is_guest_owned_restart_drained_and_retry_stable() {
        let mut store = MemStore::default();
        let (initial, _) = install_fixture(&mut store, ConsistencyModeV2::Local, b"before");
        let header = StoreHeaderV2::open(store.rows.get(header_storage_key()).unwrap()).unwrap();
        let sender = ActorId([71; 32]);
        let mut incoming = message(70, sender, actor(), None, Some(10));
        incoming.from_service.root_service = RootServiceId([90; 32]);
        incoming.from_service.deployment = DeploymentId([91; 32]);
        let source_outbox = vec![incoming.clone()];
        let source_receipt = source_receipt(&source_outbox);
        let envelope = delivery(&header, 2, incoming.clone(), source_receipt.clone());
        let request = AccumulateRequestV2::Deliver(envelope.clone());

        let before = store.clone();
        assert_eq!(
            execute_guest_accumulate(&mut store, &request).unwrap(),
            rejected(AccumulationRejectionV2::ReceiptUnavailable)
        );
        assert_eq!(store, before);

        store.receipt_allowlist.insert(
            ReceiptVerificationRequestV2 {
                expected_producer: sender,
                receipt: source_receipt,
            }
            .hash(),
        );
        let authorized = store.clone();
        let mut crdt_source = envelope.clone();
        crdt_source.source_receipt.consistency = ConsistencyModeV2::Crdt;
        crdt_source.source_receipt.resulting_state_root = None;
        crdt_source.source_receipt.resulting_crdt_heads = vec![Hash([94; 32])];
        assert_eq!(
            execute_guest_accumulate(&mut store, &AccumulateRequestV2::Deliver(crdt_source),)
                .unwrap(),
            rejected(AccumulationRejectionV2::InvalidConsistency)
        );
        assert_eq!(store, authorized);

        let mut stale = envelope.clone();
        let ConsistencyBaseV2::Linear { revision, .. } = &mut stale.base else {
            unreachable!()
        };
        *revision += 1;
        assert!(matches!(
            execute_guest_accumulate(&mut store, &AccumulateRequestV2::Deliver(stale)).unwrap(),
            AccumulationResultV2::Rejected(AccumulationRejectionV2::StaleLinearWork { .. })
        ));
        assert_eq!(store, authorized);

        let mut tampered = envelope.clone();
        tampered.source_outbox[0].payload.push(0);
        assert_eq!(
            execute_guest_accumulate(&mut store, &AccumulateRequestV2::Deliver(tampered)).unwrap(),
            rejected(AccumulationRejectionV2::NonCanonical)
        );
        assert_eq!(store, authorized);

        let accepted = execute_guest_accumulate(&mut store, &request).unwrap();
        let AccumulationResultV2::Accepted {
            receipt,
            published,
            duplicate: false,
        } = accepted
        else {
            panic!("finalized delivery rejected")
        };
        assert_eq!(published, PublishedEffectsV2::default());
        assert_eq!(receipt.accepted_transition, envelope.commitment());
        let admitted_header =
            StoreHeaderV2::open(store.rows.get(header_storage_key()).unwrap()).unwrap();
        assert_eq!(admitted_header.admission_timeslot_high_water, 2);
        let tree = ServiceStateTreeV2::new(&mut store, admitted_header.service_root);
        assert_eq!(
            tree.get(&StateKeyV2::Inbox(incoming.call_id)).unwrap(),
            Some(incoming.encode())
        );
        drop(tree);
        let admitted = DeliveryRecordV2::decode(
            store
                .rows
                .get(&delivery_storage_key(incoming.call_id))
                .unwrap(),
        )
        .unwrap();
        assert!(!admitted.consumed);
        assert_eq!(admitted.logical_timeslot, 2);

        let mut inbox_work = linear_work(initial, admitted_header.state_root.unwrap());
        inbox_work.invocation = InvocationId::for_call(incoming.call_id);
        inbox_work.logical_timeslot = 3;
        inbox_work.arguments = incoming.payload.clone();
        inbox_work.origin = Origin::Actor(incoming.from);
        inbox_work.authorization = incoming.authorization.clone();
        inbox_work.causal_parent = Some(incoming.caller_invocation);
        inbox_work.parent_call = Some(incoming.call_id);
        inbox_work.causal_context = Some(super::super::CausalCallContextV2::from(&incoming));
        inbox_work.base = ConsistencyBaseV2::Linear {
            revision: admitted_header.revision,
            state_root: admitted_header.state_root.unwrap(),
        };
        let mut inbox_transition = linear_transition(&inbox_work, b"after inbox");
        inbox_transition.reply.as_mut().unwrap().call_id = incoming.call_id;
        assert!(matches!(
            execute_guest_accumulate(
                &mut store,
                &AccumulateRequestV2::Apply(AccumulationEnvelopeV2 {
                    work: inbox_work,
                    transition: inbox_transition,
                    provided_blobs: vec![],
                }),
            )
            .unwrap(),
            AccumulationResultV2::Accepted {
                duplicate: false,
                ..
            }
        ));
        let consumed = DeliveryRecordV2::decode(
            store
                .rows
                .get(&delivery_storage_key(incoming.call_id))
                .unwrap(),
        )
        .unwrap();
        assert!(consumed.consumed);

        let current = StoreHeaderV2::open(store.rows.get(header_storage_key()).unwrap()).unwrap();
        let retry = delivery(
            &current,
            envelope.logical_timeslot + 10,
            incoming,
            envelope.source_receipt.clone(),
        );
        assert_eq!(retry.retry_identity(), envelope.retry_identity());
        assert_ne!(retry.commitment(), envelope.commitment());
        assert!(matches!(
            execute_guest_accumulate(&mut store, &AccumulateRequestV2::Deliver(retry)).unwrap(),
            AccumulationResultV2::Accepted {
                duplicate: true,
                published,
                ..
            } if published == PublishedEffectsV2::default()
        ));

        let mut divergent = envelope;
        divergent.source_receipt.sequence += 1;
        assert_eq!(
            execute_guest_accumulate(&mut store, &AccumulateRequestV2::Deliver(divergent)).unwrap(),
            rejected(AccumulationRejectionV2::DivergentDuplicate)
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
        let incoming = message(42, actor(), actor(), None, Some(10));

        let mut valid_work = linear_work(initial.clone(), root);
        valid_work.invocation = InvocationId([43; 32]);
        seed_direct_ingress(&mut installed, &valid_work);
        let outgoing = awaited_message(&valid_work, peer, Some(incoming.call_id), Some(9));
        let (mut valid, valid_continuation) = awaiting_transition(&valid_work, b"valid", outgoing);
        valid.inbox.push(incoming.clone());
        let accepted = execute_guest_accumulate(
            &mut installed,
            &AccumulateRequestV2::Apply(AccumulationEnvelopeV2 {
                work: valid_work,
                transition: valid,
                provided_blobs: vec![valid_continuation],
            }),
        )
        .unwrap();
        assert!(matches!(accepted, AccumulationResultV2::Accepted { .. }));

        let reject =
            |to: ActorId, parent: Option<super::super::CallId>, deadline_timeslot: Option<u64>| {
                let mut store = MemStore::default();
                let (initial, receipt) =
                    install_fixture(&mut store, ConsistencyModeV2::Local, b"before");
                let work = linear_work(initial, receipt.resulting_state_root.unwrap());
                seed_direct_ingress(&mut store, &work);
                let outgoing = awaited_message(&work, to, parent, deadline_timeslot);
                let (mut transition, continuation) =
                    awaiting_transition(&work, b"must-not-commit", outgoing);
                transition.inbox.push(incoming.clone());
                let before = store.clone();
                let result = execute_guest_accumulate(
                    &mut store,
                    &AccumulateRequestV2::Apply(AccumulationEnvelopeV2 {
                        work,
                        transition,
                        provided_blobs: vec![continuation],
                    }),
                )
                .unwrap();
                assert_eq!(store, before);
                result
            };

        assert_eq!(
            reject(actor(), Some(incoming.call_id), Some(9)),
            rejected(AccumulationRejectionV2::MessageCycle)
        );
        assert_eq!(
            reject(peer, Some(incoming.call_id), Some(11)),
            rejected(AccumulationRejectionV2::InvalidWorkflowTransition)
        );
        assert_eq!(
            reject(peer, Some(super::super::CallId([99; 32])), Some(9)),
            rejected(AccumulationRejectionV2::InvalidWorkflowTransition)
        );

        let mut store = MemStore::default();
        let (initial, receipt) = install_fixture(&mut store, ConsistencyModeV2::Local, b"before");
        let work = linear_work(initial, receipt.resulting_state_root.unwrap());
        seed_direct_ingress(&mut store, &work);
        let mut no_checkpoint = linear_transition(&work, b"must-not-commit");
        no_checkpoint
            .outbox
            .push(awaited_message(&work, peer, None, Some(9)));
        let before = store.clone();
        assert_eq!(
            execute_guest_accumulate(
                &mut store,
                &AccumulateRequestV2::Apply(AccumulationEnvelopeV2 {
                    work,
                    transition: no_checkpoint,
                    provided_blobs: Vec::new(),
                }),
            )
            .unwrap(),
            rejected(AccumulationRejectionV2::InvalidWorkflowTransition)
        );
        assert_eq!(store, before);

        let mut store = MemStore::default();
        let (initial, receipt) = install_fixture(&mut store, ConsistencyModeV2::Local, b"before");
        let work = linear_work(initial, receipt.resulting_state_root.unwrap());
        seed_direct_ingress(&mut store, &work);
        let mut forged_sender = linear_transition(&work, b"must-not-commit");
        forged_sender
            .inbox
            .push(message(48, caller, actor(), None, Some(9)));
        let before = store.clone();
        assert_eq!(
            execute_guest_accumulate(
                &mut store,
                &AccumulateRequestV2::Apply(AccumulationEnvelopeV2 {
                    work,
                    transition: forged_sender,
                    provided_blobs: Vec::new(),
                }),
            )
            .unwrap(),
            rejected(AccumulationRejectionV2::InvalidWorkflowTransition)
        );
        assert_eq!(store, before);

        let mut store = MemStore::default();
        let (initial, receipt) = install_fixture(&mut store, ConsistencyModeV2::Local, b"before");
        let work = linear_work(initial, receipt.resulting_state_root.unwrap());
        seed_direct_ingress(&mut store, &work);
        let mut collision = linear_transition(&work, b"must-not-commit");
        collision.inbox.push(incoming.clone());
        collision.outbox.push(incoming);
        assert_eq!(
            execute_guest_accumulate(
                &mut store,
                &AccumulateRequestV2::Apply(AccumulationEnvelopeV2 {
                    work,
                    transition: collision,
                    provided_blobs: Vec::new(),
                }),
            )
            .unwrap(),
            rejected(AccumulationRejectionV2::InvalidWorkflowTransition)
        );
    }

    #[test]
    fn nested_sender_extends_the_authenticated_root_parent_chain() {
        let mut store = MemStore::default();
        let (initial, install) = install_fixture(&mut store, ConsistencyModeV2::Local, b"before");
        let root = install.resulting_state_root.unwrap();
        let caller = ActorId([40; 32]);
        let child = ActorId([41; 32]);
        let peer = ActorId([42; 32]);
        let incoming = message(43, caller, actor(), None, Some(10));
        let root_with_inbox = {
            let mut tree = ServiceStateTreeV2::new(&mut store, root);
            tree_apply(
                &mut tree,
                &StateKeyV2::Inbox(incoming.call_id),
                Some(&incoming.encode()),
            )
            .unwrap();
            tree.root()
        };

        let mut work = linear_work(initial.clone(), root_with_inbox);
        work.invocation = InvocationId([44; 32]);
        work.origin = Origin::Actor(caller);
        work.causal_parent = Some(incoming.caller_invocation);
        work.parent_call = Some(incoming.call_id);
        work.causal_context = Some(super::super::CausalCallContextV2::from(&incoming));
        work.imported_actors.push(ImportedActorV2 {
            actor: child,
            name: "child".into(),
            parent: Some(actor()),
            deployment: work.target_deployment,
            program: program(),
            state: initial,
            causal_states: vec![],
            continuation: None,
        });
        let mut outgoing = awaited_message(&work, peer, Some(incoming.call_id), Some(9));
        outgoing.from = child;
        let mut transition = linear_transition(&work, b"after");
        transition.outbox.push(outgoing);
        let tree = ServiceStateTreeV2::new(&mut store, root_with_inbox);
        assert_eq!(
            validate_durable_messages(&tree, &work, &transition).unwrap(),
            None,
            "the first durable edge may cross from the root's inbound call to its exact nested sender"
        );
    }

    fn crdt_work(initial: BlobRefV2, invocation: u8, heads: Vec<Hash>) -> WorkEnvelopeV2 {
        let base_causal_height = Some(u64::from(!heads.is_empty()));
        WorkEnvelopeV2 {
            external_actors: external_bindings(),
            service: identity(),
            invocation: InvocationId([invocation; 32]),
            workflow_step: 0,
            logical_timeslot: 1,
            target: actor(),
            target_deployment: identity().deployment,
            target_program: program(),
            method: "set".into(),
            arguments: vec![2],
            origin: Origin::Anonymous,
            authorization: AuthorizationEvidenceV2::Public,
            causal_parent: None,
            parent_call: None,
            causal_context: None,
            awaited_reply: None,
            awaited_timeout: None,
            consistency: ConsistencyModeV2::Crdt,
            base: ConsistencyBaseV2::Crdt { heads },
            base_causal_height,
            imported_actors: vec![ImportedActorV2 {
                actor: actor(),
                name: "root".into(),
                parent: None,
                deployment: identity().deployment,
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
        let operation_scope = CrdtChangeV2::derive_operation_scope(work).unwrap();
        let field = Hash([14; 32]);
        let mut transition = TransitionV2 {
            service: work.service.clone(),
            consumed_input: work.input_id(),
            target_deployment: work.target_deployment,
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
                    id: OperationId(operation_scope.operation(actor(), 0, field, 0).0),
                    payload: vec![1],
                }],
                workflow: Vec::new(),
                materializations: vec![CrdtMaterializationV2 {
                    actor: actor(),
                    state: materialization,
                }],
                awaited_reply: work.awaited_reply.clone(),
                exported_blobs: Vec::new(),
            }),
            spawns: Vec::new(),
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
    fn crdt_retry_equivalence_ignores_branch_local_state_and_checkpoint_bytes() {
        let left_work = crdt_work(BlobRefV2::of_bytes(b"left base"), 18, vec![]);
        let mut right_work = left_work.clone();
        right_work.logical_timeslot = 2;
        right_work.base = ConsistencyBaseV2::Crdt {
            heads: vec![Hash([19; 32])],
        };
        right_work.base_causal_height = Some(1);
        right_work.imported_actors[0].state = BlobRefV2::of_bytes(b"right base");
        right_work.imported_actors[0].causal_states = vec![BlobRefV2::of_bytes(b"concurrent")];

        let left_snapshot = BlobRefV2::of_bytes(b"left physical work frame");
        let right_snapshot = BlobRefV2::of_bytes(b"right physical work frame");
        let mut left = crdt_transition(&left_work, BlobRefV2::of_bytes(b"left result"), 1);
        let mut right = crdt_transition(&right_work, BlobRefV2::of_bytes(b"right result"), 2);
        for (transition, snapshot) in [
            (&mut left, left_snapshot.clone()),
            (&mut right, right_snapshot.clone()),
        ] {
            transition.continuations.push(ContinuationChangeV2 {
                actor: actor(),
                expected: None,
                replacement: Some(snapshot.clone()),
            });
            transition.exported_blobs.push(snapshot);
        }
        left.crdt_change.as_mut().unwrap().workflow = left.workflow_operations(&left_work);
        left.crdt_change.as_mut().unwrap().exported_blobs = left.exported_blobs.clone();
        right.crdt_change.as_mut().unwrap().workflow = right.workflow_operations(&right_work);
        right.crdt_change.as_mut().unwrap().exported_blobs = right.exported_blobs.clone();

        let left_change = left.crdt_change.as_ref().unwrap();
        let right_change = right.crdt_change.as_ref().unwrap();
        assert_ne!(left_change.materializations, right_change.materializations);
        assert_ne!(left_change.exported_blobs, right_change.exported_blobs);
        assert!(crdt_retry_execution_matches(left_change, right_change));

        let mut divergent = right_change.clone();
        divergent.operations[0].payload.push(99);
        assert!(!crdt_retry_execution_matches(left_change, &divergent));
    }

    #[test]
    fn descendant_of_a_discarded_retry_observes_the_canonical_checkpoint() {
        let initial = BlobRefV2::of_bytes(b"initial");
        let mut loser_work = crdt_work(initial.clone(), 18, vec![]);
        loser_work.logical_timeslot = 1;
        let loser_state = BlobRefV2::of_bytes(b"losing result");
        let loser_continuation = BlobRefV2::of_bytes(b"losing physical checkpoint");
        let mut loser = crdt_transition(&loser_work, loser_state.clone(), 1);
        loser.continuations.push(ContinuationChangeV2 {
            actor: actor(),
            expected: None,
            replacement: Some(loser_continuation.clone()),
        });
        loser.exported_blobs.push(loser_continuation.clone());
        loser.crdt_change.as_mut().unwrap().workflow = loser.workflow_operations(&loser_work);
        loser.crdt_change.as_mut().unwrap().exported_blobs = loser.exported_blobs.clone();
        let loser = loser.crdt_change.unwrap();
        let loser_cid = loser.cid();

        // Build an unrelated two-node causal base. The equivalent retry below
        // is therefore physically height 3, while the loser's already-refined
        // descendant is height 2.
        let unrelated_one_state = BlobRefV2::of_bytes(b"unrelated one");
        let unrelated_one_work = crdt_work(initial, 70, vec![]);
        let unrelated_one = crdt_transition(&unrelated_one_work, unrelated_one_state.clone(), 1)
            .crdt_change
            .unwrap();
        let unrelated_one_cid = unrelated_one.cid();
        let mut unrelated_two_work = crdt_work(unrelated_one_state, 71, vec![unrelated_one_cid]);
        unrelated_two_work.base_causal_height = Some(1);
        let unrelated_two_state = BlobRefV2::of_bytes(b"unrelated two");
        let unrelated_two = crdt_transition(&unrelated_two_work, unrelated_two_state.clone(), 2)
            .crdt_change
            .unwrap();
        let unrelated_two_cid = unrelated_two.cid();

        // CID order, not causal height, selects the canonical retry. Find a
        // trusted scheduling slot whose height-3 physical retry wins over the
        // height-1 branch above.
        let winner_continuation = BlobRefV2::of_bytes(b"winning physical checkpoint");
        let (winner_work, winner) = (2..=10_000)
            .find_map(|logical_timeslot| {
                let mut work = loser_work.clone();
                work.logical_timeslot = logical_timeslot;
                work.base = ConsistencyBaseV2::Crdt {
                    heads: vec![unrelated_two_cid],
                };
                work.base_causal_height = Some(2);
                work.imported_actors[0].state = unrelated_two_state.clone();
                let mut transition =
                    crdt_transition(&work, BlobRefV2::of_bytes(b"winning result"), 3);
                transition.continuations.push(ContinuationChangeV2 {
                    actor: actor(),
                    expected: None,
                    replacement: Some(winner_continuation.clone()),
                });
                transition.exported_blobs.push(winner_continuation.clone());
                transition.crdt_change.as_mut().unwrap().workflow =
                    transition.workflow_operations(&work);
                transition.crdt_change.as_mut().unwrap().exported_blobs =
                    transition.exported_blobs.clone();
                let change = transition.crdt_change.unwrap();
                (change.cid() < loser_cid).then_some((work, change))
            })
            .expect("a taller retry should eventually win the CID tie-break");
        let winner_cid = winner.cid();
        assert_eq!(winner.causal_height, 3);
        assert!(winner_cid < loser_cid);
        assert!(winner_work.matches_crdt_retry(&loser_work));

        // Resume before learning that this physical step-0 branch loses the
        // deterministic tie-break. Its step-1 node therefore descends the
        // loser CID and names the loser's content-addressed checkpoint.
        let mut resumed_work = loser_work;
        resumed_work.workflow_step = 1;
        resumed_work.logical_timeslot = 3;
        resumed_work.arguments.clear();
        resumed_work.base = ConsistencyBaseV2::Crdt {
            heads: vec![loser_cid],
        };
        resumed_work.base_causal_height = Some(1);
        resumed_work.imported_actors[0].state = loser_state;
        resumed_work.imported_actors[0].continuation = Some(loser_continuation.clone());
        let final_state = BlobRefV2::of_bytes(b"descendant result");
        let mut resumed = crdt_transition(&resumed_work, final_state.clone(), 2);
        resumed.continuations.push(ContinuationChangeV2 {
            actor: actor(),
            expected: Some(loser_continuation.hash),
            replacement: None,
        });
        resumed.crdt_change.as_mut().unwrap().workflow = resumed.workflow_operations(&resumed_work);
        let resumed_change = resumed.crdt_change.unwrap();
        let resumed_cid = resumed_change.cid();

        let nodes = BTreeMap::from([
            (unrelated_one_cid, unrelated_one.encode()),
            (unrelated_two_cid, unrelated_two.encode()),
            (winner_cid, winner.encode()),
            (loser_cid, loser.encode()),
            (resumed_cid, resumed_change.encode()),
        ]);
        let mut heads = vec![winner_cid, resumed_cid];
        heads.sort();
        let frontier =
            load_causal_frontier(&heads, |cid| Ok::<_, Infallible>(nodes.get(&cid).cloned()))
                .unwrap();
        let materialized = materialize_workflow_crdt(&frontier, &identity()).unwrap();
        assert_eq!(
            materialized.workflows[&resumed_work.invocation][0]
                .value
                .input
                .workflow_step,
            1
        );
        assert_eq!(materialized.actor_states[&actor()][0].value, final_state);
        assert_eq!(materialized.continuations[&actor()][0].value, None);
    }

    #[test]
    fn discarded_retry_contraction_preserves_unique_physical_ancestors() {
        let initial = BlobRefV2::of_bytes(b"initial");
        let mut root_loser_work = crdt_work(initial.clone(), 80, vec![]);
        root_loser_work.logical_timeslot = 1;
        let root_call = root_loser_work.invocation.call_id(0);
        let root_message = awaited_message(&root_loser_work, ActorId([81; 32]), None, Some(50));
        let root_loser_state = BlobRefV2::of_bytes(b"root loser state");
        let root_loser_continuation = BlobRefV2::of_bytes(b"root loser continuation");
        let await_change = |work: &WorkEnvelopeV2,
                            state: BlobRefV2,
                            height: u64,
                            continuation: BlobRefV2|
         -> CrdtChangeV2 {
            let mut transition = crdt_transition(work, state, height);
            transition.continuations.push(ContinuationChangeV2 {
                actor: actor(),
                expected: None,
                replacement: Some(continuation.clone()),
            });
            transition.outbox.push(root_message.clone());
            transition.exported_blobs.push(continuation);
            transition.crdt_change.as_mut().unwrap().workflow =
                transition.workflow_operations(work);
            transition.crdt_change.as_mut().unwrap().exported_blobs =
                transition.exported_blobs.clone();
            transition.crdt_change.unwrap()
        };
        let root_loser = await_change(
            &root_loser_work,
            root_loser_state.clone(),
            1,
            root_loser_continuation,
        );
        let root_loser_cid = root_loser.cid();

        // Put the canonical retry on a taller, unrelated base so physical
        // height would otherwise place the expiration before the checkpoint
        // that owns its outbox.
        let unrelated_one_state = BlobRefV2::of_bytes(b"unrelated one");
        let unrelated_one_work = crdt_work(initial.clone(), 82, vec![]);
        let unrelated_one = crdt_transition(&unrelated_one_work, unrelated_one_state.clone(), 1)
            .crdt_change
            .unwrap();
        let unrelated_one_cid = unrelated_one.cid();
        let mut unrelated_two_work = crdt_work(unrelated_one_state, 83, vec![unrelated_one_cid]);
        unrelated_two_work.base_causal_height = Some(1);
        let unrelated_two_state = BlobRefV2::of_bytes(b"unrelated two");
        let unrelated_two = crdt_transition(&unrelated_two_work, unrelated_two_state.clone(), 2)
            .crdt_change
            .unwrap();
        let unrelated_two_cid = unrelated_two.cid();
        let mut unrelated_three_work = crdt_work(unrelated_two_state, 84, vec![unrelated_two_cid]);
        unrelated_three_work.base_causal_height = Some(2);
        let unrelated_three_state = BlobRefV2::of_bytes(b"unrelated three");
        let unrelated_three =
            crdt_transition(&unrelated_three_work, unrelated_three_state.clone(), 3)
                .crdt_change
                .unwrap();
        let unrelated_three_cid = unrelated_three.cid();
        let root_winner_continuation = BlobRefV2::of_bytes(b"root winner continuation");
        let (root_winner_work, root_winner) = (2..=10_000)
            .find_map(|logical_timeslot| {
                let mut work = root_loser_work.clone();
                work.logical_timeslot = logical_timeslot;
                work.base = ConsistencyBaseV2::Crdt {
                    heads: vec![unrelated_three_cid],
                };
                work.base_causal_height = Some(3);
                work.imported_actors[0].state = unrelated_three_state.clone();
                let change = await_change(
                    &work,
                    BlobRefV2::of_bytes(b"root winner state"),
                    4,
                    root_winner_continuation.clone(),
                );
                (change.cid() < root_loser_cid).then_some((work, change))
            })
            .expect("the height-4 root retry should eventually win by CID");
        let root_winner_cid = root_winner.cid();
        assert!(root_winner_work.matches_crdt_retry(&root_loser_work));

        // A second logical execution is first refined on top of the losing
        // root branch. Its independent retry wins on an empty base.
        let mut child_loser_work = crdt_work(root_loser_state, 85, vec![root_loser_cid]);
        child_loser_work.base_causal_height = Some(1);
        let child_loser = crdt_transition(
            &child_loser_work,
            BlobRefV2::of_bytes(b"child loser state"),
            2,
        )
        .crdt_change
        .unwrap();
        let child_loser_cid = child_loser.cid();
        let (child_winner_work, child_winner) = (2..=10_000)
            .find_map(|logical_timeslot| {
                let mut work = child_loser_work.clone();
                work.logical_timeslot = logical_timeslot;
                work.base = ConsistencyBaseV2::Crdt { heads: vec![] };
                work.base_causal_height = Some(0);
                work.imported_actors[0].state = initial.clone();
                let change = crdt_transition(&work, BlobRefV2::of_bytes(b"child winner state"), 1)
                    .crdt_change
                    .unwrap();
                (change.cid() < child_loser_cid).then_some((work, change))
            })
            .expect("the independent child retry should eventually win by CID");
        let child_winner_cid = child_winner.cid();
        assert!(child_winner_work.matches_crdt_retry(&child_loser_work));

        // This valid expiration physically descends root-loser through
        // child-loser. Contracting only its direct child-loser edge would
        // omit root-winner and schedule the expiration before its outbox.
        let timeout = CallTimeoutV2 {
            call_id: root_call,
            caller_invocation: root_loser_work.invocation,
            caller_actor: root_loser_work.target,
            checkpoint_step: 0,
            await_ordinal: 0,
            deadline_timeslot: 50,
            expired_at: 50,
        };
        let expiration = CrdtChangeV2 {
            id: CrdtChangeV2::derive_expiration_id(
                &root_loser_work.service,
                &timeout,
                &[child_loser_cid],
            ),
            work_hash: timeout.commitment(),
            causal_dependencies: vec![child_loser_cid],
            causal_height: 3,
            operations: vec![],
            workflow: vec![WorkflowOperationV2::ExpireCall(timeout.clone())],
            materializations: vec![],
            awaited_reply: None,
            exported_blobs: vec![],
        };
        let expiration_cid = expiration.cid();
        let nodes = BTreeMap::from([
            (root_loser_cid, root_loser.encode()),
            (root_winner_cid, root_winner.encode()),
            (child_loser_cid, child_loser.encode()),
            (child_winner_cid, child_winner.encode()),
            (expiration_cid, expiration.encode()),
            (unrelated_one_cid, unrelated_one.encode()),
            (unrelated_two_cid, unrelated_two.encode()),
            (unrelated_three_cid, unrelated_three.encode()),
        ]);

        // Each physical branch is valid by itself.
        for heads in [
            vec![expiration_cid],
            vec![root_winner_cid, child_winner_cid],
        ] {
            let frontier =
                load_causal_frontier(&heads, |cid| Ok::<_, Infallible>(nodes.get(&cid).cloned()))
                    .unwrap();
            materialize_workflow_crdt(&frontier, &identity()).unwrap();
        }

        let mut heads = vec![expiration_cid, root_winner_cid, child_winner_cid];
        heads.sort();
        let frontier =
            load_causal_frontier(&heads, |cid| Ok::<_, Infallible>(nodes.get(&cid).cloned()))
                .unwrap();
        let materialized = materialize_workflow_crdt(&frontier, &identity()).unwrap();
        assert_eq!(materialized.expirations[&root_call][0].value, timeout);
        assert_eq!(materialized.outbox[&root_call][0].value, None);
    }

    #[test]
    fn causal_reply_input_rebuilds_the_permanent_admission() {
        let mut store = MemStore::default();
        let (initial, _) = install_fixture(&mut store, ConsistencyModeV2::Crdt, b"initial");
        let first_state = BlobRefV2::of_bytes(b"waiting");
        let continuation = BlobRefV2::of_bytes(b"continuation");
        let first_work = crdt_work(initial, 29, vec![]);
        let call = first_work.invocation.call_id(0);
        let mut first = crdt_transition(&first_work, first_state.clone(), 1);
        first.continuations.push(ContinuationChangeV2 {
            actor: actor(),
            expected: None,
            replacement: Some(continuation.clone()),
        });
        first
            .outbox
            .push(message(31, actor(), ActorId([44; 32]), None, None));
        first.outbox[0].call_id = call;
        first.outbox[0].caller_invocation = first_work.invocation;
        first.outbox[0].await_ordinal = 0;
        first.exported_blobs.push(continuation.clone());
        first.crdt_change.as_mut().unwrap().workflow = first.workflow_operations(&first_work);
        first.crdt_change.as_mut().unwrap().exported_blobs = first.exported_blobs.clone();
        let first_change = first.crdt_change.unwrap();
        let first_cid = first_change.cid();

        let reply = super::super::ReplyRecordV2 {
            call_id: call,
            producer: ActorId([44; 32]),
            result: vec![7],
        };
        let awaited_reply = super::super::AccumulatedReplyV2 {
            receipt: AccumulationReceiptV2 {
                service: super::super::ServiceIdentityV2 {
                    root_service: super::super::RootServiceId([45; 32]),
                    ..identity()
                },
                accepted_transition: Hash([46; 32]),
                reply_commitment: Some(reply.commitment()),
                outbox_commitment: None,
                resulting_state_root: Some(Hash([47; 32])),
                resulting_crdt_heads: vec![],
                sequence: 1,
                checkpoint: 0,
                consistency: ConsistencyModeV2::Local,
            },
            reply,
            attestation: None,
        };
        let mut resumed_work = first_work;
        resumed_work.workflow_step = 1;
        resumed_work.logical_timeslot = 2;
        resumed_work.arguments.clear();
        resumed_work.awaited_reply = Some(awaited_reply.clone());
        resumed_work.base = ConsistencyBaseV2::Crdt {
            heads: vec![first_cid],
        };
        resumed_work.base_causal_height = Some(1);
        resumed_work.imported_actors[0].state = first_state;
        resumed_work.imported_actors[0].continuation = Some(continuation.clone());
        let mut resumed = crdt_transition(
            &resumed_work,
            BlobRefV2::of_bytes(b"completed materialization"),
            2,
        );
        resumed.continuations.push(ContinuationChangeV2 {
            actor: actor(),
            expected: Some(continuation.hash),
            replacement: None,
        });
        resumed.crdt_change.as_mut().unwrap().workflow = resumed.workflow_operations(&resumed_work);
        let resumed_transition = resumed.clone();
        let resumed_change = resumed.crdt_change.unwrap();

        let mut retry_work = resumed_work.clone();
        retry_work.logical_timeslot = 3;
        retry_work.imported_actors[0].state = BlobRefV2::of_bytes(b"other causal state");
        let mut retry = crdt_transition(
            &retry_work,
            BlobRefV2::of_bytes(b"other completed materialization"),
            2,
        );
        retry.continuations.push(ContinuationChangeV2 {
            actor: actor(),
            expected: Some(continuation.hash),
            replacement: None,
        });
        retry.crdt_change.as_mut().unwrap().workflow = retry.workflow_operations(&retry_work);
        let retry_transition = retry.clone();
        let retry_change = retry.crdt_change.unwrap();

        let receipt_for = |change: &CrdtChangeV2, checkpoint| AccumulationReceiptV2 {
            service: identity(),
            accepted_transition: change.receipt_commitment(),
            reply_commitment: None,
            outbox_commitment: MessageRecordV2::outbox_commitment(
                &change
                    .workflow
                    .iter()
                    .filter_map(|operation| match operation {
                        WorkflowOperationV2::Outbox(message) => Some(message.clone()),
                        _ => None,
                    })
                    .collect::<Vec<_>>(),
            ),
            resulting_state_root: None,
            resulting_crdt_heads: vec![change.cid()],
            sequence: change.causal_height,
            checkpoint,
            consistency: ConsistencyModeV2::Crdt,
        };
        let first_receipt = receipt_for(&first_change, 0);
        let (canonical_work, canonical_transition, canonical_change, loser_work, loser_change) =
            if resumed_change.cid() < retry_change.cid() {
                (
                    resumed_work,
                    resumed_transition,
                    resumed_change,
                    retry_work,
                    retry_change,
                )
            } else {
                (
                    retry_work,
                    retry_transition,
                    retry_change,
                    resumed_work,
                    resumed_change,
                )
            };
        let canonical_cid = canonical_change.cid();
        let loser_cid = loser_change.cid();
        let canonical_receipt = receipt_for(&canonical_change, 1);
        let loser_receipt = receipt_for(&loser_change, 1);
        for (cid, change, receipt) in [
            (first_cid, first_change, first_receipt),
            (canonical_cid, canonical_change, canonical_receipt.clone()),
            (loser_cid, loser_change, loser_receipt.clone()),
        ] {
            store
                .rows
                .insert(crdt_node_storage_key(cid), change.encode());
            store
                .rows
                .insert(crdt_node_receipt_storage_key(cid), receipt.encode());
        }
        let input = canonical_work.input_id();
        store.rows.insert(
            dedup_storage_key(input),
            DedupRecordV2 {
                input,
                work_hash: loser_work.hash(),
                transition_commitment: loser_receipt.accepted_transition,
                receipt: loser_receipt.clone(),
            }
            .encode(),
        );
        store
            .rows
            .insert(receipt_storage_key(input), loser_receipt.encode());
        store.rows.insert(
            reply_admission_storage_key(call),
            ReplyAdmissionRecordV2 {
                call_id: call,
                input,
                awaited_reply: awaited_reply.clone(),
                work_hash: loser_work.hash(),
            }
            .encode(),
        );
        let nodes = store.rows.clone();
        let mut heads = vec![canonical_cid, loser_cid];
        heads.sort();
        let frontier = load_causal_frontier(&heads, |cid| {
            Ok::<_, Infallible>(nodes.get(&crdt_node_storage_key(cid)).cloned())
        })
        .unwrap();
        let materialized = materialize_workflow_crdt(&frontier, &identity()).unwrap();
        assert!(
            materialized.workflows[&canonical_work.invocation][0]
                .value
                .resume_work
                .awaited_reply
                .is_none(),
            "the checkpoint remains normalized"
        );
        apply_dedup_materialization(&mut store, &identity(), &materialized).unwrap();
        let admission = ReplyAdmissionRecordV2::decode(
            store.rows[&reply_admission_storage_key(call)].as_slice(),
        )
        .unwrap();
        assert_eq!(admission.awaited_reply, awaited_reply);
        assert_eq!(admission.input, canonical_work.input_id());
        assert_eq!(admission.work_hash, canonical_work.hash());

        assert!(matches!(
            execute_guest_accumulate(
                &mut store,
                &AccumulateRequestV2::Apply(AccumulationEnvelopeV2 {
                    work: canonical_work,
                    transition: canonical_transition,
                    provided_blobs: vec![],
                }),
            )
            .unwrap(),
            AccumulationResultV2::Accepted {
                receipt,
                duplicate: true,
                ..
            } if receipt == canonical_receipt
        ));
    }

    #[test]
    fn crdt_apply_rejects_an_export_not_committed_by_the_causal_node() {
        let mut store = MemStore::default();
        let (initial, _) = install_fixture(&mut store, ConsistencyModeV2::Crdt, b"before");
        let work = crdt_work(initial, 20, vec![]);
        seed_direct_ingress(&mut store, &work);
        let state_bytes = b"after".to_vec();
        let state = BlobRefV2::of_bytes(&state_bytes);
        let mut transition = crdt_transition(&work, state.clone(), 1);
        let extra_bytes = b"host supplied extra export".to_vec();
        let extra = BlobRefV2::of_bytes(&extra_bytes);
        transition.exported_blobs.push(extra.clone());
        let before = store.clone();

        assert_eq!(
            execute_guest_accumulate(
                &mut store,
                &AccumulateRequestV2::Apply(AccumulationEnvelopeV2 {
                    work,
                    transition,
                    provided_blobs: vec![
                        ImportedBlobV2 {
                            reference: extra,
                            bytes: extra_bytes,
                        },
                        ImportedBlobV2 {
                            reference: state,
                            bytes: state_bytes,
                        },
                    ],
                }),
            )
            .unwrap(),
            rejected(AccumulationRejectionV2::NonCanonical)
        );
        assert_eq!(store, before);
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
            from_service: first_work.service.clone(),
            from: actor(),
            to_service: external_bindings()
                .into_iter()
                .find(|binding| binding.actor == ActorId([44; 32]))
                .unwrap()
                .service,
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
    fn causal_continuation_materialization_tracks_the_selected_frontier() {
        let initial = BlobRefV2::of_bytes(b"initial");
        let first_state = BlobRefV2::of_bytes(b"first state");
        let first_continuation = BlobRefV2::of_bytes(b"first continuation");
        let replacement = BlobRefV2::of_bytes(b"replacement continuation");
        let first_work = crdt_work(initial, 27, vec![]);
        let mut first = crdt_transition(&first_work, first_state.clone(), 1);
        first.continuations.push(ContinuationChangeV2 {
            actor: actor(),
            expected: None,
            replacement: Some(first_continuation.clone()),
        });
        first.exported_blobs.push(first_continuation.clone());
        let first_workflow = first.workflow_operations(&first_work);
        first.crdt_change.as_mut().unwrap().workflow = first_workflow;
        first.crdt_change.as_mut().unwrap().exported_blobs = first.exported_blobs.clone();
        let first_change = first.crdt_change.unwrap();
        let first_cid = first_change.cid();

        let mut resumed_work = first_work;
        resumed_work.workflow_step = 1;
        resumed_work.base = ConsistencyBaseV2::Crdt {
            heads: vec![first_cid],
        };
        resumed_work.base_causal_height = Some(1);
        resumed_work.imported_actors[0].state = first_state;
        resumed_work.imported_actors[0].continuation = Some(first_continuation.clone());
        let mut resumed = crdt_transition(&resumed_work, BlobRefV2::of_bytes(b"second state"), 2);
        resumed.continuations.push(ContinuationChangeV2 {
            actor: actor(),
            expected: Some(first_continuation.hash),
            replacement: Some(replacement.clone()),
        });
        resumed.exported_blobs.push(replacement.clone());
        let resumed_workflow = resumed.workflow_operations(&resumed_work);
        resumed.crdt_change.as_mut().unwrap().workflow = resumed_workflow;
        resumed.crdt_change.as_mut().unwrap().exported_blobs = resumed.exported_blobs.clone();
        let resumed_change = resumed.crdt_change.unwrap();
        let resumed_cid = resumed_change.cid();
        let nodes = BTreeMap::from([
            (first_cid, first_change.encode()),
            (resumed_cid, resumed_change.encode()),
        ]);

        let selected = load_causal_frontier(&[first_cid], |cid| {
            Ok::<_, Infallible>(nodes.get(&cid).cloned())
        })
        .unwrap();
        let current = load_causal_frontier(&[resumed_cid], |cid| {
            Ok::<_, Infallible>(nodes.get(&cid).cloned())
        })
        .unwrap();
        assert_eq!(
            materialized_continuations(&selected, &identity()).unwrap()[&actor()],
            Some(first_continuation)
        );
        assert_eq!(
            materialized_continuations(&current, &identity()).unwrap()[&actor()],
            Some(replacement)
        );
    }

    #[test]
    fn crdt_nodes_heads_and_materializations_are_committed_by_the_guest() {
        let mut store = MemStore::default();
        let (initial, _) = install_fixture(&mut store, ConsistencyModeV2::Crdt, b"initial");
        let materialized = BlobRefV2::of_bytes(b"one");
        let work = crdt_work(initial, 20, Vec::new());
        seed_direct_ingress(&mut store, &work);
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
        seed_direct_ingress(&mut store, &next_work);
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
            seed_direct_ingress(&mut store, &work);
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
        seed_direct_ingress(&mut store, &work);
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
        seed_direct_ingress(&mut incomplete, &work);
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
        seed_direct_ingress(&mut left_first, &left_work);
        seed_direct_ingress(&mut left_first, &right_work);
        seed_direct_ingress(&mut right_first, &left_work);
        seed_direct_ingress(&mut right_first, &right_work);
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
            seed_direct_ingress(&mut source, &work);
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
                        expected_producer: actor(),
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
                let mut change = crdt_transition(&work, state.clone(), 1)
                    .crdt_change
                    .unwrap();
                if index == 1 {
                    change.operations[0].payload.push(2);
                }
                let cid = change.cid();
                let receipt = AccumulationReceiptV2 {
                    service: identity(),
                    accepted_transition: change.receipt_commitment(),
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
                    expected_producer: actor(),
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
            rejected(AccumulationRejectionV2::InvalidWorkflowTransition)
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
        seed_direct_ingress(&mut source, &work);
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
                expected_producer: actor(),
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
        assert_eq!(checkpoint.transition_hash, cid);
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

        assert_eq!(
            destination.rows.get(&dedup_storage_key(work.input_id())),
            source.rows.get(&dedup_storage_key(work.input_id())),
            "sync must reconstruct the authenticated retry bridge"
        );
        assert_eq!(
            destination.rows.get(&receipt_storage_key(work.input_id())),
            source.rows.get(&receipt_storage_key(work.input_id())),
            "the reconstructed dedup row must retain its exact receipt"
        );

        let stored_receipt = destination
            .rows
            .get(&crdt_node_receipt_storage_key(cid))
            .unwrap()
            .clone();
        let mut alternate_receipt = sync.clone();
        alternate_receipt.nodes[0].receipt.accepted_transition = Hash([97; 32]);
        alternate_receipt.nodes[0]
            .receipt
            .resulting_crdt_heads
            .push(Hash([98; 32]));
        alternate_receipt.nodes[0]
            .receipt
            .resulting_crdt_heads
            .sort();
        destination.receipt_allowlist.insert(
            ReceiptVerificationRequestV2 {
                expected_producer: actor(),
                receipt: alternate_receipt.nodes[0].receipt.clone(),
            }
            .hash(),
        );
        let before_alternate = destination.clone();
        assert_eq!(
            execute_guest_accumulate(
                &mut destination,
                &AccumulateRequestV2::SyncCrdt(alternate_receipt),
            )
            .unwrap(),
            rejected(AccumulationRejectionV2::InvalidReceipt)
        );
        assert_eq!(destination, before_alternate);
        assert_eq!(
            destination.rows.get(&crdt_node_receipt_storage_key(cid)),
            Some(&stored_receipt)
        );

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
            accepted_transition: child.receipt_commitment(),
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
                expected_producer: actor(),
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
        seed_direct_ingress(&mut committed, &work);
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
