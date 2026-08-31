//! Journal-backed process-local Agent execution.
//!
//! This module is the clean-generation replacement for the whole-image local
//! driver.  Its only mutable truth is an [`AgentJournalStore`]; the cached
//! [`ReplayMaterialization`] is replaced only after a consuming replay
//! publication wins the durable heads CAS.

use std::collections::BTreeMap;
use std::sync::Arc;

use vos_pvm::refine_host::RefineContext;
use vos_pvm::{ExitReason, Gas};

use super::authority::{ActorInvocationReceipt, AgentAuthorityReceipt};
use super::driver::{AgentTrustProvider, DEFAULT_MANAGEMENT_GAS};
use super::execution::{
    ActorExecutionError, ActorExecutionReply, ActorExecutionStatus, ActorInvocation, RuntimeBlob,
    RuntimeExecutionCall, RuntimeExecutionReturn,
};
use super::invocation_index::InvocationIndexes;
use super::journal::{
    CanonicalJournalRecord, InvocationOutcomeAnchor, InvocationOwnershipKey,
    InvocationOwnershipScope, InvocationResultState, LaneCursor, LocalEntry, MergeEvent,
    MergeEventId, MergeFrontier, MergeFrontierId, MergeSeal, OrderedEntry, PersistedLane,
    ReplayInput, ReplayInputId, ReplayOperation, RuntimeBinding,
};
use super::journal_store::{
    AgentJournalStore, CatalogBlobResolver, CatalogBlobResolverFactory, JournalBlobClass,
    JournalStoreError,
};
use super::package::{Package, PackageError};
use super::replay::{
    MaterializeError, NoPrunedOrderedBases, ReplayCommittedRecovery, ReplayDisposition,
    ReplayError, ReplayExecutionResult, ReplayExecutor, ReplayInvocationRecovery,
    ReplayMaterialization, ReplayMaterializationSourceError, ReplayPosition, ReplayPreparation,
    ReplayProducts, ReplaySealedGenesis, ReplayStepOutcome, ReplayTransition, derive_lane_state,
    materialize_current, prepare_checkpoint, prepare_local, prepare_merge, prepare_ordered,
    recover_invocation,
};
use super::standard::{StandardAgentRuntime, StandardRuntimeState};
use super::wire::{RuntimeCall, RuntimeReturn, RuntimeState, decode_standard_runtime_state};
use super::{
    ActorDirectoryPage, AgentConfig, AgentProfile, AgentReplica, AgentRuntime, InvocationScope,
    LifecycleAuthorityAdmission, LifecycleError, LifecycleReply, LifecycleRequest, PackageKind,
};
use crate::service::wire::ServiceWire;
use crate::service::{BlobRef, CapabilityId, Hash, NodeId};

type LocalReplayError = MaterializeError<core::convert::Infallible, LocalReplayExecutorError>;

/// Immutable view of the exact catalog supplied alongside one sealed
/// genesis. Create-time validation must not consult the destination store:
/// doing so would either accept stale bytes or require staging untrusted
/// content before the root admission has been fully checked.
#[derive(Clone, Debug)]
struct SuppliedCatalogBlobResolver {
    blobs: Arc<BTreeMap<(Hash, u64), Vec<u8>>>,
}

impl SuppliedCatalogBlobResolver {
    fn from_catalog(catalog: &[RuntimeBlob]) -> Result<Self, LocalReplayExecutorError> {
        let mut blobs = BTreeMap::new();
        let mut aggregate = 0u64;
        for blob in catalog {
            if blob.bytes.len() > super::journal::MAX_ARTIFACT_CLOSURE_BYTES
                || !blob.reference.matches(&blob.bytes)
                || blobs
                    .insert(
                        (blob.reference.hash, blob.reference.len),
                        blob.bytes.clone(),
                    )
                    .is_some()
            {
                return Err(LocalReplayExecutorError::InvalidArtifact(
                    blob.reference.clone(),
                ));
            }
            aggregate = aggregate
                .checked_add(blob.reference.len)
                .ok_or(LocalReplayExecutorError::InvalidRequest)?;
        }
        if aggregate > super::journal::MAX_ARTIFACT_CLOSURE_REFERENCED_BYTES {
            return Err(LocalReplayExecutorError::InvalidRequest);
        }
        Ok(Self {
            blobs: Arc::new(blobs),
        })
    }
}

impl CatalogBlobResolver for SuppliedCatalogBlobResolver {
    fn load_catalog(&self, reference: &BlobRef) -> Result<Option<Vec<u8>>, JournalStoreError> {
        let Some(bytes) = self.blobs.get(&(reference.hash, reference.len)) else {
            return Ok(None);
        };
        if !reference.matches(bytes) {
            return Err(JournalStoreError::Corrupt);
        }
        Ok(Some(bytes.clone()))
    }
}

fn lift_checkpoint_error(
    error: MaterializeError<core::convert::Infallible, core::convert::Infallible>,
) -> LocalReplayError {
    match error {
        ReplayError::Source(error) => ReplayError::Source(error),
        ReplayError::Executor(never) => match never {},
        ReplayError::MissingOrdered(id) => ReplayError::MissingOrdered(id),
        ReplayError::MissingLocal(id) => ReplayError::MissingLocal(id),
        ReplayError::MissingMergeEvent(id) => ReplayError::MissingMergeEvent(id),
        ReplayError::MissingMergeFrontier(id) => ReplayError::MissingMergeFrontier(id),
        ReplayError::MissingMergeSeal(id) => ReplayError::MissingMergeSeal(id),
        ReplayError::MissingLaneState(id) => ReplayError::MissingLaneState(id),
        ReplayError::MissingArtifactClosure(id) => ReplayError::MissingArtifactClosure(id),
        ReplayError::MissingInvocationIndex(id) => ReplayError::MissingInvocationIndex(id),
        ReplayError::MissingCheckpoint(id) => ReplayError::MissingCheckpoint(id),
        ReplayError::InvalidRecord => ReplayError::InvalidRecord,
        ReplayError::ScopeMismatch => ReplayError::ScopeMismatch,
        ReplayError::ChainMismatch => ReplayError::ChainMismatch,
        ReplayError::ReplayLimit => ReplayError::ReplayLimit,
        ReplayError::InvalidCausalHeight => ReplayError::InvalidCausalHeight,
        ReplayError::NonMinimalFrontier => ReplayError::NonMinimalFrontier,
        ReplayError::StaleMergeBranch(id) => ReplayError::StaleMergeBranch(id),
        ReplayError::UnauthenticatedMergeEvent(id) => ReplayError::UnauthenticatedMergeEvent(id),
        ReplayError::InvalidOrderedBase => ReplayError::InvalidOrderedBase,
        ReplayError::UnavailableOrderedBase => ReplayError::UnavailableOrderedBase,
        ReplayError::InvalidFence => ReplayError::InvalidFence,
        ReplayError::StalePreFenceEvent(id) => ReplayError::StalePreFenceEvent(id),
        ReplayError::RuntimeMismatch => ReplayError::RuntimeMismatch,
        ReplayError::InvalidRuntimeUpgrade => ReplayError::InvalidRuntimeUpgrade,
        ReplayError::InvalidManagementTransition => ReplayError::InvalidManagementTransition,
        ReplayError::InvalidPosition => ReplayError::InvalidPosition,
        ReplayError::CrossLaneMutation => ReplayError::CrossLaneMutation,
        ReplayError::TerminalMutation => ReplayError::TerminalMutation,
        ReplayError::ForbiddenMergeProducts => ReplayError::ForbiddenMergeProducts,
        ReplayError::UncommittedInvocation(error) => ReplayError::UncommittedInvocation(error),
        ReplayError::InvocationOwnership(error) => ReplayError::InvocationOwnership(error),
    }
}

struct StandardLifecyclePreflight {
    result: Result<LifecycleReply, LifecycleError>,
    successor: StandardRuntimeState,
    unchanged: bool,
}

/// Execute the exact Standard lifecycle transition on a disposable clone.
///
/// Besides classifying byte-identical pre-disposition denials, this tells the
/// live admission boundary whether caller-supplied catalog bytes are actually
/// referenced by a successful successor. Deterministic consumed refusals are
/// journaled, but they never stage irrelevant content.
fn preflight_lifecycle_transition(
    state: &RuntimeState,
    request: &LifecycleRequest,
) -> Result<StandardLifecyclePreflight, LocalReplayExecutorError> {
    let decoded =
        decode_standard_runtime_state(state).map_err(|_| LocalReplayExecutorError::InvalidState)?;
    let mut runtime = StandardAgentRuntime::restore(decoded.clone())
        .map_err(|_| LocalReplayExecutorError::InvalidState)?;
    let result = runtime.apply(request.clone());
    let successor = runtime.snapshot();
    let unchanged =
        successor == decoded && successor.authority_dispositions == decoded.authority_dispositions;
    Ok(StandardLifecyclePreflight {
        result,
        successor,
        unchanged,
    })
}

/// Classify lifecycle calls whose exact Standard transition is byte-identical.
/// Such calls are answered locally so they cannot move heads or accidentally
/// finalize unrelated pending Merge work.
fn uncommitted_lifecycle_result(
    state: &RuntimeState,
    request: &LifecycleRequest,
) -> Result<Option<Result<LifecycleReply, LifecycleError>>, LocalReplayExecutorError> {
    let preflight = preflight_lifecycle_transition(state, request)?;
    Ok(preflight.unchanged.then_some(preflight.result))
}

fn validate_prospective_artifact_closure(
    genesis: super::journal::AgentJournalGenesisId,
    successor: &StandardRuntimeState,
) -> Result<(), LocalReplayExecutorError> {
    let config = successor
        .config
        .as_ref()
        .ok_or(LocalReplayExecutorError::InvalidState)?;
    let mut artifacts = vec![config.runtime_package.clone()];
    for actor in &successor.actors {
        artifacts.push(actor.record.package.clone());
        artifacts.push(actor.record.agent_schema.clone());
        artifacts.push(actor.record.role_policies.clone());
    }
    artifacts.sort_unstable_by_key(|artifact| (artifact.hash, artifact.len));
    artifacts.dedup_by_key(|artifact| (artifact.hash, artifact.len));
    let closure = super::journal::ArtifactClosure { genesis, artifacts };
    closure
        .validate()
        .map_err(|_| LocalReplayExecutorError::InvalidRequest)
}

/// Recover an exact retained lifecycle disposition without consulting live
/// package trust or the current catalog. Historical bytes may already have
/// been garbage-collected after an actor was removed; the signed claim and
/// bounded Standard disposition are the retry authority.
fn retained_lifecycle_disposition(
    state: &RuntimeState,
    request: &LifecycleRequest,
) -> Result<Option<Result<LifecycleReply, LifecycleError>>, LocalReplayExecutorError> {
    let LifecycleRequest::Authorized { admission, request } = request else {
        return Err(LocalReplayExecutorError::InvalidRequest);
    };
    let decoded =
        decode_standard_runtime_state(state).map_err(|_| LocalReplayExecutorError::InvalidState)?;
    let claim = &admission.receipt.claim;
    let claim_hash = claim.signing_message();
    Ok(decoded
        .authority_dispositions
        .iter()
        .find(|disposition| disposition.sequence == claim.sequence)
        .filter(|disposition| {
            disposition.credential == claim.credential
                && disposition.claim == claim_hash
                && disposition.operation == request.commitment()
        })
        .map(|disposition| disposition.result.clone()))
}

/// Bind a lifecycle receipt to the driver's trusted clock exactly once.
///
/// Callers provide only the signed receipt and its inner operation.  An
/// already-authorized request is rejected so its unsigned `observed_slot`
/// can never cross this live admission boundary. Historical replay consumes
/// the resulting sealed request without consulting the current clock.
fn seal_lifecycle_request(
    trust: &dyn AgentTrustProvider,
    receipt: AgentAuthorityReceipt,
    request: LifecycleRequest,
) -> Result<LifecycleRequest, LocalReplayExecutorError> {
    if matches!(request, LifecycleRequest::Authorized { .. }) {
        return Err(LocalReplayExecutorError::InvalidRequest);
    }
    let observed_slot = trust
        .current_logical_slot()
        .ok_or(LocalReplayExecutorError::TrustUnavailable)?;
    Ok(LifecycleRequest::Authorized {
        admission: LifecycleAuthorityAdmission {
            receipt,
            observed_slot,
        },
        request: Box::new(request),
    })
}

/// Authority-certified signing and verification for this exact Local replica.
///
/// Implementations are injected by the node identity boundary.  Possessing an
/// arbitrary signing key is not sufficient: the implementation must have
/// already certified that [`Self::node`] is the sole replica admitted by the
/// Agent's immutable Local profile.
pub(crate) trait LocalMergeAuthenticator: Send + Sync {
    fn node(&self) -> NodeId;

    fn sign(&self, message: Hash) -> Option<Vec<u8>>;

    fn verify(&self, event: &MergeEvent) -> bool;
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) enum LocalReplayExecutorError {
    InvalidState,
    InvalidProfile,
    WrongReplica,
    TrustUnavailable,
    InvalidAuthority,
    InvalidRequest,
    ArtifactUnavailable(BlobRef),
    InvalidArtifact(BlobRef),
    Package(PackageError),
    RuntimeExit { reason: ExitReason, pc: u32 },
    RuntimeOutput,
    RuntimeStateTooLarge,
    Store(JournalStoreError),
}

impl core::fmt::Display for LocalReplayExecutorError {
    fn fmt(&self, formatter: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        write!(formatter, "local replay executor: {self:?}")
    }
}

impl std::error::Error for LocalReplayExecutorError {}

impl From<JournalStoreError> for LocalReplayExecutorError {
    fn from(error: JournalStoreError) -> Self {
        Self::Store(error)
    }
}

/// Driver-level failures. Typed actor and lifecycle refusals are returned by
/// the operation APIs and therefore do not appear here.
#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) enum LocalJournalDriverError {
    Store(JournalStoreError),
    Replay(LocalReplayError),
    Executor(LocalReplayExecutorError),
    Lifecycle(LifecycleError),
    Conflict,
    InvalidResult,
}

impl core::fmt::Display for LocalJournalDriverError {
    fn fmt(&self, formatter: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        write!(formatter, "local journal agent driver: {self:?}")
    }
}

impl std::error::Error for LocalJournalDriverError {}

impl From<JournalStoreError> for LocalJournalDriverError {
    fn from(error: JournalStoreError) -> Self {
        if error == JournalStoreError::Conflict {
            Self::Conflict
        } else {
            Self::Store(error)
        }
    }
}

impl From<LocalReplayError> for LocalJournalDriverError {
    fn from(error: LocalReplayError) -> Self {
        match error {
            ReplayError::Source(ReplayMaterializationSourceError::Journal(
                JournalStoreError::Conflict,
            )) => Self::Conflict,
            error => Self::Replay(error),
        }
    }
}

impl From<LocalReplayExecutorError> for LocalJournalDriverError {
    fn from(error: LocalReplayExecutorError) -> Self {
        Self::Executor(error)
    }
}

/// Recovery capability returned while a Merge source remains pending.
///
/// It is restart-safe until finalization. After the owner becomes an
/// `Acknowledged` tombstone, checkpoint GC may prune this suffix position;
/// callers must then submit a fresh authenticated acknowledgement retry,
/// which resolves the permanent tombstone without the historical event.
#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) struct PendingMergeReceipt {
    pub event: MergeEventId,
    pub frontier: MergeFrontierId,
    pub input: ReplayInput,
    pub position: ReplayPosition,
}

/// Invocation result at the journal boundary.
#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) enum LocalInvocationResult {
    Final(Result<ActorExecutionReply, ActorExecutionError>),
    Pending(PendingMergeReceipt),
    Acknowledged,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) enum LocalAcknowledgementResult {
    Acknowledged,
    Pending(PendingMergeReceipt),
    /// This invocation ID is durably owned by a different request
    /// commitment. No information about that request or its result is
    /// disclosed.
    Divergent,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) struct FinalizedMergeInvocation {
    pub input: ReplayInputId,
    pub position: ReplayPosition,
    pub result: Result<ActorExecutionReply, ActorExecutionError>,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) struct LocalLifecycleResult {
    pub result: Result<LifecycleReply, LifecycleError>,
    pub finalized_merge_invocations: Vec<FinalizedMergeInvocation>,
}

/// Exact Standard-runtime replay executor backed by an immutable catalog
/// resolver snapshot.
struct StandardLocalReplayExecutor<R> {
    resolver: R,
    trust: Arc<dyn AgentTrustProvider>,
    merge: Arc<dyn LocalMergeAuthenticator>,
    management_gas: Gas,
    last_management_result: Option<(ReplayInputId, Result<LifecycleReply, LifecycleError>)>,
}

struct ActorCatalogAdmission<'a> {
    package: &'a BlobRef,
    schema: &'a BlobRef,
    policies: &'a BlobRef,
    deployment: crate::service::DeploymentId,
    program: crate::service::ProgramId,
    producer: crate::service::ProducerId,
    state_layout: Hash,
    contract: super::contract::ActorPackageContract,
    requirements: super::RuntimeRequirements,
}

impl<R: CatalogBlobResolver> StandardLocalReplayExecutor<R> {
    fn new(
        resolver: R,
        trust: Arc<dyn AgentTrustProvider>,
        merge: Arc<dyn LocalMergeAuthenticator>,
    ) -> Self {
        Self {
            resolver,
            trust,
            merge,
            management_gas: DEFAULT_MANAGEMENT_GAS,
            last_management_result: None,
        }
    }

    fn replace_resolver(&mut self, resolver: R) {
        self.resolver = resolver;
    }

    fn clear_management_result(&mut self) {
        self.last_management_result = None;
    }

    fn take_management_result(
        &mut self,
        input: ReplayInputId,
    ) -> Option<Result<LifecycleReply, LifecycleError>> {
        match self.last_management_result.take() {
            Some((committed, result)) if committed == input => Some(result),
            _ => None,
        }
    }

    fn config_for<'a>(
        &self,
        input: &'a ReplayInput,
        state: &'a StandardRuntimeState,
    ) -> Result<&'a AgentConfig, LocalReplayExecutorError> {
        if let Some(config) = state.config.as_ref() {
            return Ok(config);
        }
        let ReplayOperation::Management {
            request: LifecycleRequest::Authorized { request, .. },
        } = &input.operation
        else {
            return Err(LocalReplayExecutorError::InvalidState);
        };
        let LifecycleRequest::Create(config) = request.as_ref() else {
            return Err(LocalReplayExecutorError::InvalidState);
        };
        Ok(config)
    }

    fn validate_local_config(
        &self,
        config: &AgentConfig,
        binding: &RuntimeBinding,
    ) -> Result<(), LocalReplayExecutorError> {
        config
            .validate()
            .map_err(|_| LocalReplayExecutorError::InvalidState)?;
        if config.identity.profile != AgentProfile::Local || config.replicas.len() != 1 {
            return Err(LocalReplayExecutorError::InvalidProfile);
        }
        if config.replicas[0].node != self.merge.node() {
            return Err(LocalReplayExecutorError::WrongReplica);
        }
        let anchored = self
            .trust
            .authority_for_space(config.identity.space)
            .ok_or(LocalReplayExecutorError::TrustUnavailable)?;
        if anchored != config.authority {
            return Err(LocalReplayExecutorError::InvalidAuthority);
        }
        if binding.space != config.identity.space
            || binding.agent != config.identity.agent
            || binding.deployment != config.identity.runtime_deployment
            || binding.program != config.identity.runtime_program
            || binding.producer != config.identity.runtime_producer
            || binding.package != config.runtime_package
            || binding.runtime_abi != super::RUNTIME_ABI_ID
            || binding.execution_semantics != super::EXECUTION_SEMANTICS_ID
        {
            return Err(LocalReplayExecutorError::InvalidState);
        }
        self.runtime_package(config, binding).map(|_| ())
    }

    fn load(&self, reference: &BlobRef) -> Result<Vec<u8>, LocalReplayExecutorError> {
        self.resolver
            .load_catalog(reference)?
            .ok_or_else(|| LocalReplayExecutorError::ArtifactUnavailable(reference.clone()))
    }

    fn trusted_package(
        &self,
        config: &AgentConfig,
        reference: &BlobRef,
    ) -> Result<Package, LocalReplayExecutorError> {
        let bytes = self.load(reference)?;
        self.trusted_package_bytes(config, reference, &bytes)
    }

    fn trusted_package_bytes(
        &self,
        config: &AgentConfig,
        reference: &BlobRef,
        bytes: &[u8],
    ) -> Result<Package, LocalReplayExecutorError> {
        if !reference.matches(bytes) {
            return Err(LocalReplayExecutorError::InvalidArtifact(reference.clone()));
        }
        let package = Package::decode(bytes)
            .map_err(|_| LocalReplayExecutorError::InvalidArtifact(reference.clone()))?;
        package
            .validate()
            .map_err(LocalReplayExecutorError::Package)?;
        if !self.trust.verify_package(config, &package) {
            return Err(LocalReplayExecutorError::Package(
                PackageError::InvalidSignature,
            ));
        }
        Ok(package)
    }

    fn validate_actor_catalog(
        &self,
        config: &AgentConfig,
        supplied: &BTreeMap<(Hash, u64), &[u8]>,
        admission: ActorCatalogAdmission<'_>,
    ) -> Result<(), LocalReplayExecutorError> {
        let lookup = |reference: &BlobRef| {
            supplied
                .get(&(reference.hash, reference.len))
                .copied()
                .ok_or_else(|| LocalReplayExecutorError::ArtifactUnavailable(reference.clone()))
        };
        let package_bytes = lookup(admission.package)?;
        let schema = lookup(admission.schema)?;
        let policies = lookup(admission.policies)?;
        let package = self.trusted_package_bytes(config, admission.package, package_bytes)?;
        let PackageKind::Actor {
            contract: package_contract,
            requirements: package_requirements,
        } = package.manifest.kind
        else {
            return Err(LocalReplayExecutorError::Package(PackageError::WrongKind));
        };
        let parsed_schema = super::schema::decode(schema)
            .ok_or_else(|| LocalReplayExecutorError::InvalidArtifact(admission.schema.clone()))?;
        if package.deployment_id() != admission.deployment
            || package.manifest.program != admission.program
            || package.deployment_signature.producer != admission.producer
            || BlobRef::of_bytes(&package.encode()) != *admission.package
            || BlobRef::of_bytes(&package.agent_schema) != *admission.schema
            || BlobRef::of_bytes(&package.role_policies) != *admission.policies
            || package.agent_schema != schema
            || package.role_policies != policies
            || package_contract != admission.contract
            || package_requirements != admission.requirements
            || !config.runtime_contract.supports(admission.contract)
            || !config.capabilities.satisfies(admission.requirements)
            || parsed_schema.state_layout_hash() != admission.state_layout
            || parsed_schema.lanes() != admission.requirements.lanes
            || crate::service::PackageRolePolicies::decode(policies).is_err()
        {
            return Err(LocalReplayExecutorError::InvalidArtifact(
                admission.package.clone(),
            ));
        }
        Ok(())
    }

    /// Authenticate the complete catalog closure named by one live
    /// lifecycle request before any content is staged. This is deliberately
    /// stricter than historical replay, whose closure has already crossed an
    /// admission boundary and must remain deterministic without live trust.
    fn validate_lifecycle_catalog(
        &self,
        config: &AgentConfig,
        request: &LifecycleRequest,
        catalog: &[RuntimeBlob],
    ) -> Result<(), LocalReplayExecutorError> {
        let LifecycleRequest::Authorized { request, .. } = request else {
            return Err(LocalReplayExecutorError::InvalidRequest);
        };
        let expected = match request.as_ref() {
            LifecycleRequest::Install(install) => vec![
                &install.package,
                &install.agent_schema,
                &install.role_policies,
            ],
            LifecycleRequest::UpgradeActor(upgrade) => vec![
                &upgrade.package,
                &upgrade.agent_schema,
                &upgrade.role_policies,
            ],
            LifecycleRequest::UpgradeRuntime { package, .. } => vec![package],
            LifecycleRequest::Create(_)
            | LifecycleRequest::Inspect { .. }
            | LifecycleRequest::Suspend { .. }
            | LifecycleRequest::Resume { .. }
            | LifecycleRequest::AcknowledgeInvocation { .. }
            | LifecycleRequest::RemoveLeaf { .. }
            | LifecycleRequest::Authorized { .. } => Vec::new(),
        };
        let mut expected_by_id = BTreeMap::new();
        for reference in &expected {
            if expected_by_id
                .insert((reference.hash, reference.len), *reference)
                .is_some()
            {
                return Err(LocalReplayExecutorError::InvalidRequest);
            }
        }
        let mut supplied = BTreeMap::new();
        let mut supplied_bytes = 0u64;
        for blob in catalog {
            if blob.bytes.len() > super::journal::MAX_ARTIFACT_CLOSURE_BYTES
                || !blob.reference.matches(&blob.bytes)
                || supplied
                    .insert(
                        (blob.reference.hash, blob.reference.len),
                        blob.bytes.as_slice(),
                    )
                    .is_some()
            {
                return Err(LocalReplayExecutorError::InvalidArtifact(
                    blob.reference.clone(),
                ));
            }
            supplied_bytes = supplied_bytes
                .checked_add(blob.reference.len)
                .ok_or(LocalReplayExecutorError::InvalidRequest)?;
        }
        if supplied_bytes > super::journal::MAX_ARTIFACT_CLOSURE_REFERENCED_BYTES
            || supplied.len() != expected_by_id.len()
            || supplied.keys().any(|key| !expected_by_id.contains_key(key))
        {
            return Err(LocalReplayExecutorError::InvalidRequest);
        }
        for reference in expected_by_id.values() {
            if !supplied.contains_key(&(reference.hash, reference.len)) {
                return Err(LocalReplayExecutorError::ArtifactUnavailable(
                    (*reference).clone(),
                ));
            }
        }

        match request.as_ref() {
            LifecycleRequest::Install(install) => {
                self.validate_actor_catalog(
                    config,
                    &supplied,
                    ActorCatalogAdmission {
                        package: &install.package,
                        schema: &install.agent_schema,
                        policies: &install.role_policies,
                        deployment: install.entry.deployment,
                        program: install.entry.program,
                        producer: install.producer,
                        state_layout: install.state_layout,
                        contract: install.contract,
                        requirements: install.requirements,
                    },
                )?;
                if install.entry.package != install.package
                    || install.entry.agent_schema != install.agent_schema
                    || install.entry.role_policies != install.role_policies
                    || install.entry.state_layout != install.state_layout
                    || install.entry.lanes != install.requirements.lanes
                {
                    return Err(LocalReplayExecutorError::InvalidArtifact(
                        install.package.clone(),
                    ));
                }
            }
            LifecycleRequest::UpgradeActor(upgrade) => {
                self.validate_actor_catalog(
                    config,
                    &supplied,
                    ActorCatalogAdmission {
                        package: &upgrade.package,
                        schema: &upgrade.agent_schema,
                        policies: &upgrade.role_policies,
                        deployment: upgrade.to_deployment,
                        program: upgrade.to_program,
                        producer: upgrade.producer,
                        state_layout: upgrade.state_layout,
                        contract: upgrade.contract,
                        requirements: upgrade.requirements,
                    },
                )?;
            }
            LifecycleRequest::UpgradeRuntime {
                to_deployment,
                to_program,
                producer,
                package,
                contract,
                capabilities,
                ..
            } => {
                let bytes = supplied
                    .get(&(package.hash, package.len))
                    .copied()
                    .ok_or_else(|| {
                        LocalReplayExecutorError::ArtifactUnavailable(package.clone())
                    })?;
                let decoded = self.trusted_package_bytes(config, package, bytes)?;
                let PackageKind::AgentRuntime {
                    contract: package_contract,
                    capabilities: package_capabilities,
                } = decoded.manifest.kind
                else {
                    return Err(LocalReplayExecutorError::Package(PackageError::WrongKind));
                };
                if decoded.deployment_id() != *to_deployment
                    || decoded.manifest.program != *to_program
                    || decoded.deployment_signature.producer != *producer
                    || BlobRef::of_bytes(&decoded.encode()) != *package
                    || package_contract != *contract
                    || package_capabilities != *capabilities
                {
                    return Err(LocalReplayExecutorError::InvalidArtifact(package.clone()));
                }
            }
            LifecycleRequest::Create(_)
            | LifecycleRequest::Inspect { .. }
            | LifecycleRequest::Suspend { .. }
            | LifecycleRequest::Resume { .. }
            | LifecycleRequest::AcknowledgeInvocation { .. }
            | LifecycleRequest::RemoveLeaf { .. } => {}
            LifecycleRequest::Authorized { .. } => {
                return Err(LocalReplayExecutorError::InvalidRequest);
            }
        }
        Ok(())
    }

    fn runtime_package(
        &self,
        config: &AgentConfig,
        binding: &RuntimeBinding,
    ) -> Result<Package, LocalReplayExecutorError> {
        let package = self.trusted_package(config, &binding.package)?;
        let PackageKind::AgentRuntime {
            contract,
            capabilities,
        } = package.manifest.kind
        else {
            return Err(LocalReplayExecutorError::Package(PackageError::WrongKind));
        };
        if !contract.is_valid()
            || package.deployment_id() != binding.deployment
            || package.manifest.program != binding.program
            || package.deployment_signature.producer != binding.producer
            || BlobRef::of_bytes(&package.encode()) != binding.package
            || config.runtime_contract != contract
            || config.capabilities != capabilities
        {
            return Err(LocalReplayExecutorError::InvalidArtifact(
                binding.package.clone(),
            ));
        }
        Ok(package)
    }

    fn authenticate_management(
        &self,
        config: &AgentConfig,
        request: &LifecycleRequest,
    ) -> Result<(), LocalReplayExecutorError> {
        let LifecycleRequest::Authorized { admission, request } = request else {
            return Err(LocalReplayExecutorError::InvalidRequest);
        };
        let inner = request.as_ref();
        let capability = inner
            .required_capability()
            .ok_or(LocalReplayExecutorError::InvalidRequest)?;
        admission
            .receipt
            .verify_guest_signature(&config.authority)
            .map_err(|_| LocalReplayExecutorError::InvalidAuthority)?;
        let claim = &admission.receipt.claim;
        if claim.space != config.identity.space
            || claim.agent != config.identity.agent
            || claim.capability != CapabilityId::named(capability)
            || claim.operation != inner.commitment()
            || matches!(inner, LifecycleRequest::Create(created) if claim.principal != created.identity.owner)
        {
            return Err(LocalReplayExecutorError::InvalidAuthority);
        }
        Ok(())
    }

    fn empty_blob() -> RuntimeBlob {
        RuntimeBlob {
            reference: BlobRef {
                hash: Hash::ZERO,
                len: 0,
            },
            bytes: Vec::new(),
        }
    }

    fn actor_artifacts(
        &self,
        config: &AgentConfig,
        state: &StandardRuntimeState,
        invocation: &ActorInvocation,
    ) -> Result<Option<(Vec<u8>, RuntimeBlob, RuntimeBlob)>, LocalReplayExecutorError> {
        let Some(actor) = state
            .actors
            .iter()
            .find(|actor| actor.record.entry.actor == invocation.actor)
        else {
            return Ok(None);
        };
        let record = &actor.record;
        if record.state_generation != invocation.incarnation
            || record.entry.deployment != invocation.deployment
            || record.entry.program != invocation.program
        {
            // The guest must derive the exact durable target error. Empty
            // recovery artifacts are safe because target validation precedes
            // recovery-only admission inside the Standard runtime.
            return Ok(None);
        }
        let package = self.trusted_package(config, &record.package)?;
        let PackageKind::Actor {
            contract,
            requirements,
        } = package.manifest.kind
        else {
            return Err(LocalReplayExecutorError::Package(PackageError::WrongKind));
        };
        let schema = self.load(&record.agent_schema)?;
        let policies = self.load(&record.role_policies)?;
        let parsed_schema = super::schema::decode(&schema).ok_or_else(|| {
            LocalReplayExecutorError::InvalidArtifact(record.agent_schema.clone())
        })?;
        if package.deployment_id() != record.entry.deployment
            || package.manifest.program != record.entry.program
            || package.deployment_signature.producer != record.producer
            || BlobRef::of_bytes(&package.encode()) != record.package
            || record.entry.package != record.package
            || record.entry.agent_schema != record.agent_schema
            || record.entry.role_policies != record.role_policies
            || BlobRef::of_bytes(&package.agent_schema) != record.agent_schema
            || BlobRef::of_bytes(&package.role_policies) != record.role_policies
            || package.agent_schema != schema
            || package.role_policies != policies
            || record.contract != contract
            || record.requirements != requirements
            || record.entry.lanes != requirements.lanes
            || record.entry.state_layout != record.state_layout
            || !config.runtime_contract.supports(contract)
            || !config.capabilities.satisfies(requirements)
            || parsed_schema.state_layout_hash() != record.state_layout
            || parsed_schema.lanes() != record.entry.lanes
            || crate::service::PackageRolePolicies::decode(&policies).is_err()
        {
            return Err(LocalReplayExecutorError::InvalidArtifact(
                record.package.clone(),
            ));
        }
        Ok(Some((
            package.pvm,
            RuntimeBlob {
                reference: record.agent_schema.clone(),
                bytes: schema,
            },
            RuntimeBlob {
                reference: record.role_policies.clone(),
                bytes: policies,
            },
        )))
    }

    fn execute_wire<T: ServiceWire>(
        &self,
        runtime_pvm: &[u8],
        gas: Gas,
        input: &[u8],
    ) -> Result<T, LocalReplayExecutorError> {
        let invocation = RefineContext::load(runtime_pvm, input, gas)
            .map_err(|_| LocalReplayExecutorError::RuntimeOutput)?
            .run();
        if invocation.exit != ExitReason::Halt {
            return Err(LocalReplayExecutorError::RuntimeExit {
                reason: invocation.exit,
                pc: invocation.pc,
            });
        }
        let output = invocation
            .output()
            .ok_or(LocalReplayExecutorError::RuntimeOutput)?;
        T::decode(&output).map_err(|_| LocalReplayExecutorError::RuntimeOutput)
    }

    fn validate_state_size(
        &self,
        state: &RuntimeState,
        config: &AgentConfig,
    ) -> Result<(), LocalReplayExecutorError> {
        let bytes = state
            .encoded_len()
            .ok_or(LocalReplayExecutorError::RuntimeStateTooLarge)?;
        if state.is_empty()
            || bytes > super::execution::MAX_RUNTIME_STATE_BYTES
            || bytes > config.runtime_contract.resources.max_runtime_state_bytes as usize
        {
            return Err(LocalReplayExecutorError::RuntimeStateTooLarge);
        }
        Ok(())
    }

    fn disposition(result: &Result<ActorExecutionReply, ActorExecutionError>) -> ReplayDisposition {
        match result {
            Ok(reply) => match reply.status {
                ActorExecutionStatus::Done => ReplayDisposition::Applied,
                ActorExecutionStatus::Forbidden => ReplayDisposition::Forbidden,
                ActorExecutionStatus::Panicked => ReplayDisposition::Panicked,
                ActorExecutionStatus::OutOfGas => ReplayDisposition::OutOfGas,
            },
            Err(_) => ReplayDisposition::Rejected,
        }
    }

    fn runtime_upgrade_target(input: &ReplayInput, applied: bool) -> RuntimeBinding {
        if !applied {
            return input.runtime.clone();
        }
        let ReplayOperation::Management {
            request: LifecycleRequest::Authorized { request, .. },
        } = &input.operation
        else {
            return input.runtime.clone();
        };
        let LifecycleRequest::UpgradeRuntime {
            from_deployment,
            to_deployment,
            to_program,
            producer,
            package,
            ..
        } = request.as_ref()
        else {
            return input.runtime.clone();
        };
        if *from_deployment != input.runtime.deployment {
            return input.runtime.clone();
        }
        let mut next = input.runtime.clone();
        next.deployment = *to_deployment;
        next.program = *to_program;
        next.producer = *producer;
        next.package = package.clone();
        next
    }
}

impl<R: CatalogBlobResolver> ReplayExecutor for StandardLocalReplayExecutor<R> {
    type Error = LocalReplayExecutorError;

    fn verify_merge_event(&mut self, event: &MergeEvent) -> Result<bool, Self::Error> {
        Ok(event.author == self.merge.node() && self.merge.verify(event))
    }

    fn authenticate(
        &mut self,
        input: &ReplayInput,
        before: &RuntimeState,
        _position: ReplayPosition,
    ) -> Result<(), Self::Error> {
        let decoded = decode_standard_runtime_state(before)
            .map_err(|_| LocalReplayExecutorError::InvalidState)?;
        let config = self.config_for(input, &decoded)?;
        self.validate_local_config(config, &input.runtime)?;
        match &input.operation {
            ReplayOperation::Management { request } => {
                self.authenticate_management(config, request)
            }
            ReplayOperation::Invoke {
                invocation,
                authority,
                ..
            }
            | ReplayOperation::Acknowledge {
                invocation,
                authority,
            } => {
                invocation
                    .validate()
                    .map_err(|_| LocalReplayExecutorError::InvalidRequest)?;
                authority
                    .validate_for(
                        &config.authority,
                        config.identity.space,
                        config.identity.agent,
                        invocation,
                    )
                    .map_err(|_| LocalReplayExecutorError::InvalidAuthority)
            }
            ReplayOperation::SealMerge => Ok(()),
        }
    }

    fn execute(
        &mut self,
        input: &ReplayInput,
        before: &RuntimeState,
        position: ReplayPosition,
    ) -> Result<ReplayTransition, Self::Error> {
        self.authenticate(input, before, position)?;
        let decoded = decode_standard_runtime_state(before)
            .map_err(|_| LocalReplayExecutorError::InvalidState)?;
        let config = self.config_for(input, &decoded)?.clone();
        let runtime = self.runtime_package(&config, &input.runtime)?;

        let transition = match &input.operation {
            ReplayOperation::Management { request } => {
                let mut expected = StandardAgentRuntime::restore(decoded.clone())
                    .map_err(|_| LocalReplayExecutorError::InvalidState)?;
                let expected_result = expected.apply(request.clone());
                let returned: RuntimeReturn = self.execute_wire(
                    &runtime.pvm,
                    self.management_gas,
                    &RuntimeCall {
                        state: before.clone(),
                        request: request.clone(),
                    }
                    .encode(),
                )?;
                self.validate_state_size(&returned.state, &config)?;
                if returned.result != expected_result {
                    return Err(LocalReplayExecutorError::InvalidState);
                }
                self.last_management_result = Some((input.id(), returned.result.clone()));
                let applied = returned.result.is_ok();
                let next_runtime = Self::runtime_upgrade_target(input, applied);
                if applied && next_runtime != input.runtime {
                    let next_state = decode_standard_runtime_state(&returned.state)
                        .map_err(|_| LocalReplayExecutorError::InvalidState)?;
                    let next_config = next_state
                        .config
                        .as_ref()
                        .ok_or(LocalReplayExecutorError::InvalidState)?;
                    self.validate_local_config(next_config, &next_runtime)?;
                }
                ReplayTransition {
                    state: returned.state,
                    disposition: if applied {
                        ReplayDisposition::Applied
                    } else {
                        ReplayDisposition::Rejected
                    },
                    result: None,
                    next_runtime,
                    products: ReplayProducts::default(),
                }
            }
            ReplayOperation::Acknowledge {
                invocation,
                authority,
            } => {
                let request = LifecycleRequest::AcknowledgeInvocation {
                    scope: invocation.mode.invocation_scope(),
                    invocation: invocation.invocation,
                    request: invocation.commitment(),
                    authority: Box::new(authority.clone()),
                };
                let returned: RuntimeReturn = self.execute_wire(
                    &runtime.pvm,
                    self.management_gas,
                    &RuntimeCall {
                        state: before.clone(),
                        request,
                    }
                    .encode(),
                )?;
                self.validate_state_size(&returned.state, &config)?;
                if !matches!(
                    returned.result,
                    Ok(LifecycleReply::InvocationAcknowledged {
                        scope,
                        invocation: id,
                    }) if scope == invocation.mode.invocation_scope() && id == invocation.invocation
                ) {
                    return Err(LocalReplayExecutorError::InvalidState);
                }
                ReplayTransition {
                    state: returned.state,
                    disposition: ReplayDisposition::Applied,
                    result: None,
                    next_runtime: input.runtime.clone(),
                    products: ReplayProducts::default(),
                }
            }
            ReplayOperation::Invoke {
                invocation,
                authority,
                observed_slot,
            } => {
                let artifacts = self.actor_artifacts(&config, &decoded, invocation)?;
                let recovery_only = artifacts.is_none();
                let empty = Self::empty_blob;
                let (actor_pvm, actor_schema, actor_policies) =
                    artifacts.unwrap_or_else(|| (Vec::new(), empty(), empty()));
                let returned: RuntimeExecutionReturn = self.execute_wire(
                    &runtime.pvm,
                    self.management_gas.saturating_add(invocation.gas),
                    &RuntimeExecutionCall {
                        state: before.clone(),
                        invocation: invocation.clone(),
                        authority: authority.clone(),
                        observed_slot: *observed_slot,
                        recovery_only,
                        actor_pvm,
                        actor_schema,
                        actor_policies,
                    }
                    .encode(),
                )?;
                self.validate_state_size(&returned.state, &config)?;
                ReplayTransition {
                    disposition: Self::disposition(&returned.result),
                    state: returned.state,
                    result: Some(returned.result),
                    next_runtime: input.runtime.clone(),
                    products: ReplayProducts::default(),
                }
            }
            ReplayOperation::SealMerge => ReplayTransition {
                state: before.clone(),
                disposition: ReplayDisposition::Applied,
                result: None,
                next_runtime: input.runtime.clone(),
                products: ReplayProducts::default(),
            },
        };
        if !transition.products.is_empty() {
            return Err(LocalReplayExecutorError::InvalidState);
        }
        Ok(transition)
    }
}

/// Store/replay nucleus kept generic so both fd-pinned filesystem stores and
/// the deterministic memory store follow the identical publication path.
struct LocalJournalCore<S, E> {
    store: S,
    materialization: ReplayMaterialization,
    executor: E,
}

#[derive(Debug, PartialEq, Eq)]
struct LocalCorePublication {
    executions: Vec<ReplayExecutionResult>,
    committed: Option<ReplayCommittedRecovery>,
    published_position: Option<ReplayPosition>,
}

#[derive(Debug, PartialEq, Eq)]
enum ExistingMergeRecovery {
    Pending(PendingMergeReceipt),
    Acknowledged,
}

impl core::ops::Deref for LocalCorePublication {
    type Target = [ReplayExecutionResult];

    fn deref(&self) -> &Self::Target {
        &self.executions
    }
}

impl<S, E> LocalJournalCore<S, E>
where
    S: AgentJournalStore
        + super::replay::ReplaySource<Error = JournalStoreError>
        + CatalogBlobResolverFactory,
    E: ReplayExecutor<Error = LocalReplayExecutorError>,
{
    fn open(mut store: S, mut executor: E) -> Result<Self, LocalJournalDriverError> {
        let materialization =
            materialize_current(&mut store, &mut executor, &NoPrunedOrderedBases)?;
        Ok(Self {
            store,
            materialization,
            executor,
        })
    }

    fn checkpoint(&mut self) -> Result<(), LocalJournalDriverError> {
        let prepared = prepare_checkpoint(&mut self.store, &self.materialization)
            .map_err(lift_checkpoint_error)?;
        let (_, successor, executions) = prepared.publish()?;
        if !executions.is_empty() {
            return Err(LocalJournalDriverError::InvalidResult);
        }
        self.materialization = successor;
        Ok(())
    }

    fn persist_current_merge_seal(
        &mut self,
    ) -> Result<super::journal::MergeSealId, LocalJournalDriverError> {
        let state = &self.materialization.state().merge;
        let reference = BlobRef::of_bytes(state);
        self.store
            .put_blob(JournalBlobClass::LaneState, &reference, state)?;
        let manifest = derive_lane_state::<core::convert::Infallible, core::convert::Infallible>(
            self.materialization.heads().genesis,
            self.materialization.runtime().clone(),
            PersistedLane::Merge,
            LaneCursor::Merge {
                frontier: self.materialization.merge_frontier(),
            },
            state,
        )
        .map_err(|_| LocalJournalDriverError::InvalidResult)?;
        self.store.put(&manifest)?;
        let seal = MergeSeal {
            genesis: self.materialization.heads().genesis,
            frontier: self.materialization.merge_frontier(),
            ordered_base: self.materialization.ordered_base(),
            merge_state: manifest.id(),
        };
        self.store.put(&seal)?;
        Ok(seal.id())
    }

    fn publish_ordered(
        &mut self,
        entry: &OrderedEntry,
    ) -> Result<LocalCorePublication, LocalJournalDriverError> {
        let mut candidate = entry.clone();
        let prepared = match prepare_ordered(
            &mut self.store,
            &mut self.executor,
            &self.materialization,
            &candidate,
        ) {
            Err(ReplayError::ReplayLimit) => {
                self.checkpoint()?;
                let merge_seal = if entry.merge_seal.is_some() {
                    Some(self.persist_current_merge_seal()?)
                } else {
                    None
                };
                let heads = self.materialization.heads();
                candidate = OrderedEntry {
                    genesis: heads.genesis,
                    index: heads
                        .ordered_index
                        .checked_add(1)
                        .ok_or(LocalJournalDriverError::InvalidResult)?,
                    parent: heads.ordered_head,
                    merge_frontier: heads.merge_frontier,
                    merge_seal,
                    input: entry.input.clone(),
                };
                prepare_ordered(
                    &mut self.store,
                    &mut self.executor,
                    &self.materialization,
                    &candidate,
                )
                .map_err(LocalJournalDriverError::from)?
            }
            result => result.map_err(LocalJournalDriverError::from)?,
        };
        let published_position = ReplayPosition::Ordered {
            id: candidate.id(),
            index: candidate.index,
            merge_frontier: candidate.merge_frontier,
            merge_seal: candidate.merge_seal,
        };
        match prepared {
            ReplayPreparation::Ready(prepared) => {
                let (_, successor, executions) = prepared.publish()?;
                self.materialization = successor;
                Ok(LocalCorePublication {
                    executions,
                    committed: None,
                    published_position: Some(published_position),
                })
            }
            ReplayPreparation::AlreadyCommitted(committed) => Ok(LocalCorePublication {
                executions: Vec::new(),
                committed: Some(committed),
                published_position: None,
            }),
        }
    }

    fn publish_local(
        &mut self,
        entry: &LocalEntry,
    ) -> Result<LocalCorePublication, LocalJournalDriverError> {
        let mut candidate = entry.clone();
        let prepared = match prepare_local(
            &mut self.store,
            &mut self.executor,
            &self.materialization,
            &candidate,
        ) {
            Err(ReplayError::ReplayLimit) => {
                self.checkpoint()?;
                let heads = self.materialization.heads();
                candidate = LocalEntry {
                    genesis: heads.genesis,
                    node: heads.node,
                    revision: heads
                        .local_revision
                        .checked_add(1)
                        .ok_or(LocalJournalDriverError::InvalidResult)?,
                    parent: heads.local_head,
                    ordered_base: self.materialization.ordered_base(),
                    merge_frontier: heads.merge_frontier,
                    input: entry.input.clone(),
                };
                prepare_local(
                    &mut self.store,
                    &mut self.executor,
                    &self.materialization,
                    &candidate,
                )
                .map_err(LocalJournalDriverError::from)?
            }
            result => result.map_err(LocalJournalDriverError::from)?,
        };
        let published_position = ReplayPosition::Local {
            id: candidate.id(),
            node: candidate.node,
            revision: candidate.revision,
            ordered_base: candidate.ordered_base,
            merge_frontier: candidate.merge_frontier,
        };
        match prepared {
            ReplayPreparation::Ready(prepared) => {
                let (_, successor, executions) = prepared.publish()?;
                self.materialization = successor;
                Ok(LocalCorePublication {
                    executions,
                    committed: None,
                    published_position: Some(published_position),
                })
            }
            ReplayPreparation::AlreadyCommitted(committed) => Ok(LocalCorePublication {
                executions: Vec::new(),
                committed: Some(committed),
                published_position: None,
            }),
        }
    }

    fn publish_merge(
        &mut self,
        event: &MergeEvent,
    ) -> Result<LocalCorePublication, LocalJournalDriverError> {
        let prepared = match prepare_merge(
            &mut self.store,
            &mut self.executor,
            &NoPrunedOrderedBases,
            &self.materialization,
            event,
        ) {
            Err(ReplayError::ReplayLimit) => {
                self.checkpoint()?;
                // The checkpoint may replace the canonical OrderedBase. A
                // Merge event signs that base, so only the driver holding the
                // LocalMergeAuthenticator can rebuild it safely.
                return Err(LocalJournalDriverError::Replay(ReplayError::ReplayLimit));
            }
            result => result.map_err(LocalJournalDriverError::from)?,
        };
        let published_position = ReplayPosition::Merge {
            id: event.id(),
            causal_height: event.causal_height,
            ordered_base: event.ordered_base,
        };
        match prepared {
            ReplayPreparation::Ready(prepared) => {
                let (_, successor, executions) = prepared.publish()?;
                self.materialization = successor;
                Ok(LocalCorePublication {
                    executions,
                    committed: None,
                    published_position: Some(published_position),
                })
            }
            ReplayPreparation::AlreadyCommitted(committed) => Ok(LocalCorePublication {
                executions: Vec::new(),
                committed: Some(committed),
                published_position: None,
            }),
        }
    }

    /// Resolve a same-request pending Merge owner to its authenticated source
    /// event before proposing any alias event. The returned receipt contains
    /// the exact input and position needed for restart-safe recovery.
    fn existing_merge_recovery(
        &mut self,
        input: &ReplayInput,
    ) -> Result<Option<ExistingMergeRecovery>, LocalJournalDriverError> {
        let (invocation, acknowledgement) = match &input.operation {
            ReplayOperation::Invoke { invocation, .. } => (invocation, false),
            ReplayOperation::Acknowledge { invocation, .. } => (invocation, true),
            ReplayOperation::Management { .. } | ReplayOperation::SealMerge => return Ok(None),
        };
        if invocation.mode.invocation_scope() != InvocationScope::Merge {
            return Ok(None);
        }
        let key = InvocationOwnershipKey {
            scope: InvocationOwnershipScope::Merge,
            invocation: invocation.invocation,
        };
        let heads = self.materialization.heads();
        let indexes = InvocationIndexes::open(
            &mut self.store,
            heads.ordered_invocations,
            heads.merge_invocations,
            heads.local_invocations,
        )
        .map_err(|_| LocalJournalDriverError::InvalidResult)?;
        let Some(owner) = indexes
            .lookup(key)
            .map_err(|_| LocalJournalDriverError::InvalidResult)?
        else {
            return Ok(None);
        };
        if owner.validate().is_err()
            || owner.scope != InvocationOwnershipScope::Merge
            || owner.request_commitment != invocation.commitment()
        {
            return Ok(None);
        }
        let source_event = match (acknowledgement, owner.result_state) {
            (_, InvocationResultState::Acknowledged { .. }) => {
                return Ok(Some(ExistingMergeRecovery::Acknowledged));
            }
            (false, InvocationResultState::PendingMerge { source_event }) => source_event,
            (
                true,
                InvocationResultState::PendingMergeAcknowledgement {
                    acknowledgement_event,
                    ..
                },
            ) => acknowledgement_event,
            (false, InvocationResultState::PendingMergeAcknowledgement { .. }) => {
                let outcome = indexes
                    .outcome(key)
                    .map_err(|_| LocalJournalDriverError::InvalidResult)?
                    .ok_or(LocalJournalDriverError::InvalidResult)?;
                match outcome.anchor {
                    InvocationOutcomeAnchor::Merge { source_event, .. } => source_event,
                    InvocationOutcomeAnchor::Ordered { .. }
                    | InvocationOutcomeAnchor::Local { .. } => {
                        return Err(LocalJournalDriverError::InvalidResult);
                    }
                }
            }
            _ => return Ok(None),
        };
        drop(indexes);

        let event = self
            .store
            .get::<MergeEvent>(source_event)?
            .ok_or(LocalJournalDriverError::InvalidResult)?;
        if event.validate().is_err()
            || event.id() != source_event
            || event.genesis != self.materialization.heads().genesis
        {
            return Err(LocalJournalDriverError::InvalidResult);
        }
        let position = ReplayPosition::Merge {
            id: source_event,
            causal_height: event.causal_height,
            ordered_base: event.ordered_base,
        };
        if self.recover(&event.input, position)? != ReplayInvocationRecovery::Pending {
            return Err(LocalJournalDriverError::InvalidResult);
        }
        Ok(Some(ExistingMergeRecovery::Pending(PendingMergeReceipt {
            event: source_event,
            frontier: MergeFrontier {
                genesis: event.genesis,
                events: vec![source_event],
            }
            .id(),
            input: event.input,
            position,
        })))
    }

    fn recover(
        &mut self,
        input: &ReplayInput,
        position: ReplayPosition,
    ) -> Result<ReplayInvocationRecovery, LocalJournalDriverError> {
        recover_invocation(&mut self.store, &self.materialization, input, position)
            .map_err(|error| LocalJournalDriverError::Replay(lift_checkpoint_error(error)))
    }
}

/// Production journal-backed Local Agent driver.
///
/// `S` may be the memory reference store or the fd-pinned filesystem store;
/// both provide a cloneable read-only resolver snapshot to the exact runtime
/// executor. No whole [`super::driver::AgentImage`] is constructed or used.
pub(crate) struct LocalJournalAgentDriver<S>
where
    S: AgentJournalStore
        + super::replay::ReplaySource<Error = JournalStoreError>
        + CatalogBlobResolverFactory,
{
    core: LocalJournalCore<S, StandardLocalReplayExecutor<S::Resolver>>,
}

impl<S> LocalJournalAgentDriver<S>
where
    S: AgentJournalStore
        + super::replay::ReplaySource<Error = JournalStoreError>
        + CatalogBlobResolverFactory,
{
    fn validate_create_state(
        post_create: &RuntimeState,
        binding: &RuntimeBinding,
        replica: AgentReplica,
        resolver: SuppliedCatalogBlobResolver,
        trust: &Arc<dyn AgentTrustProvider>,
        merge: &Arc<dyn LocalMergeAuthenticator>,
    ) -> Result<(), LocalJournalDriverError> {
        let decoded = decode_standard_runtime_state(post_create)
            .map_err(|_| LocalReplayExecutorError::InvalidState)?;
        let config = decoded
            .config
            .as_ref()
            .ok_or(LocalReplayExecutorError::InvalidState)?;
        let executor =
            StandardLocalReplayExecutor::new(resolver, Arc::clone(trust), Arc::clone(merge));
        executor.validate_local_config(config, binding)?;
        if config.replicas.first().copied() != Some(replica) {
            return Err(LocalReplayExecutorError::WrongReplica.into());
        }
        Ok(())
    }

    /// Validate every semantic input to genesis installation against only the
    /// sealed post-Create state and the caller's immutable catalog snapshot.
    /// This function is intentionally store-free so a failure cannot leave a
    /// genesis, heads envelope, or catalog orphan behind.
    fn preflight_create(
        sealed: &ReplaySealedGenesis,
        catalog: &[RuntimeBlob],
        trust: &Arc<dyn AgentTrustProvider>,
        merge: &Arc<dyn LocalMergeAuthenticator>,
    ) -> Result<(), LocalJournalDriverError> {
        if sealed.replica().node != merge.node() {
            return Err(LocalReplayExecutorError::WrongReplica.into());
        }
        let resolver = SuppliedCatalogBlobResolver::from_catalog(catalog)?;
        if resolver.blobs.len() != sealed.artifacts().artifacts.len()
            || sealed.artifacts().artifacts.iter().any(|reference| {
                resolver
                    .blobs
                    .get(&(reference.hash, reference.len))
                    .is_none_or(|bytes| !reference.matches(bytes))
            })
        {
            return Err(LocalJournalDriverError::InvalidResult);
        }

        Self::validate_create_state(
            sealed.post_create(),
            sealed.genesis().runtime(),
            sealed.replica(),
            resolver,
            trust,
            merge,
        )
    }

    /// Initialize only from a root/QC-admitted, exactly executed genesis.
    /// The complete catalog closure is made durable before genesis and heads
    /// become visible.
    pub(crate) fn create(
        mut store: S,
        sealed: ReplaySealedGenesis,
        catalog: &[RuntimeBlob],
        trust: Arc<dyn AgentTrustProvider>,
        merge: Arc<dyn LocalMergeAuthenticator>,
    ) -> Result<Self, LocalJournalDriverError> {
        Self::preflight_create(&sealed, catalog, &trust, &merge)?;
        for blob in catalog {
            store.put_blob(
                JournalBlobClass::CatalogArtifact,
                &blob.reference,
                &blob.bytes,
            )?;
        }
        store.initialize(&sealed)?;
        let resolver = store.catalog_blob_resolver()?;
        let executor = StandardLocalReplayExecutor::new(resolver, trust, merge);
        let core = LocalJournalCore::open(store, executor)?;
        let driver = Self { core };
        driver.validate_opened(Some(sealed.replica()))?;
        Ok(driver)
    }

    /// Open a store whose filesystem/root adapter has already reverified the
    /// sealed genesis admission. The only state cache is rebuilt from typed
    /// journal closure and exact replay.
    pub(crate) fn open(
        store: S,
        trust: Arc<dyn AgentTrustProvider>,
        merge: Arc<dyn LocalMergeAuthenticator>,
    ) -> Result<Self, LocalJournalDriverError> {
        let resolver = store.catalog_blob_resolver()?;
        let executor = StandardLocalReplayExecutor::new(resolver, trust, merge);
        let core = LocalJournalCore::open(store, executor)?;
        let driver = Self { core };
        driver.validate_opened(None)?;
        Ok(driver)
    }

    fn validate_opened(
        &self,
        sealed_replica: Option<AgentReplica>,
    ) -> Result<(), LocalJournalDriverError> {
        let state = decode_standard_runtime_state(self.core.materialization.state())
            .map_err(|_| LocalReplayExecutorError::InvalidState)?;
        let config = state
            .config
            .as_ref()
            .ok_or(LocalReplayExecutorError::InvalidState)?;
        self.core
            .executor
            .validate_local_config(config, self.core.materialization.runtime())?;
        let replica = config.replicas[0];
        if replica.node != self.core.materialization.heads().node
            || sealed_replica.is_some_and(|sealed| sealed != replica)
        {
            return Err(LocalJournalDriverError::Executor(
                LocalReplayExecutorError::WrongReplica,
            ));
        }
        Ok(())
    }

    fn stage_catalog(&mut self, catalog: &[RuntimeBlob]) -> Result<(), LocalJournalDriverError> {
        let mut staged = BTreeMap::new();
        for blob in catalog {
            if !blob.reference.matches(&blob.bytes) {
                return Err(
                    LocalReplayExecutorError::InvalidArtifact(blob.reference.clone()).into(),
                );
            }
            match staged.insert(
                (blob.reference.hash, blob.reference.len),
                blob.bytes.as_slice(),
            ) {
                Some(existing) if existing != blob.bytes.as_slice() => {
                    return Err(
                        LocalReplayExecutorError::InvalidArtifact(blob.reference.clone()).into(),
                    );
                }
                _ => {}
            }
        }
        for blob in catalog {
            self.core.store.put_blob(
                JournalBlobClass::CatalogArtifact,
                &blob.reference,
                &blob.bytes,
            )?;
        }
        // Memory snapshots are copy-on-write and file snapshots own pinned
        // descriptors. Refresh only after every requested byte is durable.
        let resolver = self.core.store.catalog_blob_resolver()?;
        self.core.executor.replace_resolver(resolver);
        Ok(())
    }

    fn persist_merge_seal(
        &mut self,
    ) -> Result<super::journal::MergeSealId, LocalJournalDriverError> {
        self.core.persist_current_merge_seal()
    }

    /// Seal and apply one authority-signed lifecycle mutation. The trusted
    /// logical slot is sampled here and cannot be supplied by the caller.
    /// Catalog bytes for an install or upgrade are persisted before the
    /// ordered publication can name them.
    pub(crate) fn lifecycle(
        &mut self,
        receipt: AgentAuthorityReceipt,
        request: LifecycleRequest,
        catalog: &[RuntimeBlob],
    ) -> Result<LocalLifecycleResult, LocalJournalDriverError> {
        let config = self.trusted_current_config()?;
        let request = seal_lifecycle_request(self.core.executor.trust.as_ref(), receipt, request)?;
        self.core
            .executor
            .authenticate_management(&config, &request)?;
        let preflight =
            preflight_lifecycle_transition(self.core.materialization.state(), &request)?;
        if preflight.unchanged {
            return Ok(LocalLifecycleResult {
                result: preflight.result,
                finalized_merge_invocations: Vec::new(),
            });
        }
        if retained_lifecycle_disposition(self.core.materialization.state(), &request)?.is_none()
            && preflight.result.is_ok()
        {
            self.core
                .executor
                .validate_lifecycle_catalog(&config, &request, catalog)?;
            validate_prospective_artifact_closure(
                self.core.materialization.heads().genesis,
                &preflight.successor,
            )?;
            self.stage_catalog(catalog)?;
        }
        let input = ReplayInput {
            runtime: self.core.materialization.runtime().clone(),
            operation: ReplayOperation::Management {
                request: request.clone(),
            },
        };
        let input_id = input.id();
        let merge_seal = self.persist_merge_seal()?;
        let heads = self.core.materialization.heads();
        let entry = OrderedEntry {
            genesis: heads.genesis,
            index: heads
                .ordered_index
                .checked_add(1)
                .ok_or(LocalJournalDriverError::InvalidResult)?,
            parent: heads.ordered_head,
            merge_frontier: heads.merge_frontier,
            merge_seal: Some(merge_seal),
            input,
        };
        self.core.executor.clear_management_result();
        let executions = self.core.publish_ordered(&entry)?.executions;
        let finalized_merge_invocations = executions
            .iter()
            .filter_map(|execution| {
                execution
                    .result()
                    .cloned()
                    .map(|result| FinalizedMergeInvocation {
                        input: execution.input(),
                        position: execution.position(),
                        result,
                    })
            })
            .collect::<Vec<_>>();
        if executions
            .iter()
            .any(|execution| !execution.products().is_empty())
        {
            return Err(LocalJournalDriverError::InvalidResult);
        }
        let result = match self.core.executor.take_management_result(input_id) {
            Some(result) => result,
            None => self.lifecycle_result(&request)?,
        };
        Ok(LocalLifecycleResult {
            result,
            finalized_merge_invocations,
        })
    }

    fn lifecycle_result(
        &self,
        request: &LifecycleRequest,
    ) -> Result<Result<LifecycleReply, LifecycleError>, LocalJournalDriverError> {
        retained_lifecycle_disposition(self.core.materialization.state(), request)
            .map_err(LocalJournalDriverError::Executor)?
            .ok_or(LocalJournalDriverError::InvalidResult)
    }

    /// Finalize the currently admitted Merge frontier without inventing a
    /// guest lifecycle request. This is an ordered maintenance unit; replay
    /// itself synthesizes and validates the byte-identical no-op transition.
    pub(crate) fn finalize_merge(
        &mut self,
    ) -> Result<Vec<FinalizedMergeInvocation>, LocalJournalDriverError> {
        // SealMerge is maintenance rather than a signed guest operation, but
        // it must still fail closed against the live space-authority and
        // runtime-package trust roots before writing its prospective closure.
        self.trusted_current_config()?;
        let merge_seal = self.persist_merge_seal()?;
        let heads = self.core.materialization.heads();
        let input = ReplayInput {
            runtime: heads.runtime.clone(),
            operation: ReplayOperation::SealMerge,
        };
        let entry = OrderedEntry {
            genesis: heads.genesis,
            index: heads
                .ordered_index
                .checked_add(1)
                .ok_or(LocalJournalDriverError::InvalidResult)?,
            parent: heads.ordered_head,
            merge_frontier: heads.merge_frontier,
            merge_seal: Some(merge_seal),
            input,
        };
        let executions = self.core.publish_ordered(&entry)?.executions;
        if executions
            .iter()
            .any(|execution| !execution.products().is_empty())
        {
            return Err(LocalJournalDriverError::InvalidResult);
        }
        Ok(executions
            .into_iter()
            .filter_map(|execution| {
                execution
                    .result()
                    .cloned()
                    .map(|result| FinalizedMergeInvocation {
                        input: execution.input(),
                        position: execution.position(),
                        result,
                    })
            })
            .collect())
    }

    fn current_config(&self) -> Result<AgentConfig, LocalJournalDriverError> {
        decode_standard_runtime_state(self.core.materialization.state())
            .map_err(|_| LocalJournalDriverError::InvalidResult)?
            .config
            .ok_or(LocalJournalDriverError::InvalidResult)
    }

    fn trusted_current_config(&self) -> Result<AgentConfig, LocalJournalDriverError> {
        let config = self.current_config()?;
        self.core
            .executor
            .validate_local_config(&config, self.core.materialization.runtime())?;
        Ok(config)
    }

    fn validate_invocation_capability(
        config: &AgentConfig,
        input: &ReplayInput,
    ) -> Result<(), LocalJournalDriverError> {
        let (invocation, authority) = match &input.operation {
            ReplayOperation::Invoke {
                invocation,
                authority,
                ..
            }
            | ReplayOperation::Acknowledge {
                invocation,
                authority,
            } => (invocation, authority),
            ReplayOperation::Management { .. } | ReplayOperation::SealMerge => {
                return Err(LocalReplayExecutorError::InvalidRequest.into());
            }
        };
        invocation
            .validate()
            .map_err(|_| LocalReplayExecutorError::InvalidRequest)?;
        authority
            .validate_for(
                &config.authority,
                config.identity.space,
                config.identity.agent,
                invocation,
            )
            .map_err(|_| LocalReplayExecutorError::InvalidAuthority)?;
        Ok(())
    }

    fn merge_event(&self, input: ReplayInput) -> Result<MergeEvent, LocalJournalDriverError> {
        let heads = self.core.materialization.heads();
        let frontier = self
            .core
            .store
            .get::<MergeFrontier>(heads.merge_frontier)?
            .ok_or(LocalJournalDriverError::InvalidResult)?;
        if frontier.id() != heads.merge_frontier || frontier.genesis != heads.genesis {
            return Err(LocalJournalDriverError::InvalidResult);
        }
        let causal_height = if frontier.events.is_empty() {
            1
        } else {
            let mut maximum = 0_u64;
            for parent in &frontier.events {
                let event = self
                    .core
                    .store
                    .get::<MergeEvent>(*parent)?
                    .ok_or(LocalJournalDriverError::InvalidResult)?;
                if event.id() != *parent || event.genesis != heads.genesis {
                    return Err(LocalJournalDriverError::InvalidResult);
                }
                maximum = maximum.max(event.causal_height);
            }
            maximum
                .checked_add(1)
                .ok_or(LocalJournalDriverError::InvalidResult)?
        };
        let mut event = MergeEvent {
            genesis: heads.genesis,
            author: heads.node,
            ordered_base: self.core.materialization.ordered_base(),
            causal_height,
            parents: frontier.events,
            input,
            signature: Vec::new(),
        };
        event.signature = self
            .core
            .executor
            .merge
            .sign(event.signing_message())
            .ok_or(LocalReplayExecutorError::InvalidAuthority)?;
        if event.validate().is_err()
            || event.author != self.core.executor.merge.node()
            || !self.core.executor.merge.verify(&event)
        {
            return Err(LocalReplayExecutorError::InvalidAuthority.into());
        }
        Ok(event)
    }

    fn authoritative_publication_position(
        input: ReplayInputId,
        proposed: ReplayPosition,
        publication: LocalCorePublication,
    ) -> Result<(ReplayPosition, Vec<ReplayExecutionResult>, bool), LocalJournalDriverError> {
        let LocalCorePublication {
            executions,
            committed,
            published_position,
        } = publication;
        let (position, already_committed) = match committed {
            Some(committed) => {
                if committed.input() != input || published_position.is_some() {
                    return Err(LocalJournalDriverError::InvalidResult);
                }
                (committed.position(), true)
            }
            None => (
                published_position.ok_or(LocalJournalDriverError::InvalidResult)?,
                false,
            ),
        };
        let same_scope = matches!(
            (proposed, position),
            (
                ReplayPosition::Ordered { .. },
                ReplayPosition::Ordered { .. }
            ) | (ReplayPosition::Local { .. }, ReplayPosition::Local { .. })
                | (ReplayPosition::Merge { .. }, ReplayPosition::Merge { .. })
        );
        if !same_scope || already_committed && !executions.is_empty() {
            return Err(LocalJournalDriverError::InvalidResult);
        }
        Ok((position, executions, already_committed))
    }

    fn is_checkpoint_only_delta(
        before: &ReplayMaterialization,
        after: &ReplayMaterialization,
    ) -> bool {
        let old = before.heads();
        let new = after.heads();
        Self::is_canonical_checkpoint_state_delta(before.state(), after.state())
            && old.genesis == new.genesis
            && old.admission == new.admission
            && old.node == new.node
            && old.runtime == new.runtime
            && old.ordered_head == new.ordered_head
            && old.ordered_index == new.ordered_index
            && old.merge_frontier == new.merge_frontier
            && old.merge_fence == new.merge_fence
            && old.merge_seal == new.merge_seal
            && old.ordered_invocations == new.ordered_invocations
            && old.merge_invocations == new.merge_invocations
            && old.local_invocations == new.local_invocations
            && old.local_head == new.local_head
            && old.local_revision == new.local_revision
            && new.checkpoint.is_some()
            && new.publication_revision == old.publication_revision.checked_add(1).unwrap_or(0)
            && new.previous == Some(before.heads_id())
    }

    fn is_canonical_checkpoint_state_delta(before: &RuntimeState, after: &RuntimeState) -> bool {
        let Some(mut runtime) = decode_standard_runtime_state(before)
            .ok()
            .and_then(|decoded| StandardAgentRuntime::restore(decoded).ok())
        else {
            return false;
        };
        runtime.compact_historical_lane_entries_for_checkpoint();
        super::wire::encode_standard_runtime_state(&runtime.snapshot()) == *after
    }

    fn publish_invocation_input(
        &mut self,
        input: ReplayInput,
    ) -> Result<
        (
            ReplayPosition,
            Vec<ReplayExecutionResult>,
            Option<PendingMergeReceipt>,
        ),
        LocalJournalDriverError,
    > {
        let scope = match &input.operation {
            ReplayOperation::Invoke { invocation, .. }
            | ReplayOperation::Acknowledge { invocation, .. } => invocation.mode.invocation_scope(),
            ReplayOperation::Management { .. } | ReplayOperation::SealMerge => {
                return Err(LocalJournalDriverError::InvalidResult);
            }
        };
        match scope {
            InvocationScope::Ordered => {
                let input_id = input.id();
                let heads = self.core.materialization.heads();
                let entry = OrderedEntry {
                    genesis: heads.genesis,
                    index: heads
                        .ordered_index
                        .checked_add(1)
                        .ok_or(LocalJournalDriverError::InvalidResult)?,
                    parent: heads.ordered_head,
                    merge_frontier: heads.merge_frontier,
                    merge_seal: None,
                    input,
                };
                let position = ReplayPosition::Ordered {
                    id: entry.id(),
                    index: entry.index,
                    merge_frontier: entry.merge_frontier,
                    merge_seal: None,
                };
                let publication = self.core.publish_ordered(&entry)?;
                let (position, executions, _) =
                    Self::authoritative_publication_position(input_id, position, publication)?;
                Ok((position, executions, None))
            }
            InvocationScope::Local => {
                let input_id = input.id();
                let heads = self.core.materialization.heads();
                let entry = LocalEntry {
                    genesis: heads.genesis,
                    node: heads.node,
                    revision: heads
                        .local_revision
                        .checked_add(1)
                        .ok_or(LocalJournalDriverError::InvalidResult)?,
                    parent: heads.local_head,
                    ordered_base: self.core.materialization.ordered_base(),
                    merge_frontier: heads.merge_frontier,
                    input,
                };
                let position = ReplayPosition::Local {
                    id: entry.id(),
                    node: entry.node,
                    revision: entry.revision,
                    ordered_base: entry.ordered_base,
                    merge_frontier: entry.merge_frontier,
                };
                let publication = self.core.publish_local(&entry)?;
                let (position, executions, _) =
                    Self::authoritative_publication_position(input_id, position, publication)?;
                Ok((position, executions, None))
            }
            InvocationScope::Merge => {
                let input_id = input.id();
                let mut event = self.merge_event(input.clone())?;
                let mut position = ReplayPosition::Merge {
                    id: event.id(),
                    causal_height: event.causal_height,
                    ordered_base: event.ordered_base,
                };
                let publication = match self.core.publish_merge(&event) {
                    Err(LocalJournalDriverError::Replay(ReplayError::ReplayLimit)) => {
                        event = self.merge_event(input)?;
                        position = ReplayPosition::Merge {
                            id: event.id(),
                            causal_height: event.causal_height,
                            ordered_base: event.ordered_base,
                        };
                        self.core.publish_merge(&event)?
                    }
                    result => result?,
                };
                let (position, executions, already_committed) =
                    Self::authoritative_publication_position(input_id, position, publication)?;
                if !executions.is_empty() {
                    return Err(LocalJournalDriverError::InvalidResult);
                }
                let ReplayPosition::Merge { id, .. } = position else {
                    return Err(LocalJournalDriverError::InvalidResult);
                };
                let frontier = if already_committed {
                    MergeFrontier {
                        genesis: self.core.materialization.heads().genesis,
                        events: vec![id],
                    }
                    .id()
                } else {
                    self.core.materialization.merge_frontier()
                };
                let pending = PendingMergeReceipt {
                    event: id,
                    frontier,
                    input: event.input.clone(),
                    position,
                };
                Ok((position, executions, Some(pending)))
            }
        }
    }

    fn check_execution_results(
        input: &ReplayInput,
        executions: &[ReplayExecutionResult],
    ) -> Result<(), LocalJournalDriverError> {
        if executions.iter().any(|execution| {
            !execution.products().is_empty()
                || execution.input() != input.id()
                || matches!(execution.outcome(), ReplayStepOutcome::DivergentInvocation)
                    && execution.result().is_some()
        }) {
            return Err(LocalJournalDriverError::InvalidResult);
        }
        Ok(())
    }

    /// Execute or recover one invocation. The source Merge publication never
    /// exposes its provisional guest result; it returns only a pending
    /// journal receipt until [`Self::finalize_merge`] commits the frontier.
    pub(crate) fn invoke(
        &mut self,
        invocation: ActorInvocation,
        authority: ActorInvocationReceipt,
    ) -> Result<LocalInvocationResult, LocalJournalDriverError> {
        let config = self.trusted_current_config()?;
        invocation
            .validate()
            .map_err(|_| LocalReplayExecutorError::InvalidRequest)?;
        authority
            .validate_for(
                &config.authority,
                config.identity.space,
                config.identity.agent,
                &invocation,
            )
            .map_err(|_| LocalReplayExecutorError::InvalidAuthority)?;
        let observed_slot = self
            .core
            .executor
            .trust
            .current_logical_slot()
            .ok_or(LocalReplayExecutorError::TrustUnavailable)?;
        let input = ReplayInput {
            runtime: self.core.materialization.runtime().clone(),
            operation: ReplayOperation::Invoke {
                invocation,
                authority,
                observed_slot,
            },
        };
        if let Some(existing) = self.core.existing_merge_recovery(&input)? {
            return Ok(match existing {
                ExistingMergeRecovery::Pending(pending) => LocalInvocationResult::Pending(pending),
                ExistingMergeRecovery::Acknowledged => LocalInvocationResult::Acknowledged,
            });
        }
        let before = self.core.materialization.clone();
        let (position, executions, pending) = match self.publish_invocation_input(input.clone()) {
            Ok(published) => published,
            Err(LocalJournalDriverError::Replay(ReplayError::UncommittedInvocation(error))) => {
                let after = &self.core.materialization;
                if (after != &before && !Self::is_checkpoint_only_delta(&before, after))
                    || self.core.store.heads()? != Some(after.heads().clone())
                {
                    return Err(LocalJournalDriverError::InvalidResult);
                }
                return Ok(LocalInvocationResult::Final(Err(error)));
            }
            Err(error) => return Err(error),
        };
        Self::check_execution_results(&input, &executions)?;
        let recovered = self.core.recover(&input, position)?;
        self.map_invocation_recovery(recovered, pending, &executions)
    }

    fn map_invocation_recovery(
        &self,
        recovered: ReplayInvocationRecovery,
        pending: Option<PendingMergeReceipt>,
        executions: &[ReplayExecutionResult],
    ) -> Result<LocalInvocationResult, LocalJournalDriverError> {
        match recovered {
            ReplayInvocationRecovery::Retained(result) => {
                if executions
                    .iter()
                    .filter_map(ReplayExecutionResult::result)
                    .any(|direct| direct != &result)
                {
                    return Err(LocalJournalDriverError::InvalidResult);
                }
                Ok(LocalInvocationResult::Final(result))
            }
            ReplayInvocationRecovery::Pending => pending
                .map(LocalInvocationResult::Pending)
                .ok_or(LocalJournalDriverError::InvalidResult),
            ReplayInvocationRecovery::Divergent => Ok(LocalInvocationResult::Final(Err(
                ActorExecutionError::DivergentInvocation,
            ))),
            ReplayInvocationRecovery::Acknowledged => Ok(LocalInvocationResult::Acknowledged),
            ReplayInvocationRecovery::NotCommitted => Err(LocalJournalDriverError::InvalidResult),
        }
    }

    /// Recover a response from current authenticated ownership without
    /// executing runtime code. The complete input and exact committed
    /// position are the suffix-scoped lookup capability. Live config and
    /// package trust plus the invocation receipt are revalidated before that
    /// capability can disclose status or result bytes.
    pub(crate) fn recover_committed_invocation(
        &mut self,
        input: &ReplayInput,
        position: ReplayPosition,
    ) -> Result<LocalInvocationResult, LocalJournalDriverError> {
        let config = self.trusted_current_config()?;
        Self::validate_invocation_capability(&config, input)?;
        let pending = match position {
            ReplayPosition::Merge { id, .. } => Some(PendingMergeReceipt {
                event: id,
                frontier: MergeFrontier {
                    genesis: self.core.materialization.heads().genesis,
                    events: vec![id],
                }
                .id(),
                input: input.clone(),
                position,
            }),
            ReplayPosition::Genesis
            | ReplayPosition::Ordered { .. }
            | ReplayPosition::Local { .. } => None,
        };
        let recovered = self.core.recover(input, position)?;
        self.map_invocation_recovery(recovered, pending, &[])
    }

    pub(crate) fn acknowledge_invocation(
        &mut self,
        invocation: ActorInvocation,
        authority: ActorInvocationReceipt,
    ) -> Result<LocalAcknowledgementResult, LocalJournalDriverError> {
        let config = self.trusted_current_config()?;
        invocation
            .validate()
            .map_err(|_| LocalReplayExecutorError::InvalidRequest)?;
        authority
            .validate_for(
                &config.authority,
                config.identity.space,
                config.identity.agent,
                &invocation,
            )
            .map_err(|_| LocalReplayExecutorError::InvalidAuthority)?;
        let input = ReplayInput {
            runtime: self.core.materialization.runtime().clone(),
            operation: ReplayOperation::Acknowledge {
                invocation,
                authority,
            },
        };
        if let Some(existing) = self.core.existing_merge_recovery(&input)? {
            return Ok(match existing {
                ExistingMergeRecovery::Pending(pending) => {
                    LocalAcknowledgementResult::Pending(pending)
                }
                ExistingMergeRecovery::Acknowledged => LocalAcknowledgementResult::Acknowledged,
            });
        }
        let (position, executions, pending) = self.publish_invocation_input(input.clone())?;
        Self::check_execution_results(&input, &executions)?;
        Self::map_acknowledgement_recovery(self.core.recover(&input, position)?, pending)
    }

    fn map_acknowledgement_recovery(
        recovered: ReplayInvocationRecovery,
        pending: Option<PendingMergeReceipt>,
    ) -> Result<LocalAcknowledgementResult, LocalJournalDriverError> {
        match recovered {
            ReplayInvocationRecovery::Acknowledged => Ok(LocalAcknowledgementResult::Acknowledged),
            ReplayInvocationRecovery::Pending => pending
                .map(LocalAcknowledgementResult::Pending)
                .ok_or(LocalJournalDriverError::InvalidResult),
            ReplayInvocationRecovery::Divergent => Ok(LocalAcknowledgementResult::Divergent),
            _ => Err(LocalJournalDriverError::InvalidResult),
        }
    }

    fn valid_directory_page(
        after: Option<crate::service::ActorId>,
        limit: usize,
        max_actors: usize,
        page: &ActorDirectoryPage,
    ) -> bool {
        page.entries.len() <= limit
            && page.entries.len() <= max_actors
            && !page
                .entries
                .windows(2)
                .any(|pair| pair[0].entry.actor >= pair[1].entry.actor)
            && after.is_none_or(|cursor| {
                page.entries
                    .first()
                    .is_none_or(|record| record.entry.actor > cursor)
            })
            && match page.next {
                Some(next) => {
                    page.entries.len() == limit
                        && page
                            .entries
                            .last()
                            .is_some_and(|record| record.entry.actor == next)
                        && after.is_none_or(|cursor| next > cursor)
                }
                None => true,
            }
            && page
                .entries
                .iter()
                .all(|record| record.incarnation != Hash::ZERO)
    }

    /// Read-only Standard-runtime directory inspection. Any byte change in
    /// any state component is a protocol violation and is never published.
    pub(crate) fn inspect(
        &self,
        after: Option<crate::service::ActorId>,
        limit: u16,
    ) -> Result<ActorDirectoryPage, LocalJournalDriverError> {
        let config = self.trusted_current_config()?;
        let runtime = self
            .core
            .executor
            .runtime_package(&config, self.core.materialization.runtime())?;
        let request = LifecycleRequest::Inspect { after, limit };
        let decoded = decode_standard_runtime_state(self.core.materialization.state())
            .map_err(|_| LocalJournalDriverError::InvalidResult)?;
        let mut expected = StandardAgentRuntime::restore(decoded)
            .map_err(|_| LocalJournalDriverError::InvalidResult)?;
        let expected_result = expected.apply(request.clone());
        let returned: RuntimeReturn = self.core.executor.execute_wire(
            &runtime.pvm,
            self.core.executor.management_gas,
            &RuntimeCall {
                state: self.core.materialization.state().clone(),
                request,
            }
            .encode(),
        )?;
        if returned.state != *self.core.materialization.state()
            || returned.result != expected_result
        {
            return Err(LocalJournalDriverError::InvalidResult);
        }
        match returned.result {
            Ok(LifecycleReply::Directory(page))
                if Self::valid_directory_page(
                    after,
                    limit as usize,
                    config.capabilities.max_actors as usize,
                    &page,
                ) =>
            {
                Ok(page)
            }
            Ok(_) => Err(LocalJournalDriverError::InvalidResult),
            Err(error) => Err(LocalJournalDriverError::Lifecycle(error)),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    use super::super::authority::{
        ActorInvocationClaim, AgentAuthorityBinding, AgentAuthorityClaim,
    };
    use super::super::execution::ActorInvocationAuth;
    use super::super::journal_store::{
        AgentJournalGarbageCollection, GcLimits, MemoryAgentJournalStore,
    };
    use super::super::wire::encode_standard_runtime_state;
    use super::super::{ActorEntry, InstallActor, LaneSet, MethodMode, RuntimeRequirements};
    use crate::service::{
        ActorId, CapabilityId, CredentialId, DeploymentId, InvocationId, ProgramId, SpaceId,
    };
    use ed25519_dalek::{Signer as _, SigningKey};
    use std::sync::Mutex;

    struct StaticTrust {
        slot: Option<u64>,
        authority: Option<AgentAuthorityBinding>,
        trust_packages: bool,
    }

    impl AgentTrustProvider for StaticTrust {
        fn current_logical_slot(&self) -> Option<u64> {
            self.slot
        }

        fn authority_for_space(&self, _space: SpaceId) -> Option<AgentAuthorityBinding> {
            self.authority.clone()
        }

        fn verify_package(&self, _agent: &AgentConfig, _package: &Package) -> bool {
            self.trust_packages
        }
    }

    struct MutableTrust {
        slot: Option<u64>,
        authority: Mutex<Option<AgentAuthorityBinding>>,
    }

    impl AgentTrustProvider for MutableTrust {
        fn current_logical_slot(&self) -> Option<u64> {
            self.slot
        }

        fn authority_for_space(&self, _space: SpaceId) -> Option<AgentAuthorityBinding> {
            self.authority.lock().unwrap().clone()
        }

        fn verify_package(&self, _agent: &AgentConfig, _package: &Package) -> bool {
            true
        }
    }

    struct StaticMerge(NodeId);

    impl LocalMergeAuthenticator for StaticMerge {
        fn node(&self) -> NodeId {
            self.0
        }

        fn sign(&self, _message: Hash) -> Option<Vec<u8>> {
            Some(vec![0x6b; super::super::authority::ED25519_SIGNATURE_BYTES])
        }

        fn verify(&self, event: &MergeEvent) -> bool {
            event.author == self.0
        }
    }

    #[derive(Default)]
    struct ExactTestExecutor {
        executions: usize,
        refusal: Option<ActorExecutionError>,
    }

    impl ReplayExecutor for ExactTestExecutor {
        type Error = LocalReplayExecutorError;

        fn verify_merge_event(&mut self, _event: &MergeEvent) -> Result<bool, Self::Error> {
            Ok(true)
        }

        fn authenticate(
            &mut self,
            _input: &ReplayInput,
            _before: &RuntimeState,
            _position: ReplayPosition,
        ) -> Result<(), Self::Error> {
            Ok(())
        }

        fn execute(
            &mut self,
            input: &ReplayInput,
            before: &RuntimeState,
            _position: ReplayPosition,
        ) -> Result<ReplayTransition, Self::Error> {
            self.executions += 1;
            let state = decode_standard_runtime_state(before)
                .map_err(|_| LocalReplayExecutorError::InvalidState)?;
            let mut runtime = StandardAgentRuntime::restore(state)
                .map_err(|_| LocalReplayExecutorError::InvalidState)?;
            match &input.operation {
                ReplayOperation::Management { request } => {
                    let applied = runtime.apply(request.clone()).is_ok();
                    Ok(ReplayTransition {
                        state: encode_standard_runtime_state(&runtime.snapshot()),
                        disposition: if applied {
                            ReplayDisposition::Applied
                        } else {
                            ReplayDisposition::Rejected
                        },
                        result: None,
                        next_runtime: input.runtime.clone(),
                        products: ReplayProducts::default(),
                    })
                }
                ReplayOperation::Invoke {
                    invocation,
                    observed_slot,
                    ..
                } => {
                    if let Some(error) = self.refusal.take() {
                        return Ok(ReplayTransition {
                            state: before.clone(),
                            disposition: ReplayDisposition::Rejected,
                            result: Some(Err(error)),
                            next_runtime: input.runtime.clone(),
                            products: ReplayProducts::default(),
                        });
                    }
                    runtime
                        .commit_exact_outcome_clock(invocation, *observed_slot)
                        .map_err(|_| LocalReplayExecutorError::InvalidState)?;
                    Ok(ReplayTransition {
                        state: encode_standard_runtime_state(&runtime.snapshot()),
                        disposition: ReplayDisposition::Rejected,
                        result: Some(Err(ActorExecutionError::NotFound)),
                        next_runtime: input.runtime.clone(),
                        products: ReplayProducts::default(),
                    })
                }
                ReplayOperation::Acknowledge { .. } | ReplayOperation::SealMerge => {
                    Err(LocalReplayExecutorError::InvalidRequest)
                }
            }
        }
    }

    fn initialized_core() -> LocalJournalCore<MemoryAgentJournalStore, ExactTestExecutor> {
        let sealed = super::super::replay::tests::admitted_genesis(0xe1);
        let node = sealed.replica().node;
        let mut store =
            MemoryAgentJournalStore::new(sealed.genesis().runtime().agent, node).unwrap();
        assert_eq!(sealed.artifacts().artifacts.len(), 1);
        let runtime_bytes = b"replay-runtime-package";
        let runtime_reference = &sealed.artifacts().artifacts[0];
        assert!(runtime_reference.matches(runtime_bytes));
        store
            .put_blob(
                JournalBlobClass::CatalogArtifact,
                runtime_reference,
                runtime_bytes,
            )
            .unwrap();
        store.initialize(&sealed).unwrap();
        LocalJournalCore::open(store, ExactTestExecutor::default()).unwrap()
    }

    fn current_test_config(materialization: &ReplayMaterialization) -> AgentConfig {
        decode_standard_runtime_state(materialization.state())
            .unwrap()
            .config
            .unwrap()
    }

    fn admitted_authority_key() -> SigningKey {
        // `replay::tests::admitted_genesis` uses this fixed authority key.
        SigningKey::from_bytes(&[0x90; 32])
    }

    fn lifecycle_receipt(
        config: &AgentConfig,
        request: &LifecycleRequest,
        sequence: u64,
    ) -> AgentAuthorityReceipt {
        let mut credential = [0u8; 32];
        credential[..8].copy_from_slice(&sequence.to_le_bytes());
        let claim = AgentAuthorityClaim {
            authority: config.authority.clone(),
            space: config.identity.space,
            agent: config.identity.agent,
            principal: config.identity.owner,
            credential: CredentialId(credential),
            capability: CapabilityId::named(request.required_capability().unwrap()),
            operation: request.commitment(),
            sequence,
            valid_from: 10,
            valid_until: 1_000,
        };
        let signature = admitted_authority_key()
            .sign(&claim.signing_message().0)
            .to_bytes()
            .to_vec();
        AgentAuthorityReceipt { claim, signature }
    }

    fn authorized_at(
        config: &AgentConfig,
        request: LifecycleRequest,
        sequence: u64,
        slot: u64,
    ) -> LifecycleRequest {
        let receipt = lifecycle_receipt(config, &request, sequence);
        seal_lifecycle_request(
            &StaticTrust {
                slot: Some(slot),
                authority: Some(config.authority.clone()),
                trust_packages: true,
            },
            receipt,
            request,
        )
        .unwrap()
    }

    fn standard_test_driver() -> LocalJournalAgentDriver<MemoryAgentJournalStore> {
        let LocalJournalCore {
            store,
            materialization,
            ..
        } = initialized_core();
        let config = current_test_config(&materialization);
        let node = materialization.heads().node;
        let resolver = store.catalog_blob_resolver().unwrap();
        let executor = StandardLocalReplayExecutor::new(
            resolver,
            Arc::new(StaticTrust {
                slot: Some(20),
                authority: Some(config.authority),
                trust_packages: true,
            }),
            Arc::new(StaticMerge(node)),
        );
        LocalJournalAgentDriver {
            core: LocalJournalCore {
                store,
                materialization,
                executor,
            },
        }
    }

    fn invocation_input(
        materialization: &ReplayMaterialization,
        mode: MethodMode,
        discriminator: u8,
    ) -> ReplayInput {
        let config = decode_standard_runtime_state(materialization.state())
            .unwrap()
            .config
            .unwrap();
        let invocation = ActorInvocation {
            invocation: InvocationId([discriminator; 32]),
            actor: ActorId([discriminator.wrapping_add(1); 32]),
            incarnation: Hash([discriminator.wrapping_add(2); 32]),
            deployment: DeploymentId([discriminator.wrapping_add(3); 32]),
            program: ProgramId([discriminator.wrapping_add(4); 32]),
            mode,
            auth: ActorInvocationAuth::anonymous(),
            message: vec![discriminator],
            availability: Vec::new(),
            gas: 100,
        };
        let authority = ActorInvocationReceipt {
            claim: ActorInvocationClaim {
                authority: config.authority,
                space: config.identity.space,
                agent: config.identity.agent,
                principal: None,
                credential: None,
                authorization: invocation.authorization_message(),
                auth: invocation.auth.clone(),
                valid_from: 1,
                valid_until: 100,
            },
            // ReplayInput canonicality checks the exact claim linkage and
            // signature shape. ExactTestExecutor is the explicit test trust
            // boundary and deliberately accepts this fixed signature.
            signature: vec![0x5a; super::super::authority::ED25519_SIGNATURE_BYTES],
        };
        ReplayInput {
            runtime: materialization.runtime().clone(),
            operation: ReplayOperation::Invoke {
                invocation,
                authority,
                observed_slot: 10,
            },
        }
    }

    fn local_entry(materialization: &ReplayMaterialization, input: ReplayInput) -> LocalEntry {
        let heads = materialization.heads();
        LocalEntry {
            genesis: heads.genesis,
            node: heads.node,
            revision: heads.local_revision + 1,
            parent: heads.local_head,
            ordered_base: materialization.ordered_base(),
            merge_frontier: materialization.merge_frontier(),
            input,
        }
    }

    fn persist_test_merge_seal(
        core: &mut LocalJournalCore<MemoryAgentJournalStore, ExactTestExecutor>,
    ) -> super::super::journal::MergeSealId {
        let state = &core.materialization.state().merge;
        let reference = BlobRef::of_bytes(state);
        core.store
            .put_blob(JournalBlobClass::LaneState, &reference, state)
            .unwrap();
        let manifest = derive_lane_state::<core::convert::Infallible, core::convert::Infallible>(
            core.materialization.heads().genesis,
            core.materialization.runtime().clone(),
            PersistedLane::Merge,
            LaneCursor::Merge {
                frontier: core.materialization.merge_frontier(),
            },
            state,
        )
        .unwrap();
        core.store.put(&manifest).unwrap();
        let seal = MergeSeal {
            genesis: core.materialization.heads().genesis,
            frontier: core.materialization.merge_frontier(),
            ordered_base: core.materialization.ordered_base(),
            merge_state: manifest.id(),
        };
        core.store.put(&seal).unwrap();
        seal.id()
    }

    fn finalize_test_merge(
        core: &mut LocalJournalCore<MemoryAgentJournalStore, ExactTestExecutor>,
    ) -> LocalCorePublication {
        let merge_seal = persist_test_merge_seal(core);
        let heads = core.materialization.heads();
        let entry = OrderedEntry {
            genesis: heads.genesis,
            index: heads.ordered_index + 1,
            parent: heads.ordered_head,
            merge_frontier: heads.merge_frontier,
            merge_seal: Some(merge_seal),
            input: ReplayInput {
                runtime: heads.runtime.clone(),
                operation: ReplayOperation::SealMerge,
            },
        };
        core.publish_ordered(&entry).unwrap()
    }

    fn acknowledgement_for(
        materialization: &ReplayMaterialization,
        input: &ReplayInput,
        message_byte: u8,
    ) -> ReplayInput {
        let ReplayOperation::Invoke { invocation, .. } = &input.operation else {
            panic!("acknowledgement helper requires an invocation")
        };
        let mut invocation = invocation.clone();
        invocation.message = vec![message_byte];
        let config = current_test_config(materialization);
        assert_eq!(input.runtime.agent, config.identity.agent);
        let authority = ActorInvocationReceipt {
            claim: ActorInvocationClaim {
                authority: config.authority,
                space: config.identity.space,
                agent: config.identity.agent,
                principal: None,
                credential: None,
                authorization: invocation.authorization_message(),
                auth: invocation.auth.clone(),
                valid_from: 1,
                valid_until: 100,
            },
            signature: vec![0x5a; super::super::authority::ED25519_SIGNATURE_BYTES],
        };
        ReplayInput {
            runtime: input.runtime.clone(),
            operation: ReplayOperation::Acknowledge {
                invocation,
                authority,
            },
        }
    }

    #[derive(Clone)]
    enum TestPublication {
        Ordered(OrderedEntry),
        Local(LocalEntry),
        Merge(MergeEvent),
    }

    impl TestPublication {
        fn for_input(
            core: &LocalJournalCore<MemoryAgentJournalStore, ExactTestExecutor>,
            input: ReplayInput,
        ) -> Self {
            let heads = core.materialization.heads();
            let scope = match &input.operation {
                ReplayOperation::Invoke { invocation, .. }
                | ReplayOperation::Acknowledge { invocation, .. } => {
                    invocation.mode.invocation_scope()
                }
                _ => panic!("test publication requires an invocation operation"),
            };
            match scope {
                InvocationScope::Ordered => Self::Ordered(OrderedEntry {
                    genesis: heads.genesis,
                    index: heads.ordered_index + 1,
                    parent: heads.ordered_head,
                    merge_frontier: heads.merge_frontier,
                    merge_seal: None,
                    input,
                }),
                InvocationScope::Local => Self::Local(local_entry(&core.materialization, input)),
                InvocationScope::Merge => {
                    let frontier = core
                        .store
                        .get::<MergeFrontier>(core.materialization.merge_frontier())
                        .unwrap()
                        .unwrap();
                    let causal_height = frontier
                        .events
                        .iter()
                        .map(|id| {
                            core.store
                                .get::<MergeEvent>(*id)
                                .unwrap()
                                .unwrap()
                                .causal_height
                        })
                        .max()
                        .unwrap_or(0)
                        + 1;
                    Self::Merge(MergeEvent {
                        genesis: heads.genesis,
                        author: heads.node,
                        ordered_base: core.materialization.ordered_base(),
                        causal_height,
                        parents: frontier.events,
                        input,
                        signature: vec![0x6b; super::super::authority::ED25519_SIGNATURE_BYTES],
                    })
                }
            }
        }

        fn position(&self) -> ReplayPosition {
            match self {
                Self::Ordered(entry) => ReplayPosition::Ordered {
                    id: entry.id(),
                    index: entry.index,
                    merge_frontier: entry.merge_frontier,
                    merge_seal: entry.merge_seal,
                },
                Self::Local(entry) => ReplayPosition::Local {
                    id: entry.id(),
                    node: entry.node,
                    revision: entry.revision,
                    ordered_base: entry.ordered_base,
                    merge_frontier: entry.merge_frontier,
                },
                Self::Merge(event) => ReplayPosition::Merge {
                    id: event.id(),
                    causal_height: event.causal_height,
                    ordered_base: event.ordered_base,
                },
            }
        }

        fn publish(
            &self,
            core: &mut LocalJournalCore<MemoryAgentJournalStore, ExactTestExecutor>,
        ) -> Result<LocalCorePublication, LocalJournalDriverError> {
            match self {
                Self::Ordered(entry) => core.publish_ordered(entry),
                Self::Local(entry) => core.publish_local(entry),
                Self::Merge(event) => core.publish_merge(event),
            }
        }
    }

    #[test]
    fn create_preflight_rejects_profile_trust_binding_and_package_before_store_writes() {
        let sealed = super::super::replay::tests::admitted_genesis(0xe4);
        let node = sealed.replica().node;
        let store = MemoryAgentJournalStore::new(sealed.genesis().runtime().agent, node).unwrap();
        let decoded = decode_standard_runtime_state(sealed.post_create()).unwrap();
        let config = decoded.config.as_ref().unwrap();
        let catalog = [RuntimeBlob {
            reference: sealed.artifacts().artifacts[0].clone(),
            bytes: b"replay-runtime-package".to_vec(),
        }];
        let trusted: Arc<dyn AgentTrustProvider> = Arc::new(StaticTrust {
            slot: Some(20),
            authority: Some(config.authority.clone()),
            trust_packages: true,
        });
        let merge: Arc<dyn LocalMergeAuthenticator> = Arc::new(StaticMerge(node));

        assert!(matches!(
            LocalJournalAgentDriver::<MemoryAgentJournalStore>::preflight_create(
                &sealed,
                &catalog,
                &trusted,
                &merge,
            ),
            Err(LocalJournalDriverError::Executor(
                LocalReplayExecutorError::InvalidArtifact(reference)
            )) if reference == catalog[0].reference
        ));

        let resolver = SuppliedCatalogBlobResolver::from_catalog(&catalog).unwrap();
        let mut shared = decoded.clone();
        shared.config.as_mut().unwrap().identity.profile = AgentProfile::Shared;
        assert_eq!(
            LocalJournalAgentDriver::<MemoryAgentJournalStore>::validate_create_state(
                &encode_standard_runtime_state(&shared),
                sealed.genesis().runtime(),
                sealed.replica(),
                resolver.clone(),
                &trusted,
                &merge,
            ),
            Err(LocalJournalDriverError::Executor(
                LocalReplayExecutorError::InvalidProfile
            ))
        );

        let rejecting_trust: Arc<dyn AgentTrustProvider> = Arc::new(StaticTrust {
            slot: Some(20),
            authority: None,
            trust_packages: false,
        });
        assert_eq!(
            LocalJournalAgentDriver::<MemoryAgentJournalStore>::validate_create_state(
                sealed.post_create(),
                sealed.genesis().runtime(),
                sealed.replica(),
                resolver.clone(),
                &rejecting_trust,
                &merge,
            ),
            Err(LocalJournalDriverError::Executor(
                LocalReplayExecutorError::TrustUnavailable
            ))
        );

        let mut wrong_binding = sealed.genesis().runtime().clone();
        wrong_binding.runtime_abi = Hash([0xee; 32]);
        assert_eq!(
            LocalJournalAgentDriver::<MemoryAgentJournalStore>::validate_create_state(
                sealed.post_create(),
                &wrong_binding,
                sealed.replica(),
                resolver,
                &trusted,
                &merge,
            ),
            Err(LocalJournalDriverError::Executor(
                LocalReplayExecutorError::InvalidState
            ))
        );

        assert_eq!(store.genesis().unwrap(), None);
        assert_eq!(store.heads().unwrap(), None);
        assert_eq!(
            store
                .load_blob(JournalBlobClass::CatalogArtifact, &catalog[0].reference)
                .unwrap(),
            None,
            "every semantic create failure precedes catalog staging"
        );
    }

    #[test]
    fn lifecycle_admission_seals_only_the_trusted_slot_and_ratchets_that_h() {
        let core = initialized_core();
        let decoded = decode_standard_runtime_state(core.materialization.state()).unwrap();
        let config = decoded.config.clone().unwrap();
        let inner = LifecycleRequest::Suspend {
            actor: ActorId([0xc1; 32]),
            expected_deployment: DeploymentId([0xc2; 32]),
        };
        let receipt = lifecycle_receipt(&config, &inner, 2);
        let trust = StaticTrust {
            slot: Some(77),
            authority: Some(config.authority.clone()),
            trust_packages: true,
        };
        let sealed = seal_lifecycle_request(&trust, receipt.clone(), inner.clone()).unwrap();
        assert!(matches!(
            &sealed,
            LifecycleRequest::Authorized { admission, request }
                if admission.observed_slot == 77 && request.as_ref() == &inner
        ));

        let mut runtime = StandardAgentRuntime::restore(decoded).unwrap();
        assert_eq!(
            runtime.apply(sealed),
            Err(LifecycleError::NotFound),
            "a fresh deterministic refusal still consumes authority H"
        );
        assert_eq!(runtime.snapshot().authority_slot_high_water, Some(77));

        let forged = LifecycleRequest::Authorized {
            admission: LifecycleAuthorityAdmission {
                receipt,
                observed_slot: 999,
            },
            request: Box::new(inner.clone()),
        };
        let outer_receipt = lifecycle_receipt(&config, &inner, 3);
        assert_eq!(
            seal_lifecycle_request(&trust, outer_receipt, forged),
            Err(LocalReplayExecutorError::InvalidRequest),
            "an unsigned caller slot cannot enter through the inner-request API"
        );
    }

    #[test]
    fn evicted_lifecycle_retry_is_uncommitted_and_cannot_finalize_pending_merge() {
        let mut runtime = {
            let core = initialized_core();
            StandardAgentRuntime::restore(
                decode_standard_runtime_state(core.materialization.state()).unwrap(),
            )
            .unwrap()
        };
        let config = runtime.config().unwrap().clone();
        let inner = LifecycleRequest::Suspend {
            actor: ActorId([0xd1; 32]),
            expected_deployment: DeploymentId([0xd2; 32]),
        };
        let mut evicted = None;
        for sequence in 2..=258 {
            let request = authorized_at(&config, inner.clone(), sequence, 20);
            if sequence == 2 {
                evicted = Some(request.clone());
            }
            assert_eq!(runtime.apply(request), Err(LifecycleError::NotFound));
        }
        let snapshot = runtime.snapshot();
        assert_eq!(
            snapshot.authority_dispositions.len(),
            super::super::standard::MAX_AUTHORITY_DISPOSITIONS
        );
        assert_eq!(snapshot.authority_dispositions[0].sequence, 3);
        assert_eq!(snapshot.authority_sequence_high_water, Some(258));
        let encoded = encode_standard_runtime_state(&snapshot);
        let evicted = evicted.unwrap();

        let mut core = initialized_core();
        let merge_input = invocation_input(&core.materialization, MethodMode::Merge, 0xd3);
        let merge_publication = TestPublication::for_input(&core, merge_input.clone());
        let merge_position = merge_publication.position();
        assert!(merge_publication.publish(&mut core).unwrap().is_empty());
        assert_eq!(
            core.recover(&merge_input, merge_position).unwrap(),
            ReplayInvocationRecovery::Pending
        );
        let durable_heads = core.store.heads().unwrap().unwrap();
        let cached = core.materialization.clone();

        for _ in 0..2 {
            assert_eq!(
                uncommitted_lifecycle_result(&encoded, &evicted).unwrap(),
                Some(Err(LifecycleError::AuthoritySequenceRegressed))
            );
            // This is the exact preflight branch used by `lifecycle`; it
            // returns before catalog staging, Merge sealing, or publication.
            assert_eq!(core.store.heads().unwrap(), Some(durable_heads.clone()));
            assert_eq!(core.materialization, cached);
            assert_eq!(
                core.recover(&merge_input, merge_position).unwrap(),
                ReplayInvocationRecovery::Pending
            );
        }
    }

    #[test]
    fn retained_success_retry_needs_no_historical_catalog_and_only_advances_slot_h() {
        let core = initialized_core();
        let mut runtime = StandardAgentRuntime::restore(
            decode_standard_runtime_state(core.materialization.state()).unwrap(),
        )
        .unwrap();
        let config = runtime.config().unwrap().clone();
        let package = BlobRef::of_bytes(b"historical-package");
        let schema = BlobRef::of_bytes(b"historical-schema");
        let policies = BlobRef::of_bytes(b"historical-policies");
        let deployment = DeploymentId([0xde; 32]);
        let actor = ActorId::top_level(config.identity.agent, "historical-actor");
        let requirements = RuntimeRequirements {
            lanes: LaneSet::NONE,
            scheduling: false,
            proofs: false,
        };
        let install = LifecycleRequest::Install(InstallActor {
            entry: ActorEntry {
                actor,
                name: "historical-actor".into(),
                parent: None,
                deployment,
                program: ProgramId([0xdf; 32]),
                package: package.clone(),
                agent_schema: schema.clone(),
                role_policies: policies.clone(),
                state_layout: Hash([0xe0; 32]),
                lanes: requirements.lanes,
                suspended: false,
            },
            producer: config.identity.runtime_producer,
            package,
            agent_schema: schema,
            role_policies: policies,
            state_layout: Hash([0xe0; 32]),
            contract: super::super::contract::ActorPackageContract::canonical(),
            requirements,
        });
        let original = authorized_at(&config, install.clone(), 2, 20);
        let installed = runtime.apply(original).unwrap();
        assert!(matches!(installed, LifecycleReply::Installed(_)));
        assert_eq!(
            runtime.apply(authorized_at(
                &config,
                LifecycleRequest::RemoveLeaf {
                    actor,
                    expected_deployment: deployment,
                },
                3,
                21,
            )),
            Ok(LifecycleReply::Removed(actor))
        );
        assert!(runtime.actor(actor).is_none());
        let state = encode_standard_runtime_state(&runtime.snapshot());

        let same_slot_retry = authorized_at(&config, install.clone(), 2, 21);
        assert_eq!(
            uncommitted_lifecycle_result(&state, &same_slot_retry).unwrap(),
            Some(Ok(installed.clone())),
            "an exact retained retry with no H change remains local"
        );

        let newer_slot_retry = authorized_at(&config, install, 2, 50);
        assert_eq!(
            retained_lifecycle_disposition(&state, &newer_slot_retry).unwrap(),
            Some(Ok(installed.clone())),
            "the disposition, not GC-prunable package bytes, authenticates retry"
        );
        assert_eq!(
            uncommitted_lifecycle_result(&state, &newer_slot_retry).unwrap(),
            None,
            "a newer trusted slot must still publish its H advancement"
        );
        let mut reopened =
            StandardAgentRuntime::restore(decode_standard_runtime_state(&state).unwrap()).unwrap();
        assert_eq!(reopened.apply(newer_slot_retry), Ok(installed));
        assert!(reopened.actor(actor).is_none(), "retry must not reinstall");
        assert_eq!(reopened.snapshot().authority_slot_high_water, Some(50));
    }

    #[test]
    fn divergent_acknowledgement_is_typed_and_exact_across_restart_for_every_scope() {
        for (mode, discriminator) in [
            (MethodMode::Linear, 0xe1),
            (MethodMode::Local, 0xe2),
            (MethodMode::Merge, 0xe3),
        ] {
            let mut core = initialized_core();
            let original = invocation_input(&core.materialization, mode, discriminator);
            let original_publication = TestPublication::for_input(&core, original.clone());
            original_publication.publish(&mut core).unwrap();

            let acknowledgement = acknowledgement_for(
                &core.materialization,
                &original,
                discriminator.wrapping_add(1),
            );
            let acknowledgement_publication =
                TestPublication::for_input(&core, acknowledgement.clone());
            let acknowledgement_position = acknowledgement_publication.position();
            let divergent = acknowledgement_publication.publish(&mut core).unwrap();
            assert!(divergent.len() <= 1);
            assert!(divergent.iter().all(|execution| {
                matches!(execution.outcome(), ReplayStepOutcome::DivergentInvocation)
                    && execution.result().is_none()
                    && execution.products().is_empty()
            }));
            assert_eq!(
                core.recover(&acknowledgement, acknowledgement_position)
                    .unwrap(),
                ReplayInvocationRecovery::Divergent
            );
            assert_eq!(
                LocalJournalAgentDriver::<MemoryAgentJournalStore>::map_acknowledgement_recovery(
                    ReplayInvocationRecovery::Divergent,
                    None,
                )
                .unwrap(),
                LocalAcknowledgementResult::Divergent
            );

            // Simulate loss of the acknowledgement response after its CAS.
            let LocalJournalCore { store, .. } = core;
            let mut reopened = LocalJournalCore::open(store, ExactTestExecutor::default()).unwrap();
            let executions_after_replay = reopened.executor.executions;
            let heads_after_commit = reopened.store.heads().unwrap().unwrap();
            assert!(
                acknowledgement_publication
                    .publish(&mut reopened)
                    .unwrap()
                    .is_empty()
            );
            assert_eq!(reopened.executor.executions, executions_after_replay);
            assert_eq!(reopened.store.heads().unwrap(), Some(heads_after_commit));
            assert_eq!(
                reopened
                    .recover(&acknowledgement, acknowledgement_position)
                    .unwrap(),
                ReplayInvocationRecovery::Divergent
            );
            assert_eq!(
                LocalJournalAgentDriver::<MemoryAgentJournalStore>::map_acknowledgement_recovery(
                    ReplayInvocationRecovery::Divergent,
                    None,
                )
                .unwrap(),
                LocalAcknowledgementResult::Divergent
            );
        }
    }

    #[test]
    fn exact_retry_uses_the_authenticated_committed_anchor_for_every_scope() {
        for (mode, discriminator) in [
            (MethodMode::Linear, 0xe8),
            (MethodMode::Local, 0xe9),
            (MethodMode::Merge, 0xea),
        ] {
            let mut core = initialized_core();
            let input = invocation_input(&core.materialization, mode, discriminator);
            let original = TestPublication::for_input(&core, input.clone());
            let exact_retry = original.clone();
            let committed_position = original.position();
            let first = original.publish(&mut core).unwrap();
            assert!(first.committed.is_none());

            let uncommitted_proposal = TestPublication::for_input(&core, input.clone()).position();
            assert_ne!(uncommitted_proposal, committed_position);
            let retried = exact_retry.publish(&mut core).unwrap();
            assert!(retried.executions.is_empty());
            assert_eq!(
                retried.committed.map(ReplayCommittedRecovery::position),
                Some(committed_position)
            );
            let (authoritative, executions, already_committed) = LocalJournalAgentDriver::<
                MemoryAgentJournalStore,
            >::authoritative_publication_position(
                input.id(),
                uncommitted_proposal,
                retried,
            )
            .unwrap();
            assert!(already_committed);
            assert!(executions.is_empty());
            assert_eq!(authoritative, committed_position);
            assert!(matches!(
                core.recover(&input, authoritative).unwrap(),
                ReplayInvocationRecovery::Retained(Err(ActorExecutionError::NotFound))
                    | ReplayInvocationRecovery::Pending
            ));
        }
    }

    #[test]
    fn pending_merge_invoke_and_ack_retries_recover_canonical_sources_after_reopen() {
        let mut core = initialized_core();
        let original = invocation_input(&core.materialization, MethodMode::Merge, 0xeb);
        let source = TestPublication::for_input(&core, original.clone());
        let source_position = source.position();
        let ReplayPosition::Merge {
            id: source_event, ..
        } = source_position
        else {
            unreachable!()
        };
        assert!(source.publish(&mut core).unwrap().is_empty());

        let LocalJournalCore { store, .. } = core;
        let mut reopened = LocalJournalCore::open(store, ExactTestExecutor::default()).unwrap();
        let mut retry = original.clone();
        let ReplayOperation::Invoke { observed_slot, .. } = &mut retry.operation else {
            unreachable!()
        };
        *observed_slot += 1;
        let alias = TestPublication::for_input(&reopened, retry.clone());
        let alias_id = match alias {
            TestPublication::Merge(ref event) => event.id(),
            TestPublication::Ordered(_) | TestPublication::Local(_) => unreachable!(),
        };
        assert_ne!(alias_id, source_event);
        let heads_before_retry = reopened.store.heads().unwrap().unwrap();
        let executions_before_retry = reopened.executor.executions;
        let ExistingMergeRecovery::Pending(pending) =
            reopened.existing_merge_recovery(&retry).unwrap().unwrap()
        else {
            panic!("pending invocation resolved as an acknowledged tombstone")
        };
        assert_eq!(pending.event, source_event);
        assert_eq!(pending.position, source_position);
        assert_eq!(pending.input, original);
        assert_eq!(
            reopened.recover(&pending.input, pending.position).unwrap(),
            ReplayInvocationRecovery::Pending
        );
        assert_eq!(reopened.store.heads().unwrap(), Some(heads_before_retry));
        assert_eq!(reopened.executor.executions, executions_before_retry);
        assert_eq!(reopened.store.get::<MergeEvent>(alias_id).unwrap(), None);

        let finalized = finalize_test_merge(&mut reopened);
        assert_eq!(
            finalized
                .executions
                .iter()
                .filter(|execution| execution.result().is_some())
                .count(),
            1
        );
        let acknowledgement = acknowledgement_for(&reopened.materialization, &original, 0xeb);
        let acknowledgement_source = TestPublication::for_input(&reopened, acknowledgement.clone());
        let acknowledgement_position = acknowledgement_source.position();
        let ReplayPosition::Merge {
            id: acknowledgement_event,
            ..
        } = acknowledgement_position
        else {
            unreachable!()
        };
        assert!(
            acknowledgement_source
                .publish(&mut reopened)
                .unwrap()
                .is_empty()
        );

        let LocalJournalCore { store, .. } = reopened;
        let mut reopened = LocalJournalCore::open(store, ExactTestExecutor::default()).unwrap();
        let acknowledgement_alias = TestPublication::for_input(&reopened, acknowledgement.clone());
        let acknowledgement_alias_id = match acknowledgement_alias {
            TestPublication::Merge(ref event) => event.id(),
            TestPublication::Ordered(_) | TestPublication::Local(_) => unreachable!(),
        };
        assert_ne!(acknowledgement_alias_id, acknowledgement_event);
        let heads_before_retry = reopened.store.heads().unwrap().unwrap();
        let executions_before_retry = reopened.executor.executions;
        let ExistingMergeRecovery::Pending(pending) = reopened
            .existing_merge_recovery(&acknowledgement)
            .unwrap()
            .unwrap()
        else {
            panic!("pending acknowledgement resolved as an acknowledged tombstone")
        };
        assert_eq!(pending.event, acknowledgement_event);
        assert_eq!(pending.position, acknowledgement_position);
        assert_eq!(pending.input, acknowledgement);
        assert_eq!(
            reopened.recover(&pending.input, pending.position).unwrap(),
            ReplayInvocationRecovery::Pending
        );
        assert_eq!(reopened.store.heads().unwrap(), Some(heads_before_retry));
        assert_eq!(reopened.executor.executions, executions_before_retry);
        assert_eq!(
            reopened
                .store
                .get::<MergeEvent>(acknowledgement_alias_id)
                .unwrap(),
            None
        );

        let old_pending_receipt = pending.clone();
        finalize_test_merge(&mut reopened);
        let advancing_input = invocation_input(&reopened.materialization, MethodMode::Merge, 0xec);
        assert!(
            TestPublication::for_input(&reopened, advancing_input)
                .publish(&mut reopened)
                .unwrap()
                .is_empty()
        );
        finalize_test_merge(&mut reopened);
        reopened.checkpoint().unwrap();
        let expected_heads = reopened.materialization.heads_id();
        let limits = GcLimits {
            max_index_nodes: 100_000,
            max_marked_objects: 100_000,
            max_marked_blobs: 100_000,
            max_scanned_files: 100_000,
            max_scanned_bytes: u64::MAX,
            max_unlinks_per_run: 100_000,
        };
        loop {
            let collected = reopened
                .store
                .collect_garbage(expected_heads, limits)
                .unwrap();
            if collected.complete {
                break;
            }
        }
        assert_eq!(
            reopened
                .store
                .get::<MergeEvent>(acknowledgement_event)
                .unwrap(),
            None,
            "the permanent tombstone does not retain the acknowledgement suffix anchor"
        );

        let LocalJournalCore { store, .. } = reopened;
        let mut reopened = LocalJournalCore::open(store, ExactTestExecutor::default()).unwrap();
        assert_eq!(
            reopened
                .recover(&old_pending_receipt.input, old_pending_receipt.position)
                .unwrap(),
            ReplayInvocationRecovery::NotCommitted,
            "the explicitly pending receipt fails closed after finalization and GC"
        );
        let heads_before_retry = reopened.store.heads().unwrap().unwrap();
        let executions_before_retry = reopened.executor.executions;
        assert_eq!(
            reopened.existing_merge_recovery(&acknowledgement).unwrap(),
            Some(ExistingMergeRecovery::Acknowledged)
        );
        assert_eq!(reopened.store.heads().unwrap(), Some(heads_before_retry));
        assert_eq!(reopened.executor.executions, executions_before_retry);
    }

    #[test]
    fn live_trust_change_blocks_pending_owner_shortcuts_without_disclosure() {
        let mut core = initialized_core();
        let input = invocation_input(&core.materialization, MethodMode::Merge, 0xed);
        let source = TestPublication::for_input(&core, input.clone());
        let source_position = source.position();
        assert!(source.publish(&mut core).unwrap().is_empty());
        let config = current_test_config(&core.materialization);
        let node = core.materialization.heads().node;
        let resolver = core.store.catalog_blob_resolver().unwrap();
        let mutable_trust = Arc::new(MutableTrust {
            slot: Some(20),
            authority: Mutex::new(Some(config.authority.clone())),
        });
        let trust: Arc<dyn AgentTrustProvider> = mutable_trust.clone();
        let executor =
            StandardLocalReplayExecutor::new(resolver, trust, Arc::new(StaticMerge(node)));
        let mut driver = LocalJournalAgentDriver {
            core: LocalJournalCore {
                store: core.store,
                materialization: core.materialization,
                executor,
            },
        };
        *mutable_trust.authority.lock().unwrap() = None;
        let recovery_input = input.clone();
        let ReplayOperation::Invoke {
            invocation,
            authority,
            ..
        } = input.operation
        else {
            unreachable!()
        };
        let acknowledgement_input = acknowledgement_for(
            &driver.core.materialization,
            &ReplayInput {
                runtime: driver.core.materialization.runtime().clone(),
                operation: ReplayOperation::Invoke {
                    invocation: invocation.clone(),
                    authority: authority.clone(),
                    observed_slot: 10,
                },
            },
            0xed,
        );
        let ReplayOperation::Acknowledge {
            invocation: acknowledged_invocation,
            authority: acknowledgement_authority,
        } = acknowledgement_input.operation
        else {
            unreachable!()
        };
        let heads_before = driver.core.store.heads().unwrap().unwrap();
        let merge_state = BlobRef::of_bytes(&driver.core.materialization.state().merge);
        let merge_blob_before = driver
            .core
            .store
            .load_blob(JournalBlobClass::LaneState, &merge_state)
            .unwrap();
        assert_eq!(
            driver.invoke(invocation, authority),
            Err(LocalJournalDriverError::Executor(
                LocalReplayExecutorError::TrustUnavailable
            ))
        );
        assert_eq!(
            driver.acknowledge_invocation(acknowledged_invocation, acknowledgement_authority),
            Err(LocalJournalDriverError::Executor(
                LocalReplayExecutorError::TrustUnavailable
            ))
        );
        assert_eq!(
            driver.recover_committed_invocation(&recovery_input, source_position),
            Err(LocalJournalDriverError::Executor(
                LocalReplayExecutorError::TrustUnavailable
            ))
        );
        assert_eq!(
            driver.finalize_merge(),
            Err(LocalJournalDriverError::Executor(
                LocalReplayExecutorError::TrustUnavailable
            ))
        );
        assert_eq!(
            driver.inspect(None, 1),
            Err(LocalJournalDriverError::Executor(
                LocalReplayExecutorError::TrustUnavailable
            ))
        );
        let lifecycle_request = LifecycleRequest::Suspend {
            actor: ActorId([0xee; 32]),
            expected_deployment: DeploymentId([0xef; 32]),
        };
        let lifecycle_receipt = lifecycle_receipt(&config, &lifecycle_request, 2);
        assert_eq!(
            driver.lifecycle(lifecycle_receipt, lifecycle_request, &[]),
            Err(LocalJournalDriverError::Executor(
                LocalReplayExecutorError::TrustUnavailable
            ))
        );
        assert_eq!(driver.core.store.heads().unwrap(), Some(heads_before));
        assert_eq!(
            driver
                .core
                .store
                .load_blob(JournalBlobClass::LaneState, &merge_state)
                .unwrap(),
            merge_blob_before
        );
    }

    #[test]
    fn invalid_actor_catalog_is_rejected_before_blob_or_head_publication() {
        let driver = standard_test_driver();
        let config = driver.current_config().unwrap();
        let package_blob = RuntimeBlob {
            reference: BlobRef::of_bytes(b"not-a-signed-package"),
            bytes: b"not-a-signed-package".to_vec(),
        };
        let schema_blob = RuntimeBlob {
            reference: BlobRef::of_bytes(b"not-an-agent-schema"),
            bytes: b"not-an-agent-schema".to_vec(),
        };
        let policies_blob = RuntimeBlob {
            reference: BlobRef::of_bytes(b"not-role-policies"),
            bytes: b"not-role-policies".to_vec(),
        };
        let requirements = RuntimeRequirements {
            lanes: LaneSet::NONE,
            scheduling: false,
            proofs: false,
        };
        let deployment = DeploymentId([0xf1; 32]);
        let program = ProgramId([0xf2; 32]);
        let state_layout = Hash([0xf3; 32]);
        let actor = ActorId::top_level(config.identity.agent, "catalog-admission");
        let install = InstallActor {
            entry: ActorEntry {
                actor,
                name: "catalog-admission".into(),
                parent: None,
                deployment,
                program,
                package: package_blob.reference.clone(),
                agent_schema: schema_blob.reference.clone(),
                role_policies: policies_blob.reference.clone(),
                state_layout,
                lanes: requirements.lanes,
                suspended: false,
            },
            producer: config.identity.runtime_producer,
            package: package_blob.reference.clone(),
            agent_schema: schema_blob.reference.clone(),
            role_policies: policies_blob.reference.clone(),
            state_layout,
            contract: super::super::contract::ActorPackageContract::canonical(),
            requirements,
        };
        let request = LifecycleRequest::Install(install);
        let receipt = lifecycle_receipt(&config, &request, 2);
        let authorized = seal_lifecycle_request(
            &StaticTrust {
                slot: Some(20),
                authority: Some(config.authority.clone()),
                trust_packages: true,
            },
            receipt,
            request,
        )
        .unwrap();
        let before_heads = driver.core.store.heads().unwrap().unwrap();
        let before_materialization = driver.core.materialization.clone();

        assert_eq!(
            driver.core.executor.validate_lifecycle_catalog(
                &config,
                &authorized,
                &[package_blob.clone(), schema_blob.clone()],
            ),
            Err(LocalReplayExecutorError::InvalidRequest),
            "a fresh catalog closure must be complete"
        );
        let extra_blob = RuntimeBlob {
            reference: BlobRef::of_bytes(b"unreferenced-extra"),
            bytes: b"unreferenced-extra".to_vec(),
        };
        assert_eq!(
            driver.core.executor.validate_lifecycle_catalog(
                &config,
                &authorized,
                &[
                    package_blob.clone(),
                    schema_blob.clone(),
                    policies_blob.clone(),
                    extra_blob.clone(),
                ],
            ),
            Err(LocalReplayExecutorError::InvalidRequest),
            "a fresh catalog closure must contain no unreferenced content"
        );

        assert!(matches!(
            driver.core.executor.validate_lifecycle_catalog(
                &config,
                &authorized,
                &[package_blob.clone(), schema_blob.clone(), policies_blob.clone()],
            ),
            Err(LocalReplayExecutorError::InvalidArtifact(reference))
                if reference == package_blob.reference
        ));
        assert_eq!(driver.core.store.heads().unwrap(), Some(before_heads));
        assert_eq!(driver.core.materialization, before_materialization);
        for blob in [&package_blob, &schema_blob, &policies_blob, &extra_blob] {
            assert_eq!(
                driver
                    .core
                    .store
                    .load_blob(JournalBlobClass::CatalogArtifact, &blob.reference)
                    .unwrap(),
                None,
                "semantic catalog rejection must precede staging"
            );
        }
    }

    #[test]
    fn consumed_lifecycle_refusal_does_not_stage_unreferenced_catalog() {
        let core = initialized_core();
        let config = current_test_config(&core.materialization);
        let request = authorized_at(
            &config,
            LifecycleRequest::Suspend {
                actor: ActorId([0xf7; 32]),
                expected_deployment: DeploymentId([0xf8; 32]),
            },
            2,
            20,
        );
        let preflight =
            preflight_lifecycle_transition(core.materialization.state(), &request).unwrap();
        assert_eq!(preflight.result, Err(LifecycleError::NotFound));
        assert!(!preflight.unchanged, "the authority disposition is durable");
        assert_eq!(
            retained_lifecycle_disposition(core.materialization.state(), &request).unwrap(),
            None
        );

        let irrelevant = RuntimeBlob {
            reference: BlobRef::of_bytes(b"must-not-be-staged-on-refusal"),
            bytes: b"must-not-be-staged-on-refusal".to_vec(),
        };
        assert!(preflight.result.is_err());
        assert_eq!(
            core.store
                .load_blob(JournalBlobClass::CatalogArtifact, &irrelevant.reference)
                .unwrap(),
            None,
            "the live lifecycle branch stages only when this preflight is successful"
        );
    }

    #[test]
    fn memory_result_loss_restart_and_exact_retry_do_not_reexecute() {
        let mut core = initialized_core();
        let input = invocation_input(&core.materialization, MethodMode::Local, 0x31);
        let entry = local_entry(&core.materialization, input.clone());
        let position = ReplayPosition::Local {
            id: entry.id(),
            node: entry.node,
            revision: entry.revision,
            ordered_base: entry.ordered_base,
            merge_frontier: entry.merge_frontier,
        };
        let lost = core.publish_local(&entry).unwrap();
        assert_eq!(lost.len(), 1);
        assert_eq!(lost[0].result(), Some(&Err(ActorExecutionError::NotFound)));
        assert!(lost[0].products().is_empty());

        let LocalJournalCore { store, .. } = core;
        let mut reopened = LocalJournalCore::open(store, ExactTestExecutor::default()).unwrap();
        let executions_after_replay = reopened.executor.executions;
        assert_eq!(
            reopened.recover(&input, position).unwrap(),
            ReplayInvocationRecovery::Retained(Err(ActorExecutionError::NotFound))
        );
        assert_eq!(reopened.executor.executions, executions_after_replay);

        let retry_executions = reopened.publish_local(&entry).unwrap();
        assert!(retry_executions.is_empty());
        assert_eq!(reopened.executor.executions, executions_after_replay);
        assert_eq!(
            reopened.recover(&input, position).unwrap(),
            ReplayInvocationRecovery::Retained(Err(ActorExecutionError::NotFound))
        );
        assert_eq!(reopened.executor.executions, executions_after_replay);
    }

    #[test]
    fn memory_stale_materialization_conflict_never_installs_candidate_cache() {
        let mut core = initialized_core();
        let stale = core.materialization.clone();
        let committed_input = invocation_input(&stale, MethodMode::Local, 0x41);
        let committed = local_entry(&stale, committed_input);
        core.publish_local(&committed).unwrap();
        let durable_heads = core.store.heads().unwrap().unwrap();

        core.materialization = stale.clone();
        let conflicting_input = invocation_input(&stale, MethodMode::Local, 0x42);
        let conflicting = local_entry(&stale, conflicting_input);
        assert_eq!(
            core.publish_local(&conflicting),
            Err(LocalJournalDriverError::Conflict)
        );
        assert_eq!(core.materialization, stale);
        assert_eq!(core.store.heads().unwrap(), Some(durable_heads));
    }

    #[test]
    fn checkpoint_delta_accepts_only_exact_historical_lane_compaction() {
        let core = initialized_core();
        let mut before = decode_standard_runtime_state(core.materialization.state()).unwrap();
        before
            .lane_state
            .merge
            .push(super::super::standard::StandardLaneEntry {
                actor: ActorId([0xf8; 32]),
                state_generation: Hash([0xf9; 32]),
                value: vec![0xfa],
            });
        let before = encode_standard_runtime_state(&before);
        let mut runtime = StandardAgentRuntime::restore(
            decode_standard_runtime_state(&before).expect("historical state is canonical"),
        )
        .unwrap();
        runtime.compact_historical_lane_entries_for_checkpoint();
        let after = encode_standard_runtime_state(&runtime.snapshot());

        assert_ne!(before, after, "the fixture must exercise real compaction");
        assert!(
            LocalJournalAgentDriver::<MemoryAgentJournalStore>::is_canonical_checkpoint_state_delta(
                &before, &after
            )
        );
        let mut noncanonical = decode_standard_runtime_state(&after).unwrap();
        noncanonical.authority_slot_high_water = Some(999);
        assert!(!LocalJournalAgentDriver::<MemoryAgentJournalStore>::is_canonical_checkpoint_state_delta(
            &before,
            &encode_standard_runtime_state(&noncanonical),
        ));
    }

    #[test]
    fn refusal_from_a_fresh_checkpoint_base_remains_uncommitted() {
        let mut core = initialized_core();
        core.checkpoint().unwrap();
        core.executor.refusal = Some(ActorExecutionError::AuthorityExpired);
        let mut input = invocation_input(&core.materialization, MethodMode::Local, 0xf0);
        let ReplayOperation::Invoke { observed_slot, .. } = &mut input.operation else {
            unreachable!()
        };
        *observed_slot = 101;
        assert!(input.validate().is_ok());
        let entry = local_entry(&core.materialization, input);
        assert_eq!(
            core.publish_local(&entry),
            Err(LocalJournalDriverError::Replay(
                ReplayError::UncommittedInvocation(ActorExecutionError::AuthorityExpired)
            ))
        );
    }

    #[test]
    fn suffix_boundary_refusal_allows_only_the_automatic_checkpoint_delta() {
        let mut core = initialized_core();
        let config = current_test_config(&core.materialization);
        let inner = LifecycleRequest::Suspend {
            actor: ActorId([0xfb; 32]),
            expected_deployment: DeploymentId([0xfc; 32]),
        };
        for sequence in 2..=(super::super::replay::MAX_REPLAY_SUFFIX_ENTRIES as u64 + 1) {
            let input = ReplayInput {
                runtime: core.materialization.runtime().clone(),
                operation: ReplayOperation::Management {
                    request: authorized_at(&config, inner.clone(), sequence, 20),
                },
            };
            let merge_seal = persist_test_merge_seal(&mut core);
            let heads = core.materialization.heads();
            let entry = OrderedEntry {
                genesis: heads.genesis,
                index: heads.ordered_index + 1,
                parent: heads.ordered_head,
                merge_frontier: heads.merge_frontier,
                merge_seal: Some(merge_seal),
                input,
            };
            let published = core.publish_ordered(&entry).unwrap();
            assert!(published.committed.is_none());
        }

        let before = core.materialization.clone();
        core.executor.refusal = Some(ActorExecutionError::AuthorityExpired);
        let mut input = invocation_input(&core.materialization, MethodMode::Local, 0xf0);
        let ReplayOperation::Invoke { observed_slot, .. } = &mut input.operation else {
            unreachable!()
        };
        *observed_slot = 101;
        assert!(input.validate().is_ok());
        let entry = local_entry(&core.materialization, input.clone());
        let position = ReplayPosition::Local {
            id: entry.id(),
            node: entry.node,
            revision: entry.revision,
            ordered_base: entry.ordered_base,
            merge_frontier: entry.merge_frontier,
        };
        assert_eq!(
            core.publish_local(&entry),
            Err(LocalJournalDriverError::Replay(
                ReplayError::UncommittedInvocation(ActorExecutionError::AuthorityExpired)
            ))
        );
        assert!(
            LocalJournalAgentDriver::<MemoryAgentJournalStore>::is_checkpoint_only_delta(
                &before,
                &core.materialization,
            )
        );
        assert_eq!(
            core.store.heads().unwrap(),
            Some(core.materialization.heads().clone())
        );
        assert_eq!(core.store.get::<LocalEntry>(entry.id()).unwrap(), None);
        assert_eq!(
            core.recover(&input, position).unwrap(),
            ReplayInvocationRecovery::NotCommitted
        );
    }

    #[test]
    fn memory_merge_source_is_pending_until_genuine_seal_merge() {
        let mut core = initialized_core();
        let input = invocation_input(&core.materialization, MethodMode::Merge, 0x51);
        let event = MergeEvent {
            genesis: core.materialization.heads().genesis,
            author: core.materialization.heads().node,
            ordered_base: core.materialization.ordered_base(),
            causal_height: 1,
            parents: Vec::new(),
            input: input.clone(),
            signature: vec![0x6b; super::super::authority::ED25519_SIGNATURE_BYTES],
        };
        // Keep the signing preimage construction exercised even though the
        // explicit test authenticator accepts this fixed signature.
        assert_ne!(event.signing_message(), Hash::ZERO);
        let position = ReplayPosition::Merge {
            id: event.id(),
            causal_height: event.causal_height,
            ordered_base: event.ordered_base,
        };
        assert!(core.publish_merge(&event).unwrap().is_empty());
        assert_eq!(
            core.recover(&input, position).unwrap(),
            ReplayInvocationRecovery::Pending
        );

        let merge_bytes = core.materialization.state().merge.clone();
        let reference = BlobRef::of_bytes(&merge_bytes);
        core.store
            .put_blob(JournalBlobClass::LaneState, &reference, &merge_bytes)
            .unwrap();
        let manifest = derive_lane_state::<core::convert::Infallible, core::convert::Infallible>(
            core.materialization.heads().genesis,
            core.materialization.runtime().clone(),
            PersistedLane::Merge,
            LaneCursor::Merge {
                frontier: core.materialization.merge_frontier(),
            },
            &merge_bytes,
        )
        .unwrap();
        core.store.put(&manifest).unwrap();
        let seal = MergeSeal {
            genesis: core.materialization.heads().genesis,
            frontier: core.materialization.merge_frontier(),
            ordered_base: core.materialization.ordered_base(),
            merge_state: manifest.id(),
        };
        core.store.put(&seal).unwrap();
        let seal_input = ReplayInput {
            runtime: core.materialization.runtime().clone(),
            operation: ReplayOperation::SealMerge,
        };
        let ordered = OrderedEntry {
            genesis: core.materialization.heads().genesis,
            index: 1,
            parent: None,
            merge_frontier: core.materialization.merge_frontier(),
            merge_seal: Some(seal.id()),
            input: seal_input,
        };
        let finalized = core.publish_ordered(&ordered).unwrap();
        assert_eq!(
            finalized
                .iter()
                .filter_map(ReplayExecutionResult::result)
                .filter(|result| **result == Err(ActorExecutionError::NotFound))
                .count(),
            1
        );
        assert_eq!(
            core.recover(&input, position).unwrap(),
            ReplayInvocationRecovery::Retained(Err(ActorExecutionError::NotFound))
        );
    }
}
