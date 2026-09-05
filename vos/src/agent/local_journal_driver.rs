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
use super::committee::RootAnchorPins;
use super::driver::{AgentTrustProvider, DEFAULT_MANAGEMENT_GAS};
use super::execution::{
    ActorExecutionError, ActorExecutionReply, ActorExecutionStatus, ActorInvocation, RuntimeBlob,
    RuntimeExecutionCall, RuntimeExecutionReturn,
};
use super::invocation_index::{InvocationIndexLookup, InvocationIndexes};
use super::journal::{
    CanonicalJournalRecord, InvocationOutcomeAnchor, InvocationOwnershipKey,
    InvocationOwnershipScope, InvocationResultState, LaneCursor, LocalEntry, MergeEvent,
    MergeEventId, MergeFrontier, MergeFrontierId, MergeSeal, OrderedEntry, PersistedLane,
    ReplayInput, ReplayInputId, ReplayOperation, RuntimeBinding,
};
use super::journal_store::{
    AgentJournalStore, CatalogBlobResolver, CatalogBlobResolverFactory, JournalBlobClass,
    JournalStoreError, UnpublishedCatalogBlob, UnpublishedCatalogBlobStore,
};
#[cfg(all(feature = "storage", target_os = "linux"))]
use super::journal_store::{
    BoundFileSystemAuthorityLedgerOwner, ReverifiedRootJournalStore, SystemAuthorityHistoryStore,
    SystemAuthorityPublicationStore,
};
use super::package::{Package, PackageError};
use super::replay::{
    MaterializeError, NoPrunedOrderedBases, ReplayCommittedRecovery, ReplayDisposition,
    ReplayError, ReplayExecutionResult, ReplayExecutor, ReplayInvocationRecovery,
    ReplayMaterialization, ReplayMaterializationSourceError, ReplayPosition, ReplayPreparation,
    ReplayPreparedGenesis, ReplayProducts, ReplaySealedGenesis, ReplayStepOutcome,
    ReplayTransition, derive_lane_state, materialize_current, prepare_checkpoint, prepare_local,
    prepare_merge, prepare_ordered, recover_invocation,
};
#[cfg(all(feature = "storage", target_os = "linux"))]
use super::replay::{
    PendingSystemAuthorityCatalogRecovery, PendingSystemAuthorityRotationRecovery,
    SystemAuthorityRecoveryError, materialize_current_reverified,
    materialized_system_authority_view, recover_pending_system_authority_catalog,
    recover_pending_system_authority_rotation,
};
use super::standard::{StandardAgentRuntime, StandardRuntimeState};
#[cfg(all(feature = "storage", target_os = "linux"))]
use super::system_authority_ledger::SystemAuthorityLedgerError;
use super::wire::{
    RuntimeCall, RuntimeJournalContext, RuntimeReturn, RuntimeState, decode_standard_runtime_state,
};
use super::{
    ActorDirectoryPage, ActorDirectoryRecord, ActorEntry, AgentConfig, AgentIdentity, AgentProfile,
    AgentReplica, AgentRuntime, InstallActor, InvocationScope, LifecycleAuthorityAdmission,
    LifecycleError, LifecycleReply, LifecycleRequest, PackageKind, UpgradeActor,
};
use crate::service::wire::ServiceWire;
use crate::service::{ActorId, BlobRef, CapabilityId, DeploymentId, Hash, NodeId};

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

fn lift_prepared_genesis_error(
    error: ReplayError<core::convert::Infallible, LocalReplayExecutorError>,
) -> LocalReplayError {
    match error {
        ReplayError::Source(never) => match never {},
        ReplayError::Executor(error) => ReplayError::Executor(error),
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
        if let Some(installation_data) = &actor.record.installation_data {
            artifacts.push(installation_data.clone());
        }
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
pub trait LocalMergeAuthenticator: Send + Sync {
    fn node(&self) -> NodeId;

    /// Sign exactly the canonical Merge-event message in place.
    ///
    /// Keeping the complete event at this seam prevents a daemon-backed key
    /// from becoming a generic signing oracle. Implementations must refuse an
    /// event whose author is not [`Self::node`].
    fn sign_event(&self, event: &mut MergeEvent) -> bool;

    fn verify_event(&self, event: &MergeEvent) -> bool;
}

/// Why an authenticated node key cannot back Local Merge publications.
#[cfg(feature = "network")]
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Ed25519NodeMergeAuthenticatorError {
    NonEd25519Key,
}

/// Local Merge authenticator backed directly by the daemon's authenticated
/// libp2p Ed25519 identity.
///
/// Construction consumes a keypair handle rather than exporting its secret
/// bytes. The full canonical PeerId, not a compact routing prefix, derives the
/// [`NodeId`] committed by Local journal records.
#[cfg(feature = "network")]
#[derive(Clone)]
pub struct Ed25519NodeMergeAuthenticator {
    keypair: libp2p::identity::Keypair,
    node: NodeId,
}

#[cfg(feature = "network")]
impl Ed25519NodeMergeAuthenticator {
    pub fn new(
        keypair: libp2p::identity::Keypair,
    ) -> Result<Self, Ed25519NodeMergeAuthenticatorError> {
        if keypair.clone().try_into_ed25519().is_err() {
            return Err(Ed25519NodeMergeAuthenticatorError::NonEd25519Key);
        }
        let peer = keypair.public().to_peer_id();
        let node = NodeId::of_authenticated_peer(&peer.to_bytes());
        Ok(Self { keypair, node })
    }
}

#[cfg(feature = "network")]
impl LocalMergeAuthenticator for Ed25519NodeMergeAuthenticator {
    fn node(&self) -> NodeId {
        self.node
    }

    fn sign_event(&self, event: &mut MergeEvent) -> bool {
        if event.author != self.node || !event.signature.is_empty() {
            return false;
        }
        let Ok(signature) = self.keypair.sign(&event.signing_message().0) else {
            return false;
        };
        if signature.len() != super::authority::ED25519_SIGNATURE_BYTES {
            return false;
        }
        event.signature = signature;
        self.verify_event(event)
    }

    fn verify_event(&self, event: &MergeEvent) -> bool {
        event.author == self.node
            && event.signature.len() == super::authority::ED25519_SIGNATURE_BYTES
            && self
                .keypair
                .public()
                .verify(&event.signing_message().0, &event.signature)
    }
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
    AuthorityLedger,
    AuthorityRecoveryRequired,
    Conflict,
    InvalidResult,
}

#[cfg(all(feature = "storage", target_os = "linux"))]
pub(crate) enum LocalJournalUnexposedOpenError<E> {
    Driver(LocalJournalDriverError),
    BeforeExposure(E),
}

#[cfg(all(feature = "storage", target_os = "linux"))]
impl From<SystemAuthorityLedgerError> for LocalJournalDriverError {
    fn from(_error: SystemAuthorityLedgerError) -> Self {
        Self::AuthorityLedger
    }
}

#[cfg(all(feature = "storage", target_os = "linux"))]
fn map_system_authority_recovery_error(
    error: SystemAuthorityRecoveryError<LocalReplayExecutorError>,
) -> LocalJournalDriverError {
    match error {
        SystemAuthorityRecoveryError::Journal(error) => error.into(),
        SystemAuthorityRecoveryError::Ledger(_) => LocalJournalDriverError::AuthorityLedger,
        SystemAuthorityRecoveryError::Replay(error) => LocalJournalDriverError::Replay(error),
    }
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
/// It is restart-safe until finalization. After the owner becomes a
/// permanent acknowledged-history fact, checkpoint GC may prune this suffix
/// position; callers must then submit a fresh authenticated acknowledgement
/// retry, which resolves that history fact without the historical event.
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

/// One deterministic lifecycle request bound to its complete, exact catalog
/// input. The host may expose `request()` for authority signing and later
/// consume the same value for publication; callers cannot accidentally pair
/// an install request with a different package closure.
#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) struct LocalLifecycleOperation {
    request: LifecycleRequest,
    catalog: Vec<RuntimeBlob>,
}

struct StagedCatalog {
    predecessor: super::journal::JournalHeadsId,
    created: Vec<UnpublishedCatalogBlob>,
}

impl LocalLifecycleOperation {
    pub(crate) fn request(&self) -> &LifecycleRequest {
        &self.request
    }

    pub(crate) fn catalog(&self) -> &[RuntimeBlob] {
        &self.catalog
    }

    pub(crate) fn into_parts(self) -> (LifecycleRequest, Vec<RuntimeBlob>) {
        (self.request, self.catalog)
    }
}

/// Fully settled invocation result for synchronous host adapters. Unlike
/// [`LocalInvocationResult`], this type cannot represent a provisional Merge
/// disposition.
#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) enum LocalSettledInvocationResult {
    Final(Result<ActorExecutionReply, ActorExecutionError>),
    /// The exact request has already crossed its durable acknowledgement
    /// boundary, so its historical reply is intentionally unavailable.
    Acknowledged,
}

/// Fully settled acknowledgement result for synchronous host adapters.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum LocalSettledAcknowledgementResult {
    Acknowledged,
    Divergent,
}

/// Exact Standard-runtime replay executor backed by an immutable catalog
/// resolver snapshot.
struct StandardLocalReplayExecutor<R> {
    resolver: R,
    trust: Arc<dyn AgentTrustProvider>,
    merge: Arc<dyn LocalMergeAuthenticator>,
    management_gas: Gas,
    last_management_result: Option<(ReplayInputId, Result<LifecycleReply, LifecycleError>)>,
    authenticated_execution: Option<AuthenticatedLocalExecution>,
}

/// One-shot capability minted by [`ReplayExecutor::authenticate`] and consumed
/// by the immediately following [`ReplayExecutor::execute`]. Keeping the
/// already trusted runtime package here prevents execution from repeating the
/// package/root trust boundary while still refusing unauthenticated direct
/// execution.
struct AuthenticatedLocalExecution {
    input: ReplayInputId,
    before: RuntimeState,
    position: ReplayPosition,
    runtime: Package,
}

struct ActorCatalogAdmission<'a> {
    package: &'a BlobRef,
    schema: &'a BlobRef,
    policies: &'a BlobRef,
    constructor_abi: Hash,
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
            authenticated_execution: None,
        }
    }

    fn replace_resolver(&mut self, resolver: R) {
        self.resolver = resolver;
        self.authenticated_execution = None;
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

    fn validate_local_config_shape(
        config: &AgentConfig,
        binding: &RuntimeBinding,
        node: NodeId,
    ) -> Result<(), LocalReplayExecutorError> {
        config
            .validate()
            .map_err(|_| LocalReplayExecutorError::InvalidState)?;
        if config.identity.profile != AgentProfile::Local || config.replicas.len() != 1 {
            return Err(LocalReplayExecutorError::InvalidProfile);
        }
        if config.replicas[0].node != node {
            return Err(LocalReplayExecutorError::WrongReplica);
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
        Ok(())
    }

    fn validate_local_config(
        &self,
        config: &AgentConfig,
        binding: &RuntimeBinding,
    ) -> Result<Package, LocalReplayExecutorError> {
        Self::validate_local_config_shape(config, binding, self.merge.node())?;
        let anchored = self
            .trust
            .authority_for_space(config.identity.space)
            .ok_or(LocalReplayExecutorError::TrustUnavailable)?;
        if anchored != config.authority {
            return Err(LocalReplayExecutorError::InvalidAuthority);
        }
        self.runtime_package(config, binding)
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
            || package
                .constructor_abi()
                .map_err(LocalReplayExecutorError::Package)?
                != admission.constructor_abi
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
        state: &RuntimeState,
        request: &LifecycleRequest,
        catalog: &[RuntimeBlob],
    ) -> Result<(), LocalReplayExecutorError> {
        let LifecycleRequest::Authorized { request, .. } = request else {
            return Err(LocalReplayExecutorError::InvalidRequest);
        };
        self.validate_lifecycle_operation_catalog(config, request, catalog)?;
        self.validate_upgrade_installation_shape(state, request, Some(catalog))
    }

    fn validate_upgrade_installation_shape(
        &self,
        state: &RuntimeState,
        request: &LifecycleRequest,
        supplied_catalog: Option<&[RuntimeBlob]>,
    ) -> Result<(), LocalReplayExecutorError> {
        let request = match request {
            LifecycleRequest::Authorized { request, .. } => request.as_ref(),
            request => request,
        };
        let LifecycleRequest::UpgradeActor(upgrade) = request else {
            return Ok(());
        };
        let decoded = decode_standard_runtime_state(state)
            .map_err(|_| LocalReplayExecutorError::InvalidState)?;
        let Some(actor) = decoded.actors.iter().find(|actor| {
            actor.record.entry.actor == upgrade.actor
                && actor.record.entry.deployment == upgrade.from_deployment
        }) else {
            // NotFound/StaleDeployment remain exact guest lifecycle outcomes.
            return Ok(());
        };
        let package = match supplied_catalog {
            Some(catalog) => {
                let blob = catalog
                    .iter()
                    .find(|blob| blob.reference == upgrade.package)
                    .ok_or_else(|| {
                        LocalReplayExecutorError::ArtifactUnavailable(upgrade.package.clone())
                    })?;
                Package::decode(&blob.bytes)
            }
            None => Package::decode(&self.load(&upgrade.package)?),
        }
        .map_err(|_| LocalReplayExecutorError::InvalidArtifact(upgrade.package.clone()))?;
        if !package
            .accepts_installation_data_reference(actor.record.installation_data.as_ref())
            .map_err(LocalReplayExecutorError::Package)?
            || package
                .constructor_abi()
                .map_err(LocalReplayExecutorError::Package)?
                != actor.record.constructor_abi
        {
            return Err(LocalReplayExecutorError::InvalidRequest);
        }
        Ok(())
    }

    fn validate_replayed_upgrade_target(
        &self,
        state: &RuntimeState,
        request: &LifecycleRequest,
        expected_result: &Result<LifecycleReply, LifecycleError>,
    ) -> Result<(), LocalReplayExecutorError> {
        if expected_result.is_ok() {
            self.validate_upgrade_installation_shape(state, request, None)
        } else {
            // Live admission never staged a target for an exact rejection,
            // so replay must not invent a dependency on unavailable bytes.
            Ok(())
        }
    }

    fn validate_lifecycle_operation_catalog(
        &self,
        config: &AgentConfig,
        request: &LifecycleRequest,
        catalog: &[RuntimeBlob],
    ) -> Result<(), LocalReplayExecutorError> {
        let expected = match request {
            LifecycleRequest::Install(install) => {
                let mut expected = vec![
                    &install.package,
                    &install.agent_schema,
                    &install.role_policies,
                ];
                if let Some(data) = &install.installation_data {
                    expected.push(&data.reference);
                }
                expected
            }
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
            | LifecycleRequest::FinalizeSystemAuthority(_)
            | LifecycleRequest::RotateSystemAuthority(_)
            | LifecycleRequest::FinalizeCatalog(_)
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

        match request {
            LifecycleRequest::Install(install) => {
                self.validate_actor_catalog(
                    config,
                    &supplied,
                    ActorCatalogAdmission {
                        package: &install.package,
                        schema: &install.agent_schema,
                        policies: &install.role_policies,
                        constructor_abi: install.constructor_abi,
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
                    || install.entry.constructor_abi != install.constructor_abi
                    || install.entry.installation_data.as_ref()
                        != install
                            .installation_data
                            .as_ref()
                            .map(|data| &data.reference)
                    || install.installation_data.as_ref().is_some_and(|data| {
                        !data.is_valid()
                            || supplied
                                .get(&(data.reference.hash, data.reference.len))
                                .is_none_or(|bytes| *bytes != data.bytes.as_slice())
                    })
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
                        constructor_abi: upgrade.constructor_abi,
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
                let mut target = config.clone();
                target.identity.runtime_deployment = *to_deployment;
                target.identity.runtime_program = *to_program;
                target.identity.runtime_producer = *producer;
                target.runtime_package = package.clone();
                target.runtime_contract = *contract;
                target.capabilities = *capabilities;
                target
                    .validate()
                    .map_err(|_| LocalReplayExecutorError::InvalidRequest)?;
                let decoded = self.trusted_package_bytes(&target, package, bytes)?;
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
            | LifecycleRequest::RemoveLeaf { .. }
            | LifecycleRequest::FinalizeSystemAuthority(_)
            | LifecycleRequest::RotateSystemAuthority(_)
            | LifecycleRequest::FinalizeCatalog(_) => {}
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
        Self::validate_runtime_package_binding(config, binding, &package)?;
        Ok(package)
    }

    fn validate_runtime_package_binding(
        config: &AgentConfig,
        binding: &RuntimeBinding,
        package: &Package,
    ) -> Result<(), LocalReplayExecutorError> {
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
        Ok(())
    }

    fn authenticate_management(
        &self,
        config: &AgentConfig,
        request: &LifecycleRequest,
    ) -> Result<(), LocalReplayExecutorError> {
        let (admission, request) = match request {
            LifecycleRequest::FinalizeSystemAuthority(_)
            | LifecycleRequest::RotateSystemAuthority(_)
            | LifecycleRequest::FinalizeCatalog(_) => return Ok(()),
            LifecycleRequest::Authorized { admission, request } => (admission, request),
            _ => return Err(LocalReplayExecutorError::InvalidRequest),
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
    ) -> Result<
        Option<(Vec<u8>, RuntimeBlob, RuntimeBlob, Option<RuntimeBlob>)>,
        LocalReplayExecutorError,
    > {
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
            || record.entry.constructor_abi != record.constructor_abi
            || record.entry.installation_data != record.installation_data
            || BlobRef::of_bytes(&package.agent_schema) != record.agent_schema
            || BlobRef::of_bytes(&package.role_policies) != record.role_policies
            || package.agent_schema != schema
            || package.role_policies != policies
            || package
                .constructor_abi()
                .map_err(LocalReplayExecutorError::Package)?
                != record.constructor_abi
            || record.contract != contract
            || record.requirements != requirements
            || record.entry.lanes != requirements.lanes
            || record.entry.state_layout != record.state_layout
            || !config.runtime_contract.supports(contract)
            || !config.capabilities.satisfies(requirements)
            || parsed_schema.state_layout_hash() != record.state_layout
            || parsed_schema.lanes() != record.entry.lanes
            || crate::service::PackageRolePolicies::decode(&policies).is_err()
            || !package
                .accepts_installation_data_reference(record.installation_data.as_ref())
                .map_err(LocalReplayExecutorError::Package)?
        {
            return Err(LocalReplayExecutorError::InvalidArtifact(
                record.package.clone(),
            ));
        }
        let installation_data = match record.installation_data.as_ref() {
            Some(reference) => {
                let bytes = self.load(reference)?;
                if bytes.len() > super::MAX_INSTALLATION_DATA_BYTES {
                    return Err(LocalReplayExecutorError::InvalidArtifact(reference.clone()));
                }
                Some(RuntimeBlob {
                    reference: reference.clone(),
                    bytes,
                })
            }
            None => None,
        };
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
            installation_data,
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

    fn management_state_config(
        &self,
        state: &RuntimeState,
        current: &AgentConfig,
        runtime_upgraded: bool,
    ) -> Result<AgentConfig, LocalReplayExecutorError> {
        if !runtime_upgraded {
            return Ok(current.clone());
        }
        decode_standard_runtime_state(state)
            .map_err(|_| LocalReplayExecutorError::InvalidState)?
            .config
            .ok_or(LocalReplayExecutorError::InvalidState)
    }

    fn disposition(result: &Result<ActorExecutionReply, ActorExecutionError>) -> ReplayDisposition {
        match result {
            Ok(reply) => match reply.status {
                ActorExecutionStatus::Done => ReplayDisposition::Applied,
                ActorExecutionStatus::Forbidden => ReplayDisposition::Forbidden,
                ActorExecutionStatus::Panicked => ReplayDisposition::Panicked,
                ActorExecutionStatus::OutOfGas => ReplayDisposition::OutOfGas,
                // The legacy invoke journal has no intermediate-transition
                // record. The SDK Resume/Yielded path owns this case.
                ActorExecutionStatus::Yielded => ReplayDisposition::Rejected,
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
        Ok(event.author == self.merge.node() && self.merge.verify_event(event))
    }

    fn authenticate(
        &mut self,
        input: &ReplayInput,
        before: &RuntimeState,
        position: ReplayPosition,
    ) -> Result<(), Self::Error> {
        // Authentication mints a one-shot execution capability. Invalidate a
        // prior capability first so every error path fails closed.
        self.authenticated_execution = None;
        let decoded = decode_standard_runtime_state(before)
            .map_err(|_| LocalReplayExecutorError::InvalidState)?;
        let config = self.config_for(input, &decoded)?;
        let runtime = self.validate_local_config(config, &input.runtime)?;
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
        }?;
        self.authenticated_execution = Some(AuthenticatedLocalExecution {
            input: input.id(),
            before: before.clone(),
            position,
            runtime,
        });
        Ok(())
    }

    fn execute(
        &mut self,
        input: &ReplayInput,
        before: &RuntimeState,
        position: ReplayPosition,
    ) -> Result<ReplayTransition, Self::Error> {
        self.execute_with_journal_context(input, before, position, None)
    }

    fn execute_with_journal_context(
        &mut self,
        input: &ReplayInput,
        before: &RuntimeState,
        position: ReplayPosition,
        journal_context: Option<RuntimeJournalContext>,
    ) -> Result<ReplayTransition, Self::Error> {
        let authenticated = self
            .authenticated_execution
            .take()
            .ok_or(LocalReplayExecutorError::InvalidAuthority)?;
        if authenticated.input != input.id()
            || authenticated.before != *before
            || authenticated.position != position
        {
            return Err(LocalReplayExecutorError::InvalidAuthority);
        }
        let decoded = decode_standard_runtime_state(before)
            .map_err(|_| LocalReplayExecutorError::InvalidState)?;
        let config = self.config_for(input, &decoded)?.clone();
        let runtime = authenticated.runtime;

        let transition = match &input.operation {
            ReplayOperation::Management { request } => {
                let mut expected = StandardAgentRuntime::restore(decoded.clone())
                    .map_err(|_| LocalReplayExecutorError::InvalidState)?;
                let direct_system_authority = matches!(
                    request,
                    LifecycleRequest::FinalizeSystemAuthority(_)
                        | LifecycleRequest::RotateSystemAuthority(_)
                        | LifecycleRequest::FinalizeCatalog(_)
                );
                if direct_system_authority != journal_context.is_some() {
                    return Err(LocalReplayExecutorError::InvalidState);
                }
                let expected_result = match journal_context {
                    Some(context) => expected.apply_guest(Some(context), request.clone()),
                    None => expected.apply(request.clone()),
                };
                // Live admission stages and validates a fresh upgrade target
                // only when the exact Standard preflight succeeds. Historical
                // Busy/NotFound/Stale outcomes therefore must not resolve an
                // artifact which was intentionally never made durable.
                self.validate_replayed_upgrade_target(before, request, &expected_result)?;
                let call = match journal_context {
                    Some(context) => {
                        RuntimeCall::from_replay_context(before.clone(), request.clone(), context)
                    }
                    None => RuntimeCall::new(before.clone(), request.clone()),
                };
                let returned: RuntimeReturn =
                    self.execute_wire(&runtime.pvm, self.management_gas, &call.encode())?;
                if returned.result != expected_result {
                    return Err(LocalReplayExecutorError::InvalidState);
                }
                self.last_management_result = Some((input.id(), returned.result.clone()));
                let applied = returned.result.is_ok();
                let next_runtime = Self::runtime_upgrade_target(input, applied);
                let runtime_upgraded = applied && next_runtime != input.runtime;
                let state_config =
                    self.management_state_config(&returned.state, &config, runtime_upgraded)?;
                self.validate_state_size(&returned.state, &state_config)?;
                if runtime_upgraded {
                    self.validate_local_config(&state_config, &next_runtime)?;
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
                    &RuntimeCall::new(before.clone(), request).encode(),
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
                let (actor_pvm, actor_schema, actor_policies, installation_data) =
                    artifacts.unwrap_or_else(|| (Vec::new(), empty(), empty(), None));
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
                        installation_data,
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
        + CatalogBlobResolverFactory
        + UnpublishedCatalogBlobStore,
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

    fn from_materialization(store: S, executor: E, materialization: ReplayMaterialization) -> Self {
        Self {
            store,
            materialization,
            executor,
        }
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
        let Some(lookup) = indexes
            .lookup(key)
            .map_err(|_| LocalJournalDriverError::InvalidResult)?
        else {
            return Ok(None);
        };
        let owner = match lookup {
            InvocationIndexLookup::Archived(fact) => {
                if fact.validate().is_err()
                    || fact.genesis() != heads.genesis
                    || fact.key() != key
                    || fact.request_commitment() != invocation.commitment()
                {
                    return Ok(None);
                }
                return Ok(Some(ExistingMergeRecovery::Acknowledged));
            }
            InvocationIndexLookup::Live(owner) => owner,
        };
        if owner.validate().is_err()
            || owner.scope != InvocationOwnershipScope::Merge
            || owner.request_commitment != invocation.commitment()
        {
            return Ok(None);
        }
        let source_event = match (acknowledgement, owner.result_state) {
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
        + CatalogBlobResolverFactory
        + UnpublishedCatalogBlobStore,
{
    core: LocalJournalCore<S, StandardLocalReplayExecutor<S::Resolver>>,
    #[cfg(test)]
    lifecycle_fault: Option<TestLifecycleFault>,
}

#[cfg(test)]
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum TestLifecycleFault {
    CatalogPutAfterFirst,
    BeforeMergeSeal,
    BeforeOrderedPublish,
}

impl<S> LocalJournalAgentDriver<S>
where
    S: AgentJournalStore
        + super::replay::ReplaySource<Error = JournalStoreError>
        + CatalogBlobResolverFactory
        + UnpublishedCatalogBlobStore,
{
    /// Construct the exact bootstrap-owned Authorized<Create> input and its
    /// single runtime-package catalog. The trusted logical slot is sampled at
    /// this boundary; callers cannot supply an already-authorized envelope.
    ///
    /// This is a provider-miss operation only. Exact retry and reopen must
    /// reproduce the provider's archived proposal/provision unchanged; they
    /// must never resample the logical slot by rebuilding this input.
    pub(crate) fn system_genesis_input(
        config: AgentConfig,
        runtime_package: &Package,
        receipt: AgentAuthorityReceipt,
        configured_root: &RootAnchorPins,
        trust: &Arc<dyn AgentTrustProvider>,
        merge: &Arc<dyn LocalMergeAuthenticator>,
    ) -> Result<(ReplayInput, Vec<RuntimeBlob>), LocalJournalDriverError> {
        configured_root
            .validate()
            .map_err(|_| LocalReplayExecutorError::InvalidRequest)?;
        let system_authority_genesis = config
            .system_authority_genesis
            .as_ref()
            .ok_or(LocalReplayExecutorError::InvalidRequest)?;
        system_authority_genesis
            .validate_root_config(configured_root.record(), &config, receipt.claim.sequence)
            .map_err(|_| LocalReplayExecutorError::InvalidRequest)?;
        let catalog = Self::runtime_package_catalog(runtime_package);
        let runtime = RuntimeBinding {
            space: config.identity.space,
            agent: config.identity.agent,
            deployment: config.identity.runtime_deployment,
            program: config.identity.runtime_program,
            producer: config.identity.runtime_producer,
            package: catalog[0].reference.clone(),
            runtime_abi: super::RUNTIME_ABI_ID,
            execution_semantics: super::EXECUTION_SEMANTICS_ID,
        };
        let request = seal_lifecycle_request(
            trust.as_ref(),
            receipt,
            LifecycleRequest::Create(config.clone()),
        )?;
        // This provider-miss constructor performs only offline shape and exact
        // content binding checks. Receipt, package-policy, and authority-root
        // authentication happen exactly once in ReplayPreparedGenesis::prepare
        // immediately before the one execution.
        StandardLocalReplayExecutor::<SuppliedCatalogBlobResolver>::validate_local_config_shape(
            &config,
            &runtime,
            merge.node(),
        )?;
        runtime_package
            .validate()
            .map_err(LocalReplayExecutorError::Package)?;
        StandardLocalReplayExecutor::<SuppliedCatalogBlobResolver>::
            validate_runtime_package_binding(&config, &runtime, runtime_package)?;
        Ok((
            ReplayInput {
                runtime,
                operation: ReplayOperation::Management { request },
            },
            catalog,
        ))
    }

    /// Execute and authenticate the bootstrap-owned Create input without
    /// writing a destination store. The returned opaque replay token is the
    /// sole input accepted by the independent genesis proposal/seal path.
    pub(crate) fn prepare_system_genesis(
        create: ReplayInput,
        replica: AgentReplica,
        catalog: &[RuntimeBlob],
        trust: Arc<dyn AgentTrustProvider>,
        merge: Arc<dyn LocalMergeAuthenticator>,
    ) -> Result<ReplayPreparedGenesis, LocalJournalDriverError> {
        if replica.node != merge.node() {
            return Err(LocalReplayExecutorError::WrongReplica.into());
        }
        let supplied = SuppliedCatalogBlobResolver::from_catalog(catalog)?;
        let expected_catalog = supplied.blobs.clone();
        let mut executor = StandardLocalReplayExecutor::new(supplied, trust, merge);
        let prepared = ReplayPreparedGenesis::prepare(create, replica, &mut executor)
            .map_err(lift_prepared_genesis_error)?;
        if expected_catalog.len() != prepared.artifacts().len()
            || prepared.artifacts().iter().any(|reference| {
                expected_catalog
                    .get(&(reference.hash, reference.len))
                    .is_none_or(|bytes| !reference.matches(bytes))
            })
        {
            return Err(LocalJournalDriverError::InvalidResult);
        }
        Ok(prepared)
    }

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
    #[cfg(test)]
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
        let driver = Self {
            core,
            #[cfg(test)]
            lifecycle_fault: None,
        };
        driver.validate_opened(Some(sealed.replica()))?;
        Ok(driver)
    }

    /// Open a store whose filesystem/root adapter has already reverified the
    /// sealed genesis admission. The only state cache is rebuilt from typed
    /// journal closure and exact replay.
    #[cfg(test)]
    pub(crate) fn open(
        store: S,
        trust: Arc<dyn AgentTrustProvider>,
        merge: Arc<dyn LocalMergeAuthenticator>,
    ) -> Result<Self, LocalJournalDriverError> {
        let resolver = store.catalog_blob_resolver()?;
        let executor = StandardLocalReplayExecutor::new(resolver, trust, merge);
        let core = LocalJournalCore::open(store, executor)?;
        let driver = Self {
            core,
            #[cfg(test)]
            lifecycle_fault: None,
        };
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

    /// Current authenticated Standard configuration.
    pub(crate) fn config(&self) -> Result<AgentConfig, LocalJournalDriverError> {
        self.trusted_current_config()
    }

    pub(crate) fn identity(&self) -> Result<AgentIdentity, LocalJournalDriverError> {
        Ok(self.config()?.identity)
    }

    /// Revision of the currently materialized durable heads publication.
    pub(crate) fn publication_revision(&self) -> u64 {
        self.core.materialization.heads().publication_revision
    }

    fn runtime_blob(bytes: Vec<u8>) -> RuntimeBlob {
        RuntimeBlob {
            reference: BlobRef::of_bytes(&bytes),
            bytes,
        }
    }

    fn actor_package_catalog(package: &Package) -> Vec<RuntimeBlob> {
        vec![
            Self::runtime_blob(package.encode()),
            Self::runtime_blob(package.agent_schema.clone()),
            Self::runtime_blob(package.role_policies.clone()),
        ]
    }

    fn runtime_package_catalog(package: &Package) -> Vec<RuntimeBlob> {
        vec![Self::runtime_blob(package.encode())]
    }

    fn lifecycle_operation(
        &self,
        request: LifecycleRequest,
        catalog: Vec<RuntimeBlob>,
    ) -> Result<LocalLifecycleOperation, LocalJournalDriverError> {
        if matches!(
            request,
            LifecycleRequest::Create(_)
                | LifecycleRequest::Inspect { .. }
                | LifecycleRequest::AcknowledgeInvocation { .. }
                | LifecycleRequest::FinalizeSystemAuthority(_)
                | LifecycleRequest::RotateSystemAuthority(_)
                | LifecycleRequest::FinalizeCatalog(_)
                | LifecycleRequest::Authorized { .. }
        ) {
            return Err(LocalReplayExecutorError::InvalidRequest.into());
        }
        let config = self.trusted_current_config()?;
        self.core
            .executor
            .validate_lifecycle_operation_catalog(&config, &request, &catalog)?;
        Ok(LocalLifecycleOperation { request, catalog })
    }

    /// Construct an exact actor-install request and its complete catalog.
    pub(crate) fn actor_install_operation(
        &self,
        installation_id: crate::service::InstallationId,
        registry_reservation: Hash,
        name: String,
        parent: Option<ActorId>,
        installation_data: Option<Vec<u8>>,
        package: &Package,
    ) -> Result<LocalLifecycleOperation, LocalJournalDriverError> {
        if installation_id == crate::service::InstallationId::ZERO
            || registry_reservation == Hash::ZERO
            || name.is_empty()
            || name.len() > crate::service::MAX_ACTOR_NAME_BYTES
            || parent == Some(ActorId::ZERO)
        {
            return Err(LocalJournalDriverError::Lifecycle(
                LifecycleError::InvalidRequest,
            ));
        }
        package
            .validate()
            .map_err(LocalReplayExecutorError::Package)?;
        if installation_data
            .as_ref()
            .is_some_and(|bytes| bytes.len() > super::MAX_INSTALLATION_DATA_BYTES)
            || package
                .accepts_installation_data(installation_data.as_deref())
                .map_err(LocalReplayExecutorError::Package)?
                == false
        {
            return Err(LocalJournalDriverError::Lifecycle(
                LifecycleError::InvalidRequest,
            ));
        }
        let PackageKind::Actor {
            contract,
            requirements,
        } = package.manifest.kind
        else {
            return Err(LocalReplayExecutorError::Package(PackageError::WrongKind).into());
        };
        let schema = super::schema::decode(&package.agent_schema).ok_or(
            LocalReplayExecutorError::Package(PackageError::InvalidActorArtifacts),
        )?;
        let config = self.trusted_current_config()?;
        let actor = match parent {
            Some(parent) => ActorId::owned_child(parent, &name),
            None => ActorId::top_level(config.identity.agent, &name),
        };
        let mut catalog = Self::actor_package_catalog(package);
        let installation_data = installation_data.map(|bytes| super::InstallationData {
            reference: BlobRef::of_bytes(&bytes),
            bytes,
        });
        if let Some(data) = &installation_data {
            catalog.push(RuntimeBlob {
                reference: data.reference.clone(),
                bytes: data.bytes.clone(),
            });
        }
        let package_reference = catalog[0].reference.clone();
        let schema_reference = catalog[1].reference.clone();
        let policies_reference = catalog[2].reference.clone();
        let state_layout = schema.state_layout_hash();
        let constructor_abi = package
            .constructor_abi()
            .map_err(LocalReplayExecutorError::Package)?;
        self.lifecycle_operation(
            LifecycleRequest::Install(InstallActor {
                installation_id,
                registry_reservation,
                entry: ActorEntry {
                    actor,
                    name,
                    parent,
                    deployment: package.deployment_id(),
                    program: package.manifest.program,
                    package: package_reference.clone(),
                    agent_schema: schema_reference.clone(),
                    role_policies: policies_reference.clone(),
                    constructor_abi,
                    installation_data: installation_data
                        .as_ref()
                        .map(|data| data.reference.clone()),
                    state_layout,
                    lanes: requirements.lanes,
                    suspended: false,
                },
                producer: package.deployment_signature.producer,
                package: package_reference,
                agent_schema: schema_reference,
                role_policies: policies_reference,
                constructor_abi,
                installation_data,
                state_layout,
                contract,
                requirements,
            }),
            catalog,
        )
    }

    /// Construct an exact in-place actor-upgrade request and catalog.
    pub(crate) fn actor_upgrade_operation(
        &self,
        actor: ActorId,
        from_deployment: DeploymentId,
        package: &Package,
    ) -> Result<LocalLifecycleOperation, LocalJournalDriverError> {
        if actor == ActorId::ZERO || from_deployment == DeploymentId::ZERO {
            return Err(LocalJournalDriverError::Lifecycle(
                LifecycleError::InvalidRequest,
            ));
        }
        package
            .validate()
            .map_err(LocalReplayExecutorError::Package)?;
        let PackageKind::Actor {
            contract,
            requirements,
        } = package.manifest.kind
        else {
            return Err(LocalReplayExecutorError::Package(PackageError::WrongKind).into());
        };
        let schema = super::schema::decode(&package.agent_schema).ok_or(
            LocalReplayExecutorError::Package(PackageError::InvalidActorArtifacts),
        )?;
        let constructor_abi = package
            .constructor_abi()
            .map_err(LocalReplayExecutorError::Package)?;
        match self.inspect_actor(actor) {
            Ok(record) if record.entry.deployment == from_deployment => {
                if package
                    .accepts_installation_data_reference(record.entry.installation_data.as_ref())
                    .map_err(LocalReplayExecutorError::Package)?
                    == false
                {
                    return Err(LocalReplayExecutorError::InvalidRequest.into());
                }
                if record.entry.constructor_abi != constructor_abi {
                    return Err(LocalReplayExecutorError::InvalidRequest.into());
                }
            }
            Ok(_) | Err(LocalJournalDriverError::Lifecycle(LifecycleError::NotFound)) => {}
            Err(error) => return Err(error),
        }
        let catalog = Self::actor_package_catalog(package);
        self.lifecycle_operation(
            LifecycleRequest::UpgradeActor(UpgradeActor {
                actor,
                from_deployment,
                to_deployment: package.deployment_id(),
                to_program: package.manifest.program,
                producer: package.deployment_signature.producer,
                package: catalog[0].reference.clone(),
                agent_schema: catalog[1].reference.clone(),
                role_policies: catalog[2].reference.clone(),
                constructor_abi,
                state_layout: schema.state_layout_hash(),
                contract,
                requirements,
            }),
            catalog,
        )
    }

    pub(crate) fn actor_suspend_operation(
        &self,
        actor: ActorId,
    ) -> Result<LocalLifecycleOperation, LocalJournalDriverError> {
        let expected_deployment = self.inspect_actor(actor)?.entry.deployment;
        self.lifecycle_operation(
            LifecycleRequest::Suspend {
                actor,
                expected_deployment,
            },
            Vec::new(),
        )
    }

    pub(crate) fn actor_resume_operation(
        &self,
        actor: ActorId,
    ) -> Result<LocalLifecycleOperation, LocalJournalDriverError> {
        let expected_deployment = self.inspect_actor(actor)?.entry.deployment;
        self.lifecycle_operation(
            LifecycleRequest::Resume {
                actor,
                expected_deployment,
            },
            Vec::new(),
        )
    }

    pub(crate) fn actor_remove_operation(
        &self,
        actor: ActorId,
        expected_deployment: DeploymentId,
    ) -> Result<LocalLifecycleOperation, LocalJournalDriverError> {
        if actor == ActorId::ZERO || expected_deployment == DeploymentId::ZERO {
            return Err(LocalJournalDriverError::Lifecycle(
                LifecycleError::InvalidRequest,
            ));
        }
        self.lifecycle_operation(
            LifecycleRequest::RemoveLeaf {
                actor,
                expected_deployment,
            },
            Vec::new(),
        )
    }

    /// Construct a runtime upgrade against the complete signed target
    /// descriptor, not the current runtime's package-policy descriptor.
    pub(crate) fn runtime_upgrade_operation(
        &self,
        from_deployment: DeploymentId,
        package: &Package,
    ) -> Result<LocalLifecycleOperation, LocalJournalDriverError> {
        if from_deployment == DeploymentId::ZERO {
            return Err(LocalJournalDriverError::Lifecycle(
                LifecycleError::InvalidRequest,
            ));
        }
        package
            .validate()
            .map_err(LocalReplayExecutorError::Package)?;
        let PackageKind::AgentRuntime {
            contract,
            capabilities,
        } = package.manifest.kind
        else {
            return Err(LocalReplayExecutorError::Package(PackageError::WrongKind).into());
        };
        let catalog = Self::runtime_package_catalog(package);
        self.lifecycle_operation(
            LifecycleRequest::UpgradeRuntime {
                from_deployment,
                to_deployment: package.deployment_id(),
                to_program: package.manifest.program,
                producer: package.deployment_signature.producer,
                package: catalog[0].reference.clone(),
                contract,
                capabilities,
            },
            catalog,
        )
    }

    fn rollback_staged_catalog(
        &mut self,
        staged: StagedCatalog,
    ) -> Result<(), LocalJournalDriverError> {
        // A publication error can occur after its durable CAS. Authenticate
        // the physical head before deleting anything; an unreadable or moved
        // head leaves the bytes for normal reopen reconciliation.
        let Ok(Some(current)) = self.core.store.heads() else {
            return Ok(());
        };
        if current.id() != staged.predecessor {
            return Ok(());
        }
        for token in staged.created.into_iter().rev() {
            self.core.store.rollback_catalog_blob(token)?;
        }
        let resolver = self.core.store.catalog_blob_resolver()?;
        self.core.executor.replace_resolver(resolver);
        Ok(())
    }

    fn stage_catalog(
        &mut self,
        catalog: &[RuntimeBlob],
    ) -> Result<StagedCatalog, LocalJournalDriverError> {
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
        let predecessor = self.core.materialization.heads().id();
        let mut created = Vec::new();
        for blob in catalog {
            match self
                .core
                .store
                .stage_catalog_blob(predecessor, &blob.reference, &blob.bytes)
            {
                Ok(Some(token)) => {
                    created.push(token);
                    #[cfg(test)]
                    if self.lifecycle_fault == Some(TestLifecycleFault::CatalogPutAfterFirst) {
                        self.lifecycle_fault = None;
                        self.rollback_staged_catalog(StagedCatalog {
                            predecessor,
                            created,
                        })?;
                        return Err(JournalStoreError::Unavailable.into());
                    }
                }
                Ok(None) => {}
                Err(error) => {
                    self.rollback_staged_catalog(StagedCatalog {
                        predecessor,
                        created,
                    })?;
                    return Err(error.into());
                }
            }
        }
        // Memory snapshots are copy-on-write and file snapshots own pinned
        // descriptors. Refresh only after every requested byte is durable.
        let resolver = match self.core.store.catalog_blob_resolver() {
            Ok(resolver) => resolver,
            Err(error) => {
                self.rollback_staged_catalog(StagedCatalog {
                    predecessor,
                    created,
                })?;
                return Err(error.into());
            }
        };
        self.core.executor.replace_resolver(resolver);
        Ok(StagedCatalog {
            predecessor,
            created,
        })
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
        if matches!(
            request,
            LifecycleRequest::Create(_)
                | LifecycleRequest::Inspect { .. }
                | LifecycleRequest::AcknowledgeInvocation { .. }
                | LifecycleRequest::FinalizeSystemAuthority(_)
                | LifecycleRequest::RotateSystemAuthority(_)
                | LifecycleRequest::FinalizeCatalog(_)
                | LifecycleRequest::Authorized { .. }
        ) {
            return Err(LocalReplayExecutorError::InvalidRequest.into());
        }
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
        let staged = if retained_lifecycle_disposition(self.core.materialization.state(), &request)?
            .is_none()
            && preflight.result.is_ok()
        {
            self.core.executor.validate_lifecycle_catalog(
                &config,
                self.core.materialization.state(),
                &request,
                catalog,
            )?;
            validate_prospective_artifact_closure(
                self.core.materialization.heads().genesis,
                &preflight.successor,
            )?;
            Some(self.stage_catalog(catalog)?)
        } else {
            None
        };
        let result = (|| -> Result<LocalLifecycleResult, LocalJournalDriverError> {
            #[cfg(test)]
            if self.lifecycle_fault == Some(TestLifecycleFault::BeforeMergeSeal) {
                self.lifecycle_fault = None;
                return Err(JournalStoreError::Unavailable.into());
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
            #[cfg(test)]
            if self.lifecycle_fault == Some(TestLifecycleFault::BeforeOrderedPublish) {
                self.lifecycle_fault = None;
                return Err(JournalStoreError::Unavailable.into());
            }
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
        })();
        if result.is_err()
            && let Some(staged) = staged
        {
            self.rollback_staged_catalog(staged)?;
        }
        result
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
        if !self.core.executor.merge.sign_event(&mut event) {
            return Err(LocalReplayExecutorError::InvalidAuthority.into());
        }
        if event.validate().is_err()
            || event.author != self.core.executor.merge.node()
            || !self.core.executor.merge.verify_event(&event)
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

    /// Execute one invocation to a non-provisional result. A Merge source is
    /// immediately finalized by an ordered maintenance publication and then
    /// recovered through its exact authenticated input/position capability.
    pub(crate) fn invoke_synchronous(
        &mut self,
        invocation: ActorInvocation,
        authority: ActorInvocationReceipt,
    ) -> Result<LocalSettledInvocationResult, LocalJournalDriverError> {
        match self.invoke(invocation, authority)? {
            LocalInvocationResult::Final(result) => Ok(LocalSettledInvocationResult::Final(result)),
            LocalInvocationResult::Acknowledged => Ok(LocalSettledInvocationResult::Acknowledged),
            LocalInvocationResult::Pending(pending) => {
                self.finalize_merge()?;
                match self.recover_committed_invocation(&pending.input, pending.position)? {
                    LocalInvocationResult::Final(result) => {
                        Ok(LocalSettledInvocationResult::Final(result))
                    }
                    LocalInvocationResult::Acknowledged => {
                        Ok(LocalSettledInvocationResult::Acknowledged)
                    }
                    LocalInvocationResult::Pending(_) => {
                        Err(LocalJournalDriverError::InvalidResult)
                    }
                }
            }
        }
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

    /// Acknowledge one invocation to a non-provisional result. Merge
    /// acknowledgement events are finalized and then recovered through the
    /// exact event input/position before success is exposed.
    pub(crate) fn acknowledge_invocation_synchronous(
        &mut self,
        invocation: ActorInvocation,
        authority: ActorInvocationReceipt,
    ) -> Result<LocalSettledAcknowledgementResult, LocalJournalDriverError> {
        match self.acknowledge_invocation(invocation, authority)? {
            LocalAcknowledgementResult::Acknowledged => {
                Ok(LocalSettledAcknowledgementResult::Acknowledged)
            }
            LocalAcknowledgementResult::Divergent => {
                Ok(LocalSettledAcknowledgementResult::Divergent)
            }
            LocalAcknowledgementResult::Pending(pending) => {
                self.finalize_merge()?;
                let config = self.trusted_current_config()?;
                Self::validate_invocation_capability(&config, &pending.input)?;
                match Self::map_acknowledgement_recovery(
                    self.core.recover(&pending.input, pending.position)?,
                    None,
                )? {
                    LocalAcknowledgementResult::Acknowledged => {
                        Ok(LocalSettledAcknowledgementResult::Acknowledged)
                    }
                    LocalAcknowledgementResult::Divergent => {
                        Ok(LocalSettledAcknowledgementResult::Divergent)
                    }
                    LocalAcknowledgementResult::Pending(_) => {
                        Err(LocalJournalDriverError::InvalidResult)
                    }
                }
            }
        }
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

    /// Resolve one exact actor incarnation through authenticated, read-only
    /// Standard directory pages.
    pub(crate) fn inspect_actor(
        &self,
        actor: ActorId,
    ) -> Result<ActorDirectoryRecord, LocalJournalDriverError> {
        if actor == ActorId::ZERO {
            return Err(LocalJournalDriverError::Lifecycle(
                LifecycleError::InvalidRequest,
            ));
        }
        let config = self.trusted_current_config()?;
        let page_limit = usize::from(super::standard::MAX_DIRECTORY_PAGE);
        let max_actors = usize::try_from(config.capabilities.max_actors)
            .map_err(|_| LocalJournalDriverError::InvalidResult)?;
        let max_pages = max_actors.div_ceil(page_limit).saturating_add(1);
        let mut after = None;
        for _ in 0..max_pages {
            let page = self.inspect(after, super::standard::MAX_DIRECTORY_PAGE)?;
            if let Ok(index) = page
                .entries
                .binary_search_by_key(&actor, |record| record.entry.actor)
            {
                return Ok(page.entries[index].clone());
            }
            if page
                .entries
                .last()
                .is_some_and(|record| record.entry.actor > actor)
            {
                return Err(LocalJournalDriverError::Lifecycle(LifecycleError::NotFound));
            }
            let Some(next) = page.next else {
                return Err(LocalJournalDriverError::Lifecycle(LifecycleError::NotFound));
            };
            if after == Some(next) {
                return Err(LocalJournalDriverError::InvalidResult);
            }
            after = Some(next);
        }
        Err(LocalJournalDriverError::InvalidResult)
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
            && page.entries.iter().all(|record| {
                record.incarnation != Hash::ZERO
                    && record.installation_id != crate::service::InstallationId::ZERO
                    && record.registry_reservation != Hash::ZERO
            })
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
            &RuntimeCall::new(self.core.materialization.state().clone(), request).encode(),
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

#[cfg(all(feature = "storage", target_os = "linux"))]
impl<S> LocalJournalAgentDriver<S>
where
    S: AgentJournalStore
        + super::replay::ReplaySource<Error = JournalStoreError>
        + CatalogBlobResolverFactory
        + UnpublishedCatalogBlobStore
        + ReverifiedRootJournalStore
        + SystemAuthorityPublicationStore
        + SystemAuthorityHistoryStore,
{
    fn validate_route_owner(
        store: &S,
        materialization: &ReplayMaterialization,
        authority: &BoundFileSystemAuthorityLedgerOwner,
    ) -> Result<(), LocalJournalDriverError> {
        let (_, view) = materialized_system_authority_view(store, materialization)?;
        if view.route() != authority.route()
            || view.journal_store() != authority.journal_store()
            || store.instance_id() != authority.journal_store()
            || materialization.heads().node != authority.local_node()
        {
            return Err(LocalJournalDriverError::AuthorityLedger);
        }
        Ok(())
    }

    /// Initialize a reverified root store while the Host holds the owner's
    /// no-pending mutation writer. Materialization retains the sealed root
    /// provenance instead of taking the generic unverified replay path.
    pub(crate) fn create_reverified_with_owner<E>(
        mut store: S,
        sealed: ReplaySealedGenesis,
        catalog: &[RuntimeBlob],
        trust: Arc<dyn AgentTrustProvider>,
        merge: Arc<dyn LocalMergeAuthenticator>,
        authority: &BoundFileSystemAuthorityLedgerOwner,
        after_validate_before_marker: impl FnOnce() -> Result<(), E>,
    ) -> Result<Self, LocalJournalUnexposedOpenError<E>> {
        let system_genesis = sealed.genesis().id();
        authority
            .with_unexposed_journal_initialization(system_genesis, move || {
                let driver = (|| -> Result<Self, LocalJournalDriverError> {
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
                    let mut executor = StandardLocalReplayExecutor::new(resolver, trust, merge);
                    let materialization = materialize_current_reverified(
                        &mut store,
                        &mut executor,
                        &NoPrunedOrderedBases,
                    )?;
                    Self::validate_route_owner(&store, &materialization, authority)?;
                    let core =
                        LocalJournalCore::from_materialization(store, executor, materialization);
                    let driver = Self {
                        core,
                        #[cfg(test)]
                        lifecycle_fault: None,
                    };
                    driver.validate_opened(Some(sealed.replica()))?;
                    Ok(driver)
                })()
                .map_err(LocalJournalUnexposedOpenError::Driver)?;
                driver
                    .core
                    .store
                    .sync_unexposed_generation()
                    .map_err(LocalJournalDriverError::from)
                    .map_err(LocalJournalUnexposedOpenError::Driver)?;
                after_validate_before_marker()
                    .map_err(LocalJournalUnexposedOpenError::BeforeExposure)?;
                Ok(driver)
            })
            .map_err(|error| {
                LocalJournalUnexposedOpenError::Driver(LocalJournalDriverError::from(error))
            })?
    }

    /// Reverify a completely initialized journal left by a crash immediately
    /// before its permanent exposure marker was committed. The owner's
    /// pristine-unexposed writer excludes evidence creation and installs the
    /// marker only after the rebuilt driver has passed every open invariant.
    pub(crate) fn open_unexposed_reverified_with_owner<E>(
        mut store: S,
        sealed: &ReplaySealedGenesis,
        trust: Arc<dyn AgentTrustProvider>,
        merge: Arc<dyn LocalMergeAuthenticator>,
        authority: &BoundFileSystemAuthorityLedgerOwner,
        after_validate_before_marker: impl FnOnce() -> Result<(), E>,
    ) -> Result<Self, LocalJournalUnexposedOpenError<E>> {
        let system_genesis = sealed.genesis().id();
        let initial_heads = sealed.initial_heads();
        authority
            .with_unexposed_journal_initialization(system_genesis, move || {
                let driver = (|| -> Result<Self, LocalJournalDriverError> {
                    if store.heads()?.as_ref() != Some(&initial_heads) {
                        return Err(LocalJournalDriverError::InvalidResult);
                    }
                    let resolver = store.catalog_blob_resolver()?;
                    let mut executor = StandardLocalReplayExecutor::new(resolver, trust, merge);
                    let materialization = materialize_current_reverified(
                        &mut store,
                        &mut executor,
                        &NoPrunedOrderedBases,
                    )?;
                    if materialization.heads() != &initial_heads {
                        return Err(LocalJournalDriverError::InvalidResult);
                    }
                    Self::validate_route_owner(&store, &materialization, authority)?;
                    let core =
                        LocalJournalCore::from_materialization(store, executor, materialization);
                    let driver = Self {
                        core,
                        #[cfg(test)]
                        lifecycle_fault: None,
                    };
                    driver.validate_opened(None)?;
                    Ok(driver)
                })()
                .map_err(LocalJournalUnexposedOpenError::Driver)?;
                driver
                    .core
                    .store
                    .sync_unexposed_generation()
                    .map_err(LocalJournalDriverError::from)
                    .map_err(LocalJournalUnexposedOpenError::Driver)?;
                after_validate_before_marker()
                    .map_err(LocalJournalUnexposedOpenError::BeforeExposure)?;
                Ok(driver)
            })
            .map_err(|error| {
                LocalJournalUnexposedOpenError::Driver(LocalJournalDriverError::from(error))
            })?
    }

    /// Rebuild a reverified root materialization and reconcile any exact
    /// pending rotation or catalog publication before exposing a mutable
    /// driver. This path uses only the signer-independent route owner; a
    /// predecessor without durable intent stays quarantined and no driver is
    /// returned.
    pub(crate) fn open_reverified_with_owner(
        mut store: S,
        trust: Arc<dyn AgentTrustProvider>,
        merge: Arc<dyn LocalMergeAuthenticator>,
        authority: &BoundFileSystemAuthorityLedgerOwner,
    ) -> Result<Self, LocalJournalDriverError> {
        authority
            .with_recovery_owner(move |owner| {
                let resolver = store.catalog_blob_resolver()?;
                let mut executor = StandardLocalReplayExecutor::new(resolver, trust, merge);
                let current = materialize_current_reverified(
                    &mut store,
                    &mut executor,
                    &NoPrunedOrderedBases,
                )?;
                Self::validate_route_owner(&store, &current, authority)?;
                let materialization = match owner.recover_pending_claim()? {
                    None => current,
                    Some(pending) if pending.catalog_request().is_some() => {
                        match recover_pending_system_authority_catalog(
                            &mut store,
                            &mut executor,
                            current,
                            pending,
                            owner,
                        )
                        .map_err(map_system_authority_recovery_error)?
                        {
                            PendingSystemAuthorityCatalogRecovery::Pending(_quarantine) => {
                                return Err(LocalJournalDriverError::AuthorityRecoveryRequired);
                            }
                            PendingSystemAuthorityCatalogRecovery::Retired(retired) => {
                                let (_publication, materialization, _executions) =
                                    retired.into_parts();
                                materialization
                            }
                        }
                    }
                    Some(pending) if pending.rotation_request().is_some() => {
                        match recover_pending_system_authority_rotation(
                            &mut store,
                            &mut executor,
                            current,
                            pending,
                            owner,
                        )
                        .map_err(map_system_authority_recovery_error)?
                        {
                            PendingSystemAuthorityRotationRecovery::Pending(_quarantine) => {
                                return Err(LocalJournalDriverError::AuthorityRecoveryRequired);
                            }
                            PendingSystemAuthorityRotationRecovery::Retired(retired) => {
                                let (_publication, materialization, _executions) =
                                    retired.into_parts();
                                materialization
                            }
                        }
                    }
                    Some(_) => return Err(LocalJournalDriverError::AuthorityLedger),
                };
                Self::validate_route_owner(&store, &materialization, authority)?;
                let (_, replayed_authority) =
                    materialized_system_authority_view(&store, &materialization)?;
                owner.validate_replayed_view(&replayed_authority)?;
                // Filesystem crash cleanup is deliberately deferred until
                // the current heads have survived full replay and the
                // external authority META fence. A deleted required
                // directory therefore fails without being recreated.
                store.finish_reverified_open()?;
                if store.heads()?.as_ref() != Some(materialization.heads()) {
                    return Err(LocalJournalDriverError::InvalidResult);
                }
                Self::validate_route_owner(&store, &materialization, authority)?;
                let core = LocalJournalCore::from_materialization(store, executor, materialization);
                let driver = Self {
                    core,
                    #[cfg(test)]
                    lifecycle_fault: None,
                };
                driver.validate_opened(None)?;
                Ok(driver)
            })
            .map_err(LocalJournalDriverError::from)?
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    use super::super::authority::{
        ActorInvocationClaim, AgentAuthorityBinding, AgentAuthorityClaim,
    };
    use super::super::bootstrap::{
        SystemAgentGenesisLocator, SystemAgentGenesisProposal, SystemAgentGenesisProvision,
        seal_prepared_system_agent_genesis,
    };
    use super::super::committee::{
        AuthorityCommittee, AuthorityCommitteeMember, AuthorityMemberRole,
        AuthorityQuorumCertificate, AuthoritySignature, AuthoritySignerId, RootAnchorPins,
        RootAnchorRecord, SystemAgentGenesisClaim, SystemAgentGenesisEvidence,
    };
    use super::super::contract::{ActorPackageContract, RuntimePackageContract};
    use super::super::execution::ActorInvocationAuth;
    use super::super::journal_store::{
        AgentJournalGarbageCollection, GcLimits, MemoryAgentJournalStore,
    };
    use super::super::package::{PackageManifest, actor_runtime_requirements};
    use super::super::system_authority::{SystemAuthorityGenesis, SystemAuthorityState};
    use super::super::wire::encode_standard_runtime_state;
    use super::super::{
        ActorEntry, FieldPersistence, InstallActor, LaneSet, MethodMode, RuntimeCapabilities,
        RuntimeRequirements, StateLane,
    };
    use crate::service::{
        ActorId, CapabilityId, CredentialId, DeploymentId, DeploymentSignature, InvocationId,
        PackageRolePolicies, ProducerId, ProgramId, SpaceId, artifact_hash, task_dependencies_hash,
    };
    use ed25519_dalek::{Signer as _, SigningKey};
    use std::sync::{
        Mutex,
        atomic::{AtomicUsize, Ordering},
    };

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

    struct CountingTrust {
        slot: u64,
        authority: AgentAuthorityBinding,
        slot_samples: AtomicUsize,
        authority_checks: AtomicUsize,
        package_checks: AtomicUsize,
    }

    impl AgentTrustProvider for CountingTrust {
        fn current_logical_slot(&self) -> Option<u64> {
            self.slot_samples.fetch_add(1, Ordering::Relaxed);
            Some(self.slot)
        }

        fn authority_for_space(&self, _space: SpaceId) -> Option<AgentAuthorityBinding> {
            self.authority_checks.fetch_add(1, Ordering::Relaxed);
            Some(self.authority.clone())
        }

        fn verify_package(&self, _agent: &AgentConfig, _package: &Package) -> bool {
            self.package_checks.fetch_add(1, Ordering::Relaxed);
            true
        }
    }

    struct StaticMerge(NodeId);

    impl LocalMergeAuthenticator for StaticMerge {
        fn node(&self) -> NodeId {
            self.0
        }

        fn sign_event(&self, event: &mut MergeEvent) -> bool {
            if event.author != self.0 || !event.signature.is_empty() {
                return false;
            }
            event.signature = vec![0x6b; super::super::authority::ED25519_SIGNATURE_BYTES];
            true
        }

        fn verify_event(&self, event: &MergeEvent) -> bool {
            event.author == self.0
                && event.signature.len() == super::super::authority::ED25519_SIGNATURE_BYTES
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

    fn deployment_signature(discriminator: u8) -> DeploymentSignature {
        let public_key = vec![discriminator; 32];
        DeploymentSignature {
            producer: ProducerId::of_public_key(&public_key),
            public_key,
            signature: vec![discriminator; super::super::authority::ED25519_SIGNATURE_BYTES],
        }
    }

    fn host_surface_runtime_package(name: &str) -> Package {
        let pvm = include_bytes!("../../../vosx/blobs/agent_runtime.pvm").to_vec();
        let generated_interfaces = b"host-surface-runtime-interface".to_vec();
        let schemas = b"host-surface-runtime-schema".to_vec();
        Package {
            manifest: PackageManifest {
                name: name.into(),
                platform: crate::service::PLATFORM_ID,
                execution_semantics: super::super::EXECUTION_SEMANTICS_ID,
                kind: PackageKind::AgentRuntime {
                    contract: RuntimePackageContract::canonical(),
                    capabilities: RuntimeCapabilities::standard(),
                },
                program: ProgramId::of_pvm(&pvm),
                interfaces_hash: artifact_hash(b"interfaces", &generated_interfaces),
                role_policies_hash: artifact_hash(b"role-policies", &[]),
                schemas_hash: artifact_hash(b"schemas", &schemas),
                agent_schema_hash: artifact_hash(b"agent-schema", &[]),
                dependencies_hash: task_dependencies_hash(&[]),
            },
            pvm,
            generated_interfaces,
            role_policies: Vec::new(),
            schemas,
            agent_schema: Vec::new(),
            task_dependencies: Vec::new(),
            diagnostics: None,
            deployment_signature: deployment_signature(0x71),
        }
    }

    const HOST_SURFACE_ACTOR_META: crate::metadata::ActorMeta = crate::metadata::ActorMeta {
        actor_name: "merge-fixture",
        messages: &[crate::metadata::MessageMeta {
            name: "mutate",
            is_query: false,
            fields: &[],
            returns: "()",
            doc: "",
            timeout_ms: 0,
            mode: 0,
            attested: false,
            space_role: None,
            actor_role: None,
            capability: None,
        }],
        constructor: &[],
        cli_methods: &[],
        doc: "",
        crdt: false,
        provable: false,
    };

    const HOST_SURFACE_PARAMETERIZED_META: crate::metadata::ActorMeta =
        crate::metadata::ActorMeta {
            constructor: &[crate::metadata::FieldMeta {
                name: "tenant",
                ty: "u64",
            }],
            ..HOST_SURFACE_ACTOR_META
        };

    const HOST_SURFACE_STRING_PARAMETER_META: crate::metadata::ActorMeta =
        crate::metadata::ActorMeta {
            constructor: &[crate::metadata::FieldMeta {
                name: "tenant",
                ty: "String",
            }],
            ..HOST_SURFACE_ACTOR_META
        };

    const FRESH_UPGRADE_METHODS: &[crate::agent_sdk::schema::MethodMeta] =
        &[crate::agent_sdk::schema::MethodMeta {
            source_index: 0,
            name: "mutate",
            mode: crate::agent_sdk::MethodMode::Merge,
            explicit: false,
        }];
    const FRESH_UPGRADE_SCHEMA: crate::agent_sdk::schema::SchemaMeta =
        crate::agent_sdk::schema::SchemaMeta {
            fields: &[],
            methods: FRESH_UPGRADE_METHODS,
        };

    const HOST_SURFACE_ACTOR_SCHEMA: super::super::schema::SchemaMeta =
        super::super::schema::SchemaMeta {
            uses_storage: false,
            fields: &[super::super::schema::FieldMeta {
                name: "value",
                codec: "fixture::Vec<u8>",
                persistence: FieldPersistence::State(StateLane::Merge),
            }],
            methods: &[super::super::schema::MethodMeta {
                name: "mutate",
                mode: MethodMode::Merge,
                explicit: false,
            }],
        };

    fn host_surface_actor_package() -> Package {
        host_surface_actor_package_with_meta(&HOST_SURFACE_ACTOR_META)
    }

    fn host_surface_actor_package_with_meta(meta: &crate::metadata::ActorMeta) -> Package {
        let pvm = vos_pvm_program::build_standard_program(&vos_pvm_program::StandardProgram {
            ro_data: Vec::new(),
            rw_data: Vec::new(),
            heap_pages: 0,
            stack_size: vos_pvm_program::PAGE_SIZE,
            code: vos_pvm_program::CodeBlob {
                jump_table: Vec::new(),
                code: vec![0],
                bitmask: vec![1],
            },
        })
        .unwrap();
        let (metadata_bytes, metadata_len) = crate::metadata::encode::<1024>(meta);
        let schemas = metadata_bytes[..metadata_len].to_vec();
        let metadata = crate::metadata::decode(&schemas).unwrap();
        let role_policies = PackageRolePolicies::from_metadata(&metadata)
            .unwrap()
            .encode();
        let (schema_bytes, schema_len) = super::super::schema::encode_with_entry::<1024>(
            &HOST_SURFACE_ACTOR_SCHEMA,
            super::super::schema::ExecutionEntryKind::AgentActor,
        );
        let agent_schema = schema_bytes[..schema_len].to_vec();
        let parsed_schema = super::super::schema::decode(&agent_schema).unwrap();
        let requirements = actor_runtime_requirements(&parsed_schema, &metadata, false);
        let generated_interfaces = b"host-surface-actor-interface".to_vec();
        Package {
            manifest: PackageManifest {
                name: meta.actor_name.into(),
                platform: crate::service::PLATFORM_ID,
                execution_semantics: super::super::EXECUTION_SEMANTICS_ID,
                kind: PackageKind::Actor {
                    contract: ActorPackageContract::canonical(),
                    requirements,
                },
                program: ProgramId::of_pvm(&pvm),
                interfaces_hash: artifact_hash(b"interfaces", &generated_interfaces),
                role_policies_hash: artifact_hash(b"role-policies", &role_policies),
                schemas_hash: artifact_hash(b"schemas", &schemas),
                agent_schema_hash: artifact_hash(b"agent-schema", &agent_schema),
                dependencies_hash: task_dependencies_hash(&[]),
            },
            pvm,
            generated_interfaces,
            role_policies,
            schemas,
            agent_schema,
            task_dependencies: Vec::new(),
            diagnostics: None,
            deployment_signature: deployment_signature(0x72),
        }
    }

    fn fresh_upgrade_actor_package(
        meta: &crate::metadata::ActorMeta,
        discriminator: u8,
    ) -> Package {
        let mut package = host_surface_actor_package_with_meta(meta);
        let (schema, schema_len) = crate::agent_sdk::schema::encode::<1024>(&FRESH_UPGRADE_SCHEMA);
        package.agent_schema = schema[..schema_len].to_vec();
        package.manifest.agent_schema_hash = artifact_hash(b"agent-schema", &package.agent_schema);
        package.manifest.kind = PackageKind::Actor {
            contract: ActorPackageContract::canonical(),
            requirements: RuntimeRequirements {
                lanes: LaneSet::of(StateLane::Merge),
                scheduling: false,
                proofs: false,
            },
        };
        package.pvm = vos_pvm_program::build_standard_program(&vos_pvm_program::StandardProgram {
            ro_data: vec![discriminator],
            rw_data: Vec::new(),
            heap_pages: 0,
            stack_size: vos_pvm_program::PAGE_SIZE,
            code: vos_pvm_program::CodeBlob {
                jump_table: Vec::new(),
                code: vec![0],
                bitmask: vec![1],
            },
        })
        .unwrap();
        package.manifest.program = ProgramId::of_pvm(&package.pvm);
        package.deployment_signature = deployment_signature(discriminator);
        package.validate().unwrap_or_else(|error| {
            panic!(
                "fresh actor package with {} constructor fields: {error:?}",
                meta.constructor.len()
            )
        });
        package
    }

    fn host_surface_root_material(config: &AgentConfig) -> (RootAnchorRecord, [SigningKey; 3]) {
        let keys = [
            SigningKey::from_bytes(&[0x81; 32]),
            SigningKey::from_bytes(&[0x82; 32]),
            SigningKey::from_bytes(&[0x83; 32]),
        ];
        let mut members = keys
            .iter()
            .enumerate()
            .map(|(index, key)| {
                AuthorityCommitteeMember::new(
                    NodeId([(index + 1) as u8; 32]),
                    key.verifying_key().to_bytes(),
                    AuthorityMemberRole::Voter,
                )
                .unwrap()
            })
            .collect::<Vec<_>>();
        members.sort_by_key(AuthorityCommitteeMember::signer);
        let binding = config.authority.commitment();
        let committee =
            AuthorityCommittee::new(config.identity.space, binding, 1, None, members).unwrap();
        let root = RootAnchorRecord::new(
            1,
            config.identity.space,
            config.identity.agent,
            binding,
            Hash([0x84; 32]),
            committee.clone(),
        )
        .unwrap();
        (root, keys)
    }

    fn host_surface_root_pins(
        config: &AgentConfig,
        receipt: &AgentAuthorityReceipt,
        observed_slot: u64,
    ) -> RootAnchorPins {
        let runtime = RuntimeBinding {
            space: config.identity.space,
            agent: config.identity.agent,
            deployment: config.identity.runtime_deployment,
            program: config.identity.runtime_program,
            producer: config.identity.runtime_producer,
            package: config.runtime_package.clone(),
            runtime_abi: super::super::RUNTIME_ABI_ID,
            execution_semantics: super::super::EXECUTION_SEMANTICS_ID,
        };
        let create = ReplayInput {
            runtime,
            operation: ReplayOperation::Management {
                request: LifecycleRequest::Authorized {
                    admission: LifecycleAuthorityAdmission {
                        receipt: receipt.clone(),
                        observed_slot,
                    },
                    request: Box::new(LifecycleRequest::Create(config.clone())),
                },
            },
        };
        let mut executor = ExactTestExecutor::default();
        let prepared =
            ReplayPreparedGenesis::prepare(create, config.replicas[0], &mut executor).unwrap();
        let (root, _) = host_surface_root_material(config);
        let claim = SystemAgentGenesisClaim::new(&root, prepared.expectations()).unwrap();
        RootAnchorPins::new(
            root.clone(),
            root.config_version(),
            root.id(),
            root.config_commitment(),
            claim.authority_claim(),
        )
        .unwrap()
    }

    fn seal_host_surface_genesis(
        config: &AgentConfig,
        prepared: ReplayPreparedGenesis,
        configured_root: &RootAnchorPins,
    ) -> ReplaySealedGenesis {
        let locator = SystemAgentGenesisLocator {
            space: config.identity.space,
            agent: config.identity.agent,
            node: config.replicas[0].node,
        };
        let proposal = SystemAgentGenesisProposal::from_prepared(locator, &prepared).unwrap();
        let (root, keys) = host_surface_root_material(config);
        assert_eq!(configured_root.record(), &root);
        let committee = root.initial_committee().clone();
        let claim = SystemAgentGenesisClaim::new(&root, proposal.expectations()).unwrap();
        let message = AuthorityQuorumCertificate::signing_message(
            committee.authority_binding(),
            committee.epoch(),
            committee.commitment(),
            claim.authority_claim(),
        );
        let mut signatures = keys[..2]
            .iter()
            .map(|key| {
                AuthoritySignature::new(
                    AuthoritySignerId::of_raw_ed25519(&key.verifying_key().to_bytes()),
                    key.sign(&message.0).to_bytes(),
                )
                .unwrap()
            })
            .collect::<Vec<_>>();
        signatures.sort_by_key(AuthoritySignature::signer);
        let evidence = SystemAgentGenesisEvidence::new(
            claim.clone(),
            AuthorityQuorumCertificate::new(&committee, claim.authority_claim(), signatures)
                .unwrap(),
        )
        .unwrap();
        assert_eq!(configured_root.genesis_claim(), claim.authority_claim());
        let provision =
            SystemAgentGenesisProvision::new(proposal, configured_root.clone(), evidence).unwrap();
        seal_prepared_system_agent_genesis(prepared, configured_root, &provision).unwrap()
    }

    fn host_surface_config_and_runtime(name: &str) -> (AgentConfig, Package) {
        let template = super::super::replay::tests::admitted_genesis(0xe7);
        let mut config = decode_standard_runtime_state(template.post_create())
            .unwrap()
            .config
            .unwrap();
        let runtime_package = host_surface_runtime_package(name);
        config.identity.runtime_deployment = runtime_package.deployment_id();
        config.identity.runtime_program = runtime_package.manifest.program;
        config.identity.runtime_producer = runtime_package.deployment_signature.producer;
        config.runtime_package = BlobRef::of_bytes(&runtime_package.encode());
        let PackageKind::AgentRuntime {
            contract,
            capabilities,
        } = runtime_package.manifest.kind
        else {
            unreachable!()
        };
        config.runtime_contract = contract;
        config.capabilities = capabilities;
        let (root, _) = host_surface_root_material(&config);
        config.system_authority_genesis = Some(
            SystemAuthorityGenesis::new(
                root.id(),
                root.config_version(),
                root.config_commitment(),
                root.initial_committee().clone(),
                1,
                Hash([0x75; 32]),
                Hash([0x76; 32]),
                8,
                8,
                8,
            )
            .unwrap(),
        );
        config.validate().unwrap();
        runtime_package.validate().unwrap();
        (config, runtime_package)
    }

    fn host_surface_driver() -> (
        LocalJournalAgentDriver<MemoryAgentJournalStore>,
        AgentConfig,
        Arc<dyn AgentTrustProvider>,
        Arc<dyn LocalMergeAuthenticator>,
    ) {
        let (config, runtime_package) = host_surface_config_and_runtime("host-surface-runtime");
        let trust: Arc<dyn AgentTrustProvider> = Arc::new(StaticTrust {
            slot: Some(20),
            authority: Some(config.authority.clone()),
            trust_packages: true,
        });
        let merge: Arc<dyn LocalMergeAuthenticator> =
            Arc::new(StaticMerge(config.replicas[0].node));
        let create = LifecycleRequest::Create(config.clone());
        let receipt = lifecycle_receipt(&config, &create, 1);
        let configured_root = host_surface_root_pins(&config, &receipt, 20);
        let (input, catalog) =
            LocalJournalAgentDriver::<MemoryAgentJournalStore>::system_genesis_input(
                config.clone(),
                &runtime_package,
                receipt,
                &configured_root,
                &trust,
                &merge,
            )
            .unwrap();
        let prepared = LocalJournalAgentDriver::<MemoryAgentJournalStore>::prepare_system_genesis(
            input,
            config.replicas[0],
            &catalog,
            Arc::clone(&trust),
            Arc::clone(&merge),
        )
        .unwrap();
        let sealed = seal_host_surface_genesis(&config, prepared, &configured_root);
        let store =
            MemoryAgentJournalStore::new(config.identity.agent, config.replicas[0].node).unwrap();
        let driver = LocalJournalAgentDriver::create(
            store,
            sealed,
            &catalog,
            Arc::clone(&trust),
            Arc::clone(&merge),
        )
        .unwrap();
        (driver, config, trust, merge)
    }

    fn signed_invocation_receipt(
        config: &AgentConfig,
        invocation: &ActorInvocation,
    ) -> ActorInvocationReceipt {
        let claim = ActorInvocationClaim {
            authority: config.authority.clone(),
            space: config.identity.space,
            agent: config.identity.agent,
            principal: None,
            credential: None,
            authorization: invocation.authorization_message(),
            auth: invocation.auth.clone(),
            valid_from: 10,
            valid_until: 100,
        };
        ActorInvocationReceipt {
            signature: admitted_authority_key()
                .sign(&claim.signing_message().0)
                .to_bytes()
                .to_vec(),
            claim,
        }
    }

    #[test]
    fn prepared_genesis_crosses_each_live_trust_boundary_once() {
        let (config, runtime_package) =
            host_surface_config_and_runtime("single-auth-genesis-runtime");
        let counted = Arc::new(CountingTrust {
            slot: 20,
            authority: config.authority.clone(),
            slot_samples: AtomicUsize::new(0),
            authority_checks: AtomicUsize::new(0),
            package_checks: AtomicUsize::new(0),
        });
        let trust: Arc<dyn AgentTrustProvider> = counted.clone();
        let merge: Arc<dyn LocalMergeAuthenticator> =
            Arc::new(StaticMerge(config.replicas[0].node));
        let create = LifecycleRequest::Create(config.clone());
        let receipt = lifecycle_receipt(&config, &create, 1);
        let configured_root = host_surface_root_pins(&config, &receipt, 20);

        let (input, catalog) =
            LocalJournalAgentDriver::<MemoryAgentJournalStore>::system_genesis_input(
                config.clone(),
                &runtime_package,
                receipt,
                &configured_root,
                &trust,
                &merge,
            )
            .unwrap();
        assert_eq!(counted.slot_samples.load(Ordering::Relaxed), 1);
        assert_eq!(counted.authority_checks.load(Ordering::Relaxed), 0);
        assert_eq!(counted.package_checks.load(Ordering::Relaxed), 0);

        LocalJournalAgentDriver::<MemoryAgentJournalStore>::prepare_system_genesis(
            input,
            config.replicas[0],
            &catalog,
            trust,
            merge,
        )
        .unwrap();
        assert_eq!(counted.slot_samples.load(Ordering::Relaxed), 1);
        assert_eq!(counted.authority_checks.load(Ordering::Relaxed), 1);
        assert_eq!(counted.package_checks.load(Ordering::Relaxed), 1);
    }

    #[test]
    fn root_marker_mismatch_fails_before_clock_sampling_or_destination_work() {
        let (config, runtime_package) =
            host_surface_config_and_runtime("root-marker-preflight-runtime");
        let create = LifecycleRequest::Create(config.clone());
        let receipt = lifecycle_receipt(&config, &create, 1);
        let configured_root = host_surface_root_pins(&config, &receipt, 20);
        let counted = Arc::new(CountingTrust {
            slot: 20,
            authority: config.authority.clone(),
            slot_samples: AtomicUsize::new(0),
            authority_checks: AtomicUsize::new(0),
            package_checks: AtomicUsize::new(0),
        });
        let trust: Arc<dyn AgentTrustProvider> = counted.clone();
        let merge: Arc<dyn LocalMergeAuthenticator> =
            Arc::new(StaticMerge(config.replicas[0].node));

        let mut missing = config.clone();
        missing.system_authority_genesis = None;
        let missing_request = LifecycleRequest::Create(missing.clone());
        let missing_receipt = lifecycle_receipt(&missing, &missing_request, 1);
        assert_eq!(
            LocalJournalAgentDriver::<MemoryAgentJournalStore>::system_genesis_input(
                missing,
                &runtime_package,
                missing_receipt,
                &configured_root,
                &trust,
                &merge,
            ),
            Err(LocalJournalDriverError::Executor(
                LocalReplayExecutorError::InvalidRequest
            ))
        );

        let mut divergent = config.clone();
        let configured_record = configured_root.record();
        let divergent_record = RootAnchorRecord::new(
            configured_record.config_version() + 1,
            configured_record.space(),
            configured_record.system_agent(),
            configured_record.authority_binding(),
            Hash([0x85; 32]),
            configured_record.initial_committee().clone(),
        )
        .unwrap();
        divergent.system_authority_genesis = Some(
            SystemAuthorityGenesis::new(
                divergent_record.id(),
                divergent_record.config_version(),
                divergent_record.config_commitment(),
                divergent_record.initial_committee().clone(),
                1,
                Hash([0x75; 32]),
                Hash([0x76; 32]),
                8,
                8,
                8,
            )
            .unwrap(),
        );
        let divergent_request = LifecycleRequest::Create(divergent.clone());
        let divergent_receipt = lifecycle_receipt(&divergent, &divergent_request, 1);
        assert_eq!(
            LocalJournalAgentDriver::<MemoryAgentJournalStore>::system_genesis_input(
                divergent,
                &runtime_package,
                divergent_receipt,
                &configured_root,
                &trust,
                &merge,
            ),
            Err(LocalJournalDriverError::Executor(
                LocalReplayExecutorError::InvalidRequest
            ))
        );

        let mut wrong_sequence = config.clone();
        let marker = wrong_sequence.system_authority_genesis.as_ref().unwrap();
        wrong_sequence.system_authority_genesis = Some(
            SystemAuthorityGenesis::new(
                marker.root_anchor(),
                marker.root_anchor_config_version(),
                marker.root_anchor_config(),
                marker.initial_committee().clone(),
                2,
                marker.catalog_binding(),
                marker.initial_catalog_commitment(),
                marker.decision_limit(),
                marker.rotation_limit(),
                marker.catalog_limit(),
            )
            .unwrap(),
        );
        let wrong_sequence_request = LifecycleRequest::Create(wrong_sequence.clone());
        let wrong_sequence_receipt = lifecycle_receipt(&wrong_sequence, &wrong_sequence_request, 1);
        assert_eq!(
            LocalJournalAgentDriver::<MemoryAgentJournalStore>::system_genesis_input(
                wrong_sequence,
                &runtime_package,
                wrong_sequence_receipt,
                &configured_root,
                &trust,
                &merge,
            ),
            Err(LocalJournalDriverError::Executor(
                LocalReplayExecutorError::InvalidRequest
            ))
        );

        assert_eq!(counted.slot_samples.load(Ordering::Relaxed), 0);
        assert_eq!(counted.authority_checks.load(Ordering::Relaxed), 0);
        assert_eq!(counted.package_checks.load(Ordering::Relaxed), 0);
    }

    #[test]
    fn seeded_root_authority_is_exact_after_create_and_reopen() {
        let (driver, config, trust, merge) = host_surface_driver();
        let expected = SystemAuthorityState::from_genesis(
            config.identity.agent,
            config.system_authority_genesis.as_ref().unwrap(),
        )
        .unwrap();
        let created = decode_standard_runtime_state(driver.core.materialization.state()).unwrap();
        assert_eq!(created.system_authority.as_ref(), Some(&expected));

        let store = driver.core.store;
        let reopened = LocalJournalAgentDriver::open(store, trust, merge).unwrap();
        let restored =
            decode_standard_runtime_state(reopened.core.materialization.state()).unwrap();
        assert_eq!(restored.config.as_ref(), Some(&config));
        assert_eq!(restored.system_authority, Some(expected));
    }

    #[test]
    fn install_identity_is_idempotent_and_exact_across_journal_reopen() {
        let (mut driver, config, trust, merge) = host_surface_driver();
        let package = host_surface_actor_package();
        let installation_id = crate::service::InstallationId([0xa1; 32]);
        let registry_reservation = Hash([0xa2; 32]);
        let operation = driver
            .actor_install_operation(
                installation_id,
                registry_reservation,
                "journal-identity".into(),
                None,
                None,
                &package,
            )
            .unwrap();
        let request = operation.request().clone();
        let catalog = operation.catalog().to_vec();

        let first = driver
            .lifecycle(
                lifecycle_receipt(&config, &request, 2),
                request.clone(),
                &catalog,
            )
            .unwrap();
        let entry = match first.result.unwrap() {
            LifecycleReply::Installed(entry) => entry,
            other => panic!("unexpected install result: {other:?}"),
        };
        let first_record = driver.inspect_actor(entry.actor).unwrap();
        assert_eq!(first_record.installation_id, installation_id);
        assert_eq!(first_record.registry_reservation, registry_reservation);

        let retry = driver
            .lifecycle(
                lifecycle_receipt(&config, &request, 3),
                request.clone(),
                &catalog,
            )
            .unwrap();
        assert_eq!(retry.result, Ok(LifecycleReply::Installed(entry.clone())));
        let retry_record = driver.inspect_actor(entry.actor).unwrap();
        assert_eq!(retry_record, first_record);

        let mut mismatch = match request {
            LifecycleRequest::Install(install) => install,
            _ => unreachable!("fixture constructs an install"),
        };
        mismatch.registry_reservation = Hash([0xa3; 32]);
        let mismatch = LifecycleRequest::Install(mismatch);
        let rejected = driver
            .lifecycle(lifecycle_receipt(&config, &mismatch, 4), mismatch, &catalog)
            .unwrap();
        assert_eq!(rejected.result, Err(LifecycleError::InvalidRequest));
        assert_eq!(driver.inspect_actor(entry.actor).unwrap(), first_record);

        let store = driver.core.store;
        let reopened = LocalJournalAgentDriver::open(store, trust, merge).unwrap();
        assert_eq!(reopened.inspect_actor(entry.actor).unwrap(), first_record);
    }

    #[test]
    fn fresh_upgrade_catalog_preserves_the_installed_constructor_argument_shape() {
        fn installed_state(
            driver: &LocalJournalAgentDriver<MemoryAgentJournalStore>,
            config: &AgentConfig,
            package: &Package,
            installation_data: Option<Vec<u8>>,
            discriminator: u8,
        ) -> (RuntimeState, ActorEntry) {
            let catalog =
                LocalJournalAgentDriver::<MemoryAgentJournalStore>::actor_package_catalog(package);
            let PackageKind::Actor {
                contract,
                requirements,
            } = package.manifest.kind
            else {
                panic!("fixture is an actor package")
            };
            let name = format!("upgrade-shape-{discriminator}");
            let installation_data = installation_data.map(|bytes| super::super::InstallationData {
                reference: BlobRef::of_bytes(&bytes),
                bytes,
            });
            let parsed_schema = crate::agent_sdk::schema::decode(&package.agent_schema).unwrap();
            let constructor_abi = package.constructor_abi().unwrap();
            let entry = ActorEntry {
                actor: ActorId::top_level(config.identity.agent, &name),
                name,
                parent: None,
                deployment: package.deployment_id(),
                program: package.manifest.program,
                package: catalog[0].reference.clone(),
                agent_schema: catalog[1].reference.clone(),
                role_policies: catalog[2].reference.clone(),
                constructor_abi,
                installation_data: installation_data
                    .as_ref()
                    .map(|data| data.reference.clone()),
                state_layout: Hash(parsed_schema.state_layout_hash().unwrap().0),
                lanes: requirements.lanes,
                suspended: false,
            };
            let request = LifecycleRequest::Install(InstallActor {
                installation_id: crate::service::InstallationId([discriminator; 32]),
                registry_reservation: Hash([discriminator.wrapping_add(1); 32]),
                entry: entry.clone(),
                producer: package.deployment_signature.producer,
                package: catalog[0].reference.clone(),
                agent_schema: catalog[1].reference.clone(),
                role_policies: catalog[2].reference.clone(),
                constructor_abi,
                installation_data,
                state_layout: entry.state_layout,
                contract,
                requirements,
            });
            let request = authorized_at(config, request, 2, 20);
            let mut runtime = StandardAgentRuntime::restore(
                decode_standard_runtime_state(driver.core.materialization.state()).unwrap(),
            )
            .unwrap();
            let reply = runtime.apply(request).unwrap();
            let LifecycleReply::Installed(entry) = reply else {
                panic!("expected installed actor")
            };
            (encode_standard_runtime_state(&runtime.snapshot()), entry)
        }

        fn upgrade_validation(
            driver: &LocalJournalAgentDriver<MemoryAgentJournalStore>,
            config: &AgentConfig,
            state: &RuntimeState,
            installed: &ActorEntry,
            target: &Package,
        ) -> Result<(), LocalReplayExecutorError> {
            let catalog =
                LocalJournalAgentDriver::<MemoryAgentJournalStore>::actor_package_catalog(target);
            let PackageKind::Actor {
                contract,
                requirements,
            } = target.manifest.kind
            else {
                panic!("fixture is an actor package")
            };
            let parsed_schema = crate::agent_sdk::schema::decode(&target.agent_schema).unwrap();
            let constructor_abi = target.constructor_abi().unwrap();
            let request = LifecycleRequest::UpgradeActor(UpgradeActor {
                actor: installed.actor,
                from_deployment: installed.deployment,
                to_deployment: target.deployment_id(),
                to_program: target.manifest.program,
                producer: target.deployment_signature.producer,
                package: catalog[0].reference.clone(),
                agent_schema: catalog[1].reference.clone(),
                role_policies: catalog[2].reference.clone(),
                constructor_abi,
                state_layout: Hash(parsed_schema.state_layout_hash().unwrap().0),
                contract,
                requirements,
            });
            let target_reference = catalog[0].reference.clone();
            assert!(matches!(
                driver.core.executor.load(&target_reference),
                Err(LocalReplayExecutorError::ArtifactUnavailable(reference))
                    if reference == target_reference
            ));
            let authorized = authorized_at(config, request, 3, 20);
            driver.core.executor.validate_upgrade_installation_shape(
                state,
                &authorized,
                Some(&catalog),
            )
        }

        let driver = standard_test_driver();
        let config = current_test_config(&driver.core.materialization);
        let ordinary = fresh_upgrade_actor_package(&HOST_SURFACE_ACTOR_META, 0xb0);
        let ordinary_target = fresh_upgrade_actor_package(&HOST_SURFACE_ACTOR_META, 0xb1);
        let required = fresh_upgrade_actor_package(&HOST_SURFACE_PARAMETERIZED_META, 0xb2);
        let incompatible_typed =
            fresh_upgrade_actor_package(&HOST_SURFACE_STRING_PARAMETER_META, 0xb5);

        let (absent_state, absent_actor) = installed_state(&driver, &config, &ordinary, None, 0xb3);
        assert_eq!(
            upgrade_validation(
                &driver,
                &config,
                &absent_state,
                &absent_actor,
                &ordinary_target,
            ),
            Ok(()),
            "live admission must authenticate a fresh package from the supplied catalog"
        );
        assert_eq!(
            upgrade_validation(&driver, &config, &absent_state, &absent_actor, &required),
            Err(LocalReplayExecutorError::InvalidRequest),
            "an absent argument object cannot upgrade into a parameterized constructor"
        );

        let (present_state, present_actor) =
            installed_state(&driver, &config, &required, Some(vec![0x44]), 0xb4);
        assert_eq!(
            upgrade_validation(
                &driver,
                &config,
                &present_state,
                &present_actor,
                &ordinary_target,
            ),
            Err(LocalReplayExecutorError::InvalidRequest),
            "immutable constructor arguments cannot be stranded by an upgrade"
        );
        assert_eq!(
            upgrade_validation(
                &driver,
                &config,
                &present_state,
                &present_actor,
                &incompatible_typed,
            ),
            Err(LocalReplayExecutorError::InvalidRequest),
            "equal constructor presence cannot reinterpret typed argument bytes"
        );

        let target_catalog =
            LocalJournalAgentDriver::<MemoryAgentJournalStore>::actor_package_catalog(
                &ordinary_target,
            );
        let PackageKind::Actor {
            contract,
            requirements,
        } = ordinary_target.manifest.kind
        else {
            unreachable!()
        };
        let target_schema =
            crate::agent_sdk::schema::decode(&ordinary_target.agent_schema).unwrap();
        let busy_upgrade = authorized_at(
            &config,
            LifecycleRequest::UpgradeActor(UpgradeActor {
                actor: absent_actor.actor,
                from_deployment: absent_actor.deployment,
                to_deployment: ordinary_target.deployment_id(),
                to_program: ordinary_target.manifest.program,
                producer: ordinary_target.deployment_signature.producer,
                package: target_catalog[0].reference.clone(),
                agent_schema: target_catalog[1].reference.clone(),
                role_policies: target_catalog[2].reference.clone(),
                constructor_abi: ordinary_target.constructor_abi().unwrap(),
                state_layout: Hash(target_schema.state_layout_hash().unwrap().0),
                contract,
                requirements,
            }),
            4,
            20,
        );
        let mut busy = decode_standard_runtime_state(&absent_state).unwrap();
        busy.actors[0].debt.lifecycle_operations = 1;
        let busy_state = encode_standard_runtime_state(&busy);
        let preflight = preflight_lifecycle_transition(&busy_state, &busy_upgrade).unwrap();
        assert!(matches!(preflight.result, Err(LifecycleError::Busy(_))));
        assert!(matches!(
            driver.core.executor.load(&target_catalog[0].reference),
            Err(LocalReplayExecutorError::ArtifactUnavailable(_))
        ));
        assert_eq!(
            driver.core.executor.validate_replayed_upgrade_target(
                &busy_state,
                &busy_upgrade,
                &preflight.result,
            ),
            Ok(()),
            "historical Busy replay must not resolve an unstaged target"
        );
    }

    #[test]
    fn lifecycle_catalog_staging_rolls_back_each_prepublication_failure_boundary() {
        for (index, fault) in [
            TestLifecycleFault::CatalogPutAfterFirst,
            TestLifecycleFault::BeforeMergeSeal,
            TestLifecycleFault::BeforeOrderedPublish,
        ]
        .into_iter()
        .enumerate()
        {
            let mut driver = standard_test_driver();
            let catalog = (0..3_u8)
                .map(|item| {
                    let bytes = vec![0xc0 + index as u8, item];
                    RuntimeBlob {
                        reference: BlobRef::of_bytes(&bytes),
                        bytes,
                    }
                })
                .collect::<Vec<_>>();
            let predecessor = driver.core.store.heads().unwrap().unwrap();

            // Content which predates the attempted transaction mints no
            // deletion capability and must survive every cleanup boundary.
            assert!(
                driver
                    .core
                    .store
                    .put_blob(
                        JournalBlobClass::CatalogArtifact,
                        &catalog[0].reference,
                        &catalog[0].bytes,
                    )
                    .unwrap()
            );
            if fault == TestLifecycleFault::CatalogPutAfterFirst {
                driver.lifecycle_fault = Some(fault);
                assert!(matches!(
                    driver.stage_catalog(&catalog),
                    Err(LocalJournalDriverError::Store(
                        JournalStoreError::Unavailable
                    ))
                ));
            } else {
                // These are the two error boundaries immediately after
                // staging in `lifecycle`: merge-seal preparation and ordered
                // publication. Both consume the same opaque transaction.
                let staged = driver.stage_catalog(&catalog).unwrap();
                driver.rollback_staged_catalog(staged).unwrap();
            }
            assert_eq!(driver.core.store.heads().unwrap(), Some(predecessor));
            assert_eq!(
                driver
                    .core
                    .store
                    .load_blob(JournalBlobClass::CatalogArtifact, &catalog[0].reference)
                    .unwrap(),
                Some(catalog[0].bytes.clone())
            );
            for blob in &catalog[1..] {
                assert_eq!(
                    driver
                        .core
                        .store
                        .load_blob(JournalBlobClass::CatalogArtifact, &blob.reference)
                        .unwrap(),
                    None,
                    "{fault:?} left an unpublished catalog orphan"
                );
                assert!(matches!(
                    driver.core.executor.load(&blob.reference),
                    Err(LocalReplayExecutorError::ArtifactUnavailable(_))
                ));
            }
        }
    }

    #[cfg(feature = "network")]
    #[test]
    fn ed25519_node_merge_authenticator_binds_the_full_peer_and_exact_event() {
        let keypair = libp2p::identity::Keypair::generate_ed25519();
        let expected_node =
            NodeId::of_authenticated_peer(&keypair.public().to_peer_id().to_bytes());
        let authenticator = Ed25519NodeMergeAuthenticator::new(keypair).unwrap();
        assert_eq!(authenticator.node(), expected_node);

        let core = initialized_core();
        let input = invocation_input(&core.materialization, MethodMode::Merge, 0x91);
        let frontier = core
            .store
            .get::<MergeFrontier>(core.materialization.merge_frontier())
            .unwrap()
            .unwrap();
        let mut event = MergeEvent {
            genesis: core.materialization.heads().genesis,
            author: expected_node,
            ordered_base: core.materialization.ordered_base(),
            causal_height: 1,
            parents: frontier.events,
            input,
            signature: Vec::new(),
        };
        assert!(authenticator.sign_event(&mut event));
        assert_eq!(
            event.signature.len(),
            super::super::authority::ED25519_SIGNATURE_BYTES
        );
        assert!(authenticator.verify_event(&event));
        assert!(!authenticator.sign_event(&mut event));

        let mut tampered = event.clone();
        tampered.signature[0] ^= 1;
        assert!(!authenticator.verify_event(&tampered));
        let mut wrong_author = event;
        wrong_author.author = NodeId([0x92; 32]);
        assert!(!authenticator.verify_event(&wrong_author));
    }

    #[test]
    fn memory_host_surface_builds_exact_operations_and_settles_merge_calls() {
        let (mut driver, config, _, _) = host_surface_driver();
        assert_eq!(driver.config().unwrap(), config);
        assert_eq!(driver.identity().unwrap(), config.identity);
        assert_eq!(driver.publication_revision(), 0);

        let before_create_retry = driver.publication_revision();
        let forbidden_create = LifecycleRequest::Create(config.clone());
        assert_eq!(
            driver.lifecycle(
                lifecycle_receipt(&config, &forbidden_create, 2),
                forbidden_create,
                &[],
            ),
            Err(LocalJournalDriverError::Executor(
                LocalReplayExecutorError::InvalidRequest
            ))
        );
        assert_eq!(driver.publication_revision(), before_create_retry);

        let actor_package = host_surface_actor_package();
        actor_package.validate().unwrap();
        let operation = driver
            .actor_install_operation(
                crate::service::InstallationId([0x91; 32]),
                Hash([0x92; 32]),
                "merge-fixture".into(),
                None,
                None,
                &actor_package,
            )
            .unwrap();
        assert_eq!(operation.catalog().len(), 3);
        assert!(
            operation
                .catalog()
                .iter()
                .all(|blob| blob.reference.matches(&blob.bytes))
        );
        let install_receipt = lifecycle_receipt(&config, operation.request(), 2);
        let (request, catalog) = operation.into_parts();
        let installed = driver
            .lifecycle(install_receipt, request, &catalog)
            .unwrap();
        let entry = match installed.result.unwrap() {
            LifecycleReply::Installed(entry) => entry,
            other => panic!("unexpected install result: {other:?}"),
        };
        let record = driver.inspect_actor(entry.actor).unwrap();
        assert_eq!(record.entry, entry);

        let suspend = driver.actor_suspend_operation(entry.actor).unwrap();
        assert!(suspend.catalog().is_empty());
        assert!(matches!(
            suspend.request(),
            LifecycleRequest::Suspend {
                actor,
                expected_deployment,
            } if *actor == entry.actor && *expected_deployment == entry.deployment
        ));
        let resume = driver.actor_resume_operation(entry.actor).unwrap();
        assert!(resume.catalog().is_empty());
        let remove = driver
            .actor_remove_operation(entry.actor, entry.deployment)
            .unwrap();
        assert!(remove.catalog().is_empty());

        let actor_upgrade = driver
            .actor_upgrade_operation(entry.actor, entry.deployment, &actor_package)
            .unwrap();
        assert_eq!(actor_upgrade.catalog().len(), 3);
        assert!(matches!(
            actor_upgrade.request(),
            LifecycleRequest::UpgradeActor(upgrade)
                if upgrade.actor == entry.actor
                    && upgrade.from_deployment == entry.deployment
        ));

        let target_runtime = host_surface_runtime_package("host-surface-runtime-next");
        let runtime_upgrade = driver
            .runtime_upgrade_operation(config.identity.runtime_deployment, &target_runtime)
            .unwrap();
        assert_eq!(runtime_upgrade.catalog().len(), 1);
        assert!(matches!(
            runtime_upgrade.request(),
            LifecycleRequest::UpgradeRuntime {
                from_deployment,
                to_deployment,
                package,
                ..
            } if *from_deployment == config.identity.runtime_deployment
                && *to_deployment == target_runtime.deployment_id()
                && package == &runtime_upgrade.catalog()[0].reference
        ));

        let invocation = ActorInvocation {
            invocation: InvocationId([0x93; 32]),
            actor: entry.actor,
            incarnation: record.incarnation,
            deployment: entry.deployment,
            program: entry.program,
            mode: MethodMode::Merge,
            auth: ActorInvocationAuth::anonymous(),
            message: vec![1],
            availability: Vec::new(),
            gas: 100,
        };
        let authority = signed_invocation_receipt(&config, &invocation);
        let before_invoke = driver.publication_revision();
        assert!(matches!(
            driver
                .invoke_synchronous(invocation.clone(), authority.clone())
                .unwrap(),
            LocalSettledInvocationResult::Final(_)
        ));
        assert!(
            driver.publication_revision() >= before_invoke + 2,
            "Merge source and ordered finalizer must both become durable"
        );

        let before_acknowledge = driver.publication_revision();
        assert_eq!(
            driver
                .acknowledge_invocation_synchronous(invocation.clone(), authority.clone())
                .unwrap(),
            LocalSettledAcknowledgementResult::Acknowledged
        );
        assert!(driver.publication_revision() >= before_acknowledge + 2);
        let after_acknowledge = driver.publication_revision();
        assert_eq!(
            driver.invoke_synchronous(invocation, authority).unwrap(),
            LocalSettledInvocationResult::Acknowledged
        );
        assert_eq!(
            driver.publication_revision(),
            after_acknowledge,
            "permanent acknowledgement history resolves without a new publication"
        );
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
            lifecycle_fault: None,
        }
    }

    #[test]
    fn local_lifecycle_surface_rejects_direct_system_authority_commands() {
        let sealed = super::super::replay::tests::admitted_genesis(0xe9);
        let finalize = super::super::replay::tests::admitted_finalize_for_test(&sealed, 2);
        let mut driver = standard_test_driver();
        let config = current_test_config(&driver.core.materialization);
        let dummy = LifecycleRequest::Suspend {
            actor: ActorId([0xea; 32]),
            expected_deployment: DeploymentId([0xeb; 32]),
        };
        let receipt = lifecycle_receipt(&config, &dummy, 2);
        let heads_before = driver.core.store.heads().unwrap().unwrap();
        assert!(matches!(
            driver.lifecycle(
                receipt,
                LifecycleRequest::FinalizeSystemAuthority(finalize),
                &[],
            ),
            Err(LocalJournalDriverError::Executor(
                LocalReplayExecutorError::InvalidRequest
            ))
        ));
        assert_eq!(driver.core.store.heads().unwrap().unwrap(), heads_before);
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
    fn applied_runtime_upgrade_uses_the_target_signed_state_ceiling() {
        let driver = standard_test_driver();
        let mut target =
            decode_standard_runtime_state(driver.core.materialization.state()).unwrap();
        target
            .config
            .as_mut()
            .unwrap()
            .runtime_contract
            .resources
            .max_runtime_state_bytes = super::super::execution::MAX_RUNTIME_STATE_BYTES as u32;
        let returned = encode_standard_runtime_state(&target);

        let mut current = target.config.as_ref().unwrap().clone();
        current.runtime_contract.resources.max_runtime_state_bytes = 1;
        assert!(
            driver
                .core
                .executor
                .validate_state_size(&returned, &current)
                .is_err(),
            "the successor intentionally exceeds the old signed ceiling"
        );

        let selected = driver
            .core
            .executor
            .management_state_config(&returned, &current, true)
            .unwrap();
        assert_eq!(selected, target.config.unwrap());
        driver
            .core
            .executor
            .validate_state_size(&returned, &selected)
            .unwrap();
        assert_eq!(
            driver
                .core
                .executor
                .management_state_config(&returned, &current, false)
                .unwrap(),
            current,
            "rejected and non-upgrade management stays under the current contract"
        );
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
            installation_id: crate::service::InstallationId([0xd8; 32]),
            registry_reservation: Hash([0xd9; 32]),
            entry: ActorEntry {
                actor,
                name: "historical-actor".into(),
                parent: None,
                deployment,
                program: ProgramId([0xdf; 32]),
                package: package.clone(),
                agent_schema: schema.clone(),
                role_policies: policies.clone(),
                constructor_abi: Hash([0xe1; 32]),
                installation_data: None,
                state_layout: Hash([0xe0; 32]),
                lanes: requirements.lanes,
                suspended: false,
            },
            producer: config.identity.runtime_producer,
            package,
            agent_schema: schema,
            role_policies: policies,
            constructor_abi: Hash([0xe1; 32]),
            installation_data: None,
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
            panic!("pending invocation resolved as acknowledged history")
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
            panic!("pending acknowledgement resolved as acknowledged history")
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
            "permanent acknowledged history does not retain the acknowledgement suffix anchor"
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
            lifecycle_fault: None,
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
            installation_id: crate::service::InstallationId([0xed; 32]),
            registry_reservation: Hash([0xee; 32]),
            entry: ActorEntry {
                actor,
                name: "catalog-admission".into(),
                parent: None,
                deployment,
                program,
                package: package_blob.reference.clone(),
                agent_schema: schema_blob.reference.clone(),
                role_policies: policies_blob.reference.clone(),
                constructor_abi: Hash([0xf4; 32]),
                installation_data: None,
                state_layout,
                lanes: requirements.lanes,
                suspended: false,
            },
            producer: config.identity.runtime_producer,
            package: package_blob.reference.clone(),
            agent_schema: schema_blob.reference.clone(),
            role_policies: policies_blob.reference.clone(),
            constructor_abi: Hash([0xf4; 32]),
            installation_data: None,
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
                driver.core.materialization.state(),
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
                driver.core.materialization.state(),
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
                driver.core.materialization.state(),
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
