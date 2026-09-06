//! Deterministic replay for canonical Agent lane journals.
//!
//! This module owns ordering and transition validation, not PVM execution or
//! storage policy. [`ReplaySource`] resolves authenticated journal objects and
//! [`ReplayExecutor`] runs the exact runtime named by a [`ReplayInput`]. The
//! engine then proves chain continuity, causal ordering, lane isolation,
//! lifecycle fences, duplicate handling, and Merge replay purity.

use alloc::collections::{BTreeMap, BTreeSet};
use alloc::vec;
use alloc::vec::Vec;

#[cfg(all(feature = "std", feature = "storage"))]
use super::committee::AuthorityClaimCommitment;
use super::committee::{
    RootAnchorRecord, SystemAgentGenesisAdmissionId, SystemAgentGenesisAdmissionRecord,
    SystemAgentGenesisEvidence, SystemAgentGenesisExpectations, VerifiedSystemAgentGenesis,
};
use super::execution::{
    ActorExecutionError, ActorExecutionReply, ActorExecutionStatus, MAX_RUNTIME_STATE_BYTES,
};
use super::genesis::{
    AgentGenesisAdmissionId, AgentGenesisAdmissionRecord, AgentGenesisExpectations,
    AgentReplicaCommittee, VerifiedAgentGenesisProvision,
};
use super::invocation_history::InvocationHistoryWritePlan;
#[cfg(feature = "std")]
use super::invocation_index::InvocationIndexes;
use super::invocation_index::{InvocationIndexBatchOperation, InvocationIndexLookup};
use super::journal::{
    AgentJournalGenesis, AgentJournalGenesisId, ArtifactClosure, ArtifactClosureId,
    CanonicalJournalRecord, CheckpointId, CheckpointLane, CheckpointManifest,
    InvocationAcknowledgedFact, InvocationDisposition, InvocationIndexId, InvocationIndexManifest,
    InvocationOutcomeAnchor, InvocationOutcomeId, InvocationOutcomeRecord, InvocationOutcomeRef,
    InvocationOwnershipKey, InvocationOwnershipScope, InvocationOwnershipValue,
    InvocationResultState, JournalHeads, JournalHeadsId, LaneCursor, LaneStateId,
    LaneStateManifest, LocalEntry, LocalEntryId, MergeEvent, MergeEventId, MergeFrontier,
    MergeFrontierId, MergeSeal, MergeSealId, OrderedBase, OrderedEntry, OrderedEntryId,
    PersistedLane, ReplayInput, ReplayOperation, RuntimeBinding,
    system_genesis_artifact_closure_commitment, system_genesis_post_create_state_commitment,
};
#[cfg(feature = "std")]
use super::journal::{
    MAX_INVOCATION_INDEX_LIVE_ENTRIES, MAX_INVOCATION_INDEX_RESERVED_OUTCOME_BYTES,
    MAX_INVOCATION_OUTCOME_BYTES,
};
#[cfg(feature = "std")]
use super::journal_store::{
    AgentJournalStore, JournalBlobClass, JournalPublication, JournalStoreError,
    SharedOrderedCommitStore,
};
#[cfg(all(feature = "std", feature = "storage"))]
use super::journal_store::{
    ReverifiedRootJournalStore, SystemAuthorityHistoryStore, SystemAuthorityPublicationStore,
};
use super::shared_commit::OrderedCommitClaim;
#[cfg(feature = "std")]
use super::shared_commit::{
    SharedAgentSnapshotClaim, SharedLaneProjection, SharedSealedMergeProjection,
    VerifiedSharedAgentSnapshot,
};
#[cfg(all(feature = "std", feature = "storage"))]
use super::shared_journal_driver::ValidatedSharedArtifactBatch;
use super::shared_raft::{
    AgentRaftCommand, AgentRouteKey, JournalStoreInstanceId, ReservedAgentRaftApplication,
};
use super::standard::{StandardAgentRuntime, StandardSystemAuthorityWrite};
#[cfg(all(feature = "std", feature = "storage"))]
use super::system_authority::{
    MAX_SYSTEM_AUTHORITY_CATALOG_NODE_BYTES, MAX_SYSTEM_AUTHORITY_CATALOG_RECORD_BYTES,
    MAX_SYSTEM_AUTHORITY_COMMITTEE_RECORD_BYTES, MAX_SYSTEM_AUTHORITY_ROTATION_NODE_BYTES,
    MAX_SYSTEM_AUTHORITY_ROTATION_TREE_NODES, SystemAuthorityCatalogFinalize,
    SystemAuthorityCatalogFinalizeOutcome, SystemAuthorityCatalogNode,
    SystemAuthorityCatalogWritePlan, SystemAuthorityJournalScope, SystemAuthorityRotation,
    SystemAuthorityRotationNode, SystemAuthorityRotationWritePlan, prove_catalog, prove_rotation,
};
#[cfg(feature = "std")]
use super::system_authority::{
    SystemAuthorityCatalogNodeId, SystemAuthorityCatalogRecord, SystemAuthorityCommitteeRecord,
    SystemAuthorityRotationNodeId, SystemAuthorityRotationRecord,
};
#[cfg(all(feature = "std", feature = "storage"))]
use super::system_authority_ledger::{
    PendingSystemAuthorityRecovery, ReplayedSystemAuthorityView, ReservedSystemAuthorityClaim,
    RetiredSystemAuthorityCatalog, RetiredSystemAuthorityRotation, SystemAuthorityLedgerClaim,
    SystemAuthorityLedgerError, SystemAuthorityLedgerRoute, SystemAuthorityLedgerRouteOwner,
};
use super::wire::{
    RuntimeJournalContext, RuntimeState, decode_standard_runtime_state,
    encode_standard_runtime_state,
};
use super::{
    AgentProfile, AgentReplica, AgentRuntime, InvocationResultStorage, LifecycleReply,
    LifecycleRequest, StateLane,
};
use crate::service::wire::ServiceWire;
use crate::service::{BlobRef, Hash, InvocationId, NodeId};

const LOCAL_GENESIS_ADMISSION_DOMAIN: &[u8] = b"vos/agent/local-genesis-admission/v1";

/// Maximum records replayed after one checkpoint before another checkpoint is
/// mandatory. This independently bounds an adversarial parent chain.
pub const MAX_REPLAY_SUFFIX_ENTRIES: usize = 1_024;
/// Maximum encoded journal bytes loaded for one replay suffix.
pub const MAX_REPLAY_SUFFIX_BYTES: usize = 64 * 1024 * 1024;

fn validate_runtime_state_bound<SourceError, ExecutorError>(
    state: &RuntimeState,
) -> Result<(), ReplayError<SourceError, ExecutorError>> {
    if state
        .encoded_len()
        .is_none_or(|length| length > MAX_RUNTIME_STATE_BYTES)
    {
        Err(ReplayError::ReplayLimit)
    } else {
        Ok(())
    }
}

/// Typed, bounded record lookup used by replay. Implementations must decode,
/// validate, and recompute the requested content ID before returning a record.
pub trait ReplaySource {
    type Error;

    fn ordered(&self, id: OrderedEntryId) -> Result<Option<OrderedEntry>, Self::Error>;
    fn local(&self, id: LocalEntryId) -> Result<Option<LocalEntry>, Self::Error>;
    fn merge_event(&self, id: MergeEventId) -> Result<Option<MergeEvent>, Self::Error>;
    fn merge_frontier(&self, id: MergeFrontierId) -> Result<Option<MergeFrontier>, Self::Error>;
    fn merge_seal(&self, id: MergeSealId) -> Result<Option<MergeSeal>, Self::Error>;
    fn lane_state(&self, id: LaneStateId) -> Result<Option<LaneStateManifest>, Self::Error>;
    fn artifact_closure(
        &self,
        id: ArtifactClosureId,
    ) -> Result<Option<ArtifactClosure>, Self::Error>;
    fn invocation_index(
        &self,
        id: InvocationIndexId,
    ) -> Result<Option<InvocationIndexManifest>, Self::Error>;
    fn checkpoint(&self, id: CheckpointId) -> Result<Option<CheckpointManifest>, Self::Error>;
}

/// Durable side products reported by an exact runtime transition.
///
/// None of these products has a content-addressed publication closure yet,
/// so replay rejects every transition which attempts to emit one.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct ReplayProducts {
    pub effects: bool,
    pub calls: bool,
    pub schedules: bool,
    pub proofs: bool,
}

impl ReplayProducts {
    pub const fn is_empty(self) -> bool {
        !self.effects && !self.calls && !self.schedules && !self.proofs
    }
}

/// Runtime-level disposition of one deterministic transition.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ReplayDisposition {
    /// The operation completed and its successor state is authoritative.
    Applied,
    /// The guest deterministically rejected the operation. Authority
    /// disposition state may still advance in the operation's owning lane.
    Rejected,
    /// Actor policy denied execution before application code ran.
    Forbidden,
    /// Application execution panicked or faulted.
    Panicked,
    /// Application execution exhausted its deterministic budget.
    OutOfGas,
}

impl ReplayDisposition {
    const fn is_terminal_noop(self) -> bool {
        matches!(self, Self::Forbidden | Self::Panicked | Self::OutOfGas)
    }
}

const fn invocation_disposition(disposition: ReplayDisposition) -> InvocationDisposition {
    match disposition {
        ReplayDisposition::Applied => InvocationDisposition::Applied,
        ReplayDisposition::Rejected => InvocationDisposition::Rejected,
        ReplayDisposition::Forbidden => InvocationDisposition::Forbidden,
        ReplayDisposition::Panicked => InvocationDisposition::Panicked,
        ReplayDisposition::OutOfGas => InvocationDisposition::OutOfGas,
    }
}

const fn replay_disposition(disposition: InvocationDisposition) -> ReplayDisposition {
    match disposition {
        InvocationDisposition::Applied => ReplayDisposition::Applied,
        InvocationDisposition::Rejected => ReplayDisposition::Rejected,
        InvocationDisposition::Forbidden => ReplayDisposition::Forbidden,
        InvocationDisposition::Panicked => ReplayDisposition::Panicked,
        InvocationDisposition::OutOfGas => ReplayDisposition::OutOfGas,
    }
}

/// Exact location of a replay input in journal truth.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ReplayPosition {
    Genesis,
    Ordered {
        id: OrderedEntryId,
        index: u64,
        merge_frontier: MergeFrontierId,
        merge_seal: Option<MergeSealId>,
    },
    Merge {
        id: MergeEventId,
        causal_height: u64,
        ordered_base: OrderedBase,
    },
    Local {
        id: LocalEntryId,
        node: NodeId,
        revision: u64,
        ordered_base: OrderedBase,
        merge_frontier: MergeFrontierId,
    },
}

/// Validated output of one exact runtime execution.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ReplayTransition {
    pub state: RuntimeState,
    pub disposition: ReplayDisposition,
    /// Exact actor result for `Invoke`; management and acknowledgement
    /// transitions must leave this absent. Replay validates that the result
    /// derives the separately reported disposition and is safe to retain.
    pub result: Option<Result<ActorExecutionReply, ActorExecutionError>>,
    /// Runtime selected after this operation. It changes only after a
    /// successfully applied `UpgradeRuntime` management entry.
    pub next_runtime: RuntimeBinding,
    pub products: ReplayProducts,
}

/// One live authority execution selected by replay provenance. The guest
/// receives only `context`; native revalidation additionally consumes the
/// opaque `scope`. Neither member is wire authority on its own.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
struct ReplaySystemAuthorityExecution {
    context: RuntimeJournalContext,
    scope: super::system_authority::SystemAuthorityJournalScope,
}

impl ReplaySystemAuthorityExecution {
    fn from_replayed_root(
        identity: &ReplayedRootJournalIdentity,
    ) -> Result<Self, super::system_authority::SystemAuthorityError> {
        Ok(Self {
            context: RuntimeJournalContext::from_replayed_root(identity)?,
            scope: super::system_authority::SystemAuthorityJournalScope::from_replayed_root(
                identity,
            )?,
        })
    }
}

/// Runtime and Merge-authentication seam. The executor is responsible for
/// resolving exact packages/programs and for verifying the event author's
/// authority-certified signing key.
pub trait ReplayExecutor {
    type Error;

    fn verify_merge_event(&mut self, event: &MergeEvent) -> Result<bool, Self::Error>;

    /// Authenticate one canonical input against the exact pre-transition
    /// runtime state without executing application code or consuming an
    /// authority sequence/slot.
    ///
    /// Replay invokes this before consulting invocation ownership. This is a
    /// trust boundary: an exact retry, divergent reuse, or already-acknowledged
    /// request must never become durable merely because it can take an
    /// ownership short circuit. Implementations must verify the same receipt,
    /// authority binding, operation, space, and agent facts as execution,
    /// while deliberately leaving target and logical-slot freshness to
    /// [`Self::execute`]. Exact committed work remains recoverable after its
    /// original receipt window expires; only unseen execution applies that
    /// window.
    fn authenticate(
        &mut self,
        input: &ReplayInput,
        before: &RuntimeState,
        position: ReplayPosition,
    ) -> Result<(), Self::Error>;

    fn execute(
        &mut self,
        input: &ReplayInput,
        before: &RuntimeState,
        position: ReplayPosition,
    ) -> Result<ReplayTransition, Self::Error>;

    /// Execute with replay-authenticated journal context. Executors which do
    /// not understand the bundled Standard runtime deliberately receive no
    /// additional authority: the default discards this data-only context,
    /// while replay still performs native scoped revalidation of the result.
    fn execute_with_journal_context(
        &mut self,
        input: &ReplayInput,
        before: &RuntimeState,
        position: ReplayPosition,
        journal_context: Option<RuntimeJournalContext>,
    ) -> Result<ReplayTransition, Self::Error> {
        let _ = journal_context;
        self.execute(input, before, position)
    }
}

/// A QC-authenticated Control/Linear snapshot older than the locally retained
/// ordered suffix.
///
/// Fields are deliberately private and this module exposes no constructor.
/// The future Shared resolver adapter will verify its Raft ordered-snapshot QC
/// before constructing this value. A caller cannot turn raw bytes, or an
/// ordinary checkpoint, into old-base replay authority.
pub struct ResolvedOrderedSnapshot {
    genesis: AgentJournalGenesisId,
    canonical_head: OrderedBase,
    base: OrderedBase,
    runtime: RuntimeBinding,
    control: Vec<u8>,
    linear: Vec<u8>,
    control_commitment: BlobRef,
    linear_commitment: BlobRef,
    evidence_commitment: Hash,
}

/// Trust boundary for an ordered base older than the locally retained suffix.
/// Local-only integration may deliberately refuse every such lookup. Shared
/// integration must authenticate the complete snapshot with its Raft-QC
/// ordered-snapshot certificate; a checkpoint by itself is not an implicit
/// lifecycle fence or historical-state certificate.
pub trait OrderedBaseResolver {
    type Error;

    fn snapshot_at(
        &self,
        genesis: AgentJournalGenesisId,
        canonical_head: OrderedBase,
        base: OrderedBase,
    ) -> Result<Option<ResolvedOrderedSnapshot>, Self::Error>;
}

/// Resolver used by Local-only integration: pruned ordered bases are simply
/// unavailable rather than being inferred from a newer checkpoint.
#[derive(Clone, Copy, Debug, Default)]
pub struct NoPrunedOrderedBases;

impl OrderedBaseResolver for NoPrunedOrderedBases {
    type Error = core::convert::Infallible;

    fn snapshot_at(
        &self,
        _genesis: AgentJournalGenesisId,
        _canonical_head: OrderedBase,
        _base: OrderedBase,
    ) -> Result<Option<ResolvedOrderedSnapshot>, Self::Error> {
        Ok(None)
    }
}

/// Deterministic failure before a derived state can be published.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum ReplayError<SourceError, ExecutorError> {
    Source(SourceError),
    Executor(ExecutorError),
    MissingOrdered(OrderedEntryId),
    MissingLocal(LocalEntryId),
    MissingMergeEvent(MergeEventId),
    MissingMergeFrontier(MergeFrontierId),
    MissingMergeSeal(MergeSealId),
    MissingLaneState(LaneStateId),
    MissingArtifactClosure(ArtifactClosureId),
    MissingInvocationIndex(InvocationIndexId),
    MissingCheckpoint(CheckpointId),
    InvalidRecord,
    ScopeMismatch,
    ChainMismatch,
    ReplayLimit,
    InvalidCausalHeight,
    NonMinimalFrontier,
    StaleMergeBranch(MergeEventId),
    UnauthenticatedMergeEvent(MergeEventId),
    InvalidOrderedBase,
    UnavailableOrderedBase,
    InvalidFence,
    StalePreFenceEvent(MergeEventId),
    RuntimeMismatch,
    InvalidRuntimeUpgrade,
    InvalidManagementTransition,
    InvalidPosition,
    CrossLaneMutation,
    TerminalMutation,
    ForbiddenMergeProducts,
    /// Authenticated live invocation refused before any durable transition.
    /// The caller may return this typed error without publishing a journal
    /// entry or ownership leaf.
    UncommittedInvocation(ActorExecutionError),
    InvocationOwnership(InvocationOwnershipError),
}

/// Distinguishes physical journal failures from the independently trusted
/// ordered-snapshot resolver used for pruned bases.
#[cfg(feature = "std")]
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum ReplayMaterializationSourceError<ResolverError> {
    Journal(JournalStoreError),
    Resolver(ResolverError),
}

impl<SourceError, ExecutorError> ReplayError<SourceError, ExecutorError> {
    pub(crate) fn map_source<NextSourceError>(
        self,
        map: impl FnOnce(SourceError) -> NextSourceError,
    ) -> ReplayError<NextSourceError, ExecutorError> {
        match self {
            Self::Source(error) => ReplayError::Source(map(error)),
            Self::Executor(error) => ReplayError::Executor(error),
            Self::MissingOrdered(id) => ReplayError::MissingOrdered(id),
            Self::MissingLocal(id) => ReplayError::MissingLocal(id),
            Self::MissingMergeEvent(id) => ReplayError::MissingMergeEvent(id),
            Self::MissingMergeFrontier(id) => ReplayError::MissingMergeFrontier(id),
            Self::MissingMergeSeal(id) => ReplayError::MissingMergeSeal(id),
            Self::MissingLaneState(id) => ReplayError::MissingLaneState(id),
            Self::MissingArtifactClosure(id) => ReplayError::MissingArtifactClosure(id),
            Self::MissingInvocationIndex(id) => ReplayError::MissingInvocationIndex(id),
            Self::MissingCheckpoint(id) => ReplayError::MissingCheckpoint(id),
            Self::InvalidRecord => ReplayError::InvalidRecord,
            Self::ScopeMismatch => ReplayError::ScopeMismatch,
            Self::ChainMismatch => ReplayError::ChainMismatch,
            Self::ReplayLimit => ReplayError::ReplayLimit,
            Self::InvalidCausalHeight => ReplayError::InvalidCausalHeight,
            Self::NonMinimalFrontier => ReplayError::NonMinimalFrontier,
            Self::StaleMergeBranch(id) => ReplayError::StaleMergeBranch(id),
            Self::UnauthenticatedMergeEvent(id) => ReplayError::UnauthenticatedMergeEvent(id),
            Self::InvalidOrderedBase => ReplayError::InvalidOrderedBase,
            Self::UnavailableOrderedBase => ReplayError::UnavailableOrderedBase,
            Self::InvalidFence => ReplayError::InvalidFence,
            Self::StalePreFenceEvent(id) => ReplayError::StalePreFenceEvent(id),
            Self::RuntimeMismatch => ReplayError::RuntimeMismatch,
            Self::InvalidRuntimeUpgrade => ReplayError::InvalidRuntimeUpgrade,
            Self::InvalidManagementTransition => ReplayError::InvalidManagementTransition,
            Self::InvalidPosition => ReplayError::InvalidPosition,
            Self::CrossLaneMutation => ReplayError::CrossLaneMutation,
            Self::TerminalMutation => ReplayError::TerminalMutation,
            Self::ForbiddenMergeProducts => ReplayError::ForbiddenMergeProducts,
            Self::UncommittedInvocation(error) => ReplayError::UncommittedInvocation(error),
            Self::InvocationOwnership(error) => ReplayError::InvocationOwnership(error),
        }
    }

    pub(crate) fn map_executor<NextExecutorError>(
        self,
        map: impl FnOnce(ExecutorError) -> NextExecutorError,
    ) -> ReplayError<SourceError, NextExecutorError> {
        match self {
            Self::Source(error) => ReplayError::Source(error),
            Self::Executor(error) => ReplayError::Executor(map(error)),
            Self::MissingOrdered(id) => ReplayError::MissingOrdered(id),
            Self::MissingLocal(id) => ReplayError::MissingLocal(id),
            Self::MissingMergeEvent(id) => ReplayError::MissingMergeEvent(id),
            Self::MissingMergeFrontier(id) => ReplayError::MissingMergeFrontier(id),
            Self::MissingMergeSeal(id) => ReplayError::MissingMergeSeal(id),
            Self::MissingLaneState(id) => ReplayError::MissingLaneState(id),
            Self::MissingArtifactClosure(id) => ReplayError::MissingArtifactClosure(id),
            Self::MissingInvocationIndex(id) => ReplayError::MissingInvocationIndex(id),
            Self::MissingCheckpoint(id) => ReplayError::MissingCheckpoint(id),
            Self::InvalidRecord => ReplayError::InvalidRecord,
            Self::ScopeMismatch => ReplayError::ScopeMismatch,
            Self::ChainMismatch => ReplayError::ChainMismatch,
            Self::ReplayLimit => ReplayError::ReplayLimit,
            Self::InvalidCausalHeight => ReplayError::InvalidCausalHeight,
            Self::NonMinimalFrontier => ReplayError::NonMinimalFrontier,
            Self::StaleMergeBranch(id) => ReplayError::StaleMergeBranch(id),
            Self::UnauthenticatedMergeEvent(id) => ReplayError::UnauthenticatedMergeEvent(id),
            Self::InvalidOrderedBase => ReplayError::InvalidOrderedBase,
            Self::UnavailableOrderedBase => ReplayError::UnavailableOrderedBase,
            Self::InvalidFence => ReplayError::InvalidFence,
            Self::StalePreFenceEvent(id) => ReplayError::StalePreFenceEvent(id),
            Self::RuntimeMismatch => ReplayError::RuntimeMismatch,
            Self::InvalidRuntimeUpgrade => ReplayError::InvalidRuntimeUpgrade,
            Self::InvalidManagementTransition => ReplayError::InvalidManagementTransition,
            Self::InvalidPosition => ReplayError::InvalidPosition,
            Self::CrossLaneMutation => ReplayError::CrossLaneMutation,
            Self::TerminalMutation => ReplayError::TerminalMutation,
            Self::ForbiddenMergeProducts => ReplayError::ForbiddenMergeProducts,
            Self::UncommittedInvocation(error) => ReplayError::UncommittedInvocation(error),
            Self::InvocationOwnership(error) => ReplayError::InvocationOwnership(error),
        }
    }
}

/// Only refusals which occur after receipt authentication but before any
/// executable/durable admission may be returned as a normal nonpublication.
/// Structural, ownership, authorization, and implementation-bug variants stay
/// fail-closed.
const fn is_uncommitted_refusal(error: ActorExecutionError) -> bool {
    matches!(
        error,
        ActorExecutionError::UnsupportedResultStorage
            | ActorExecutionError::MissingState
            | ActorExecutionError::InvalidAvailability
            | ActorExecutionError::ResultCapacity
            | ActorExecutionError::AuthorityExpired
            | ActorExecutionError::AuthoritySlotRegressed
    )
}

/// A refusal is legal only for an input which has not crossed a heads CAS.
/// Encountering one while rebuilding authenticated history proves the stored
/// publication was impossible and is therefore corruption.
fn historical_replay_error<SourceError, ExecutorError>(
    error: ReplayError<SourceError, ExecutorError>,
) -> ReplayError<SourceError, ExecutorError> {
    match error {
        ReplayError::UncommittedInvocation(_) => ReplayError::InvalidRecord,
        error => error,
    }
}

pub type ReplayValidationError = ReplayError<core::convert::Infallible, core::convert::Infallible>;

/// Fully validated Control/Linear prefix in ascending index order.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct OrderedReplay {
    pub genesis: AgentJournalGenesisId,
    /// Authenticated checkpoint cursor excluded from `entries`.
    pub checkpoint: OrderedBase,
    pub base: OrderedBase,
    entries: Vec<(OrderedEntryId, OrderedEntry)>,
    runtime_history: BTreeMap<OrderedBase, RuntimeBinding>,
}

impl OrderedReplay {
    pub fn entries(&self) -> &[(OrderedEntryId, OrderedEntry)] {
        &self.entries
    }

    pub fn contains_base(&self, base: OrderedBase) -> bool {
        if base == self.checkpoint {
            return true;
        }
        if base.index <= self.checkpoint.index || base.index > self.base.index {
            return false;
        }
        let Ok(index) = usize::try_from(base.index - self.checkpoint.index - 1) else {
            return false;
        };
        self.entries
            .get(index)
            .is_some_and(|(id, entry)| Some(*id) == base.head && entry.index == base.index)
    }

    /// Runtime selected after replaying the exact ordered base. Structural
    /// loading alone cannot populate this map; values appear only from an
    /// authenticated checkpoint binding or exact ordered execution.
    pub fn runtime_at(&self, base: OrderedBase) -> Option<&RuntimeBinding> {
        self.runtime_history.get(&base)
    }
}

/// Fully validated Local prefix for one exact node.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct LocalReplay {
    pub genesis: AgentJournalGenesisId,
    pub node: NodeId,
    pub checkpoint_revision: u64,
    pub checkpoint_head: Option<LocalEntryId>,
    pub revision: u64,
    entries: Vec<(LocalEntryId, LocalEntry)>,
}

impl LocalReplay {
    pub fn entries(&self) -> &[(LocalEntryId, LocalEntry)] {
        &self.entries
    }
}

/// Reachable Merge events in canonical `(causal_height, EventId)` order.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct MergeReplay {
    pub genesis: AgentJournalGenesisId,
    /// Authenticated sealed frontier excluded from `events`.
    pub checkpoint_frontier: MergeFrontierId,
    pub frontier_id: MergeFrontierId,
    pub frontier: MergeFrontier,
    events: Vec<(MergeEventId, MergeEvent)>,
    ancestry: BTreeSet<MergeEventId>,
}

impl MergeReplay {
    pub fn events(&self) -> &[(MergeEventId, MergeEvent)] {
        &self.events
    }

    pub fn contains(&self, event: MergeEventId) -> bool {
        self.ancestry.contains(&event)
    }
}

/// Retained causal roots of a sealed Merge checkpoint. Parent records before
/// these tips may be garbage-collected.
#[derive(Clone, Debug, PartialEq, Eq)]
struct SealedMergeBase {
    structural: StructuralMergeBase,
}

/// Content-validated frontier metadata with no durable-head provenance. This
/// is deliberately a different type from [`SealedMergeBase`]: resolving an
/// unreferenced frontier object can never establish a replay boundary.
#[derive(Clone, Debug, PartialEq, Eq)]
struct StructuralMergeBase {
    genesis: AgentJournalGenesisId,
    frontier_id: MergeFrontierId,
    /// Strictly ordered retained frontier tips and their structural heights.
    roots: Vec<SealedMergeRoot>,
}

#[derive(Clone, Debug, PartialEq, Eq)]
struct SealedMergeRoot {
    id: MergeEventId,
    causal_height: u64,
    ordered_base: OrderedBase,
    runtime: RuntimeBinding,
}

impl SealedMergeBase {
    const fn genesis(&self) -> AgentJournalGenesisId {
        self.structural.genesis
    }

    const fn frontier_id(&self) -> MergeFrontierId {
        self.structural.frontier_id
    }

    fn roots(&self) -> &[SealedMergeRoot] {
        &self.structural.roots
    }
}

/// Load and validate an ordered parent chain.
pub fn load_ordered_replay<S: ReplaySource>(
    source: &S,
    genesis: AgentJournalGenesisId,
    base: OrderedBase,
) -> Result<OrderedReplay, ReplayError<S::Error, core::convert::Infallible>> {
    load_ordered_suffix(source, genesis, OrderedBase::post_genesis(), base)
}

/// Load only the ordered suffix after an authenticated checkpoint cursor.
/// The checkpoint record itself may already have been garbage-collected; the
/// first retained entry must link to its exact content ID.
pub fn load_ordered_suffix<S: ReplaySource>(
    source: &S,
    genesis: AgentJournalGenesisId,
    checkpoint: OrderedBase,
    target: OrderedBase,
) -> Result<OrderedReplay, ReplayError<S::Error, core::convert::Infallible>> {
    if genesis == AgentJournalGenesisId::ZERO
        || checkpoint.validate().is_err()
        || target.validate().is_err()
        || checkpoint.index > target.index
        || (checkpoint.index == target.index && checkpoint != target)
    {
        return Err(ReplayError::InvalidRecord);
    }
    if checkpoint == target {
        return Ok(OrderedReplay {
            genesis,
            checkpoint,
            base: target,
            entries: Vec::new(),
            runtime_history: BTreeMap::new(),
        });
    }

    let mut expected_id = target.head.ok_or(ReplayError::ChainMismatch)?;
    let mut expected_index = target.index;
    let mut encoded_bytes = 0usize;
    let mut reversed = Vec::new();
    loop {
        let entry = source
            .ordered(expected_id)
            .map_err(ReplayError::Source)?
            .ok_or(ReplayError::MissingOrdered(expected_id))?;
        validate_loaded_record(&entry, expected_id, genesis, &mut encoded_bytes)?;
        if entry.index != expected_index {
            return Err(ReplayError::ChainMismatch);
        }
        reversed.push((expected_id, entry));
        enforce_entry_count(reversed.len())?;
        if expected_index == checkpoint.index + 1 {
            if reversed.last().and_then(|(_, entry)| entry.parent) != checkpoint.head {
                return Err(ReplayError::ChainMismatch);
            }
            break;
        }
        expected_index -= 1;
        expected_id = reversed
            .last()
            .and_then(|(_, entry)| entry.parent)
            .ok_or(ReplayError::ChainMismatch)?;
    }
    reversed.reverse();
    Ok(OrderedReplay {
        genesis,
        checkpoint,
        base: target,
        entries: reversed,
        runtime_history: BTreeMap::new(),
    })
}

/// Load an ordered suffix with the runtime binding authenticated by its
/// checkpoint manifest. Later bases are populated by
/// [`ReplayMachine::apply_ordered_entry`].
pub fn load_checkpoint_ordered_suffix<S: ReplaySource>(
    source: &S,
    checkpoint_id: CheckpointId,
    target: OrderedBase,
) -> Result<OrderedReplay, ReplayError<S::Error, core::convert::Infallible>> {
    let checkpoint = source
        .checkpoint(checkpoint_id)
        .map_err(ReplayError::Source)?
        .ok_or(ReplayError::MissingCheckpoint(checkpoint_id))?;
    if checkpoint.validate().is_err() || checkpoint.id() != checkpoint_id {
        return Err(ReplayError::InvalidRecord);
    }
    let base = OrderedBase {
        index: checkpoint.ordered_index,
        head: checkpoint.ordered_head,
    };
    let mut replay = load_ordered_suffix(source, checkpoint.genesis, base, target)?;
    replay.runtime_history.insert(base, checkpoint.runtime);
    Ok(replay)
}

/// Load and validate one node's Local parent chain.
pub fn load_local_replay<S: ReplaySource>(
    source: &S,
    genesis: AgentJournalGenesisId,
    node: NodeId,
    revision: u64,
    head: Option<LocalEntryId>,
) -> Result<LocalReplay, ReplayError<S::Error, core::convert::Infallible>> {
    load_local_suffix(source, genesis, node, 0, None, revision, head)
}

/// Load only one node's Local suffix after an authenticated checkpoint.
pub fn load_local_suffix<S: ReplaySource>(
    source: &S,
    genesis: AgentJournalGenesisId,
    node: NodeId,
    checkpoint_revision: u64,
    checkpoint_head: Option<LocalEntryId>,
    revision: u64,
    head: Option<LocalEntryId>,
) -> Result<LocalReplay, ReplayError<S::Error, core::convert::Infallible>> {
    if genesis == AgentJournalGenesisId::ZERO
        || node == NodeId::ZERO
        || (checkpoint_revision == 0) != checkpoint_head.is_none()
        || (revision == 0) != head.is_none()
        || checkpoint_revision > revision
        || (checkpoint_revision == revision && checkpoint_head != head)
    {
        return Err(ReplayError::InvalidRecord);
    }
    if checkpoint_revision == revision {
        return Ok(LocalReplay {
            genesis,
            node,
            checkpoint_revision,
            checkpoint_head,
            revision,
            entries: Vec::new(),
        });
    }

    let mut expected_id = head.ok_or(ReplayError::ChainMismatch)?;
    let mut expected_revision = revision;
    let mut encoded_bytes = 0usize;
    let mut reversed = Vec::new();
    loop {
        let entry = source
            .local(expected_id)
            .map_err(ReplayError::Source)?
            .ok_or(ReplayError::MissingLocal(expected_id))?;
        validate_loaded_record(&entry, expected_id, genesis, &mut encoded_bytes)?;
        if entry.node != node || entry.revision != expected_revision {
            return Err(ReplayError::ChainMismatch);
        }
        reversed.push((expected_id, entry));
        enforce_entry_count(reversed.len())?;
        if expected_revision == checkpoint_revision + 1 {
            if reversed.last().and_then(|(_, entry)| entry.parent) != checkpoint_head {
                return Err(ReplayError::ChainMismatch);
            }
            break;
        }
        expected_revision -= 1;
        expected_id = reversed
            .last()
            .and_then(|(_, entry)| entry.parent)
            .ok_or(ReplayError::ChainMismatch)?;
    }
    reversed.reverse();
    Ok(LocalReplay {
        genesis,
        node,
        checkpoint_revision,
        checkpoint_head,
        revision,
        entries: reversed,
    })
}

/// Load a complete causal closure, verify heights, and derive its minimal
/// advertised frontier. Exact duplicate IDs encountered through multiple
/// parent paths are loaded once.
pub fn load_merge_replay<S: ReplaySource>(
    source: &S,
    genesis: AgentJournalGenesisId,
    frontier_id: MergeFrontierId,
) -> Result<MergeReplay, ReplayError<S::Error, core::convert::Infallible>> {
    let empty = MergeFrontier {
        genesis,
        events: Vec::new(),
    };
    load_structural_merge_suffix(
        source,
        &StructuralMergeBase {
            genesis,
            frontier_id: empty.id(),
            roots: Vec::new(),
        },
        frontier_id,
    )
}

/// Resolve only the retained tips and heights of a checkpoint frontier. Tip
/// parents are deliberately not followed.
/// Resolve a sealed base only through an immutable, content-identified
/// checkpoint. Callers cannot manufacture retained root IDs or heights.
/// Structural helper only. A result from this function is not a replay trust
/// token: callers in this module may use it only after the frontier was bound
/// to an exact durable-head/checkpoint materialization and its retained tips
/// were executor-authenticated.
fn load_structural_merge_base<S: ReplaySource>(
    source: &S,
    genesis: AgentJournalGenesisId,
    frontier_id: MergeFrontierId,
) -> Result<StructuralMergeBase, ReplayError<S::Error, core::convert::Infallible>> {
    if genesis == AgentJournalGenesisId::ZERO || frontier_id == MergeFrontierId::ZERO {
        return Err(ReplayError::InvalidRecord);
    }
    let frontier = source
        .merge_frontier(frontier_id)
        .map_err(ReplayError::Source)?
        .ok_or(ReplayError::MissingMergeFrontier(frontier_id))?;
    if frontier.validate().is_err() || frontier.id() != frontier_id || frontier.genesis != genesis {
        return Err(ReplayError::InvalidRecord);
    }
    let mut roots = Vec::new();
    for id in &frontier.events {
        let event = source
            .merge_event(*id)
            .map_err(ReplayError::Source)?
            .ok_or(ReplayError::MissingMergeEvent(*id))?;
        if event.validate().is_err() || event.id() != *id || event.genesis != genesis {
            return Err(ReplayError::InvalidRecord);
        }
        roots.push(SealedMergeRoot {
            id: *id,
            causal_height: event.causal_height,
            ordered_base: event.ordered_base,
            runtime: event.input.runtime,
        });
    }
    Ok(StructuralMergeBase {
        genesis,
        frontier_id,
        roots,
    })
}

/// Load the causal suffix after a sealed frontier. Every new branch must
/// reach one of the retained sealed tips (or be a root when the sealed
/// frontier is empty); branching from a pruned internal ancestor is stale.
fn load_merge_suffix<S: ReplaySource>(
    source: &S,
    checkpoint: &SealedMergeBase,
    frontier_id: MergeFrontierId,
) -> Result<MergeReplay, ReplayError<S::Error, core::convert::Infallible>> {
    load_structural_merge_suffix(source, &checkpoint.structural, frontier_id)
}

fn load_structural_merge_suffix<S: ReplaySource>(
    source: &S,
    checkpoint: &StructuralMergeBase,
    frontier_id: MergeFrontierId,
) -> Result<MergeReplay, ReplayError<S::Error, core::convert::Infallible>> {
    if checkpoint.genesis == AgentJournalGenesisId::ZERO
        || checkpoint.frontier_id == MergeFrontierId::ZERO
        || checkpoint
            .roots
            .windows(2)
            .any(|pair| pair[0].id >= pair[1].id)
        || checkpoint
            .roots
            .iter()
            .any(|root| root.id == MergeEventId::ZERO || root.causal_height == 0)
    {
        return Err(ReplayError::InvalidRecord);
    }
    let frontier = source
        .merge_frontier(frontier_id)
        .map_err(ReplayError::Source)?
        .ok_or(ReplayError::MissingMergeFrontier(frontier_id))?;
    if frontier.validate().is_err()
        || frontier.id() != frontier_id
        || frontier.genesis != checkpoint.genesis
    {
        return Err(ReplayError::InvalidRecord);
    }

    let mut encoded_bytes = frontier.encode().len();
    enforce_byte_count(encoded_bytes)?;
    let roots = checkpoint
        .roots
        .iter()
        .map(|root| (root.id, root))
        .collect::<BTreeMap<_, _>>();
    let mut pending = frontier.events.clone();
    let mut loaded = BTreeMap::<MergeEventId, MergeEvent>::new();
    while let Some(id) = pending.pop() {
        if roots.contains_key(&id) || loaded.contains_key(&id) {
            continue;
        }
        let event = source
            .merge_event(id)
            .map_err(ReplayError::Source)?
            .ok_or(ReplayError::MissingMergeEvent(id))?;
        validate_loaded_record(&event, id, checkpoint.genesis, &mut encoded_bytes)?;
        pending.extend(event.parents.iter().copied());
        loaded.insert(id, event);
        enforce_entry_count(loaded.len())?;
    }

    for event in loaded.values() {
        let expected_height = if event.parents.is_empty() {
            if roots.is_empty() {
                1
            } else {
                return Err(ReplayError::StaleMergeBranch(event.id()));
            }
        } else {
            event
                .parents
                .iter()
                .map(|parent| {
                    loaded
                        .get(parent)
                        .map(|event| event.causal_height)
                        .or_else(|| roots.get(parent).map(|root| root.causal_height))
                        .ok_or(ReplayError::ChainMismatch)
                })
                .collect::<Result<Vec<_>, _>>()?
                .into_iter()
                .max()
                .and_then(|height| height.checked_add(1))
                .ok_or(ReplayError::InvalidCausalHeight)?
        };
        if event.causal_height != expected_height {
            return Err(ReplayError::InvalidCausalHeight);
        }
    }

    let mut events = loaded.into_iter().collect::<Vec<_>>();
    events.sort_unstable_by_key(|(id, event)| (event.causal_height, *id));

    for (_, event) in &events {
        for parent in &event.parents {
            let parent_base = events
                .iter()
                .find(|(id, _)| id == parent)
                .map(|(_, event)| event.ordered_base)
                .or_else(|| roots.get(parent).map(|root| root.ordered_base))
                .ok_or(ReplayError::ChainMismatch)?;
            if parent_base.index > event.ordered_base.index
                || (parent_base.index == event.ordered_base.index
                    && parent_base.head != event.ordered_base.head)
            {
                return Err(ReplayError::InvalidOrderedBase);
            }
        }
    }

    // Re-derive maximal tips from the complete topological order. A frontier
    // which contains an ancestor beside its descendant is non-minimal.
    let mut derived = roots.keys().copied().collect::<BTreeSet<_>>();
    for (id, event) in &events {
        for parent in &event.parents {
            derived.remove(parent);
        }
        derived.insert(*id);
    }
    if !derived.iter().copied().eq(frontier.events.iter().copied()) {
        return Err(ReplayError::NonMinimalFrontier);
    }

    Ok(MergeReplay {
        genesis: checkpoint.genesis,
        checkpoint_frontier: checkpoint.frontier_id,
        frontier_id,
        frontier,
        ancestry: roots
            .keys()
            .copied()
            .chain(events.iter().map(|(id, _)| *id))
            .collect(),
        events,
    })
}

/// Prove that every cross-lane base names the same canonical ordered chain
/// and that an ordered input never depends on a Merge event admitted at that
/// input or a later index.
pub fn validate_cross_lane_bases<SourceError, ExecutorError>(
    ordered: &OrderedReplay,
    merge: &MergeReplay,
    consuming_ordered_index: Option<u64>,
) -> Result<(), ReplayError<SourceError, ExecutorError>> {
    if ordered.genesis != merge.genesis {
        return Err(ReplayError::ScopeMismatch);
    }
    for (_, event) in &merge.events {
        if !ordered.contains_base(event.ordered_base)
            || consuming_ordered_index.is_some_and(|index| event.ordered_base.index >= index)
        {
            return Err(ReplayError::InvalidOrderedBase);
        }
    }
    Ok(())
}

/// Monotone Raft-owned fence installed by a management entry.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct MergeFence {
    pub ordered_index: u64,
    pub ordered_head: OrderedEntryId,
    pub frontier: MergeFrontierId,
    seal: MergeSealId,
    sealed_ancestry: BTreeSet<MergeEventId>,
}

impl MergeFence {
    /// A pre-fence event is admissible only when it was already in the
    /// ancestry sealed by Raft. Such an import is an exact duplicate/no-op;
    /// a genuinely late branch is permanently stale.
    pub fn admit<SourceError, ExecutorError>(
        &self,
        id: MergeEventId,
        event: &MergeEvent,
    ) -> Result<(), ReplayError<SourceError, ExecutorError>> {
        if event.ordered_base.index < self.ordered_index && !self.sealed_ancestry.contains(&id) {
            return Err(ReplayError::StalePreFenceEvent(id));
        }
        Ok(())
    }

    pub fn is_sealed_duplicate(&self, id: MergeEventId, event: &MergeEvent) -> bool {
        event.ordered_base.index < self.ordered_index && self.sealed_ancestry.contains(&id)
    }

    pub const fn seal(&self) -> MergeSealId {
        self.seal
    }
}

/// Authenticate the exact Merge state and causal closure consumed by one
/// ordered lifecycle or seal-only mutation. The returned fence becomes effective when the
/// ordered entry itself is committed, regardless of whether guest policy
/// applies or rejects the requested mutation.
fn validate_management_fence_inner<S: ReplaySource, F>(
    source: &S,
    entry_id: OrderedEntryId,
    entry: &OrderedEntry,
    ordered: &OrderedReplay,
    merge: &MergeReplay,
    merge_state: &[u8],
    pruned_base_is_authenticated: F,
) -> Result<MergeFence, ReplayError<S::Error, core::convert::Infallible>>
where
    F: Fn(&MergeEvent) -> bool,
{
    let seal_id = entry.merge_seal.ok_or(ReplayError::InvalidFence)?;
    if entry.id() != entry_id
        || entry.genesis != merge.genesis
        || entry.merge_frontier != merge.frontier_id
        || !matches!(
            entry.input.operation,
            ReplayOperation::Management { .. } | ReplayOperation::SealMerge
        )
    {
        return Err(ReplayError::InvalidFence);
    }
    let seal = source
        .merge_seal(seal_id)
        .map_err(ReplayError::Source)?
        .ok_or(ReplayError::MissingMergeSeal(seal_id))?;
    let ordered_base = OrderedBase {
        index: entry.index - 1,
        head: entry.parent,
    };
    if ordered.genesis != entry.genesis || ordered.base != ordered_base {
        return Err(ReplayError::InvalidFence);
    }
    for (_, event) in merge.events() {
        if event.ordered_base.index >= entry.index
            || (!ordered.contains_base(event.ordered_base) && !pruned_base_is_authenticated(event))
        {
            return Err(ReplayError::InvalidOrderedBase);
        }
    }
    if seal.validate().is_err()
        || seal.id() != seal_id
        || seal.genesis != entry.genesis
        || seal.frontier != entry.merge_frontier
        || seal.ordered_base != ordered_base
    {
        return Err(ReplayError::InvalidFence);
    }

    let manifest = LaneStateManifest {
        genesis: entry.genesis,
        runtime: entry.input.runtime.clone(),
        lane: PersistedLane::Merge,
        cursor: LaneCursor::Merge {
            frontier: entry.merge_frontier,
        },
        state: BlobRef::of_bytes(merge_state),
    };
    if manifest.validate().is_err() || manifest.id() != seal.merge_state {
        return Err(ReplayError::InvalidFence);
    }
    let stored = source
        .lane_state(seal.merge_state)
        .map_err(ReplayError::Source)?
        .ok_or(ReplayError::MissingLaneState(seal.merge_state))?;
    if stored != manifest || stored.id() != seal.merge_state {
        return Err(ReplayError::InvalidFence);
    }

    Ok(MergeFence {
        ordered_index: entry.index,
        ordered_head: entry_id,
        frontier: entry.merge_frontier,
        seal: seal_id,
        sealed_ancestry: merge.ancestry.clone(),
    })
}

/// Result reported for one journal input after duplicate and lane validation.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ReplayStepOutcome {
    Applied(ReplayDisposition),
    ExactDuplicate,
    DivergentInvocation,
}

/// Replay-only durable authority objects selected by native scoped
/// revalidation. The operation commitment prevents a plan selected for one
/// command from being attached to another command with replaceable proofs.
/// Storage integration consumes this private token in batch 5c.
#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) struct ReplaySystemAuthorityWrite {
    operation: Hash,
    result: LifecycleReply,
    selected: StandardSystemAuthorityWrite,
    predecessor_control: Vec<u8>,
    successor_control: Vec<u8>,
    predecessor_authority: super::system_authority::SystemAuthorityState,
    successor_authority: super::system_authority::SystemAuthorityState,
}

impl ReplaySystemAuthorityWrite {
    pub(crate) const fn operation(&self) -> Hash {
        self.operation
    }

    pub(crate) const fn selected(&self) -> &StandardSystemAuthorityWrite {
        &self.selected
    }

    pub(crate) const fn result(&self) -> &LifecycleReply {
        &self.result
    }

    pub(crate) fn predecessor_control(&self) -> &[u8] {
        &self.predecessor_control
    }

    pub(crate) fn successor_control(&self) -> &[u8] {
        &self.successor_control
    }

    pub(crate) const fn predecessor_authority(
        &self,
    ) -> &super::system_authority::SystemAuthorityState {
        &self.predecessor_authority
    }

    pub(crate) const fn successor_authority(
        &self,
    ) -> &super::system_authority::SystemAuthorityState {
        &self.successor_authority
    }
}

/// Exact permanent authority-history result which must be visible before the
/// corresponding Control successor becomes reachable through `heads`.
///
/// This value is replay-private storage data, not an admission capability.
/// In particular, an ordinary decision fact becomes usable only after the
/// later destination-journal bridge consumes a post-CAS receipt.
#[cfg(feature = "std")]
#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) struct ReplaySystemAuthorityHistory {
    record: SystemAuthorityRotationRecord,
    root: SystemAuthorityRotationNodeId,
}

/// Exact permanent catalog receipt and sparse-history root selected by the
/// replay-authenticated native transition.
#[cfg(feature = "std")]
#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) struct ReplaySystemAuthorityCatalogHistory {
    record: SystemAuthorityCatalogRecord,
    root: SystemAuthorityCatalogNodeId,
}

#[cfg(feature = "std")]
impl ReplaySystemAuthorityCatalogHistory {
    pub(crate) const fn record(&self) -> &SystemAuthorityCatalogRecord {
        &self.record
    }

    pub(crate) const fn root(&self) -> SystemAuthorityCatalogNodeId {
        self.root
    }
}

#[cfg(feature = "std")]
impl ReplaySystemAuthorityHistory {
    pub(crate) const fn record(&self) -> &SystemAuthorityRotationRecord {
        &self.record
    }

    pub(crate) const fn root(&self) -> SystemAuthorityRotationNodeId {
        self.root
    }
}

/// Complete typed content-addressed dependency closure selected while binding
/// one replay publication to its durable authority reservation.
#[cfg(feature = "std")]
#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) enum ReplaySystemAuthorityStoragePlan {
    Rotation {
        history: ReplaySystemAuthorityHistory,
        committee_records: Vec<SystemAuthorityCommitteeRecord>,
    },
    Catalog {
        history: ReplaySystemAuthorityCatalogHistory,
        committee_record: SystemAuthorityCommitteeRecord,
    },
}

#[cfg(feature = "std")]
impl ReplaySystemAuthorityStoragePlan {
    pub(crate) const fn rotation_history(&self) -> Option<&ReplaySystemAuthorityHistory> {
        match self {
            Self::Rotation { history, .. } => Some(history),
            Self::Catalog { .. } => None,
        }
    }

    pub(crate) const fn catalog_history(&self) -> Option<&ReplaySystemAuthorityCatalogHistory> {
        match self {
            Self::Catalog { history, .. } => Some(history),
            Self::Rotation { .. } => None,
        }
    }

    pub(crate) fn committee_records(&self) -> &[SystemAuthorityCommitteeRecord] {
        match self {
            Self::Rotation {
                committee_records, ..
            } => committee_records,
            Self::Catalog {
                committee_record, ..
            } => core::slice::from_ref(committee_record),
        }
    }
}

/// Validated successor of one replay step.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ReplayStep {
    state: RuntimeState,
    runtime: RuntimeBinding,
    outcome: ReplayStepOutcome,
    result: Option<Result<ActorExecutionReply, ActorExecutionError>>,
    products: ReplayProducts,
    input: super::journal::ReplayInputId,
    position: ReplayPosition,
    ownership_delta: InvocationIndexDelta,
    sealed_outcomes: Vec<ReplaySealedOutcome>,
    system_authority_write: Option<ReplaySystemAuthorityWrite>,
    merge_authenticated: bool,
}

#[derive(Clone, Debug)]
struct MergeExecutionFact {
    event: MergeEvent,
    before: RuntimeState,
    after: RuntimeState,
    result: Option<Result<ActorExecutionReply, ActorExecutionError>>,
}

impl ReplayStep {
    pub fn state(&self) -> &RuntimeState {
        &self.state
    }

    pub fn runtime(&self) -> &RuntimeBinding {
        &self.runtime
    }

    pub const fn outcome(&self) -> ReplayStepOutcome {
        self.outcome
    }

    pub const fn products(&self) -> ReplayProducts {
        self.products
    }

    pub fn result(&self) -> Option<&Result<ActorExecutionReply, ActorExecutionError>> {
        self.result.as_ref()
    }

    fn execution_result(&self, expose_result: bool) -> ReplayExecutionResult {
        ReplayExecutionResult {
            outcome: self.outcome,
            result: expose_result.then(|| self.result.clone()).flatten(),
            products: self.products,
            input: self.input,
            position: self.position,
        }
    }
}

#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
struct InvocationIndexDelta {
    ordered: bool,
    merge: bool,
    local: bool,
}

impl InvocationIndexDelta {
    const NONE: Self = Self {
        ordered: false,
        merge: false,
        local: false,
    };

    const fn with(mut self, scope: InvocationOwnershipScope) -> Self {
        match scope {
            InvocationOwnershipScope::Ordered => self.ordered = true,
            InvocationOwnershipScope::Merge => self.merge = true,
            InvocationOwnershipScope::Local(_) => self.local = true,
        }
        self
    }

    const fn changed(self, scope: InvocationOwnershipScope) -> bool {
        match scope {
            InvocationOwnershipScope::Ordered => self.ordered,
            InvocationOwnershipScope::Merge => self.merge,
            InvocationOwnershipScope::Local(_) => self.local,
        }
    }
}

/// Exact immutable record(s) made durable before a sealed head publication.
/// Visibility is crate-scoped so storage can dispatch to its private generic
/// writer without exposing an unvalidated generic publication API.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum ReplayPublicationAnchor {
    Ordered(OrderedEntry),
    Local(LocalEntry),
    Merge {
        event: MergeEvent,
        frontier: MergeFrontier,
    },
    Checkpoint(CheckpointManifest),
}

/// Opaque identity of the exact root-admitted journal generation replay may
/// use for live system-authority transitions.
///
/// The fields are intentionally private and the type is neither wire
/// encodable nor constructible from `JournalHeads`. Only a root-reverified
/// [`ReplaySealedGenesis`] can mint it. The admission is the tagged outer
/// `AgentGenesisAdmissionId`, never the inner root-admission ID.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) struct ReplayedRootJournalIdentity {
    genesis: AgentJournalGenesisId,
    outer_admission: AgentGenesisAdmissionId,
}

impl ReplayedRootJournalIdentity {
    pub(crate) const fn genesis(self) -> AgentJournalGenesisId {
        self.genesis
    }

    pub(crate) const fn outer_admission(self) -> AgentGenesisAdmissionId {
        self.outer_admission
    }
}

/// Exact, genesis-ID-free result of executing the one admitted Create input.
///
/// Fields are deliberately private. The token can only be minted by the
/// replay engine after authentication, exact execution, and the complete
/// genesis transition checks. In particular, neither a caller-supplied state
/// nor a placeholder admission/genesis ID can be promoted into a seal.
#[derive(Debug, PartialEq, Eq)]
pub(crate) struct ReplayPreparedGenesis {
    create: ReplayInput,
    replica: AgentReplica,
    post_create: RuntimeState,
    artifacts: Vec<BlobRef>,
    expectations: SystemAgentGenesisExpectations,
}

impl ReplayPreparedGenesis {
    pub(crate) fn prepare<E: ReplayExecutor>(
        create: ReplayInput,
        replica: AgentReplica,
        executor: &mut E,
    ) -> Result<Self, ReplayError<core::convert::Infallible, E::Error>> {
        if create.validate().is_err() {
            return Err(ReplayError::InvalidRecord);
        }
        validate_position(&create, ReplayPosition::Genesis)?;
        let ReplayOperation::Management { request } = &create.operation else {
            return Err(ReplayError::InvalidRecord);
        };
        let LifecycleRequest::Authorized { request, .. } = request else {
            return Err(ReplayError::InvalidRecord);
        };
        let LifecycleRequest::Create(config) = request.as_ref() else {
            return Err(ReplayError::InvalidRecord);
        };
        match config.identity.profile {
            super::AgentProfile::Local if config.replicas.as_slice() == [replica] => {}
            super::AgentProfile::Shared if config.replicas.contains(&replica) => {}
            _ => return Err(ReplayError::ScopeMismatch),
        }

        let before = RuntimeState::default();
        validate_runtime_state_bound(&before)?;
        executor
            .authenticate(&create, &before, ReplayPosition::Genesis)
            .map_err(ReplayError::Executor)?;
        let transition = executor
            .execute(&create, &before, ReplayPosition::Genesis)
            .map_err(ReplayError::Executor)?;
        validate_runtime_state_bound(&transition.state)?;
        let system_authority_write = validate_transition(
            &create,
            &before,
            &transition,
            ReplayPosition::Genesis,
            &create.runtime,
            false,
            false,
            None,
            None,
        )?;
        if system_authority_write.is_some() {
            return Err(ReplayError::InvalidManagementTransition);
        }
        if transition.disposition != ReplayDisposition::Applied
            || transition.result.is_some()
            || transition.next_runtime != create.runtime
        {
            return Err(ReplayError::InvalidManagementTransition);
        }

        let post_create = transition.state;
        let decoded =
            decode_standard_runtime_state(&post_create).map_err(|_| ReplayError::InvalidRecord)?;
        if decoded.config.as_ref() != Some(config)
            || !decoded
                .config
                .as_ref()
                .is_some_and(|created| match created.identity.profile {
                    super::AgentProfile::Local => created.replicas.as_slice() == [replica],
                    super::AgentProfile::Shared => created.replicas.contains(&replica),
                    super::AgentProfile::Private => false,
                })
        {
            return Err(ReplayError::InvalidManagementTransition);
        }
        let expected_system_authority = config
            .system_authority_genesis
            .as_ref()
            .map(|genesis| {
                super::system_authority::SystemAuthorityState::from_genesis(
                    config.identity.agent,
                    genesis,
                )
            })
            .transpose()
            .map_err(|_| ReplayError::InvalidManagementTransition)?;
        if decoded.system_authority != expected_system_authority {
            return Err(ReplayError::InvalidManagementTransition);
        }
        let artifacts = derive_standard_artifact_references::<core::convert::Infallible>(
            &create.runtime,
            &post_create,
        )
        .map_err(|error| error.map_executor(|never| match never {}))?;
        let expectations = SystemAgentGenesisExpectations::new(
            create.runtime.commitment(),
            request.commitment(),
            system_genesis_post_create_state_commitment(&post_create)
                .map_err(|_| ReplayError::InvalidRecord)?,
            system_genesis_artifact_closure_commitment(&artifacts)
                .map_err(|_| ReplayError::InvalidRecord)?,
            match &create.operation {
                ReplayOperation::Management {
                    request: LifecycleRequest::Authorized { admission, .. },
                } => admission.receipt.claim.sequence,
                _ => unreachable!("validated genesis operation"),
            },
        )
        .map_err(|_| ReplayError::InvalidRecord)?;

        Ok(Self {
            create,
            replica,
            post_create,
            artifacts,
            expectations,
        })
    }

    pub(crate) const fn create(&self) -> &ReplayInput {
        &self.create
    }

    pub(crate) const fn replica(&self) -> AgentReplica {
        self.replica
    }

    pub(crate) fn artifacts(&self) -> &[BlobRef] {
        &self.artifacts
    }

    pub(crate) const fn expectations(&self) -> SystemAgentGenesisExpectations {
        self.expectations
    }
}

/// Receipt-authenticated admission for one ordinary Local Agent genesis.
///
/// This capability is deliberately neither wire encodable nor publicly
/// constructible.  It can only be minted from [`ReplayPreparedGenesis`],
/// after the replay executor has authenticated the exact Authorized<Create>
/// receipt, trusted runtime package, Local replica, and post-Create state.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) struct ReplayedLocalGenesisAdmission {
    admission: AgentGenesisAdmissionId,
    create: super::journal::ReplayInputId,
    authority: Hash,
    receipt: Hash,
    node: NodeId,
    post_create: Hash,
    artifacts: Hash,
}

impl ReplayedLocalGenesisAdmission {
    pub(crate) const fn id(self) -> AgentGenesisAdmissionId {
        self.admission
    }

    pub(crate) const fn node(self) -> NodeId {
        self.node
    }

    fn from_prepared(prepared: &ReplayPreparedGenesis) -> Result<Self, ReplayValidationError> {
        let ReplayOperation::Management {
            request: LifecycleRequest::Authorized { admission, request },
        } = &prepared.create.operation
        else {
            return Err(ReplayError::InvalidRecord);
        };
        let LifecycleRequest::Create(config) = request.as_ref() else {
            return Err(ReplayError::InvalidRecord);
        };
        if config.identity.profile != AgentProfile::Local
            || config.system_authority_genesis.is_some()
            || config.replicas.as_slice() != [prepared.replica]
            || admission.receipt.claim.authority != config.authority
        {
            return Err(ReplayError::ScopeMismatch);
        }
        let create = prepared.create.id();
        let authority = config.authority.commitment();
        let receipt = Hash::digest(
            b"vos/agent/local-genesis-receipt/v1",
            &[&admission.receipt.encode()],
        );
        let node = prepared.replica.node;
        let post_create = prepared.expectations.post_create_state();
        let artifacts = prepared.expectations.artifact_closure();
        let admission = AgentGenesisAdmissionId::from_bytes(
            Hash::digest(
                LOCAL_GENESIS_ADMISSION_DOMAIN,
                &[
                    create.as_bytes(),
                    authority.as_bytes(),
                    receipt.as_bytes(),
                    node.as_bytes(),
                    post_create.as_bytes(),
                    artifacts.as_bytes(),
                ],
            )
            .0,
        );
        if admission == AgentGenesisAdmissionId::ZERO {
            return Err(ReplayError::InvalidRecord);
        }
        Ok(Self {
            admission,
            create,
            authority,
            receipt,
            node,
            post_create,
            artifacts,
        })
    }

    pub(crate) fn validate_against(
        self,
        genesis: &AgentJournalGenesis,
        post_create: &RuntimeState,
        artifacts: &ArtifactClosure,
    ) -> Result<(), ReplayValidationError> {
        let ReplayOperation::Management {
            request: LifecycleRequest::Authorized { admission, request },
        } = &genesis.create.operation
        else {
            return Err(ReplayError::InvalidRecord);
        };
        let LifecycleRequest::Create(config) = request.as_ref() else {
            return Err(ReplayError::InvalidRecord);
        };
        let receipt = Hash::digest(
            b"vos/agent/local-genesis-receipt/v1",
            &[&admission.receipt.encode()],
        );
        if genesis.admission != self.admission
            || genesis.create.id() != self.create
            || config.identity.profile != AgentProfile::Local
            || config.system_authority_genesis.is_some()
            || config.authority.commitment() != self.authority
            || receipt != self.receipt
            || config.replicas.len() != 1
            || config.replicas[0].node != self.node
            || system_genesis_post_create_state_commitment(post_create)
                .map_err(|_| ReplayError::InvalidRecord)?
                != self.post_create
            || artifacts
                .system_genesis_commitment()
                .map_err(|_| ReplayError::InvalidRecord)?
                != self.artifacts
        {
            return Err(ReplayError::ScopeMismatch);
        }
        Ok(())
    }
}

/// Opaque, receipt-verified clean-generation seal for an ordinary Local
/// Agent.  Unlike [`ReplaySealedGenesis`], this carries no root authority or
/// system-authority-ledger ownership capability.
pub(crate) struct ReplaySealedLocalGenesis {
    genesis: AgentJournalGenesis,
    post_create: RuntimeState,
    empty_frontier: MergeFrontier,
    ordered_invocations: InvocationIndexManifest,
    merge_invocations: InvocationIndexManifest,
    local_invocations: InvocationIndexManifest,
    artifacts: ArtifactClosure,
    admission: ReplayedLocalGenesisAdmission,
    replica: AgentReplica,
}

impl ReplaySealedLocalGenesis {
    pub(crate) fn from_prepared(
        prepared: ReplayPreparedGenesis,
    ) -> Result<Self, ReplayValidationError> {
        let admission = ReplayedLocalGenesisAdmission::from_prepared(&prepared)?;
        let genesis = AgentJournalGenesis {
            admission: admission.id(),
            create: prepared.create,
        };
        genesis.validate().map_err(|_| ReplayError::InvalidRecord)?;
        let genesis_id = genesis.id();
        if genesis_id == AgentJournalGenesisId::ZERO {
            return Err(ReplayError::InvalidRecord);
        }
        let artifacts = ArtifactClosure {
            genesis: genesis_id,
            artifacts: prepared.artifacts,
        };
        artifacts
            .validate()
            .map_err(|_| ReplayError::InvalidRecord)?;
        let post_create = prepared.post_create;
        admission.validate_against(&genesis, &post_create, &artifacts)?;
        let replica = prepared.replica;
        let empty_frontier = MergeFrontier {
            genesis: genesis_id,
            events: Vec::new(),
        };
        Ok(Self {
            genesis,
            post_create,
            empty_frontier,
            ordered_invocations: InvocationIndexManifest::empty(
                genesis_id,
                InvocationOwnershipScope::Ordered,
            ),
            merge_invocations: InvocationIndexManifest::empty(
                genesis_id,
                InvocationOwnershipScope::Merge,
            ),
            local_invocations: InvocationIndexManifest::empty(
                genesis_id,
                InvocationOwnershipScope::Local(replica.node),
            ),
            artifacts,
            admission,
            replica,
        })
    }

    pub(crate) const fn genesis(&self) -> &AgentJournalGenesis {
        &self.genesis
    }

    pub(crate) const fn post_create(&self) -> &RuntimeState {
        &self.post_create
    }

    pub(crate) const fn empty_frontier(&self) -> &MergeFrontier {
        &self.empty_frontier
    }

    pub(crate) const fn ordered_invocations(&self) -> &InvocationIndexManifest {
        &self.ordered_invocations
    }

    pub(crate) const fn merge_invocations(&self) -> &InvocationIndexManifest {
        &self.merge_invocations
    }

    pub(crate) const fn local_invocations(&self) -> &InvocationIndexManifest {
        &self.local_invocations
    }

    pub(crate) const fn artifacts(&self) -> &ArtifactClosure {
        &self.artifacts
    }

    pub(crate) const fn admission(&self) -> ReplayedLocalGenesisAdmission {
        self.admission
    }

    pub(crate) const fn replica(&self) -> AgentReplica {
        self.replica
    }

    pub(crate) fn admission_commitment(&self) -> Hash {
        self.genesis.admission.as_hash()
    }

    pub(crate) fn lane_manifest(&self, lane: PersistedLane) -> LaneStateManifest {
        let cursor = match lane {
            PersistedLane::Control | PersistedLane::Linear => LaneCursor::Ordered {
                base: OrderedBase::post_genesis(),
            },
            PersistedLane::Merge => LaneCursor::Merge {
                frontier: self.empty_frontier.id(),
            },
            PersistedLane::Local => LaneCursor::Local {
                node: self.replica.node,
                revision: 0,
                head: None,
            },
        };
        LaneStateManifest {
            genesis: self.genesis.id(),
            runtime: self.genesis.runtime().clone(),
            lane,
            cursor,
            state: BlobRef::of_bytes(state_component(&self.post_create, lane)),
        }
    }

    pub(crate) fn initial_heads(&self) -> JournalHeads {
        JournalHeads::initial(
            self.genesis.id(),
            self.genesis.admission,
            self.replica.node,
            self.empty_frontier.id(),
            self.genesis.runtime().clone(),
        )
    }

    pub(crate) fn validate(&self) -> Result<(), ReplayValidationError> {
        self.admission
            .validate_against(&self.genesis, &self.post_create, &self.artifacts)
    }
}

/// Opaque, system-finality-verified clean-generation seal for one physical
/// replica of an ordinary Shared Agent.
///
/// The selected replica is local storage identity only. The complete
/// authority-certified committee remains attached to the seal so journal,
/// Raft, and transport routing cannot independently reconstruct membership
/// from a caller-supplied `AgentConfig`.
pub(crate) struct ReplaySealedSharedGenesis {
    genesis: AgentJournalGenesis,
    post_create: RuntimeState,
    empty_frontier: MergeFrontier,
    ordered_invocations: InvocationIndexManifest,
    merge_invocations: InvocationIndexManifest,
    local_invocations: InvocationIndexManifest,
    artifacts: ArtifactClosure,
    admission_record: AgentGenesisAdmissionRecord,
    committee: AgentReplicaCommittee,
    replica: AgentReplica,
}

impl ReplaySealedSharedGenesis {
    pub(crate) fn from_prepared_verified(
        verified: &VerifiedAgentGenesisProvision,
        prepared: ReplayPreparedGenesis,
    ) -> Result<Self, ReplayValidationError> {
        let provision = verified.provision();
        provision
            .validate()
            .map_err(|_| ReplayError::InvalidRecord)?;
        let proposal = provision.proposal();
        let config = proposal.config().map_err(|_| ReplayError::InvalidRecord)?;
        let expected = AgentGenesisExpectations::new(
            prepared.expectations.runtime_binding(),
            prepared.expectations.inner_create_request(),
            prepared.expectations.post_create_state(),
            prepared.expectations.artifact_closure(),
            prepared.expectations.sequence(),
        )
        .map_err(|_| ReplayError::InvalidRecord)?;
        let committee = provision.replicas();
        if proposal.create() != &prepared.create
            || proposal.expectations() != expected
            || proposal.catalog() != prepared.artifacts.as_slice()
            || config.identity.profile != AgentProfile::Shared
            || config.system_authority_genesis.is_some()
            || committee.profile() != AgentProfile::Shared
            || committee.space() != prepared.create.runtime.space
            || committee.agent() != prepared.create.runtime.agent
            || committee
                .member_by_node(prepared.replica.node)
                .map(|member| member.replica())
                != Some(prepared.replica)
        {
            return Err(ReplayError::ScopeMismatch);
        }
        committee
            .validate_for(config)
            .map_err(|_| ReplayError::ScopeMismatch)?;
        let admission_record = provision
            .admission_record()
            .map_err(|_| ReplayError::InvalidRecord)?;
        if !matches!(
            &admission_record,
            AgentGenesisAdmissionRecord::SystemAuthorized { .. }
        ) || admission_record.id() == AgentGenesisAdmissionId::ZERO
        {
            return Err(ReplayError::InvalidRecord);
        }

        let genesis = AgentJournalGenesis {
            admission: admission_record.id(),
            create: prepared.create,
        };
        genesis.validate().map_err(|_| ReplayError::InvalidRecord)?;
        let genesis_id = genesis.id();
        if genesis_id == AgentJournalGenesisId::ZERO {
            return Err(ReplayError::InvalidRecord);
        }
        let artifacts = ArtifactClosure {
            genesis: genesis_id,
            artifacts: prepared.artifacts,
        };
        artifacts
            .validate()
            .map_err(|_| ReplayError::InvalidRecord)?;
        if artifacts
            .system_genesis_commitment()
            .map_err(|_| ReplayError::InvalidRecord)?
            != expected.artifact_closure()
            || system_genesis_post_create_state_commitment(&prepared.post_create)
                .map_err(|_| ReplayError::InvalidRecord)?
                != expected.post_create_state()
        {
            return Err(ReplayError::InvalidRecord);
        }
        let replica = prepared.replica;
        let empty_frontier = MergeFrontier {
            genesis: genesis_id,
            events: Vec::new(),
        };
        let sealed = Self {
            genesis,
            post_create: prepared.post_create,
            empty_frontier,
            ordered_invocations: InvocationIndexManifest::empty(
                genesis_id,
                InvocationOwnershipScope::Ordered,
            ),
            merge_invocations: InvocationIndexManifest::empty(
                genesis_id,
                InvocationOwnershipScope::Merge,
            ),
            local_invocations: InvocationIndexManifest::empty(
                genesis_id,
                InvocationOwnershipScope::Local(replica.node),
            ),
            artifacts,
            admission_record,
            committee: committee.clone(),
            replica,
        };
        sealed.validate()?;
        Ok(sealed)
    }

    pub(crate) const fn genesis(&self) -> &AgentJournalGenesis {
        &self.genesis
    }

    pub(crate) const fn post_create(&self) -> &RuntimeState {
        &self.post_create
    }

    pub(crate) const fn empty_frontier(&self) -> &MergeFrontier {
        &self.empty_frontier
    }

    pub(crate) const fn ordered_invocations(&self) -> &InvocationIndexManifest {
        &self.ordered_invocations
    }

    pub(crate) const fn merge_invocations(&self) -> &InvocationIndexManifest {
        &self.merge_invocations
    }

    pub(crate) const fn local_invocations(&self) -> &InvocationIndexManifest {
        &self.local_invocations
    }

    pub(crate) const fn artifacts(&self) -> &ArtifactClosure {
        &self.artifacts
    }

    pub(crate) const fn admission_record(&self) -> &AgentGenesisAdmissionRecord {
        &self.admission_record
    }

    pub(crate) const fn committee(&self) -> &AgentReplicaCommittee {
        &self.committee
    }

    pub(crate) const fn replica(&self) -> AgentReplica {
        self.replica
    }

    pub(crate) fn admission_commitment(&self) -> Hash {
        self.genesis.admission.as_hash()
    }

    pub(crate) fn lane_manifest(&self, lane: PersistedLane) -> LaneStateManifest {
        let cursor = match lane {
            PersistedLane::Control | PersistedLane::Linear => LaneCursor::Ordered {
                base: OrderedBase::post_genesis(),
            },
            PersistedLane::Merge => LaneCursor::Merge {
                frontier: self.empty_frontier.id(),
            },
            PersistedLane::Local => LaneCursor::Local {
                node: self.replica.node,
                revision: 0,
                head: None,
            },
        };
        LaneStateManifest {
            genesis: self.genesis.id(),
            runtime: self.genesis.runtime().clone(),
            lane,
            cursor,
            state: BlobRef::of_bytes(state_component(&self.post_create, lane)),
        }
    }

    pub(crate) fn initial_heads(&self) -> JournalHeads {
        JournalHeads::initial(
            self.genesis.id(),
            self.genesis.admission,
            self.replica.node,
            self.empty_frontier.id(),
            self.genesis.runtime().clone(),
        )
    }

    pub(crate) fn route(&self) -> Result<AgentRouteKey, ReplayValidationError> {
        AgentRouteKey::new(
            self.genesis.runtime().space,
            self.genesis.runtime().agent,
            self.genesis.id(),
            self.genesis.admission,
            self.committee.id(),
        )
        .map_err(|_| ReplayError::ScopeMismatch)
    }

    pub(crate) fn validate(&self) -> Result<(), ReplayValidationError> {
        self.genesis
            .validate()
            .map_err(|_| ReplayError::InvalidRecord)?;
        self.admission_record
            .validate()
            .map_err(|_| ReplayError::InvalidRecord)?;
        let ReplayOperation::Management {
            request: LifecycleRequest::Authorized { request, .. },
        } = &self.genesis.create.operation
        else {
            return Err(ReplayError::InvalidRecord);
        };
        let LifecycleRequest::Create(config) = request.as_ref() else {
            return Err(ReplayError::InvalidRecord);
        };
        if self.genesis.admission != self.admission_record.id()
            || !matches!(
                &self.admission_record,
                AgentGenesisAdmissionRecord::SystemAuthorized { .. }
            )
            || config.identity.profile != AgentProfile::Shared
            || config.system_authority_genesis.is_some()
            || self.committee.validate_for(config).is_err()
            || self
                .committee
                .member_by_node(self.replica.node)
                .map(|member| member.replica())
                != Some(self.replica)
            || self.artifacts.genesis != self.genesis.id()
            || self.empty_frontier.genesis != self.genesis.id()
            || !self.empty_frontier.events.is_empty()
        {
            return Err(ReplayError::ScopeMismatch);
        }
        self.route()?;
        Ok(())
    }
}

/// Storage-only view shared by the independently sealed Local and Shared
/// ordinary-genesis capabilities. Keeping this trait crate-private lets the
/// filesystem slot reuse one crash protocol without accepting raw genesis
/// data or erasing either admission authority.
pub(crate) trait ReplaySealedOrdinaryGenesis {
    fn genesis(&self) -> &AgentJournalGenesis;
    fn post_create(&self) -> &RuntimeState;
    fn empty_frontier(&self) -> &MergeFrontier;
    fn ordered_invocations(&self) -> &InvocationIndexManifest;
    fn merge_invocations(&self) -> &InvocationIndexManifest;
    fn local_invocations(&self) -> &InvocationIndexManifest;
    fn artifacts(&self) -> &ArtifactClosure;
    fn replica(&self) -> AgentReplica;
    fn admission_commitment(&self) -> Hash;
    fn lane_manifest(&self, lane: PersistedLane) -> LaneStateManifest;
    fn initial_heads(&self) -> JournalHeads;
    fn validates_config(&self, config: &super::AgentConfig) -> bool;
    fn admission_record(&self) -> Option<&AgentGenesisAdmissionRecord>;
    fn validate_seal(&self) -> Result<(), ReplayValidationError>;
}

impl ReplaySealedOrdinaryGenesis for ReplaySealedLocalGenesis {
    fn genesis(&self) -> &AgentJournalGenesis {
        self.genesis()
    }

    fn post_create(&self) -> &RuntimeState {
        self.post_create()
    }

    fn empty_frontier(&self) -> &MergeFrontier {
        self.empty_frontier()
    }

    fn ordered_invocations(&self) -> &InvocationIndexManifest {
        self.ordered_invocations()
    }

    fn merge_invocations(&self) -> &InvocationIndexManifest {
        self.merge_invocations()
    }

    fn local_invocations(&self) -> &InvocationIndexManifest {
        self.local_invocations()
    }

    fn artifacts(&self) -> &ArtifactClosure {
        self.artifacts()
    }

    fn replica(&self) -> AgentReplica {
        self.replica()
    }

    fn admission_commitment(&self) -> Hash {
        self.admission_commitment()
    }

    fn lane_manifest(&self, lane: PersistedLane) -> LaneStateManifest {
        self.lane_manifest(lane)
    }

    fn initial_heads(&self) -> JournalHeads {
        self.initial_heads()
    }

    fn validates_config(&self, config: &super::AgentConfig) -> bool {
        config.identity.profile == AgentProfile::Local
            && config.system_authority_genesis.is_none()
            && config.replicas.as_slice() == [self.replica]
            && self.admission.node() == self.replica.node
    }

    fn admission_record(&self) -> Option<&AgentGenesisAdmissionRecord> {
        None
    }

    fn validate_seal(&self) -> Result<(), ReplayValidationError> {
        self.validate()
    }
}

impl ReplaySealedOrdinaryGenesis for ReplaySealedSharedGenesis {
    fn genesis(&self) -> &AgentJournalGenesis {
        self.genesis()
    }

    fn post_create(&self) -> &RuntimeState {
        self.post_create()
    }

    fn empty_frontier(&self) -> &MergeFrontier {
        self.empty_frontier()
    }

    fn ordered_invocations(&self) -> &InvocationIndexManifest {
        self.ordered_invocations()
    }

    fn merge_invocations(&self) -> &InvocationIndexManifest {
        self.merge_invocations()
    }

    fn local_invocations(&self) -> &InvocationIndexManifest {
        self.local_invocations()
    }

    fn artifacts(&self) -> &ArtifactClosure {
        self.artifacts()
    }

    fn replica(&self) -> AgentReplica {
        self.replica()
    }

    fn admission_commitment(&self) -> Hash {
        self.admission_commitment()
    }

    fn lane_manifest(&self, lane: PersistedLane) -> LaneStateManifest {
        self.lane_manifest(lane)
    }

    fn initial_heads(&self) -> JournalHeads {
        self.initial_heads()
    }

    fn validates_config(&self, config: &super::AgentConfig) -> bool {
        config.identity.profile == AgentProfile::Shared
            && config.system_authority_genesis.is_none()
            && self.committee.validate_for(config).is_ok()
            && self
                .committee
                .member_by_node(self.replica.node)
                .map(|member| member.replica())
                == Some(self.replica)
    }

    fn admission_record(&self) -> Option<&AgentGenesisAdmissionRecord> {
        Some(&self.admission_record)
    }

    fn validate_seal(&self) -> Result<(), ReplayValidationError> {
        self.validate()
    }
}

/// Root-admitted, exactly executed clean-generation journal bootstrap.
///
/// Storage may inspect this closure, but cannot manufacture one from a merely
/// self-canonical genesis record or decoded authority evidence.
pub struct ReplaySealedGenesis {
    genesis: AgentJournalGenesis,
    post_create: RuntimeState,
    empty_frontier: MergeFrontier,
    ordered_invocations: InvocationIndexManifest,
    merge_invocations: InvocationIndexManifest,
    local_invocations: InvocationIndexManifest,
    artifacts: ArtifactClosure,
    root_anchor: RootAnchorRecord,
    root_admission_record: SystemAgentGenesisAdmissionRecord,
    admission_record: AgentGenesisAdmissionRecord,
    admission_evidence: SystemAgentGenesisEvidence,
    replica: AgentReplica,
}

impl ReplaySealedGenesis {
    pub fn genesis(&self) -> &AgentJournalGenesis {
        &self.genesis
    }

    pub fn post_create(&self) -> &RuntimeState {
        &self.post_create
    }

    pub fn empty_frontier(&self) -> &MergeFrontier {
        &self.empty_frontier
    }

    pub fn ordered_invocations(&self) -> &InvocationIndexManifest {
        &self.ordered_invocations
    }

    pub fn merge_invocations(&self) -> &InvocationIndexManifest {
        &self.merge_invocations
    }

    pub fn local_invocations(&self) -> &InvocationIndexManifest {
        &self.local_invocations
    }

    pub fn artifacts(&self) -> &ArtifactClosure {
        &self.artifacts
    }

    pub fn root_anchor(&self) -> &RootAnchorRecord {
        &self.root_anchor
    }

    pub fn admission_record(&self) -> &AgentGenesisAdmissionRecord {
        &self.admission_record
    }

    /// Typed inner root admission. This is distinct from the tagged outer
    /// journal admission whose ID is committed by [`AgentJournalGenesis`].
    pub const fn root_admission_record(&self) -> &SystemAgentGenesisAdmissionRecord {
        &self.root_admission_record
    }

    pub fn root_admission_id(&self) -> SystemAgentGenesisAdmissionId {
        self.root_admission_record.id()
    }

    pub fn admission_evidence(&self) -> &SystemAgentGenesisEvidence {
        &self.admission_evidence
    }

    pub fn admission_commitment(&self) -> Hash {
        self.genesis.admission.as_hash()
    }

    /// Mint replay provenance from the complete root-reverified seal. This
    /// is deliberately the only production constructor for the opaque root
    /// journal identity.
    pub(crate) fn replayed_root_identity(
        &self,
    ) -> Result<ReplayedRootJournalIdentity, ReplayValidationError> {
        let AgentGenesisAdmissionRecord::RootBootstrap(root_admission) = &self.admission_record
        else {
            return Err(ReplayError::ScopeMismatch);
        };
        if root_admission != &self.root_admission_record
            || self.admission_record.id() != self.genesis.admission
            || root_admission.root_anchor() != self.root_anchor.id()
            || root_admission.root_anchor_config_version() != self.root_anchor.config_version()
            || root_admission.root_anchor_config() != self.root_anchor.config_commitment()
            || root_admission.evidence() != self.admission_evidence.id()
        {
            return Err(ReplayError::ScopeMismatch);
        }
        Ok(ReplayedRootJournalIdentity {
            genesis: self.genesis.id(),
            outer_admission: self.genesis.admission,
        })
    }

    /// Derive the signer-independent durable authority route from this exact
    /// root-admitted seal. Host cannot assemble a route from raw IDs or a
    /// decoded state independently of the opaque replay provenance.
    #[cfg(all(feature = "std", feature = "storage"))]
    pub(crate) fn system_authority_ledger_route(
        &self,
    ) -> Result<SystemAuthorityLedgerRoute, ReplayValidationError> {
        let identity = self.replayed_root_identity()?;
        let scope = SystemAuthorityJournalScope::from_replayed_root(&identity)
            .map_err(|_| ReplayError::ScopeMismatch)?;
        let decoded = decode_standard_runtime_state(&self.post_create)
            .map_err(|_| ReplayError::ScopeMismatch)?;
        let authority = decoded
            .system_authority
            .as_ref()
            .ok_or(ReplayError::ScopeMismatch)?;
        if authority.system_agent() != self.genesis.runtime().agent {
            return Err(ReplayError::ScopeMismatch);
        }
        SystemAuthorityLedgerRoute::from_authenticated_replay(scope, authority)
            .map_err(|_| ReplayError::ScopeMismatch)
    }

    pub const fn replica(&self) -> AgentReplica {
        self.replica
    }

    /// Mint the sole production bootstrap capability from a root/QC-verified
    /// system-Agent admission and the exact replayed Create transition.
    /// Decoded evidence, a self-canonical genesis, or caller-supplied state is
    /// never sufficient on its own.
    pub(crate) fn from_prepared_verified(
        verified: &VerifiedSystemAgentGenesis,
        admission_evidence: SystemAgentGenesisEvidence,
        prepared: ReplayPreparedGenesis,
    ) -> Result<Self, ReplayValidationError> {
        let ReplayOperation::Management { request } = &prepared.create.operation else {
            return Err(ReplayError::InvalidRecord);
        };
        let LifecycleRequest::Authorized { request, .. } = request else {
            return Err(ReplayError::InvalidRecord);
        };
        let LifecycleRequest::Create(config) = request.as_ref() else {
            return Err(ReplayError::InvalidRecord);
        };
        let root_admission = verified.admission_record();
        let root_anchor = verified.root_anchor().clone();
        if root_admission.evidence() != verified.evidence_id()
            || root_admission.root_anchor() != root_anchor.id()
            || root_admission.root_anchor_config_version() != root_anchor.config_version()
            || root_admission.root_anchor_config() != root_anchor.config_commitment()
            || admission_evidence.id() != verified.evidence_id()
            || verified.space() != prepared.create.runtime.space
            || verified.system_agent() != prepared.create.runtime.agent
            || verified.authority_binding() != config.authority.commitment()
            || verified.genesis_intent() != prepared.expectations.genesis_intent()
            || verified.runtime_binding() != prepared.expectations.runtime_binding()
            || verified.post_create_state() != prepared.expectations.post_create_state()
            || verified.artifact_closure() != prepared.expectations.artifact_closure()
            || verified.sequence() != prepared.expectations.sequence()
            || config.identity.profile != super::AgentProfile::Local
            || config.replicas.as_slice() != [prepared.replica]
        {
            return Err(ReplayError::InvalidRecord);
        }

        let admission_record = AgentGenesisAdmissionRecord::root_bootstrap(root_admission)
            .map_err(|_| ReplayError::InvalidRecord)?;
        let root_admission_id = root_admission.id();
        let journal_admission_id = admission_record.id();
        if root_admission_id == SystemAgentGenesisAdmissionId::ZERO
            || journal_admission_id == AgentGenesisAdmissionId::ZERO
            || journal_admission_id.as_bytes() == root_admission_id.as_bytes()
        {
            return Err(ReplayError::InvalidRecord);
        }

        let genesis = AgentJournalGenesis {
            admission: journal_admission_id,
            create: prepared.create,
        };
        genesis.validate().map_err(|_| ReplayError::InvalidRecord)?;
        if verified.admission_commitment() != root_admission.id().as_hash()
            || admission_record.id() != genesis.admission
            || genesis
                .genesis_intent()
                .map_err(|_| ReplayError::InvalidRecord)?
                != verified.genesis_intent()
            || genesis
                .genesis_authority_sequence()
                .map_err(|_| ReplayError::InvalidRecord)?
                != verified.sequence()
        {
            return Err(ReplayError::InvalidRecord);
        }
        let genesis_id = genesis.id();
        if genesis_id == AgentJournalGenesisId::ZERO {
            return Err(ReplayError::InvalidRecord);
        }
        let artifacts = ArtifactClosure {
            genesis: genesis_id,
            artifacts: prepared.artifacts,
        };
        artifacts
            .validate()
            .map_err(|_| ReplayError::InvalidRecord)?;
        if artifacts
            .system_genesis_commitment()
            .map_err(|_| ReplayError::InvalidRecord)?
            != verified.artifact_closure()
        {
            return Err(ReplayError::InvalidRecord);
        }
        let post_create = prepared.post_create;
        let replica = prepared.replica;
        let empty_frontier = MergeFrontier {
            genesis: genesis_id,
            events: Vec::new(),
        };
        Ok(Self {
            genesis,
            post_create,
            empty_frontier,
            ordered_invocations: InvocationIndexManifest::empty(
                genesis_id,
                InvocationOwnershipScope::Ordered,
            ),
            merge_invocations: InvocationIndexManifest::empty(
                genesis_id,
                InvocationOwnershipScope::Merge,
            ),
            local_invocations: InvocationIndexManifest::empty(
                genesis_id,
                InvocationOwnershipScope::Local(replica.node),
            ),
            artifacts,
            root_anchor,
            root_admission_record: root_admission,
            admission_record,
            admission_evidence,
            replica,
        })
    }

    pub fn lane_manifest(&self, lane: PersistedLane) -> LaneStateManifest {
        let cursor = match lane {
            PersistedLane::Control | PersistedLane::Linear => LaneCursor::Ordered {
                base: OrderedBase::post_genesis(),
            },
            PersistedLane::Merge => LaneCursor::Merge {
                frontier: self.empty_frontier.id(),
            },
            PersistedLane::Local => LaneCursor::Local {
                node: self.replica.node,
                revision: 0,
                head: None,
            },
        };
        LaneStateManifest {
            genesis: self.genesis.id(),
            runtime: self.genesis.runtime().clone(),
            lane,
            cursor,
            state: BlobRef::of_bytes(state_component(&self.post_create, lane)),
        }
    }

    pub fn initial_heads(&self) -> JournalHeads {
        JournalHeads::initial(
            self.genesis.id(),
            self.genesis.admission,
            self.replica.node,
            self.empty_frontier.id(),
            self.genesis.runtime().clone(),
        )
    }
}

/// Replay-authenticated closure of one checkpoint publication.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ReplaySealedCheckpoint {
    manifest: CheckpointManifest,
    lanes: Vec<(CheckpointLane, LaneStateManifest)>,
    artifacts: ArtifactClosure,
    invocation_indexes: Vec<(InvocationIndexId, InvocationIndexManifest)>,
    local_cursors: Vec<(NodeId, u64, Option<LocalEntryId>)>,
    fence_ancestry: FenceAncestryEvidence,
}

impl ReplaySealedCheckpoint {
    pub fn manifest(&self) -> &CheckpointManifest {
        &self.manifest
    }

    pub fn lanes(&self) -> &[(CheckpointLane, LaneStateManifest)] {
        &self.lanes
    }

    pub fn artifacts(&self) -> &ArtifactClosure {
        &self.artifacts
    }

    pub fn invocation_indexes(&self) -> &[(InvocationIndexId, InvocationIndexManifest)] {
        &self.invocation_indexes
    }

    pub fn local_cursors(&self) -> &[(NodeId, u64, Option<LocalEntryId>)] {
        &self.local_cursors
    }

    pub(crate) const fn fence_ancestry(&self) -> &FenceAncestryEvidence {
        &self.fence_ancestry
    }
}

/// Replay-proven ancestry of the latest lifecycle fence relative to the
/// current checkpoint boundary.
///
/// The ordered head content ID is already a commitment to its parent chain;
/// this opaque evidence binds that anchor to the exact checkpoint base and
/// fence after deterministic replay. Local cold recovery treats the owned
/// descriptor store's published checkpoint as its trust root. Shared mode
/// must authenticate [`Self::commitment`] with its ordered-snapshot Raft QC.
#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) struct FenceAncestryEvidence {
    genesis: AgentJournalGenesisId,
    checkpoint_base: OrderedBase,
    canonical_head: OrderedBase,
    fence: OrderedBase,
    ordered_anchor: Hash,
}

impl FenceAncestryEvidence {
    fn post_genesis(genesis: AgentJournalGenesisId) -> Result<Self, ReplayValidationError> {
        if genesis == AgentJournalGenesisId::ZERO {
            return Err(ReplayError::InvalidFence);
        }
        Ok(Self {
            genesis,
            checkpoint_base: OrderedBase::post_genesis(),
            canonical_head: OrderedBase::post_genesis(),
            fence: OrderedBase::post_genesis(),
            ordered_anchor: Hash::digest(
                b"vos/agent/replay/genesis-ordered-ancestry",
                &[&genesis.0],
            ),
        })
    }

    /// Restore the transitive ancestry proof carried by an exact checkpoint
    /// selected by the currently durable Local descriptor head. This is not a
    /// raw checkpoint validator: the caller must first prove `heads` is the
    /// store-owned current trust root and load the exact referenced closure.
    /// Shared mode must replace this Local trust step with a verified QC.
    fn from_published_local_checkpoint(
        heads: &JournalHeads,
        checkpoint_id: CheckpointId,
        checkpoint: &CheckpointManifest,
    ) -> Result<Self, ReplayValidationError> {
        let checkpoint_base = OrderedBase {
            index: checkpoint.ordered_index,
            head: checkpoint.ordered_head,
        };
        if heads.validate().is_err()
            || checkpoint.validate().is_err()
            || heads.checkpoint != Some(checkpoint_id)
            || checkpoint.id() != checkpoint_id
            || heads.genesis != checkpoint.genesis
            || checkpoint_base.validate().is_err()
            || checkpoint.merge_fence.validate().is_err()
            || checkpoint.merge_fence.index > checkpoint_base.index
            || (checkpoint.merge_fence.index == checkpoint_base.index
                && checkpoint.merge_fence.head != checkpoint_base.head)
        {
            return Err(ReplayError::InvalidFence);
        }
        let checkpoint_bytes = ordered_base_evidence_bytes(checkpoint_base);
        Ok(Self {
            genesis: checkpoint.genesis,
            checkpoint_base,
            canonical_head: checkpoint_base,
            fence: checkpoint.merge_fence,
            ordered_anchor: Hash::digest(
                b"vos/agent/replay/local-checkpoint-trust-root",
                &[&checkpoint_id.0, &checkpoint_bytes],
            ),
        })
    }

    /// Advance ancestry by one already-validated canonical OrderedEntry.
    fn advance_ordered(
        &self,
        entry: &OrderedEntry,
        next_fence: OrderedBase,
    ) -> Result<Self, ReplayValidationError> {
        let id = entry.id();
        let canonical_head = OrderedBase {
            index: entry.index,
            head: Some(id),
        };
        let advances_fence = next_fence == canonical_head;
        if !self.validate()
            || entry.validate().is_err()
            || entry.genesis != self.genesis
            || entry.parent != self.canonical_head.head
            || entry.index
                != self
                    .canonical_head
                    .index
                    .checked_add(1)
                    .ok_or(ReplayError::ReplayLimit)?
            || next_fence.validate().is_err()
            || advances_fence != entry.merge_seal.is_some()
            || (!advances_fence && next_fence != self.fence)
        {
            return Err(ReplayError::InvalidFence);
        }
        let index = entry.index.to_le_bytes();
        Ok(Self {
            genesis: self.genesis,
            checkpoint_base: self.checkpoint_base,
            canonical_head,
            fence: next_fence,
            ordered_anchor: Hash::digest(
                b"vos/agent/replay/ordered-ancestry-step",
                &[&self.ordered_anchor.0, &id.0, &index],
            ),
        })
    }

    fn checkpointed(&self) -> Result<Self, ReplayValidationError> {
        if !self.validate() {
            return Err(ReplayError::InvalidFence);
        }
        let base = ordered_base_evidence_bytes(self.canonical_head);
        Ok(Self {
            genesis: self.genesis,
            checkpoint_base: self.canonical_head,
            canonical_head: self.canonical_head,
            fence: self.fence,
            ordered_anchor: Hash::digest(
                b"vos/agent/replay/checkpoint-ordered-ancestry",
                &[&self.commitment().0, &base],
            ),
        })
    }

    pub(crate) const fn genesis(&self) -> AgentJournalGenesisId {
        self.genesis
    }

    pub(crate) const fn checkpoint_base(&self) -> OrderedBase {
        self.checkpoint_base
    }

    pub(crate) const fn canonical_head(&self) -> OrderedBase {
        self.canonical_head
    }

    pub(crate) const fn fence(&self) -> OrderedBase {
        self.fence
    }

    pub(crate) fn commitment(&self) -> Hash {
        let checkpoint_bytes = ordered_base_evidence_bytes(self.checkpoint_base);
        let canonical_bytes = ordered_base_evidence_bytes(self.canonical_head);
        let fence_bytes = ordered_base_evidence_bytes(self.fence);
        Hash::digest(
            b"vos/agent/replay/fence-ancestry-evidence",
            &[
                &self.genesis.0,
                &checkpoint_bytes,
                &canonical_bytes,
                &fence_bytes,
                &self.ordered_anchor.0,
            ],
        )
    }

    pub(crate) fn validate(&self) -> bool {
        self.genesis != AgentJournalGenesisId::ZERO
            && self.checkpoint_base.validate().is_ok()
            && self.canonical_head.validate().is_ok()
            && self.fence.validate().is_ok()
            && self.checkpoint_base.index <= self.canonical_head.index
            && (self.checkpoint_base.index != self.canonical_head.index
                || self.checkpoint_base.head == self.canonical_head.head)
            && self.fence.index <= self.canonical_head.index
            && (self.fence.index != self.canonical_head.index
                || self.fence.head == self.canonical_head.head)
            && self.ordered_anchor != Hash::ZERO
            && self.commitment() != Hash::ZERO
    }
}

fn ordered_base_evidence_bytes(base: OrderedBase) -> [u8; 41] {
    let mut bytes = [0_u8; 41];
    bytes[0] = u8::from(base.head.is_some());
    bytes[1..9].copy_from_slice(&base.index.to_le_bytes());
    if let Some(head) = base.head {
        bytes[9..].copy_from_slice(&head.0);
    }
    bytes
}

/// Opaque authority required by the journal store's public CAS operation.
///
/// Shared ordered publications are the one exception to the local journal's
/// usual `entry.merge_frontier == current.merge_frontier` shape.  The mode is
/// private to replay and storage: callers cannot turn a generic/raw journal
/// anchor into a state splice.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum ReplayPublicationMode {
    Canonical,
    SharedOrderedPreserveMerge,
    SharedOrderedInstallFence,
}

/// Opaque evidence that an exact Shared Ordered entry crossed the durable
/// Raft-log commit boundary. Replay deliberately accepts neither a bare entry
/// nor an application QC here: replicas first apply the committed log slot,
/// then certify the exact replay-derived projection. A durable exact
/// reservation is irrevocable: a later divergent reservation fail-stops new
/// work but cannot revoke a bearer which may already have crossed journal
/// CAS; the ledger still permits that originally stored exact reservation to
/// consume into its one anchor.
#[derive(Debug)]
pub(crate) struct CommittedSharedOrdered {
    reservation: ReservedAgentRaftApplication,
    entry: OrderedEntry,
    route: AgentRouteKey,
    raft_index: u64,
    raft_term: u64,
    raft_payload_commitment: Hash,
    journal_store: JournalStoreInstanceId,
    local_node: NodeId,
    committee: AgentReplicaCommittee,
}

impl CommittedSharedOrdered {
    /// Bridge seam for an exact command read from the durable committed Raft
    /// log and the independently admitted committee named by its route.
    pub(crate) fn from_reserved_raft_application(
        reserved: ReservedAgentRaftApplication,
        trusted_committee: &AgentReplicaCommittee,
        #[cfg(feature = "storage")] validated_batch: Option<ValidatedSharedArtifactBatch>,
    ) -> Result<Self, ReplayValidationError> {
        let committed = reserved.committed();
        let AgentRaftCommand::Ordered {
            route,
            artifact_batch,
            entry,
        } = committed.command()
        else {
            return Err(ReplayError::InvalidRecord);
        };
        #[cfg(feature = "storage")]
        let staged_batch_matches = match (artifact_batch, validated_batch.as_ref()) {
            (None, None) => true,
            (Some(expected), Some(validated)) => {
                *expected == validated.batch() && *route == validated.route()
            }
            _ => false,
        };
        #[cfg(not(feature = "storage"))]
        let staged_batch_matches = artifact_batch.is_none();
        if !staged_batch_matches
            || *artifact_batch != reserved.artifact_batch()
            || entry.validate().is_err()
            || route.validate().is_err()
            || route.genesis() != entry.genesis
            || route.space() != entry.input.runtime.space
            || route.agent() != entry.input.runtime.agent
            || route.committee() != trusted_committee.id()
            || trusted_committee.profile() != AgentProfile::Shared
            || route.space() != trusted_committee.space()
            || route.agent() != trusted_committee.agent()
            || committed.index() == 0
            || committed.term() == 0
            || committed.committed_index() < committed.index()
            || committed.payload_commitment() == Hash::ZERO
            || trusted_committee
                .member_by_node(reserved.local_node())
                .is_none()
        {
            return Err(ReplayError::InvalidRecord);
        }
        let entry = entry.clone();
        let route = *route;
        let raft_index = committed.index();
        let raft_term = committed.term();
        let raft_payload_commitment = committed.payload_commitment();
        let journal_store = reserved.journal_store();
        let local_node = reserved.local_node();
        Ok(Self {
            reservation: reserved,
            entry,
            route,
            raft_index,
            raft_term,
            raft_payload_commitment,
            journal_store,
            local_node,
            committee: trusted_committee.clone(),
        })
    }

    fn authenticated_entry(&self) -> Result<&OrderedEntry, ReplayValidationError> {
        let AgentRaftCommand::Ordered {
            route,
            artifact_batch,
            entry,
        } = self.reservation.committed().command()
        else {
            return Err(ReplayError::InvalidRecord);
        };
        if *artifact_batch != self.reservation.artifact_batch()
            || route != &self.route
            || entry != &self.entry
            || self.entry.validate().is_err()
            || self.route.validate().is_err()
            || self.route.genesis() != self.entry.genesis
            || self.route.space() != self.entry.input.runtime.space
            || self.route.agent() != self.entry.input.runtime.agent
            || self.route.committee() != self.committee.id()
            || self.committee.profile() != AgentProfile::Shared
            || self.raft_index == 0
            || self.raft_term == 0
            || self.raft_payload_commitment == Hash::ZERO
            || self.reservation.journal_store() != self.journal_store
            || self.committee.member_by_node(self.local_node).is_none()
            || self.reservation.route() != self.route
            || self.reservation.index() != self.raft_index
            || self.reservation.term() != self.raft_term
            || self.reservation.payload_commitment() != self.raft_payload_commitment
            || self.reservation.local_node() != self.local_node
        {
            Err(ReplayError::InvalidRecord)
        } else {
            Ok(&self.entry)
        }
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ReplaySealedPublication {
    expected: JournalHeadsId,
    next: JournalHeads,
    anchor: ReplayPublicationAnchor,
    outcomes: Vec<ReplaySealedOutcome>,
    history_plans: Vec<InvocationHistoryWritePlan>,
    checkpoint: Option<ReplaySealedCheckpoint>,
    shared_merge_projection: Option<ReplaySealedSharedMergeProjection>,
    shared_ordered_commit: Option<ReplaySealedSharedOrderedCommit>,
    system_authority_write: Option<ReplaySystemAuthorityWrite>,
    fence_ancestry: FenceAncestryEvidence,
    mode: ReplayPublicationMode,
}

/// Replay-authenticated pre-transition Merge(F) projection retained as an
/// immutable publication dependency for Shared exact retry and recovery.
///
/// This is deliberately not a public wire capability: only the Shared replay
/// path can place it inside a sealed publication, and storage validates and
/// persists it before making the successor heads visible.
#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) struct ReplaySealedSharedMergeProjection {
    manifest: LaneStateManifest,
    state: Vec<u8>,
}

impl ReplaySealedSharedMergeProjection {
    pub(crate) const fn manifest(&self) -> &LaneStateManifest {
        &self.manifest
    }

    pub(crate) fn state(&self) -> &[u8] {
        &self.state
    }
}

/// Full deterministic claim derived while applying one durable Shared Raft
/// slot. Storage binds it immutably to the Ordered entry before the successor
/// head CAS so a crash between publication and ledger anchoring is retryable.
#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) struct ReplaySealedSharedOrderedCommit {
    journal_store: JournalStoreInstanceId,
    claim: OrderedCommitClaim,
    raft_payload_commitment: Hash,
}

impl ReplaySealedSharedOrderedCommit {
    pub(crate) const fn journal_store(&self) -> JournalStoreInstanceId {
        self.journal_store
    }

    pub(crate) const fn claim(&self) -> &OrderedCommitClaim {
        &self.claim
    }

    pub(crate) const fn raft_payload_commitment(&self) -> Hash {
        self.raft_payload_commitment
    }
}

/// Opaque proof that one exact replay-derived Shared projection is visible at
/// the journal head. The evidence ledger accepts this receipt, never a raw
/// caller-supplied claim.
#[derive(Debug)]
pub(crate) struct PublishedSharedOrdered {
    journal_store: JournalStoreInstanceId,
    claim: OrderedCommitClaim,
    entry: OrderedEntryId,
    successor: JournalHeadsId,
    raft_payload_commitment: Hash,
    reservation: ReservedAgentRaftApplication,
}

impl PublishedSharedOrdered {
    pub(crate) const fn journal_store(&self) -> JournalStoreInstanceId {
        self.journal_store
    }

    pub(crate) const fn claim(&self) -> &OrderedCommitClaim {
        &self.claim
    }

    pub(crate) const fn entry(&self) -> OrderedEntryId {
        self.entry
    }

    pub(crate) const fn successor(&self) -> JournalHeadsId {
        self.successor
    }

    pub(crate) const fn raft_index(&self) -> u64 {
        self.claim.raft_index()
    }

    pub(crate) const fn raft_term(&self) -> u64 {
        self.claim.raft_term()
    }

    pub(crate) const fn raft_payload_commitment(&self) -> Hash {
        self.raft_payload_commitment
    }

    pub(crate) const fn reservation(&self) -> &ReservedAgentRaftApplication {
        &self.reservation
    }

    #[cfg(feature = "std")]
    fn from_binding(
        binding: &ReplaySealedSharedOrderedCommit,
        successor: JournalHeadsId,
        authority: CommittedSharedOrdered,
    ) -> Result<Self, JournalStoreError> {
        let entry = binding
            .claim
            .ordered()
            .head
            .ok_or(JournalStoreError::NonCanonical)?;
        if binding.claim.validate().is_err()
            || successor == JournalHeadsId::ZERO
            || binding.raft_payload_commitment == Hash::ZERO
            || binding.journal_store != authority.journal_store
            || binding.claim.genesis() != authority.route.genesis()
            || binding.claim.admission() != authority.route.admission()
            || binding.claim.committee() != authority.route.committee()
            || binding.claim.raft_index() != authority.raft_index
            || binding.claim.raft_term() != authority.raft_term
            || entry != authority.entry.id()
            || binding.raft_payload_commitment != authority.raft_payload_commitment
        {
            return Err(JournalStoreError::NonCanonical);
        }
        Ok(Self {
            journal_store: binding.journal_store,
            claim: binding.claim.clone(),
            entry,
            successor,
            raft_payload_commitment: binding.raft_payload_commitment,
            reservation: authority.reservation,
        })
    }
}

/// Exact input/outcome pair authenticated by replay and installed before the
/// successor ownership root becomes visible.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ReplaySealedOutcome {
    record: InvocationOutcomeRecord,
    input: ReplayInput,
}

impl ReplaySealedOutcome {
    pub fn record(&self) -> &InvocationOutcomeRecord {
        &self.record
    }

    pub fn input(&self) -> &ReplayInput {
        &self.input
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
struct MaterializedOrderedSnapshot {
    runtime: RuntimeBinding,
    control: Vec<u8>,
    linear: Vec<u8>,
}

const MAX_MATERIALIZED_ORDERED_SNAPSHOTS: usize = MAX_REPLAY_SUFFIX_ENTRIES + 1;
const MAX_MATERIALIZED_ORDERED_SNAPSHOT_BYTES: usize = MAX_REPLAY_SUFFIX_BYTES;

/// Bounded authenticated cache of the Control/Linear images needed by the
/// current replay suffix. Checkpoint compaction retains only the current
/// ordered base; any older base must be supplied by the certified resolver.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
struct MaterializedOrderedSnapshots {
    values: BTreeMap<OrderedBase, MaterializedOrderedSnapshot>,
    bytes: usize,
}

/// Exact native system-authority side product reconstructed while replaying
/// the current canonical Ordered head. This is process-local evidence inside
/// an authenticated materialization, never a persisted or caller-supplied
/// backwards state transition.
#[derive(Clone, Debug, PartialEq, Eq)]
struct ReplayMaterializedSystemAuthorityWrite {
    entry: OrderedEntry,
    write: ReplaySystemAuthorityWrite,
}

impl MaterializedOrderedSnapshots {
    fn get(&self, base: &OrderedBase) -> Option<&MaterializedOrderedSnapshot> {
        self.values.get(base)
    }

    fn iter(&self) -> impl Iterator<Item = (&OrderedBase, &MaterializedOrderedSnapshot)> {
        self.values.iter()
    }

    fn len(&self) -> usize {
        self.values.len()
    }

    fn insert(
        &mut self,
        base: OrderedBase,
        snapshot: MaterializedOrderedSnapshot,
    ) -> Result<(), ReplayValidationError> {
        let snapshot_bytes = snapshot
            .control
            .len()
            .checked_add(snapshot.linear.len())
            .ok_or(ReplayError::ReplayLimit)?;
        if let Some(existing) = self.values.get(&base) {
            return if existing == &snapshot {
                Ok(())
            } else {
                Err(ReplayError::InvalidOrderedBase)
            };
        }
        let next_count = self
            .values
            .len()
            .checked_add(1)
            .ok_or(ReplayError::ReplayLimit)?;
        let next_bytes = self
            .bytes
            .checked_add(snapshot_bytes)
            .ok_or(ReplayError::ReplayLimit)?;
        if next_count > MAX_MATERIALIZED_ORDERED_SNAPSHOTS
            || next_bytes > MAX_MATERIALIZED_ORDERED_SNAPSHOT_BYTES
        {
            return Err(ReplayError::ReplayLimit);
        }
        self.values.insert(base, snapshot);
        self.bytes = next_bytes;
        Ok(())
    }

    fn singleton(
        base: OrderedBase,
        snapshot: MaterializedOrderedSnapshot,
    ) -> Result<Self, ReplayValidationError> {
        let mut snapshots = Self::default();
        snapshots.insert(base, snapshot)?;
        Ok(snapshots)
    }

    fn validate(&self) -> Result<(), ReplayValidationError> {
        let bytes = self.values.values().try_fold(0usize, |bytes, snapshot| {
            bytes
                .checked_add(snapshot.control.len())
                .and_then(|bytes| bytes.checked_add(snapshot.linear.len()))
                .ok_or(ReplayError::ReplayLimit)
        })?;
        if bytes != self.bytes {
            Err(ReplayError::InvalidRecord)
        } else if self.values.len() > MAX_MATERIALIZED_ORDERED_SNAPSHOTS
            || bytes > MAX_MATERIALIZED_ORDERED_SNAPSHOT_BYTES
        {
            Err(ReplayError::ReplayLimit)
        } else {
            Ok(())
        }
    }
}

/// Exact checkpoint-relative dependency budget for the durable suffix.
///
/// The identity sets are retained in the opaque materialization so live
/// publication charges the same unique records as crash recovery. A
/// checkpoint is the only operation which resets this value.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
struct ReplaySuffixBudget {
    entries: usize,
    bytes: usize,
    ordered: BTreeSet<OrderedEntryId>,
    local: BTreeSet<LocalEntryId>,
    merge: BTreeSet<MergeEventId>,
    frontiers: BTreeSet<MergeFrontierId>,
    seals: BTreeSet<MergeSealId>,
}

impl ReplaySuffixBudget {
    fn add_entry(&mut self, inserted: bool, encoded: usize) -> Result<(), ReplayValidationError> {
        if !inserted {
            return Ok(());
        }
        self.entries = self
            .entries
            .checked_add(1)
            .ok_or(ReplayError::ReplayLimit)?;
        self.bytes = self
            .bytes
            .checked_add(encoded)
            .ok_or(ReplayError::ReplayLimit)?;
        self.validate_limits()
    }

    fn ordered(
        &mut self,
        id: OrderedEntryId,
        entry: &OrderedEntry,
    ) -> Result<(), ReplayValidationError> {
        let inserted = self.ordered.insert(id);
        self.add_entry(inserted, entry.encode().len())
    }

    fn local(&mut self, id: LocalEntryId, entry: &LocalEntry) -> Result<(), ReplayValidationError> {
        let inserted = self.local.insert(id);
        self.add_entry(inserted, entry.encode().len())
    }

    fn merge(&mut self, id: MergeEventId, event: &MergeEvent) -> Result<(), ReplayValidationError> {
        let inserted = self.merge.insert(id);
        self.add_entry(inserted, event.encode().len())
    }

    fn frontier(&mut self, frontier: &MergeFrontier) -> Result<(), ReplayValidationError> {
        if self.frontiers.insert(frontier.id()) {
            self.bytes = self
                .bytes
                .checked_add(frontier.encode().len())
                .ok_or(ReplayError::ReplayLimit)?;
        }
        self.validate_limits()
    }

    fn seal(&mut self, seal: &MergeSeal) -> Result<(), ReplayValidationError> {
        if self.seals.insert(seal.id()) {
            self.bytes = self
                .bytes
                .checked_add(seal.encode().len())
                .ok_or(ReplayError::ReplayLimit)?;
        }
        self.validate_limits()
    }

    fn validate_limits(&self) -> Result<(), ReplayValidationError> {
        if self.entries > MAX_REPLAY_SUFFIX_ENTRIES || self.bytes > MAX_REPLAY_SUFFIX_BYTES {
            Err(ReplayError::ReplayLimit)
        } else {
            Ok(())
        }
    }

    fn validate(&self) -> Result<(), ReplayValidationError> {
        let indexed_entries = self
            .ordered
            .len()
            .checked_add(self.local.len())
            .and_then(|count| count.checked_add(self.merge.len()))
            .ok_or(ReplayError::ReplayLimit)?;
        if self.entries != indexed_entries {
            Err(ReplayError::InvalidRecord)
        } else {
            self.validate_limits()
        }
    }
}

/// Authenticated aggregate initialized from the exact durable head's genesis
/// or checkpoint closure and advanced through its complete bounded suffix.
/// Every field is private: callers may inspect facts but cannot substitute
/// state bytes or cursors when preparing a publication.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ReplayMaterialization {
    heads_id: JournalHeadsId,
    heads: JournalHeads,
    replayed_root: Option<ReplayedRootJournalIdentity>,
    state: RuntimeState,
    final_system_authority_write: Option<ReplayMaterializedSystemAuthorityWrite>,
    ordered_snapshots: MaterializedOrderedSnapshots,
    merge_roots: Vec<SealedMergeRoot>,
    /// Retained roots of the authenticated replay boundary. A new Merge
    /// branch may descend from these roots or any loaded descendant, but not
    /// from a pruned internal ancestor. An empty set is the post-genesis
    /// boundary and permits independent height-one roots.
    merge_boundary_roots: BTreeSet<MergeEventId>,
    merge_boundary_ancestry: BTreeSet<MergeEventId>,
    merge_boundary_state: Vec<u8>,
    merge_boundary_invocations: InvocationIndexId,
    merge_ancestry: BTreeSet<MergeEventId>,
    fence: Option<MergeFence>,
    artifacts: ArtifactClosure,
    suffix_budget: ReplaySuffixBudget,
    replay_boundary: OrderedBase,
    fence_ancestry: FenceAncestryEvidence,
}

impl ReplayMaterialization {
    pub const fn heads_id(&self) -> JournalHeadsId {
        self.heads_id
    }

    pub fn heads(&self) -> &JournalHeads {
        &self.heads
    }

    pub fn state(&self) -> &RuntimeState {
        &self.state
    }

    pub fn runtime(&self) -> &RuntimeBinding {
        &self.heads.runtime
    }

    pub const fn ordered_base(&self) -> OrderedBase {
        OrderedBase {
            index: self.heads.ordered_index,
            head: self.heads.ordered_head,
        }
    }

    pub const fn merge_frontier(&self) -> MergeFrontierId {
        self.heads.merge_frontier
    }

    /// Whether an immutable Merge object is reachable from the authenticated
    /// materialized head. A journal store may also contain crash-safe staged
    /// objects; mere content presence is deliberately not publication proof.
    pub(crate) fn contains_merge(&self, event: MergeEventId) -> bool {
        self.merge_ancestry.contains(&event)
    }

    pub const fn local_cursor(&self) -> (NodeId, u64, Option<LocalEntryId>) {
        (
            self.heads.node,
            self.heads.local_revision,
            self.heads.local_head,
        )
    }

    pub const fn invocation_indexes(
        &self,
    ) -> (InvocationIndexId, InvocationIndexId, InvocationIndexId) {
        (
            self.heads.ordered_invocations,
            self.heads.merge_invocations,
            self.heads.local_invocations,
        )
    }

    pub fn artifacts(&self) -> &ArtifactClosure {
        &self.artifacts
    }

    /// Attach root provenance only from the exact independently reverified
    /// seal for this already authenticated materialization. Cold store
    /// integration calls this seam in batch 5c; until then reopen remains
    /// deliberately unscoped.
    pub(crate) fn attach_replayed_root(
        &mut self,
        sealed: &ReplaySealedGenesis,
    ) -> Result<(), ReplayValidationError> {
        let identity = sealed.replayed_root_identity()?;
        self.attach_replayed_root_identity(identity)
    }

    fn attach_replayed_root_identity(
        &mut self,
        identity: ReplayedRootJournalIdentity,
    ) -> Result<(), ReplayValidationError> {
        if identity.genesis() != self.heads.genesis
            || identity.outer_admission() != self.heads.admission
        {
            return Err(ReplayError::ScopeMismatch);
        }
        self.replayed_root = Some(identity);
        Ok(())
    }

    pub(crate) const fn replayed_root(&self) -> Option<ReplayedRootJournalIdentity> {
        self.replayed_root
    }
}

/// One prepared CAS and the only successor materialization which may become
/// usable if that CAS succeeds. `publish` consumes the session on every path;
/// a conflict therefore discards all staged root IDs. The exclusive store
/// borrow binds every candidate index path and outcome staged during prepare
/// to the exact store which performs the CAS; safe callers cannot transfer a
/// prepared publication to another store or mutate that store in between.
#[cfg(feature = "std")]
pub struct ReplayPreparedPublication<'store, S: AgentJournalStore> {
    store: &'store mut S,
    sealed: ReplaySealedPublication,
    successor: ReplayMaterialization,
    executions: Vec<ReplayExecutionResult>,
}

/// Authenticated execution facts carried by a prepared journal publication.
/// The durable reply itself remains in the scoped invocation-result state of
/// the returned successor materialization; these fields tell the driver
/// exactly which result to recover without re-executing the input.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ReplayExecutionResult {
    outcome: ReplayStepOutcome,
    result: Option<Result<ActorExecutionReply, ActorExecutionError>>,
    products: ReplayProducts,
    input: super::journal::ReplayInputId,
    position: ReplayPosition,
}

impl ReplayExecutionResult {
    pub const fn outcome(&self) -> ReplayStepOutcome {
        self.outcome
    }

    pub fn result(&self) -> Option<&Result<ActorExecutionReply, ActorExecutionError>> {
        self.result.as_ref()
    }

    pub const fn products(&self) -> ReplayProducts {
        self.products
    }

    pub const fn input(&self) -> super::journal::ReplayInputId {
        self.input
    }

    pub const fn position(&self) -> ReplayPosition {
        self.position
    }
}

/// Exact committed input which must be recovered from authenticated state on
/// a response-loss retry. No runtime transition is executed a second time.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct ReplayCommittedRecovery {
    input: super::journal::ReplayInputId,
    position: ReplayPosition,
}

/// Authenticated durable state of one scoped invocation identity. A retained
/// result is loaded through the exact ownership root in `ReplayMaterialization`;
/// decoded outcome bytes alone never confer this authority.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum ReplayInvocationRecovery {
    NotCommitted,
    Pending,
    Retained(Result<ActorExecutionReply, ActorExecutionError>),
    Acknowledged,
    Divergent,
}

impl ReplayCommittedRecovery {
    pub const fn input(self) -> super::journal::ReplayInputId {
        self.input
    }

    pub const fn position(self) -> ReplayPosition {
        self.position
    }
}

#[cfg(feature = "std")]
impl<'store, S: AgentJournalStore> ReplayPreparedPublication<'store, S> {
    pub fn publish(
        self,
    ) -> Result<
        (
            JournalPublication,
            ReplayMaterialization,
            Vec<ReplayExecutionResult>,
        ),
        JournalStoreError,
    > {
        if self.sealed.mode != ReplayPublicationMode::Canonical
            || self.sealed.shared_ordered_commit.is_some()
            || self.sealed.system_authority_write.is_some()
        {
            return Err(JournalStoreError::NonCanonical);
        }
        let publication = self.store.publish(&self.sealed)?;
        Ok((publication, self.successor, self.executions))
    }
}

/// Owned, read-only-derived Shared checkpoint plan. Candidate construction
/// writes nothing; only a quorum-verified snapshot capability can stage its
/// content-addressed lane blobs and cross the journal-head CAS.
#[cfg(feature = "std")]
pub(crate) struct PreparedSharedCheckpoint {
    sealed: ReplaySealedPublication,
    successor: ReplayMaterialization,
    lane_blobs: Vec<(BlobRef, Vec<u8>)>,
}

#[cfg(feature = "std")]
impl PreparedSharedCheckpoint {
    pub(crate) fn predecessor_heads(&self) -> JournalHeadsId {
        self.sealed.expected
    }

    pub(crate) fn next_heads(&self) -> &JournalHeads {
        self.sealed.next()
    }

    pub(crate) fn checkpoint(&self) -> &ReplaySealedCheckpoint {
        self.sealed
            .checkpoint_validation()
            .expect("Shared checkpoint plans always carry validation")
    }

    pub(crate) fn lane_roots(
        &self,
    ) -> Option<(LaneStateId, LaneStateId, LaneStateId, LaneStateId)> {
        let mut roots = [None; 4];
        for (lane, state) in self.checkpoint().lanes() {
            let index = match lane.lane {
                PersistedLane::Control => 0,
                PersistedLane::Linear => 1,
                PersistedLane::Merge => 2,
                PersistedLane::Local if lane.node == Some(self.successor.heads.node) => 3,
                PersistedLane::Local => return None,
            };
            if roots[index].replace(state.id()).is_some() {
                return None;
            }
        }
        Some((roots[0]?, roots[1]?, roots[2]?, roots[3]?))
    }

    pub(crate) fn validate_claim(
        &self,
        claim: &SharedAgentSnapshotClaim,
    ) -> Result<(), JournalStoreError> {
        let checkpoint = self.checkpoint();
        let manifest = checkpoint.manifest();
        let mut control = None;
        let mut linear = None;
        let mut merge = None;
        let mut local = None;
        for (lane, state) in checkpoint.lanes() {
            match lane.lane {
                PersistedLane::Control if lane.node.is_none() => control = Some(state.id()),
                PersistedLane::Linear if lane.node.is_none() => linear = Some(state.id()),
                PersistedLane::Merge if lane.node.is_none() => merge = Some(state.id()),
                PersistedLane::Local if lane.node == Some(self.successor.heads.node) => {
                    local = Some(state.id())
                }
                _ => return Err(JournalStoreError::NonCanonical),
            }
        }
        if claim.checkpoint_predecessor() != self.sealed.expected
            || claim.journal_heads() != self.successor.heads_id
            || claim.checkpoint() != manifest.id()
            || claim.local_node() != self.successor.heads.node
            || control != Some(claim.control())
            || linear != Some(claim.linear())
            || merge != Some(claim.merge())
            || local != Some(claim.local())
            || claim.ordered_invocations() != self.successor.heads.ordered_invocations
            || claim.merge_invocations() != self.successor.heads.merge_invocations
            || claim.local_invocations() != self.successor.heads.local_invocations
            || claim.artifacts() != manifest.artifacts
            || self.successor.artifacts.id() != manifest.artifacts
            || manifest.ordered_index != claim.ordered().ordered().index
            || manifest.ordered_head != claim.ordered().ordered().head
            || manifest.runtime != *claim.ordered().runtime()
        {
            return Err(JournalStoreError::NonCanonical);
        }
        Ok(())
    }

    pub(crate) fn publish_shared<S: AgentJournalStore>(
        self,
        store: &mut S,
        verified: &VerifiedSharedAgentSnapshot,
    ) -> Result<ReplayMaterialization, JournalStoreError> {
        self.validate_claim(verified.claim())?;
        if store.instance_id().as_bytes() != &verified.claim().journal_store().0 {
            return Err(JournalStoreError::ScopeMismatch);
        }
        for (reference, bytes) in &self.lane_blobs {
            store.put_blob(JournalBlobClass::LaneState, reference, bytes)?;
        }
        let publication = store.publish(&self.sealed)?;
        if !publication.heads_advanced && store.heads()?.as_ref() != Some(self.sealed.next()) {
            return Err(JournalStoreError::Corrupt);
        }
        Ok(self.successor)
    }
}

/// Non-clonable holder of one exact pre-publication Shared reservation. An
/// evidence ledger may reissue equivalent `(store, route, slot, payload)`
/// reservations after failure; safety comes from the bound physical store,
/// idempotent exact journal CAS, and single durable ledger anchor rather than
/// from global bearer uniqueness. The reservation remains outside the
/// clonable sealed-store token and crosses into the receipt only after CAS.
#[cfg(feature = "std")]
pub(crate) struct PreparedSharedOrderedPublication<'store, S: AgentJournalStore> {
    inner: ReplayPreparedPublication<'store, S>,
    authority: CommittedSharedOrdered,
}

#[cfg(feature = "std")]
impl<'store, S: AgentJournalStore> PreparedSharedOrderedPublication<'store, S> {
    pub(crate) fn publish_shared(
        self,
    ) -> Result<
        (
            JournalPublication,
            ReplayMaterialization,
            Vec<ReplayExecutionResult>,
            PublishedSharedOrdered,
        ),
        JournalStoreError,
    > {
        let Self { inner, authority } = self;
        if !matches!(
            inner.sealed.mode,
            ReplayPublicationMode::SharedOrderedPreserveMerge
                | ReplayPublicationMode::SharedOrderedInstallFence
        ) || inner.sealed.system_authority_write.is_some()
        {
            return Err(JournalStoreError::NonCanonical);
        }
        if inner.store.instance_id() != authority.journal_store {
            return Err(JournalStoreError::NonCanonical);
        }
        let binding = inner
            .sealed
            .shared_ordered_commit
            .as_ref()
            .ok_or(JournalStoreError::NonCanonical)?
            .clone();
        let successor = inner.successor.heads_id;
        let publication = inner.store.publish(&inner.sealed)?;
        let receipt = PublishedSharedOrdered::from_binding(&binding, successor, authority)?;
        Ok((publication, inner.successor, inner.executions, receipt))
    }
}

/// Error crossing the independently crash-safe authority-ledger and journal
/// publication boundaries.
#[cfg(all(feature = "std", feature = "storage"))]
#[derive(Debug)]
pub(crate) enum SystemAuthorityPublicationError {
    Journal(JournalStoreError),
    Ledger(SystemAuthorityLedgerError),
}

#[cfg(all(feature = "std", feature = "storage"))]
impl From<JournalStoreError> for SystemAuthorityPublicationError {
    fn from(error: JournalStoreError) -> Self {
        Self::Journal(error)
    }
}

#[cfg(all(feature = "std", feature = "storage"))]
impl From<SystemAuthorityLedgerError> for SystemAuthorityPublicationError {
    fn from(error: SystemAuthorityLedgerError) -> Self {
        Self::Ledger(error)
    }
}

/// Failure to classify and validate one cold pending rotation against the
/// independently reverified current journal.
#[cfg(all(feature = "std", feature = "storage"))]
#[derive(Debug)]
pub(crate) enum SystemAuthorityRecoveryError<ExecutorError> {
    Journal(JournalStoreError),
    Ledger(SystemAuthorityLedgerError),
    Replay(ReplayError<ReplayMaterializationSourceError<core::convert::Infallible>, ExecutorError>),
}

#[cfg(all(feature = "std", feature = "storage"))]
impl<ExecutorError> From<JournalStoreError> for SystemAuthorityRecoveryError<ExecutorError> {
    fn from(error: JournalStoreError) -> Self {
        Self::Journal(error)
    }
}

#[cfg(all(feature = "std", feature = "storage"))]
impl<ExecutorError> From<SystemAuthorityLedgerError>
    for SystemAuthorityRecoveryError<ExecutorError>
{
    fn from(error: SystemAuthorityLedgerError) -> Self {
        Self::Ledger(error)
    }
}

/// Exact replay-owned facts committed durably before crossing the journal CAS
/// and retained by the opaque post-CAS receipt. The private fields prevent a
/// caller-constructed successor tuple from becoming either publication intent
/// or retirement authority.
#[cfg(all(feature = "std", feature = "storage"))]
#[derive(Debug)]
pub(crate) struct SystemAuthorityRotationPublicationFacts {
    journal_store: JournalStoreInstanceId,
    predecessor_heads: JournalHeadsId,
    successor_heads: JournalHeadsId,
    ordered_entry: OrderedEntry,
    predecessor_control: LaneStateId,
    successor_control: LaneStateId,
    predecessor_view: Hash,
    successor_view: Hash,
    predecessor_authority_state: Hash,
    successor_authority_state: Hash,
    claim: AuthorityClaimCommitment,
    command: SystemAuthorityRotation,
    operation: Hash,
    result: LifecycleReply,
    record: SystemAuthorityRotationRecord,
    root: SystemAuthorityRotationNodeId,
    storage_plan: Hash,
}

#[cfg(all(feature = "std", feature = "storage"))]
impl SystemAuthorityRotationPublicationFacts {
    pub(crate) const fn journal_store(&self) -> JournalStoreInstanceId {
        self.journal_store
    }

    pub(crate) const fn predecessor_heads(&self) -> JournalHeadsId {
        self.predecessor_heads
    }

    pub(crate) const fn successor_heads(&self) -> JournalHeadsId {
        self.successor_heads
    }

    pub(crate) const fn ordered_entry(&self) -> &OrderedEntry {
        &self.ordered_entry
    }

    pub(crate) fn ordered_entry_id(&self) -> OrderedEntryId {
        self.ordered_entry.id()
    }

    pub(crate) const fn predecessor_control(&self) -> LaneStateId {
        self.predecessor_control
    }

    pub(crate) const fn successor_control(&self) -> LaneStateId {
        self.successor_control
    }

    pub(crate) const fn predecessor_view(&self) -> Hash {
        self.predecessor_view
    }

    pub(crate) const fn successor_view(&self) -> Hash {
        self.successor_view
    }

    pub(crate) const fn predecessor_authority_state(&self) -> Hash {
        self.predecessor_authority_state
    }

    pub(crate) const fn successor_authority_state(&self) -> Hash {
        self.successor_authority_state
    }

    pub(crate) const fn claim(&self) -> AuthorityClaimCommitment {
        self.claim
    }

    pub(crate) const fn command(&self) -> &SystemAuthorityRotation {
        &self.command
    }

    pub(crate) const fn operation(&self) -> Hash {
        self.operation
    }

    pub(crate) const fn result(&self) -> &LifecycleReply {
        &self.result
    }

    pub(crate) const fn record(&self) -> &SystemAuthorityRotationRecord {
        &self.record
    }

    pub(crate) const fn root(&self) -> SystemAuthorityRotationNodeId {
        self.root
    }

    pub(crate) const fn storage_plan(&self) -> Hash {
        self.storage_plan
    }

    /// Domain-separated commitment persisted in the evidence ledger before
    /// any authority dependency or successor Heads can become durable.
    pub(crate) fn commitment(&self) -> Hash {
        const DOMAIN: &[u8] = b"vos/agent/system-authority-publication-intent/v2";
        const ENTRY_DOMAIN: &[u8] = b"vos/agent/system-authority-publication-entry/v1";
        const COMMAND_DOMAIN: &[u8] = b"vos/agent/system-authority-publication-command/v1";
        const RESULT_DOMAIN: &[u8] = b"vos/agent/system-authority-publication-result/v1";
        const RECORD_DOMAIN: &[u8] = b"vos/agent/system-authority-publication-record/v1";
        let command = self.command.encode();
        let result = match &self.result {
            LifecycleReply::SystemAuthorityRotated {
                rotation,
                epoch,
                exact_retry,
            } => Hash::digest(
                RESULT_DOMAIN,
                &[
                    rotation.as_bytes(),
                    &epoch.to_le_bytes(),
                    &[u8::from(*exact_retry)],
                ],
            ),
            _ => Hash::ZERO,
        };
        let record = self.record.encode();
        let entry = self.ordered_entry.encode();
        let entry = Hash::digest(ENTRY_DOMAIN, &[&entry]);
        let command = Hash::digest(COMMAND_DOMAIN, &[&command]);
        let record = Hash::digest(RECORD_DOMAIN, &[&record]);
        Hash::digest(
            DOMAIN,
            &[
                self.journal_store.as_bytes(),
                self.predecessor_heads.as_bytes(),
                self.successor_heads.as_bytes(),
                self.ordered_entry.id().as_bytes(),
                &entry.0,
                self.predecessor_control.as_bytes(),
                self.successor_control.as_bytes(),
                &self.predecessor_view.0,
                &self.successor_view.0,
                &self.predecessor_authority_state.0,
                &self.successor_authority_state.0,
                &self.claim.claim_hash().0,
                &self.operation.0,
                &command.0,
                &result.0,
                &record.0,
                self.record.id().as_bytes(),
                self.record.leaf_id().as_bytes(),
                self.root.as_bytes(),
                self.record.old_committee().as_bytes(),
                self.record.new_committee().as_bytes(),
                &self.storage_plan.0,
            ],
        )
    }
}

/// Exact replay-owned catalog successor facts committed to the authority
/// ledger before any catalog-history dependency or journal Heads CAS.
/// Construction is restricted to a fresh vacant-proof insertion.
#[cfg(all(feature = "std", feature = "storage"))]
#[derive(Debug)]
pub(crate) struct SystemAuthorityCatalogPublicationFacts {
    journal_store: JournalStoreInstanceId,
    predecessor_heads: JournalHeadsId,
    successor_heads: JournalHeadsId,
    ordered_entry: OrderedEntry,
    predecessor_control: LaneStateId,
    successor_control: LaneStateId,
    predecessor_view: Hash,
    successor_view: Hash,
    predecessor_authority_state: Hash,
    successor_authority_state: Hash,
    claim: AuthorityClaimCommitment,
    command: SystemAuthorityCatalogFinalize,
    operation: Hash,
    result: LifecycleReply,
    record: SystemAuthorityCatalogRecord,
    root: SystemAuthorityCatalogNodeId,
    storage_plan: Hash,
}

#[cfg(all(feature = "std", feature = "storage"))]
impl SystemAuthorityCatalogPublicationFacts {
    pub(crate) const fn journal_store(&self) -> JournalStoreInstanceId {
        self.journal_store
    }

    pub(crate) const fn predecessor_heads(&self) -> JournalHeadsId {
        self.predecessor_heads
    }

    pub(crate) const fn successor_heads(&self) -> JournalHeadsId {
        self.successor_heads
    }

    pub(crate) const fn ordered_entry(&self) -> &OrderedEntry {
        &self.ordered_entry
    }

    pub(crate) fn ordered_entry_id(&self) -> OrderedEntryId {
        self.ordered_entry.id()
    }

    pub(crate) const fn predecessor_control(&self) -> LaneStateId {
        self.predecessor_control
    }

    pub(crate) const fn successor_control(&self) -> LaneStateId {
        self.successor_control
    }

    pub(crate) const fn predecessor_view(&self) -> Hash {
        self.predecessor_view
    }

    pub(crate) const fn successor_view(&self) -> Hash {
        self.successor_view
    }

    pub(crate) const fn predecessor_authority_state(&self) -> Hash {
        self.predecessor_authority_state
    }

    pub(crate) const fn successor_authority_state(&self) -> Hash {
        self.successor_authority_state
    }

    pub(crate) const fn claim(&self) -> AuthorityClaimCommitment {
        self.claim
    }

    pub(crate) const fn command(&self) -> &SystemAuthorityCatalogFinalize {
        &self.command
    }

    pub(crate) const fn operation(&self) -> Hash {
        self.operation
    }

    pub(crate) const fn result(&self) -> &LifecycleReply {
        &self.result
    }

    pub(crate) const fn record(&self) -> &SystemAuthorityCatalogRecord {
        &self.record
    }

    pub(crate) const fn root(&self) -> SystemAuthorityCatalogNodeId {
        self.root
    }

    pub(crate) const fn storage_plan(&self) -> Hash {
        self.storage_plan
    }

    /// Domain-separated exact-candidate commitment. The command and record
    /// encodings retain the complete mutation, result projection, QC, and
    /// sparse proof rather than reducing publication intent to caller-chosen
    /// hashes.
    pub(crate) fn commitment(&self) -> Hash {
        const DOMAIN: &[u8] = b"vos/agent/system-authority-catalog-publication-intent/v1";
        const ENTRY_DOMAIN: &[u8] = b"vos/agent/system-authority-catalog-publication-entry/v1";
        const COMMAND_DOMAIN: &[u8] = b"vos/agent/system-authority-catalog-publication-command/v1";
        const RESULT_DOMAIN: &[u8] = b"vos/agent/system-authority-catalog-publication-result/v1";
        const RECORD_DOMAIN: &[u8] = b"vos/agent/system-authority-catalog-publication-record/v1";
        let entry = Hash::digest(ENTRY_DOMAIN, &[&self.ordered_entry.encode()]);
        let command = Hash::digest(COMMAND_DOMAIN, &[&self.command.encode()]);
        let record = Hash::digest(RECORD_DOMAIN, &[&self.record.encode()]);
        let result = match self.result {
            LifecycleReply::CatalogFinalized(outcome) => {
                let tag = if outcome.operation_conflicted() {
                    2
                } else if outcome.exact_retry() {
                    1
                } else {
                    0
                };
                let result = outcome.result().unwrap_or(Hash::ZERO);
                let catalog_head = outcome.catalog_head().unwrap_or(Hash::ZERO);
                let authority_generation = outcome.authority_generation().unwrap_or(Hash::ZERO);
                let sequence = outcome.sequence().unwrap_or_default().to_le_bytes();
                let occupied = outcome.occupied_record_id().unwrap_or_default();
                Hash::digest(
                    RESULT_DOMAIN,
                    &[
                        &[tag],
                        &outcome.operation().0,
                        &result.0,
                        &catalog_head.0,
                        &authority_generation.0,
                        &sequence,
                        occupied.as_bytes(),
                    ],
                )
            }
            _ => Hash::ZERO,
        };
        Hash::digest(
            DOMAIN,
            &[
                self.journal_store.as_bytes(),
                self.predecessor_heads.as_bytes(),
                self.successor_heads.as_bytes(),
                self.ordered_entry.id().as_bytes(),
                &entry.0,
                self.predecessor_control.as_bytes(),
                self.successor_control.as_bytes(),
                &self.predecessor_view.0,
                &self.successor_view.0,
                &self.predecessor_authority_state.0,
                &self.successor_authority_state.0,
                &self.claim.claim_hash().0,
                &self.operation.0,
                &command.0,
                &result.0,
                &record.0,
                self.record.id().as_bytes(),
                self.record.leaf_id().as_bytes(),
                self.root.as_bytes(),
                &self.record.receipt().certificate().committee().0,
                &self.storage_plan.0,
            ],
        )
    }
}

/// Opaque post-CAS rotation receipt. Holding the physical store borrow keeps
/// same-process code from advancing this journal again before ledger
/// retirement consumes the exact receipt and returns the replay results.
#[cfg(all(feature = "std", feature = "storage"))]
pub(crate) struct PublishedSystemAuthorityRotation<'store, S: AgentJournalStore> {
    store: &'store mut S,
    reserved: ReservedSystemAuthorityClaim,
    facts: SystemAuthorityRotationPublicationFacts,
    publication: JournalPublication,
    successor: ReplayMaterialization,
    executions: Vec<ReplayExecutionResult>,
}

#[cfg(all(feature = "std", feature = "storage"))]
impl<'store, S: AgentJournalStore> PublishedSystemAuthorityRotation<'store, S> {
    pub(crate) const fn reserved(&self) -> &ReservedSystemAuthorityClaim {
        &self.reserved
    }

    pub(crate) const fn facts(&self) -> &SystemAuthorityRotationPublicationFacts {
        &self.facts
    }

    /// Release the store borrow and replay results only after the evidence
    /// ledger has durably retired this exact receipt. The sole production
    /// caller is `SystemAuthorityEvidenceLedger::retire_published_rotation`.
    pub(crate) fn into_results(
        self,
        _retired: RetiredSystemAuthorityRotation,
    ) -> (
        JournalPublication,
        ReplayMaterialization,
        Vec<ReplayExecutionResult>,
    ) {
        let Self {
            store: _,
            reserved: _,
            facts: _,
            publication,
            successor,
            executions,
        } = self;
        (publication, successor, executions)
    }
}

/// Cold-reconstructed proof that the exact intent successor is already the
/// reverified physical store head. It is rotation-retirement evidence only:
/// the receipt is non-Clone, retains the mutable store borrow, and releases
/// the materialization solely through the ledger's private retirement token.
#[cfg(all(feature = "std", feature = "storage"))]
pub(crate) struct RecoveredSystemAuthorityRotation<'store, S: AgentJournalStore> {
    store: &'store mut S,
    pending: PendingSystemAuthorityRecovery,
    facts: SystemAuthorityRotationPublicationFacts,
    current: ReplayMaterialization,
    publication: Option<JournalPublication>,
    executions: Vec<ReplayExecutionResult>,
}

#[cfg(all(feature = "std", feature = "storage"))]
impl<'store, S: AgentJournalStore> RecoveredSystemAuthorityRotation<'store, S> {
    pub(crate) const fn pending(&self) -> &PendingSystemAuthorityRecovery {
        &self.pending
    }

    pub(crate) const fn facts(&self) -> &SystemAuthorityRotationPublicationFacts {
        &self.facts
    }

    pub(crate) fn into_retired(
        self,
        _retired: RetiredSystemAuthorityRotation,
    ) -> RetiredSystemAuthorityRotationRecovery {
        let Self {
            store: _,
            pending: _,
            facts: _,
            current,
            publication,
            executions,
        } = self;
        RetiredSystemAuthorityRotationRecovery {
            publication,
            materialization: current,
            executions,
        }
    }
}

/// Outputs released only after cold recovery atomically retires the exact
/// durable reservation, intent, and frozen QCs. An already-visible successor
/// has no recoverable publication response; an in-process cold resume retains
/// its exact journal publication and replay executions here.
#[cfg(all(feature = "std", feature = "storage"))]
pub(crate) struct RetiredSystemAuthorityRotationRecovery {
    publication: Option<JournalPublication>,
    materialization: ReplayMaterialization,
    executions: Vec<ReplayExecutionResult>,
}

#[cfg(all(feature = "std", feature = "storage"))]
impl RetiredSystemAuthorityRotationRecovery {
    pub(crate) const fn publication(&self) -> Option<&JournalPublication> {
        self.publication.as_ref()
    }

    pub(crate) const fn materialization(&self) -> &ReplayMaterialization {
        &self.materialization
    }

    pub(crate) fn executions(&self) -> &[ReplayExecutionResult] {
        &self.executions
    }

    pub(crate) fn into_parts(
        self,
    ) -> (
        Option<JournalPublication>,
        ReplayMaterialization,
        Vec<ReplayExecutionResult>,
    ) {
        (self.publication, self.materialization, self.executions)
    }
}

/// Cold reconciliation never upgrades a predecessor reservation into signing
/// authority. The predecessor status also retains the mutable store borrow so
/// startup cannot expose a mutable journal driver while its reservation is
/// unresolved.
#[cfg(all(feature = "std", feature = "storage"))]
pub(crate) struct ReconciledPendingSystemAuthorityRotation<'store, S: AgentJournalStore> {
    store: &'store mut S,
    current: ReplayMaterialization,
    pending: PendingSystemAuthorityRecovery,
}

#[cfg(all(feature = "std", feature = "storage"))]
impl<'store, S: AgentJournalStore> ReconciledPendingSystemAuthorityRotation<'store, S> {
    pub(crate) const fn current(&self) -> &ReplayMaterialization {
        &self.current
    }

    pub(crate) const fn pending(&self) -> &PendingSystemAuthorityRecovery {
        &self.pending
    }
}

/// Only an exact intent successor carries the opaque retirement receipt; both
/// outcomes keep the physical store quarantined.
#[cfg(all(feature = "std", feature = "storage"))]
pub(crate) enum PendingSystemAuthorityRotationRecovery<'store, S: AgentJournalStore> {
    Pending(ReconciledPendingSystemAuthorityRotation<'store, S>),
    Retired(RetiredSystemAuthorityRotationRecovery),
}

/// Opaque post-CAS catalog receipt. The physical store remains borrowed until
/// the evidence ledger retires the exact catalog reservation and intent.
#[cfg(all(feature = "std", feature = "storage"))]
pub(crate) struct PublishedSystemAuthorityCatalog<'store, S: AgentJournalStore> {
    store: &'store mut S,
    reserved: ReservedSystemAuthorityClaim,
    facts: SystemAuthorityCatalogPublicationFacts,
    publication: JournalPublication,
    successor: ReplayMaterialization,
    executions: Vec<ReplayExecutionResult>,
}

#[cfg(all(feature = "std", feature = "storage"))]
impl<'store, S: AgentJournalStore> PublishedSystemAuthorityCatalog<'store, S> {
    pub(crate) const fn reserved(&self) -> &ReservedSystemAuthorityClaim {
        &self.reserved
    }

    pub(crate) const fn facts(&self) -> &SystemAuthorityCatalogPublicationFacts {
        &self.facts
    }

    pub(crate) fn into_results(
        self,
        _retired: RetiredSystemAuthorityCatalog,
    ) -> (
        JournalPublication,
        ReplayMaterialization,
        Vec<ReplayExecutionResult>,
    ) {
        let Self {
            store: _,
            reserved: _,
            facts: _,
            publication,
            successor,
            executions,
        } = self;
        (publication, successor, executions)
    }
}

/// Cold-reconstructed proof that the exact catalog intent successor is the
/// independently reverified physical head.
#[cfg(all(feature = "std", feature = "storage"))]
pub(crate) struct RecoveredSystemAuthorityCatalog<'store, S: AgentJournalStore> {
    store: &'store mut S,
    pending: PendingSystemAuthorityRecovery,
    facts: SystemAuthorityCatalogPublicationFacts,
    current: ReplayMaterialization,
    publication: Option<JournalPublication>,
    executions: Vec<ReplayExecutionResult>,
}

#[cfg(all(feature = "std", feature = "storage"))]
impl<'store, S: AgentJournalStore> RecoveredSystemAuthorityCatalog<'store, S> {
    pub(crate) const fn pending(&self) -> &PendingSystemAuthorityRecovery {
        &self.pending
    }

    pub(crate) const fn facts(&self) -> &SystemAuthorityCatalogPublicationFacts {
        &self.facts
    }

    pub(crate) fn into_retired(
        self,
        _retired: RetiredSystemAuthorityCatalog,
    ) -> RetiredSystemAuthorityCatalogRecovery {
        let Self {
            store: _,
            pending: _,
            facts: _,
            current,
            publication,
            executions,
        } = self;
        RetiredSystemAuthorityCatalogRecovery {
            publication,
            materialization: current,
            executions,
        }
    }
}

/// Catalog replay outputs released only after durable retirement.
#[cfg(all(feature = "std", feature = "storage"))]
pub(crate) struct RetiredSystemAuthorityCatalogRecovery {
    publication: Option<JournalPublication>,
    materialization: ReplayMaterialization,
    executions: Vec<ReplayExecutionResult>,
}

#[cfg(all(feature = "std", feature = "storage"))]
impl RetiredSystemAuthorityCatalogRecovery {
    pub(crate) const fn publication(&self) -> Option<&JournalPublication> {
        self.publication.as_ref()
    }

    pub(crate) const fn materialization(&self) -> &ReplayMaterialization {
        &self.materialization
    }

    pub(crate) fn executions(&self) -> &[ReplayExecutionResult] {
        &self.executions
    }

    pub(crate) fn into_parts(
        self,
    ) -> (
        Option<JournalPublication>,
        ReplayMaterialization,
        Vec<ReplayExecutionResult>,
    ) {
        (self.publication, self.materialization, self.executions)
    }
}

#[cfg(all(feature = "std", feature = "storage"))]
pub(crate) struct ReconciledPendingSystemAuthorityCatalog<'store, S: AgentJournalStore> {
    store: &'store mut S,
    current: ReplayMaterialization,
    pending: PendingSystemAuthorityRecovery,
}

#[cfg(all(feature = "std", feature = "storage"))]
impl<'store, S: AgentJournalStore> ReconciledPendingSystemAuthorityCatalog<'store, S> {
    pub(crate) const fn current(&self) -> &ReplayMaterialization {
        &self.current
    }

    pub(crate) const fn pending(&self) -> &PendingSystemAuthorityRecovery {
        &self.pending
    }
}

#[cfg(all(feature = "std", feature = "storage"))]
pub(crate) enum PendingSystemAuthorityCatalogRecovery<'store, S: AgentJournalStore> {
    Pending(ReconciledPendingSystemAuthorityCatalog<'store, S>),
    Retired(RetiredSystemAuthorityCatalogRecovery),
}

/// Fresh rotation publication bound to one exact active durable reservation.
#[cfg(all(feature = "std", feature = "storage"))]
pub(crate) struct PreparedSystemAuthorityRotationPublication<'store, S>
where
    S: AgentJournalStore + SystemAuthorityPublicationStore,
{
    inner: ReplayPreparedPublication<'store, S>,
    reserved: ReservedSystemAuthorityClaim,
    storage: ReplaySystemAuthorityStoragePlan,
    command: SystemAuthorityRotation,
    predecessor: ReplayedSystemAuthorityView,
    successor: ReplayedSystemAuthorityView,
}

/// Recovery-only fresh rotation candidate reconstructed from one immutable
/// durable Intent. It contains pending evidence rather than signing authority
/// and is constructible only by replaying the exact stored ordered entry
/// against its independently reverified predecessor.
#[cfg(all(feature = "std", feature = "storage"))]
struct PreparedPendingSystemAuthorityRotationPublication<'store, S>
where
    S: AgentJournalStore + SystemAuthorityPublicationStore,
{
    inner: ReplayPreparedPublication<'store, S>,
    pending: PendingSystemAuthorityRecovery,
    storage: ReplaySystemAuthorityStoragePlan,
    command: SystemAuthorityRotation,
    predecessor: ReplayedSystemAuthorityView,
    successor: ReplayedSystemAuthorityView,
}

/// Fresh catalog publication bound to one exact current-committee durable
/// reservation. Occupied retry/conflict outcomes cannot construct it.
#[cfg(all(feature = "std", feature = "storage"))]
pub(crate) struct PreparedSystemAuthorityCatalogPublication<'store, S>
where
    S: AgentJournalStore + SystemAuthorityPublicationStore,
{
    inner: ReplayPreparedPublication<'store, S>,
    reserved: ReservedSystemAuthorityClaim,
    storage: ReplaySystemAuthorityStoragePlan,
    command: SystemAuthorityCatalogFinalize,
    predecessor: ReplayedSystemAuthorityView,
    successor: ReplayedSystemAuthorityView,
}

/// Recovery-only fresh catalog candidate reconstructed from the exact
/// immutable ledger intent and ordered entry.
#[cfg(all(feature = "std", feature = "storage"))]
struct PreparedPendingSystemAuthorityCatalogPublication<'store, S>
where
    S: AgentJournalStore + SystemAuthorityPublicationStore,
{
    inner: ReplayPreparedPublication<'store, S>,
    pending: PendingSystemAuthorityRecovery,
    storage: ReplaySystemAuthorityStoragePlan,
    command: SystemAuthorityCatalogFinalize,
    predecessor: ReplayedSystemAuthorityView,
    successor: ReplayedSystemAuthorityView,
}

#[cfg(all(feature = "std", feature = "storage"))]
fn sealed_rotation_components(
    sealed: &ReplaySealedPublication,
) -> Result<
    (
        &OrderedEntry,
        &SystemAuthorityRotation,
        &ReplaySystemAuthorityWrite,
        &SystemAuthorityRotationRecord,
        &SystemAuthorityRotationWritePlan,
        bool,
    ),
    JournalStoreError,
> {
    let ReplayPublicationAnchor::Ordered(entry) = sealed.anchor() else {
        return Err(JournalStoreError::NonCanonical);
    };
    let ReplayOperation::Management {
        request: LifecycleRequest::RotateSystemAuthority(command),
    } = &entry.input.operation
    else {
        return Err(JournalStoreError::NonCanonical);
    };
    let write = sealed
        .system_authority_write()
        .ok_or(JournalStoreError::NonCanonical)?;
    let StandardSystemAuthorityWrite::Rotation { record, history } = write.selected() else {
        return Err(JournalStoreError::NonCanonical);
    };
    let LifecycleReply::SystemAuthorityRotated {
        rotation,
        epoch,
        exact_retry,
    } = write.result()
    else {
        return Err(JournalStoreError::NonCanonical);
    };
    if *rotation != record.id()
        || *epoch != record.new_epoch()
        || command.certificate() != record.certificate()
        || command.new_committee().commitment().0 != *record.new_committee().as_bytes()
        || write.operation()
            != LifecycleRequest::RotateSystemAuthority(command.clone()).commitment()
    {
        return Err(JournalStoreError::NonCanonical);
    }
    Ok((entry, command, write, record, history, *exact_retry))
}

#[cfg(all(feature = "std", feature = "storage"))]
fn catalog_outcome_matches_record(
    outcome: SystemAuthorityCatalogFinalizeOutcome,
    record: &SystemAuthorityCatalogRecord,
    exact_retry: bool,
) -> bool {
    let fact = record.receipt().fact();
    outcome.operation() == record.operation_id()
        && outcome.result() == Some(fact.result().commitment())
        && outcome.catalog_head() == Some(fact.resulting_catalog_head())
        && outcome.authority_generation() == Some(fact.resulting_authority_generation())
        && outcome.sequence() == Some(fact.sequence())
        && outcome.exact_retry() == exact_retry
        && !outcome.operation_conflicted()
}

#[cfg(all(feature = "std", feature = "storage"))]
fn sealed_catalog_components(
    sealed: &ReplaySealedPublication,
) -> Result<
    (
        &OrderedEntry,
        &SystemAuthorityCatalogFinalize,
        &ReplaySystemAuthorityWrite,
        Option<&SystemAuthorityCatalogRecord>,
        &SystemAuthorityCatalogWritePlan,
        SystemAuthorityCatalogFinalizeOutcome,
    ),
    JournalStoreError,
> {
    let ReplayPublicationAnchor::Ordered(entry) = sealed.anchor() else {
        return Err(JournalStoreError::NonCanonical);
    };
    let ReplayOperation::Management {
        request: LifecycleRequest::FinalizeCatalog(command),
    } = &entry.input.operation
    else {
        return Err(JournalStoreError::NonCanonical);
    };
    let write = sealed
        .system_authority_write()
        .ok_or(JournalStoreError::NonCanonical)?;
    let StandardSystemAuthorityWrite::Catalog { record, history } = write.selected() else {
        return Err(JournalStoreError::NonCanonical);
    };
    let LifecycleReply::CatalogFinalized(outcome) = write.result() else {
        return Err(JournalStoreError::NonCanonical);
    };
    command
        .validate()
        .map_err(|_| JournalStoreError::NonCanonical)?;
    if write.operation() != command.operation_commitment()
        || command
            .proof()
            .root()
            .map_err(|_| JournalStoreError::NonCanonical)?
            != history.previous_root()
        || outcome.operation() != command.operation_id()
    {
        return Err(JournalStoreError::NonCanonical);
    }
    match record {
        Some(record)
            if record.receipt() == command.receipt()
                && catalog_outcome_matches_record(*outcome, record, !history.inserted()) => {}
        None if !history.inserted()
            && outcome.operation_conflicted()
            && outcome.occupied_record_id() == command.proof().occupied_record_id() => {}
        _ => return Err(JournalStoreError::NonCanonical),
    }
    Ok((entry, command, write, record.as_ref(), history, *outcome))
}

#[cfg(all(feature = "std", feature = "storage"))]
fn rotation_committee_records(
    old: &super::committee::AuthorityCommittee,
    new: &super::committee::AuthorityCommittee,
) -> Result<Vec<SystemAuthorityCommitteeRecord>, JournalStoreError> {
    let mut records = vec![
        SystemAuthorityCommitteeRecord::new(old.clone())
            .map_err(|_| JournalStoreError::NonCanonical)?,
        SystemAuthorityCommitteeRecord::new(new.clone())
            .map_err(|_| JournalStoreError::NonCanonical)?,
    ];
    records.sort_by_key(SystemAuthorityCommitteeRecord::id);
    records.dedup_by_key(|record| record.id());
    if records.len() != 2 {
        return Err(JournalStoreError::NonCanonical);
    }
    Ok(records)
}

#[cfg(all(feature = "std", feature = "storage"))]
fn rotation_storage_plan_commitment(
    history: &SystemAuthorityRotationWritePlan,
) -> Result<Hash, JournalStoreError> {
    const DOMAIN: &[u8] = b"vos/agent/system-authority-storage-plan/v1";
    const NODE_DOMAIN: &[u8] = b"vos/agent/system-authority-storage-plan/node/v1";
    const RETIRED_DOMAIN: &[u8] = b"vos/agent/system-authority-storage-plan/retired/v1";
    const COMMITTEE_DOMAIN: &[u8] = b"vos/agent/system-authority-storage-plan/committee/v1";
    const STEP_DOMAIN: &[u8] = b"vos/agent/system-authority-storage-plan/step/v1";

    if history.nodes().is_empty()
        || history.nodes().len() > MAX_SYSTEM_AUTHORITY_ROTATION_TREE_NODES
        || history.retired_node_ids().len() > MAX_SYSTEM_AUTHORITY_ROTATION_TREE_NODES
        || history.committee_records().len() != 2
    {
        return Err(JournalStoreError::LimitExceeded);
    }
    let node_count = u64::try_from(history.nodes().len())
        .map_err(|_| JournalStoreError::LimitExceeded)?
        .to_le_bytes();
    let retired_count = u64::try_from(history.retired_node_ids().len())
        .map_err(|_| JournalStoreError::LimitExceeded)?
        .to_le_bytes();
    let committee_count = u64::try_from(history.committee_records().len())
        .map_err(|_| JournalStoreError::LimitExceeded)?
        .to_le_bytes();
    let mut commitment = Hash::digest(
        DOMAIN,
        &[
            history.previous_root().as_bytes(),
            history.root().as_bytes(),
            &[u8::from(history.inserted())],
            &node_count,
            &retired_count,
            &committee_count,
        ],
    );
    for node in history.nodes() {
        let encoded = node.encode();
        if encoded.len() > MAX_SYSTEM_AUTHORITY_ROTATION_NODE_BYTES {
            return Err(JournalStoreError::LimitExceeded);
        }
        let component = Hash::digest(NODE_DOMAIN, &[node.id().as_bytes(), &encoded]);
        commitment = Hash::digest(STEP_DOMAIN, &[&commitment.0, &component.0]);
    }
    for retired in history.retired_node_ids() {
        let component = Hash::digest(RETIRED_DOMAIN, &[retired.as_bytes()]);
        commitment = Hash::digest(STEP_DOMAIN, &[&commitment.0, &component.0]);
    }
    for committee in history.committee_records() {
        let encoded = committee.encode();
        if encoded.len() > MAX_SYSTEM_AUTHORITY_COMMITTEE_RECORD_BYTES {
            return Err(JournalStoreError::LimitExceeded);
        }
        let component = Hash::digest(COMMITTEE_DOMAIN, &[committee.id().as_bytes(), &encoded]);
        commitment = Hash::digest(STEP_DOMAIN, &[&commitment.0, &component.0]);
    }
    Ok(commitment)
}

/// One sparse insertion materializes the leaf plus all 256 branch levels.
#[cfg(all(feature = "std", feature = "storage"))]
const MAX_SYSTEM_AUTHORITY_CATALOG_WRITE_NODES: usize = 257;

#[cfg(all(feature = "std", feature = "storage"))]
fn catalog_storage_plan_commitment(
    record: &SystemAuthorityCatalogRecord,
    history: &SystemAuthorityCatalogWritePlan,
    committee: &SystemAuthorityCommitteeRecord,
) -> Result<Hash, JournalStoreError> {
    const DOMAIN: &[u8] = b"vos/agent/system-authority-catalog-storage-plan/v1";
    const RECORD_DOMAIN: &[u8] = b"vos/agent/system-authority-catalog-storage-plan/record/v1";
    const NODE_DOMAIN: &[u8] = b"vos/agent/system-authority-catalog-storage-plan/node/v1";
    const RETIRED_DOMAIN: &[u8] = b"vos/agent/system-authority-catalog-storage-plan/retired/v1";
    const COMMITTEE_DOMAIN: &[u8] = b"vos/agent/system-authority-catalog-storage-plan/committee/v1";
    const STEP_DOMAIN: &[u8] = b"vos/agent/system-authority-catalog-storage-plan/step/v1";

    if !history.inserted()
        || history.previous_root() == SystemAuthorityCatalogNodeId::ZERO
        || history.root() == SystemAuthorityCatalogNodeId::ZERO
        || history.root() == history.previous_root()
        || history.nodes().len() != MAX_SYSTEM_AUTHORITY_CATALOG_WRITE_NODES
        || history.retired_node_ids().len() >= MAX_SYSTEM_AUTHORITY_CATALOG_WRITE_NODES
        || history
            .nodes()
            .windows(2)
            .any(|pair| pair[0].id() >= pair[1].id())
        || history.nodes().iter().any(|node| node.validate().is_err())
        || history
            .nodes()
            .iter()
            .all(|node| node.id() != history.root())
        || history
            .nodes()
            .iter()
            .all(|node| node != &SystemAuthorityCatalogNode::Leaf(record.clone()))
        || history
            .retired_node_ids()
            .windows(2)
            .any(|pair| pair[0] >= pair[1])
        || history.retired_node_ids().iter().any(|id| {
            *id == SystemAuthorityCatalogNodeId::ZERO
                || history
                    .nodes()
                    .binary_search_by_key(id, SystemAuthorityCatalogNode::id)
                    .is_ok()
        })
    {
        return Err(JournalStoreError::NonCanonical);
    }
    let record_bytes = record.encode();
    let committee_bytes = committee.encode();
    if record_bytes.len() > MAX_SYSTEM_AUTHORITY_CATALOG_RECORD_BYTES
        || committee_bytes.len() > MAX_SYSTEM_AUTHORITY_COMMITTEE_RECORD_BYTES
    {
        return Err(JournalStoreError::LimitExceeded);
    }
    let node_count = u64::try_from(history.nodes().len())
        .map_err(|_| JournalStoreError::LimitExceeded)?
        .to_le_bytes();
    let retired_count = u64::try_from(history.retired_node_ids().len())
        .map_err(|_| JournalStoreError::LimitExceeded)?
        .to_le_bytes();
    let record_component = Hash::digest(
        RECORD_DOMAIN,
        &[
            record.id().as_bytes(),
            record.leaf_id().as_bytes(),
            &record_bytes,
        ],
    );
    let committee_component = Hash::digest(
        COMMITTEE_DOMAIN,
        &[committee.id().as_bytes(), &committee_bytes],
    );
    let mut commitment = Hash::digest(
        DOMAIN,
        &[
            history.previous_root().as_bytes(),
            history.root().as_bytes(),
            &[1],
            &node_count,
            &retired_count,
            &record_component.0,
            &committee_component.0,
        ],
    );
    for node in history.nodes() {
        let encoded = node.encode();
        if encoded.len() > MAX_SYSTEM_AUTHORITY_CATALOG_NODE_BYTES {
            return Err(JournalStoreError::LimitExceeded);
        }
        let component = Hash::digest(NODE_DOMAIN, &[node.id().as_bytes(), &encoded]);
        commitment = Hash::digest(STEP_DOMAIN, &[&commitment.0, &component.0]);
    }
    for retired in history.retired_node_ids() {
        let component = Hash::digest(RETIRED_DOMAIN, &[retired.as_bytes()]);
        commitment = Hash::digest(STEP_DOMAIN, &[&commitment.0, &component.0]);
    }
    Ok(commitment)
}

#[cfg(all(feature = "std", feature = "storage"))]
fn verify_rotation_storage_closure<S: SystemAuthorityHistoryStore>(
    store: &S,
    storage: &ReplaySystemAuthorityStoragePlan,
    command: &SystemAuthorityRotation,
    historical_retry: bool,
) -> Result<(), JournalStoreError> {
    let history = storage
        .rotation_history()
        .ok_or(JournalStoreError::NonCanonical)?;
    if store
        .load_system_authority_rotation_node(history.record().leaf_id())?
        .as_ref()
        != Some(&SystemAuthorityRotationNode::Leaf(history.record().clone()))
    {
        return Err(JournalStoreError::MissingObject);
    }
    let lookup = prove_rotation(history.root(), history.record().new_epoch(), |id| {
        store
            .load_system_authority_rotation_node(id)
            .map(|node| node.map(|node| node.encode()))
    })
    .map_err(|_| JournalStoreError::Corrupt)?;
    if lookup.occupied_record() != Some(history.record())
        || (historical_retry && lookup.proof() != command.proof())
    {
        return Err(JournalStoreError::Corrupt);
    }
    for record in storage.committee_records() {
        if store
            .load_system_authority_committee_record(record.id())?
            .as_ref()
            != Some(record)
        {
            return Err(JournalStoreError::MissingObject);
        }
    }
    Ok(())
}

#[cfg(all(feature = "std", feature = "storage"))]
fn verify_catalog_storage_closure<S: SystemAuthorityHistoryStore>(
    store: &S,
    storage: &ReplaySystemAuthorityStoragePlan,
    command: &SystemAuthorityCatalogFinalize,
) -> Result<(), JournalStoreError> {
    let history = storage
        .catalog_history()
        .ok_or(JournalStoreError::NonCanonical)?;
    let [committee] = storage.committee_records() else {
        return Err(JournalStoreError::NonCanonical);
    };
    if history.record().receipt() != command.receipt()
        || store
            .load_system_authority_catalog_record(history.record().id())?
            .as_ref()
            != Some(history.record())
        || store
            .load_system_authority_catalog_node(history.record().leaf_id())?
            .as_ref()
            != Some(&SystemAuthorityCatalogNode::Leaf(history.record().clone()))
        || store
            .load_system_authority_committee_record(committee.id())?
            .as_ref()
            != Some(committee)
    {
        return Err(JournalStoreError::MissingObject);
    }
    let lookup = prove_catalog(history.root(), history.record().operation_id(), |id| {
        store
            .load_system_authority_catalog_node(id)
            .map(|node| node.map(|node| node.encode()))
    })
    .map_err(|_| JournalStoreError::Corrupt)?;
    if lookup.occupied_record_id() != Some(history.record().id()) {
        return Err(JournalStoreError::Corrupt);
    }
    history
        .record()
        .verify(
            command.receipt().fact().intent().binding(),
            committee.committee(),
        )
        .map_err(|_| JournalStoreError::NonCanonical)
}

#[cfg(all(feature = "std", feature = "storage"))]
fn authority_transition_views<S>(
    prepared: &ReplayPreparedPublication<'_, S>,
    entry: &OrderedEntry,
    write: &ReplaySystemAuthorityWrite,
) -> Result<
    (
        SystemAuthorityJournalScope,
        ReplayedSystemAuthorityView,
        ReplayedSystemAuthorityView,
    ),
    JournalStoreError,
>
where
    S: AgentJournalStore + ReverifiedRootJournalStore,
{
    let identity = prepared
        .successor
        .replayed_root()
        .ok_or(JournalStoreError::NonCanonical)?;
    if prepared.store.replayed_root_identity() != Some(identity)
        || identity.genesis() != prepared.sealed.next().genesis
        || identity.outer_admission() != prepared.sealed.next().admission
        || prepared.sealed.next().previous != Some(prepared.sealed.expected())
        || prepared.sealed.next().id() != prepared.successor.heads_id
        || write.successor_control() != prepared.successor.state.control
    {
        return Err(JournalStoreError::NonCanonical);
    }
    let decoded_successor = decode_standard_runtime_state(&prepared.successor.state)
        .map_err(|_| JournalStoreError::NonCanonical)?;
    if decoded_successor.system_authority.as_ref() != Some(write.successor_authority()) {
        return Err(JournalStoreError::NonCanonical);
    }
    let scope = SystemAuthorityJournalScope::from_replayed_root(&identity)
        .map_err(|_| JournalStoreError::NonCanonical)?;
    let predecessor_base = OrderedBase {
        index: entry
            .index
            .checked_sub(1)
            .ok_or(JournalStoreError::NonCanonical)?,
        head: entry.parent,
    };
    let successor_base = OrderedBase {
        index: entry.index,
        head: Some(entry.id()),
    };
    let predecessor_control =
        derive_lane_state::<core::convert::Infallible, core::convert::Infallible>(
            entry.genesis,
            entry.input.runtime.clone(),
            PersistedLane::Control,
            LaneCursor::Ordered {
                base: predecessor_base,
            },
            write.predecessor_control(),
        )
        .map_err(|_| JournalStoreError::NonCanonical)?
        .id();
    let successor_control =
        derive_lane_state::<core::convert::Infallible, core::convert::Infallible>(
            entry.genesis,
            prepared.successor.heads.runtime.clone(),
            PersistedLane::Control,
            LaneCursor::Ordered {
                base: successor_base,
            },
            write.successor_control(),
        )
        .map_err(|_| JournalStoreError::NonCanonical)?
        .id();
    let journal_store = prepared.store.instance_id();
    let predecessor = ReplayedSystemAuthorityView::from_authenticated_replay(
        scope,
        write.predecessor_authority(),
        journal_store,
        prepared.sealed.expected(),
        predecessor_control,
    )
    .map_err(|_| JournalStoreError::NonCanonical)?;
    let successor = ReplayedSystemAuthorityView::from_authenticated_replay(
        scope,
        write.successor_authority(),
        journal_store,
        prepared.sealed.next().id(),
        successor_control,
    )
    .map_err(|_| JournalStoreError::NonCanonical)?;
    if predecessor.route() != successor.route() {
        return Err(JournalStoreError::NonCanonical);
    }
    Ok((scope, predecessor, successor))
}

#[cfg(all(feature = "std", feature = "storage"))]
fn validate_fresh_rotation_state_transition(
    scope: SystemAuthorityJournalScope,
    before: &super::system_authority::SystemAuthorityState,
    after: &super::system_authority::SystemAuthorityState,
    retiring: &super::committee::AuthorityCommittee,
    incoming: &super::committee::AuthorityCommittee,
    record: &SystemAuthorityRotationRecord,
    history: &SystemAuthorityRotationWritePlan,
) -> Result<(), JournalStoreError> {
    let transition = record.certificate().transition();
    before
        .validate()
        .map_err(|_| JournalStoreError::NonCanonical)?;
    after
        .validate()
        .map_err(|_| JournalStoreError::NonCanonical)?;
    if !history.inserted()
        || history.previous_root() != before.rotations_root()
        || history.root() != after.rotations_root()
        || before.current_committee() != retiring
        || after.current_committee() != incoming
        || record.old_committee().as_bytes() != &retiring.commitment().0
        || record.new_committee().as_bytes() != &incoming.commitment().0
        || after.committee_sequence_high_water() != transition.rotation_sequence()
        || after.rotation_first_sequence() != Some(transition.first_sequence())
        || before.rotation_count().checked_add(1) != Some(after.rotation_count())
        || before.decisions_root() != after.decisions_root()
        || before.decision_count() != after.decision_count()
        || before.root_anchor() != after.root_anchor()
        || before.root_anchor_config_version() != after.root_anchor_config_version()
        || before.root_anchor_config() != after.root_anchor_config()
        || before.system_agent() != after.system_agent()
        || before.space() != after.space()
        || before.authority_binding() != after.authority_binding()
        || before.decision_limit() != after.decision_limit()
        || before.rotation_limit() != after.rotation_limit()
        || after.journal_binding() != Some(scope.binding())
        || history
            .nodes()
            .iter()
            .all(|node| node != &SystemAuthorityRotationNode::Leaf(record.clone()))
    {
        return Err(JournalStoreError::NonCanonical);
    }
    after
        .verify_historical_rotation(scope, record, retiring, incoming)
        .map_err(|_| JournalStoreError::NonCanonical)
}

#[cfg(all(feature = "std", feature = "storage"))]
fn validate_fresh_catalog_state_transition(
    scope: SystemAuthorityJournalScope,
    before: &super::system_authority::SystemAuthorityState,
    after: &super::system_authority::SystemAuthorityState,
    record: &SystemAuthorityCatalogRecord,
    history: &SystemAuthorityCatalogWritePlan,
) -> Result<(), JournalStoreError> {
    let fact = record.receipt().fact();
    before
        .validate()
        .map_err(|_| JournalStoreError::NonCanonical)?;
    after
        .validate()
        .map_err(|_| JournalStoreError::NonCanonical)?;
    let valid_sequence = before.rotation_first_sequence().map_or_else(
        || fact.sequence() > before.committee_sequence_high_water(),
        |first| fact.sequence() == first,
    );
    if !valid_sequence
        || !history.inserted()
        || history.previous_root() != before.catalog_history_root()
        || history.root() != after.catalog_history_root()
        || fact.actual_predecessor_authority_generation() != before.authority_generation()
        || fact.actual_predecessor_catalog_head() != before.catalog_head()
        || fact.resulting_authority_generation() != after.authority_generation()
        || fact.resulting_catalog_head() != after.catalog_head()
        || after.committee_sequence_high_water() != fact.sequence()
        || after.rotation_first_sequence().is_some()
        || before.catalog_count().checked_add(1) != Some(after.catalog_count())
        || before.current_committee() != after.current_committee()
        || record.receipt().certificate().committee() != before.current_committee().commitment()
        || before.decisions_root() != after.decisions_root()
        || before.decision_count() != after.decision_count()
        || before.rotations_root() != after.rotations_root()
        || before.rotation_count() != after.rotation_count()
        || before.root_anchor() != after.root_anchor()
        || before.root_anchor_config_version() != after.root_anchor_config_version()
        || before.root_anchor_config() != after.root_anchor_config()
        || before.system_agent() != after.system_agent()
        || before.space() != after.space()
        || before.authority_binding() != after.authority_binding()
        || before.catalog_binding() != after.catalog_binding()
        || before.catalog_limit() != after.catalog_limit()
        || before.decision_limit() != after.decision_limit()
        || before.rotation_limit() != after.rotation_limit()
        || after.journal_binding() != Some(scope.binding())
        || history
            .nodes()
            .iter()
            .all(|node| node != &SystemAuthorityCatalogNode::Leaf(record.clone()))
    {
        return Err(JournalStoreError::NonCanonical);
    }
    after
        .verify_historical_catalog_receipt(scope, record.receipt(), before.current_committee())
        .map_err(|_| JournalStoreError::NonCanonical)
}

#[cfg(all(feature = "std", feature = "storage"))]
impl<'store, S> ReplayPreparedPublication<'store, S>
where
    S: AgentJournalStore
        + ReverifiedRootJournalStore
        + SystemAuthorityPublicationStore
        + ReplaySource<Error = JournalStoreError>,
{
    /// Consume the exact fresh rotation reservation and bind it to this one
    /// replay-selected predecessor/successor transition. AgentGenesis and
    /// historical retry claims deliberately have no constructor here.
    pub(crate) fn prepare_system_authority_rotation(
        self,
        reserved: ReservedSystemAuthorityClaim,
    ) -> Result<PreparedSystemAuthorityRotationPublication<'store, S>, JournalStoreError> {
        if self.sealed.mode() != ReplayPublicationMode::Canonical
            || self.sealed.shared_ordered_commit().is_some()
            || self.sealed.shared_merge_projection().is_some()
        {
            return Err(JournalStoreError::NonCanonical);
        }
        let (entry, command, write, record, history, exact_retry) =
            sealed_rotation_components(&self.sealed)?;
        if exact_retry || !history.inserted() {
            return Err(JournalStoreError::NonCanonical);
        }
        let (scope, predecessor, successor) = authority_transition_views(&self, entry, write)?;
        let reapplied = write
            .predecessor_authority()
            .apply_rotation(scope, command)
            .map_err(|_| JournalStoreError::NonCanonical)?;
        if reapplied.exact_retry()
            || reapplied.state() != write.successor_authority()
            || reapplied.record() != record
            || reapplied.history() != history
        {
            return Err(JournalStoreError::NonCanonical);
        }
        let SystemAuthorityLedgerClaim::CommitteeRotation {
            retiring,
            incoming,
            transition,
        } = reserved.request()
        else {
            return Err(JournalStoreError::NonCanonical);
        };
        if reserved.journal_store() != self.store.instance_id()
            || reserved.predecessor_heads() != self.sealed.expected()
            || reserved.control_state() != predecessor.control_state()
            || reserved.state_view_commitment() != predecessor.commitment()
            || reserved.authority_state_commitment() != predecessor.authority_state_commitment()
            || reserved.route() != predecessor.route()
            || reserved.request().claim() != transition.authority_claim()
            || command.new_committee() != incoming
            || command.certificate().transition() != transition
            || record.certificate().transition() != transition
            || record.old_committee().as_bytes() != &retiring.commitment().0
            || record.new_committee().as_bytes() != &incoming.commitment().0
            || successor.committee_sequence_high_water() != transition.rotation_sequence()
            || successor.rotation_first_sequence() != Some(transition.first_sequence())
        {
            return Err(JournalStoreError::NonCanonical);
        }
        validate_fresh_rotation_state_transition(
            scope,
            write.predecessor_authority(),
            write.successor_authority(),
            retiring,
            incoming,
            record,
            history,
        )?;
        let committee_records = rotation_committee_records(retiring, incoming)?;
        if history.committee_records() != committee_records {
            return Err(JournalStoreError::NonCanonical);
        }
        let storage = ReplaySystemAuthorityStoragePlan::Rotation {
            history: ReplaySystemAuthorityHistory {
                record: record.clone(),
                root: history.root(),
            },
            committee_records,
        };
        let command = command.clone();
        Ok(PreparedSystemAuthorityRotationPublication {
            inner: self,
            reserved,
            storage,
            command,
            predecessor,
            successor,
        })
    }

    /// Consume one fresh vacant-proof catalog reservation and bind it to the
    /// exact replay-selected predecessor, receipt, sparse write plan, and
    /// successor. Occupied retry/conflict transitions have no constructor.
    pub(crate) fn prepare_system_authority_catalog(
        self,
        reserved: ReservedSystemAuthorityClaim,
    ) -> Result<PreparedSystemAuthorityCatalogPublication<'store, S>, JournalStoreError> {
        if self.sealed.mode() != ReplayPublicationMode::Canonical
            || self.sealed.shared_ordered_commit().is_some()
            || self.sealed.shared_merge_projection().is_some()
        {
            return Err(JournalStoreError::NonCanonical);
        }
        let (entry, command, write, record, history, outcome) =
            sealed_catalog_components(&self.sealed)?;
        let record = record.ok_or(JournalStoreError::NonCanonical)?;
        if !history.inserted() || outcome.exact_retry() || outcome.operation_conflicted() {
            return Err(JournalStoreError::NonCanonical);
        }
        let (scope, predecessor, successor) = authority_transition_views(&self, entry, write)?;
        let reapplied = write
            .predecessor_authority()
            .apply_catalog_finalize(scope, command)
            .map_err(|_| JournalStoreError::NonCanonical)?;
        if reapplied.outcome() != outcome
            || reapplied.state() != write.successor_authority()
            || reapplied.record() != Some(record)
            || reapplied.history() != history
        {
            return Err(JournalStoreError::NonCanonical);
        }
        let SystemAuthorityLedgerClaim::Catalog {
            committee,
            fact,
            proof,
        } = reserved.request()
        else {
            return Err(JournalStoreError::NonCanonical);
        };
        if reserved.journal_store() != self.store.instance_id()
            || reserved.predecessor_heads() != self.sealed.expected()
            || reserved.control_state() != predecessor.control_state()
            || reserved.state_view_commitment() != predecessor.commitment()
            || reserved.authority_state_commitment() != predecessor.authority_state_commitment()
            || reserved.route() != predecessor.route()
            || reserved.request().claim() != fact.authority_claim()
            || command.receipt().fact() != fact
            || command.proof() != proof
            || record.receipt() != command.receipt()
            || committee != write.predecessor_authority().current_committee()
            || successor.committee() != committee
            || successor.committee_sequence_high_water() != fact.sequence()
            || successor.rotation_first_sequence().is_some()
        {
            return Err(JournalStoreError::NonCanonical);
        }
        validate_fresh_catalog_state_transition(
            scope,
            write.predecessor_authority(),
            write.successor_authority(),
            record,
            history,
        )?;
        let committee_record = SystemAuthorityCommitteeRecord::new(committee.clone())
            .map_err(|_| JournalStoreError::NonCanonical)?;
        catalog_storage_plan_commitment(record, history, &committee_record)?;
        let storage = ReplaySystemAuthorityStoragePlan::Catalog {
            history: ReplaySystemAuthorityCatalogHistory {
                record: record.clone(),
                root: history.root(),
            },
            committee_record,
        };
        let command = command.clone();
        Ok(PreparedSystemAuthorityCatalogPublication {
            inner: self,
            reserved,
            storage,
            command,
            predecessor,
            successor,
        })
    }

    fn prepare_pending_system_authority_rotation(
        self,
        pending: PendingSystemAuthorityRecovery,
        frozen: &super::system_authority::SystemAuthorityRotationCertificate,
    ) -> Result<PreparedPendingSystemAuthorityRotationPublication<'store, S>, JournalStoreError>
    {
        if self.sealed.mode() != ReplayPublicationMode::Canonical
            || self.sealed.shared_ordered_commit().is_some()
            || self.sealed.shared_merge_projection().is_some()
        {
            return Err(JournalStoreError::NonCanonical);
        }
        let (entry, command, write, record, history, exact_retry) =
            sealed_rotation_components(&self.sealed)?;
        if exact_retry || !history.inserted() {
            return Err(JournalStoreError::NonCanonical);
        }
        let (scope, predecessor, successor) = authority_transition_views(&self, entry, write)?;
        let reapplied = write
            .predecessor_authority()
            .apply_rotation(scope, command)
            .map_err(|_| JournalStoreError::NonCanonical)?;
        if reapplied.exact_retry()
            || reapplied.state() != write.successor_authority()
            || reapplied.record() != record
            || reapplied.history() != history
        {
            return Err(JournalStoreError::NonCanonical);
        }
        let SystemAuthorityLedgerClaim::CommitteeRotation {
            retiring,
            incoming,
            transition,
        } = pending.request()
        else {
            return Err(JournalStoreError::NonCanonical);
        };
        if pending.journal_store() != self.store.instance_id()
            || pending.predecessor_heads() != self.sealed.expected()
            || pending.control_state() != predecessor.control_state()
            || pending.state_view_commitment() != predecessor.commitment()
            || pending.authority_state_commitment() != predecessor.authority_state_commitment()
            || pending.route() != predecessor.route()
            || pending.claim() != transition.authority_claim()
            || command.new_committee() != incoming
            || command.certificate() != frozen
            || command.certificate().transition() != transition
            || record.certificate() != frozen
            || record.certificate().transition() != transition
            || record.old_committee().as_bytes() != &retiring.commitment().0
            || record.new_committee().as_bytes() != &incoming.commitment().0
            || successor.committee_sequence_high_water() != transition.rotation_sequence()
            || successor.rotation_first_sequence() != Some(transition.first_sequence())
        {
            return Err(JournalStoreError::NonCanonical);
        }
        validate_fresh_rotation_state_transition(
            scope,
            write.predecessor_authority(),
            write.successor_authority(),
            retiring,
            incoming,
            record,
            history,
        )?;
        let committee_records = rotation_committee_records(retiring, incoming)?;
        if history.committee_records() != committee_records {
            return Err(JournalStoreError::NonCanonical);
        }
        let storage = ReplaySystemAuthorityStoragePlan::Rotation {
            history: ReplaySystemAuthorityHistory {
                record: record.clone(),
                root: history.root(),
            },
            committee_records,
        };
        let command = command.clone();
        Ok(PreparedPendingSystemAuthorityRotationPublication {
            inner: self,
            pending,
            storage,
            command,
            predecessor,
            successor,
        })
    }

    fn prepare_pending_system_authority_catalog(
        self,
        pending: PendingSystemAuthorityRecovery,
        frozen: &super::committee::AuthorityQuorumCertificate,
    ) -> Result<PreparedPendingSystemAuthorityCatalogPublication<'store, S>, JournalStoreError>
    {
        if self.sealed.mode() != ReplayPublicationMode::Canonical
            || self.sealed.shared_ordered_commit().is_some()
            || self.sealed.shared_merge_projection().is_some()
        {
            return Err(JournalStoreError::NonCanonical);
        }
        let (entry, command, write, record, history, outcome) =
            sealed_catalog_components(&self.sealed)?;
        let record = record.ok_or(JournalStoreError::NonCanonical)?;
        if !history.inserted() || outcome.exact_retry() || outcome.operation_conflicted() {
            return Err(JournalStoreError::NonCanonical);
        }
        let (scope, predecessor, successor) = authority_transition_views(&self, entry, write)?;
        let reapplied = write
            .predecessor_authority()
            .apply_catalog_finalize(scope, command)
            .map_err(|_| JournalStoreError::NonCanonical)?;
        if reapplied.outcome() != outcome
            || reapplied.state() != write.successor_authority()
            || reapplied.record() != Some(record)
            || reapplied.history() != history
        {
            return Err(JournalStoreError::NonCanonical);
        }
        let SystemAuthorityLedgerClaim::Catalog {
            committee,
            fact,
            proof,
        } = pending.request()
        else {
            return Err(JournalStoreError::NonCanonical);
        };
        if pending.journal_store() != self.store.instance_id()
            || pending.predecessor_heads() != self.sealed.expected()
            || pending.control_state() != predecessor.control_state()
            || pending.state_view_commitment() != predecessor.commitment()
            || pending.authority_state_commitment() != predecessor.authority_state_commitment()
            || pending.route() != predecessor.route()
            || pending.claim() != fact.authority_claim()
            || command.receipt().fact() != fact
            || command.receipt().certificate() != frozen
            || command.proof() != proof
            || record.receipt() != command.receipt()
            || committee != write.predecessor_authority().current_committee()
            || successor.committee() != committee
            || successor.committee_sequence_high_water() != fact.sequence()
            || successor.rotation_first_sequence().is_some()
        {
            return Err(JournalStoreError::NonCanonical);
        }
        validate_fresh_catalog_state_transition(
            scope,
            write.predecessor_authority(),
            write.successor_authority(),
            record,
            history,
        )?;
        let committee_record = SystemAuthorityCommitteeRecord::new(committee.clone())
            .map_err(|_| JournalStoreError::NonCanonical)?;
        catalog_storage_plan_commitment(record, history, &committee_record)?;
        let storage = ReplaySystemAuthorityStoragePlan::Catalog {
            history: ReplaySystemAuthorityCatalogHistory {
                record: record.clone(),
                root: history.root(),
            },
            committee_record,
        };
        let command = command.clone();
        Ok(PreparedPendingSystemAuthorityCatalogPublication {
            inner: self,
            pending,
            storage,
            command,
            predecessor,
            successor,
        })
    }
}

#[cfg(all(feature = "std", feature = "storage"))]
impl<'store, S> PreparedSystemAuthorityRotationPublication<'store, S>
where
    S: AgentJournalStore
        + ReverifiedRootJournalStore
        + SystemAuthorityPublicationStore
        + ReplaySource<Error = JournalStoreError>,
{
    fn publication_facts(
        &self,
    ) -> Result<SystemAuthorityRotationPublicationFacts, JournalStoreError> {
        let ReplayPublicationAnchor::Ordered(entry) = self.inner.sealed.anchor() else {
            return Err(JournalStoreError::NonCanonical);
        };
        let write = self
            .inner
            .sealed
            .system_authority_write()
            .ok_or(JournalStoreError::NonCanonical)?;
        let StandardSystemAuthorityWrite::Rotation { history, .. } = write.selected() else {
            return Err(JournalStoreError::NonCanonical);
        };
        let storage = self
            .storage
            .rotation_history()
            .ok_or(JournalStoreError::NonCanonical)?;
        Ok(SystemAuthorityRotationPublicationFacts {
            journal_store: self.inner.store.instance_id(),
            predecessor_heads: self.reserved.predecessor_heads(),
            successor_heads: self.inner.sealed.next().id(),
            ordered_entry: entry.clone(),
            predecessor_control: self.predecessor.control_state(),
            successor_control: self.successor.control_state(),
            predecessor_view: self.predecessor.commitment(),
            successor_view: self.successor.commitment(),
            predecessor_authority_state: self.predecessor.authority_state_commitment(),
            successor_authority_state: self.successor.authority_state_commitment(),
            claim: self.reserved.request().claim(),
            command: self.command.clone(),
            operation: write.operation(),
            result: write.result().clone(),
            record: storage.record().clone(),
            root: storage.root(),
            storage_plan: rotation_storage_plan_commitment(history)?,
        })
    }

    pub(crate) fn publish_system_authority_rotation(
        self,
        owner: &SystemAuthorityLedgerRouteOwner,
    ) -> Result<PublishedSystemAuthorityRotation<'store, S>, SystemAuthorityPublicationError> {
        let facts = self.publication_facts()?;
        let Self {
            inner,
            reserved,
            storage,
            command,
            predecessor: _,
            successor,
        } = self;
        let active = reserved.clone();
        let operation_reserved = reserved.clone();
        let expected_certificate = command.certificate().clone();
        let (store, publication, materialization, executions) = owner
            .with_active_publication_reservation(
                &active,
                &expected_certificate,
                &facts,
                move || {
                    let ReplayPreparedPublication {
                        store,
                        sealed,
                        successor: materialization,
                        executions,
                    } = inner;
                    let publication = store.publish_system_authority(&sealed, &storage)?;
                    let durable = store.heads()?.ok_or(JournalStoreError::NotInitialized)?;
                    let next = sealed.next();
                    let ReplayPublicationAnchor::Ordered(entry) = sealed.anchor() else {
                        return Err(JournalStoreError::NonCanonical);
                    };
                    if durable != *next
                        || durable.id() != next.id()
                        || next.previous != Some(operation_reserved.predecessor_heads())
                        || store.get::<OrderedEntry>(entry.id())?.as_ref() != Some(entry)
                        || (!publication.heads_advanced
                            && (durable.id() != next.id()
                                || next.previous != Some(sealed.expected())))
                    {
                        return Err(JournalStoreError::Corrupt);
                    }
                    verify_rotation_storage_closure(store, &storage, &command, false)?;
                    let replayed_root = materialization
                        .replayed_root()
                        .ok_or(JournalStoreError::NonCanonical)?;
                    let scope = SystemAuthorityJournalScope::from_replayed_root(&replayed_root)
                        .map_err(|_| JournalStoreError::NonCanonical)?;
                    let post = ReplayedSystemAuthorityView::from_authenticated_replay(
                        scope,
                        successor.authority_state(),
                        store.instance_id(),
                        durable.id(),
                        successor.control_state(),
                    )
                    .map_err(|_| JournalStoreError::NonCanonical)?;
                    if post.commitment() != successor.commitment()
                        || post.authority_state_commitment()
                            != successor.authority_state_commitment()
                    {
                        return Err(JournalStoreError::Corrupt);
                    }
                    Ok((store, publication, materialization, executions))
                },
            )??;
        Ok(PublishedSystemAuthorityRotation {
            store,
            reserved,
            facts,
            publication,
            successor: materialization,
            executions,
        })
    }
}

#[cfg(all(feature = "std", feature = "storage"))]
impl<'store, S> PreparedPendingSystemAuthorityRotationPublication<'store, S>
where
    S: AgentJournalStore
        + ReverifiedRootJournalStore
        + SystemAuthorityPublicationStore
        + ReplaySource<Error = JournalStoreError>,
{
    fn publication_facts(
        &self,
    ) -> Result<SystemAuthorityRotationPublicationFacts, JournalStoreError> {
        let ReplayPublicationAnchor::Ordered(entry) = self.inner.sealed.anchor() else {
            return Err(JournalStoreError::NonCanonical);
        };
        let write = self
            .inner
            .sealed
            .system_authority_write()
            .ok_or(JournalStoreError::NonCanonical)?;
        let StandardSystemAuthorityWrite::Rotation { history, .. } = write.selected() else {
            return Err(JournalStoreError::NonCanonical);
        };
        let storage = self
            .storage
            .rotation_history()
            .ok_or(JournalStoreError::NonCanonical)?;
        Ok(SystemAuthorityRotationPublicationFacts {
            journal_store: self.inner.store.instance_id(),
            predecessor_heads: self.pending.predecessor_heads(),
            successor_heads: self.inner.sealed.next().id(),
            ordered_entry: entry.clone(),
            predecessor_control: self.predecessor.control_state(),
            successor_control: self.successor.control_state(),
            predecessor_view: self.predecessor.commitment(),
            successor_view: self.successor.commitment(),
            predecessor_authority_state: self.predecessor.authority_state_commitment(),
            successor_authority_state: self.successor.authority_state_commitment(),
            claim: self.pending.claim(),
            command: self.command.clone(),
            operation: write.operation(),
            result: write.result().clone(),
            record: storage.record().clone(),
            root: storage.root(),
            storage_plan: rotation_storage_plan_commitment(history)?,
        })
    }

    /// Publish a cold-reconstructed candidate only after its complete replay
    /// facts and storage plan exact-match the immutable v4 Intent. The owner
    /// calls this while holding its pending-recovery writer through durable
    /// retirement, so the returned receipt never escapes unretired.
    fn publish_recovered(
        self,
    ) -> Result<RecoveredSystemAuthorityRotation<'store, S>, JournalStoreError> {
        let facts = self.publication_facts()?;
        if !self.pending.matches_publication_facts(&facts) {
            return Err(JournalStoreError::NonCanonical);
        }
        let Self {
            inner,
            pending,
            storage,
            command,
            predecessor: _,
            successor,
        } = self;
        let ReplayPreparedPublication {
            store,
            sealed,
            successor: materialization,
            executions,
        } = inner;
        let publication = store.publish_system_authority(&sealed, &storage)?;
        let durable = store.heads()?.ok_or(JournalStoreError::NotInitialized)?;
        let next = sealed.next();
        let ReplayPublicationAnchor::Ordered(entry) = sealed.anchor() else {
            return Err(JournalStoreError::NonCanonical);
        };
        if durable != *next
            || durable.id() != next.id()
            || next.previous != Some(pending.predecessor_heads())
            || store.get::<OrderedEntry>(entry.id())?.as_ref() != Some(entry)
            || (!publication.heads_advanced
                && (durable.id() != next.id() || next.previous != Some(sealed.expected())))
        {
            return Err(JournalStoreError::Corrupt);
        }
        verify_rotation_storage_closure(store, &storage, &command, false)?;
        let replayed_root = materialization
            .replayed_root()
            .ok_or(JournalStoreError::NonCanonical)?;
        let scope = SystemAuthorityJournalScope::from_replayed_root(&replayed_root)
            .map_err(|_| JournalStoreError::NonCanonical)?;
        let post = ReplayedSystemAuthorityView::from_authenticated_replay(
            scope,
            successor.authority_state(),
            store.instance_id(),
            durable.id(),
            successor.control_state(),
        )
        .map_err(|_| JournalStoreError::NonCanonical)?;
        if post.commitment() != successor.commitment()
            || post.authority_state_commitment() != successor.authority_state_commitment()
        {
            return Err(JournalStoreError::Corrupt);
        }
        Ok(RecoveredSystemAuthorityRotation {
            store,
            pending,
            facts,
            current: materialization,
            publication: Some(publication),
            executions,
        })
    }
}

#[cfg(all(feature = "std", feature = "storage"))]
impl<'store, S> PreparedSystemAuthorityCatalogPublication<'store, S>
where
    S: AgentJournalStore
        + ReverifiedRootJournalStore
        + SystemAuthorityPublicationStore
        + ReplaySource<Error = JournalStoreError>,
{
    fn publication_facts(
        &self,
    ) -> Result<SystemAuthorityCatalogPublicationFacts, JournalStoreError> {
        let ReplayPublicationAnchor::Ordered(entry) = self.inner.sealed.anchor() else {
            return Err(JournalStoreError::NonCanonical);
        };
        let write = self
            .inner
            .sealed
            .system_authority_write()
            .ok_or(JournalStoreError::NonCanonical)?;
        let StandardSystemAuthorityWrite::Catalog {
            record: Some(record),
            history,
        } = write.selected()
        else {
            return Err(JournalStoreError::NonCanonical);
        };
        let storage = self
            .storage
            .catalog_history()
            .ok_or(JournalStoreError::NonCanonical)?;
        let [committee] = self.storage.committee_records() else {
            return Err(JournalStoreError::NonCanonical);
        };
        if storage.record() != record || storage.root() != history.root() {
            return Err(JournalStoreError::NonCanonical);
        }
        Ok(SystemAuthorityCatalogPublicationFacts {
            journal_store: self.inner.store.instance_id(),
            predecessor_heads: self.reserved.predecessor_heads(),
            successor_heads: self.inner.sealed.next().id(),
            ordered_entry: entry.clone(),
            predecessor_control: self.predecessor.control_state(),
            successor_control: self.successor.control_state(),
            predecessor_view: self.predecessor.commitment(),
            successor_view: self.successor.commitment(),
            predecessor_authority_state: self.predecessor.authority_state_commitment(),
            successor_authority_state: self.successor.authority_state_commitment(),
            claim: self.reserved.request().claim(),
            command: self.command.clone(),
            operation: write.operation(),
            result: write.result().clone(),
            record: storage.record().clone(),
            root: storage.root(),
            storage_plan: catalog_storage_plan_commitment(record, history, committee)?,
        })
    }

    pub(crate) fn publish_system_authority_catalog(
        self,
        owner: &SystemAuthorityLedgerRouteOwner,
    ) -> Result<PublishedSystemAuthorityCatalog<'store, S>, SystemAuthorityPublicationError> {
        let facts = self.publication_facts()?;
        let Self {
            inner,
            reserved,
            storage,
            command,
            predecessor: _,
            successor,
        } = self;
        let active = reserved.clone();
        let operation_reserved = reserved.clone();
        let expected_certificate = command.receipt().certificate().clone();
        let (store, publication, materialization, executions) = owner
            .with_active_catalog_publication_reservation(
                &active,
                &expected_certificate,
                &facts,
                move || {
                    let ReplayPreparedPublication {
                        store,
                        sealed,
                        successor: materialization,
                        executions,
                    } = inner;
                    let publication = store.publish_system_authority(&sealed, &storage)?;
                    let durable = store.heads()?.ok_or(JournalStoreError::NotInitialized)?;
                    let next = sealed.next();
                    let ReplayPublicationAnchor::Ordered(entry) = sealed.anchor() else {
                        return Err(JournalStoreError::NonCanonical);
                    };
                    if durable != *next
                        || durable.id() != next.id()
                        || next.previous != Some(operation_reserved.predecessor_heads())
                        || store.get::<OrderedEntry>(entry.id())?.as_ref() != Some(entry)
                        || (!publication.heads_advanced
                            && (durable.id() != next.id()
                                || next.previous != Some(sealed.expected())))
                    {
                        return Err(JournalStoreError::Corrupt);
                    }
                    verify_catalog_storage_closure(store, &storage, &command)?;
                    let replayed_root = materialization
                        .replayed_root()
                        .ok_or(JournalStoreError::NonCanonical)?;
                    let scope = SystemAuthorityJournalScope::from_replayed_root(&replayed_root)
                        .map_err(|_| JournalStoreError::NonCanonical)?;
                    let post = ReplayedSystemAuthorityView::from_authenticated_replay(
                        scope,
                        successor.authority_state(),
                        store.instance_id(),
                        durable.id(),
                        successor.control_state(),
                    )
                    .map_err(|_| JournalStoreError::NonCanonical)?;
                    if post.commitment() != successor.commitment()
                        || post.authority_state_commitment()
                            != successor.authority_state_commitment()
                    {
                        return Err(JournalStoreError::Corrupt);
                    }
                    Ok((store, publication, materialization, executions))
                },
            )??;
        Ok(PublishedSystemAuthorityCatalog {
            store,
            reserved,
            facts,
            publication,
            successor: materialization,
            executions,
        })
    }
}

#[cfg(all(feature = "std", feature = "storage"))]
impl<'store, S> PreparedPendingSystemAuthorityCatalogPublication<'store, S>
where
    S: AgentJournalStore
        + ReverifiedRootJournalStore
        + SystemAuthorityPublicationStore
        + ReplaySource<Error = JournalStoreError>,
{
    fn publication_facts(
        &self,
    ) -> Result<SystemAuthorityCatalogPublicationFacts, JournalStoreError> {
        let ReplayPublicationAnchor::Ordered(entry) = self.inner.sealed.anchor() else {
            return Err(JournalStoreError::NonCanonical);
        };
        let write = self
            .inner
            .sealed
            .system_authority_write()
            .ok_or(JournalStoreError::NonCanonical)?;
        let StandardSystemAuthorityWrite::Catalog {
            record: Some(record),
            history,
        } = write.selected()
        else {
            return Err(JournalStoreError::NonCanonical);
        };
        let storage = self
            .storage
            .catalog_history()
            .ok_or(JournalStoreError::NonCanonical)?;
        let [committee] = self.storage.committee_records() else {
            return Err(JournalStoreError::NonCanonical);
        };
        if storage.record() != record || storage.root() != history.root() {
            return Err(JournalStoreError::NonCanonical);
        }
        Ok(SystemAuthorityCatalogPublicationFacts {
            journal_store: self.inner.store.instance_id(),
            predecessor_heads: self.pending.predecessor_heads(),
            successor_heads: self.inner.sealed.next().id(),
            ordered_entry: entry.clone(),
            predecessor_control: self.predecessor.control_state(),
            successor_control: self.successor.control_state(),
            predecessor_view: self.predecessor.commitment(),
            successor_view: self.successor.commitment(),
            predecessor_authority_state: self.predecessor.authority_state_commitment(),
            successor_authority_state: self.successor.authority_state_commitment(),
            claim: self.pending.claim(),
            command: self.command.clone(),
            operation: write.operation(),
            result: write.result().clone(),
            record: storage.record().clone(),
            root: storage.root(),
            storage_plan: catalog_storage_plan_commitment(record, history, committee)?,
        })
    }

    fn publish_recovered(
        self,
    ) -> Result<RecoveredSystemAuthorityCatalog<'store, S>, JournalStoreError> {
        let facts = self.publication_facts()?;
        if !self.pending.matches_catalog_publication_facts(&facts) {
            return Err(JournalStoreError::NonCanonical);
        }
        let Self {
            inner,
            pending,
            storage,
            command,
            predecessor: _,
            successor,
        } = self;
        let ReplayPreparedPublication {
            store,
            sealed,
            successor: materialization,
            executions,
        } = inner;
        let publication = store.publish_system_authority(&sealed, &storage)?;
        let durable = store.heads()?.ok_or(JournalStoreError::NotInitialized)?;
        let next = sealed.next();
        let ReplayPublicationAnchor::Ordered(entry) = sealed.anchor() else {
            return Err(JournalStoreError::NonCanonical);
        };
        if durable != *next
            || durable.id() != next.id()
            || next.previous != Some(pending.predecessor_heads())
            || store.get::<OrderedEntry>(entry.id())?.as_ref() != Some(entry)
            || (!publication.heads_advanced
                && (durable.id() != next.id() || next.previous != Some(sealed.expected())))
        {
            return Err(JournalStoreError::Corrupt);
        }
        verify_catalog_storage_closure(store, &storage, &command)?;
        let replayed_root = materialization
            .replayed_root()
            .ok_or(JournalStoreError::NonCanonical)?;
        let scope = SystemAuthorityJournalScope::from_replayed_root(&replayed_root)
            .map_err(|_| JournalStoreError::NonCanonical)?;
        let post = ReplayedSystemAuthorityView::from_authenticated_replay(
            scope,
            successor.authority_state(),
            store.instance_id(),
            durable.id(),
            successor.control_state(),
        )
        .map_err(|_| JournalStoreError::NonCanonical)?;
        if post.commitment() != successor.commitment()
            || post.authority_state_commitment() != successor.authority_state_commitment()
        {
            return Err(JournalStoreError::Corrupt);
        }
        Ok(RecoveredSystemAuthorityCatalog {
            store,
            pending,
            facts,
            current: materialization,
            publication: Some(publication),
            executions,
        })
    }
}

/// Preparing an exact anchor already visible at the authenticated head is an
/// idempotent response-loss retry and performs no second CAS.
#[allow(clippy::large_enum_variant)]
#[cfg(feature = "std")]
pub enum ReplayPreparation<'store, S: AgentJournalStore> {
    Ready(ReplayPreparedPublication<'store, S>),
    AlreadyCommitted(ReplayCommittedRecovery),
}

/// Shared apply keeps its post-publication receipt explicit, including on an
/// authenticated response-loss retry, without widening the Local preparation
/// API or allowing generic publication of a Shared splice.
#[cfg(feature = "std")]
pub(crate) enum SharedReplayPreparation<'store, S: AgentJournalStore> {
    Ready(PreparedSharedOrderedPublication<'store, S>),
    AlreadyCommitted {
        recovery: ReplayCommittedRecovery,
        publication: PublishedSharedOrdered,
    },
}

impl ReplaySealedPublication {
    pub const fn expected(&self) -> JournalHeadsId {
        self.expected
    }

    pub fn next(&self) -> &JournalHeads {
        &self.next
    }

    pub fn anchor(&self) -> &ReplayPublicationAnchor {
        &self.anchor
    }

    pub fn checkpoint_validation(&self) -> Option<&ReplaySealedCheckpoint> {
        self.checkpoint.as_ref()
    }

    pub(crate) fn outcomes(&self) -> &[ReplaySealedOutcome] {
        &self.outcomes
    }

    pub(crate) fn history_plans(&self) -> &[InvocationHistoryWritePlan] {
        &self.history_plans
    }

    pub(crate) const fn fence_ancestry(&self) -> &FenceAncestryEvidence {
        &self.fence_ancestry
    }

    pub(crate) const fn shared_merge_projection(
        &self,
    ) -> Option<&ReplaySealedSharedMergeProjection> {
        self.shared_merge_projection.as_ref()
    }

    pub(crate) const fn shared_ordered_commit(&self) -> Option<&ReplaySealedSharedOrderedCommit> {
        self.shared_ordered_commit.as_ref()
    }

    /// Private batch-5c handoff. Generic publication deliberately rejects a
    /// token returned here until storage can stage and read back its complete
    /// content-addressed dependency closure.
    pub(crate) const fn system_authority_write(&self) -> Option<&ReplaySystemAuthorityWrite> {
        self.system_authority_write.as_ref()
    }

    pub(crate) const fn mode(&self) -> ReplayPublicationMode {
        self.mode
    }
}

/// Failure while consulting checkpoint-authenticated InvocationId ownership.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum InvocationOwnershipError {
    Unavailable,
    Unauthenticated,
    Conflict,
}

/// Opaque live-admission evidence preloaded from the current authenticated
/// manifest. A key-specific membership result is never interpreted until the
/// caller receipt has been authenticated inside `ReplayMachine`.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum UnseenInvocationAdmission {
    Available,
    AtCapacity(Result<bool, InvocationOwnershipError>),
}

/// Exact ownership index used across checkpoint compaction. Implementations
/// must authenticate `lookup` against the invocation-index root committed by
/// the opened head/checkpoint. Mutations update the bounded live tree or
/// atomically archive an acknowledged owner into permanent history for the
/// same publication as the successor lane manifests.
pub trait InvocationOwnership {
    fn lookup(
        &self,
        key: InvocationOwnershipKey,
    ) -> Result<Option<InvocationIndexLookup>, InvocationOwnershipError>;

    fn mutate(
        &mut self,
        operation: InvocationIndexBatchOperation,
    ) -> Result<(), InvocationOwnershipError> {
        self.mutate_batch(operation.key().scope, core::slice::from_ref(&operation))
    }

    /// Install and read back an immutable exact outcome before any ownership
    /// root may reference it.
    fn persist_outcome(
        &mut self,
        outcome: &InvocationOutcomeRecord,
    ) -> Result<InvocationOutcomeRef, InvocationOwnershipError>;

    /// Resolve the exact outcome authenticated by the current ownership leaf.
    fn outcome(
        &self,
        key: InvocationOwnershipKey,
    ) -> Result<Option<InvocationOutcomeRecord>, InvocationOwnershipError>;

    /// Apply one strictly key-ordered set of transitions to exactly one scope
    /// and expose only the final root.
    fn mutate_batch(
        &mut self,
        scope: InvocationOwnershipScope,
        operations: &[InvocationIndexBatchOperation],
    ) -> Result<(), InvocationOwnershipError>;

    /// Authenticated number of Merge owners which are not yet finalized.
    fn unfinalized(&self, scope: InvocationOwnershipScope)
    -> Result<u64, InvocationOwnershipError>;

    /// Content identity of the currently staged authenticated index. Replay
    /// publication is unavailable until a non-empty index implementation can
    /// return its exact manifest ID.
    fn index_id(
        &self,
        scope: InvocationOwnershipScope,
    ) -> Result<InvocationIndexId, InvocationOwnershipError>;

    /// Pure, bounded history-node plans staged while this ownership view was
    /// mutated. Storage validates and installs them only inside the consuming
    /// heads CAS; preparation never publishes permanent history objects.
    fn history_write_plans(
        &self,
    ) -> Result<Vec<InvocationHistoryWritePlan>, InvocationOwnershipError>;
}

/// In-memory ownership used only while replaying from immutable genesis.
/// Checkpoint recovery must supply its authenticated index implementation.
pub struct GenesisInvocationOwnership {
    genesis: AgentJournalGenesisId,
    entries: BTreeMap<InvocationOwnershipKey, InvocationOwnershipValue>,
    history: BTreeMap<InvocationOwnershipKey, InvocationAcknowledgedFact>,
    outcomes: BTreeMap<InvocationOutcomeId, InvocationOutcomeRecord>,
}

impl InvocationOwnership for GenesisInvocationOwnership {
    fn lookup(
        &self,
        key: InvocationOwnershipKey,
    ) -> Result<Option<InvocationIndexLookup>, InvocationOwnershipError> {
        match (self.entries.get(&key), self.history.get(&key)) {
            (Some(_), Some(_)) => Err(InvocationOwnershipError::Unauthenticated),
            (Some(owner), None) => Ok(Some(InvocationIndexLookup::Live(*owner))),
            (None, Some(fact)) => Ok(Some(InvocationIndexLookup::Archived(*fact))),
            (None, None) => Ok(None),
        }
    }

    fn persist_outcome(
        &mut self,
        outcome: &InvocationOutcomeRecord,
    ) -> Result<InvocationOutcomeRef, InvocationOwnershipError> {
        outcome
            .validate()
            .map_err(|_| InvocationOwnershipError::Unauthenticated)?;
        let reference = InvocationOutcomeRef::for_record(outcome)
            .map_err(|_| InvocationOwnershipError::Unauthenticated)?;
        match self.outcomes.get(&reference.outcome) {
            Some(existing) if existing == outcome => Ok(reference),
            Some(_) => Err(InvocationOwnershipError::Conflict),
            None => {
                self.outcomes.insert(reference.outcome, outcome.clone());
                Ok(reference)
            }
        }
    }

    fn outcome(
        &self,
        key: InvocationOwnershipKey,
    ) -> Result<Option<InvocationOutcomeRecord>, InvocationOwnershipError> {
        let Some(owner) = self.entries.get(&key) else {
            return Ok(None);
        };
        let Some(reference) = owner.outcome() else {
            return Ok(None);
        };
        let outcome = self
            .outcomes
            .get(&reference.outcome)
            .ok_or(InvocationOwnershipError::Unavailable)?;
        if !reference.authenticates(outcome)
            || outcome.genesis != self.genesis
            || outcome.key != key
            || outcome.request_commitment != owner.request_commitment
            || outcome.first_input != owner.first_input
            || outcome.lane != owner.lane
            || outcome.node != owner.node
            || Some(outcome.disposition()) != owner.disposition()
        {
            return Err(InvocationOwnershipError::Unauthenticated);
        }
        Ok(Some(outcome.clone()))
    }

    fn mutate_batch(
        &mut self,
        scope: InvocationOwnershipScope,
        operations: &[InvocationIndexBatchOperation],
    ) -> Result<(), InvocationOwnershipError> {
        if operations
            .windows(2)
            .any(|pair| pair[0].key() >= pair[1].key())
            || operations
                .iter()
                .any(|operation| operation.key().scope != scope)
        {
            return Err(InvocationOwnershipError::Unauthenticated);
        }
        let mut entries = self.entries.clone();
        let mut history = self.history.clone();
        for operation in operations {
            match *operation {
                InvocationIndexBatchOperation::PutLive { key, value } => {
                    if key.validate().is_err()
                        || value.validate().is_err()
                        || value.scope != key.scope
                    {
                        return Err(InvocationOwnershipError::Unauthenticated);
                    }
                    if let Some(fact) = history.get(&key) {
                        let candidate =
                            InvocationAcknowledgedFact::from_owner(self.genesis, key, value)
                                .map_err(|_| InvocationOwnershipError::Conflict)?;
                        if fact != &candidate {
                            return Err(InvocationOwnershipError::Conflict);
                        }
                        continue;
                    }
                    match entries.get(&key) {
                        Some(existing) if existing == &value => {}
                        Some(existing)
                            if existing.request_commitment == value.request_commitment
                                && existing.scope == value.scope
                                && existing.first_input == value.first_input
                                && existing.lane == value.lane
                                && existing.node == value.node =>
                        {
                            entries.insert(key, value);
                        }
                        Some(_) => return Err(InvocationOwnershipError::Conflict),
                        None => {
                            entries.insert(key, value);
                        }
                    }
                }
                InvocationIndexBatchOperation::Archive { key, expected } => {
                    let fact = InvocationAcknowledgedFact::from_owner(self.genesis, key, expected)
                        .map_err(|_| InvocationOwnershipError::Unauthenticated)?;
                    match (entries.get(&key), history.get(&key)) {
                        (Some(owner), None) if owner == &expected => {
                            entries.remove(&key);
                            history.insert(key, fact);
                        }
                        (None, Some(existing)) if existing == &fact => {}
                        _ => return Err(InvocationOwnershipError::Conflict),
                    }
                }
            }
        }
        self.entries = entries;
        self.history = history;
        Ok(())
    }

    fn unfinalized(
        &self,
        scope: InvocationOwnershipScope,
    ) -> Result<u64, InvocationOwnershipError> {
        Ok(self
            .entries
            .iter()
            .filter(|(key, owner)| key.scope == scope && owner.is_unfinalized())
            .count() as u64)
    }

    fn index_id(
        &self,
        scope: InvocationOwnershipScope,
    ) -> Result<InvocationIndexId, InvocationOwnershipError> {
        if self.entries.keys().any(|key| key.scope == scope)
            || self.history.keys().any(|key| key.scope == scope)
        {
            return Err(InvocationOwnershipError::Unavailable);
        }
        Ok(InvocationIndexManifest::empty(self.genesis, scope).id())
    }

    fn history_write_plans(
        &self,
    ) -> Result<Vec<InvocationHistoryWritePlan>, InvocationOwnershipError> {
        Ok(Vec::new())
    }
}

/// Stateful transition validator shared by ordered, Merge, and Local replay.
pub struct ReplayMachine<Ownership> {
    genesis: AgentJournalGenesisId,
    replayed_root: Option<ReplayedRootJournalIdentity>,
    runtime: RuntimeBinding,
    runtime_history: BTreeMap<OrderedBase, RuntimeBinding>,
    ownership: Ownership,
    fence: Option<MergeFence>,
}

impl ReplayMachine<GenesisInvocationOwnership> {
    /// Start the one legitimate empty ownership index at immutable genesis.
    pub fn from_genesis(
        genesis: AgentJournalGenesisId,
        runtime: RuntimeBinding,
    ) -> Result<Self, InvocationOwnershipError> {
        if genesis == AgentJournalGenesisId::ZERO || runtime.validate().is_err() {
            return Err(InvocationOwnershipError::Unauthenticated);
        }
        Ok(Self {
            genesis,
            replayed_root: None,
            runtime: runtime.clone(),
            runtime_history: BTreeMap::from([(OrderedBase::post_genesis(), runtime)]),
            ownership: GenesisInvocationOwnership {
                genesis,
                entries: BTreeMap::new(),
                history: BTreeMap::new(),
                outcomes: BTreeMap::new(),
            },
            fence: None,
        })
    }

    /// Start replay from an explicitly root-reverified sealed generation.
    /// This is intentionally distinct from [`Self::from_genesis`], whose raw
    /// IDs never acquire live authority provenance.
    pub(crate) fn from_replayed_root_genesis(
        sealed: &ReplaySealedGenesis,
        runtime: RuntimeBinding,
    ) -> Result<Self, InvocationOwnershipError> {
        let identity = sealed
            .replayed_root_identity()
            .map_err(|_| InvocationOwnershipError::Unauthenticated)?;
        if sealed.genesis().runtime() != &runtime
            || sealed.genesis().id() != identity.genesis()
            || sealed.genesis().admission != identity.outer_admission()
        {
            return Err(InvocationOwnershipError::Unauthenticated);
        }
        let mut machine = Self::from_genesis(identity.genesis(), runtime)?;
        machine.replayed_root = Some(identity);
        Ok(machine)
    }
}

impl<Ownership: InvocationOwnership> ReplayMachine<Ownership> {
    fn from_materialization(
        materialization: &ReplayMaterialization,
        ownership: Ownership,
    ) -> Result<Self, InvocationOwnershipError> {
        let heads = &materialization.heads;
        for scope in [
            InvocationOwnershipScope::Ordered,
            InvocationOwnershipScope::Merge,
            InvocationOwnershipScope::Local(heads.node),
        ] {
            if ownership.index_id(scope)?
                != invocation_index_at(heads, scope)
                    .ok_or(InvocationOwnershipError::Unauthenticated)?
            {
                return Err(InvocationOwnershipError::Unauthenticated);
            }
        }
        Ok(Self {
            genesis: heads.genesis,
            replayed_root: materialization.replayed_root,
            runtime: heads.runtime.clone(),
            runtime_history: materialization
                .ordered_snapshots
                .iter()
                .map(|(base, snapshot)| (*base, snapshot.runtime.clone()))
                .collect(),
            ownership,
            fence: materialization.fence.clone(),
        })
    }

    /// Resume from a checkpoint-authenticated ownership implementation.
    /// There is deliberately no checkpoint constructor which defaults to an
    /// empty map.
    pub fn from_checkpoint(
        checkpoint: &ReplaySealedCheckpoint,
        ownership: Ownership,
        fence: Option<MergeFence>,
    ) -> Result<Self, InvocationOwnershipError> {
        let manifest = &checkpoint.manifest;
        let genesis = manifest.genesis;
        let ordered_base = OrderedBase {
            index: manifest.ordered_index,
            head: manifest.ordered_head,
        };
        let runtime = manifest.runtime.clone();
        if manifest.validate().is_err() {
            return Err(InvocationOwnershipError::Unauthenticated);
        }
        for (id, index) in &checkpoint.invocation_indexes {
            if ownership.index_id(index.scope)? != *id {
                return Err(InvocationOwnershipError::Unauthenticated);
            }
        }
        match (manifest.merge_fence, manifest.merge_seal, fence.as_ref()) {
            (base, None, None) if base == OrderedBase::post_genesis() => {}
            (base, Some(seal), Some(fence))
                if base.index == fence.ordered_index
                    && base.head == Some(fence.ordered_head)
                    && seal == fence.seal => {}
            _ => return Err(InvocationOwnershipError::Unauthenticated),
        }
        Ok(Self {
            genesis,
            replayed_root: None,
            runtime: runtime.clone(),
            runtime_history: BTreeMap::from([(ordered_base, runtime)]),
            ownership,
            fence,
        })
    }

    pub fn runtime(&self) -> &RuntimeBinding {
        &self.runtime
    }

    pub fn runtime_at(&self, base: OrderedBase) -> Option<&RuntimeBinding> {
        self.runtime_history.get(&base)
    }

    /// Hydrate one pruned ordered base only through an explicit authenticated
    /// resolver. Absence is distinguishable from an invalid base so callers
    /// cannot silently reinterpret checkpoint age as a Merge/Local fence.
    fn resolve_ordered_base<R: OrderedBaseResolver, ExecutorError>(
        &mut self,
        resolver: &R,
        canonical_head: OrderedBase,
        base: OrderedBase,
    ) -> Result<(), ReplayError<R::Error, ExecutorError>> {
        let known_head = self
            .runtime_history
            .keys()
            .next_back()
            .copied()
            .ok_or(ReplayError::UnavailableOrderedBase)?;
        if canonical_head.validate().is_err()
            || base.validate().is_err()
            || base.index > canonical_head.index
            || canonical_head != known_head
        {
            return Err(ReplayError::InvalidOrderedBase);
        }
        let snapshot = resolver
            .snapshot_at(self.genesis, canonical_head, base)
            .map_err(ReplayError::Source)?
            .ok_or(ReplayError::UnavailableOrderedBase)?;
        let runtime = snapshot.runtime;
        if snapshot.genesis != self.genesis
            || snapshot.canonical_head != canonical_head
            || snapshot.base != base
            || snapshot.control_commitment != BlobRef::of_bytes(&snapshot.control)
            || snapshot.linear_commitment != BlobRef::of_bytes(&snapshot.linear)
            || snapshot.evidence_commitment == Hash::ZERO
        {
            return Err(ReplayError::InvalidOrderedBase);
        }
        if runtime.validate().is_err()
            || runtime.space != self.runtime.space
            || runtime.agent != self.runtime.agent
        {
            return Err(ReplayError::RuntimeMismatch);
        }
        if let Some(existing) = self.runtime_history.get(&base) {
            if existing != &runtime {
                return Err(ReplayError::RuntimeMismatch);
            }
        } else {
            self.runtime_history.insert(base, runtime);
        }
        Ok(())
    }

    pub fn fence(&self) -> Option<&MergeFence> {
        self.fence.as_ref()
    }

    fn ownership_ids(
        &self,
        node: NodeId,
    ) -> Result<(InvocationIndexId, InvocationIndexId, InvocationIndexId), InvocationOwnershipError>
    {
        Ok((
            self.ownership.index_id(InvocationOwnershipScope::Ordered)?,
            self.ownership.index_id(InvocationOwnershipScope::Merge)?,
            self.ownership
                .index_id(InvocationOwnershipScope::Local(node))?,
        ))
    }

    fn system_authority_execution<SourceError, ExecutorError>(
        &self,
        input: &ReplayInput,
    ) -> Result<Option<ReplaySystemAuthorityExecution>, ReplayError<SourceError, ExecutorError>>
    {
        let ReplayOperation::Management { request } = &input.operation else {
            return Ok(None);
        };
        if !matches!(
            request,
            LifecycleRequest::FinalizeSystemAuthority(_)
                | LifecycleRequest::RotateSystemAuthority(_)
                | LifecycleRequest::FinalizeCatalog(_)
        ) {
            return Ok(None);
        }
        let identity = self.replayed_root.ok_or(ReplayError::ScopeMismatch)?;
        if identity.genesis() != self.genesis {
            return Err(ReplayError::ScopeMismatch);
        }
        ReplaySystemAuthorityExecution::from_replayed_root(&identity)
            .map(Some)
            .map_err(|_| ReplayError::ScopeMismatch)
    }

    /// Validate the Raft-owned Merge seal consumed by an ordered management
    /// entry. Pruned ordered bases are accepted only when this machine was
    /// explicitly hydrated through [`OrderedBaseResolver`].
    pub fn validate_management_fence<S: ReplaySource>(
        &self,
        source: &S,
        entry_id: OrderedEntryId,
        entry: &OrderedEntry,
        ordered: &OrderedReplay,
        merge: &MergeReplay,
        merge_state: &[u8],
    ) -> Result<MergeFence, ReplayError<S::Error, core::convert::Infallible>> {
        validate_management_fence_inner(
            source,
            entry_id,
            entry,
            ordered,
            merge,
            merge_state,
            |event| self.runtime_at(event.ordered_base) == Some(&event.input.runtime),
        )
    }

    pub fn install_fence<SourceError, ExecutorError>(
        &mut self,
        fence: MergeFence,
    ) -> Result<(), ReplayError<SourceError, ExecutorError>> {
        if self
            .fence
            .as_ref()
            .is_some_and(|current| fence.ordered_index <= current.ordered_index)
        {
            return Err(ReplayError::InvalidFence);
        }
        self.fence = Some(fence);
        Ok(())
    }

    /// Execute the next structurally loaded Control/Linear entry and attach
    /// its resulting runtime binding to the ordered replay token.
    pub fn apply_ordered_entry<E: ReplayExecutor, SourceError>(
        &mut self,
        executor: &mut E,
        ordered: &mut OrderedReplay,
        id: OrderedEntryId,
        before: &RuntimeState,
    ) -> Result<ReplayStep, ReplayError<SourceError, E::Error>> {
        if ordered.genesis != self.genesis {
            return Err(ReplayError::ScopeMismatch);
        }
        let entry = ordered
            .entries
            .iter()
            .find(|(entry_id, _)| *entry_id == id)
            .map(|(_, entry)| entry.clone())
            .ok_or(ReplayError::MissingOrdered(id))?;
        let parent_base = OrderedBase {
            index: entry
                .index
                .checked_sub(1)
                .ok_or(ReplayError::ChainMismatch)?,
            head: entry.parent,
        };
        if self.runtime_history.keys().next_back().copied() != Some(parent_base) {
            return Err(ReplayError::ChainMismatch);
        }
        let parent_runtime = self
            .runtime_at(parent_base)
            .cloned()
            .ok_or(ReplayError::UnavailableOrderedBase)?;
        if let Some(existing) = ordered.runtime_history.get(&parent_base) {
            if existing != &parent_runtime {
                return Err(ReplayError::RuntimeMismatch);
            }
        } else {
            ordered.runtime_history.insert(parent_base, parent_runtime);
        }
        let step = self
            .apply(
                executor,
                &entry.input,
                before,
                ReplayPosition::Ordered {
                    id,
                    index: entry.index,
                    merge_frontier: entry.merge_frontier,
                    merge_seal: entry.merge_seal,
                },
            )
            .map_err(historical_replay_error)?;
        ordered.runtime_history.insert(
            OrderedBase {
                index: entry.index,
                head: Some(id),
            },
            step.runtime.clone(),
        );
        Ok(step)
    }

    pub fn apply<E: ReplayExecutor, SourceError>(
        &mut self,
        executor: &mut E,
        input: &ReplayInput,
        before: &RuntimeState,
        position: ReplayPosition,
    ) -> Result<ReplayStep, ReplayError<SourceError, E::Error>> {
        self.apply_with_unseen_capacity(executor, input, before, position, None)
    }

    /// Live preparation supplies a read-only capacity decision derived from
    /// the exact authenticated scope manifest. Authentication and ownership
    /// lookup still happen inside this method before the decision can be
    /// observed, so a forged request cannot probe index occupancy. Existing
    /// owners (retry, divergence, acknowledgement) never consume the reserve.
    fn apply_with_unseen_capacity<E: ReplayExecutor, SourceError>(
        &mut self,
        executor: &mut E,
        input: &ReplayInput,
        before: &RuntimeState,
        position: ReplayPosition,
        unseen_admission: Option<UnseenInvocationAdmission>,
    ) -> Result<ReplayStep, ReplayError<SourceError, E::Error>> {
        if input.validate().is_err() {
            return Err(ReplayError::InvalidRecord);
        }
        validate_runtime_state_bound(before)?;
        validate_position(input, position)?;
        let execution_runtime = match position {
            ReplayPosition::Merge { ordered_base, .. }
            | ReplayPosition::Local { ordered_base, .. } => self
                .runtime_history
                .get(&ordered_base)
                .cloned()
                .ok_or(ReplayError::InvalidOrderedBase)?,
            ReplayPosition::Genesis | ReplayPosition::Ordered { .. } => self.runtime.clone(),
        };
        if input.runtime != execution_runtime {
            return Err(ReplayError::RuntimeMismatch);
        }
        let system_authority_execution = self.system_authority_execution(input)?;

        // Authority admission precedes every ownership shortcut. In
        // particular, a forged receipt with an otherwise exact request
        // commitment cannot advance a journal position as a duplicate or
        // divergence without entering the executor's authenticated boundary.
        // SealMerge is instead an ordered-log protocol unit with no caller
        // receipt or application execution; its exact ordered position and
        // referenced seal are authenticated by the publication closure.
        if !matches!(input.operation, ReplayOperation::SealMerge) {
            executor
                .authenticate(input, before, position)
                .map_err(ReplayError::Executor)?;
        }

        if let ReplayPosition::Merge { id, .. } = position {
            if let Some(fence) = &self.fence {
                let event_stub = match position {
                    ReplayPosition::Merge { ordered_base, .. } => ordered_base,
                    _ => unreachable!(),
                };
                if event_stub.index < fence.ordered_index && !fence.sealed_ancestry.contains(&id) {
                    return Err(ReplayError::StalePreFenceEvent(id));
                }
            }
        }

        let invocation_owner =
            invocation_identity(input).map(|(invocation, request, operation)| {
                (
                    invocation_ownership_key(position, invocation),
                    request,
                    operation,
                )
            });
        let mut prior_owner = None;
        let mut retained_outcome = None;
        let mut acknowledgement_outcome = None;
        let mut retained_recovery = false;
        let mut replaying_pending_source = false;
        let mut ownership_delta = InvocationIndexDelta::NONE;
        let mut sealed_outcomes = Vec::new();
        if let Some((key, request, operation)) = invocation_owner {
            let lookup = self
                .ownership
                .lookup(key)
                .map_err(ReplayError::InvocationOwnership)?;
            if let Some(InvocationIndexLookup::Archived(fact)) = lookup {
                validate_archived_for_input(fact, self.genesis, key, input)
                    .map_err(ReplayError::InvocationOwnership)?;
                self.advance_noop_position(position, &execution_runtime);
                return Ok(noop_replay_step(
                    input,
                    before,
                    execution_runtime,
                    position,
                    if fact.request_commitment() == request {
                        ReplayStepOutcome::ExactDuplicate
                    } else {
                        ReplayStepOutcome::DivergentInvocation
                    },
                ));
            }
            if let Some(InvocationIndexLookup::Live(seen)) = lookup {
                validate_owner_for_input(seen, key, input)
                    .map_err(ReplayError::InvocationOwnership)?;
                if seen.request_commitment != request {
                    self.advance_noop_position(position, &execution_runtime);
                    return Ok(noop_replay_step(
                        input,
                        before,
                        execution_runtime,
                        position,
                        ReplayStepOutcome::DivergentInvocation,
                    ));
                }
                prior_owner = Some(seen);
                match (operation, seen.result_state) {
                    (
                        InvocationOwnershipOperation::Invoke,
                        InvocationResultState::PendingMerge { source_event },
                    ) => {
                        let is_source = matches!(
                            position,
                            ReplayPosition::Merge { id, .. } if id == source_event
                        );
                        if is_source {
                            replaying_pending_source = true;
                        } else {
                            self.advance_noop_position(position, &execution_runtime);
                            return Ok(noop_replay_step(
                                input,
                                before,
                                execution_runtime,
                                position,
                                ReplayStepOutcome::ExactDuplicate,
                            ));
                        }
                    }
                    (
                        InvocationOwnershipOperation::Invoke,
                        InvocationResultState::Retained { .. },
                    ) => {
                        let outcome = self
                            .ownership
                            .outcome(key)
                            .map_err(ReplayError::InvocationOwnership)?
                            .ok_or(ReplayError::InvocationOwnership(
                                InvocationOwnershipError::Unauthenticated,
                            ))?;
                        validate_retained_outcome(&outcome, self.genesis, key, seen, input)
                            .map_err(ReplayError::InvocationOwnership)?;
                        retained_outcome = Some(outcome);
                        retained_recovery = true;
                    }
                    (
                        InvocationOwnershipOperation::Invoke,
                        InvocationResultState::PendingMergeAcknowledgement { .. },
                    ) => {
                        // The canonical acknowledgement may already have
                        // removed an Applied guest result from provisional
                        // Merge state. It is committed intent, not a second
                        // opportunity to disclose or reconstruct the reply.
                        self.advance_noop_position(position, &execution_runtime);
                        return Ok(noop_replay_step(
                            input,
                            before,
                            execution_runtime,
                            position,
                            ReplayStepOutcome::ExactDuplicate,
                        ));
                    }
                    (
                        InvocationOwnershipOperation::Acknowledge,
                        InvocationResultState::PendingMergeAcknowledgement { .. },
                    ) => {
                        self.advance_noop_position(position, &execution_runtime);
                        return Ok(noop_replay_step(
                            input,
                            before,
                            execution_runtime,
                            position,
                            ReplayStepOutcome::ExactDuplicate,
                        ));
                    }
                    (
                        InvocationOwnershipOperation::Acknowledge,
                        InvocationResultState::PendingMerge { .. },
                    ) => {
                        return Err(ReplayError::InvocationOwnership(
                            InvocationOwnershipError::Unauthenticated,
                        ));
                    }
                    (
                        InvocationOwnershipOperation::Acknowledge,
                        InvocationResultState::Retained { .. },
                    ) => {
                        let outcome = self
                            .ownership
                            .outcome(key)
                            .map_err(ReplayError::InvocationOwnership)?
                            .ok_or(ReplayError::InvocationOwnership(
                                InvocationOwnershipError::Unauthenticated,
                            ))?;
                        validate_retained_outcome(&outcome, self.genesis, key, seen, input)
                            .map_err(ReplayError::InvocationOwnership)?;
                        acknowledgement_outcome = Some(outcome);
                    }
                }
            } else {
                if operation == InvocationOwnershipOperation::Acknowledge {
                    return Err(ReplayError::InvocationOwnership(
                        InvocationOwnershipError::Unauthenticated,
                    ));
                }
                match unseen_admission {
                    Some(UnseenInvocationAdmission::AtCapacity(Ok(false))) => {
                        return Err(ReplayError::UncommittedInvocation(
                            ActorExecutionError::ResultCapacity,
                        ));
                    }
                    Some(UnseenInvocationAdmission::AtCapacity(Err(error))) => {
                        return Err(ReplayError::InvocationOwnership(error));
                    }
                    None
                    | Some(UnseenInvocationAdmission::Available)
                    | Some(UnseenInvocationAdmission::AtCapacity(Ok(true))) => {}
                }
            }
        }

        let non_applied_ack = matches!(
            (invocation_owner, prior_owner),
            (
                Some((_, _, InvocationOwnershipOperation::Acknowledge)),
                Some(owner)
            ) if owner.disposition() != Some(InvocationDisposition::Applied)
        );
        let transition = if non_applied_ack {
            ReplayTransition {
                state: before.clone(),
                disposition: ReplayDisposition::Applied,
                result: None,
                next_runtime: execution_runtime.clone(),
                products: ReplayProducts::default(),
            }
        } else if matches!(input.operation, ReplayOperation::SealMerge) {
            ReplayTransition {
                state: before.clone(),
                disposition: ReplayDisposition::Applied,
                result: None,
                next_runtime: execution_runtime.clone(),
                products: ReplayProducts::default(),
            }
        } else if retained_recovery {
            retained_exact_transition(
                input,
                before,
                &execution_runtime,
                retained_outcome
                    .as_ref()
                    .ok_or(ReplayError::InvocationOwnership(
                        InvocationOwnershipError::Unauthenticated,
                    ))?,
            )?
        } else {
            executor
                .execute_with_journal_context(
                    input,
                    before,
                    position,
                    system_authority_execution.map(|execution| execution.context),
                )
                .map_err(ReplayError::Executor)?
        };
        if prior_owner.is_none()
            && matches!(
                invocation_owner,
                Some((_, _, InvocationOwnershipOperation::Invoke))
            )
            && let Some(Err(error)) = transition.result.as_ref()
            && is_uncommitted_refusal(*error)
        {
            if !transition.products.is_empty() {
                return Err(ReplayError::ForbiddenMergeProducts);
            }
            if transition.state != *before
                || transition.next_runtime != execution_runtime
                || transition.disposition != ReplayDisposition::Rejected
            {
                return Err(ReplayError::TerminalMutation);
            }
            return Err(ReplayError::UncommittedInvocation(*error));
        }
        validate_runtime_state_bound(&transition.state)?;
        let system_authority_write = validate_transition(
            input,
            before,
            &transition,
            position,
            &execution_runtime,
            retained_recovery,
            non_applied_ack,
            acknowledgement_outcome.as_ref(),
            system_authority_execution,
        )?;
        if retained_recovery
            && let Some(outcome) = &retained_outcome
            && transition.result.as_ref() != Some(&outcome.result)
        {
            return Err(ReplayError::InvocationOwnership(
                InvocationOwnershipError::Unauthenticated,
            ));
        }
        if let Some((key, request, operation)) = invocation_owner {
            let mutation = match (operation, prior_owner) {
                (InvocationOwnershipOperation::Invoke, None) => {
                    let result_state = match position {
                        ReplayPosition::Merge { id, .. } => {
                            InvocationResultState::PendingMerge { source_event: id }
                        }
                        ReplayPosition::Ordered { .. } | ReplayPosition::Local { .. } => {
                            let anchor = invocation_outcome_anchor(position).ok_or(
                                ReplayError::InvocationOwnership(
                                    InvocationOwnershipError::Unauthenticated,
                                ),
                            )?;
                            let result = transition.result.clone().ok_or(
                                ReplayError::InvocationOwnership(
                                    InvocationOwnershipError::Unauthenticated,
                                ),
                            )?;
                            let outcome = InvocationOutcomeRecord::from_runtime_states(
                                self.genesis,
                                key.scope,
                                anchor,
                                input,
                                before,
                                &transition.state,
                                result,
                            )
                            .map_err(|_| {
                                ReplayError::InvocationOwnership(
                                    InvocationOwnershipError::Unauthenticated,
                                )
                            })?;
                            outcome.validate_for(input).map_err(|_| {
                                ReplayError::InvocationOwnership(
                                    InvocationOwnershipError::Unauthenticated,
                                )
                            })?;
                            let reference = self
                                .ownership
                                .persist_outcome(&outcome)
                                .map_err(ReplayError::InvocationOwnership)?;
                            sealed_outcomes.push(ReplaySealedOutcome {
                                record: outcome.clone(),
                                input: input.clone(),
                            });
                            InvocationResultState::Retained {
                                disposition: outcome.disposition(),
                                outcome: reference,
                            }
                        }
                        ReplayPosition::Genesis => {
                            return Err(ReplayError::InvalidPosition);
                        }
                    };
                    let value = InvocationOwnershipValue {
                        scope: key.scope,
                        request_commitment: request,
                        first_input: input.id(),
                        lane: input.persisted_lane(),
                        node: match key.scope {
                            InvocationOwnershipScope::Local(node) => Some(node),
                            InvocationOwnershipScope::Ordered | InvocationOwnershipScope::Merge => {
                                None
                            }
                        },
                        result_state,
                    };
                    Some(InvocationIndexBatchOperation::PutLive { key, value })
                }
                (InvocationOwnershipOperation::Acknowledge, Some(mut existing)) => {
                    let disposition =
                        existing
                            .disposition()
                            .ok_or(ReplayError::InvocationOwnership(
                                InvocationOwnershipError::Unauthenticated,
                            ))?;
                    match (key.scope, position, existing.result_state) {
                        (
                            InvocationOwnershipScope::Merge,
                            ReplayPosition::Merge { id, .. },
                            InvocationResultState::Retained { outcome, .. },
                        ) => {
                            existing.result_state =
                                InvocationResultState::PendingMergeAcknowledgement {
                                    acknowledgement_event: id,
                                    disposition,
                                    outcome,
                                };
                            Some(InvocationIndexBatchOperation::PutLive {
                                key,
                                value: existing,
                            })
                        }
                        (
                            InvocationOwnershipScope::Ordered | InvocationOwnershipScope::Local(_),
                            _,
                            InvocationResultState::Retained { .. },
                        ) => Some(InvocationIndexBatchOperation::Archive {
                            key,
                            expected: existing,
                        }),
                        _ => {
                            return Err(ReplayError::InvocationOwnership(
                                InvocationOwnershipError::Unauthenticated,
                            ));
                        }
                    }
                }
                (InvocationOwnershipOperation::Invoke, Some(_)) if replaying_pending_source => None,
                (InvocationOwnershipOperation::Invoke, Some(_)) => None,
                (InvocationOwnershipOperation::Acknowledge, None) => {
                    return Err(ReplayError::InvocationOwnership(
                        InvocationOwnershipError::Unauthenticated,
                    ));
                }
            };
            if let Some(mutation) = mutation {
                ownership_delta = ownership_delta.with(key.scope);
                self.ownership
                    .mutate(mutation)
                    .map_err(ReplayError::InvocationOwnership)?;
            }
        }
        if let ReplayPosition::Ordered { id, index, .. } = position {
            let base = OrderedBase {
                index,
                head: Some(id),
            };
            self.runtime = transition.next_runtime.clone();
            self.runtime_history.insert(base, self.runtime.clone());
        } else if matches!(position, ReplayPosition::Genesis) {
            self.runtime = transition.next_runtime.clone();
            self.runtime_history
                .insert(OrderedBase::post_genesis(), self.runtime.clone());
        }
        Ok(ReplayStep {
            state: transition.state,
            runtime: transition.next_runtime,
            outcome: if retained_recovery {
                ReplayStepOutcome::ExactDuplicate
            } else {
                ReplayStepOutcome::Applied(transition.disposition)
            },
            result: transition.result,
            products: transition.products,
            input: input.id(),
            position,
            ownership_delta,
            sealed_outcomes,
            system_authority_write,
            merge_authenticated: false,
        })
    }

    pub fn verify_and_apply_merge<E: ReplayExecutor, SourceError>(
        &mut self,
        executor: &mut E,
        ordered: &OrderedReplay,
        id: MergeEventId,
        event: &MergeEvent,
        before: &RuntimeState,
    ) -> Result<ReplayStep, ReplayError<SourceError, E::Error>> {
        self.verify_and_apply_merge_with_unseen_capacity(executor, ordered, id, event, before, None)
    }

    fn verify_and_apply_merge_with_unseen_capacity<E: ReplayExecutor, SourceError>(
        &mut self,
        executor: &mut E,
        ordered: &OrderedReplay,
        id: MergeEventId,
        event: &MergeEvent,
        before: &RuntimeState,
        unseen_admission: Option<UnseenInvocationAdmission>,
    ) -> Result<ReplayStep, ReplayError<SourceError, E::Error>> {
        validate_runtime_state_bound(before)?;
        if event.validate().is_err()
            || event.id() != id
            || event.genesis != ordered.genesis
            || (!ordered.contains_base(event.ordered_base)
                && !self.runtime_history.contains_key(&event.ordered_base))
        {
            return Err(ReplayError::InvalidOrderedBase);
        }
        if !executor
            .verify_merge_event(event)
            .map_err(ReplayError::Executor)?
        {
            return Err(ReplayError::UnauthenticatedMergeEvent(id));
        }
        if let Some(fence) = &self.fence {
            fence.admit(id, event)?;
            if fence.is_sealed_duplicate(id, event) {
                let position = ReplayPosition::Merge {
                    id,
                    causal_height: event.causal_height,
                    ordered_base: event.ordered_base,
                };
                return Ok(ReplayStep {
                    state: before.clone(),
                    runtime: self
                        .runtime_at(event.ordered_base)
                        .cloned()
                        .ok_or(ReplayError::InvalidOrderedBase)?,
                    outcome: ReplayStepOutcome::ExactDuplicate,
                    result: None,
                    products: ReplayProducts::default(),
                    input: event.input.id(),
                    position,
                    ownership_delta: InvocationIndexDelta::NONE,
                    sealed_outcomes: Vec::new(),
                    system_authority_write: None,
                    merge_authenticated: true,
                });
            }
        }
        let mut step = self.apply_with_unseen_capacity(
            executor,
            &event.input,
            before,
            ReplayPosition::Merge {
                id,
                causal_height: event.causal_height,
                ordered_base: event.ordered_base,
            },
            unseen_admission,
        )?;
        step.merge_authenticated = true;
        Ok(step)
    }

    fn advance_noop_position(&mut self, position: ReplayPosition, runtime: &RuntimeBinding) {
        if let ReplayPosition::Ordered { id, index, .. } = position {
            let base = OrderedBase {
                index,
                head: Some(id),
            };
            self.runtime = runtime.clone();
            self.runtime_history.insert(base, runtime.clone());
        }
    }

    fn validate_direct_outcomes(
        &self,
        input: &ReplayInput,
        before: &RuntimeState,
        step: &ReplayStep,
        scope: InvocationOwnershipScope,
        anchor: InvocationOutcomeAnchor,
    ) -> Result<Vec<ReplaySealedOutcome>, ReplayValidationError> {
        let newly_executed = matches!(input.operation, ReplayOperation::Invoke { .. })
            && matches!(step.outcome, ReplayStepOutcome::Applied(_));
        let direct = step
            .sealed_outcomes
            .iter()
            .filter(|outcome| outcome.record.key.scope == scope)
            .cloned()
            .collect::<Vec<_>>();
        if !newly_executed {
            return if direct.is_empty() {
                Ok(Vec::new())
            } else {
                Err(ReplayError::InvalidRecord)
            };
        }
        let result = step.result.clone().ok_or(ReplayError::InvalidRecord)?;
        let record = InvocationOutcomeRecord::from_runtime_states(
            self.genesis,
            scope,
            anchor,
            input,
            before,
            &step.state,
            result,
        )
        .map_err(|_| ReplayError::InvalidRecord)?;
        let expected = ReplaySealedOutcome {
            record,
            input: input.clone(),
        };
        if direct.as_slice() != [expected.clone()] {
            return Err(ReplayError::InvalidRecord);
        }
        Ok(vec![expected])
    }

    fn finalize_merge_outcomes(
        &mut self,
        finalizing_entry: OrderedEntryId,
        seal: MergeSealId,
        facts: &BTreeMap<MergeEventId, MergeExecutionFact>,
    ) -> Result<
        (
            InvocationIndexDelta,
            Vec<ReplaySealedOutcome>,
            Vec<ReplayExecutionResult>,
        ),
        ReplayValidationError,
    > {
        if finalizing_entry == OrderedEntryId::ZERO || seal == MergeSealId::ZERO {
            return Err(ReplayError::InvalidFence);
        }

        // Build the complete final net mutation before persisting anything.
        // The BTreeMap order is the canonical ownership-key batch order and
        // also the order in which newly public results are returned.
        let mut transitions = BTreeMap::new();
        let mut outcome_candidates = BTreeMap::new();
        let mut executions = BTreeMap::new();
        for (event_id, fact) in facts {
            if fact.event.validate().is_err() || fact.event.id() != *event_id {
                return Err(ReplayError::InvalidRecord);
            }
            let Some((invocation, request, operation)) = invocation_identity(&fact.event.input)
            else {
                continue;
            };
            let key = InvocationOwnershipKey {
                scope: InvocationOwnershipScope::Merge,
                invocation,
            };
            let lookup = self
                .ownership
                .lookup(key)
                .map_err(ReplayError::InvocationOwnership)?;
            let mut owner = match lookup {
                Some(InvocationIndexLookup::Live(owner)) => owner,
                Some(InvocationIndexLookup::Archived(archived)) => {
                    validate_archived_for_input(archived, self.genesis, key, &fact.event.input)
                        .map_err(ReplayError::InvocationOwnership)?;
                    continue;
                }
                None => {
                    return Err(ReplayError::InvocationOwnership(
                        InvocationOwnershipError::Unauthenticated,
                    ));
                }
            };
            validate_owner_for_input(owner, key, &fact.event.input)
                .map_err(ReplayError::InvocationOwnership)?;
            if owner.request_commitment != request {
                continue;
            }

            match (operation, owner.result_state) {
                (
                    InvocationOwnershipOperation::Invoke,
                    InvocationResultState::PendingMerge { source_event },
                ) if source_event == *event_id && owner.first_input == fact.event.input.id() => {
                    let result = fact.result.clone().ok_or(ReplayError::InvalidRecord)?;
                    let record = InvocationOutcomeRecord::from_runtime_states(
                        self.genesis,
                        InvocationOwnershipScope::Merge,
                        InvocationOutcomeAnchor::Merge {
                            source_event: *event_id,
                            finalizing_entry,
                            seal,
                        },
                        &fact.event.input,
                        &fact.before,
                        &fact.after,
                        result.clone(),
                    )
                    .map_err(|_| ReplayError::InvalidRecord)?;
                    record
                        .validate_for_genesis(self.genesis, &fact.event.input)
                        .map_err(|_| ReplayError::InvalidRecord)?;
                    let reference = InvocationOutcomeRef::for_record(&record)
                        .map_err(|_| ReplayError::InvalidRecord)?;
                    owner.result_state = InvocationResultState::Retained {
                        disposition: record.disposition(),
                        outcome: reference,
                    };
                    owner.validate().map_err(|_| ReplayError::InvalidRecord)?;
                    if transitions
                        .insert(
                            key,
                            InvocationIndexBatchOperation::PutLive { key, value: owner },
                        )
                        .is_some()
                        || outcome_candidates.insert(key, record.clone()).is_some()
                        || executions
                            .insert(
                                key,
                                ReplayExecutionResult {
                                    outcome: ReplayStepOutcome::Applied(replay_disposition(
                                        record.disposition(),
                                    )),
                                    result: Some(result),
                                    products: ReplayProducts::default(),
                                    input: fact.event.input.id(),
                                    position: ReplayPosition::Merge {
                                        id: *event_id,
                                        causal_height: fact.event.causal_height,
                                        ordered_base: fact.event.ordered_base,
                                    },
                                },
                            )
                            .is_some()
                    {
                        return Err(ReplayError::InvalidRecord);
                    }
                }
                (
                    InvocationOwnershipOperation::Acknowledge,
                    InvocationResultState::PendingMergeAcknowledgement {
                        acknowledgement_event,
                        ..
                    },
                ) if acknowledgement_event == *event_id => {
                    let outcome = self
                        .ownership
                        .outcome(key)
                        .map_err(ReplayError::InvocationOwnership)?
                        .ok_or(ReplayError::InvocationOwnership(
                            InvocationOwnershipError::Unauthenticated,
                        ))?;
                    validate_retained_outcome(
                        &outcome,
                        self.genesis,
                        key,
                        owner,
                        &fact.event.input,
                    )
                    .map_err(ReplayError::InvocationOwnership)?;
                    if transitions
                        .insert(
                            key,
                            InvocationIndexBatchOperation::Archive {
                                key,
                                expected: owner,
                            },
                        )
                        .is_some()
                    {
                        return Err(ReplayError::InvalidRecord);
                    }
                }
                // An alias event or already-finalized owner contributes no
                // second transition. Exact source/ack inclusion is enforced
                // below by requiring that no authenticated unfinalized owner
                // remains after this batch.
                _ => {}
            }
        }

        let mut sealed_outcomes = Vec::with_capacity(outcome_candidates.len());
        for (key, record) in &outcome_candidates {
            let reference = self
                .ownership
                .persist_outcome(record)
                .map_err(ReplayError::InvocationOwnership)?;
            if transitions.get(key).and_then(|operation| match operation {
                InvocationIndexBatchOperation::PutLive { value, .. } => value.outcome(),
                InvocationIndexBatchOperation::Archive { .. } => None,
            }) != Some(reference)
            {
                return Err(ReplayError::InvocationOwnership(
                    InvocationOwnershipError::Unauthenticated,
                ));
            }
            let fact = facts
                .get(&match record.anchor {
                    InvocationOutcomeAnchor::Merge { source_event, .. } => source_event,
                    InvocationOutcomeAnchor::Ordered { .. }
                    | InvocationOutcomeAnchor::Local { .. } => {
                        return Err(ReplayError::InvalidRecord);
                    }
                })
                .ok_or(ReplayError::InvalidRecord)?;
            sealed_outcomes.push(ReplaySealedOutcome {
                record: record.clone(),
                input: fact.event.input.clone(),
            });
        }
        let batch = transitions.into_values().collect::<Vec<_>>();
        if !batch.is_empty() {
            self.ownership
                .mutate_batch(InvocationOwnershipScope::Merge, &batch)
                .map_err(ReplayError::InvocationOwnership)?;
            for operation in &batch {
                let expected = match *operation {
                    InvocationIndexBatchOperation::PutLive { value, .. } => {
                        InvocationIndexLookup::Live(value)
                    }
                    InvocationIndexBatchOperation::Archive { key, expected } => {
                        InvocationIndexLookup::Archived(
                            InvocationAcknowledgedFact::from_owner(self.genesis, key, expected)
                                .map_err(|_| ReplayError::InvalidRecord)?,
                        )
                    }
                };
                if self
                    .ownership
                    .lookup(operation.key())
                    .map_err(ReplayError::InvocationOwnership)?
                    != Some(expected)
                {
                    return Err(ReplayError::InvocationOwnership(
                        InvocationOwnershipError::Unauthenticated,
                    ));
                }
            }
        }
        if self
            .ownership
            .unfinalized(InvocationOwnershipScope::Merge)
            .map_err(ReplayError::InvocationOwnership)?
            != 0
        {
            return Err(ReplayError::InvocationOwnership(
                InvocationOwnershipError::Unauthenticated,
            ));
        }
        Ok((
            if batch.is_empty() {
                InvocationIndexDelta::NONE
            } else {
                InvocationIndexDelta::NONE.with(InvocationOwnershipScope::Merge)
            },
            sealed_outcomes,
            executions.into_values().collect(),
        ))
    }

    /// Mint the only authority accepted by storage for an ordered CAS.
    fn seal_ordered_publication(
        &self,
        current: &JournalHeads,
        entry: &OrderedEntry,
        next: JournalHeads,
        step: &ReplayStep,
        materialization: &ReplayMaterialization,
    ) -> Result<ReplaySealedPublication, ReplayValidationError> {
        validate_publication_envelope(self.genesis, current, &next)?;
        validate_system_authority_side_product(&entry.input, step)?;
        let id = entry.id();
        let position_matches = matches!(
            step.position,
            ReplayPosition::Ordered {
                id: position_id,
                index,
                merge_frontier,
                merge_seal,
            } if position_id == id
                && index == entry.index
                && merge_frontier == entry.merge_frontier
                && merge_seal == entry.merge_seal
        );
        let parent_base = OrderedBase {
            index: current.ordered_index,
            head: current.ordered_head,
        };
        if entry.validate().is_err()
            || entry.genesis != current.genesis
            || entry.parent != current.ordered_head
            || entry.index
                != current
                    .ordered_index
                    .checked_add(1)
                    .ok_or(ReplayError::ReplayLimit)?
            || entry.merge_frontier != current.merge_frontier
            || entry.input.id() != step.input
            || !position_matches
            || self.runtime_at(parent_base) != Some(&entry.input.runtime)
            || next.ordered_head != Some(id)
            || next.ordered_index != entry.index
            || next.runtime != step.runtime
            || next.merge_frontier != current.merge_frontier
            || next.local_head != current.local_head
            || next.local_revision != current.local_revision
            || next.checkpoint != current.checkpoint
        {
            return Err(ReplayError::InvalidRecord);
        }
        if let Some(seal) = entry.merge_seal {
            let fence = self.fence.as_ref().ok_or(ReplayError::InvalidFence)?;
            if fence.ordered_index != entry.index
                || fence.ordered_head != id
                || fence.frontier != entry.merge_frontier
                || fence.seal != seal
                || next.merge_fence
                    != (OrderedBase {
                        index: entry.index,
                        head: Some(id),
                    })
                || next.merge_seal != Some(seal)
            {
                return Err(ReplayError::InvalidFence);
            }
        } else if next.merge_fence != current.merge_fence || next.merge_seal != current.merge_seal {
            return Err(ReplayError::InvalidFence);
        }
        self.validate_publication_indexes(current, &next, step.ownership_delta)?;
        let mut outcomes = self.validate_direct_outcomes(
            &entry.input,
            &materialization.state,
            step,
            InvocationOwnershipScope::Ordered,
            InvocationOutcomeAnchor::Ordered { entry: id },
        )?;
        for outcome in &step.sealed_outcomes {
            if outcome.record.key.scope == InvocationOwnershipScope::Ordered {
                continue;
            }
            let Some(seal) = entry.merge_seal else {
                return Err(ReplayError::InvalidRecord);
            };
            let InvocationOutcomeAnchor::Merge {
                source_event,
                finalizing_entry,
                seal: outcome_seal,
            } = outcome.record.anchor
            else {
                return Err(ReplayError::InvalidRecord);
            };
            let key = outcome.record.key;
            let owner = match self
                .ownership
                .lookup(key)
                .map_err(ReplayError::InvocationOwnership)?
            {
                Some(InvocationIndexLookup::Live(owner)) => owner,
                Some(InvocationIndexLookup::Archived(_)) | None => {
                    return Err(ReplayError::InvocationOwnership(
                        InvocationOwnershipError::Unauthenticated,
                    ));
                }
            };
            if key.scope != InvocationOwnershipScope::Merge
                || source_event == MergeEventId::ZERO
                || finalizing_entry != id
                || outcome_seal != seal
                || outcome
                    .record
                    .validate_for_genesis(self.genesis, &outcome.input)
                    .is_err()
                || owner.outcome() != InvocationOutcomeRef::for_record(&outcome.record).ok()
                || owner.disposition() != Some(outcome.record.disposition())
            {
                return Err(ReplayError::InvalidRecord);
            }
            outcomes.push(outcome.clone());
        }
        let fence_ancestry = successor_fence_ancestry(materialization, &next, false, Some(entry))?;
        Ok(ReplaySealedPublication {
            expected: current.id(),
            next,
            anchor: ReplayPublicationAnchor::Ordered(entry.clone()),
            outcomes,
            history_plans: self
                .ownership
                .history_write_plans()
                .map_err(ReplayError::InvocationOwnership)?,
            checkpoint: None,
            shared_merge_projection: None,
            shared_ordered_commit: None,
            system_authority_write: step.system_authority_write.clone(),
            fence_ancestry,
            mode: ReplayPublicationMode::Canonical,
        })
    }

    /// Mint the storage authority for a Raft-committed Shared Ordered splice.
    /// `execution_before` is the authenticated Control/Linear + pinned
    /// Merge(F) projection used by the executor; `materialization` remains the
    /// physical replica image whose active Merge and Local lanes are spliced
    /// into the successor.
    fn seal_shared_ordered_publication(
        &self,
        current: &JournalHeads,
        entry: &OrderedEntry,
        next: JournalHeads,
        step: &ReplayStep,
        execution_before: &RuntimeState,
        materialization: &ReplayMaterialization,
        pinned_merge_manifest: &LaneStateManifest,
        pinned_merge_state: &[u8],
        journal_store: JournalStoreInstanceId,
        claim: &OrderedCommitClaim,
        raft_payload_commitment: Hash,
        mode: ReplayPublicationMode,
    ) -> Result<ReplaySealedPublication, ReplayValidationError> {
        validate_publication_envelope(self.genesis, current, &next)?;
        validate_system_authority_side_product(&entry.input, step)?;
        let id = entry.id();
        let installing_fence = mode == ReplayPublicationMode::SharedOrderedInstallFence;
        if !matches!(
            mode,
            ReplayPublicationMode::SharedOrderedPreserveMerge
                | ReplayPublicationMode::SharedOrderedInstallFence
        ) {
            return Err(ReplayError::InvalidRecord);
        }
        if pinned_merge_manifest.genesis != current.genesis
            || pinned_merge_manifest.runtime != entry.input.runtime
            || pinned_merge_manifest.lane != PersistedLane::Merge
            || pinned_merge_manifest.cursor
                != (LaneCursor::Merge {
                    frontier: entry.merge_frontier,
                })
            || pinned_merge_manifest.state != BlobRef::of_bytes(pinned_merge_state)
            || claim.validate().is_err()
            || claim.ordered()
                != (OrderedBase {
                    index: entry.index,
                    head: Some(id),
                })
            || claim.merge_frontier() != entry.merge_frontier
            || claim.runtime() != &next.runtime
            || claim.ordered_invocations() != next.ordered_invocations
            || claim.merge_fence() != next.merge_fence
            || raft_payload_commitment == Hash::ZERO
        {
            return Err(ReplayError::InvalidRecord);
        }
        let position_matches = matches!(
            step.position,
            ReplayPosition::Ordered {
                id: position_id,
                index,
                merge_frontier,
                merge_seal,
            } if position_id == id
                && index == entry.index
                && merge_frontier == entry.merge_frontier
                && merge_seal == entry.merge_seal
        );
        let parent_base = OrderedBase {
            index: current.ordered_index,
            head: current.ordered_head,
        };
        if entry.validate().is_err()
            || entry.genesis != current.genesis
            || entry.parent != current.ordered_head
            || entry.index
                != current
                    .ordered_index
                    .checked_add(1)
                    .ok_or(ReplayError::ReplayLimit)?
            || entry.input.id() != step.input
            || !position_matches
            || self.runtime_at(parent_base) != Some(&entry.input.runtime)
            || next.ordered_head != Some(id)
            || next.ordered_index != entry.index
            || next.runtime != step.runtime
            || next.local_head != current.local_head
            || next.local_revision != current.local_revision
            || next.local_invocations != current.local_invocations
            || next.checkpoint != current.checkpoint
            || (installing_fence != entry.merge_seal.is_some())
        {
            return Err(ReplayError::InvalidRecord);
        }
        if installing_fence {
            let seal = entry.merge_seal.ok_or(ReplayError::InvalidFence)?;
            let fence = self.fence.as_ref().ok_or(ReplayError::InvalidFence)?;
            if fence.ordered_index != entry.index
                || fence.ordered_head != id
                || fence.frontier != entry.merge_frontier
                || fence.seal != seal
                || next.merge_frontier != entry.merge_frontier
                || next.merge_fence
                    != (OrderedBase {
                        index: entry.index,
                        head: Some(id),
                    })
                || next.merge_seal != Some(seal)
            {
                return Err(ReplayError::InvalidFence);
            }
        } else if next.merge_frontier != current.merge_frontier
            || next.merge_invocations != current.merge_invocations
            || next.merge_fence != current.merge_fence
            || next.merge_seal != current.merge_seal
        {
            return Err(ReplayError::InvalidFence);
        }

        let staged_ordered = self
            .ownership
            .index_id(InvocationOwnershipScope::Ordered)
            .map_err(ReplayError::InvocationOwnership)?;
        let ordered_changed = step
            .ownership_delta
            .changed(InvocationOwnershipScope::Ordered);
        if (ordered_changed
            && (staged_ordered == current.ordered_invocations
                || next.ordered_invocations != staged_ordered))
            || (!ordered_changed
                && (staged_ordered != current.ordered_invocations
                    || next.ordered_invocations != current.ordered_invocations))
        {
            return Err(ReplayError::InvocationOwnership(
                InvocationOwnershipError::Conflict,
            ));
        }
        let staged_local = self
            .ownership
            .index_id(InvocationOwnershipScope::Local(current.node))
            .map_err(ReplayError::InvocationOwnership)?;
        if step
            .ownership_delta
            .changed(InvocationOwnershipScope::Local(current.node))
            || staged_local != current.local_invocations
            || next.local_invocations != current.local_invocations
        {
            return Err(ReplayError::InvocationOwnership(
                InvocationOwnershipError::Conflict,
            ));
        }
        if installing_fence {
            let staged_merge = self
                .ownership
                .index_id(InvocationOwnershipScope::Merge)
                .map_err(ReplayError::InvocationOwnership)?;
            if next.merge_invocations != staged_merge {
                return Err(ReplayError::InvocationOwnership(
                    InvocationOwnershipError::Conflict,
                ));
            }
        }

        let mut outcomes = self.validate_direct_outcomes(
            &entry.input,
            execution_before,
            step,
            InvocationOwnershipScope::Ordered,
            InvocationOutcomeAnchor::Ordered { entry: id },
        )?;
        for outcome in &step.sealed_outcomes {
            if outcome.record.key.scope == InvocationOwnershipScope::Ordered {
                continue;
            }
            let seal = entry.merge_seal.ok_or(ReplayError::InvalidRecord)?;
            let InvocationOutcomeAnchor::Merge {
                source_event,
                finalizing_entry,
                seal: outcome_seal,
            } = outcome.record.anchor
            else {
                return Err(ReplayError::InvalidRecord);
            };
            let key = outcome.record.key;
            let owner = match self
                .ownership
                .lookup(key)
                .map_err(ReplayError::InvocationOwnership)?
            {
                Some(InvocationIndexLookup::Live(owner)) => owner,
                Some(InvocationIndexLookup::Archived(_)) | None => {
                    return Err(ReplayError::InvocationOwnership(
                        InvocationOwnershipError::Unauthenticated,
                    ));
                }
            };
            if !installing_fence
                || key.scope != InvocationOwnershipScope::Merge
                || source_event == MergeEventId::ZERO
                || finalizing_entry != id
                || outcome_seal != seal
                || outcome
                    .record
                    .validate_for_genesis(self.genesis, &outcome.input)
                    .is_err()
                || owner.outcome() != InvocationOutcomeRef::for_record(&outcome.record).ok()
                || owner.disposition() != Some(outcome.record.disposition())
            {
                return Err(ReplayError::InvalidRecord);
            }
            outcomes.push(outcome.clone());
        }
        let history_plans = self
            .ownership
            .history_write_plans()
            .map_err(ReplayError::InvocationOwnership)?;
        if !installing_fence
            && history_plans
                .iter()
                .any(|plan| plan.scope() != InvocationOwnershipScope::Ordered)
        {
            return Err(ReplayError::InvocationOwnership(
                InvocationOwnershipError::Conflict,
            ));
        }
        let fence_ancestry = successor_fence_ancestry(materialization, &next, false, Some(entry))?;
        Ok(ReplaySealedPublication {
            expected: current.id(),
            next,
            anchor: ReplayPublicationAnchor::Ordered(entry.clone()),
            outcomes,
            history_plans,
            checkpoint: None,
            shared_merge_projection: Some(ReplaySealedSharedMergeProjection {
                manifest: pinned_merge_manifest.clone(),
                state: pinned_merge_state.to_vec(),
            }),
            shared_ordered_commit: Some(ReplaySealedSharedOrderedCommit {
                journal_store,
                claim: claim.clone(),
                raft_payload_commitment,
            }),
            system_authority_write: step.system_authority_write.clone(),
            fence_ancestry,
            mode,
        })
    }

    /// Mint the only authority accepted by storage for a node-local CAS.
    fn seal_local_publication(
        &self,
        current: &JournalHeads,
        entry: &LocalEntry,
        next: JournalHeads,
        step: &ReplayStep,
        materialization: &ReplayMaterialization,
    ) -> Result<ReplaySealedPublication, ReplayValidationError> {
        validate_publication_envelope(self.genesis, current, &next)?;
        validate_system_authority_side_product(&entry.input, step)?;
        let id = entry.id();
        let ordered_base = OrderedBase {
            index: current.ordered_index,
            head: current.ordered_head,
        };
        let position_matches = matches!(
            step.position,
            ReplayPosition::Local {
                id: position_id,
                node,
                revision,
                ordered_base: position_base,
                merge_frontier,
            } if position_id == id
                && node == entry.node
                && revision == entry.revision
                && position_base == entry.ordered_base
                && merge_frontier == entry.merge_frontier
        );
        if entry.validate().is_err()
            || entry.genesis != current.genesis
            || entry.node != current.node
            || entry.parent != current.local_head
            || entry.revision
                != current
                    .local_revision
                    .checked_add(1)
                    .ok_or(ReplayError::ReplayLimit)?
            || entry.ordered_base != ordered_base
            || entry.merge_frontier != current.merge_frontier
            || entry.input.id() != step.input
            || !position_matches
            || step.runtime != current.runtime
            || next.runtime != current.runtime
            || next.local_head != Some(id)
            || next.local_revision != entry.revision
            || next.ordered_head != current.ordered_head
            || next.ordered_index != current.ordered_index
            || next.merge_frontier != current.merge_frontier
            || next.merge_fence != current.merge_fence
            || next.merge_seal != current.merge_seal
            || next.checkpoint != current.checkpoint
        {
            return Err(ReplayError::InvalidRecord);
        }
        self.validate_publication_indexes(current, &next, step.ownership_delta)?;
        let outcomes = self.validate_direct_outcomes(
            &entry.input,
            &materialization.state,
            step,
            InvocationOwnershipScope::Local(entry.node),
            InvocationOutcomeAnchor::Local { entry: id },
        )?;
        if outcomes.len() != step.sealed_outcomes.len() {
            return Err(ReplayError::InvalidRecord);
        }
        let fence_ancestry = successor_fence_ancestry(materialization, &next, false, None)?;
        Ok(ReplaySealedPublication {
            expected: current.id(),
            next,
            anchor: ReplayPublicationAnchor::Local(entry.clone()),
            outcomes,
            history_plans: self
                .ownership
                .history_write_plans()
                .map_err(ReplayError::InvocationOwnership)?,
            checkpoint: None,
            shared_merge_projection: None,
            shared_ordered_commit: None,
            system_authority_write: None,
            fence_ancestry,
            mode: ReplayPublicationMode::Canonical,
        })
    }

    /// Mint the only authority accepted by storage for one canonical Merge
    /// import. `replay` must start at the current frontier, so the token also
    /// binds every newly loaded parent in the bounded suffix.
    fn seal_merge_publication(
        &self,
        current: &JournalHeads,
        event: &MergeEvent,
        replay: &MergeReplay,
        next: JournalHeads,
        step: &ReplayStep,
        materialization: &ReplayMaterialization,
    ) -> Result<ReplaySealedPublication, ReplayValidationError> {
        validate_publication_envelope(self.genesis, current, &next)?;
        validate_system_authority_side_product(&event.input, step)?;
        let id = event.id();
        let position_matches = matches!(
            step.position,
            ReplayPosition::Merge {
                id: position_id,
                causal_height,
                ordered_base,
            } if position_id == id
                && causal_height == event.causal_height
                && ordered_base == event.ordered_base
        );
        if event.validate().is_err()
            || event.genesis != current.genesis
            || event.input.id() != step.input
            || !position_matches
            || !step.merge_authenticated
            || replay.genesis != current.genesis
            || replay.checkpoint_frontier != current.merge_frontier
            || replay.frontier_id == current.merge_frontier
            || replay.frontier_id != next.merge_frontier
            || !replay.events.iter().any(|(event_id, _)| *event_id == id)
            || next.runtime != current.runtime
            || next.ordered_head != current.ordered_head
            || next.ordered_index != current.ordered_index
            || next.merge_fence != current.merge_fence
            || next.merge_seal != current.merge_seal
            || next.local_head != current.local_head
            || next.local_revision != current.local_revision
            || next.checkpoint != current.checkpoint
        {
            return Err(ReplayError::InvalidRecord);
        }
        if !step.sealed_outcomes.is_empty() {
            return Err(ReplayError::InvalidRecord);
        }
        self.validate_publication_indexes(current, &next, step.ownership_delta)?;
        let fence_ancestry = successor_fence_ancestry(materialization, &next, false, None)?;
        Ok(ReplaySealedPublication {
            expected: current.id(),
            next,
            anchor: ReplayPublicationAnchor::Merge {
                event: event.clone(),
                frontier: replay.frontier.clone(),
            },
            outcomes: Vec::new(),
            history_plans: self
                .ownership
                .history_write_plans()
                .map_err(ReplayError::InvocationOwnership)?,
            checkpoint: None,
            shared_merge_projection: None,
            shared_ordered_commit: None,
            system_authority_write: None,
            fence_ancestry,
            mode: ReplayPublicationMode::Canonical,
        })
    }

    fn validate_publication_indexes(
        &self,
        current: &JournalHeads,
        next: &JournalHeads,
        delta: InvocationIndexDelta,
    ) -> Result<(), ReplayValidationError> {
        for scope in [
            InvocationOwnershipScope::Ordered,
            InvocationOwnershipScope::Merge,
            InvocationOwnershipScope::Local(current.node),
        ] {
            let staged = self
                .ownership
                .index_id(scope)
                .map_err(ReplayError::InvocationOwnership)?;
            let changed = delta.changed(scope);
            let old = invocation_index_at(current, scope).ok_or(ReplayError::ScopeMismatch)?;
            let new = invocation_index_at(next, scope).ok_or(ReplayError::ScopeMismatch)?;
            if (changed && (staged == old || new != staged))
                || (!changed && (staged != old || new != old))
            {
                return Err(ReplayError::InvocationOwnership(
                    InvocationOwnershipError::Conflict,
                ));
            }
        }
        Ok(())
    }
}

fn validate_publication_envelope(
    genesis: AgentJournalGenesisId,
    current: &JournalHeads,
    next: &JournalHeads,
) -> Result<(), ReplayValidationError> {
    if current.genesis != genesis
        || current.validate().is_err()
        || current.validate_successor(next).is_err()
    {
        return Err(ReplayError::InvalidRecord);
    }
    Ok(())
}

fn successor_fence_ancestry(
    materialization: &ReplayMaterialization,
    next: &JournalHeads,
    checkpoint_reset: bool,
    ordered_entry: Option<&OrderedEntry>,
) -> Result<FenceAncestryEvidence, ReplayValidationError> {
    let current_base = materialization.ordered_base();
    if !materialization.fence_ancestry.validate()
        || materialization.fence_ancestry.genesis() != materialization.heads.genesis
        || materialization.fence_ancestry.checkpoint_base() != materialization.replay_boundary
        || materialization.fence_ancestry.canonical_head() != current_base
        || materialization.fence_ancestry.fence() != materialization.heads.merge_fence
        || next.genesis != materialization.heads.genesis
    {
        return Err(ReplayError::InvalidFence);
    }
    let canonical_head = OrderedBase {
        index: next.ordered_index,
        head: next.ordered_head,
    };
    if checkpoint_reset {
        if ordered_entry.is_some()
            || canonical_head != current_base
            || next.merge_fence != materialization.heads.merge_fence
        {
            return Err(ReplayError::InvalidFence);
        }
        materialization.fence_ancestry.checkpointed()
    } else if let Some(entry) = ordered_entry {
        materialization
            .fence_ancestry
            .advance_ordered(entry, next.merge_fence)
    } else if canonical_head == current_base
        && next.merge_fence == materialization.heads.merge_fence
    {
        Ok(materialization.fence_ancestry.clone())
    } else {
        Err(ReplayError::InvalidFence)
    }
}

fn invocation_index_at(
    heads: &JournalHeads,
    scope: InvocationOwnershipScope,
) -> Option<InvocationIndexId> {
    match scope {
        InvocationOwnershipScope::Ordered => Some(heads.ordered_invocations),
        InvocationOwnershipScope::Merge => Some(heads.merge_invocations),
        InvocationOwnershipScope::Local(node) if node == heads.node => {
            Some(heads.local_invocations)
        }
        InvocationOwnershipScope::Local(_) => None,
    }
}

fn derive_standard_artifact_closure<SourceError>(
    genesis: AgentJournalGenesisId,
    runtime: &RuntimeBinding,
    state: &RuntimeState,
) -> Result<ArtifactClosure, ReplayError<SourceError, core::convert::Infallible>> {
    let artifacts = derive_standard_artifact_references(runtime, state)?;
    let closure = ArtifactClosure { genesis, artifacts };
    if closure.validate().is_err() {
        return Err(ReplayError::InvalidRecord);
    }
    Ok(closure)
}

fn derive_standard_artifact_references<SourceError>(
    runtime: &RuntimeBinding,
    state: &RuntimeState,
) -> Result<Vec<BlobRef>, ReplayError<SourceError, core::convert::Infallible>> {
    validate_runtime_state_bound(state)?;
    let decoded = decode_standard_runtime_state(state).map_err(|_| ReplayError::InvalidRecord)?;
    let config = decoded.config.as_ref().ok_or(ReplayError::InvalidRecord)?;
    if config.identity.space != runtime.space
        || config.identity.agent != runtime.agent
        || config.identity.runtime_deployment != runtime.deployment
        || config.identity.runtime_program != runtime.program
        || config.identity.runtime_producer != runtime.producer
        || config.runtime_package != runtime.package
    {
        return Err(ReplayError::RuntimeMismatch);
    }
    let mut artifacts = vec![runtime.package.clone(), config.runtime_package.clone()];
    for actor in &decoded.actors {
        artifacts.push(actor.record.package.clone());
        artifacts.push(actor.record.agent_schema.clone());
        artifacts.push(actor.record.role_policies.clone());
        if let Some(installation_data) = &actor.record.installation_data {
            artifacts.push(installation_data.clone());
        }
    }
    artifacts.sort_unstable_by_key(|artifact| (artifact.hash, artifact.len));
    artifacts.dedup_by_key(|artifact| (artifact.hash, artifact.len));
    if system_genesis_artifact_closure_commitment(&artifacts).is_err() {
        return Err(ReplayError::InvalidRecord);
    }
    Ok(artifacts)
}

trait ScopedJournalRecord: CanonicalJournalRecord {
    fn genesis(&self) -> AgentJournalGenesisId;
}

impl ScopedJournalRecord for OrderedEntry {
    fn genesis(&self) -> AgentJournalGenesisId {
        self.genesis
    }
}

impl ScopedJournalRecord for LocalEntry {
    fn genesis(&self) -> AgentJournalGenesisId {
        self.genesis
    }
}

impl ScopedJournalRecord for MergeEvent {
    fn genesis(&self) -> AgentJournalGenesisId {
        self.genesis
    }
}

fn validate_loaded_record<R, SourceError, ExecutorError>(
    record: &R,
    expected_id: R::Id,
    genesis: AgentJournalGenesisId,
    encoded_bytes: &mut usize,
) -> Result<(), ReplayError<SourceError, ExecutorError>>
where
    R: ScopedJournalRecord,
{
    if record.validate().is_err() || record.id() != expected_id || record.genesis() != genesis {
        return Err(ReplayError::InvalidRecord);
    }
    *encoded_bytes = encoded_bytes
        .checked_add(record.encode().len())
        .ok_or(ReplayError::ReplayLimit)?;
    enforce_byte_count(*encoded_bytes)
}

fn enforce_entry_count<SourceError, ExecutorError>(
    count: usize,
) -> Result<(), ReplayError<SourceError, ExecutorError>> {
    if count > MAX_REPLAY_SUFFIX_ENTRIES {
        Err(ReplayError::ReplayLimit)
    } else {
        Ok(())
    }
}

fn enforce_byte_count<SourceError, ExecutorError>(
    bytes: usize,
) -> Result<(), ReplayError<SourceError, ExecutorError>> {
    if bytes > MAX_REPLAY_SUFFIX_BYTES {
        Err(ReplayError::ReplayLimit)
    } else {
        Ok(())
    }
}

fn validate_position<SourceError, ExecutorError>(
    input: &ReplayInput,
    position: ReplayPosition,
) -> Result<(), ReplayError<SourceError, ExecutorError>> {
    let valid = match position {
        ReplayPosition::Genesis => matches!(
            input.operation,
            ReplayOperation::Management {
                request: LifecycleRequest::Authorized { ref request, .. }
            } if matches!(request.as_ref(), LifecycleRequest::Create(_))
        ),
        ReplayPosition::Ordered { merge_seal, .. } => {
            matches!(
                input.persisted_lane(),
                PersistedLane::Control | PersistedLane::Linear
            ) && (matches!(
                input.operation,
                ReplayOperation::Management { .. } | ReplayOperation::SealMerge
            ) == merge_seal.is_some())
        }
        ReplayPosition::Merge { .. } => input.persisted_lane() == PersistedLane::Merge,
        ReplayPosition::Local { .. } => input.persisted_lane() == PersistedLane::Local,
    };
    if valid {
        Ok(())
    } else {
        Err(ReplayError::InvalidPosition)
    }
}

fn validate_system_authority_side_product<SourceError, ExecutorError>(
    input: &ReplayInput,
    step: &ReplayStep,
) -> Result<(), ReplayError<SourceError, ExecutorError>> {
    let direct_request = match &input.operation {
        ReplayOperation::Management { request }
            if matches!(
                request,
                LifecycleRequest::FinalizeSystemAuthority(_)
                    | LifecycleRequest::RotateSystemAuthority(_)
                    | LifecycleRequest::FinalizeCatalog(_)
            ) =>
        {
            Some(request)
        }
        _ => None,
    };
    match (direct_request, step.system_authority_write.as_ref()) {
        (Some(request), Some(write))
            if step.outcome == ReplayStepOutcome::Applied(ReplayDisposition::Applied)
                && write.operation() == request.commitment() =>
        {
            Ok(())
        }
        (None, None) => Ok(()),
        _ => Err(ReplayError::InvalidManagementTransition),
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum InvocationOwnershipOperation {
    Invoke,
    Acknowledge,
}

fn invocation_identity(
    input: &ReplayInput,
) -> Option<(InvocationId, Hash, InvocationOwnershipOperation)> {
    match &input.operation {
        ReplayOperation::Invoke { invocation, .. } => Some((
            invocation.invocation,
            invocation.commitment(),
            InvocationOwnershipOperation::Invoke,
        )),
        ReplayOperation::Acknowledge { invocation, .. } => Some((
            invocation.invocation,
            invocation.commitment(),
            InvocationOwnershipOperation::Acknowledge,
        )),
        ReplayOperation::Management { .. }
        | ReplayOperation::CleanInvoke { .. }
        | ReplayOperation::SealMerge => None,
    }
}

fn invocation_ownership_key(
    position: ReplayPosition,
    invocation: InvocationId,
) -> InvocationOwnershipKey {
    let scope = match position {
        ReplayPosition::Genesis | ReplayPosition::Ordered { .. } => {
            InvocationOwnershipScope::Ordered
        }
        ReplayPosition::Merge { .. } => InvocationOwnershipScope::Merge,
        ReplayPosition::Local { node, .. } => InvocationOwnershipScope::Local(node),
    };
    InvocationOwnershipKey { scope, invocation }
}

fn validate_owner_for_input(
    owner: InvocationOwnershipValue,
    key: InvocationOwnershipKey,
    input: &ReplayInput,
) -> Result<(), InvocationOwnershipError> {
    let Some((invocation, _, _)) = invocation_identity(input) else {
        return Err(InvocationOwnershipError::Unauthenticated);
    };
    let expected_node = match key.scope {
        InvocationOwnershipScope::Local(node) => Some(node),
        InvocationOwnershipScope::Ordered | InvocationOwnershipScope::Merge => None,
    };
    if key.validate().is_err()
        || owner.validate().is_err()
        || owner.scope != key.scope
        || key.invocation != invocation
        || owner.lane != input.persisted_lane()
        || owner.node != expected_node
    {
        return Err(InvocationOwnershipError::Unauthenticated);
    }
    Ok(())
}

fn validate_archived_for_input(
    fact: InvocationAcknowledgedFact,
    genesis: AgentJournalGenesisId,
    key: InvocationOwnershipKey,
    input: &ReplayInput,
) -> Result<(), InvocationOwnershipError> {
    let Some((invocation, _, _)) = invocation_identity(input) else {
        return Err(InvocationOwnershipError::Unauthenticated);
    };
    let expected_node = match key.scope {
        InvocationOwnershipScope::Local(node) => Some(node),
        InvocationOwnershipScope::Ordered | InvocationOwnershipScope::Merge => None,
    };
    if key.validate().is_err()
        || fact.validate().is_err()
        || fact.genesis() != genesis
        || fact.key() != key
        || key.invocation != invocation
        || fact.lane() != input.persisted_lane()
        || fact.node() != expected_node
    {
        return Err(InvocationOwnershipError::Unauthenticated);
    }
    Ok(())
}

fn validate_retained_outcome(
    outcome: &InvocationOutcomeRecord,
    genesis: AgentJournalGenesisId,
    key: InvocationOwnershipKey,
    owner: InvocationOwnershipValue,
    input: &ReplayInput,
) -> Result<(), InvocationOwnershipError> {
    let invocation = match &input.operation {
        ReplayOperation::Invoke { invocation, .. }
        | ReplayOperation::Acknowledge { invocation, .. } => invocation,
        ReplayOperation::Management { .. }
        | ReplayOperation::CleanInvoke { .. }
        | ReplayOperation::SealMerge => {
            return Err(InvocationOwnershipError::Unauthenticated);
        }
    };
    let Some(reference) = owner.outcome() else {
        return Err(InvocationOwnershipError::Unauthenticated);
    };
    if outcome.validate().is_err()
        || outcome.genesis != genesis
        || outcome.key != key
        || outcome.request_commitment != owner.request_commitment
        || outcome.first_input != owner.first_input
        || outcome.lane != owner.lane
        || outcome.node != owner.node
        || outcome.request_commitment != invocation.commitment()
        || !outcome.request.matches_invocation(invocation)
        || outcome.disposition()
            != owner
                .disposition()
                .ok_or(InvocationOwnershipError::Unauthenticated)?
        || !reference.authenticates(outcome)
    {
        return Err(InvocationOwnershipError::Unauthenticated);
    }
    Ok(())
}

const fn invocation_outcome_anchor(position: ReplayPosition) -> Option<InvocationOutcomeAnchor> {
    match position {
        ReplayPosition::Ordered { id, .. } => Some(InvocationOutcomeAnchor::Ordered { entry: id }),
        ReplayPosition::Local { id, .. } => Some(InvocationOutcomeAnchor::Local { entry: id }),
        ReplayPosition::Genesis | ReplayPosition::Merge { .. } => None,
    }
}

fn noop_replay_step(
    input: &ReplayInput,
    before: &RuntimeState,
    runtime: RuntimeBinding,
    position: ReplayPosition,
    outcome: ReplayStepOutcome,
) -> ReplayStep {
    ReplayStep {
        state: before.clone(),
        runtime,
        outcome,
        result: None,
        products: ReplayProducts::default(),
        input: input.id(),
        position,
        ownership_delta: InvocationIndexDelta::NONE,
        sealed_outcomes: Vec::new(),
        system_authority_write: None,
        merge_authenticated: false,
    }
}

/// Rebuild the sole legal successor for an authenticated retained outcome.
///
/// Retained recovery is journal work, not application execution: the exact
/// result is already authenticated by the ownership leaf and outcome object.
/// The only state mutation is the owning physical component's monotone
/// authority-slot high-water. A later runtime capability downgrade must not
/// strand an already-committed terminal/error outcome, so this path is gated
/// by the immutable profile rather than the current package capabilities.
/// Unseen work still enters `ReplayExecutor::execute` and therefore retains
/// the ordinary current-capability preflight. In particular, a Private agent
/// can never acquire or recover a Linear clock because its profile has never
/// supported that component.
fn advance_historical_result_clock(
    state: &mut super::standard::StandardRuntimeState,
    storage: InvocationResultStorage,
    observed_slot: u64,
) -> Result<(), ()> {
    let profile = state.config.as_ref().ok_or(())?.identity.profile;
    let advance = |current: &mut Option<u64>| {
        *current = Some((*current).map_or(observed_slot, |slot| slot.max(observed_slot)));
    };
    match storage {
        InvocationResultStorage::Control => advance(&mut state.control_authority_slot),
        InvocationResultStorage::Lane(lane) => {
            if !profile.supports(lane) {
                return Err(());
            }
            match lane {
                StateLane::Linear => advance(&mut state.lane_revisions.linear_authority_slot),
                StateLane::Merge => advance(&mut state.lane_revisions.merge_authority_slot),
                StateLane::Local => advance(&mut state.lane_revisions.local_authority_slot),
            }
        }
    }
    Ok(())
}

fn retained_exact_transition<SourceError, ExecutorError>(
    input: &ReplayInput,
    before: &RuntimeState,
    runtime: &RuntimeBinding,
    outcome: &InvocationOutcomeRecord,
) -> Result<ReplayTransition, ReplayError<SourceError, ExecutorError>> {
    let ReplayOperation::Invoke {
        invocation,
        observed_slot,
        ..
    } = &input.operation
    else {
        return Err(ReplayError::InvalidPosition);
    };
    let mut state =
        decode_standard_runtime_state(before).map_err(|_| ReplayError::InvalidRecord)?;
    StandardAgentRuntime::restore(state.clone()).map_err(|_| ReplayError::InvalidRecord)?;
    advance_historical_result_clock(&mut state, invocation.mode.result_storage(), *observed_slot)
        .map_err(|_| ReplayError::TerminalMutation)?;
    StandardAgentRuntime::restore(state.clone()).map_err(|_| ReplayError::TerminalMutation)?;
    Ok(ReplayTransition {
        state: encode_standard_runtime_state(&state),
        disposition: replay_disposition(outcome.disposition()),
        result: Some(outcome.result.clone()),
        next_runtime: runtime.clone(),
        products: ReplayProducts::default(),
    })
}

fn validate_transition<SourceError, ExecutorError>(
    input: &ReplayInput,
    before: &RuntimeState,
    transition: &ReplayTransition,
    position: ReplayPosition,
    current_runtime: &RuntimeBinding,
    retained_recovery: bool,
    synthetic_acknowledgement: bool,
    acknowledgement_outcome: Option<&InvocationOutcomeRecord>,
    system_authority_execution: Option<ReplaySystemAuthorityExecution>,
) -> Result<Option<ReplaySystemAuthorityWrite>, ReplayError<SourceError, ExecutorError>> {
    // Runtime side products are not yet content-addressed members of the
    // journal CAS. Accepting them here would make a crash able to lose or
    // duplicate replies/effects even when state replay is exact.
    if !transition.products.is_empty() {
        return Err(ReplayError::ForbiddenMergeProducts);
    }
    match &input.operation {
        ReplayOperation::Invoke { invocation, .. } => {
            let result = transition
                .result
                .as_ref()
                .ok_or(ReplayError::InvalidRecord)?;
            let clock_only = retained_recovery
                || !matches!(
                    result,
                    Ok(reply) if reply.status == ActorExecutionStatus::Done
                );
            let expected_disposition = match result {
                Ok(reply) => {
                    if super::wire::validate_execution_reply(reply).is_err()
                        || reply.invocation != invocation.invocation
                        || reply.actor != invocation.actor
                        || reply.incarnation != invocation.incarnation
                        || reply.deployment != invocation.deployment
                        || reply.mode != invocation.mode
                        || reply.gas_remaining > invocation.gas
                    {
                        return Err(ReplayError::InvalidRecord);
                    }
                    match reply.status {
                        ActorExecutionStatus::Done => ReplayDisposition::Applied,
                        ActorExecutionStatus::Forbidden => ReplayDisposition::Forbidden,
                        ActorExecutionStatus::Panicked => ReplayDisposition::Panicked,
                        ActorExecutionStatus::OutOfGas => ReplayDisposition::OutOfGas,
                        // A yielded slice is not a terminal replay result.
                        // Accept it only through the dedicated portable
                        // Resume/Yielded transition protocol.
                        ActorExecutionStatus::Yielded => {
                            return Err(ReplayError::InvalidRecord);
                        }
                    }
                }
                Err(error) if error.is_durable_exact_outcome() => ReplayDisposition::Rejected,
                Err(_) => return Err(ReplayError::InvalidRecord),
            };
            if transition.disposition != expected_disposition
                || transition.next_runtime != *current_runtime
            {
                return Err(ReplayError::TerminalMutation);
            }
            validate_standard_invocation_successor(
                input,
                before,
                &transition.state,
                result,
                retained_recovery,
                clock_only,
            )?;
            let authority_write = validate_lane_mutation(
                input,
                before,
                &transition.state,
                transition.disposition,
                position,
                None,
            )?;
            if authority_write.is_some() {
                return Err(ReplayError::InvalidRecord);
            }
        }
        ReplayOperation::Acknowledge { .. } => {
            if transition.result.is_some()
                || transition.disposition != ReplayDisposition::Applied
                || transition.next_runtime != *current_runtime
            {
                return Err(ReplayError::TerminalMutation);
            }
            validate_standard_acknowledgement_successor(
                input,
                before,
                &transition.state,
                synthetic_acknowledgement,
                acknowledgement_outcome.ok_or(ReplayError::InvalidRecord)?,
            )?;
            let authority_write = validate_lane_mutation(
                input,
                before,
                &transition.state,
                transition.disposition,
                position,
                None,
            )?;
            if authority_write.is_some() {
                return Err(ReplayError::InvalidRecord);
            }
        }
        ReplayOperation::CleanInvoke { .. } => {
            if transition.result.is_some() || transition.next_runtime != *current_runtime {
                return Err(ReplayError::TerminalMutation);
            }
            let authority_write = validate_lane_mutation(
                input,
                before,
                &transition.state,
                transition.disposition,
                position,
                None,
            )?;
            if authority_write.is_some() {
                return Err(ReplayError::InvalidRecord);
            }
        }
        ReplayOperation::Management { .. } => {
            if transition.result.is_some() {
                return Err(ReplayError::InvalidManagementTransition);
            }
            validate_runtime_successor(input, transition, current_runtime)?;
            return validate_lane_mutation(
                input,
                before,
                &transition.state,
                transition.disposition,
                position,
                system_authority_execution,
            );
        }
        ReplayOperation::SealMerge => {
            if transition.state != *before
                || transition.result.is_some()
                || transition.disposition != ReplayDisposition::Applied
                || transition.next_runtime != *current_runtime
            {
                return Err(ReplayError::TerminalMutation);
            }
        }
    }

    Ok(None)
}

fn validate_standard_invocation_successor<SourceError, ExecutorError>(
    input: &ReplayInput,
    before: &RuntimeState,
    after: &RuntimeState,
    result: &Result<ActorExecutionReply, ActorExecutionError>,
    retained_recovery: bool,
    clock_only: bool,
) -> Result<(), ReplayError<SourceError, ExecutorError>> {
    let ReplayOperation::Invoke {
        invocation,
        observed_slot,
        ..
    } = &input.operation
    else {
        return Err(ReplayError::InvalidPosition);
    };
    let decoded_before =
        decode_standard_runtime_state(before).map_err(|_| ReplayError::InvalidRecord)?;
    let decoded_after =
        decode_standard_runtime_state(after).map_err(|_| ReplayError::InvalidRecord)?;
    let mut runtime = StandardAgentRuntime::restore(decoded_before.clone())
        .map_err(|_| ReplayError::InvalidRecord)?;
    StandardAgentRuntime::restore(decoded_after.clone()).map_err(|_| ReplayError::InvalidRecord)?;
    if !retained_recovery {
        runtime
            .validate_invocation_result_storage(invocation)
            .map_err(|_| ReplayError::InvalidRecord)?;
    }

    let scope = invocation.mode.invocation_scope();
    let before_result = decoded_before
        .invocation_results
        .iter()
        .find(|record| record.scope == scope && record.invocation == invocation.invocation);
    let after_result = decoded_after
        .invocation_results
        .iter()
        .find(|record| record.scope == scope && record.invocation == invocation.invocation);
    let matches_reply = |record: &super::standard::StandardInvocationResult,
                         reply: &ActorExecutionReply| {
        record.scope == scope
            && record.invocation == invocation.invocation
            && record.incarnation == invocation.incarnation
            && record.request == invocation.commitment()
            && record.reply == *reply
            && record.storage == invocation.mode.result_storage()
    };
    match result {
        Ok(reply) if reply.status == ActorExecutionStatus::Done => {
            if (retained_recovery
                && before_result.is_none_or(|record| !matches_reply(record, reply)))
                || (!retained_recovery && before_result.is_some())
                || after_result.is_none_or(|record| !matches_reply(record, reply))
            {
                return Err(ReplayError::TerminalMutation);
            }
        }
        Ok(_) | Err(_) => {
            if before_result.is_some() || after_result.is_some() {
                return Err(ReplayError::TerminalMutation);
            }
        }
    }
    if clock_only {
        let expected = if retained_recovery {
            let mut expected = decoded_before;
            advance_historical_result_clock(
                &mut expected,
                invocation.mode.result_storage(),
                *observed_slot,
            )
            .map_err(|_| ReplayError::TerminalMutation)?;
            StandardAgentRuntime::restore(expected.clone())
                .map_err(|_| ReplayError::TerminalMutation)?;
            expected
        } else {
            runtime
                .commit_exact_outcome_clock(invocation, *observed_slot)
                .map_err(|_| ReplayError::TerminalMutation)?;
            runtime.snapshot()
        };
        if encode_standard_runtime_state(&expected) != *after {
            return Err(ReplayError::TerminalMutation);
        }
    }
    Ok(())
}

fn validate_standard_acknowledgement_successor<SourceError, ExecutorError>(
    input: &ReplayInput,
    before: &RuntimeState,
    after: &RuntimeState,
    synthetic: bool,
    outcome: &InvocationOutcomeRecord,
) -> Result<(), ReplayError<SourceError, ExecutorError>> {
    let ReplayOperation::Acknowledge { invocation, .. } = &input.operation else {
        return Err(ReplayError::InvalidPosition);
    };
    let decoded_before =
        decode_standard_runtime_state(before).map_err(|_| ReplayError::InvalidRecord)?;
    let decoded_after =
        decode_standard_runtime_state(after).map_err(|_| ReplayError::InvalidRecord)?;
    StandardAgentRuntime::restore(decoded_before.clone())
        .map_err(|_| ReplayError::InvalidRecord)?;
    StandardAgentRuntime::restore(decoded_after.clone()).map_err(|_| ReplayError::InvalidRecord)?;
    let scope = invocation.mode.invocation_scope();
    let exact = |record: &super::standard::StandardInvocationResult,
                 reply: &ActorExecutionReply| {
        record.scope == scope
            && record.invocation == invocation.invocation
            && record.incarnation == invocation.incarnation
            && record.request == invocation.commitment()
            && record.reply == *reply
            && record.storage == invocation.mode.result_storage()
    };
    if synthetic {
        if before != after
            || decoded_before
                .invocation_results
                .iter()
                .any(|record| record.scope == scope && record.invocation == invocation.invocation)
        {
            return Err(ReplayError::TerminalMutation);
        }
        return Ok(());
    }
    let Ok(reply) = &outcome.result else {
        return Err(ReplayError::InvalidRecord);
    };
    if reply.status != ActorExecutionStatus::Done {
        return Err(ReplayError::InvalidRecord);
    }
    let Some(before_record) = decoded_before
        .invocation_results
        .iter()
        .find(|record| record.scope == scope && record.invocation == invocation.invocation)
    else {
        return Err(ReplayError::TerminalMutation);
    };
    if !exact(before_record, reply) {
        return Err(ReplayError::TerminalMutation);
    }
    let mut expected = decoded_before;
    expected
        .invocation_results
        .retain(|record| !(record.scope == scope && record.invocation == invocation.invocation));
    if encode_standard_runtime_state(&expected) != *after {
        return Err(ReplayError::TerminalMutation);
    }
    Ok(())
}

fn validate_runtime_successor<SourceError, ExecutorError>(
    input: &ReplayInput,
    transition: &ReplayTransition,
    current: &RuntimeBinding,
) -> Result<(), ReplayError<SourceError, ExecutorError>> {
    let expected = if transition.disposition == ReplayDisposition::Applied {
        runtime_upgrade_target(input, current).unwrap_or_else(|| current.clone())
    } else {
        current.clone()
    };
    if transition.next_runtime == expected {
        Ok(())
    } else {
        Err(ReplayError::InvalidRuntimeUpgrade)
    }
}

fn runtime_upgrade_target(input: &ReplayInput, current: &RuntimeBinding) -> Option<RuntimeBinding> {
    let ReplayOperation::Management {
        request: LifecycleRequest::Authorized { request, .. },
    } = &input.operation
    else {
        return None;
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
        return None;
    };
    if *from_deployment != current.deployment {
        return None;
    }
    let mut target = current.clone();
    target.deployment = *to_deployment;
    target.program = *to_program;
    target.producer = *producer;
    target.package = package.clone();
    Some(target)
}

fn validate_lane_mutation<SourceError, ExecutorError>(
    input: &ReplayInput,
    before: &RuntimeState,
    after: &RuntimeState,
    disposition: ReplayDisposition,
    position: ReplayPosition,
    system_authority_execution: Option<ReplaySystemAuthorityExecution>,
) -> Result<Option<ReplaySystemAuthorityWrite>, ReplayError<SourceError, ExecutorError>> {
    if matches!(input.operation, ReplayOperation::Management { .. }) {
        if !matches!(
            position,
            ReplayPosition::Genesis
                | ReplayPosition::Ordered {
                    merge_seal: Some(_),
                    ..
                }
        ) {
            return Err(ReplayError::InvalidFence);
        }
        return validate_standard_management_transition(
            input,
            before,
            after,
            disposition,
            system_authority_execution,
        );
    }

    let lane = input.persisted_lane();
    let changed_outside_owner = match lane {
        PersistedLane::Control => {
            after.linear != before.linear
                || after.merge != before.merge
                || after.local != before.local
        }
        PersistedLane::Linear => {
            after.control != before.control
                || after.merge != before.merge
                || after.local != before.local
        }
        PersistedLane::Merge => {
            after.control != before.control
                || after.linear != before.linear
                || after.local != before.local
        }
        PersistedLane::Local => {
            after.control != before.control
                || after.linear != before.linear
                || after.merge != before.merge
        }
    };
    if changed_outside_owner {
        Err(ReplayError::CrossLaneMutation)
    } else {
        Ok(None)
    }
}

fn validate_standard_management_transition<SourceError, ExecutorError>(
    input: &ReplayInput,
    before: &RuntimeState,
    after: &RuntimeState,
    disposition: ReplayDisposition,
    system_authority_execution: Option<ReplaySystemAuthorityExecution>,
) -> Result<Option<ReplaySystemAuthorityWrite>, ReplayError<SourceError, ExecutorError>> {
    let ReplayOperation::Management { request } = &input.operation else {
        return Err(ReplayError::InvalidPosition);
    };
    let decoded = decode_standard_runtime_state(before)
        .map_err(|_| ReplayError::InvalidManagementTransition)?;
    let predecessor_authority = decoded.system_authority.clone();
    let mut runtime = StandardAgentRuntime::restore(decoded)
        .map_err(|_| ReplayError::InvalidManagementTransition)?;
    let direct_system_authority = matches!(
        request,
        LifecycleRequest::FinalizeSystemAuthority(_)
            | LifecycleRequest::RotateSystemAuthority(_)
            | LifecycleRequest::FinalizeCatalog(_)
    );
    let (result, selected) = match (direct_system_authority, system_authority_execution) {
        (true, Some(execution)) => runtime
            .apply_scoped(execution.context, execution.scope, request.clone())
            .into_parts(),
        (true, None) | (false, Some(_)) => {
            return Err(ReplayError::ScopeMismatch);
        }
        (false, None) => (runtime.apply(request.clone()), None),
    };
    let expected_disposition = if result.is_ok() {
        ReplayDisposition::Applied
    } else {
        ReplayDisposition::Rejected
    };
    if disposition != expected_disposition
        || encode_standard_runtime_state(&runtime.snapshot()) != *after
    {
        return Err(ReplayError::InvalidManagementTransition);
    }
    match (result, selected) {
        (Ok(result), Some(selected)) if direct_system_authority => {
            let successor_authority = decode_standard_runtime_state(after)
                .map_err(|_| ReplayError::InvalidManagementTransition)?
                .system_authority
                .ok_or(ReplayError::InvalidManagementTransition)?;
            Ok(Some(ReplaySystemAuthorityWrite {
                operation: request.commitment(),
                result,
                selected,
                predecessor_control: before.control.clone(),
                successor_control: after.control.clone(),
                predecessor_authority: predecessor_authority
                    .ok_or(ReplayError::InvalidManagementTransition)?,
                successor_authority,
            }))
        }
        (Ok(_), Some(_)) | (Err(_), Some(_)) | (Ok(_), None) | (Err(_), None)
            if direct_system_authority =>
        {
            Err(ReplayError::InvalidManagementTransition)
        }
        (_, Some(_)) => Err(ReplayError::InvalidManagementTransition),
        (_, None) => Ok(None),
    }
}

/// Construct and validate one derived lane-state manifest.
pub fn derive_lane_state<SourceError, ExecutorError>(
    genesis: AgentJournalGenesisId,
    runtime: RuntimeBinding,
    lane: PersistedLane,
    cursor: LaneCursor,
    state: &[u8],
) -> Result<LaneStateManifest, ReplayError<SourceError, ExecutorError>> {
    let manifest = LaneStateManifest {
        genesis,
        runtime,
        lane,
        cursor,
        state: BlobRef::of_bytes(state),
    };
    if manifest.validate().is_err() {
        Err(ReplayError::InvalidRecord)
    } else {
        Ok(manifest)
    }
}

/// Build the coherent aggregate checkpoint after all referenced lane
/// manifests and the artifact closure have been persisted.
#[allow(clippy::too_many_arguments)]
pub fn derive_checkpoint<SourceError, ExecutorError>(
    genesis: AgentJournalGenesisId,
    admission: AgentGenesisAdmissionId,
    runtime: RuntimeBinding,
    publication_revision: u64,
    ordered: OrderedBase,
    merge_frontier: MergeFrontierId,
    merge_fence: OrderedBase,
    merge_seal: Option<MergeSealId>,
    ordered_invocations: InvocationIndexId,
    merge_invocations: InvocationIndexId,
    lanes: Vec<CheckpointLane>,
    artifacts: ArtifactClosureId,
) -> Result<CheckpointManifest, ReplayError<SourceError, ExecutorError>> {
    let checkpoint = CheckpointManifest {
        genesis,
        admission,
        runtime,
        publication_revision,
        ordered_head: ordered.head,
        ordered_index: ordered.index,
        merge_frontier,
        merge_fence,
        merge_seal,
        ordered_invocations,
        merge_invocations,
        lanes,
        artifacts,
    };
    if checkpoint.validate().is_err() {
        Err(ReplayError::InvalidRecord)
    } else {
        Ok(checkpoint)
    }
}

/// Physical component selected by a persisted lane.
pub fn state_component(state: &RuntimeState, lane: PersistedLane) -> &[u8] {
    match lane {
        PersistedLane::Control => &state.control,
        PersistedLane::Linear => &state.linear,
        PersistedLane::Merge => &state.merge,
        PersistedLane::Local => &state.local,
    }
}

/// Result owner retained for public callers which need to route an
/// acknowledgement before converting it to [`PersistedLane`].
pub const fn result_lane(storage: InvocationResultStorage) -> PersistedLane {
    match storage {
        InvocationResultStorage::Control => PersistedLane::Control,
        InvocationResultStorage::Lane(StateLane::Linear) => PersistedLane::Linear,
        InvocationResultStorage::Lane(StateLane::Merge) => PersistedLane::Merge,
        InvocationResultStorage::Lane(StateLane::Local) => PersistedLane::Local,
    }
}

#[cfg(feature = "std")]
mod aggregate {
    use super::*;

    pub(crate) type MaterializeError<ResolverError, ExecutorError> =
        ReplayError<ReplayMaterializationSourceError<ResolverError>, ExecutorError>;
    pub(crate) type RecoveryError =
        MaterializeError<core::convert::Infallible, core::convert::Infallible>;

    struct ReplayBase {
        state: RuntimeState,
        ordered: OrderedBase,
        local_revision: u64,
        local_head: Option<LocalEntryId>,
        merge: SealedMergeBase,
        merge_ancestry: BTreeSet<MergeEventId>,
        snapshots: MaterializedOrderedSnapshots,
        fence: Option<MergeFence>,
        ordered_invocations: InvocationIndexId,
        merge_invocations: InvocationIndexId,
        local_invocations: InvocationIndexId,
        genesis_input: Option<ReplayInput>,
        fence_ancestry: FenceAncestryEvidence,
    }

    #[derive(Clone)]
    struct FenceDependency {
        id: MergeSealId,
        seal: MergeSeal,
        state: LaneStateManifest,
        bytes: Vec<u8>,
    }

    #[allow(clippy::large_enum_variant)]
    enum MaterializationAction {
        Merge {
            replay: MergeReplay,
            roots: Vec<SealedMergeRoot>,
            ancestry: BTreeSet<MergeEventId>,
            reset_to_boundary: bool,
        },
        Local(LocalEntryId, LocalEntry),
        Ordered {
            id: OrderedEntryId,
            entry: OrderedEntry,
            fence: Option<FenceDependency>,
        },
    }

    struct MaterializationPlan {
        actions: Vec<MaterializationAction>,
        ordered: OrderedReplay,
        final_roots: Vec<SealedMergeRoot>,
        final_ancestry: BTreeSet<MergeEventId>,
        suffix_budget: ReplaySuffixBudget,
    }

    #[cfg(test)]
    pub(super) fn test_composite_entry_budget(
        ordered: usize,
        merge: usize,
        local: usize,
    ) -> Result<(), ReplayValidationError> {
        let mut budget = ReplaySuffixBudget::default();
        for count in [ordered, merge, local] {
            for _ in 0..count {
                budget.add_entry(true, 0)?;
            }
        }
        Ok(())
    }

    fn journal<ResolverError, ExecutorError>(
        error: JournalStoreError,
    ) -> MaterializeError<ResolverError, ExecutorError> {
        ReplayError::Source(ReplayMaterializationSourceError::Journal(error))
    }

    fn lift_replay<ResolverError, ExecutorError>(
        error: ReplayError<JournalStoreError, core::convert::Infallible>,
    ) -> MaterializeError<ResolverError, ExecutorError> {
        error
            .map_source(ReplayMaterializationSourceError::Journal)
            .map_executor(|never| match never {})
    }

    fn lift_validation<ResolverError, ExecutorError>(
        error: ReplayValidationError,
    ) -> MaterializeError<ResolverError, ExecutorError> {
        error
            .map_source(|never| match never {})
            .map_executor(|never| match never {})
    }

    fn require_record<S, R, ResolverError, ExecutorError>(
        store: &S,
        id: R::Id,
    ) -> Result<R, MaterializeError<ResolverError, ExecutorError>>
    where
        S: AgentJournalStore,
        R: CanonicalJournalRecord,
    {
        AgentJournalStore::get(store, id)
            .map_err(journal)?
            .ok_or_else(|| journal(JournalStoreError::MissingObject))
    }

    fn require_blob<S, ResolverError, ExecutorError>(
        store: &S,
        class: JournalBlobClass,
        reference: &BlobRef,
    ) -> Result<Vec<u8>, MaterializeError<ResolverError, ExecutorError>>
    where
        S: AgentJournalStore,
    {
        store
            .load_blob(class, reference)
            .map_err(journal)?
            .ok_or_else(|| journal(JournalStoreError::MissingObject))
    }

    fn authenticate_artifacts<S, ResolverError, ExecutorError>(
        store: &S,
        expected: &ArtifactClosure,
    ) -> Result<(), MaterializeError<ResolverError, ExecutorError>>
    where
        S: AgentJournalStore,
    {
        if expected.validate().is_err() {
            return Err(ReplayError::InvalidRecord);
        }
        for artifact in &expected.artifacts {
            require_blob(store, JournalBlobClass::CatalogArtifact, artifact)?;
        }
        Ok(())
    }

    fn load_fence_dependency<S, ResolverError, ExecutorError>(
        store: &S,
        id: MergeSealId,
    ) -> Result<FenceDependency, MaterializeError<ResolverError, ExecutorError>>
    where
        S: AgentJournalStore,
    {
        let seal: MergeSeal = require_record(store, id)?;
        if seal.id() != id || seal.validate().is_err() {
            return Err(ReplayError::InvalidFence);
        }
        let state: LaneStateManifest = require_record(store, seal.merge_state)?;
        let bytes = require_blob(store, JournalBlobClass::LaneState, &state.state)?;
        if state.id() != seal.merge_state
            || state.genesis != seal.genesis
            || state.lane != PersistedLane::Merge
            || state.state != BlobRef::of_bytes(&bytes)
            || !matches!(state.cursor, LaneCursor::Merge { frontier } if frontier == seal.frontier)
        {
            return Err(ReplayError::InvalidFence);
        }
        Ok(FenceDependency {
            id,
            seal,
            state,
            bytes,
        })
    }

    fn checkpoint_fence<S, ResolverError, ExecutorError>(
        store: &S,
        checkpoint: &CheckpointManifest,
        roots: &[SealedMergeRoot],
    ) -> Result<Option<MergeFence>, MaterializeError<ResolverError, ExecutorError>>
    where
        S: AgentJournalStore,
    {
        if checkpoint.merge_fence == OrderedBase::post_genesis() {
            return if checkpoint.merge_seal.is_none() {
                Ok(None)
            } else {
                Err(ReplayError::InvalidFence)
            };
        }
        let head = checkpoint
            .merge_fence
            .head
            .ok_or(ReplayError::InvalidFence)?;
        let entry: OrderedEntry = require_record(store, head)?;
        let dependency = load_fence_dependency(
            store,
            checkpoint.merge_seal.ok_or(ReplayError::InvalidFence)?,
        )?;
        if entry.id() != head
            || entry.genesis != checkpoint.genesis
            || entry.index != checkpoint.merge_fence.index
            || entry.merge_seal != Some(dependency.id)
            || dependency.seal.genesis != checkpoint.genesis
            || dependency.seal.frontier != entry.merge_frontier
            || dependency.seal.ordered_base
                != (OrderedBase {
                    index: entry
                        .index
                        .checked_sub(1)
                        .ok_or(ReplayError::InvalidFence)?,
                    head: entry.parent,
                })
        {
            return Err(ReplayError::InvalidFence);
        }
        Ok(Some(MergeFence {
            ordered_index: entry.index,
            ordered_head: head,
            frontier: entry.merge_frontier,
            seal: dependency.id,
            // The durable checkpoint is the authentication boundary. Its
            // retained tips are never replayed; new pre-fence descendants are
            // rejected, so pruned internal ancestry is not guessed here.
            sealed_ancestry: roots.iter().map(|root| root.id).collect(),
        }))
    }

    fn load_checkpoint_base<S, E, R>(
        store: &S,
        executor: &mut E,
        heads: &JournalHeads,
        checkpoint_id: CheckpointId,
    ) -> Result<ReplayBase, MaterializeError<R::Error, E::Error>>
    where
        S: AgentJournalStore + ReplaySource<Error = JournalStoreError>,
        E: ReplayExecutor,
        R: OrderedBaseResolver,
    {
        let checkpoint: CheckpointManifest = require_record(store, checkpoint_id)?;
        if checkpoint.validate().is_err()
            || checkpoint.id() != checkpoint_id
            || checkpoint.genesis != heads.genesis
            || checkpoint.publication_revision >= heads.publication_revision
            || checkpoint.ordered_index > heads.ordered_index
            || checkpoint.merge_fence.index > heads.merge_fence.index
            || checkpoint.lanes.len() != 4
        {
            return Err(ReplayError::InvalidRecord);
        }

        let ordered = OrderedBase {
            index: checkpoint.ordered_index,
            head: checkpoint.ordered_head,
        };
        let mut state = RuntimeState::default();
        let mut local_cursor = None;
        let mut aggregate_state_bytes = 0usize;
        for lane in &checkpoint.lanes {
            let manifest: LaneStateManifest = require_record(store, lane.state)?;
            if manifest.validate().is_err()
                || manifest.id() != lane.state
                || manifest.genesis != checkpoint.genesis
                || manifest.runtime != checkpoint.runtime
                || manifest.lane != lane.lane
            {
                return Err(ReplayError::InvalidRecord);
            }
            aggregate_state_bytes = aggregate_state_bytes
                .checked_add(
                    usize::try_from(manifest.state.len).map_err(|_| ReplayError::ReplayLimit)?,
                )
                .ok_or(ReplayError::ReplayLimit)?;
            if aggregate_state_bytes > MAX_RUNTIME_STATE_BYTES {
                return Err(ReplayError::ReplayLimit);
            }
            let bytes = require_blob(store, JournalBlobClass::LaneState, &manifest.state)?;
            if manifest.state != BlobRef::of_bytes(&bytes) {
                return Err(ReplayError::InvalidRecord);
            }
            match (lane.lane, lane.node, lane.invocations, &manifest.cursor) {
                (PersistedLane::Control, None, None, LaneCursor::Ordered { base })
                    if *base == ordered =>
                {
                    state.control = bytes
                }
                (PersistedLane::Linear, None, None, LaneCursor::Ordered { base })
                    if *base == ordered =>
                {
                    state.linear = bytes
                }
                (PersistedLane::Merge, None, None, LaneCursor::Merge { frontier })
                    if *frontier == checkpoint.merge_frontier =>
                {
                    state.merge = bytes
                }
                (
                    PersistedLane::Local,
                    Some(node),
                    Some(invocations),
                    LaneCursor::Local {
                        node: cursor_node,
                        revision,
                        head,
                    },
                ) if node == heads.node && *cursor_node == node => {
                    if invocations == InvocationIndexId::ZERO || local_cursor.is_some() {
                        return Err(ReplayError::InvalidRecord);
                    }
                    state.local = bytes;
                    local_cursor = Some((*revision, *head, invocations));
                }
                _ => return Err(ReplayError::InvalidRecord),
            }
        }
        let (local_revision, local_head, local_invocations) =
            local_cursor.ok_or(ReplayError::InvalidRecord)?;
        validate_runtime_state_bound(&state)?;

        let artifacts: ArtifactClosure = require_record(store, checkpoint.artifacts)?;
        let expected_artifacts =
            derive_standard_artifact_closure(checkpoint.genesis, &checkpoint.runtime, &state)
                .map_err(lift_validation)?;
        if artifacts.id() != checkpoint.artifacts || artifacts != expected_artifacts {
            return Err(ReplayError::InvalidRecord);
        }
        authenticate_artifacts(store, &artifacts)?;

        let structural_merge =
            load_structural_merge_base(store, checkpoint.genesis, checkpoint.merge_frontier)
                .map_err(lift_replay)?;
        for root in &structural_merge.roots {
            let event: MergeEvent = require_record(store, root.id)?;
            if event.causal_height != root.causal_height
                || event.ordered_base != root.ordered_base
                || event.input.runtime != root.runtime
                || !executor
                    .verify_merge_event(&event)
                    .map_err(ReplayError::Executor)?
            {
                return Err(ReplayError::UnauthenticatedMergeEvent(root.id));
            }
        }
        let merge = SealedMergeBase {
            structural: structural_merge,
        };
        let fence = checkpoint_fence(store, &checkpoint, merge.roots())?;
        let snapshots = MaterializedOrderedSnapshots::singleton(
            ordered,
            MaterializedOrderedSnapshot {
                runtime: checkpoint.runtime.clone(),
                control: state.control.clone(),
                linear: state.linear.clone(),
            },
        )
        .map_err(lift_validation)?;
        Ok(ReplayBase {
            state,
            ordered,
            local_revision,
            local_head,
            merge_ancestry: merge.roots().iter().map(|root| root.id).collect(),
            merge,
            snapshots,
            fence,
            ordered_invocations: checkpoint.ordered_invocations,
            merge_invocations: checkpoint.merge_invocations,
            local_invocations,
            genesis_input: None,
            fence_ancestry: FenceAncestryEvidence::from_published_local_checkpoint(
                heads,
                checkpoint_id,
                &checkpoint,
            )
            .map_err(lift_validation)?,
        })
    }

    fn load_genesis_base<S, E, R>(
        store: &S,
        heads: &JournalHeads,
    ) -> Result<ReplayBase, MaterializeError<R::Error, E::Error>>
    where
        S: AgentJournalStore,
        E: ReplayExecutor,
        R: OrderedBaseResolver,
    {
        let genesis = store
            .genesis()
            .map_err(journal)?
            .ok_or_else(|| journal(JournalStoreError::NotInitialized))?;
        if genesis.validate().is_err()
            || genesis.id() != heads.genesis
            || genesis.runtime().space != heads.runtime.space
            || genesis.runtime().agent != heads.runtime.agent
        {
            return Err(ReplayError::InvalidRecord);
        }
        let empty = MergeFrontier {
            genesis: heads.genesis,
            events: Vec::new(),
        };
        let stored: MergeFrontier = require_record(store, empty.id())?;
        if stored != empty {
            return Err(ReplayError::InvalidRecord);
        }
        for (id, scope) in [
            (
                InvocationIndexManifest::empty(heads.genesis, InvocationOwnershipScope::Ordered)
                    .id(),
                InvocationOwnershipScope::Ordered,
            ),
            (
                InvocationIndexManifest::empty(heads.genesis, InvocationOwnershipScope::Merge).id(),
                InvocationOwnershipScope::Merge,
            ),
            (
                InvocationIndexManifest::empty(
                    heads.genesis,
                    InvocationOwnershipScope::Local(heads.node),
                )
                .id(),
                InvocationOwnershipScope::Local(heads.node),
            ),
        ] {
            let manifest: InvocationIndexManifest = require_record(store, id)?;
            if manifest.id() != id || manifest.scope != scope || manifest.genesis != heads.genesis {
                return Err(ReplayError::InvalidRecord);
            }
        }
        Ok(ReplayBase {
            state: RuntimeState::default(),
            ordered: OrderedBase::post_genesis(),
            local_revision: 0,
            local_head: None,
            merge: SealedMergeBase {
                structural: StructuralMergeBase {
                    genesis: heads.genesis,
                    frontier_id: empty.id(),
                    roots: Vec::new(),
                },
            },
            merge_ancestry: BTreeSet::new(),
            snapshots: MaterializedOrderedSnapshots::default(),
            fence: None,
            ordered_invocations: InvocationIndexManifest::empty(
                heads.genesis,
                InvocationOwnershipScope::Ordered,
            )
            .id(),
            merge_invocations: InvocationIndexManifest::empty(
                heads.genesis,
                InvocationOwnershipScope::Merge,
            )
            .id(),
            local_invocations: InvocationIndexManifest::empty(
                heads.genesis,
                InvocationOwnershipScope::Local(heads.node),
            )
            .id(),
            genesis_input: Some(genesis.create),
            fence_ancestry: FenceAncestryEvidence::post_genesis(heads.genesis)
                .map_err(lift_validation)?,
        })
    }

    fn successor_merge_base(
        previous: &SealedMergeBase,
        replay: &MergeReplay,
    ) -> Result<SealedMergeBase, ReplayValidationError> {
        if replay.genesis != previous.genesis()
            || replay.checkpoint_frontier != previous.frontier_id()
        {
            return Err(ReplayError::ChainMismatch);
        }
        let previous = previous
            .roots()
            .iter()
            .map(|root| (root.id, root.clone()))
            .collect::<BTreeMap<_, _>>();
        let loaded = replay
            .events
            .iter()
            .map(|(id, event)| {
                (
                    *id,
                    SealedMergeRoot {
                        id: *id,
                        causal_height: event.causal_height,
                        ordered_base: event.ordered_base,
                        runtime: event.input.runtime.clone(),
                    },
                )
            })
            .collect::<BTreeMap<_, _>>();
        let mut roots = Vec::new();
        for id in &replay.frontier.events {
            roots.push(
                loaded
                    .get(id)
                    .or_else(|| previous.get(id))
                    .cloned()
                    .ok_or(ReplayError::ChainMismatch)?,
            );
        }
        Ok(SealedMergeBase {
            structural: StructuralMergeBase {
                genesis: replay.genesis,
                frontier_id: replay.frontier_id,
                roots,
            },
        })
    }

    fn append_merge<S, R, E>(
        store: &S,
        target: MergeFrontierId,
        available_ordered: OrderedBase,
        boundary: &SealedMergeBase,
        boundary_ancestry: &BTreeSet<MergeEventId>,
        current: &mut SealedMergeBase,
        ancestry: &mut BTreeSet<MergeEventId>,
        actions: &mut Vec<MaterializationAction>,
        budget: &mut ReplaySuffixBudget,
    ) -> Result<(), MaterializeError<R::Error, E::Error>>
    where
        S: AgentJournalStore + ReplaySource<Error = JournalStoreError>,
        R: OrderedBaseResolver,
        E: ReplayExecutor,
    {
        if target == current.frontier_id() {
            return Ok(());
        }
        let (replay, reset_to_boundary) = match load_merge_suffix(store, current, target) {
            Ok(replay) => (replay, false),
            Err(
                ReplayError::ChainMismatch
                | ReplayError::NonMinimalFrontier
                | ReplayError::StaleMergeBranch(_),
            ) => (
                load_merge_suffix(store, boundary, target).map_err(lift_replay)?,
                true,
            ),
            Err(error) => return Err(lift_replay(error)),
        };
        budget.frontier(&replay.frontier).map_err(lift_validation)?;
        for (id, event) in replay.events() {
            budget.merge(*id, event).map_err(lift_validation)?;
            if event.ordered_base.index > available_ordered.index
                || (event.ordered_base.index == available_ordered.index
                    && event.ordered_base.head != available_ordered.head)
            {
                return Err(ReplayError::InvalidOrderedBase);
            }
        }
        let previous = if reset_to_boundary {
            *ancestry = boundary_ancestry.clone();
            boundary
        } else {
            &*current
        };
        let next = successor_merge_base(previous, &replay).map_err(lift_validation)?;
        ancestry.extend(replay.events().iter().map(|(id, _)| *id));
        *current = next;
        actions.push(MaterializationAction::Merge {
            replay,
            roots: current.roots().to_vec(),
            ancestry: ancestry.clone(),
            reset_to_boundary,
        });
        Ok(())
    }

    fn build_plan<S, R, E>(
        store: &S,
        heads: &JournalHeads,
        base: &ReplayBase,
    ) -> Result<MaterializationPlan, MaterializeError<R::Error, E::Error>>
    where
        S: AgentJournalStore + ReplaySource<Error = JournalStoreError>,
        R: OrderedBaseResolver,
        E: ReplayExecutor,
    {
        let target_ordered = OrderedBase {
            index: heads.ordered_index,
            head: heads.ordered_head,
        };
        let ordered = load_ordered_suffix(store, heads.genesis, base.ordered, target_ordered)
            .map_err(lift_replay)?;
        let local = load_local_suffix(
            store,
            heads.genesis,
            heads.node,
            base.local_revision,
            base.local_head,
            heads.local_revision,
            heads.local_head,
        )
        .map_err(lift_replay)?;
        let mut budget = ReplaySuffixBudget::default();
        for (id, entry) in ordered.entries() {
            budget.ordered(*id, entry).map_err(lift_validation)?;
        }
        for (id, entry) in local.entries() {
            budget.local(*id, entry).map_err(lift_validation)?;
        }

        let mut actions = Vec::new();
        let mut current_merge = base.merge.clone();
        let mut ancestry = base.merge_ancestry.clone();
        let mut merge_boundary = base.merge.clone();
        let mut merge_boundary_ancestry = base.merge_ancestry.clone();
        let mut local_index = 0usize;
        let mut current_ordered = base.ordered;
        for (id, entry) in ordered.entries() {
            while let Some((local_id, local_entry)) = local.entries().get(local_index) {
                if local_entry.ordered_base.index < current_ordered.index
                    || (local_entry.ordered_base.index == current_ordered.index
                        && local_entry.ordered_base.head != current_ordered.head)
                {
                    return Err(ReplayError::InvalidOrderedBase);
                }
                if local_entry.ordered_base != current_ordered {
                    break;
                }
                append_merge::<S, R, E>(
                    store,
                    local_entry.merge_frontier,
                    current_ordered,
                    &merge_boundary,
                    &merge_boundary_ancestry,
                    &mut current_merge,
                    &mut ancestry,
                    &mut actions,
                    &mut budget,
                )?;
                actions.push(MaterializationAction::Local(*local_id, local_entry.clone()));
                local_index += 1;
            }
            append_merge::<S, R, E>(
                store,
                entry.merge_frontier,
                current_ordered,
                &merge_boundary,
                &merge_boundary_ancestry,
                &mut current_merge,
                &mut ancestry,
                &mut actions,
                &mut budget,
            )?;
            let fence = if let Some(seal) = entry.merge_seal {
                let dependency = load_fence_dependency(store, seal)?;
                budget.seal(&dependency.seal).map_err(lift_validation)?;
                Some(dependency)
            } else {
                None
            };
            actions.push(MaterializationAction::Ordered {
                id: *id,
                entry: entry.clone(),
                fence,
            });
            if entry.merge_seal.is_some() {
                merge_boundary = current_merge.clone();
                merge_boundary_ancestry = ancestry.clone();
            }
            current_ordered = OrderedBase {
                index: entry.index,
                head: Some(*id),
            };
        }

        while let Some((local_id, local_entry)) = local.entries().get(local_index) {
            if local_entry.ordered_base != current_ordered {
                return Err(ReplayError::InvalidOrderedBase);
            }
            append_merge::<S, R, E>(
                store,
                local_entry.merge_frontier,
                current_ordered,
                &merge_boundary,
                &merge_boundary_ancestry,
                &mut current_merge,
                &mut ancestry,
                &mut actions,
                &mut budget,
            )?;
            actions.push(MaterializationAction::Local(*local_id, local_entry.clone()));
            local_index += 1;
        }
        append_merge::<S, R, E>(
            store,
            heads.merge_frontier,
            current_ordered,
            &merge_boundary,
            &merge_boundary_ancestry,
            &mut current_merge,
            &mut ancestry,
            &mut actions,
            &mut budget,
        )?;
        Ok(MaterializationPlan {
            actions,
            ordered,
            final_roots: current_merge.roots().to_vec(),
            final_ancestry: ancestry,
            suffix_budget: budget,
        })
    }

    fn validate_resolved_snapshot<ResolverError, ExecutorError>(
        genesis: AgentJournalGenesisId,
        canonical_head: OrderedBase,
        requested: OrderedBase,
        snapshot: ResolvedOrderedSnapshot,
    ) -> Result<MaterializedOrderedSnapshot, MaterializeError<ResolverError, ExecutorError>> {
        if snapshot.genesis != genesis
            || snapshot.canonical_head != canonical_head
            || snapshot.base != requested
            || snapshot.runtime.validate().is_err()
            || snapshot.control_commitment != BlobRef::of_bytes(&snapshot.control)
            || snapshot.linear_commitment != BlobRef::of_bytes(&snapshot.linear)
            || snapshot.evidence_commitment == Hash::ZERO
            || snapshot
                .control
                .len()
                .checked_add(snapshot.linear.len())
                .is_none_or(|len| len > MAX_RUNTIME_STATE_BYTES)
        {
            return Err(ReplayError::InvalidOrderedBase);
        }
        Ok(MaterializedOrderedSnapshot {
            runtime: snapshot.runtime,
            control: snapshot.control,
            linear: snapshot.linear,
        })
    }

    fn resolve_snapshot<R, E>(
        resolver: &R,
        genesis: AgentJournalGenesisId,
        canonical_head: OrderedBase,
        requested: OrderedBase,
        snapshots: &mut MaterializedOrderedSnapshots,
    ) -> Result<MaterializedOrderedSnapshot, MaterializeError<R::Error, E::Error>>
    where
        R: OrderedBaseResolver,
        E: ReplayExecutor,
    {
        if let Some(snapshot) = snapshots.get(&requested) {
            return Ok(snapshot.clone());
        }
        let snapshot = resolver
            .snapshot_at(genesis, canonical_head, requested)
            .map_err(|error| {
                ReplayError::Source(ReplayMaterializationSourceError::Resolver(error))
            })?
            .ok_or(ReplayError::UnavailableOrderedBase)?;
        let snapshot = validate_resolved_snapshot(genesis, canonical_head, requested, snapshot)?;
        snapshots
            .insert(requested, snapshot.clone())
            .map_err(lift_validation)?;
        Ok(snapshot)
    }

    fn authenticate_action_fence<ResolverError, ExecutorError>(
        dependency: &FenceDependency,
        id: OrderedEntryId,
        entry: &OrderedEntry,
        state: &RuntimeState,
        frontier: MergeFrontierId,
        ancestry: &BTreeSet<MergeEventId>,
    ) -> Result<MergeFence, MaterializeError<ResolverError, ExecutorError>> {
        let parent = OrderedBase {
            index: entry
                .index
                .checked_sub(1)
                .ok_or(ReplayError::InvalidFence)?,
            head: entry.parent,
        };
        if entry.merge_seal != Some(dependency.id)
            || !matches!(
                entry.input.operation,
                ReplayOperation::Management { .. } | ReplayOperation::SealMerge
            )
            || dependency.seal.genesis != entry.genesis
            || dependency.seal.frontier != frontier
            || dependency.seal.ordered_base != parent
            || dependency.state.runtime != entry.input.runtime
            || dependency.bytes != state.merge
            || dependency.state.state != BlobRef::of_bytes(&state.merge)
        {
            return Err(ReplayError::InvalidFence);
        }
        Ok(MergeFence {
            ordered_index: entry.index,
            ordered_head: id,
            frontier,
            seal: dependency.id,
            sealed_ancestry: ancestry.clone(),
        })
    }

    fn execute_plan<S, E, R>(
        store: &mut S,
        executor: &mut E,
        resolver: &R,
        heads: JournalHeads,
        mut base: ReplayBase,
        plan: MaterializationPlan,
        replayed_root: Option<ReplayedRootJournalIdentity>,
    ) -> Result<ReplayMaterialization, MaterializeError<R::Error, E::Error>>
    where
        S: AgentJournalStore + ReplaySource<Error = JournalStoreError>,
        E: ReplayExecutor,
        R: OrderedBaseResolver,
    {
        let canonical_head = OrderedBase {
            index: heads.ordered_index,
            head: heads.ordered_head,
        };
        let replay_boundary = base.ordered;
        let mut fence_ancestry = base.fence_ancestry.clone();
        let indexes = InvocationIndexes::open(
            store,
            base.ordered_invocations,
            base.merge_invocations,
            base.local_invocations,
        )
        .map_err(|_| ReplayError::InvocationOwnership(InvocationOwnershipError::Unauthenticated))?;
        let mut machine = ReplayMachine {
            genesis: heads.genesis,
            replayed_root,
            runtime: base
                .snapshots
                .get(&base.ordered)
                .map(|snapshot| snapshot.runtime.clone())
                .unwrap_or_else(|| {
                    base.genesis_input
                        .as_ref()
                        .expect("genesis base carries its Create input")
                        .runtime
                        .clone()
                }),
            runtime_history: base
                .snapshots
                .iter()
                .map(|(cursor, snapshot)| (*cursor, snapshot.runtime.clone()))
                .collect(),
            ownership: indexes,
            fence: base.fence.take(),
        };
        let mut state = base.state;
        let mut snapshots = base.snapshots;
        let mut current_ordered = base.ordered;
        let mut current_frontier = base.merge.frontier_id();
        let mut merge_boundary_roots = base
            .merge
            .roots()
            .iter()
            .map(|root| root.id)
            .collect::<BTreeSet<_>>();
        let mut merge_boundary_frontier = base.merge.frontier_id();
        let mut merge_boundary_ancestry = base.merge_ancestry.clone();
        let mut merge_boundary_state = state.merge.clone();
        let mut merge_boundary_invocations = base.merge_invocations;
        let mut current_roots = base.merge.roots().to_vec();
        let mut current_ancestry = base.merge_ancestry;
        let mut local_revision = base.local_revision;
        let mut local_head = base.local_head;
        let mut merge_facts = BTreeMap::new();
        let mut final_system_authority_write = None;

        if InvocationOwnership::unfinalized(&machine.ownership, InvocationOwnershipScope::Merge)
            .map_err(ReplayError::InvocationOwnership)?
            != 0
        {
            return Err(ReplayError::InvocationOwnership(
                InvocationOwnershipError::Unauthenticated,
            ));
        }

        if let Some(input) = base.genesis_input {
            let step = machine
                .apply::<_, ReplayMaterializationSourceError<R::Error>>(
                    executor,
                    &input,
                    &state,
                    ReplayPosition::Genesis,
                )
                .map_err(historical_replay_error)?;
            state = step.state;
            validate_runtime_state_bound(&state)?;
            if step.runtime != input.runtime {
                return Err(ReplayError::RuntimeMismatch);
            }
            snapshots
                .insert(
                    OrderedBase::post_genesis(),
                    MaterializedOrderedSnapshot {
                        runtime: step.runtime,
                        control: state.control.clone(),
                        linear: state.linear.clone(),
                    },
                )
                .map_err(lift_validation)?;
            current_ordered = OrderedBase::post_genesis();
            merge_boundary_state = state.merge.clone();
        }

        for action in plan.actions {
            match action {
                MaterializationAction::Merge {
                    replay,
                    roots,
                    ancestry,
                    reset_to_boundary,
                } => {
                    if reset_to_boundary {
                        let ordered_invocations = InvocationOwnership::index_id(
                            &machine.ownership,
                            InvocationOwnershipScope::Ordered,
                        )
                        .map_err(ReplayError::InvocationOwnership)?;
                        let local_invocations = InvocationOwnership::index_id(
                            &machine.ownership,
                            InvocationOwnershipScope::Local(heads.node),
                        )
                        .map_err(ReplayError::InvocationOwnership)?;
                        let runtime = machine.runtime.clone();
                        let runtime_history = machine.runtime_history.clone();
                        let fence = machine.fence.clone();
                        drop(machine);
                        let indexes = InvocationIndexes::open(
                            store,
                            ordered_invocations,
                            merge_boundary_invocations,
                            local_invocations,
                        )
                        .map_err(|_| {
                            ReplayError::InvocationOwnership(
                                InvocationOwnershipError::Unauthenticated,
                            )
                        })?;
                        machine = ReplayMachine {
                            genesis: heads.genesis,
                            replayed_root,
                            runtime,
                            runtime_history,
                            ownership: indexes,
                            fence,
                        };
                        if InvocationOwnership::unfinalized(
                            &machine.ownership,
                            InvocationOwnershipScope::Merge,
                        )
                        .map_err(ReplayError::InvocationOwnership)?
                            != 0
                        {
                            return Err(ReplayError::InvocationOwnership(
                                InvocationOwnershipError::Unauthenticated,
                            ));
                        }
                        state.merge = merge_boundary_state.clone();
                        current_frontier = merge_boundary_frontier;
                        merge_facts.clear();
                    }
                    if replay.checkpoint_frontier != current_frontier {
                        return Err(ReplayError::ChainMismatch);
                    }
                    for (id, event) in replay.events() {
                        let snapshot = resolve_snapshot::<R, E>(
                            resolver,
                            heads.genesis,
                            canonical_head,
                            event.ordered_base,
                            &mut snapshots,
                        )?;
                        if snapshot.runtime != event.input.runtime {
                            return Err(ReplayError::RuntimeMismatch);
                        }
                        machine
                            .runtime_history
                            .insert(event.ordered_base, snapshot.runtime.clone());
                        let before = RuntimeState {
                            control: snapshot.control,
                            linear: snapshot.linear,
                            merge: state.merge.clone(),
                            local: state.local.clone(),
                        };
                        let step = machine
                            .verify_and_apply_merge::<
                                E,
                                ReplayMaterializationSourceError<R::Error>,
                            >(executor, &plan.ordered, *id, event, &before)
                            .map_err(historical_replay_error)?;
                        if merge_facts
                            .insert(
                                *id,
                                MergeExecutionFact {
                                    event: event.clone(),
                                    before,
                                    after: step.state.clone(),
                                    result: step.result.clone(),
                                },
                            )
                            .is_some()
                        {
                            return Err(ReplayError::InvalidRecord);
                        }
                        state.merge = step.state.merge;
                        validate_runtime_state_bound(&state)?;
                    }
                    current_frontier = replay.frontier_id;
                    current_roots = roots;
                    current_ancestry = ancestry;
                }
                MaterializationAction::Local(id, entry) => {
                    if entry.parent != local_head
                        || entry.revision
                            != local_revision
                                .checked_add(1)
                                .ok_or(ReplayError::ReplayLimit)?
                        || entry.merge_frontier != current_frontier
                    {
                        return Err(ReplayError::ChainMismatch);
                    }
                    let snapshot = resolve_snapshot::<R, E>(
                        resolver,
                        heads.genesis,
                        canonical_head,
                        entry.ordered_base,
                        &mut snapshots,
                    )?;
                    if snapshot.runtime != entry.input.runtime {
                        return Err(ReplayError::RuntimeMismatch);
                    }
                    machine
                        .runtime_history
                        .insert(entry.ordered_base, snapshot.runtime.clone());
                    let before = RuntimeState {
                        control: snapshot.control,
                        linear: snapshot.linear,
                        merge: state.merge.clone(),
                        local: state.local.clone(),
                    };
                    let step = machine
                        .apply::<_, ReplayMaterializationSourceError<R::Error>>(
                            executor,
                            &entry.input,
                            &before,
                            ReplayPosition::Local {
                                id,
                                node: entry.node,
                                revision: entry.revision,
                                ordered_base: entry.ordered_base,
                                merge_frontier: entry.merge_frontier,
                            },
                        )
                        .map_err(historical_replay_error)?;
                    state.local = step.state.local;
                    validate_runtime_state_bound(&state)?;
                    local_revision = entry.revision;
                    local_head = Some(id);
                }
                MaterializationAction::Ordered { id, entry, fence } => {
                    let parent = OrderedBase {
                        index: entry
                            .index
                            .checked_sub(1)
                            .ok_or(ReplayError::ChainMismatch)?,
                        head: entry.parent,
                    };
                    if parent != current_ordered || entry.merge_frontier != current_frontier {
                        return Err(ReplayError::ChainMismatch);
                    }
                    let next_fence = match fence.as_ref() {
                        Some(dependency) => Some(authenticate_action_fence(
                            dependency,
                            id,
                            &entry,
                            &state,
                            current_frontier,
                            &current_ancestry,
                        )?),
                        None if entry.merge_seal.is_none() => None,
                        None => return Err(ReplayError::InvalidFence),
                    };
                    if let Some(seal) = entry.merge_seal {
                        machine
                            .finalize_merge_outcomes(id, seal, &merge_facts)
                            .map_err(lift_validation)?;
                    }
                    let step = machine
                        .apply::<_, ReplayMaterializationSourceError<R::Error>>(
                            executor,
                            &entry.input,
                            &state,
                            ReplayPosition::Ordered {
                                id,
                                index: entry.index,
                                merge_frontier: entry.merge_frontier,
                                merge_seal: entry.merge_seal,
                            },
                        )
                        .map_err(historical_replay_error)?;
                    if canonical_head.head == Some(id) && canonical_head.index == entry.index {
                        final_system_authority_write =
                            step.system_authority_write.clone().map(|write| {
                                ReplayMaterializedSystemAuthorityWrite {
                                    entry: entry.clone(),
                                    write,
                                }
                            });
                    }
                    state = step.state;
                    validate_runtime_state_bound(&state)?;
                    current_ordered = OrderedBase {
                        index: entry.index,
                        head: Some(id),
                    };
                    let evidence_fence = if next_fence.is_some() {
                        current_ordered
                    } else {
                        fence_ancestry.fence()
                    };
                    fence_ancestry = fence_ancestry
                        .advance_ordered(&entry, evidence_fence)
                        .map_err(lift_validation)?;
                    snapshots
                        .insert(
                            current_ordered,
                            MaterializedOrderedSnapshot {
                                runtime: step.runtime,
                                control: state.control.clone(),
                                linear: state.linear.clone(),
                            },
                        )
                        .map_err(lift_validation)?;
                    if let Some(fence) = next_fence {
                        machine.install_fence(fence)?;
                        merge_boundary_roots = current_roots.iter().map(|root| root.id).collect();
                        merge_boundary_frontier = current_frontier;
                        merge_boundary_ancestry = current_ancestry.clone();
                        merge_boundary_state = state.merge.clone();
                        merge_boundary_invocations = InvocationOwnership::index_id(
                            &machine.ownership,
                            InvocationOwnershipScope::Merge,
                        )
                        .map_err(ReplayError::InvocationOwnership)?;
                        merge_facts.clear();
                    }
                }
            }
        }

        let merge_unfinalized =
            InvocationOwnership::unfinalized(&machine.ownership, InvocationOwnershipScope::Merge)
                .map_err(ReplayError::InvocationOwnership)?;
        let ids = machine
            .ownership_ids(heads.node)
            .map_err(ReplayError::InvocationOwnership)?;
        if ids
            != (
                heads.ordered_invocations,
                heads.merge_invocations,
                heads.local_invocations,
            )
            || current_ordered != canonical_head
            || current_frontier != heads.merge_frontier
            || local_revision != heads.local_revision
            || local_head != heads.local_head
            || machine.runtime != heads.runtime
            || current_roots != plan.final_roots
            || current_ancestry != plan.final_ancestry
        {
            return Err(ReplayError::InvalidRecord);
        }
        match (heads.merge_fence, heads.merge_seal, machine.fence.as_ref()) {
            (base, None, None) if base == OrderedBase::post_genesis() => {}
            (base, Some(seal), Some(fence))
                if base.index == fence.ordered_index
                    && base.head == Some(fence.ordered_head)
                    && seal == fence.seal => {}
            _ => return Err(ReplayError::InvalidFence),
        }
        if merge_unfinalized != 0 {
            validate_merge_finalizer_capacity(
                &plan.suffix_budget,
                heads.genesis,
                &heads.runtime,
                current_ordered,
                current_frontier,
                &state.merge,
            )
            .map_err(lift_validation)?;
        }
        let fence = machine.fence.clone();
        drop(machine);
        validate_runtime_state_bound(&state)?;

        let artifacts = derive_standard_artifact_closure(heads.genesis, &heads.runtime, &state)
            .map_err(lift_validation)?;
        authenticate_artifacts(store, &artifacts)?;
        if !fence_ancestry.validate()
            || fence_ancestry.genesis() != heads.genesis
            || fence_ancestry.checkpoint_base() != replay_boundary
            || fence_ancestry.canonical_head() != canonical_head
            || fence_ancestry.fence() != heads.merge_fence
        {
            return Err(ReplayError::InvalidFence);
        }
        Ok(ReplayMaterialization {
            heads_id: heads.id(),
            heads,
            replayed_root,
            state,
            final_system_authority_write,
            ordered_snapshots: snapshots,
            merge_roots: current_roots,
            merge_boundary_roots,
            merge_boundary_ancestry,
            merge_boundary_state,
            merge_boundary_invocations,
            merge_ancestry: current_ancestry,
            fence,
            artifacts,
            suffix_budget: plan.suffix_budget,
            replay_boundary,
            fence_ancestry,
        })
    }

    /// Resolve the exact durable heads and rebuild their complete bounded
    /// post-checkpoint dependency closure. No state bytes are accepted from
    /// the caller.
    pub(crate) fn materialize_current<S, E, R>(
        store: &mut S,
        executor: &mut E,
        resolver: &R,
    ) -> Result<ReplayMaterialization, MaterializeError<R::Error, E::Error>>
    where
        S: AgentJournalStore + ReplaySource<Error = JournalStoreError>,
        E: ReplayExecutor,
        R: OrderedBaseResolver,
    {
        let heads = store
            .heads()
            .map_err(journal)?
            .ok_or_else(|| journal(JournalStoreError::NotInitialized))?;
        if heads.validate().is_err() || heads.id() == JournalHeadsId::ZERO {
            return Err(ReplayError::InvalidRecord);
        }
        let base = match heads.checkpoint {
            Some(checkpoint) => {
                load_checkpoint_base::<S, E, R>(store, executor, &heads, checkpoint)?
            }
            None => load_genesis_base::<S, E, R>(store, &heads)?,
        };
        let plan = build_plan::<S, R, E>(store, &heads, &base)?;
        execute_plan(store, executor, resolver, heads, base, plan, None)
    }

    /// Materialize a live root journal while retaining only the process-local
    /// provenance minted by `initialize`/`open_reverified`. A raw store open
    /// has no such identity and cannot use this authority path.
    #[cfg(feature = "storage")]
    pub(crate) fn materialize_current_reverified<S, E, R>(
        store: &mut S,
        executor: &mut E,
        resolver: &R,
    ) -> Result<ReplayMaterialization, MaterializeError<R::Error, E::Error>>
    where
        S: AgentJournalStore + ReverifiedRootJournalStore + ReplaySource<Error = JournalStoreError>,
        E: ReplayExecutor,
        R: OrderedBaseResolver,
    {
        let replayed_root = store
            .replayed_root_identity()
            .ok_or_else(|| journal(JournalStoreError::Unavailable))?;
        let heads = store
            .heads()
            .map_err(journal)?
            .ok_or_else(|| journal(JournalStoreError::NotInitialized))?;
        if replayed_root.genesis() != heads.genesis
            || replayed_root.outer_admission() != heads.admission
            || heads.validate().is_err()
            || heads.id() == JournalHeadsId::ZERO
        {
            return Err(ReplayError::ScopeMismatch);
        }
        let base = match heads.checkpoint {
            Some(checkpoint) => {
                load_checkpoint_base::<S, E, R>(store, executor, &heads, checkpoint)?
            }
            None => load_genesis_base::<S, E, R>(store, &heads)?,
        };
        let plan = build_plan::<S, R, E>(store, &heads, &base)?;
        execute_plan(
            store,
            executor,
            resolver,
            heads,
            base,
            plan,
            Some(replayed_root),
        )
    }

    #[cfg(feature = "storage")]
    pub(crate) fn materialized_system_authority_view<S>(
        store: &S,
        current: &ReplayMaterialization,
    ) -> Result<(SystemAuthorityJournalScope, ReplayedSystemAuthorityView), JournalStoreError>
    where
        S: AgentJournalStore + ReverifiedRootJournalStore,
    {
        authenticated_materialization::<core::convert::Infallible, core::convert::Infallible>(
            current,
        )
        .map_err(|_| JournalStoreError::NonCanonical)?;
        let durable = store.heads()?.ok_or(JournalStoreError::NotInitialized)?;
        let identity = current
            .replayed_root()
            .ok_or(JournalStoreError::NonCanonical)?;
        if durable != current.heads
            || durable.id() != current.heads_id
            || JournalStoreInstanceId::from_bytes(*store.instance_id().as_bytes()).is_none()
            || store.replayed_root_identity() != Some(identity)
            || identity.genesis() != current.heads.genesis
            || identity.outer_admission() != current.heads.admission
        {
            return Err(JournalStoreError::Conflict);
        }
        let decoded = decode_standard_runtime_state(&current.state)
            .map_err(|_| JournalStoreError::NonCanonical)?;
        let authority = decoded
            .system_authority
            .as_ref()
            .ok_or(JournalStoreError::NonCanonical)?;
        let control = derive_lane_state::<core::convert::Infallible, core::convert::Infallible>(
            current.heads.genesis,
            current.heads.runtime.clone(),
            PersistedLane::Control,
            LaneCursor::Ordered {
                base: current.ordered_base(),
            },
            &current.state.control,
        )
        .map_err(|_| JournalStoreError::NonCanonical)?
        .id();
        let scope = SystemAuthorityJournalScope::from_replayed_root(&identity)
            .map_err(|_| JournalStoreError::NonCanonical)?;
        let view = ReplayedSystemAuthorityView::from_authenticated_replay(
            scope,
            authority,
            store.instance_id(),
            current.heads_id,
            control,
        )
        .map_err(|_| JournalStoreError::NonCanonical)?;
        Ok((scope, view))
    }

    /// Reconcile one cold pending rotation without reconstructing signing
    /// authority. A predecessor without Intent remains borrow-quarantined. A
    /// predecessor with the immutable v4 replay payload is deterministically
    /// prepared and published; an already-visible exact successor is merely
    /// reverified. Both success paths retire under the owner's still-held
    /// writer before releasing the store or replay outputs.
    #[cfg(feature = "storage")]
    pub(crate) fn recover_pending_system_authority_rotation<'store, S, E>(
        store: &'store mut S,
        executor: &mut E,
        current: ReplayMaterialization,
        pending: PendingSystemAuthorityRecovery,
        owner: &SystemAuthorityLedgerRouteOwner,
    ) -> Result<
        PendingSystemAuthorityRotationRecovery<'store, S>,
        SystemAuthorityRecoveryError<E::Error>,
    >
    where
        S: AgentJournalStore
            + ReverifiedRootJournalStore
            + SystemAuthorityPublicationStore
            + SystemAuthorityHistoryStore
            + ReplaySource<Error = JournalStoreError>,
        E: ReplayExecutor,
    {
        if store.instance_id() != pending.journal_store() {
            return Err(JournalStoreError::NonCanonical.into());
        }
        let (_scope, current_view) = materialized_system_authority_view(store, &current)?;
        if current.heads_id() == pending.predecessor_heads() {
            owner.recheck_pending_recovery(&pending)?;
            if current_view.route() != pending.route()
                || current_view.journal_store() != pending.journal_store()
                || current_view.heads() != pending.predecessor_heads()
                || current_view.control_state() != pending.control_state()
                || current_view.commitment() != pending.state_view_commitment()
                || current_view.authority_state_commitment() != pending.authority_state_commitment()
            {
                return Err(JournalStoreError::NonCanonical.into());
            }
            let Some(entry) = pending.expected_ordered_entry().cloned() else {
                return Ok(PendingSystemAuthorityRotationRecovery::Pending(
                    ReconciledPendingSystemAuthorityRotation {
                        store,
                        current,
                        pending,
                    },
                ));
            };
            let stable_pending = pending.clone();
            let retired = owner.with_pending_rotation_recovery_and_retirement(
                &stable_pending,
                move |frozen| {
                    let prepared = match prepare_ordered(store, executor, &current, &entry)
                        .map_err(SystemAuthorityRecoveryError::Replay)?
                    {
                        ReplayPreparation::Ready(prepared) => prepared,
                        ReplayPreparation::AlreadyCommitted(_) => {
                            return Err(SystemAuthorityRecoveryError::Journal(
                                JournalStoreError::Conflict,
                            ));
                        }
                    };
                    prepared
                        .prepare_pending_system_authority_rotation(pending, frozen)
                        .and_then(
                            PreparedPendingSystemAuthorityRotationPublication::publish_recovered,
                        )
                        .map_err(SystemAuthorityRecoveryError::Journal)
                },
            )??;
            return Ok(PendingSystemAuthorityRotationRecovery::Retired(retired));
        }

        let expected_successor = pending
            .expected_successor_heads()
            .ok_or(SystemAuthorityLedgerError::PublicationRecoveryRequired)?;
        let expected_entry_id = pending
            .expected_ordered_entry_id()
            .ok_or(SystemAuthorityLedgerError::PublicationRecoveryRequired)?;
        let expected_entry = pending
            .expected_ordered_entry()
            .cloned()
            .ok_or(SystemAuthorityLedgerError::PublicationRecoveryRequired)?;
        if current.heads_id() != expected_successor
            || current.heads().previous != Some(pending.predecessor_heads())
            || current.heads().ordered_head != Some(expected_entry_id)
        {
            return Err(JournalStoreError::Conflict.into());
        }

        let stable_pending = pending.clone();
        let retired = owner.with_pending_rotation_recovery_and_retirement(
            &stable_pending,
            move |frozen| {
                // Re-read the exact physical head and provenance only after
                // acquiring the owner writer. A stale materialization from a
                // pre-lock classification must never retire the pending row.
                let (scope, current_view) = materialized_system_authority_view(store, &current)?;
                let final_write = current
                    .final_system_authority_write
                    .as_ref()
                    .ok_or(JournalStoreError::NonCanonical)?;
                let entry = &final_write.entry;
                let write = &final_write.write;
                let stored = store
                    .get::<OrderedEntry>(entry.id())?
                    .ok_or(JournalStoreError::MissingObject)?;
                let ReplayOperation::Management {
                    request: LifecycleRequest::RotateSystemAuthority(command),
                } = &entry.input.operation
                else {
                    return Err(JournalStoreError::NonCanonical);
                };
                let StandardSystemAuthorityWrite::Rotation { record, history } = write.selected()
                else {
                    return Err(JournalStoreError::NonCanonical);
                };
                let LifecycleReply::SystemAuthorityRotated {
                    rotation,
                    epoch,
                    exact_retry,
                } = write.result()
                else {
                    return Err(JournalStoreError::NonCanonical);
                };
                let SystemAuthorityLedgerClaim::CommitteeRotation {
                    retiring,
                    incoming,
                    transition,
                } = pending.request()
                else {
                    return Err(JournalStoreError::NonCanonical);
                };
                if stored != *entry
                    || *entry != expected_entry
                    || entry.id() != expected_entry_id
                    || entry.id() != current.heads().ordered_head.unwrap_or_default()
                    || entry.index != current.heads().ordered_index
                    || write.successor_control() != current.state.control
                    || write.operation()
                        != LifecycleRequest::RotateSystemAuthority(command.clone()).commitment()
                    || command.operation_commitment() != write.operation()
                    || command.certificate() != frozen
                    || record.certificate() != frozen
                    || record.certificate().transition() != transition
                    || pending.claim() != transition.authority_claim()
                    || command.new_committee() != incoming
                    || record.old_committee().as_bytes() != &retiring.commitment().0
                    || record.new_committee().as_bytes() != &incoming.commitment().0
                    || *rotation != record.id()
                    || *epoch != record.new_epoch()
                    || *exact_retry
                    || !history.inserted()
                {
                    return Err(JournalStoreError::NonCanonical);
                }

                let reapplied = write
                    .predecessor_authority()
                    .apply_rotation(scope, command)
                    .map_err(|_| JournalStoreError::NonCanonical)?;
                if reapplied.exact_retry()
                    || reapplied.state() != write.successor_authority()
                    || reapplied.record() != record
                    || reapplied.history() != history
                {
                    return Err(JournalStoreError::NonCanonical);
                }
                validate_fresh_rotation_state_transition(
                    scope,
                    write.predecessor_authority(),
                    write.successor_authority(),
                    retiring,
                    incoming,
                    record,
                    history,
                )?;
                let committee_records = rotation_committee_records(retiring, incoming)?;
                if history.committee_records() != committee_records {
                    return Err(JournalStoreError::NonCanonical);
                }
                let storage = ReplaySystemAuthorityStoragePlan::Rotation {
                    history: ReplaySystemAuthorityHistory {
                        record: record.clone(),
                        root: history.root(),
                    },
                    committee_records,
                };
                verify_rotation_storage_closure(store, &storage, command, false)?;

                let predecessor_base = OrderedBase {
                    index: entry
                        .index
                        .checked_sub(1)
                        .ok_or(JournalStoreError::NonCanonical)?,
                    head: entry.parent,
                };
                let successor_base = OrderedBase {
                    index: entry.index,
                    head: Some(entry.id()),
                };
                let predecessor_control =
                    derive_lane_state::<core::convert::Infallible, core::convert::Infallible>(
                        entry.genesis,
                        entry.input.runtime.clone(),
                        PersistedLane::Control,
                        LaneCursor::Ordered {
                            base: predecessor_base,
                        },
                        write.predecessor_control(),
                    )
                    .map_err(|_| JournalStoreError::NonCanonical)?
                    .id();
                let successor_control =
                    derive_lane_state::<core::convert::Infallible, core::convert::Infallible>(
                        entry.genesis,
                        current.heads().runtime.clone(),
                        PersistedLane::Control,
                        LaneCursor::Ordered {
                            base: successor_base,
                        },
                        write.successor_control(),
                    )
                    .map_err(|_| JournalStoreError::NonCanonical)?
                    .id();
                let predecessor_view = ReplayedSystemAuthorityView::from_authenticated_replay(
                    scope,
                    write.predecessor_authority(),
                    store.instance_id(),
                    pending.predecessor_heads(),
                    predecessor_control,
                )
                .map_err(|_| JournalStoreError::NonCanonical)?;
                let successor_view = ReplayedSystemAuthorityView::from_authenticated_replay(
                    scope,
                    write.successor_authority(),
                    store.instance_id(),
                    current.heads_id(),
                    successor_control,
                )
                .map_err(|_| JournalStoreError::NonCanonical)?;
                if predecessor_view.route() != pending.route()
                    || predecessor_view.control_state() != pending.control_state()
                    || predecessor_view.commitment() != pending.state_view_commitment()
                    || predecessor_view.authority_state_commitment()
                        != pending.authority_state_commitment()
                    || successor_view.route() != current_view.route()
                    || successor_view.control_state() != current_view.control_state()
                    || successor_view.commitment() != current_view.commitment()
                    || successor_view.authority_state_commitment()
                        != current_view.authority_state_commitment()
                {
                    return Err(JournalStoreError::NonCanonical);
                }

                let facts = SystemAuthorityRotationPublicationFacts {
                    journal_store: store.instance_id(),
                    predecessor_heads: pending.predecessor_heads(),
                    successor_heads: current.heads_id(),
                    ordered_entry: entry.clone(),
                    predecessor_control,
                    successor_control,
                    predecessor_view: predecessor_view.commitment(),
                    successor_view: successor_view.commitment(),
                    predecessor_authority_state: predecessor_view.authority_state_commitment(),
                    successor_authority_state: successor_view.authority_state_commitment(),
                    claim: pending.claim(),
                    command: command.clone(),
                    operation: write.operation(),
                    result: write.result().clone(),
                    record: record.clone(),
                    root: history.root(),
                    storage_plan: rotation_storage_plan_commitment(history)?,
                };
                if !pending.matches_publication_facts(&facts) {
                    return Err(JournalStoreError::NonCanonical);
                }
                Ok(RecoveredSystemAuthorityRotation {
                    store,
                    pending,
                    facts,
                    current,
                    publication: None,
                    executions: Vec::new(),
                })
            },
        )??;
        Ok(PendingSystemAuthorityRotationRecovery::Retired(retired))
    }

    /// Reconcile one cold pending catalog claim without recreating signing
    /// authority. Only a fresh vacant-proof claim can own a durable intent;
    /// occupied exact-retry and conflict outcomes never enter this path.
    #[cfg(feature = "storage")]
    pub(crate) fn recover_pending_system_authority_catalog<'store, S, E>(
        store: &'store mut S,
        executor: &mut E,
        current: ReplayMaterialization,
        pending: PendingSystemAuthorityRecovery,
        owner: &SystemAuthorityLedgerRouteOwner,
    ) -> Result<
        PendingSystemAuthorityCatalogRecovery<'store, S>,
        SystemAuthorityRecoveryError<E::Error>,
    >
    where
        S: AgentJournalStore
            + ReverifiedRootJournalStore
            + SystemAuthorityPublicationStore
            + SystemAuthorityHistoryStore
            + ReplaySource<Error = JournalStoreError>,
        E: ReplayExecutor,
    {
        if store.instance_id() != pending.journal_store()
            || !matches!(
                pending.request(),
                SystemAuthorityLedgerClaim::Catalog { .. }
            )
        {
            return Err(JournalStoreError::NonCanonical.into());
        }
        let (_scope, current_view) = materialized_system_authority_view(store, &current)?;
        if current.heads_id() == pending.predecessor_heads() {
            owner.recheck_pending_recovery(&pending)?;
            if current_view.route() != pending.route()
                || current_view.journal_store() != pending.journal_store()
                || current_view.heads() != pending.predecessor_heads()
                || current_view.control_state() != pending.control_state()
                || current_view.commitment() != pending.state_view_commitment()
                || current_view.authority_state_commitment() != pending.authority_state_commitment()
            {
                return Err(JournalStoreError::NonCanonical.into());
            }
            let Some(entry) = pending.expected_ordered_entry().cloned() else {
                return Ok(PendingSystemAuthorityCatalogRecovery::Pending(
                    ReconciledPendingSystemAuthorityCatalog {
                        store,
                        current,
                        pending,
                    },
                ));
            };
            let stable_pending = pending.clone();
            let retired = owner.with_pending_catalog_recovery_and_retirement(
                &stable_pending,
                move |frozen| {
                    let prepared = match prepare_ordered(store, executor, &current, &entry)
                        .map_err(SystemAuthorityRecoveryError::Replay)?
                    {
                        ReplayPreparation::Ready(prepared) => prepared,
                        ReplayPreparation::AlreadyCommitted(_) => {
                            return Err(SystemAuthorityRecoveryError::Journal(
                                JournalStoreError::Conflict,
                            ));
                        }
                    };
                    prepared
                        .prepare_pending_system_authority_catalog(pending, frozen)
                        .and_then(
                            PreparedPendingSystemAuthorityCatalogPublication::publish_recovered,
                        )
                        .map_err(SystemAuthorityRecoveryError::Journal)
                },
            )??;
            return Ok(PendingSystemAuthorityCatalogRecovery::Retired(retired));
        }

        let expected_successor = pending
            .expected_successor_heads()
            .ok_or(SystemAuthorityLedgerError::PublicationRecoveryRequired)?;
        let expected_entry_id = pending
            .expected_ordered_entry_id()
            .ok_or(SystemAuthorityLedgerError::PublicationRecoveryRequired)?;
        let expected_entry = pending
            .expected_ordered_entry()
            .cloned()
            .ok_or(SystemAuthorityLedgerError::PublicationRecoveryRequired)?;
        if current.heads_id() != expected_successor
            || current.heads().previous != Some(pending.predecessor_heads())
            || current.heads().ordered_head != Some(expected_entry_id)
        {
            return Err(JournalStoreError::Conflict.into());
        }

        let stable_pending = pending.clone();
        let retired = owner.with_pending_catalog_recovery_and_retirement(
            &stable_pending,
            move |frozen| {
                let (scope, current_view) = materialized_system_authority_view(store, &current)?;
                let final_write = current
                    .final_system_authority_write
                    .as_ref()
                    .ok_or(JournalStoreError::NonCanonical)?;
                let entry = &final_write.entry;
                let write = &final_write.write;
                let stored = store
                    .get::<OrderedEntry>(entry.id())?
                    .ok_or(JournalStoreError::MissingObject)?;
                let ReplayOperation::Management {
                    request: LifecycleRequest::FinalizeCatalog(command),
                } = &entry.input.operation
                else {
                    return Err(JournalStoreError::NonCanonical);
                };
                let StandardSystemAuthorityWrite::Catalog {
                    record: Some(record),
                    history,
                } = write.selected()
                else {
                    return Err(JournalStoreError::NonCanonical);
                };
                let LifecycleReply::CatalogFinalized(outcome) = write.result() else {
                    return Err(JournalStoreError::NonCanonical);
                };
                let SystemAuthorityLedgerClaim::Catalog {
                    committee,
                    fact,
                    proof,
                } = pending.request()
                else {
                    return Err(JournalStoreError::NonCanonical);
                };
                if stored != *entry
                    || *entry != expected_entry
                    || entry.id() != expected_entry_id
                    || entry.id() != current.heads().ordered_head.unwrap_or_default()
                    || entry.index != current.heads().ordered_index
                    || write.successor_control() != current.state.control
                    || write.operation() != command.operation_commitment()
                    || command.receipt().certificate() != frozen
                    || command.receipt().fact() != fact
                    || command.proof() != proof
                    || proof.occupied_record_id().is_some()
                    || record.receipt() != command.receipt()
                    || committee != write.predecessor_authority().current_committee()
                    || pending.claim() != fact.authority_claim()
                    || !catalog_outcome_matches_record(*outcome, record, false)
                    || !history.inserted()
                {
                    return Err(JournalStoreError::NonCanonical);
                }

                let reapplied = write
                    .predecessor_authority()
                    .apply_catalog_finalize(scope, command)
                    .map_err(|_| JournalStoreError::NonCanonical)?;
                if reapplied.outcome() != *outcome
                    || reapplied.state() != write.successor_authority()
                    || reapplied.record() != Some(record)
                    || reapplied.history() != history
                {
                    return Err(JournalStoreError::NonCanonical);
                }
                validate_fresh_catalog_state_transition(
                    scope,
                    write.predecessor_authority(),
                    write.successor_authority(),
                    record,
                    history,
                )?;
                let committee_record = SystemAuthorityCommitteeRecord::new(committee.clone())
                    .map_err(|_| JournalStoreError::NonCanonical)?;
                let storage = ReplaySystemAuthorityStoragePlan::Catalog {
                    history: ReplaySystemAuthorityCatalogHistory {
                        record: record.clone(),
                        root: history.root(),
                    },
                    committee_record: committee_record.clone(),
                };
                verify_catalog_storage_closure(store, &storage, command)?;

                let predecessor_base = OrderedBase {
                    index: entry
                        .index
                        .checked_sub(1)
                        .ok_or(JournalStoreError::NonCanonical)?,
                    head: entry.parent,
                };
                let successor_base = OrderedBase {
                    index: entry.index,
                    head: Some(entry.id()),
                };
                let predecessor_control =
                    derive_lane_state::<core::convert::Infallible, core::convert::Infallible>(
                        entry.genesis,
                        entry.input.runtime.clone(),
                        PersistedLane::Control,
                        LaneCursor::Ordered {
                            base: predecessor_base,
                        },
                        write.predecessor_control(),
                    )
                    .map_err(|_| JournalStoreError::NonCanonical)?
                    .id();
                let successor_control =
                    derive_lane_state::<core::convert::Infallible, core::convert::Infallible>(
                        entry.genesis,
                        current.heads().runtime.clone(),
                        PersistedLane::Control,
                        LaneCursor::Ordered {
                            base: successor_base,
                        },
                        write.successor_control(),
                    )
                    .map_err(|_| JournalStoreError::NonCanonical)?
                    .id();
                let predecessor_view = ReplayedSystemAuthorityView::from_authenticated_replay(
                    scope,
                    write.predecessor_authority(),
                    store.instance_id(),
                    pending.predecessor_heads(),
                    predecessor_control,
                )
                .map_err(|_| JournalStoreError::NonCanonical)?;
                let successor_view = ReplayedSystemAuthorityView::from_authenticated_replay(
                    scope,
                    write.successor_authority(),
                    store.instance_id(),
                    current.heads_id(),
                    successor_control,
                )
                .map_err(|_| JournalStoreError::NonCanonical)?;
                if predecessor_view.route() != pending.route()
                    || predecessor_view.control_state() != pending.control_state()
                    || predecessor_view.commitment() != pending.state_view_commitment()
                    || predecessor_view.authority_state_commitment()
                        != pending.authority_state_commitment()
                    || successor_view.route() != current_view.route()
                    || successor_view.control_state() != current_view.control_state()
                    || successor_view.commitment() != current_view.commitment()
                    || successor_view.authority_state_commitment()
                        != current_view.authority_state_commitment()
                {
                    return Err(JournalStoreError::NonCanonical);
                }

                let facts = SystemAuthorityCatalogPublicationFacts {
                    journal_store: store.instance_id(),
                    predecessor_heads: pending.predecessor_heads(),
                    successor_heads: current.heads_id(),
                    ordered_entry: entry.clone(),
                    predecessor_control,
                    successor_control,
                    predecessor_view: predecessor_view.commitment(),
                    successor_view: successor_view.commitment(),
                    predecessor_authority_state: predecessor_view.authority_state_commitment(),
                    successor_authority_state: successor_view.authority_state_commitment(),
                    claim: pending.claim(),
                    command: command.clone(),
                    operation: write.operation(),
                    result: write.result().clone(),
                    record: record.clone(),
                    root: history.root(),
                    storage_plan: catalog_storage_plan_commitment(
                        record,
                        history,
                        &committee_record,
                    )?,
                };
                if !pending.matches_catalog_publication_facts(&facts) {
                    return Err(JournalStoreError::NonCanonical);
                }
                Ok(RecoveredSystemAuthorityCatalog {
                    store,
                    pending,
                    facts,
                    current,
                    publication: None,
                    executions: Vec::new(),
                })
            },
        )??;
        Ok(PendingSystemAuthorityCatalogRecovery::Retired(retired))
    }

    fn successor_heads(current: &JournalHeads) -> Result<JournalHeads, ReplayValidationError> {
        let mut next = current.clone();
        next.publication_revision = current
            .publication_revision
            .checked_add(1)
            .ok_or(ReplayError::ReplayLimit)?;
        next.previous = Some(current.id());
        Ok(next)
    }

    fn authenticated_materialization<ResolverError, ExecutorError>(
        materialization: &ReplayMaterialization,
    ) -> Result<(), MaterializeError<ResolverError, ExecutorError>> {
        validate_runtime_state_bound(&materialization.state)?;
        materialization
            .suffix_budget
            .validate()
            .map_err(lift_validation)?;
        materialization
            .ordered_snapshots
            .validate()
            .map_err(lift_validation)?;
        if let Some(final_write) = &materialization.final_system_authority_write {
            let decoded = decode_standard_runtime_state(&materialization.state)
                .map_err(|_| ReplayError::InvalidRecord)?;
            let request = match &final_write.entry.input.operation {
                ReplayOperation::Management { request }
                    if matches!(
                        request,
                        LifecycleRequest::FinalizeSystemAuthority(_)
                            | LifecycleRequest::RotateSystemAuthority(_)
                            | LifecycleRequest::FinalizeCatalog(_)
                    ) =>
                {
                    request
                }
                _ => return Err(ReplayError::InvalidRecord),
            };
            if materialization.replayed_root.is_none()
                || final_write.entry.validate().is_err()
                || final_write.entry.genesis != materialization.heads.genesis
                || final_write.entry.id() != materialization.heads.ordered_head.unwrap_or_default()
                || final_write.entry.index != materialization.heads.ordered_index
                || final_write.entry.input.runtime != materialization.heads.runtime
                || final_write.write.operation() != request.commitment()
                || final_write.write.successor_control() != materialization.state.control
                || decoded.system_authority.as_ref()
                    != Some(final_write.write.successor_authority())
            {
                return Err(ReplayError::InvalidRecord);
            }
        }
        if materialization.merge_boundary_state.len() > MAX_RUNTIME_STATE_BYTES {
            return Err(ReplayError::ReplayLimit);
        }
        if materialization.heads.validate().is_err()
            || materialization.heads.id() != materialization.heads_id
            || materialization.ordered_base().validate().is_err()
            || !materialization.fence_ancestry.validate()
            || materialization.fence_ancestry.genesis() != materialization.heads.genesis
            || materialization.fence_ancestry.checkpoint_base() != materialization.replay_boundary
            || materialization.fence_ancestry.canonical_head() != materialization.ordered_base()
            || materialization.fence_ancestry.fence() != materialization.heads.merge_fence
            || materialization.heads.runtime != *materialization.runtime()
            || materialization
                .ordered_snapshots
                .get(&materialization.ordered_base())
                .is_none_or(|snapshot| {
                    snapshot.runtime != materialization.heads.runtime
                        || snapshot.control != materialization.state.control
                        || snapshot.linear != materialization.state.linear
                })
            || materialization
                .merge_roots
                .windows(2)
                .any(|pair| pair[0].id >= pair[1].id)
            || !materialization
                .merge_boundary_roots
                .is_subset(&materialization.merge_boundary_ancestry)
            || !materialization
                .merge_boundary_ancestry
                .is_subset(&materialization.merge_ancestry)
            || materialization.merge_boundary_invocations == InvocationIndexId::ZERO
            || materialization
                .merge_roots
                .iter()
                .any(|root| !materialization.merge_ancestry.contains(&root.id))
        {
            return Err(ReplayError::InvalidRecord);
        }
        Ok(())
    }

    fn require_current_materialization<S, ResolverError, ExecutorError>(
        store: &S,
        materialization: &ReplayMaterialization,
    ) -> Result<(), MaterializeError<ResolverError, ExecutorError>>
    where
        S: AgentJournalStore,
    {
        authenticated_materialization(materialization)?;
        let durable = store
            .heads()
            .map_err(journal)?
            .ok_or_else(|| journal(JournalStoreError::NotInitialized))?;
        if durable != materialization.heads || durable.id() != materialization.heads_id {
            return Err(journal(JournalStoreError::Conflict));
        }
        Ok(())
    }

    fn outcome_anchor_input<S>(
        store: &S,
        genesis: AgentJournalGenesisId,
        outcome: &InvocationOutcomeRecord,
    ) -> Result<ReplayInput, RecoveryError>
    where
        S: AgentJournalStore,
    {
        let input = match outcome.anchor {
            InvocationOutcomeAnchor::Ordered { entry } => {
                let record: OrderedEntry = require_record(store, entry)?;
                if record.validate().is_err() || record.id() != entry || record.genesis != genesis {
                    return Err(ReplayError::InvalidRecord);
                }
                record.input
            }
            InvocationOutcomeAnchor::Local { entry } => {
                let record: LocalEntry = require_record(store, entry)?;
                if record.validate().is_err()
                    || record.id() != entry
                    || record.genesis != genesis
                    || record.node != outcome.node.ok_or(ReplayError::InvalidRecord)?
                {
                    return Err(ReplayError::InvalidRecord);
                }
                record.input
            }
            InvocationOutcomeAnchor::Merge {
                source_event,
                finalizing_entry,
                seal,
            } => {
                let source: MergeEvent = require_record(store, source_event)?;
                let finalizer: OrderedEntry = require_record(store, finalizing_entry)?;
                let sealed: MergeSeal = require_record(store, seal)?;
                let finalizer_base = OrderedBase {
                    index: finalizer
                        .index
                        .checked_sub(1)
                        .ok_or(ReplayError::InvalidRecord)?,
                    head: finalizer.parent,
                };
                if source.validate().is_err()
                    || source.id() != source_event
                    || finalizer.validate().is_err()
                    || finalizer.id() != finalizing_entry
                    || sealed.validate().is_err()
                    || sealed.id() != seal
                    || source.genesis != genesis
                    || finalizer.genesis != genesis
                    || sealed.genesis != genesis
                    || finalizer.merge_seal != Some(seal)
                    || sealed.frontier != finalizer.merge_frontier
                    || sealed.ordered_base != finalizer_base
                {
                    return Err(ReplayError::InvalidRecord);
                }
                source.input
            }
        };
        if input.id() != outcome.first_input || outcome.validate_for(&input).is_err() {
            return Err(ReplayError::InvalidRecord);
        }
        Ok(input)
    }

    fn recovery_position_matches_outcome_anchor(
        position: ReplayPosition,
        anchor: InvocationOutcomeAnchor,
    ) -> bool {
        matches!(
            (position, anchor),
            (
                ReplayPosition::Ordered { id, .. },
                InvocationOutcomeAnchor::Ordered { entry }
            ) if id == entry
        ) || matches!(
            (position, anchor),
            (
                ReplayPosition::Local { id, .. },
                InvocationOutcomeAnchor::Local { entry }
            ) if id == entry
        ) || matches!(
            (position, anchor),
            (
                ReplayPosition::Merge { id, .. },
                InvocationOutcomeAnchor::Merge { source_event, .. }
            ) if id == source_event
        )
    }

    /// Whether the caller position is part of the exact journal closure
    /// authenticated by the current durable heads. Merely resolving a valid
    /// content-addressed object is insufficient: stores intentionally permit
    /// objects to be staged before their heads CAS.
    fn recovery_position_is_reachable(
        materialization: &ReplayMaterialization,
        position: ReplayPosition,
    ) -> bool {
        match position {
            ReplayPosition::Ordered { id, .. } => {
                materialization.heads.ordered_head == Some(id)
                    || materialization.suffix_budget.ordered.contains(&id)
            }
            ReplayPosition::Merge { id, .. } => materialization.merge_ancestry.contains(&id),
            ReplayPosition::Local { id, .. } => {
                materialization.heads.local_head == Some(id)
                    || materialization.suffix_budget.local.contains(&id)
            }
            ReplayPosition::Genesis => false,
        }
    }

    /// Recover a committed response through its exact content-addressed
    /// journal anchor and the invocation index authenticated by current
    /// durable heads.
    ///
    /// This is intentionally independent of historical runtime snapshots.
    /// A checkpoint may compact the transition's pre-state while retaining a
    /// live outcome and its journal anchors. The exact caller-provided input
    /// and position act only as a nondisclosing lookup capability: malformed,
    /// missing, or non-byte-identical anchors return `NotCommitted` before an
    /// ownership leaf or result is exposed. Existing authenticated objects
    /// which fail their own canonical invariants remain hard corruption.
    pub(crate) fn recover_invocation<S>(
        store: &mut S,
        materialization: &ReplayMaterialization,
        input: &ReplayInput,
        position: ReplayPosition,
    ) -> Result<ReplayInvocationRecovery, RecoveryError>
    where
        S: AgentJournalStore,
    {
        require_current_materialization(store, materialization)?;
        if input.validate().is_err()
            || validate_position::<
                ReplayMaterializationSourceError<core::convert::Infallible>,
                core::convert::Infallible,
            >(input, position)
            .is_err()
        {
            return Ok(ReplayInvocationRecovery::NotCommitted);
        }
        let (invocation, operation) = match &input.operation {
            ReplayOperation::Invoke { invocation, .. } => {
                (invocation, InvocationOwnershipOperation::Invoke)
            }
            ReplayOperation::Acknowledge { invocation, .. } => {
                (invocation, InvocationOwnershipOperation::Acknowledge)
            }
            ReplayOperation::Management { .. }
            | ReplayOperation::CleanInvoke { .. }
            | ReplayOperation::SealMerge => {
                return Err(ReplayError::InvalidPosition);
            }
        };
        let (scope, committed_input) = match position {
            ReplayPosition::Genesis => return Err(ReplayError::InvalidPosition),
            ReplayPosition::Ordered {
                id,
                index,
                merge_frontier,
                merge_seal,
            } => {
                let Some(entry): Option<OrderedEntry> =
                    AgentJournalStore::get(store, id).map_err(journal)?
                else {
                    return Ok(ReplayInvocationRecovery::NotCommitted);
                };
                if entry.validate().is_err() || entry.id() != id {
                    return Err(ReplayError::InvalidRecord);
                }
                if entry.genesis != materialization.heads.genesis
                    || entry.index != index
                    || entry.merge_frontier != merge_frontier
                    || entry.merge_seal != merge_seal
                {
                    return Ok(ReplayInvocationRecovery::NotCommitted);
                }
                (InvocationOwnershipScope::Ordered, entry.input)
            }
            ReplayPosition::Merge {
                id,
                causal_height,
                ordered_base,
            } => {
                let Some(event): Option<MergeEvent> =
                    AgentJournalStore::get(store, id).map_err(journal)?
                else {
                    return Ok(ReplayInvocationRecovery::NotCommitted);
                };
                if event.validate().is_err() || event.id() != id {
                    return Err(ReplayError::InvalidRecord);
                }
                if event.genesis != materialization.heads.genesis
                    || event.causal_height != causal_height
                    || event.ordered_base != ordered_base
                {
                    return Ok(ReplayInvocationRecovery::NotCommitted);
                }
                (InvocationOwnershipScope::Merge, event.input)
            }
            ReplayPosition::Local {
                id,
                node,
                revision,
                ordered_base,
                merge_frontier,
            } => {
                let Some(entry): Option<LocalEntry> =
                    AgentJournalStore::get(store, id).map_err(journal)?
                else {
                    return Ok(ReplayInvocationRecovery::NotCommitted);
                };
                if entry.validate().is_err() || entry.id() != id {
                    return Err(ReplayError::InvalidRecord);
                }
                if entry.genesis != materialization.heads.genesis
                    || entry.node != node
                    || entry.revision != revision
                    || entry.ordered_base != ordered_base
                    || entry.merge_frontier != merge_frontier
                {
                    return Ok(ReplayInvocationRecovery::NotCommitted);
                }
                (InvocationOwnershipScope::Local(node), entry.input)
            }
        };
        if committed_input != *input {
            return Ok(ReplayInvocationRecovery::NotCommitted);
        }
        let position_reachable = recovery_position_is_reachable(materialization, position);
        if matches!(scope, InvocationOwnershipScope::Local(node) if node != materialization.heads.node)
        {
            return Ok(ReplayInvocationRecovery::NotCommitted);
        }
        let expected_lane = result_lane(invocation.mode.result_storage());
        let expected_node = match scope {
            InvocationOwnershipScope::Local(node) => Some(node),
            InvocationOwnershipScope::Ordered | InvocationOwnershipScope::Merge => None,
        };
        let key = InvocationOwnershipKey {
            scope,
            invocation: invocation.invocation,
        };
        let indexes = InvocationIndexes::open(
            store,
            materialization.heads.ordered_invocations,
            materialization.heads.merge_invocations,
            materialization.heads.local_invocations,
        )
        .map_err(|_| ReplayError::InvocationOwnership(InvocationOwnershipError::Unauthenticated))?;
        let lookup =
            InvocationOwnership::lookup(&indexes, key).map_err(ReplayError::InvocationOwnership)?;
        let owner = match lookup {
            Some(InvocationIndexLookup::Archived(fact)) => {
                if !position_reachable {
                    return Ok(ReplayInvocationRecovery::NotCommitted);
                }
                validate_archived_for_input(fact, materialization.heads.genesis, key, input)
                    .map_err(ReplayError::InvocationOwnership)?;
                return Ok(if fact.request_commitment() == invocation.commitment() {
                    ReplayInvocationRecovery::Acknowledged
                } else {
                    ReplayInvocationRecovery::Divergent
                });
            }
            Some(InvocationIndexLookup::Live(owner)) => owner,
            None => return Ok(ReplayInvocationRecovery::NotCommitted),
        };
        // A staged object which lost (or has not yet attempted) its heads CAS
        // is not a recovery capability. The sole exception is a retained
        // result requested through its permanent authenticated outcome anchor;
        // checkpoint/GC may legitimately prune that anchor from the live
        // suffix while keeping it reachable from the ownership outcome.
        let mut authenticated_outcome = None;
        if !position_reachable {
            if operation == InvocationOwnershipOperation::Acknowledge
                || !matches!(owner.result_state, InvocationResultState::Retained { .. })
            {
                return Ok(ReplayInvocationRecovery::NotCommitted);
            }
            let outcome = InvocationOwnership::outcome(&indexes, key)
                .map_err(ReplayError::InvocationOwnership)?
                .ok_or(ReplayError::InvocationOwnership(
                    InvocationOwnershipError::Unauthenticated,
                ))?;
            if !recovery_position_matches_outcome_anchor(position, outcome.anchor) {
                return Ok(ReplayInvocationRecovery::NotCommitted);
            }
            authenticated_outcome = Some(outcome);
        }
        if owner.validate().is_err()
            || owner.scope != scope
            || owner.lane != expected_lane
            || owner.node != expected_node
        {
            return Err(ReplayError::InvocationOwnership(
                InvocationOwnershipError::Unauthenticated,
            ));
        }
        if owner.request_commitment != invocation.commitment() {
            return Ok(if position_reachable {
                ReplayInvocationRecovery::Divergent
            } else {
                ReplayInvocationRecovery::NotCommitted
            });
        }
        match owner.result_state {
            InvocationResultState::PendingMerge { source_event } => {
                let exact_source = operation == InvocationOwnershipOperation::Invoke
                    && matches!(position, ReplayPosition::Merge { id, .. } if id == source_event)
                    && materialization.merge_ancestry.contains(&source_event);
                Ok(if position_reachable && exact_source {
                    ReplayInvocationRecovery::Pending
                } else {
                    ReplayInvocationRecovery::NotCommitted
                })
            }
            InvocationResultState::PendingMergeAcknowledgement {
                acknowledgement_event,
                ..
            } => {
                let Some(position_event) = (match position {
                    ReplayPosition::Merge { id, .. } => Some(id),
                    ReplayPosition::Genesis
                    | ReplayPosition::Ordered { .. }
                    | ReplayPosition::Local { .. } => None,
                }) else {
                    return Ok(ReplayInvocationRecovery::NotCommitted);
                };
                if !position_reachable
                    || !materialization
                        .merge_ancestry
                        .contains(&acknowledgement_event)
                {
                    return Ok(ReplayInvocationRecovery::NotCommitted);
                }
                let exact_event = match operation {
                    InvocationOwnershipOperation::Acknowledge => {
                        position_event == acknowledgement_event
                    }
                    InvocationOwnershipOperation::Invoke => {
                        let outcome = InvocationOwnership::outcome(&indexes, key)
                            .map_err(ReplayError::InvocationOwnership)?
                            .ok_or(ReplayError::InvocationOwnership(
                                InvocationOwnershipError::Unauthenticated,
                            ))?;
                        validate_retained_outcome(
                            &outcome,
                            materialization.heads.genesis,
                            key,
                            owner,
                            input,
                        )
                        .map_err(ReplayError::InvocationOwnership)?;
                        let first_input =
                            outcome_anchor_input(store, materialization.heads.genesis, &outcome)?;
                        first_input == *input
                            && matches!(
                                outcome.anchor,
                                InvocationOutcomeAnchor::Merge { source_event, .. }
                                    if position_event == source_event
                                        && materialization.merge_ancestry.contains(&source_event)
                            )
                    }
                };
                Ok(if exact_event {
                    ReplayInvocationRecovery::Pending
                } else {
                    ReplayInvocationRecovery::NotCommitted
                })
            }
            InvocationResultState::Retained { .. } => {
                if operation == InvocationOwnershipOperation::Acknowledge {
                    return Ok(ReplayInvocationRecovery::NotCommitted);
                }
                let outcome = match authenticated_outcome {
                    Some(outcome) => outcome,
                    None => InvocationOwnership::outcome(&indexes, key)
                        .map_err(ReplayError::InvocationOwnership)?
                        .ok_or(ReplayError::InvocationOwnership(
                            InvocationOwnershipError::Unauthenticated,
                        ))?,
                };
                let reference = owner.outcome().ok_or(ReplayError::InvocationOwnership(
                    InvocationOwnershipError::Unauthenticated,
                ))?;
                let first_input =
                    outcome_anchor_input(store, materialization.heads.genesis, &outcome)?;
                if !position_reachable
                    && !recovery_position_matches_outcome_anchor(position, outcome.anchor)
                {
                    return Ok(ReplayInvocationRecovery::NotCommitted);
                }
                if outcome.validate().is_err()
                    || outcome.genesis != materialization.heads.genesis
                    || outcome.key != key
                    || outcome.request_commitment != owner.request_commitment
                    || outcome.first_input != owner.first_input
                    || outcome.lane != owner.lane
                    || outcome.node != owner.node
                    || !outcome.request.matches_invocation(invocation)
                    || outcome.validate_for(&first_input).is_err()
                    || outcome.disposition()
                        != owner.disposition().ok_or(ReplayError::InvocationOwnership(
                            InvocationOwnershipError::Unauthenticated,
                        ))?
                    || !reference.authenticates(&outcome)
                {
                    return Err(ReplayError::InvocationOwnership(
                        InvocationOwnershipError::Unauthenticated,
                    ));
                }
                Ok(ReplayInvocationRecovery::Retained(outcome.result))
            }
        }
    }

    fn successor_artifacts<S, ResolverError, E>(
        store: &S,
        heads: &JournalHeads,
        state: &RuntimeState,
    ) -> Result<ArtifactClosure, MaterializeError<ResolverError, E::Error>>
    where
        S: AgentJournalStore,
        E: ReplayExecutor,
    {
        validate_runtime_state_bound(state)?;
        let artifacts = derive_standard_artifact_closure(heads.genesis, &heads.runtime, state)
            .map_err(lift_validation)?;
        authenticate_artifacts(store, &artifacts)?;
        Ok(artifacts)
    }

    fn claim_lane_matches(
        projection: &SharedLaneProjection,
        manifest: &LaneStateManifest,
        state: &[u8],
    ) -> bool {
        projection.manifest() == manifest.id()
            && projection.state() == &manifest.state
            && projection.verify_state(state).is_ok()
    }

    /// Read-only worst-case admission for one invocation owner. Existing
    /// members remain admissible at the ceiling; this matters for Merge,
    /// whose canonical rebuild begins at the sealed boundary rather than the
    /// current provisional index. The decision remains opaque until
    /// ReplayMachine authenticates the receipt, and a false result is
    /// consulted only when the reconstructed lookup proves the request is
    /// unseen.
    fn has_unseen_invocation_capacity<S, ResolverError, ExecutorError>(
        indexes: &InvocationIndexes<'_, S>,
        input: &ReplayInput,
        position: ReplayPosition,
    ) -> Result<UnseenInvocationAdmission, MaterializeError<ResolverError, ExecutorError>>
    where
        S: AgentJournalStore,
    {
        let ReplayOperation::Invoke { invocation, .. } = &input.operation else {
            return Ok(UnseenInvocationAdmission::Available);
        };
        let key = invocation_ownership_key(position, invocation.invocation);
        let scope = key.scope;
        let manifest = indexes.manifest(scope).map_err(|_| {
            ReplayError::InvocationOwnership(InvocationOwnershipError::Unauthenticated)
        })?;
        let reserved = manifest
            .reserved_outcome_bytes
            .checked_add(MAX_INVOCATION_OUTCOME_BYTES as u64);
        let has_capacity = manifest.entries < MAX_INVOCATION_INDEX_LIVE_ENTRIES
            && reserved.is_some_and(|bytes| bytes <= MAX_INVOCATION_INDEX_RESERVED_OUTCOME_BYTES);
        if has_capacity {
            return Ok(UnseenInvocationAdmission::Available);
        }
        let current_member = indexes
            .lookup(key)
            .map(|owner| owner.is_some())
            .map_err(|_| InvocationOwnershipError::Unauthenticated);
        Ok(UnseenInvocationAdmission::AtCapacity(current_member))
    }

    /// Prove that the current suffix can still publish the one ordered
    /// maintenance entry required to finalize pending Merge ownership.
    ///
    /// Both content IDs embedded below are fixed-width. The eventual
    /// post-Merge state can change their values but cannot change the encoded
    /// size charged here, so this is an exact, non-executing reservation.
    fn validate_merge_finalizer_capacity(
        budget: &ReplaySuffixBudget,
        genesis: AgentJournalGenesisId,
        runtime: &RuntimeBinding,
        ordered_base: OrderedBase,
        frontier: MergeFrontierId,
        merge_state: &[u8],
    ) -> Result<(), ReplayValidationError> {
        let reserved_merge_state =
            derive_lane_state::<core::convert::Infallible, core::convert::Infallible>(
                genesis,
                runtime.clone(),
                PersistedLane::Merge,
                LaneCursor::Merge { frontier },
                merge_state,
            )?;
        let reserved_seal = MergeSeal {
            genesis,
            frontier,
            ordered_base,
            merge_state: reserved_merge_state.id(),
        };
        let reserved_finalizer = OrderedEntry {
            genesis,
            index: ordered_base
                .index
                .checked_add(1)
                .ok_or(ReplayError::ReplayLimit)?,
            parent: ordered_base.head,
            merge_frontier: frontier,
            merge_seal: Some(reserved_seal.id()),
            input: ReplayInput {
                runtime: runtime.clone(),
                operation: ReplayOperation::SealMerge,
            },
        };
        if reserved_seal.validate().is_err() || reserved_finalizer.validate().is_err() {
            return Err(ReplayError::InvalidRecord);
        }
        let mut reserved = budget.clone();
        reserved.ordered(reserved_finalizer.id(), &reserved_finalizer)?;
        reserved.seal(&reserved_seal)
    }

    pub(crate) fn prepare_ordered<'store, S, E>(
        store: &'store mut S,
        executor: &mut E,
        materialization: &ReplayMaterialization,
        entry: &OrderedEntry,
    ) -> Result<ReplayPreparation<'store, S>, MaterializeError<core::convert::Infallible, E::Error>>
    where
        S: AgentJournalStore + ReplaySource<Error = JournalStoreError>,
        E: ReplayExecutor,
    {
        require_current_materialization(store, materialization)?;
        let current = &materialization.heads;
        let id = entry.id();
        if current.ordered_head == Some(id) && current.ordered_index == entry.index {
            let stored: OrderedEntry = require_record(store, id)?;
            return if stored == *entry {
                Ok(ReplayPreparation::AlreadyCommitted(
                    ReplayCommittedRecovery {
                        input: entry.input.id(),
                        position: ReplayPosition::Ordered {
                            id,
                            index: entry.index,
                            merge_frontier: entry.merge_frontier,
                            merge_seal: entry.merge_seal,
                        },
                    },
                ))
            } else {
                Err(ReplayError::InvalidRecord)
            };
        }
        if entry.validate().is_err()
            || entry.genesis != current.genesis
            || entry.parent != current.ordered_head
            || entry.index
                != current
                    .ordered_index
                    .checked_add(1)
                    .ok_or(ReplayError::ReplayLimit)?
            || entry.merge_frontier != current.merge_frontier
            || entry.input.runtime != current.runtime
        {
            return Err(ReplayError::InvalidRecord);
        }
        let fence_dependency = entry
            .merge_seal
            .map(|seal| load_fence_dependency(store, seal))
            .transpose()?;
        let mut suffix_budget = materialization.suffix_budget.clone();
        suffix_budget.ordered(id, entry).map_err(lift_validation)?;
        if let Some(dependency) = fence_dependency.as_ref() {
            suffix_budget
                .seal(&dependency.seal)
                .map_err(lift_validation)?;
        }
        let mut canonical_merge_events = Vec::new();
        if entry.merge_seal.is_some() {
            for event_id in materialization
                .merge_ancestry
                .difference(&materialization.merge_boundary_ancestry)
            {
                let event: MergeEvent = require_record(store, *event_id)?;
                if event.validate().is_err()
                    || event.id() != *event_id
                    || event.genesis != current.genesis
                {
                    return Err(ReplayError::InvalidRecord);
                }
                canonical_merge_events.push((*event_id, event));
            }
            canonical_merge_events
                .sort_unstable_by_key(|(event_id, event)| (event.causal_height, *event_id));
        }
        let mut snapshots = materialization.ordered_snapshots.clone();
        let starting_merge_index = if entry.merge_seal.is_some() {
            materialization.merge_boundary_invocations
        } else {
            current.merge_invocations
        };
        let indexes = InvocationIndexes::open(
            store,
            current.ordered_invocations,
            starting_merge_index,
            current.local_invocations,
        )
        .map_err(|_| ReplayError::InvocationOwnership(InvocationOwnershipError::Unauthenticated))?;
        if entry.merge_seal.is_none()
            && InvocationOwnership::unfinalized(&indexes, InvocationOwnershipScope::Merge)
                .map_err(ReplayError::InvocationOwnership)?
                != 0
        {
            validate_merge_finalizer_capacity(
                &suffix_budget,
                current.genesis,
                &current.runtime,
                OrderedBase {
                    index: entry.index,
                    head: Some(id),
                },
                current.merge_frontier,
                &materialization.state.merge,
            )
            .map_err(lift_validation)?;
        }
        let unseen_capacity = has_unseen_invocation_capacity(
            &indexes,
            &entry.input,
            ReplayPosition::Ordered {
                id,
                index: entry.index,
                merge_frontier: entry.merge_frontier,
                merge_seal: entry.merge_seal,
            },
        )?;
        let mut machine = if entry.merge_seal.is_some() {
            ReplayMachine {
                genesis: current.genesis,
                replayed_root: materialization.replayed_root,
                runtime: current.runtime.clone(),
                runtime_history: materialization
                    .ordered_snapshots
                    .iter()
                    .map(|(base, snapshot)| (*base, snapshot.runtime.clone()))
                    .collect(),
                ownership: indexes,
                fence: materialization.fence.clone(),
            }
        } else {
            ReplayMachine::from_materialization(materialization, indexes)
                .map_err(ReplayError::InvocationOwnership)?
        };
        let mut finalized_outcomes = Vec::new();
        let mut finalized_executions = Vec::new();
        let mut finalized_delta = InvocationIndexDelta::NONE;
        if let Some(seal) = entry.merge_seal {
            if InvocationOwnership::unfinalized(&machine.ownership, InvocationOwnershipScope::Merge)
                .map_err(ReplayError::InvocationOwnership)?
                != 0
            {
                return Err(ReplayError::InvocationOwnership(
                    InvocationOwnershipError::Unauthenticated,
                ));
            }
            let ordered = OrderedReplay {
                genesis: current.genesis,
                checkpoint: materialization.ordered_base(),
                base: materialization.ordered_base(),
                entries: Vec::new(),
                runtime_history: BTreeMap::new(),
            };
            let mut merge_state = materialization.merge_boundary_state.clone();
            let mut facts = BTreeMap::new();
            for (event_id, event) in &canonical_merge_events {
                let snapshot = snapshots
                    .get(&event.ordered_base)
                    .cloned()
                    .ok_or(ReplayError::UnavailableOrderedBase)?;
                if snapshot.runtime != event.input.runtime {
                    return Err(ReplayError::RuntimeMismatch);
                }
                machine
                    .runtime_history
                    .insert(event.ordered_base, snapshot.runtime.clone());
                let before = RuntimeState {
                    control: snapshot.control,
                    linear: snapshot.linear,
                    merge: merge_state.clone(),
                    local: materialization.state.local.clone(),
                };
                let replayed = machine
                    .verify_and_apply_merge::<
                        E,
                        ReplayMaterializationSourceError<core::convert::Infallible>,
                    >(executor, &ordered, *event_id, event, &before)
                    .map_err(historical_replay_error)?;
                merge_state = replayed.state.merge.clone();
                if facts
                    .insert(
                        *event_id,
                        MergeExecutionFact {
                            event: event.clone(),
                            before,
                            after: replayed.state.clone(),
                            result: replayed.result.clone(),
                        },
                    )
                    .is_some()
                {
                    return Err(ReplayError::InvalidRecord);
                }
            }
            if merge_state != materialization.state.merge
                || InvocationOwnership::index_id(
                    &machine.ownership,
                    InvocationOwnershipScope::Merge,
                )
                .map_err(ReplayError::InvocationOwnership)?
                    != current.merge_invocations
            {
                return Err(ReplayError::InvalidRecord);
            }
            let unfinalized = InvocationOwnership::unfinalized(
                &machine.ownership,
                InvocationOwnershipScope::Merge,
            )
            .map_err(ReplayError::InvocationOwnership)?;
            if matches!(entry.input.operation, ReplayOperation::SealMerge) && unfinalized == 0 {
                return Err(ReplayError::InvalidFence);
            }
            (finalized_delta, finalized_outcomes, finalized_executions) = machine
                .finalize_merge_outcomes(id, seal, &facts)
                .map_err(lift_validation)?;
        }
        let next_fence = match fence_dependency.as_ref() {
            Some(dependency) => Some(authenticate_action_fence(
                dependency,
                id,
                entry,
                &materialization.state,
                current.merge_frontier,
                &materialization.merge_ancestry,
            )?),
            None if entry.merge_seal.is_none() => None,
            None => return Err(ReplayError::InvalidFence),
        };
        let mut step = machine
            .apply_with_unseen_capacity::<
                _,
                ReplayMaterializationSourceError<core::convert::Infallible>,
            >(
                executor,
                &entry.input,
                &materialization.state,
                ReplayPosition::Ordered {
                    id,
                    index: entry.index,
                    merge_frontier: entry.merge_frontier,
                    merge_seal: entry.merge_seal,
                },
                Some(unseen_capacity),
            )?;
        step.ownership_delta.ordered |= finalized_delta.ordered;
        step.ownership_delta.merge |= finalized_delta.merge;
        step.ownership_delta.local |= finalized_delta.local;
        step.sealed_outcomes.extend(finalized_outcomes);
        if let Some(fence) = next_fence {
            machine.install_fence(fence)?;
        }
        let (ordered_invocations, merge_invocations, local_invocations) = machine
            .ownership_ids(current.node)
            .map_err(ReplayError::InvocationOwnership)?;
        let mut next = successor_heads(current).map_err(lift_validation)?;
        next.runtime = step.runtime.clone();
        next.ordered_head = Some(id);
        next.ordered_index = entry.index;
        next.ordered_invocations = ordered_invocations;
        next.merge_invocations = merge_invocations;
        next.local_invocations = local_invocations;
        if let Some(fence) = machine.fence.as_ref()
            && entry.merge_seal.is_some()
        {
            next.merge_fence = OrderedBase {
                index: fence.ordered_index,
                head: Some(fence.ordered_head),
            };
            next.merge_seal = Some(fence.seal);
        }
        let sealed = machine
            .seal_ordered_publication(current, entry, next.clone(), &step, materialization)
            .map_err(lift_validation)?;
        let fence_ancestry = sealed.fence_ancestry.clone();
        let fence = machine.fence.clone();
        drop(machine);
        let mut executions = vec![step.execution_result(true)];
        executions.extend(finalized_executions);

        snapshots
            .insert(
                OrderedBase {
                    index: entry.index,
                    head: Some(id),
                },
                MaterializedOrderedSnapshot {
                    runtime: step.runtime.clone(),
                    control: step.state.control.clone(),
                    linear: step.state.linear.clone(),
                },
            )
            .map_err(lift_validation)?;
        let artifacts =
            successor_artifacts::<S, core::convert::Infallible, E>(store, &next, &step.state)?;
        let (
            merge_boundary_roots,
            merge_boundary_ancestry,
            merge_boundary_state,
            merge_boundary_invocations,
        ) = if entry.merge_seal.is_some() {
            (
                materialization
                    .merge_roots
                    .iter()
                    .map(|root| root.id)
                    .collect(),
                materialization.merge_ancestry.clone(),
                step.state.merge.clone(),
                next.merge_invocations,
            )
        } else {
            (
                materialization.merge_boundary_roots.clone(),
                materialization.merge_boundary_ancestry.clone(),
                materialization.merge_boundary_state.clone(),
                materialization.merge_boundary_invocations,
            )
        };
        Ok(ReplayPreparation::Ready(ReplayPreparedPublication {
            store,
            sealed,
            successor: ReplayMaterialization {
                heads_id: next.id(),
                heads: next,
                replayed_root: materialization.replayed_root,
                final_system_authority_write: step.system_authority_write.clone().map(|write| {
                    ReplayMaterializedSystemAuthorityWrite {
                        entry: entry.clone(),
                        write,
                    }
                }),
                state: step.state,
                ordered_snapshots: snapshots,
                merge_roots: materialization.merge_roots.clone(),
                merge_boundary_roots,
                merge_boundary_ancestry,
                merge_boundary_state,
                merge_boundary_invocations,
                merge_ancestry: materialization.merge_ancestry.clone(),
                fence,
                artifacts,
                suffix_budget,
                replay_boundary: materialization.replay_boundary,
                fence_ancestry,
            },
            executions,
        }))
    }

    /// Prepare one authenticated Raft-committed Shared Ordered entry.
    ///
    /// The entry's Merge frontier is an execution dependency, not an
    /// instruction to move this replica's active Merge cursor.  Ordinary
    /// entries therefore execute against C/L + Merge(F), then splice only the
    /// resulting C/L projection into the physical C/L + Merge(G) + Local
    /// image.  A lifecycle/seal entry is the explicit exception: it finalizes
    /// exactly F and installs F as the next active Merge boundary.
    pub(crate) fn prepare_shared_ordered<'store, S, E, R>(
        store: &'store mut S,
        executor: &mut E,
        resolver: &R,
        materialization: &ReplayMaterialization,
        committed: CommittedSharedOrdered,
    ) -> Result<SharedReplayPreparation<'store, S>, MaterializeError<R::Error, E::Error>>
    where
        S: AgentJournalStore + SharedOrderedCommitStore + ReplaySource<Error = JournalStoreError>,
        E: ReplayExecutor,
        R: OrderedBaseResolver,
    {
        require_current_materialization(store, materialization)?;
        let entry = committed.authenticated_entry().map_err(lift_validation)?;
        let current = &materialization.heads;
        let id = entry.id();
        let decoded = decode_standard_runtime_state(&materialization.state)
            .map_err(|_| ReplayError::InvalidRecord)?;
        let config = decoded.config.as_ref().ok_or(ReplayError::InvalidRecord)?;
        if committed.committee.profile() != AgentProfile::Shared
            || config.identity.profile != AgentProfile::Shared
            || config.identity.space != committed.committee.space()
            || config.identity.agent != committed.committee.agent()
            || store.instance_id() != committed.journal_store
            || current.node != committed.local_node
            || current.genesis != committed.route.genesis()
            || current.admission.as_bytes() != committed.route.admission().as_bytes()
            || current.runtime.space != committed.route.space()
            || current.runtime.agent != committed.route.agent()
            || committed.route.committee() != committed.committee.id()
        {
            return Err(ReplayError::InvalidRecord);
        }
        if current.ordered_head == Some(id) && current.ordered_index == entry.index {
            let stored: OrderedEntry = require_record(store, id)?;
            let stored_commit = store
                .shared_ordered_commit(id)
                .map_err(journal)?
                .ok_or_else(|| journal(JournalStoreError::Unavailable))?;
            let claim = stored_commit.claim();
            let current_base = materialization.ordered_base();
            let control_manifest =
                derive_lane_state::<ReplayMaterializationSourceError<R::Error>, E::Error>(
                    current.genesis,
                    current.runtime.clone(),
                    PersistedLane::Control,
                    LaneCursor::Ordered { base: current_base },
                    &materialization.state.control,
                )?;
            let linear_manifest =
                derive_lane_state::<ReplayMaterializationSourceError<R::Error>, E::Error>(
                    current.genesis,
                    current.runtime.clone(),
                    PersistedLane::Linear,
                    LaneCursor::Ordered { base: current_base },
                    &materialization.state.linear,
                )?;
            let claimed_merge_manifest: LaneStateManifest =
                require_record(store, claim.merge().manifest())?;
            let claimed_merge_state =
                require_blob(store, JournalBlobClass::LaneState, claim.merge().state())?;
            let merge_projection_matches = claimed_merge_manifest.genesis == current.genesis
                && claimed_merge_manifest.runtime == entry.input.runtime
                && claimed_merge_manifest.lane == PersistedLane::Merge
                && matches!(
                    claimed_merge_manifest.cursor,
                    LaneCursor::Merge { frontier } if frontier == entry.merge_frontier
                )
                && claim_lane_matches(claim.merge(), &claimed_merge_manifest, &claimed_merge_state);
            {
                let claimed_indexes = InvocationIndexes::open(
                    store,
                    current.ordered_invocations,
                    claim.merge_invocations(),
                    current.local_invocations,
                )
                .map_err(|_| {
                    ReplayError::InvocationOwnership(InvocationOwnershipError::Unauthenticated)
                })?;
                if InvocationOwnership::index_id(&claimed_indexes, InvocationOwnershipScope::Merge)
                    .map_err(ReplayError::InvocationOwnership)?
                    != claim.merge_invocations()
                {
                    return Err(ReplayError::InvalidRecord);
                }
            }
            let sealed_matches = match (claim.sealed_merge(), current.merge_seal) {
                (None, None) if current.merge_fence == OrderedBase::post_genesis() => true,
                (Some(sealed), Some(seal)) => {
                    let dependency = load_fence_dependency::<S, R::Error, E::Error>(store, seal)?;
                    sealed.seal() == seal
                        && sealed.frontier() == dependency.seal.frontier
                        && claim_lane_matches(sealed.lane(), &dependency.state, &dependency.bytes)
                        && sealed.invocations() == materialization.merge_boundary_invocations
                }
                _ => false,
            };
            if stored != *entry
                || claim.genesis() != current.genesis
                || claim.space() != current.runtime.space
                || claim.agent() != current.runtime.agent
                || claim.admission() != committed.route.admission()
                || claim.committee() != committed.route.committee()
                || claim.raft_index() != committed.raft_index
                || claim.raft_term() != committed.raft_term
                || claim.ordered() != current_base
                || claim.merge_frontier() != entry.merge_frontier
                || stored_commit.journal_store() != committed.journal_store
                || stored_commit.raft_payload_commitment() != committed.raft_payload_commitment
                || claim.runtime() != &current.runtime
                || !claim_lane_matches(
                    claim.control(),
                    &control_manifest,
                    &materialization.state.control,
                )
                || !claim_lane_matches(
                    claim.linear(),
                    &linear_manifest,
                    &materialization.state.linear,
                )
                || claim.ordered_invocations() != current.ordered_invocations
                || claim.artifacts() != materialization.artifacts.id()
                || claim.merge_fence() != current.merge_fence
                || claim.fence_ancestry() != materialization.fence_ancestry.commitment()
                || !merge_projection_matches
                || !sealed_matches
            {
                return Err(ReplayError::InvalidRecord);
            }
            let binding = ReplaySealedSharedOrderedCommit {
                journal_store: stored_commit.journal_store(),
                claim: claim.clone(),
                raft_payload_commitment: stored_commit.raft_payload_commitment(),
            };
            let recovery = ReplayCommittedRecovery {
                input: entry.input.id(),
                position: ReplayPosition::Ordered {
                    id,
                    index: entry.index,
                    merge_frontier: entry.merge_frontier,
                    merge_seal: entry.merge_seal,
                },
            };
            let publication =
                PublishedSharedOrdered::from_binding(&binding, current.id(), committed)
                    .map_err(journal)?;
            return Ok(SharedReplayPreparation::AlreadyCommitted {
                recovery,
                publication,
            });
        }
        if entry.genesis != current.genesis
            || entry.parent != current.ordered_head
            || entry.index
                != current
                    .ordered_index
                    .checked_add(1)
                    .ok_or(ReplayError::ReplayLimit)?
            || entry.input.runtime != current.runtime
        {
            return Err(ReplayError::InvalidRecord);
        }

        let fence_dependency = entry
            .merge_seal
            .map(|seal| load_fence_dependency(store, seal))
            .transpose()?;
        let retained_fence_dependency = if entry.merge_seal.is_none() {
            current
                .merge_seal
                .map(|seal| load_fence_dependency(store, seal))
                .transpose()?
        } else {
            None
        };
        let mut suffix_budget = materialization.suffix_budget.clone();
        suffix_budget.ordered(id, entry).map_err(lift_validation)?;
        if let Some(dependency) = fence_dependency.as_ref() {
            suffix_budget
                .seal(&dependency.seal)
                .map_err(lift_validation)?;
        }

        // Reconstruct the retained boundary from the materialization rather
        // than from the current active G.  This makes missing closure for F a
        // hard unavailable/error and prevents fallback to newer replica-local
        // Merge bytes.
        let boundary_frontier = MergeFrontier {
            genesis: current.genesis,
            events: materialization
                .merge_boundary_roots
                .iter()
                .copied()
                .collect(),
        };
        if boundary_frontier.validate().is_err() {
            return Err(ReplayError::InvalidRecord);
        }
        let stored_boundary: MergeFrontier = require_record(store, boundary_frontier.id())?;
        if stored_boundary != boundary_frontier {
            return Err(ReplayError::InvalidRecord);
        }
        let mut boundary_roots = Vec::with_capacity(boundary_frontier.events.len());
        for root_id in &boundary_frontier.events {
            let event: MergeEvent = require_record(store, *root_id)?;
            if event.validate().is_err()
                || event.id() != *root_id
                || event.genesis != current.genesis
                || !executor
                    .verify_merge_event(&event)
                    .map_err(ReplayError::Executor)?
            {
                return Err(ReplayError::UnauthenticatedMergeEvent(*root_id));
            }
            boundary_roots.push(SealedMergeRoot {
                id: *root_id,
                causal_height: event.causal_height,
                ordered_base: event.ordered_base,
                runtime: event.input.runtime,
            });
        }
        let boundary = SealedMergeBase {
            structural: StructuralMergeBase {
                genesis: current.genesis,
                frontier_id: boundary_frontier.id(),
                roots: boundary_roots,
            },
        };
        let pinned =
            load_merge_suffix(store, &boundary, entry.merge_frontier).map_err(lift_replay)?;
        suffix_budget
            .frontier(&pinned.frontier)
            .map_err(lift_validation)?;
        for (event_id, event) in pinned.events() {
            suffix_budget
                .merge(*event_id, event)
                .map_err(lift_validation)?;
        }
        let pinned_base = successor_merge_base(&boundary, &pinned).map_err(lift_validation)?;
        let mut pinned_ancestry = materialization.merge_boundary_ancestry.clone();
        pinned_ancestry.extend(pinned.ancestry.iter().copied());

        // The current ownership schema has no durable `StaleAfterFence`
        // archive.  Dropping an active G-only pending owner would make its
        // InvocationId appear unseen and permit re-execution, so fences which
        // exclude any active event fail closed until that quarantine schema
        // exists.  This check precedes all pinned replay/finalization writes.
        if entry.merge_seal.is_some()
            && materialization
                .merge_ancestry
                .difference(&pinned_ancestry)
                .next()
                .is_some()
        {
            return Err(ReplayError::InvalidFence);
        }

        // An ordinary Shared Ordered splice preserves G, including its
        // pending-owner capacity obligation.
        if entry.merge_seal.is_none() {
            let physical_indexes = InvocationIndexes::open(
                store,
                current.ordered_invocations,
                current.merge_invocations,
                current.local_invocations,
            )
            .map_err(|_| {
                ReplayError::InvocationOwnership(InvocationOwnershipError::Unauthenticated)
            })?;
            if InvocationOwnership::unfinalized(&physical_indexes, InvocationOwnershipScope::Merge)
                .map_err(ReplayError::InvocationOwnership)?
                != 0
            {
                validate_merge_finalizer_capacity(
                    &suffix_budget,
                    current.genesis,
                    &current.runtime,
                    OrderedBase {
                        index: entry.index,
                        head: Some(id),
                    },
                    current.merge_frontier,
                    &materialization.state.merge,
                )
                .map_err(lift_validation)?;
            }
        }

        let mut snapshots = materialization.ordered_snapshots.clone();
        let indexes = InvocationIndexes::open(
            store,
            current.ordered_invocations,
            materialization.merge_boundary_invocations,
            current.local_invocations,
        )
        .map_err(|_| ReplayError::InvocationOwnership(InvocationOwnershipError::Unauthenticated))?;
        let mut machine = ReplayMachine {
            genesis: current.genesis,
            replayed_root: materialization.replayed_root,
            runtime: current.runtime.clone(),
            runtime_history: materialization
                .ordered_snapshots
                .iter()
                .map(|(base, snapshot)| (*base, snapshot.runtime.clone()))
                .collect(),
            ownership: indexes,
            fence: materialization.fence.clone(),
        };
        if InvocationOwnership::unfinalized(&machine.ownership, InvocationOwnershipScope::Merge)
            .map_err(ReplayError::InvocationOwnership)?
            != 0
        {
            return Err(ReplayError::InvocationOwnership(
                InvocationOwnershipError::Unauthenticated,
            ));
        }
        let ordered = OrderedReplay {
            genesis: current.genesis,
            checkpoint: materialization.ordered_base(),
            base: materialization.ordered_base(),
            entries: Vec::new(),
            runtime_history: BTreeMap::new(),
        };
        let mut pinned_state = materialization.state.clone();
        pinned_state.merge = materialization.merge_boundary_state.clone();
        let mut facts = BTreeMap::new();
        for (event_id, event) in pinned.events() {
            if event.ordered_base.index > current.ordered_index
                || (event.ordered_base.index == current.ordered_index
                    && event.ordered_base.head != current.ordered_head)
            {
                return Err(ReplayError::InvalidOrderedBase);
            }
            let snapshot = resolve_snapshot::<R, E>(
                resolver,
                current.genesis,
                materialization.ordered_base(),
                event.ordered_base,
                &mut snapshots,
            )?;
            if snapshot.runtime != event.input.runtime {
                return Err(ReplayError::RuntimeMismatch);
            }
            machine
                .runtime_history
                .insert(event.ordered_base, snapshot.runtime.clone());
            let before = RuntimeState {
                control: snapshot.control,
                linear: snapshot.linear,
                merge: pinned_state.merge.clone(),
                local: materialization.state.local.clone(),
            };
            let replayed = machine
                .verify_and_apply_merge::<E, ReplayMaterializationSourceError<R::Error>>(
                    executor, &ordered, *event_id, event, &before,
                )
                .map_err(historical_replay_error)?;
            pinned_state.merge = replayed.state.merge.clone();
            if facts
                .insert(
                    *event_id,
                    MergeExecutionFact {
                        event: event.clone(),
                        before,
                        after: replayed.state,
                        result: replayed.result,
                    },
                )
                .is_some()
            {
                return Err(ReplayError::InvalidRecord);
            }
        }
        validate_runtime_state_bound(&pinned_state)?;
        let pinned_manifest =
            derive_lane_state::<ReplayMaterializationSourceError<R::Error>, E::Error>(
                current.genesis,
                entry.input.runtime.clone(),
                PersistedLane::Merge,
                LaneCursor::Merge {
                    frontier: entry.merge_frontier,
                },
                &pinned_state.merge,
            )?;
        let observed_merge_invocations =
            InvocationOwnership::index_id(&machine.ownership, InvocationOwnershipScope::Merge)
                .map_err(ReplayError::InvocationOwnership)?;
        let observed_merge_projection =
            SharedLaneProjection::new(pinned_manifest.id(), pinned_manifest.state.clone())
                .map_err(|_| ReplayError::InvalidRecord)?;

        let committed_base = OrderedBase {
            index: entry.index,
            head: Some(id),
        };
        let retained_sealed_merge = if entry.merge_seal.is_none() {
            match current.merge_seal {
                None if current.merge_fence == OrderedBase::post_genesis() => None,
                Some(seal) => {
                    let dependency = retained_fence_dependency
                        .as_ref()
                        .ok_or(ReplayError::InvalidRecord)?;
                    if dependency.id != seal {
                        return Err(ReplayError::InvalidRecord);
                    }
                    let lane = SharedLaneProjection::new(
                        dependency.state.id(),
                        dependency.state.state.clone(),
                    )
                    .map_err(|_| ReplayError::InvalidRecord)?;
                    Some(
                        SharedSealedMergeProjection::new(
                            seal,
                            dependency.seal.frontier,
                            lane,
                            materialization.merge_boundary_invocations,
                        )
                        .map_err(|_| ReplayError::InvalidRecord)?,
                    )
                }
                _ => return Err(ReplayError::InvalidRecord),
            }
        } else {
            None
        };

        let position = ReplayPosition::Ordered {
            id,
            index: entry.index,
            merge_frontier: entry.merge_frontier,
            merge_seal: entry.merge_seal,
        };
        let unseen_capacity =
            has_unseen_invocation_capacity(&machine.ownership, &entry.input, position)?;
        let mut finalized_outcomes = Vec::new();
        let mut finalized_executions = Vec::new();
        let mut finalized_delta = InvocationIndexDelta::NONE;
        let next_fence = match fence_dependency.as_ref() {
            Some(dependency) => {
                let unfinalized = InvocationOwnership::unfinalized(
                    &machine.ownership,
                    InvocationOwnershipScope::Merge,
                )
                .map_err(ReplayError::InvocationOwnership)?;
                if matches!(entry.input.operation, ReplayOperation::SealMerge) && unfinalized == 0 {
                    return Err(ReplayError::InvalidFence);
                }
                (finalized_delta, finalized_outcomes, finalized_executions) = machine
                    .finalize_merge_outcomes(id, dependency.id, &facts)
                    .map_err(lift_validation)?;
                Some(authenticate_action_fence(
                    dependency,
                    id,
                    entry,
                    &pinned_state,
                    entry.merge_frontier,
                    &pinned_ancestry,
                )?)
            }
            None if entry.merge_seal.is_none() => None,
            None => return Err(ReplayError::InvalidFence),
        };
        let execution_before = pinned_state.clone();
        let mut step = machine
            .apply_with_unseen_capacity::<_, ReplayMaterializationSourceError<R::Error>>(
                executor,
                &entry.input,
                &execution_before,
                position,
                Some(unseen_capacity),
            )?;
        step.ownership_delta.ordered |= finalized_delta.ordered;
        step.ownership_delta.merge |= finalized_delta.merge;
        step.ownership_delta.local |= finalized_delta.local;
        step.sealed_outcomes.extend(finalized_outcomes);
        if let Some(fence) = next_fence {
            machine.install_fence(fence)?;
        }

        let (ordered_invocations, finalized_merge_invocations, local_invocations) = machine
            .ownership_ids(current.node)
            .map_err(ReplayError::InvocationOwnership)?;
        if local_invocations != current.local_invocations {
            return Err(ReplayError::CrossLaneMutation);
        }
        let installing_fence = entry.merge_seal.is_some();
        let mode = if installing_fence {
            ReplayPublicationMode::SharedOrderedInstallFence
        } else {
            ReplayPublicationMode::SharedOrderedPreserveMerge
        };
        let mut next = successor_heads(current).map_err(lift_validation)?;
        next.runtime = step.runtime.clone();
        next.ordered_head = Some(id);
        next.ordered_index = entry.index;
        next.ordered_invocations = ordered_invocations;
        next.local_invocations = current.local_invocations;
        if installing_fence {
            let fence = machine.fence.as_ref().ok_or(ReplayError::InvalidFence)?;
            next.merge_frontier = entry.merge_frontier;
            next.merge_invocations = finalized_merge_invocations;
            next.merge_fence = OrderedBase {
                index: fence.ordered_index,
                head: Some(fence.ordered_head),
            };
            next.merge_seal = Some(fence.seal);
        } else {
            next.merge_frontier = current.merge_frontier;
            next.merge_invocations = current.merge_invocations;
        }

        let mut state = step.state.clone();
        state.local = materialization.state.local.clone();
        if !installing_fence {
            state.merge = materialization.state.merge.clone();
        }
        validate_runtime_state_bound(&state)?;
        let projected_artifacts = derive_standard_artifact_closure::<core::convert::Infallible>(
            next.genesis,
            &next.runtime,
            &state,
        )
        .map_err(lift_validation)?;
        let output_base = OrderedBase {
            index: entry.index,
            head: Some(id),
        };
        let control_manifest =
            derive_lane_state::<ReplayMaterializationSourceError<R::Error>, E::Error>(
                current.genesis,
                step.runtime.clone(),
                PersistedLane::Control,
                LaneCursor::Ordered { base: output_base },
                &step.state.control,
            )?;
        let linear_manifest =
            derive_lane_state::<ReplayMaterializationSourceError<R::Error>, E::Error>(
                current.genesis,
                step.runtime.clone(),
                PersistedLane::Linear,
                LaneCursor::Ordered { base: output_base },
                &step.state.linear,
            )?;
        let derived_fence_ancestry =
            successor_fence_ancestry(materialization, &next, false, Some(entry))
                .map_err(lift_validation)?;
        let control_projection =
            SharedLaneProjection::new(control_manifest.id(), control_manifest.state.clone())
                .map_err(|_| ReplayError::InvalidRecord)?;
        let linear_projection =
            SharedLaneProjection::new(linear_manifest.id(), linear_manifest.state.clone())
                .map_err(|_| ReplayError::InvalidRecord)?;
        let sealed_merge = if installing_fence {
            Some(
                SharedSealedMergeProjection::new(
                    entry.merge_seal.ok_or(ReplayError::InvalidFence)?,
                    entry.merge_frontier,
                    observed_merge_projection.clone(),
                    finalized_merge_invocations,
                )
                .map_err(|_| ReplayError::InvalidRecord)?,
            )
        } else {
            retained_sealed_merge
        };
        let claim = OrderedCommitClaim::new(
            current.genesis,
            committed.route.admission(),
            committed.route.committee(),
            committed.raft_index,
            committed.raft_term,
            committed_base,
            entry.merge_frontier,
            observed_merge_projection,
            observed_merge_invocations,
            step.runtime.clone(),
            control_projection,
            linear_projection,
            ordered_invocations,
            projected_artifacts.id(),
            next.merge_fence,
            sealed_merge,
            derived_fence_ancestry.commitment(),
        )
        .map_err(|_| ReplayError::InvalidRecord)?;

        let sealed = machine
            .seal_shared_ordered_publication(
                current,
                entry,
                next.clone(),
                &step,
                &execution_before,
                materialization,
                &pinned_manifest,
                &pinned_state.merge,
                committed.journal_store,
                &claim,
                committed.raft_payload_commitment,
                mode,
            )
            .map_err(lift_validation)?;
        let fence_ancestry = sealed.fence_ancestry.clone();
        let fence = machine.fence.clone();
        drop(machine);
        let artifacts = successor_artifacts::<S, R::Error, E>(store, &next, &state)?;
        if artifacts != projected_artifacts {
            return Err(ReplayError::InvalidRecord);
        }
        snapshots
            .insert(
                OrderedBase {
                    index: entry.index,
                    head: Some(id),
                },
                MaterializedOrderedSnapshot {
                    runtime: step.runtime.clone(),
                    control: step.state.control.clone(),
                    linear: step.state.linear.clone(),
                },
            )
            .map_err(lift_validation)?;
        let (
            merge_roots,
            merge_boundary_roots,
            merge_boundary_ancestry,
            merge_boundary_state,
            merge_boundary_invocations,
            merge_ancestry,
        ) = if installing_fence {
            (
                pinned_base.roots().to_vec(),
                pinned_base.roots().iter().map(|root| root.id).collect(),
                pinned_ancestry.clone(),
                state.merge.clone(),
                next.merge_invocations,
                pinned_ancestry.clone(),
            )
        } else {
            (
                materialization.merge_roots.clone(),
                materialization.merge_boundary_roots.clone(),
                materialization.merge_boundary_ancestry.clone(),
                materialization.merge_boundary_state.clone(),
                materialization.merge_boundary_invocations,
                materialization.merge_ancestry.clone(),
            )
        };
        let mut executions = vec![step.execution_result(true)];
        executions.extend(finalized_executions);
        Ok(SharedReplayPreparation::Ready(
            PreparedSharedOrderedPublication {
                inner: ReplayPreparedPublication {
                    store,
                    sealed,
                    successor: ReplayMaterialization {
                        heads_id: next.id(),
                        heads: next,
                        replayed_root: materialization.replayed_root,
                        final_system_authority_write: step.system_authority_write.clone().map(
                            |write| ReplayMaterializedSystemAuthorityWrite {
                                entry: entry.clone(),
                                write,
                            },
                        ),
                        state,
                        ordered_snapshots: snapshots,
                        merge_roots,
                        merge_boundary_roots,
                        merge_boundary_ancestry,
                        merge_boundary_state,
                        merge_boundary_invocations,
                        merge_ancestry,
                        fence,
                        artifacts,
                        suffix_budget,
                        replay_boundary: materialization.replay_boundary,
                        fence_ancestry,
                    },
                    executions,
                },
                authority: committed,
            },
        ))
    }

    pub(crate) fn prepare_local<'store, S, E>(
        store: &'store mut S,
        executor: &mut E,
        materialization: &ReplayMaterialization,
        entry: &LocalEntry,
    ) -> Result<ReplayPreparation<'store, S>, MaterializeError<core::convert::Infallible, E::Error>>
    where
        S: AgentJournalStore + ReplaySource<Error = JournalStoreError>,
        E: ReplayExecutor,
    {
        require_current_materialization(store, materialization)?;
        let current = &materialization.heads;
        let id = entry.id();
        if current.local_head == Some(id) && current.local_revision == entry.revision {
            let stored: LocalEntry = require_record(store, id)?;
            return if stored == *entry {
                Ok(ReplayPreparation::AlreadyCommitted(
                    ReplayCommittedRecovery {
                        input: entry.input.id(),
                        position: ReplayPosition::Local {
                            id,
                            node: entry.node,
                            revision: entry.revision,
                            ordered_base: entry.ordered_base,
                            merge_frontier: entry.merge_frontier,
                        },
                    },
                ))
            } else {
                Err(ReplayError::InvalidRecord)
            };
        }
        if entry.validate().is_err()
            || entry.genesis != current.genesis
            || entry.node != current.node
            || entry.parent != current.local_head
            || entry.revision
                != current
                    .local_revision
                    .checked_add(1)
                    .ok_or(ReplayError::ReplayLimit)?
            || entry.ordered_base != materialization.ordered_base()
            || entry.merge_frontier != current.merge_frontier
            || entry.input.runtime != current.runtime
        {
            return Err(ReplayError::InvalidRecord);
        }
        let mut suffix_budget = materialization.suffix_budget.clone();
        suffix_budget.local(id, entry).map_err(lift_validation)?;
        let indexes = InvocationIndexes::open(
            store,
            current.ordered_invocations,
            current.merge_invocations,
            current.local_invocations,
        )
        .map_err(|_| ReplayError::InvocationOwnership(InvocationOwnershipError::Unauthenticated))?;
        if InvocationOwnership::unfinalized(&indexes, InvocationOwnershipScope::Merge)
            .map_err(ReplayError::InvocationOwnership)?
            != 0
        {
            validate_merge_finalizer_capacity(
                &suffix_budget,
                current.genesis,
                &current.runtime,
                materialization.ordered_base(),
                current.merge_frontier,
                &materialization.state.merge,
            )
            .map_err(lift_validation)?;
        }
        let position = ReplayPosition::Local {
            id,
            node: entry.node,
            revision: entry.revision,
            ordered_base: entry.ordered_base,
            merge_frontier: entry.merge_frontier,
        };
        let unseen_capacity = has_unseen_invocation_capacity(&indexes, &entry.input, position)?;
        let mut machine = ReplayMachine::from_materialization(materialization, indexes)
            .map_err(ReplayError::InvocationOwnership)?;
        let step = machine
            .apply_with_unseen_capacity::<
                _,
                ReplayMaterializationSourceError<core::convert::Infallible>,
            >(
                executor,
                &entry.input,
                &materialization.state,
                position,
                Some(unseen_capacity),
            )?;
        let (ordered_invocations, merge_invocations, local_invocations) = machine
            .ownership_ids(current.node)
            .map_err(ReplayError::InvocationOwnership)?;
        let mut next = successor_heads(current).map_err(lift_validation)?;
        next.ordered_invocations = ordered_invocations;
        next.merge_invocations = merge_invocations;
        next.local_invocations = local_invocations;
        next.local_head = Some(id);
        next.local_revision = entry.revision;
        let sealed = machine
            .seal_local_publication(current, entry, next.clone(), &step, materialization)
            .map_err(lift_validation)?;
        let fence_ancestry = sealed.fence_ancestry.clone();
        drop(machine);
        let execution = step.execution_result(true);
        let mut state = materialization.state.clone();
        state.local = step.state.local;
        validate_runtime_state_bound(&state)?;
        let artifacts =
            successor_artifacts::<S, core::convert::Infallible, E>(store, &next, &state)?;
        Ok(ReplayPreparation::Ready(ReplayPreparedPublication {
            store,
            sealed,
            successor: ReplayMaterialization {
                heads_id: next.id(),
                heads: next,
                replayed_root: materialization.replayed_root,
                final_system_authority_write: materialization.final_system_authority_write.clone(),
                state,
                ordered_snapshots: materialization.ordered_snapshots.clone(),
                merge_roots: materialization.merge_roots.clone(),
                merge_boundary_roots: materialization.merge_boundary_roots.clone(),
                merge_boundary_ancestry: materialization.merge_boundary_ancestry.clone(),
                merge_boundary_state: materialization.merge_boundary_state.clone(),
                merge_boundary_invocations: materialization.merge_boundary_invocations,
                merge_ancestry: materialization.merge_ancestry.clone(),
                fence: materialization.fence.clone(),
                artifacts,
                suffix_budget,
                replay_boundary: materialization.replay_boundary,
                fence_ancestry,
            },
            executions: vec![execution],
        }))
    }

    pub(crate) fn prepare_merge<'store, S, E, R>(
        store: &'store mut S,
        executor: &mut E,
        resolver: &R,
        materialization: &ReplayMaterialization,
        event: &MergeEvent,
    ) -> Result<ReplayPreparation<'store, S>, MaterializeError<R::Error, E::Error>>
    where
        S: AgentJournalStore + ReplaySource<Error = JournalStoreError>,
        E: ReplayExecutor,
        R: OrderedBaseResolver,
    {
        require_current_materialization(store, materialization)?;
        let current = &materialization.heads;
        let id = event.id();
        if materialization.merge_ancestry.contains(&id) {
            let stored: MergeEvent = require_record(store, id)?;
            return if stored == *event {
                Ok(ReplayPreparation::AlreadyCommitted(
                    ReplayCommittedRecovery {
                        input: event.input.id(),
                        position: ReplayPosition::Merge {
                            id,
                            causal_height: event.causal_height,
                            ordered_base: event.ordered_base,
                        },
                    },
                ))
            } else {
                Err(ReplayError::InvalidRecord)
            };
        }
        if event.validate().is_err()
            || event.genesis != current.genesis
            || event.ordered_base.index > current.ordered_index
            || (event.ordered_base.index == current.ordered_index
                && event.ordered_base.head != current.ordered_head)
        {
            return Err(ReplayError::InvalidRecord);
        }
        let current_frontier: MergeFrontier = require_record(store, current.merge_frontier)?;
        if current_frontier.genesis != current.genesis
            || current_frontier.id() != current.merge_frontier
            || !current_frontier
                .events
                .iter()
                .copied()
                .eq(materialization.merge_roots.iter().map(|root| root.id))
        {
            return Err(ReplayError::InvalidRecord);
        }
        let current_roots = materialization
            .merge_roots
            .iter()
            .map(|root| (root.id, root))
            .collect::<BTreeMap<_, _>>();
        let expected_height = if event.parents.is_empty() {
            if materialization.merge_boundary_roots.is_empty() {
                1
            } else {
                return Err(ReplayError::StaleMergeBranch(id));
            }
        } else {
            let mut parents = Vec::with_capacity(event.parents.len());
            for parent in &event.parents {
                let metadata = if let Some(root) = current_roots.get(parent) {
                    (*root).clone()
                } else if materialization.merge_ancestry.contains(parent) {
                    if materialization.merge_boundary_ancestry.contains(parent)
                        && !materialization.merge_boundary_roots.contains(parent)
                    {
                        return Err(ReplayError::StaleMergeBranch(id));
                    }
                    let retained: MergeEvent = require_record(store, *parent)?;
                    if retained.validate().is_err()
                        || retained.id() != *parent
                        || retained.genesis != current.genesis
                    {
                        return Err(ReplayError::InvalidRecord);
                    }
                    SealedMergeRoot {
                        id: *parent,
                        causal_height: retained.causal_height,
                        ordered_base: retained.ordered_base,
                        runtime: retained.input.runtime,
                    }
                } else {
                    return Err(ReplayError::StaleMergeBranch(id));
                };
                if metadata.ordered_base.index > event.ordered_base.index
                    || (metadata.ordered_base.index == event.ordered_base.index
                        && metadata.ordered_base.head != event.ordered_base.head)
                {
                    return Err(ReplayError::InvalidOrderedBase);
                }
                parents.push(metadata.causal_height);
            }
            parents
                .into_iter()
                .max()
                .and_then(|height| height.checked_add(1))
                .ok_or(ReplayError::InvalidCausalHeight)?
        };
        if event.causal_height != expected_height {
            return Err(ReplayError::InvalidCausalHeight);
        }

        let mut tips = current_frontier
            .events
            .iter()
            .copied()
            .collect::<BTreeSet<_>>();
        for parent in &event.parents {
            tips.remove(parent);
        }
        tips.insert(id);
        let frontier = MergeFrontier {
            genesis: current.genesis,
            events: tips.into_iter().collect(),
        };
        if frontier.validate().is_err() {
            return Err(ReplayError::InvalidRecord);
        }
        let mut suffix_budget = materialization.suffix_budget.clone();
        suffix_budget.merge(id, event).map_err(lift_validation)?;
        suffix_budget.frontier(&frontier).map_err(lift_validation)?;

        // Importing a Merge event creates work which cannot be checkpointed
        // until an ordered SealMerge entry finalizes it. Reserve that protocol
        // entry before authenticating or executing the source, so a successful
        // Merge CAS can never consume the last suffix capacity and strand
        // itself.
        validate_merge_finalizer_capacity(
            &suffix_budget,
            current.genesis,
            &current.runtime,
            materialization.ordered_base(),
            frontier.id(),
            &materialization.state.merge,
        )
        .map_err(lift_validation)?;
        let mut ancestry = materialization.merge_ancestry.clone();
        ancestry.insert(id);
        let replay = MergeReplay {
            genesis: current.genesis,
            checkpoint_frontier: current.merge_frontier,
            frontier_id: frontier.id(),
            frontier: frontier.clone(),
            events: vec![(id, event.clone())],
            ancestry: ancestry.clone(),
        };

        // A newly imported concurrent event may sort before already applied
        // events at the same height. Rebuild the complete post-boundary Merge
        // suffix in canonical order; incrementally appending to current bytes
        // would make state depend on arrival order.
        let mut canonical_events = Vec::new();
        for retained_id in materialization
            .merge_ancestry
            .difference(&materialization.merge_boundary_ancestry)
        {
            let retained: MergeEvent = require_record(store, *retained_id)?;
            if retained.validate().is_err()
                || retained.id() != *retained_id
                || retained.genesis != current.genesis
            {
                return Err(ReplayError::InvalidRecord);
            }
            canonical_events.push((*retained_id, retained));
        }
        canonical_events.push((id, event.clone()));
        canonical_events
            .sort_unstable_by_key(|(event_id, retained)| (retained.causal_height, *event_id));

        // The canonical rebuild starts from the sealed Merge boundary, but
        // admission capacity belongs to the current authenticated Merge
        // index. In particular, every still-pending event after that boundary
        // already owns one live slot and reserves the maximum outcome size.
        // Read the current manifest before borrowing the boundary index and
        // consult this decision only for the newly imported event; retained
        // events are historical replay and must never turn corruption into a
        // live quota refusal.
        let imported_position = ReplayPosition::Merge {
            id,
            causal_height: event.causal_height,
            ordered_base: event.ordered_base,
        };
        let unseen_capacity = {
            let current_indexes = InvocationIndexes::open(
                store,
                current.ordered_invocations,
                current.merge_invocations,
                current.local_invocations,
            )
            .map_err(|_| {
                ReplayError::InvocationOwnership(InvocationOwnershipError::Unauthenticated)
            })?;
            has_unseen_invocation_capacity(&current_indexes, &event.input, imported_position)?
        };
        let mut snapshots = materialization.ordered_snapshots.clone();
        let indexes = InvocationIndexes::open(
            store,
            current.ordered_invocations,
            materialization.merge_boundary_invocations,
            current.local_invocations,
        )
        .map_err(|_| ReplayError::InvocationOwnership(InvocationOwnershipError::Unauthenticated))?;
        let mut machine = ReplayMachine {
            genesis: current.genesis,
            replayed_root: materialization.replayed_root,
            runtime: current.runtime.clone(),
            runtime_history: materialization
                .ordered_snapshots
                .iter()
                .map(|(base, snapshot)| (*base, snapshot.runtime.clone()))
                .collect(),
            ownership: indexes,
            fence: materialization.fence.clone(),
        };
        let ordered = OrderedReplay {
            genesis: current.genesis,
            checkpoint: materialization.ordered_base(),
            base: materialization.ordered_base(),
            entries: Vec::new(),
            runtime_history: BTreeMap::new(),
        };
        let mut state = materialization.state.clone();
        state.merge = materialization.merge_boundary_state.clone();
        let mut imported_step = None;
        for (event_id, retained) in &canonical_events {
            let snapshot = resolve_snapshot::<R, E>(
                resolver,
                current.genesis,
                materialization.ordered_base(),
                retained.ordered_base,
                &mut snapshots,
            )?;
            if snapshot.runtime != retained.input.runtime {
                return Err(ReplayError::RuntimeMismatch);
            }
            machine
                .runtime_history
                .insert(retained.ordered_base, snapshot.runtime.clone());
            let before = RuntimeState {
                control: snapshot.control,
                linear: snapshot.linear,
                merge: state.merge.clone(),
                local: materialization.state.local.clone(),
            };
            let step = machine
                .verify_and_apply_merge_with_unseen_capacity::<
                    E,
                    ReplayMaterializationSourceError<R::Error>,
                >(
                    executor,
                    &ordered,
                    *event_id,
                    retained,
                    &before,
                    if *event_id == id {
                        Some(unseen_capacity)
                    } else {
                        None
                    },
                )
                .map_err(|error| {
                    if *event_id == id {
                        error
                    } else {
                        historical_replay_error(error)
                    }
                })?;
            state.merge = step.state.merge.clone();
            validate_runtime_state_bound(&state)?;
            if *event_id == id {
                imported_step = Some(step);
            }
        }
        let step = imported_step.ok_or(ReplayError::InvalidRecord)?;
        let (ordered_invocations, merge_invocations, local_invocations) = machine
            .ownership_ids(current.node)
            .map_err(ReplayError::InvocationOwnership)?;
        let mut next = successor_heads(current).map_err(lift_validation)?;
        next.merge_frontier = frontier.id();
        next.ordered_invocations = ordered_invocations;
        next.merge_invocations = merge_invocations;
        next.local_invocations = local_invocations;
        let sealed = machine
            .seal_merge_publication(
                current,
                event,
                &replay,
                next.clone(),
                &step,
                materialization,
            )
            .map_err(lift_validation)?;
        let fence_ancestry = sealed.fence_ancestry.clone();
        drop(machine);
        let artifacts = successor_artifacts::<S, R::Error, E>(store, &next, &state)?;
        let mut next_roots = materialization
            .merge_roots
            .iter()
            .filter(|root| !event.parents.contains(&root.id))
            .cloned()
            .collect::<Vec<_>>();
        next_roots.push(SealedMergeRoot {
            id,
            causal_height: event.causal_height,
            ordered_base: event.ordered_base,
            runtime: event.input.runtime.clone(),
        });
        next_roots.sort_unstable_by_key(|root| root.id);
        Ok(ReplayPreparation::Ready(ReplayPreparedPublication {
            store,
            sealed,
            successor: ReplayMaterialization {
                heads_id: next.id(),
                heads: next,
                replayed_root: materialization.replayed_root,
                final_system_authority_write: materialization.final_system_authority_write.clone(),
                state,
                ordered_snapshots: snapshots,
                merge_roots: next_roots,
                merge_boundary_roots: materialization.merge_boundary_roots.clone(),
                merge_boundary_ancestry: materialization.merge_boundary_ancestry.clone(),
                merge_boundary_state: materialization.merge_boundary_state.clone(),
                merge_boundary_invocations: materialization.merge_boundary_invocations,
                merge_ancestry: ancestry,
                fence: materialization.fence.clone(),
                artifacts,
                suffix_budget,
                replay_boundary: materialization.replay_boundary,
                fence_ancestry,
            },
            // A Merge CAS admits only the event. Its apparent disposition is
            // not final because a later same-height event can precede it in
            // the canonical rebuild. Exact outcomes become observable only
            // when an ordered seal finalizes the complete batch.
            executions: Vec::new(),
        }))
    }

    fn compact_standard_checkpoint<ResolverError, ExecutorError>(
        state: &RuntimeState,
    ) -> Result<RuntimeState, MaterializeError<ResolverError, ExecutorError>> {
        validate_runtime_state_bound(state)?;
        let decoded =
            decode_standard_runtime_state(state).map_err(|_| ReplayError::InvalidRecord)?;
        let mut runtime =
            StandardAgentRuntime::restore(decoded).map_err(|_| ReplayError::InvalidRecord)?;
        runtime.compact_historical_lane_entries_for_checkpoint();
        let compacted = encode_standard_runtime_state(&runtime.snapshot());
        validate_runtime_state_bound(&compacted)?;
        Ok(compacted)
    }

    /// Build a complete Shared checkpoint without writing any object, blob,
    /// or head. The caller combines its exact roots with the V2 ledger
    /// context, obtains voter signatures, and returns the verified capability
    /// to `PreparedSharedCheckpoint::publish_shared`.
    pub(crate) fn prepare_shared_checkpoint<S>(
        store: &mut S,
        materialization: &ReplayMaterialization,
    ) -> Result<
        PreparedSharedCheckpoint,
        MaterializeError<core::convert::Infallible, core::convert::Infallible>,
    >
    where
        S: AgentJournalStore + ReplaySource<Error = JournalStoreError>,
    {
        require_current_materialization(store, materialization)?;
        let current = &materialization.heads;
        let decoded = decode_standard_runtime_state(&materialization.state)
            .map_err(|_| ReplayError::InvalidRecord)?;
        if decoded
            .config
            .as_ref()
            .is_none_or(|config| config.identity.profile != AgentProfile::Shared)
        {
            return Err(ReplayError::InvalidRecord);
        }
        let indexes = InvocationIndexes::open(
            store,
            current.ordered_invocations,
            current.merge_invocations,
            current.local_invocations,
        )
        .map_err(|_| ReplayError::InvocationOwnership(InvocationOwnershipError::Unauthenticated))?;
        for scope in [
            InvocationOwnershipScope::Ordered,
            InvocationOwnershipScope::Merge,
            InvocationOwnershipScope::Local(current.node),
        ] {
            if InvocationOwnership::unfinalized(&indexes, scope)
                .map_err(ReplayError::InvocationOwnership)?
                != 0
            {
                return Err(ReplayError::InvocationOwnership(
                    InvocationOwnershipError::Unauthenticated,
                ));
            }
        }
        drop(indexes);
        let state = compact_standard_checkpoint(&materialization.state)?;
        let artifacts = derive_standard_artifact_closure(current.genesis, &current.runtime, &state)
            .map_err(lift_validation)?;
        authenticate_artifacts(store, &artifacts)?;
        let ordered = materialization.ordered_base();
        let cursors = [
            LaneCursor::Ordered { base: ordered },
            LaneCursor::Ordered { base: ordered },
            LaneCursor::Merge {
                frontier: current.merge_frontier,
            },
            LaneCursor::Local {
                node: current.node,
                revision: current.local_revision,
                head: current.local_head,
            },
        ];
        let persisted = [
            PersistedLane::Control,
            PersistedLane::Linear,
            PersistedLane::Merge,
            PersistedLane::Local,
        ];
        let mut lanes = Vec::new();
        let mut sealed_lanes = Vec::new();
        let mut lane_blobs = Vec::new();
        for (lane, cursor) in persisted.into_iter().zip(cursors) {
            let bytes = state_component(&state, lane);
            let reference = BlobRef::of_bytes(bytes);
            lane_blobs.push((reference.clone(), bytes.to_vec()));
            let manifest = derive_lane_state(
                current.genesis,
                current.runtime.clone(),
                lane,
                cursor,
                bytes,
            )
            .map_err(lift_validation)?;
            let checkpoint_lane = CheckpointLane {
                lane,
                node: (lane == PersistedLane::Local).then_some(current.node),
                state: manifest.id(),
                invocations: (lane == PersistedLane::Local).then_some(current.local_invocations),
            };
            lanes.push(checkpoint_lane.clone());
            sealed_lanes.push((checkpoint_lane, manifest));
        }
        let manifest = derive_checkpoint(
            current.genesis,
            current.admission,
            current.runtime.clone(),
            current.publication_revision,
            ordered,
            current.merge_frontier,
            current.merge_fence,
            current.merge_seal,
            current.ordered_invocations,
            current.merge_invocations,
            lanes,
            artifacts.id(),
        )
        .map_err(lift_validation)?;
        let id = manifest.id();
        let mut next = successor_heads(current).map_err(lift_validation)?;
        next.checkpoint = Some(id);
        let expected_indexes = [
            (
                current.ordered_invocations,
                InvocationOwnershipScope::Ordered,
            ),
            (current.merge_invocations, InvocationOwnershipScope::Merge),
            (
                current.local_invocations,
                InvocationOwnershipScope::Local(current.node),
            ),
        ];
        let mut invocation_indexes = Vec::new();
        for (index_id, scope) in expected_indexes {
            let index: InvocationIndexManifest = require_record(store, index_id)?;
            if index.id() != index_id || index.genesis != current.genesis || index.scope != scope {
                return Err(ReplayError::InvalidRecord);
            }
            invocation_indexes.push((index_id, index));
        }
        let fence_ancestry = successor_fence_ancestry(materialization, &next, true, None)
            .map_err(lift_validation)?;
        let checkpoint = ReplaySealedCheckpoint {
            manifest: manifest.clone(),
            lanes: sealed_lanes,
            artifacts: artifacts.clone(),
            invocation_indexes,
            local_cursors: vec![(current.node, current.local_revision, current.local_head)],
            fence_ancestry: fence_ancestry.clone(),
        };
        let sealed = ReplaySealedPublication {
            expected: materialization.heads_id,
            next: next.clone(),
            anchor: ReplayPublicationAnchor::Checkpoint(manifest),
            outcomes: Vec::new(),
            history_plans: Vec::new(),
            checkpoint: Some(checkpoint),
            shared_merge_projection: None,
            shared_ordered_commit: None,
            system_authority_write: None,
            fence_ancestry: fence_ancestry.clone(),
            mode: ReplayPublicationMode::Canonical,
        };
        let snapshots = MaterializedOrderedSnapshots::singleton(
            ordered,
            MaterializedOrderedSnapshot {
                runtime: current.runtime.clone(),
                control: state.control.clone(),
                linear: state.linear.clone(),
            },
        )
        .map_err(lift_validation)?;
        let checkpoint_roots = materialization
            .merge_roots
            .iter()
            .map(|root| root.id)
            .collect::<BTreeSet<_>>();
        let mut checkpoint_fence = materialization.fence.clone();
        if let Some(fence) = checkpoint_fence.as_mut() {
            fence
                .sealed_ancestry
                .retain(|event| checkpoint_roots.contains(event));
        }
        let checkpoint_merge_state = state.merge.clone();
        Ok(PreparedSharedCheckpoint {
            sealed,
            successor: ReplayMaterialization {
                heads_id: next.id(),
                heads: next,
                replayed_root: materialization.replayed_root,
                final_system_authority_write: None,
                state,
                ordered_snapshots: snapshots,
                merge_roots: materialization.merge_roots.clone(),
                merge_boundary_roots: checkpoint_roots.clone(),
                merge_boundary_ancestry: checkpoint_roots.clone(),
                merge_boundary_state: checkpoint_merge_state,
                merge_boundary_invocations: current.merge_invocations,
                merge_ancestry: checkpoint_roots,
                fence: checkpoint_fence,
                artifacts,
                suffix_budget: ReplaySuffixBudget::default(),
                replay_boundary: ordered,
                fence_ancestry,
            },
            lane_blobs,
        })
    }

    /// Revalidate a checkpoint already visible at the durable Shared head.
    /// This is the crash-recovery half of journal-first snapshot publication:
    /// a certificate retry may proceed to the atomic Raft install only when
    /// every signed root resolves to the exact current materialization.
    pub(crate) fn validate_published_shared_checkpoint<S>(
        store: &S,
        materialization: &ReplayMaterialization,
        claim: &SharedAgentSnapshotClaim,
    ) -> Result<(), MaterializeError<core::convert::Infallible, core::convert::Infallible>>
    where
        S: AgentJournalStore + ReplaySource<Error = JournalStoreError>,
    {
        let current = materialization.heads();
        let checkpoint: CheckpointManifest = require_record(store, claim.checkpoint())?;
        if checkpoint.id() != claim.checkpoint()
            || checkpoint.genesis != claim.ordered().genesis()
            || checkpoint.admission != claim.ordered().admission()
            || checkpoint.runtime != *claim.ordered().runtime()
            || checkpoint.ordered_index != claim.ordered().ordered().index
            || checkpoint.ordered_head != claim.ordered().ordered().head
            || checkpoint.ordered_invocations != claim.ordered_invocations()
            || checkpoint.merge_invocations != claim.merge_invocations()
            || checkpoint.artifacts != claim.artifacts()
        {
            return Err(ReplayError::InvalidRecord);
        }
        let mut roots = [None; 4];
        let mut local_cursor = None;
        for lane in &checkpoint.lanes {
            let manifest: LaneStateManifest = require_record(store, lane.state)?;
            let state = require_blob(store, JournalBlobClass::LaneState, &manifest.state)?;
            let expected = match lane.lane {
                PersistedLane::Control
                    if lane.node.is_none()
                        && manifest.cursor
                            == (LaneCursor::Ordered {
                                base: claim.ordered().ordered(),
                            }) =>
                {
                    0
                }
                PersistedLane::Linear
                    if lane.node.is_none()
                        && manifest.cursor
                            == (LaneCursor::Ordered {
                                base: claim.ordered().ordered(),
                            }) =>
                {
                    1
                }
                PersistedLane::Merge
                    if lane.node.is_none()
                        && manifest.cursor
                            == (LaneCursor::Merge {
                                frontier: checkpoint.merge_frontier,
                            }) =>
                {
                    2
                }
                PersistedLane::Local if lane.node == Some(claim.local_node()) => {
                    let LaneCursor::Local {
                        node,
                        revision,
                        head,
                    } = &manifest.cursor
                    else {
                        return Err(ReplayError::InvalidRecord);
                    };
                    if *node != claim.local_node()
                        || lane.invocations != Some(claim.local_invocations())
                        || local_cursor.replace((*revision, *head)).is_some()
                    {
                        return Err(ReplayError::InvalidRecord);
                    }
                    3
                }
                _ => return Err(ReplayError::InvalidRecord),
            };
            if manifest.genesis != checkpoint.genesis
                || manifest.runtime != checkpoint.runtime
                || manifest.id() != lane.state
                || manifest.state != BlobRef::of_bytes(&state)
                || roots[expected].replace(lane.state).is_some()
            {
                return Err(ReplayError::InvalidRecord);
            }
        }
        if roots
            != [
                Some(claim.control()),
                Some(claim.linear()),
                Some(claim.merge()),
                Some(claim.local()),
            ]
        {
            return Err(ReplayError::InvalidRecord);
        }
        let (local_revision, local_head) = local_cursor.ok_or(ReplayError::InvalidRecord)?;
        let snapshot_heads = JournalHeads {
            genesis: checkpoint.genesis,
            admission: checkpoint.admission,
            node: claim.local_node(),
            runtime: checkpoint.runtime.clone(),
            publication_revision: checkpoint
                .publication_revision
                .checked_add(1)
                .ok_or(ReplayError::ReplayLimit)?,
            previous: Some(claim.checkpoint_predecessor()),
            ordered_head: checkpoint.ordered_head,
            ordered_index: checkpoint.ordered_index,
            merge_frontier: checkpoint.merge_frontier,
            merge_fence: checkpoint.merge_fence,
            merge_seal: checkpoint.merge_seal,
            ordered_invocations: checkpoint.ordered_invocations,
            merge_invocations: checkpoint.merge_invocations,
            local_invocations: claim.local_invocations(),
            local_head,
            local_revision,
            checkpoint: Some(claim.checkpoint()),
        };
        if snapshot_heads.validate().is_err()
            || snapshot_heads.id() != claim.journal_heads()
            || current.checkpoint != Some(claim.checkpoint())
            || current.genesis != snapshot_heads.genesis
            || current.admission != snapshot_heads.admission
            || current.node != snapshot_heads.node
            || current.publication_revision < snapshot_heads.publication_revision
            || current.ordered_index < snapshot_heads.ordered_index
            || (current.ordered_index == snapshot_heads.ordered_index
                && (current.ordered_head != snapshot_heads.ordered_head
                    || current.runtime != snapshot_heads.runtime))
        {
            return Err(ReplayError::InvalidRecord);
        }
        Ok(())
    }

    pub(crate) fn prepare_checkpoint<'store, S>(
        store: &'store mut S,
        materialization: &ReplayMaterialization,
    ) -> Result<
        ReplayPreparedPublication<'store, S>,
        MaterializeError<core::convert::Infallible, core::convert::Infallible>,
    >
    where
        S: AgentJournalStore + ReplaySource<Error = JournalStoreError>,
    {
        require_current_materialization(store, materialization)?;
        let current = &materialization.heads;
        let decoded = decode_standard_runtime_state(&materialization.state)
            .map_err(|_| ReplayError::InvalidRecord)?;
        if decoded
            .config
            .as_ref()
            .is_some_and(|config| config.identity.profile == AgentProfile::Shared)
        {
            // Shared compaction requires a certified snapshot which retains
            // the complete ordered claim/QC and pinned Merge audit closure.
            // The canonical Local checkpoint capability carries none of that
            // authority, so it must fail closed even before ledger anchoring.
            return Err(ReplayError::InvalidRecord);
        }
        let indexes = InvocationIndexes::open(
            store,
            current.ordered_invocations,
            current.merge_invocations,
            current.local_invocations,
        )
        .map_err(|_| ReplayError::InvocationOwnership(InvocationOwnershipError::Unauthenticated))?;
        for scope in [
            InvocationOwnershipScope::Ordered,
            InvocationOwnershipScope::Merge,
            InvocationOwnershipScope::Local(current.node),
        ] {
            if InvocationOwnership::unfinalized(&indexes, scope)
                .map_err(ReplayError::InvocationOwnership)?
                != 0
            {
                return Err(ReplayError::InvocationOwnership(
                    InvocationOwnershipError::Unauthenticated,
                ));
            }
        }
        drop(indexes);
        let state = compact_standard_checkpoint(&materialization.state)?;
        let artifacts = derive_standard_artifact_closure(current.genesis, &current.runtime, &state)
            .map_err(lift_validation)?;
        authenticate_artifacts(store, &artifacts)?;
        let ordered = materialization.ordered_base();
        let cursors = [
            LaneCursor::Ordered { base: ordered },
            LaneCursor::Ordered { base: ordered },
            LaneCursor::Merge {
                frontier: current.merge_frontier,
            },
            LaneCursor::Local {
                node: current.node,
                revision: current.local_revision,
                head: current.local_head,
            },
        ];
        let persisted = [
            PersistedLane::Control,
            PersistedLane::Linear,
            PersistedLane::Merge,
            PersistedLane::Local,
        ];
        let mut lanes = Vec::new();
        let mut sealed_lanes = Vec::new();
        for (lane, cursor) in persisted.into_iter().zip(cursors) {
            let bytes = state_component(&state, lane);
            let reference = BlobRef::of_bytes(bytes);
            store
                .put_blob(JournalBlobClass::LaneState, &reference, bytes)
                .map_err(journal)?;
            let manifest = derive_lane_state(
                current.genesis,
                current.runtime.clone(),
                lane,
                cursor,
                bytes,
            )
            .map_err(lift_validation)?;
            let checkpoint_lane = CheckpointLane {
                lane,
                node: (lane == PersistedLane::Local).then_some(current.node),
                state: manifest.id(),
                invocations: (lane == PersistedLane::Local).then_some(current.local_invocations),
            };
            lanes.push(checkpoint_lane.clone());
            sealed_lanes.push((checkpoint_lane, manifest));
        }
        let manifest = derive_checkpoint(
            current.genesis,
            current.admission,
            current.runtime.clone(),
            current.publication_revision,
            ordered,
            current.merge_frontier,
            current.merge_fence,
            current.merge_seal,
            current.ordered_invocations,
            current.merge_invocations,
            lanes,
            artifacts.id(),
        )
        .map_err(lift_validation)?;
        let id = manifest.id();
        let mut next = successor_heads(current).map_err(lift_validation)?;
        next.checkpoint = Some(id);
        let expected_indexes = [
            (
                current.ordered_invocations,
                InvocationOwnershipScope::Ordered,
            ),
            (current.merge_invocations, InvocationOwnershipScope::Merge),
            (
                current.local_invocations,
                InvocationOwnershipScope::Local(current.node),
            ),
        ];
        let mut invocation_indexes = Vec::new();
        for (index_id, scope) in expected_indexes {
            let index: InvocationIndexManifest = require_record(store, index_id)?;
            if index.id() != index_id || index.genesis != current.genesis || index.scope != scope {
                return Err(ReplayError::InvalidRecord);
            }
            invocation_indexes.push((index_id, index));
        }
        let fence_ancestry = successor_fence_ancestry(materialization, &next, true, None)
            .map_err(lift_validation)?;
        let checkpoint = ReplaySealedCheckpoint {
            manifest: manifest.clone(),
            lanes: sealed_lanes,
            artifacts: artifacts.clone(),
            invocation_indexes,
            local_cursors: vec![(current.node, current.local_revision, current.local_head)],
            fence_ancestry: fence_ancestry.clone(),
        };
        let sealed = ReplaySealedPublication {
            expected: materialization.heads_id,
            next: next.clone(),
            anchor: ReplayPublicationAnchor::Checkpoint(manifest),
            outcomes: Vec::new(),
            history_plans: Vec::new(),
            checkpoint: Some(checkpoint),
            shared_merge_projection: None,
            shared_ordered_commit: None,
            system_authority_write: None,
            fence_ancestry: fence_ancestry.clone(),
            mode: ReplayPublicationMode::Canonical,
        };
        let snapshots = MaterializedOrderedSnapshots::singleton(
            ordered,
            MaterializedOrderedSnapshot {
                runtime: current.runtime.clone(),
                control: state.control.clone(),
                linear: state.linear.clone(),
            },
        )
        .map_err(lift_validation)?;
        let checkpoint_roots = materialization
            .merge_roots
            .iter()
            .map(|root| root.id)
            .collect::<BTreeSet<_>>();
        let mut checkpoint_fence = materialization.fence.clone();
        if let Some(fence) = checkpoint_fence.as_mut() {
            fence
                .sealed_ancestry
                .retain(|event| checkpoint_roots.contains(event));
        }
        let checkpoint_merge_state = state.merge.clone();
        Ok(ReplayPreparedPublication {
            store,
            sealed,
            successor: ReplayMaterialization {
                heads_id: next.id(),
                heads: next,
                replayed_root: materialization.replayed_root,
                final_system_authority_write: None,
                state,
                ordered_snapshots: snapshots,
                merge_roots: materialization.merge_roots.clone(),
                merge_boundary_roots: checkpoint_roots.clone(),
                merge_boundary_ancestry: checkpoint_roots.clone(),
                merge_boundary_state: checkpoint_merge_state,
                merge_boundary_invocations: current.merge_invocations,
                merge_ancestry: checkpoint_roots,
                fence: checkpoint_fence,
                artifacts,
                suffix_budget: ReplaySuffixBudget::default(),
                replay_boundary: ordered,
                fence_ancestry,
            },
            executions: Vec::new(),
        })
    }
}

#[cfg(feature = "std")]
#[allow(unused_imports)]
pub(crate) use aggregate::{
    MaterializeError, materialize_current, prepare_checkpoint, prepare_local, prepare_merge,
    prepare_ordered, prepare_shared_checkpoint, prepare_shared_ordered, recover_invocation,
    validate_published_shared_checkpoint,
};

#[cfg(all(feature = "std", feature = "storage"))]
#[allow(unused_imports)]
pub(crate) use aggregate::{
    materialize_current_reverified, materialized_system_authority_view,
    recover_pending_system_authority_catalog, recover_pending_system_authority_rotation,
};

#[cfg(test)]
pub(crate) mod tests {
    use super::*;
    use alloc::vec;

    use crate::agent::MethodMode;
    use crate::agent::authority::{
        ActorInvocationClaim, ActorInvocationReceipt, AgentAuthorityBinding, AgentAuthorityClaim,
        AgentAuthorityReceipt, ED25519_SIGNATURE_BYTES, ed25519_public_key_wire,
    };
    #[cfg(all(feature = "std", feature = "storage"))]
    use crate::agent::catalog_finality::{
        CatalogMutation, CatalogMutationDisposition, CatalogMutationIntent, CatalogMutationKind,
        CatalogMutationResult, FinalizedCatalogMutationFact, FinalizedCatalogMutationReceipt,
    };
    #[cfg(feature = "std")]
    use crate::agent::committee::{
        AuthorityCommittee, AuthorityCommitteeMember, AuthorityMemberRole,
        AuthorityQuorumCertificate, AuthoritySignature, AuthoritySignerId, RootAnchorRecord,
        SystemAgentGenesisClaim, SystemAgentGenesisEvidence, TrustedRootAnchor,
    };
    use crate::agent::contract::RuntimePackageContract;
    use crate::agent::execution::{ActorInvocation, ActorInvocationAuth, ActorObservation};
    #[cfg(feature = "std")]
    use crate::agent::genesis::{
        AgentGenesisAdmissionId, AgentGenesisClaim, AgentGenesisDecision, AgentGenesisEvidence,
        AgentGenesisExpectations, AgentGenesisLocator, AgentGenesisProposal, AgentReplicaCommittee,
        AgentReplicaCommitteeId, AgentReplicaMember, derive_replica_raft_slot,
    };
    #[cfg(feature = "std")]
    use crate::agent::invocation_history::{InvocationHistoryNode, InvocationHistoryStore};
    #[cfg(feature = "std")]
    use crate::agent::invocation_index::{InvocationIndexStore, InvocationOutcomeStore};
    #[cfg(feature = "std")]
    use crate::agent::journal::InvocationHistoryNodeId;
    #[cfg(all(feature = "std", feature = "storage"))]
    use crate::agent::journal_store::ReverifiedRootJournalStore;
    #[cfg(feature = "std")]
    use crate::agent::journal_store::SystemAuthorityHistoryStore;
    #[cfg(feature = "std")]
    use crate::agent::journal_store::{
        AgentJournalGarbageCollection, AgentJournalStore, GcLimits, JournalBlobClass,
        JournalPublication, JournalStoreError, MemoryAgentJournalStore,
    };
    #[cfg(feature = "std")]
    use crate::agent::shared_commit::{
        OrderedCommitClaim, ReplicaCommitSignature, ReplicaQuorumCertificate, SharedLaneProjection,
        SharedSealedMergeProjection,
    };
    #[cfg(all(feature = "std", feature = "storage"))]
    use crate::agent::shared_raft::AgentRaftEvidenceLedger;
    #[cfg(feature = "std")]
    use crate::agent::shared_raft::{
        AgentRaftCommand, AgentRouteKey, ArtifactBatchId, CommittedAgentRaftEntry,
        DurableAgentRaftLogWitness,
    };
    #[cfg(all(feature = "std", feature = "storage"))]
    use crate::agent::system_authority::{
        SystemAuthorityCatalogFinalize, SystemAuthorityCatalogProof, SystemAuthorityJournalScope,
        SystemAuthorityRotation, SystemAuthorityRotationClaim, SystemAuthorityRotationProof,
    };
    #[cfg(feature = "std")]
    use crate::agent::system_authority::{
        SystemAuthorityDecisionProof, SystemAuthorityFinalize, SystemAuthorityGenesis,
    };
    #[cfg(all(feature = "std", feature = "storage"))]
    use crate::agent::system_authority_ledger::{
        ReplayedSystemAuthorityView, SystemAuthorityCatalogReservationRequest,
        SystemAuthorityCommitteeLeg, SystemAuthorityEvidenceLedger,
        SystemAuthorityRotationReservationRequest, SystemAuthoritySigner,
    };
    use crate::agent::{
        AgentConfig, AgentIdentity, AgentProfile, AgentReplica, LaneSet,
        LifecycleAuthorityAdmission, ReplicaRole, RuntimeCapabilities,
    };
    use crate::service::{
        ActorId, AgentId, CapabilityId, CredentialId, DeploymentId, OperationId, PrincipalId,
        ProducerId, ProgramId, SpaceId,
    };
    #[cfg(feature = "std")]
    use ed25519_dalek::{Signer as _, SigningKey};
    #[cfg(feature = "std")]
    use redb::Database;

    #[derive(Default)]
    struct MemorySource {
        ordered: BTreeMap<OrderedEntryId, OrderedEntry>,
        local: BTreeMap<LocalEntryId, LocalEntry>,
        events: BTreeMap<MergeEventId, MergeEvent>,
        frontiers: BTreeMap<MergeFrontierId, MergeFrontier>,
        seals: BTreeMap<MergeSealId, MergeSeal>,
        lanes: BTreeMap<LaneStateId, LaneStateManifest>,
        artifacts: BTreeMap<ArtifactClosureId, ArtifactClosure>,
        invocation_indexes: BTreeMap<InvocationIndexId, InvocationIndexManifest>,
        checkpoints: BTreeMap<CheckpointId, CheckpointManifest>,
    }

    /// Linear-time durable reference used only for the exact 1,024-entry
    /// live-budget boundary. The production Memory store intentionally
    /// re-audits the complete checkpoint-relative ancestry and clones its
    /// candidate on every CAS, which makes a boundary-length debug test
    /// quadratic. Separate tests below exercise that real sealed handoff;
    /// this harness still stores every typed object/blob/index and reopens
    /// solely through `materialize_current` from its durable head.
    #[cfg(feature = "std")]
    struct LinearReplayStore {
        inner: MemoryAgentJournalStore,
        heads: JournalHeads,
        history_nodes: BTreeMap<InvocationHistoryNodeId, Vec<u8>>,
    }

    #[cfg(feature = "std")]
    impl InvocationIndexStore for LinearReplayStore {
        type Error = JournalStoreError;

        fn node_limit(&self) -> usize {
            InvocationIndexStore::node_limit(&self.inner)
        }

        fn load_manifest(&self, id: InvocationIndexId) -> Result<Option<Vec<u8>>, Self::Error> {
            InvocationIndexStore::load_manifest(&self.inner, id)
        }

        fn load_node(
            &self,
            id: super::super::journal::InvocationIndexNodeId,
        ) -> Result<Option<Vec<u8>>, Self::Error> {
            InvocationIndexStore::load_node(&self.inner, id)
        }

        fn put_manifest(&mut self, id: InvocationIndexId, bytes: &[u8]) -> Result<(), Self::Error> {
            InvocationIndexStore::put_manifest(&mut self.inner, id, bytes)
        }

        fn put_node(
            &mut self,
            id: super::super::journal::InvocationIndexNodeId,
            bytes: &[u8],
        ) -> Result<(), Self::Error> {
            InvocationIndexStore::put_node(&mut self.inner, id, bytes)
        }
    }

    #[cfg(feature = "std")]
    impl InvocationOutcomeStore for LinearReplayStore {
        fn load_outcome(&self, id: InvocationOutcomeId) -> Result<Option<Vec<u8>>, Self::Error> {
            InvocationOutcomeStore::load_outcome(&self.inner, id)
        }

        fn put_outcome(
            &mut self,
            id: InvocationOutcomeId,
            bytes: &[u8],
        ) -> Result<(), Self::Error> {
            InvocationOutcomeStore::put_outcome(&mut self.inner, id, bytes)
        }
    }

    #[cfg(feature = "std")]
    impl InvocationHistoryStore for LinearReplayStore {
        type Error = JournalStoreError;

        fn load_history_node(
            &self,
            id: InvocationHistoryNodeId,
        ) -> Result<Option<Vec<u8>>, Self::Error> {
            if id == InvocationHistoryNodeId::ZERO {
                return Err(JournalStoreError::Corrupt);
            }
            self.history_nodes
                .get(&id)
                .map(|bytes| {
                    let node = InvocationHistoryNode::decode(bytes)
                        .map_err(|_| JournalStoreError::Corrupt)?;
                    node.validate().map_err(|_| JournalStoreError::Corrupt)?;
                    if node.id() != id {
                        return Err(JournalStoreError::Corrupt);
                    }
                    Ok(bytes.clone())
                })
                .transpose()
        }
    }

    #[cfg(feature = "std")]
    impl AgentJournalStore for LinearReplayStore {
        fn instance_id(&self) -> JournalStoreInstanceId {
            self.inner.instance_id()
        }

        fn initialize(&mut self, sealed: &ReplaySealedGenesis) -> Result<bool, JournalStoreError> {
            let created = self.inner.initialize(sealed)?;
            self.heads = self
                .inner
                .heads()?
                .ok_or(JournalStoreError::NotInitialized)?;
            Ok(created)
        }

        fn genesis(&self) -> Result<Option<AgentJournalGenesis>, JournalStoreError> {
            self.inner.genesis()
        }

        fn heads(&self) -> Result<Option<JournalHeads>, JournalStoreError> {
            Ok(Some(self.heads.clone()))
        }

        fn put<R: CanonicalJournalRecord>(
            &mut self,
            record: &R,
        ) -> Result<bool, JournalStoreError> {
            self.inner.put(record)
        }

        fn get<R: CanonicalJournalRecord>(
            &self,
            id: R::Id,
        ) -> Result<Option<R>, JournalStoreError> {
            self.inner.get(id)
        }

        fn put_blob(
            &mut self,
            class: JournalBlobClass,
            reference: &BlobRef,
            bytes: &[u8],
        ) -> Result<bool, JournalStoreError> {
            self.inner.put_blob(class, reference, bytes)
        }

        fn load_blob(
            &self,
            class: JournalBlobClass,
            reference: &BlobRef,
        ) -> Result<Option<Vec<u8>>, JournalStoreError> {
            self.inner.load_blob(class, reference)
        }

        fn publish(
            &mut self,
            publication: &ReplaySealedPublication,
        ) -> Result<JournalPublication, JournalStoreError> {
            if publication.next() == &self.heads {
                return Ok(JournalPublication {
                    object_created: false,
                    heads_advanced: false,
                });
            }
            if publication.expected() != self.heads.id()
                || self.heads.validate_successor(publication.next()).is_err()
            {
                return Err(JournalStoreError::Conflict);
            }
            let mut object_created = false;
            for plan in publication.history_plans() {
                plan.validate(self)
                    .map_err(|_| JournalStoreError::Corrupt)?;
                for write in plan.node_writes() {
                    let node = InvocationHistoryNode::decode(write.bytes())
                        .map_err(|_| JournalStoreError::Corrupt)?;
                    node.validate().map_err(|_| JournalStoreError::Corrupt)?;
                    if node.id() != write.id() {
                        return Err(JournalStoreError::Corrupt);
                    }
                    match self.history_nodes.get(&write.id()) {
                        Some(bytes) if bytes.as_slice() == write.bytes() => {}
                        Some(_) => return Err(JournalStoreError::Corrupt),
                        None => {
                            self.history_nodes
                                .insert(write.id(), write.bytes().to_vec());
                            object_created = true;
                        }
                    }
                }
                plan.validate(self)
                    .map_err(|_| JournalStoreError::Corrupt)?;
            }
            for outcome in publication.outcomes() {
                let record = outcome.record();
                InvocationOutcomeStore::put_outcome(
                    &mut self.inner,
                    record.id(),
                    &record.encode(),
                )?;
            }
            match publication.anchor() {
                ReplayPublicationAnchor::Ordered(entry) => {
                    object_created |= self.inner.put(entry)?
                }
                ReplayPublicationAnchor::Local(entry) => object_created |= self.inner.put(entry)?,
                ReplayPublicationAnchor::Merge { event, frontier } => {
                    object_created |= self.inner.put(frontier)?;
                    object_created |= self.inner.put(event)?;
                }
                ReplayPublicationAnchor::Checkpoint(checkpoint) => {
                    let sealed = publication
                        .checkpoint_validation()
                        .ok_or(JournalStoreError::NonCanonical)?;
                    for (_, state) in sealed.lanes() {
                        object_created |= self.inner.put(state)?;
                    }
                    object_created |= self.inner.put(sealed.artifacts())?;
                    for (_, index) in sealed.invocation_indexes() {
                        object_created |= self.inner.put(index)?;
                    }
                    object_created |= self.inner.put(checkpoint)?;
                }
            }
            self.heads = publication.next().clone();
            Ok(JournalPublication {
                object_created,
                heads_advanced: true,
            })
        }
    }

    #[cfg(feature = "std")]
    impl ReplaySource for LinearReplayStore {
        type Error = JournalStoreError;

        fn ordered(&self, id: OrderedEntryId) -> Result<Option<OrderedEntry>, Self::Error> {
            self.inner.get(id)
        }

        fn local(&self, id: LocalEntryId) -> Result<Option<LocalEntry>, Self::Error> {
            self.inner.get(id)
        }

        fn merge_event(&self, id: MergeEventId) -> Result<Option<MergeEvent>, Self::Error> {
            self.inner.get(id)
        }

        fn merge_frontier(
            &self,
            id: MergeFrontierId,
        ) -> Result<Option<MergeFrontier>, Self::Error> {
            self.inner.get(id)
        }

        fn merge_seal(&self, id: MergeSealId) -> Result<Option<MergeSeal>, Self::Error> {
            self.inner.get(id)
        }

        fn lane_state(&self, id: LaneStateId) -> Result<Option<LaneStateManifest>, Self::Error> {
            self.inner.get(id)
        }

        fn artifact_closure(
            &self,
            id: ArtifactClosureId,
        ) -> Result<Option<ArtifactClosure>, Self::Error> {
            self.inner.get(id)
        }

        fn invocation_index(
            &self,
            id: InvocationIndexId,
        ) -> Result<Option<InvocationIndexManifest>, Self::Error> {
            self.inner.get(id)
        }

        fn checkpoint(&self, id: CheckpointId) -> Result<Option<CheckpointManifest>, Self::Error> {
            self.inner.get(id)
        }
    }

    impl ReplaySource for MemorySource {
        type Error = ();

        fn ordered(&self, id: OrderedEntryId) -> Result<Option<OrderedEntry>, Self::Error> {
            Ok(self.ordered.get(&id).cloned())
        }

        fn local(&self, id: LocalEntryId) -> Result<Option<LocalEntry>, Self::Error> {
            Ok(self.local.get(&id).cloned())
        }

        fn merge_event(&self, id: MergeEventId) -> Result<Option<MergeEvent>, Self::Error> {
            Ok(self.events.get(&id).cloned())
        }

        fn merge_frontier(
            &self,
            id: MergeFrontierId,
        ) -> Result<Option<MergeFrontier>, Self::Error> {
            Ok(self.frontiers.get(&id).cloned())
        }

        fn merge_seal(&self, id: MergeSealId) -> Result<Option<MergeSeal>, Self::Error> {
            Ok(self.seals.get(&id).cloned())
        }

        fn lane_state(&self, id: LaneStateId) -> Result<Option<LaneStateManifest>, Self::Error> {
            Ok(self.lanes.get(&id).cloned())
        }

        fn artifact_closure(
            &self,
            id: ArtifactClosureId,
        ) -> Result<Option<ArtifactClosure>, Self::Error> {
            Ok(self.artifacts.get(&id).cloned())
        }

        fn invocation_index(
            &self,
            id: InvocationIndexId,
        ) -> Result<Option<InvocationIndexManifest>, Self::Error> {
            Ok(self.invocation_indexes.get(&id).copied())
        }

        fn checkpoint(&self, id: CheckpointId) -> Result<Option<CheckpointManifest>, Self::Error> {
            Ok(self.checkpoints.get(&id).cloned())
        }
    }

    fn authority() -> AgentAuthorityBinding {
        let public_key = ed25519_public_key_wire([0x41; 32]);
        AgentAuthorityBinding {
            agent: AgentId([0x42; 32]),
            actor: ActorId([0x43; 32]),
            deployment: DeploymentId([0x44; 32]),
            program: ProgramId([0x45; 32]),
            producer: ProducerId::of_public_key(&public_key),
            public_key,
        }
    }

    fn runtime() -> RuntimeBinding {
        RuntimeBinding {
            space: SpaceId([1; 32]),
            agent: AgentId([2; 32]),
            deployment: DeploymentId([3; 32]),
            program: ProgramId([4; 32]),
            producer: ProducerId([5; 32]),
            package: BlobRef {
                hash: Hash([6; 32]),
                len: 1,
            },
            runtime_abi: super::super::RUNTIME_ABI_ID,
            execution_semantics: super::super::EXECUTION_SEMANTICS_ID,
        }
    }

    fn standard_test_actor() -> (AgentId, ActorId) {
        let agent = AgentId::derive(
            SpaceId([0x31; 32]),
            PrincipalId([0x32; 32]),
            Hash([0x33; 32]).as_bytes(),
        );
        (agent, ActorId::top_level(agent, "replay-test-actor"))
    }

    fn input(mode: MethodMode) -> ReplayInput {
        input_with_message(mode, vec![1])
    }

    fn input_with_message(mode: MethodMode, message: Vec<u8>) -> ReplayInput {
        let (_, actor) = standard_test_actor();
        let invocation = ActorInvocation {
            invocation: InvocationId([0x51; 32]),
            actor,
            incarnation: Hash([0x50; 32]),
            deployment: DeploymentId([0x53; 32]),
            program: ProgramId([0x54; 32]),
            mode,
            auth: ActorInvocationAuth::anonymous(),
            message,
            availability: Vec::new(),
            gas: 1,
        };
        let receipt = ActorInvocationReceipt {
            claim: ActorInvocationClaim {
                authority: authority(),
                space: runtime().space,
                agent: runtime().agent,
                principal: None,
                credential: None,
                authorization: invocation.authorization_message(),
                auth: invocation.auth.clone(),
                valid_from: 0,
                valid_until: 10,
            },
            signature: vec![0x55; ED25519_SIGNATURE_BYTES],
        };
        ReplayInput {
            runtime: runtime(),
            operation: ReplayOperation::Invoke {
                invocation,
                authority: receipt,
                observed_slot: 1,
            },
        }
    }

    fn successful_result(input: &ReplayInput) -> Result<ActorExecutionReply, ActorExecutionError> {
        let ReplayOperation::Invoke { invocation, .. } = &input.operation else {
            panic!("test result requires an invocation")
        };
        Ok(ActorExecutionReply {
            invocation: invocation.invocation,
            actor: invocation.actor,
            incarnation: invocation.incarnation,
            deployment: invocation.deployment,
            mode: invocation.mode,
            lane: result_lane(invocation.mode.result_storage()).state_lane(),
            status: ActorExecutionStatus::Done,
            reply: Vec::new(),
            gas_remaining: invocation.gas,
            observation: ActorObservation::default(),
        })
    }

    fn standard_before() -> RuntimeState {
        let space = SpaceId([0x31; 32]);
        let owner = PrincipalId([0x32; 32]);
        let creation_nonce = Hash([0x33; 32]);
        let agent = AgentId::derive(space, owner, creation_nonce.as_bytes());
        let config = AgentConfig {
            identity: AgentIdentity {
                space,
                agent,
                owner,
                profile: AgentProfile::Local,
                runtime_deployment: DeploymentId([0x34; 32]),
                runtime_program: ProgramId([0x35; 32]),
                runtime_producer: ProducerId([0x36; 32]),
            },
            creation_nonce,
            authority: authority(),
            system_authority_genesis: None,
            runtime_package: BlobRef::of_bytes(b"replay-test-runtime"),
            runtime_contract: RuntimePackageContract::canonical(),
            capabilities: RuntimeCapabilities {
                lanes: LaneSet::ALL,
                scheduling: false,
                proofs: false,
                max_actors: 64,
            },
            replicas: vec![AgentReplica {
                node: NodeId([0x37; 32]),
                principal: owner,
                role: ReplicaRole::Voter,
            }],
        };
        assert!(config.validate().is_ok());
        let (_, actor) = standard_test_actor();
        let package = BlobRef::of_bytes(b"replay-test-actor-package");
        let agent_schema = BlobRef::of_bytes(b"replay-test-agent-schema");
        let role_policies = BlobRef::of_bytes(b"replay-test-role-policies");
        let state_layout = Hash([0x38; 32]);
        let requirements = crate::agent::RuntimeRequirements {
            lanes: LaneSet::of(StateLane::Linear),
            scheduling: false,
            proofs: false,
        };
        let entry = crate::agent::ActorEntry {
            actor,
            name: "replay-test-actor".into(),
            parent: None,
            deployment: DeploymentId([0x53; 32]),
            program: ProgramId([0x54; 32]),
            package: package.clone(),
            agent_schema: agent_schema.clone(),
            role_policies: role_policies.clone(),
            constructor_abi: Hash([0x3a; 32]),
            installation_data: None,
            state_layout,
            lanes: requirements.lanes,
            suspended: false,
        };
        let state = crate::agent::standard::StandardRuntimeState {
            config: Some(config.clone()),
            actors: vec![crate::agent::standard::StandardActorState {
                record: crate::agent::ActorRecord {
                    entry,
                    state_generation: Hash([0x50; 32]),
                    installation_id: crate::service::InstallationId([0x55; 32]),
                    registry_reservation: Hash([0x56; 32]),
                    install_request_commitment: Hash([0x57; 32]),
                    producer: ProducerId([0x39; 32]),
                    package,
                    agent_schema,
                    role_policies,
                    constructor_abi: Hash([0x3a; 32]),
                    installation_data: None,
                    state_layout,
                    contract: crate::agent::contract::ActorPackageContract::canonical(),
                    requirements,
                },
                debt: crate::agent::ActorLifecycleDebt::default(),
            }],
            authority_slot_high_water: Some(1),
            authority_sequence_high_water: Some(1),
            authority_dispositions: vec![crate::agent::standard::StandardAuthorityDisposition {
                credential: CredentialId([0x51; 32]),
                sequence: 1,
                claim: Hash([0x52; 32]),
                operation: Hash([0x53; 32]),
                result: Ok(crate::agent::LifecycleReply::Created(config.identity)),
            }],
            ..crate::agent::standard::StandardRuntimeState::default()
        };
        assert!(StandardAgentRuntime::restore(state.clone()).is_ok());
        encode_standard_runtime_state(&state)
    }

    #[test]
    fn standard_artifact_references_retain_present_installation_data() {
        for bytes in [&b""[..], &b"immutable-constructor-data"[..]] {
            let installation_data = BlobRef::of_bytes(bytes);
            let mut decoded = decode_standard_runtime_state(&standard_before()).unwrap();
            let config = decoded.config.as_ref().unwrap().clone();
            let actor = &mut decoded.actors[0].record;
            actor.entry.installation_data = Some(installation_data.clone());
            actor.installation_data = Some(installation_data.clone());
            assert!(StandardAgentRuntime::restore(decoded.clone()).is_ok());

            let runtime = RuntimeBinding {
                space: config.identity.space,
                agent: config.identity.agent,
                deployment: config.identity.runtime_deployment,
                program: config.identity.runtime_program,
                producer: config.identity.runtime_producer,
                package: config.runtime_package,
                runtime_abi: super::super::RUNTIME_ABI_ID,
                execution_semantics: super::super::EXECUTION_SEMANTICS_ID,
            };
            let state = encode_standard_runtime_state(&decoded);
            let artifacts =
                derive_standard_artifact_references::<core::convert::Infallible>(&runtime, &state)
                    .unwrap();

            assert_eq!(
                artifacts
                    .iter()
                    .filter(|artifact| **artifact == installation_data)
                    .count(),
                1
            );
        }
    }

    fn clock_only_state(input: &ReplayInput, before: &RuntimeState) -> RuntimeState {
        let ReplayOperation::Invoke {
            invocation,
            observed_slot,
            ..
        } = &input.operation
        else {
            panic!("clock-only test transition requires an invocation")
        };
        let decoded = decode_standard_runtime_state(before).unwrap();
        let mut runtime = StandardAgentRuntime::restore(decoded).unwrap();
        runtime
            .commit_exact_outcome_clock(invocation, *observed_slot)
            .unwrap();
        encode_standard_runtime_state(&runtime.snapshot())
    }

    fn with_exact_standard_result(input: &ReplayInput, state: &RuntimeState) -> RuntimeState {
        let ReplayOperation::Invoke { invocation, .. } = &input.operation else {
            panic!("test result state requires an invocation")
        };
        let Ok(reply) = successful_result(input) else {
            unreachable!()
        };
        let mut decoded = decode_standard_runtime_state(state).unwrap();
        decoded
            .invocation_results
            .push(super::super::standard::StandardInvocationResult {
                scope: invocation.mode.invocation_scope(),
                invocation: invocation.invocation,
                incarnation: invocation.incarnation,
                request: invocation.commitment(),
                reply,
                storage: invocation.mode.result_storage(),
                clean: None,
            });
        encode_standard_runtime_state(&decoded)
    }

    #[cfg(feature = "std")]
    fn admitted_authority_key() -> SigningKey {
        SigningKey::from_bytes(&[0x90; 32])
    }

    #[cfg(feature = "std")]
    fn admitted_authority() -> AgentAuthorityBinding {
        let public_key =
            ed25519_public_key_wire(admitted_authority_key().verifying_key().to_bytes());
        AgentAuthorityBinding {
            agent: admitted_agent(),
            actor: ActorId([0x8a; 32]),
            deployment: DeploymentId([0x8b; 32]),
            program: ProgramId([0x8c; 32]),
            producer: ProducerId::of_public_key(&public_key),
            public_key,
        }
    }

    #[cfg(feature = "std")]
    fn admitted_agent() -> AgentId {
        AgentId::derive(
            SpaceId([0x91; 32]),
            PrincipalId([0x92; 32]),
            Hash([0x93; 32]).as_bytes(),
        )
    }

    #[cfg(feature = "std")]
    fn admitted_root_material(config: &AgentConfig) -> (RootAnchorRecord, [SigningKey; 3]) {
        let keys = [
            SigningKey::from_bytes(&[0xd1; 32]),
            SigningKey::from_bytes(&[0xd2; 32]),
            SigningKey::from_bytes(&[0xd3; 32]),
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
            Hash([0xd4; 32]),
            committee,
        )
        .unwrap();
        (root, keys)
    }

    #[cfg(all(feature = "std", feature = "storage"))]
    struct AuthorityTestSigner(SigningKey);

    #[cfg(all(feature = "std", feature = "storage"))]
    impl SystemAuthoritySigner for AuthorityTestSigner {
        type Error = ();

        fn signer(&self) -> AuthoritySignerId {
            AuthoritySignerId::of_raw_ed25519(&self.0.verifying_key().to_bytes())
        }

        fn sign_authority_message(&self, message: Hash) -> Result<[u8; 64], Self::Error> {
            Ok(self.0.sign(&message.0).to_bytes())
        }
    }

    #[cfg(all(feature = "std", feature = "storage"))]
    fn rotated_committee(
        retiring: &AuthorityCommittee,
        keys: &[SigningKey; 3],
    ) -> AuthorityCommittee {
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
        AuthorityCommittee::new(
            retiring.space(),
            retiring.authority_binding(),
            retiring.epoch() + 1,
            Some(retiring.commitment()),
            members,
        )
        .unwrap()
    }

    #[cfg(all(feature = "std", feature = "storage"))]
    fn retain_rotation_qc_leg(
        ledger: &SystemAuthorityEvidenceLedger,
        reserved: &ReservedSystemAuthorityClaim,
        leg: SystemAuthorityCommitteeLeg,
        committee: &AuthorityCommittee,
        keys: &[SigningKey; 3],
    ) {
        let local = AuthorityTestSigner(keys[0].clone());
        ledger.sign_reserved_leg(reserved, leg, &local).unwrap();
        let claim = reserved.request().claim();
        let message = AuthorityQuorumCertificate::signing_message(
            committee.authority_binding(),
            committee.epoch(),
            committee.commitment(),
            claim,
        );
        let remote = AuthoritySignature::new(
            AuthoritySignerId::of_raw_ed25519(&keys[1].verifying_key().to_bytes()),
            keys[1].sign(&message.0).to_bytes(),
        )
        .unwrap();
        assert!(
            ledger
                .record_remote_share(reserved, leg, remote)
                .unwrap()
                .certificate()
                .is_some()
        );
    }

    #[cfg(all(feature = "std", feature = "storage"))]
    struct RotationPublicationFixture {
        store: MemoryAgentJournalStore,
        executor: ExactCreateRejectInvocations,
        predecessor: ReplayMaterialization,
        ledger: SystemAuthorityEvidenceLedger,
        reserved: ReservedSystemAuthorityClaim,
        entry: OrderedEntry,
        database: alloc::sync::Arc<Database>,
        directory: std::path::PathBuf,
    }

    #[cfg(all(feature = "std", feature = "storage"))]
    fn rotation_publication_fixture(seed: u8) -> RotationPublicationFixture {
        let sealed = admitted_genesis(seed);
        let node = admitted_config().replicas[0].node;
        let mut store = MemoryAgentJournalStore::new(admitted_runtime().agent, node).unwrap();
        store
            .put_blob(
                JournalBlobClass::CatalogArtifact,
                &admitted_runtime().package,
                b"replay-runtime-package",
            )
            .unwrap();
        assert!(store.initialize(&sealed).unwrap());

        let mut executor = ExactCreateRejectInvocations::default();
        let predecessor =
            materialize_current_reverified(&mut store, &mut executor, &NoPrunedOrderedBases)
                .unwrap();
        let identity = predecessor.replayed_root().unwrap();
        let scope = SystemAuthorityJournalScope::from_replayed_root(&identity).unwrap();
        let decoded = decode_standard_runtime_state(predecessor.state()).unwrap();
        let authority = decoded.system_authority.unwrap();
        let retiring = authority.current_committee().clone();
        let (_, keys) = admitted_root_material(&admitted_config());
        let incoming = rotated_committee(&retiring, &keys);
        let transition = SystemAuthorityRotationClaim::new(
            authority.root_anchor(),
            authority.root_anchor_config_version(),
            authority.root_anchor_config(),
            scope.commitment(authority.root_anchor()).unwrap(),
            &retiring,
            &incoming,
            2,
            3,
        )
        .unwrap();
        let request = SystemAuthorityRotationReservationRequest::new(
            retiring.clone(),
            incoming.clone(),
            transition,
        )
        .unwrap();
        let predecessor_control = derive_lane_state::<(), ()>(
            predecessor.heads().genesis,
            predecessor.runtime().clone(),
            PersistedLane::Control,
            LaneCursor::Ordered {
                base: predecessor.ordered_base(),
            },
            &predecessor.state().control,
        )
        .unwrap()
        .id();
        let view = ReplayedSystemAuthorityView::from_authenticated_replay(
            scope,
            &authority,
            store.instance_id(),
            predecessor.heads_id(),
            predecessor_control,
        )
        .unwrap();

        let directory = std::env::temp_dir().join(alloc::format!(
            "vos_authority_recovery_{}_{}_{}",
            std::process::id(),
            seed,
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_nanos(),
        ));
        std::fs::create_dir_all(&directory).unwrap();
        let database =
            alloc::sync::Arc::new(Database::create(directory.join("evidence.redb")).unwrap());
        let local_signer = AuthoritySignerId::of_raw_ed25519(&keys[0].verifying_key().to_bytes());
        let local_node = retiring.member(local_signer).unwrap().node();
        let ledger = SystemAuthorityEvidenceLedger::open(
            database.clone(),
            view.route(),
            store.instance_id(),
            local_node,
            local_signer,
        )
        .unwrap();
        let reserved = ledger
            .reserve_or_reconcile(&view, request)
            .unwrap()
            .into_reserved();
        retain_rotation_qc_leg(
            &ledger,
            &reserved,
            SystemAuthorityCommitteeLeg::Retiring,
            &retiring,
            &keys,
        );
        retain_rotation_qc_leg(
            &ledger,
            &reserved,
            SystemAuthorityCommitteeLeg::Incoming,
            &incoming,
            &keys,
        );
        let certificate = ledger
            .joint_rotation_certificate(&reserved)
            .unwrap()
            .unwrap();
        let command = SystemAuthorityRotation::new(
            incoming,
            certificate,
            SystemAuthorityRotationProof::vacant(retiring.epoch() + 1, vec![]).unwrap(),
        )
        .unwrap();
        let merge_seal = persist_merge_seal(&mut store, &predecessor);
        let entry = OrderedEntry {
            genesis: predecessor.heads().genesis,
            index: 1,
            parent: None,
            merge_frontier: predecessor.merge_frontier(),
            merge_seal: Some(merge_seal),
            input: ReplayInput {
                runtime: predecessor.runtime().clone(),
                operation: ReplayOperation::Management {
                    request: LifecycleRequest::RotateSystemAuthority(command),
                },
            },
        };

        RotationPublicationFixture {
            store,
            executor,
            predecessor,
            ledger,
            reserved,
            entry,
            database,
            directory,
        }
    }

    #[cfg(all(feature = "std", feature = "storage"))]
    struct CatalogPublicationFixture {
        store: MemoryAgentJournalStore,
        executor: ExactCreateRejectInvocations,
        predecessor: ReplayMaterialization,
        ledger: SystemAuthorityEvidenceLedger,
        reserved: ReservedSystemAuthorityClaim,
        entry: OrderedEntry,
        database: alloc::sync::Arc<Database>,
        directory: std::path::PathBuf,
    }

    #[cfg(all(feature = "std", feature = "storage"))]
    fn catalog_publication_fixture(seed: u8) -> CatalogPublicationFixture {
        let sealed = admitted_genesis(seed);
        let node = admitted_config().replicas[0].node;
        let mut store = MemoryAgentJournalStore::new(admitted_runtime().agent, node).unwrap();
        store
            .put_blob(
                JournalBlobClass::CatalogArtifact,
                &admitted_runtime().package,
                b"replay-runtime-package",
            )
            .unwrap();
        assert!(store.initialize(&sealed).unwrap());

        let mut executor = ExactCreateRejectInvocations::default();
        let predecessor =
            materialize_current_reverified(&mut store, &mut executor, &NoPrunedOrderedBases)
                .unwrap();
        let identity = predecessor.replayed_root().unwrap();
        let scope = SystemAuthorityJournalScope::from_replayed_root(&identity).unwrap();
        let decoded = decode_standard_runtime_state(predecessor.state()).unwrap();
        let authority = decoded.system_authority.unwrap();
        let committee = authority.current_committee().clone();
        let binding = authority.catalog_binding_record().unwrap();
        let operation = OperationId([seed.wrapping_add(0x31); 32]);
        let intent = CatalogMutationIntent::new(
            binding,
            authority.authority_generation(),
            authority.catalog_head(),
            PrincipalId([seed.wrapping_add(0x32); 32]),
            CredentialId([seed.wrapping_add(0x33); 32]),
            CapabilityId::named("catalog.update.metadata"),
            operation,
            CatalogMutation::new(
                CatalogMutationKind::UpdateMetadata,
                vec![seed, seed.wrapping_add(1)],
            )
            .unwrap(),
        )
        .unwrap();
        let fact = FinalizedCatalogMutationFact::new(
            intent,
            authority.authority_generation(),
            authority.catalog_head(),
            CatalogMutationResult::new(
                CatalogMutationDisposition::Applied,
                vec![seed.wrapping_add(2)],
            )
            .unwrap(),
            2,
        )
        .unwrap();
        let proof = SystemAuthorityCatalogProof::vacant(operation, vec![]).unwrap();
        let request = SystemAuthorityCatalogReservationRequest::new(
            committee.clone(),
            fact.clone(),
            proof.clone(),
        )
        .unwrap();
        let predecessor_control = derive_lane_state::<(), ()>(
            predecessor.heads().genesis,
            predecessor.runtime().clone(),
            PersistedLane::Control,
            LaneCursor::Ordered {
                base: predecessor.ordered_base(),
            },
            &predecessor.state().control,
        )
        .unwrap()
        .id();
        let view = ReplayedSystemAuthorityView::from_authenticated_replay(
            scope,
            &authority,
            store.instance_id(),
            predecessor.heads_id(),
            predecessor_control,
        )
        .unwrap();

        let directory = std::env::temp_dir().join(alloc::format!(
            "vos_catalog_authority_recovery_{}_{}_{}",
            std::process::id(),
            seed,
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_nanos(),
        ));
        std::fs::create_dir_all(&directory).unwrap();
        let database =
            alloc::sync::Arc::new(Database::create(directory.join("evidence.redb")).unwrap());
        let (_, keys) = admitted_root_material(&admitted_config());
        let local_signer = AuthoritySignerId::of_raw_ed25519(&keys[0].verifying_key().to_bytes());
        let local_node = committee.member(local_signer).unwrap().node();
        let ledger = SystemAuthorityEvidenceLedger::open(
            database.clone(),
            view.route(),
            store.instance_id(),
            local_node,
            local_signer,
        )
        .unwrap();
        let reserved = ledger
            .reserve_catalog_or_reconcile(&view, request)
            .unwrap()
            .into_reserved();
        retain_rotation_qc_leg(
            &ledger,
            &reserved,
            SystemAuthorityCommitteeLeg::Current,
            &committee,
            &keys,
        );
        let certificate = ledger
            .owner()
            .certificate(&reserved, SystemAuthorityCommitteeLeg::Current)
            .unwrap()
            .unwrap();
        let receipt =
            FinalizedCatalogMutationReceipt::new(fact, certificate, binding, &committee).unwrap();
        let command = SystemAuthorityCatalogFinalize::new(receipt, proof).unwrap();
        let merge_seal = persist_merge_seal(&mut store, &predecessor);
        let entry = OrderedEntry {
            genesis: predecessor.heads().genesis,
            index: 1,
            parent: None,
            merge_frontier: predecessor.merge_frontier(),
            merge_seal: Some(merge_seal),
            input: ReplayInput {
                runtime: predecessor.runtime().clone(),
                operation: ReplayOperation::Management {
                    request: LifecycleRequest::FinalizeCatalog(command),
                },
            },
        };

        CatalogPublicationFixture {
            store,
            executor,
            predecessor,
            ledger,
            reserved,
            entry,
            database,
            directory,
        }
    }

    #[cfg(all(feature = "std", feature = "storage"))]
    fn catalog_fact_for_authority(
        authority: &crate::agent::system_authority::SystemAuthorityState,
        operation: OperationId,
        sequence: u64,
        seed: u8,
    ) -> FinalizedCatalogMutationFact {
        let intent = CatalogMutationIntent::new(
            authority.catalog_binding_record().unwrap(),
            authority.authority_generation(),
            authority.catalog_head(),
            PrincipalId([seed.wrapping_add(1); 32]),
            CredentialId([seed.wrapping_add(2); 32]),
            CapabilityId::named("catalog.update.metadata"),
            operation,
            CatalogMutation::new(
                CatalogMutationKind::UpdateMetadata,
                vec![seed, seed.wrapping_add(3)],
            )
            .unwrap(),
        )
        .unwrap();
        FinalizedCatalogMutationFact::new(
            intent,
            authority.authority_generation(),
            authority.catalog_head(),
            CatalogMutationResult::new(
                CatalogMutationDisposition::Applied,
                vec![seed.wrapping_add(4)],
            )
            .unwrap(),
            sequence,
        )
        .unwrap()
    }

    #[cfg(all(feature = "std", feature = "storage"))]
    fn signed_catalog_receipt(
        fact: FinalizedCatalogMutationFact,
        committee: &AuthorityCommittee,
        keys: &[SigningKey; 3],
    ) -> FinalizedCatalogMutationReceipt {
        let message = AuthorityQuorumCertificate::signing_message(
            committee.authority_binding(),
            committee.epoch(),
            committee.commitment(),
            fact.authority_claim(),
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
        let certificate =
            AuthorityQuorumCertificate::new(committee, fact.authority_claim(), signatures).unwrap();
        FinalizedCatalogMutationReceipt::new(
            fact.clone(),
            certificate,
            fact.intent().binding(),
            committee,
        )
        .unwrap()
    }

    #[cfg(all(feature = "std", feature = "storage"))]
    fn catalog_ordered_entry(
        store: &mut MemoryAgentJournalStore,
        predecessor: &ReplayMaterialization,
        command: SystemAuthorityCatalogFinalize,
    ) -> OrderedEntry {
        let merge_seal = persist_merge_seal(store, predecessor);
        OrderedEntry {
            genesis: predecessor.heads().genesis,
            index: predecessor.heads().ordered_index + 1,
            parent: predecessor.heads().ordered_head,
            merge_frontier: predecessor.merge_frontier(),
            merge_seal: Some(merge_seal),
            input: ReplayInput {
                runtime: predecessor.runtime().clone(),
                operation: ReplayOperation::Management {
                    request: LifecycleRequest::FinalizeCatalog(command),
                },
            },
        }
    }

    #[cfg(all(feature = "std", feature = "storage"))]
    fn publish_test_rotation(
        store: &mut MemoryAgentJournalStore,
        executor: &mut ExactCreateRejectInvocations,
        predecessor: &ReplayMaterialization,
        ledger: &SystemAuthorityEvidenceLedger,
        keys: &[SigningKey; 3],
        rotation_sequence: u64,
        first_sequence: u64,
    ) -> ReplayMaterialization {
        let (scope, view) = materialized_system_authority_view(store, predecessor).unwrap();
        let authority = view.authority_state();
        let retiring = authority.current_committee().clone();
        let incoming = rotated_committee(&retiring, keys);
        let transition = SystemAuthorityRotationClaim::new(
            authority.root_anchor(),
            authority.root_anchor_config_version(),
            authority.root_anchor_config(),
            scope.commitment(authority.root_anchor()).unwrap(),
            &retiring,
            &incoming,
            rotation_sequence,
            first_sequence,
        )
        .unwrap();
        let request = SystemAuthorityRotationReservationRequest::new(
            retiring.clone(),
            incoming.clone(),
            transition,
        )
        .unwrap();
        let reserved = ledger
            .reserve_or_reconcile(&view, request)
            .unwrap()
            .into_reserved();
        retain_rotation_qc_leg(
            ledger,
            &reserved,
            SystemAuthorityCommitteeLeg::Retiring,
            &retiring,
            keys,
        );
        retain_rotation_qc_leg(
            ledger,
            &reserved,
            SystemAuthorityCommitteeLeg::Incoming,
            &incoming,
            keys,
        );
        let certificate = ledger
            .joint_rotation_certificate(&reserved)
            .unwrap()
            .unwrap();
        let command = SystemAuthorityRotation::new(
            incoming,
            certificate,
            SystemAuthorityRotationProof::vacant(retiring.epoch() + 1, vec![]).unwrap(),
        )
        .unwrap();
        let merge_seal = persist_merge_seal(store, predecessor);
        let entry = OrderedEntry {
            genesis: predecessor.heads().genesis,
            index: predecessor.heads().ordered_index + 1,
            parent: predecessor.heads().ordered_head,
            merge_frontier: predecessor.merge_frontier(),
            merge_seal: Some(merge_seal),
            input: ReplayInput {
                runtime: predecessor.runtime().clone(),
                operation: ReplayOperation::Management {
                    request: LifecycleRequest::RotateSystemAuthority(command),
                },
            },
        };
        let prepared = match prepare_ordered(store, executor, predecessor, &entry).unwrap() {
            ReplayPreparation::Ready(prepared) => prepared,
            ReplayPreparation::AlreadyCommitted(_) => unreachable!(),
        }
        .prepare_system_authority_rotation(reserved)
        .unwrap();
        let published = prepared
            .publish_system_authority_rotation(ledger.owner())
            .unwrap();
        let (_, successor, _) = ledger.owner().retire_published_rotation(published).unwrap();
        successor
    }

    #[cfg(feature = "std")]
    fn admitted_config() -> AgentConfig {
        let space = SpaceId([0x91; 32]);
        let owner = PrincipalId([0x92; 32]);
        let creation_nonce = Hash([0x93; 32]);
        let agent = AgentId::derive(space, owner, creation_nonce.as_bytes());
        let mut config = AgentConfig {
            identity: AgentIdentity {
                space,
                agent,
                owner,
                profile: AgentProfile::Local,
                runtime_deployment: DeploymentId([0x94; 32]),
                runtime_program: ProgramId([0x95; 32]),
                runtime_producer: ProducerId([0x96; 32]),
            },
            creation_nonce,
            authority: admitted_authority(),
            system_authority_genesis: None,
            runtime_package: BlobRef::of_bytes(b"replay-runtime-package"),
            runtime_contract: RuntimePackageContract::canonical(),
            capabilities: RuntimeCapabilities {
                lanes: LaneSet::ALL,
                scheduling: false,
                proofs: false,
                max_actors: 64,
            },
            replicas: vec![AgentReplica {
                node: NodeId([0x97; 32]),
                principal: owner,
                role: ReplicaRole::Voter,
            }],
        };
        let (root, _) = admitted_root_material(&config);
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
        config
    }

    #[cfg(feature = "std")]
    fn shared_admitted_config() -> AgentConfig {
        let mut config = admitted_config();
        config.identity.profile = AgentProfile::Shared;
        config.system_authority_genesis = None;
        let runtime = admitted_runtime();
        let (committee, _) = shared_test_committee(&runtime);
        config.replicas = committee
            .members()
            .iter()
            .map(|member| member.replica())
            .collect();
        config.validate().unwrap();
        config
    }

    #[cfg(feature = "std")]
    fn admitted_runtime() -> RuntimeBinding {
        let config = admitted_config();
        RuntimeBinding {
            space: config.identity.space,
            agent: config.identity.agent,
            deployment: config.identity.runtime_deployment,
            program: config.identity.runtime_program,
            producer: config.identity.runtime_producer,
            package: config.runtime_package,
            runtime_abi: super::super::RUNTIME_ABI_ID,
            execution_semantics: super::super::EXECUTION_SEMANTICS_ID,
        }
    }

    #[cfg(feature = "std")]
    struct AdmittedFinalizeFixture {
        command: SystemAuthorityFinalize,
        later_admission: AgentGenesisAdmissionRecord,
    }

    #[cfg(feature = "std")]
    fn admitted_finalize_fixture(
        sealed: &ReplaySealedGenesis,
        sequence: u64,
        signed_scope: Option<(AgentJournalGenesisId, AgentGenesisAdmissionId)>,
    ) -> AdmittedFinalizeFixture {
        const PEER_ID_PREFIX: [u8; 6] = [0x00, 0x24, 0x08, 0x01, 0x12, 0x20];

        let ReplayOperation::Management {
            request: LifecycleRequest::Authorized { request, .. },
        } = &sealed.genesis().create.operation
        else {
            unreachable!()
        };
        let LifecycleRequest::Create(system) = request.as_ref() else {
            unreachable!()
        };
        let (root, committee_keys) = admitted_root_material(system);
        assert_eq!(&root, sealed.root_anchor());

        let raw_member_key = [0x31; 32];
        let mut peer_id = Vec::from(PEER_ID_PREFIX);
        peer_id.extend_from_slice(&raw_member_key);
        let member = AgentReplicaMember::new(
            AgentReplica {
                node: NodeId::of_authenticated_peer(&peer_id),
                principal: PrincipalId::of_public_key(&raw_member_key),
                role: ReplicaRole::Voter,
            },
            peer_id.clone(),
            raw_member_key,
            Some(derive_replica_raft_slot(&peer_id)),
        )
        .unwrap();
        let owner = PrincipalId([0x12; 32]);
        let nonce = Hash([0x10_u8.wrapping_add(sequence as u8); 32]);
        let agent = AgentId::derive(system.identity.space, owner, nonce.as_bytes());
        let target = AgentConfig {
            identity: AgentIdentity {
                space: system.identity.space,
                agent,
                owner,
                profile: AgentProfile::Shared,
                runtime_deployment: DeploymentId([0x21; 32]),
                runtime_program: ProgramId([0x22; 32]),
                runtime_producer: ProducerId([0x23; 32]),
            },
            creation_nonce: nonce,
            authority: system.authority.clone(),
            system_authority_genesis: None,
            runtime_package: BlobRef::of_bytes(b"ordinary-replay-runtime"),
            runtime_contract: RuntimePackageContract::canonical(),
            capabilities: RuntimeCapabilities::standard(),
            replicas: vec![member.replica()],
        };
        target.validate().unwrap();

        let inner = LifecycleRequest::Create(target.clone());
        let create = ReplayInput {
            runtime: RuntimeBinding {
                space: target.identity.space,
                agent,
                deployment: target.identity.runtime_deployment,
                program: target.identity.runtime_program,
                producer: target.identity.runtime_producer,
                package: target.runtime_package.clone(),
                runtime_abi: super::super::RUNTIME_ABI_ID,
                execution_semantics: super::super::EXECUTION_SEMANTICS_ID,
            },
            operation: ReplayOperation::Management {
                request: LifecycleRequest::Authorized {
                    admission: LifecycleAuthorityAdmission {
                        receipt: AgentAuthorityReceipt {
                            claim: AgentAuthorityClaim {
                                authority: target.authority.clone(),
                                space: target.identity.space,
                                agent,
                                principal: owner,
                                credential: CredentialId([0x24; 32]),
                                capability: CapabilityId::named("agent.create.shared"),
                                operation: inner.commitment(),
                                sequence,
                                valid_from: 10,
                                valid_until: 40,
                            },
                            signature: vec![0x25; ED25519_SIGNATURE_BYTES],
                        },
                        observed_slot: 20,
                    },
                    request: alloc::boxed::Box::new(inner.clone()),
                },
            },
        };
        create.validate().unwrap();
        let catalog = vec![target.runtime_package.clone()];
        let expectations = AgentGenesisExpectations::new(
            create.runtime.commitment(),
            inner.commitment(),
            Hash([0x26; 32]),
            system_genesis_artifact_closure_commitment(&catalog).unwrap(),
            sequence,
        )
        .unwrap();
        let proposal = AgentGenesisProposal::new(
            AgentGenesisLocator {
                space: target.identity.space,
                agent,
            },
            create,
            expectations,
            catalog,
        )
        .unwrap();
        let replicas = AgentReplicaCommittee::new(
            target.identity.space,
            agent,
            AgentProfile::Shared,
            vec![member],
        )
        .unwrap();
        let (system_genesis, system_admission) =
            signed_scope.unwrap_or((sealed.genesis().id(), sealed.genesis().admission));
        let claim = AgentGenesisClaim::new(
            system.identity.agent,
            system_genesis,
            system_admission,
            &proposal,
            &replicas,
        )
        .unwrap();
        let committee = root.initial_committee();
        let message = AuthorityQuorumCertificate::signing_message(
            committee.authority_binding(),
            committee.epoch(),
            committee.commitment(),
            claim.authority_claim(),
        );
        let mut signatures = committee_keys[..2]
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
        let certificate =
            AuthorityQuorumCertificate::new(committee, claim.authority_claim(), signatures)
                .unwrap();
        let evidence = AgentGenesisEvidence::new(claim, certificate).unwrap();
        let decision = AgentGenesisDecision::new(&proposal, &replicas, &evidence).unwrap();
        let later_admission =
            AgentGenesisAdmissionRecord::system_authorized(&decision, &evidence, &replicas)
                .unwrap();
        let command = SystemAuthorityFinalize::new(
            decision,
            evidence,
            SystemAuthorityDecisionProof::vacant(agent, vec![]).unwrap(),
        )
        .unwrap();
        AdmittedFinalizeFixture {
            command,
            later_admission,
        }
    }

    #[cfg(feature = "std")]
    pub(crate) fn admitted_finalize_for_test(
        sealed: &ReplaySealedGenesis,
        sequence: u64,
    ) -> SystemAuthorityFinalize {
        admitted_finalize_fixture(sealed, sequence, None).command
    }

    #[cfg(feature = "std")]
    fn authority_finalize_input(
        sealed: &ReplaySealedGenesis,
        command: SystemAuthorityFinalize,
    ) -> ReplayInput {
        ReplayInput {
            runtime: sealed.genesis().runtime().clone(),
            operation: ReplayOperation::Management {
                request: LifecycleRequest::FinalizeSystemAuthority(command),
            },
        }
    }

    #[cfg(feature = "std")]
    fn admitted_create_input_for(config: AgentConfig, credential: u8) -> ReplayInput {
        let runtime = admitted_runtime();
        let inner = LifecycleRequest::Create(config.clone());
        let claim = AgentAuthorityClaim {
            authority: config.authority.clone(),
            space: runtime.space,
            agent: runtime.agent,
            principal: config.identity.owner,
            credential: CredentialId([credential; 32]),
            capability: CapabilityId::named("agent.create.local"),
            operation: inner.commitment(),
            sequence: 1,
            valid_from: 10,
            valid_until: 20,
        };
        let signature = admitted_authority_key()
            .sign(&claim.signing_message().0)
            .to_bytes()
            .to_vec();
        ReplayInput {
            runtime,
            operation: ReplayOperation::Management {
                request: LifecycleRequest::Authorized {
                    admission: LifecycleAuthorityAdmission {
                        receipt: AgentAuthorityReceipt { claim, signature },
                        observed_slot: 15,
                    },
                    request: alloc::boxed::Box::new(inner),
                },
            },
        }
    }

    #[cfg(feature = "std")]
    fn shared_admitted_create_input_for(config: AgentConfig, credential: u8) -> ReplayInput {
        let runtime = admitted_runtime();
        let inner = LifecycleRequest::Create(config.clone());
        let claim = AgentAuthorityClaim {
            authority: config.authority.clone(),
            space: runtime.space,
            agent: runtime.agent,
            principal: config.identity.owner,
            credential: CredentialId([credential; 32]),
            capability: CapabilityId::named("agent.create.shared"),
            operation: inner.commitment(),
            sequence: 1,
            valid_from: 10,
            valid_until: 20,
        };
        let signature = admitted_authority_key()
            .sign(&claim.signing_message().0)
            .to_bytes()
            .to_vec();
        ReplayInput {
            runtime,
            operation: ReplayOperation::Management {
                request: LifecycleRequest::Authorized {
                    admission: LifecycleAuthorityAdmission {
                        receipt: AgentAuthorityReceipt { claim, signature },
                        observed_slot: 15,
                    },
                    request: alloc::boxed::Box::new(inner),
                },
            },
        }
    }

    #[cfg(feature = "std")]
    fn admitted_invocation(mode: MethodMode, discriminator: u8) -> ReplayInput {
        let runtime = admitted_runtime();
        let invocation = ActorInvocation {
            invocation: InvocationId([discriminator; 32]),
            actor: ActorId([0xa1; 32]),
            incarnation: Hash([0xa0; 32]),
            deployment: DeploymentId([0xa2; 32]),
            program: ProgramId([0xa3; 32]),
            mode,
            auth: ActorInvocationAuth::anonymous(),
            message: vec![discriminator],
            availability: Vec::new(),
            gas: 1_000,
        };
        let receipt = ActorInvocationReceipt {
            claim: ActorInvocationClaim {
                authority: authority(),
                space: runtime.space,
                agent: runtime.agent,
                principal: None,
                credential: None,
                authorization: invocation.authorization_message(),
                auth: invocation.auth.clone(),
                valid_from: 10,
                valid_until: 20,
            },
            signature: vec![0xaa; ED25519_SIGNATURE_BYTES],
        };
        ReplayInput {
            runtime,
            operation: ReplayOperation::Invoke {
                invocation,
                authority: receipt,
                observed_slot: 15,
            },
        }
    }

    #[cfg(feature = "std")]
    fn admitted_acknowledgement(input: &ReplayInput) -> ReplayInput {
        let ReplayOperation::Invoke {
            invocation,
            authority,
            ..
        } = &input.operation
        else {
            panic!("test acknowledgement requires an invocation")
        };
        ReplayInput {
            runtime: input.runtime.clone(),
            operation: ReplayOperation::Acknowledge {
                invocation: invocation.clone(),
                authority: authority.clone(),
            },
        }
    }

    #[cfg(feature = "std")]
    fn divergent_invocation_input(input: &ReplayInput, discriminator: u8) -> ReplayInput {
        let mut divergent = input.clone();
        let (invocation, authority) = match &mut divergent.operation {
            ReplayOperation::Invoke {
                invocation,
                authority,
                ..
            }
            | ReplayOperation::Acknowledge {
                invocation,
                authority,
            } => (invocation, authority),
            ReplayOperation::Management { .. }
            | ReplayOperation::CleanInvoke { .. }
            | ReplayOperation::SealMerge => {
                panic!("test divergence requires an invocation")
            }
        };
        invocation.message.push(discriminator);
        authority.claim.authorization = invocation.authorization_message();
        assert!(divergent.validate().is_ok());
        divergent
    }

    #[cfg(feature = "std")]
    fn merge_position(event: &MergeEvent) -> ReplayPosition {
        ReplayPosition::Merge {
            id: event.id(),
            causal_height: event.causal_height,
            ordered_base: event.ordered_base,
        }
    }

    #[cfg(feature = "std")]
    fn persist_merge_seal<S: AgentJournalStore>(
        store: &mut S,
        materialized: &ReplayMaterialization,
    ) -> MergeSealId {
        let bytes = &materialized.state().merge;
        let state = BlobRef::of_bytes(bytes);
        store
            .put_blob(JournalBlobClass::LaneState, &state, bytes)
            .unwrap();
        let manifest = derive_lane_state::<(), ()>(
            materialized.heads().genesis,
            materialized.runtime().clone(),
            PersistedLane::Merge,
            LaneCursor::Merge {
                frontier: materialized.merge_frontier(),
            },
            bytes,
        )
        .unwrap();
        store.put(&manifest).unwrap();
        let seal = MergeSeal {
            genesis: materialized.heads().genesis,
            frontier: materialized.merge_frontier(),
            ordered_base: materialized.ordered_base(),
            merge_state: manifest.id(),
        };
        store.put(&seal).unwrap();
        seal.id()
    }

    #[cfg(feature = "std")]
    #[derive(Default)]
    struct ExactCreateRejectInvocations {
        executions: usize,
        merge_verifications: usize,
        merge_execution_order: Vec<MergeEventId>,
    }

    #[cfg(feature = "std")]
    impl ReplayExecutor for ExactCreateRejectInvocations {
        type Error = ();

        fn verify_merge_event(&mut self, _event: &MergeEvent) -> Result<bool, Self::Error> {
            self.merge_verifications += 1;
            Ok(true)
        }

        fn authenticate(
            &mut self,
            input: &ReplayInput,
            _before: &RuntimeState,
            _position: ReplayPosition,
        ) -> Result<(), Self::Error> {
            match &input.operation {
                ReplayOperation::Invoke { authority, .. }
                | ReplayOperation::Acknowledge { authority, .. } => authority
                    .signature
                    .first()
                    .copied()
                    .filter(|byte| *byte == 0xaa)
                    .map(|_| ())
                    .ok_or(()),
                ReplayOperation::CleanInvoke { authorization, .. } => {
                    let crate::agent_sdk::InvocationAuthorization::AuthorityReceipt(authority) =
                        authorization
                    else {
                        return Err(());
                    };
                    authority
                        .signature
                        .first()
                        .copied()
                        .filter(|byte| *byte == 0xaa)
                        .map(|_| ())
                        .ok_or(())
                }
                ReplayOperation::Management { .. } | ReplayOperation::SealMerge => Ok(()),
            }
        }

        fn execute(
            &mut self,
            input: &ReplayInput,
            before: &RuntimeState,
            position: ReplayPosition,
        ) -> Result<ReplayTransition, Self::Error> {
            self.executions += 1;
            if let ReplayPosition::Merge { id, .. } = position {
                self.merge_execution_order.push(id);
            }
            if let ReplayOperation::Management { request } = &input.operation {
                let decoded = decode_standard_runtime_state(before).map_err(|_| ())?;
                let mut runtime = StandardAgentRuntime::restore(decoded).map_err(|_| ())?;
                let disposition = if runtime.apply(request.clone()).is_ok() {
                    ReplayDisposition::Applied
                } else {
                    ReplayDisposition::Rejected
                };
                return Ok(ReplayTransition {
                    state: encode_standard_runtime_state(&runtime.snapshot()),
                    disposition,
                    result: None,
                    next_runtime: input.runtime.clone(),
                    products: ReplayProducts::default(),
                });
            }
            Ok(ReplayTransition {
                state: clock_only_state(input, before),
                disposition: ReplayDisposition::Rejected,
                result: Some(Err(ActorExecutionError::NotFound)),
                next_runtime: input.runtime.clone(),
                products: ReplayProducts::default(),
            })
        }

        fn execute_with_journal_context(
            &mut self,
            input: &ReplayInput,
            before: &RuntimeState,
            position: ReplayPosition,
            journal_context: Option<RuntimeJournalContext>,
        ) -> Result<ReplayTransition, Self::Error> {
            let Some(context) = journal_context else {
                return self.execute(input, before, position);
            };
            self.executions += 1;
            let ReplayOperation::Management { request } = &input.operation else {
                return Err(());
            };
            let decoded = decode_standard_runtime_state(before).map_err(|_| ())?;
            let mut runtime = StandardAgentRuntime::restore(decoded).map_err(|_| ())?;
            let result = runtime.apply_guest(Some(context), request.clone());
            Ok(ReplayTransition {
                state: encode_standard_runtime_state(&runtime.snapshot()),
                disposition: if result.is_ok() {
                    ReplayDisposition::Applied
                } else {
                    ReplayDisposition::Rejected
                },
                result: None,
                next_runtime: input.runtime.clone(),
                products: ReplayProducts::default(),
            })
        }
    }

    /// Test-only root admission. It still authenticates and executes the
    /// exact Create transition and derives the complete artifact closure; it
    /// exposes no callable authority constructor in non-test code.
    #[cfg(feature = "std")]
    pub(crate) fn admitted_genesis(admission: u8) -> ReplaySealedGenesis {
        let config = admitted_config();
        let create = admitted_create_input_for(config.clone(), admission);
        admitted_genesis_for(config, create)
    }

    #[cfg(feature = "std")]
    fn shared_admitted_genesis(admission: u8) -> ReplaySealedGenesis {
        let config = shared_admitted_config();
        let create = shared_admitted_create_input_for(config.clone(), admission);
        admitted_genesis_for(config, create)
    }

    #[cfg(feature = "std")]
    fn admitted_genesis_for(config: AgentConfig, create: ReplayInput) -> ReplaySealedGenesis {
        let mut executor = ExactCreateRejectInvocations::default();
        let is_shared = config.identity.profile == AgentProfile::Shared;
        let replica = config.replicas[0];
        let prepared = if config.identity.profile == AgentProfile::Shared {
            prepare_shared_genesis_for_test(create, replica, &mut executor)
        } else {
            ReplayPreparedGenesis::prepare(create, replica, &mut executor).unwrap()
        };
        let expected = prepared.expectations();
        let (root, signing_keys) = admitted_root_material(&config);
        let committee = root.initial_committee().clone();
        let claim = SystemAgentGenesisClaim::new(&root, expected).unwrap();
        let trusted = TrustedRootAnchor::verify_configured(
            root.clone(),
            root.config_version(),
            root.id(),
            root.config_commitment(),
            claim.authority_claim(),
        )
        .unwrap();
        let message = AuthorityQuorumCertificate::signing_message(
            committee.authority_binding(),
            committee.epoch(),
            committee.commitment(),
            claim.authority_claim(),
        );
        let mut signatures = signing_keys[..2]
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
        let certificate =
            AuthorityQuorumCertificate::new(&committee, claim.authority_claim(), signatures)
                .unwrap();
        let evidence = SystemAgentGenesisEvidence::new(claim, certificate).unwrap();
        let verified = evidence.verify(&trusted, expected).unwrap();
        if is_shared {
            seal_shared_prepared_genesis_for_test(&verified, evidence, prepared)
        } else {
            ReplaySealedGenesis::from_prepared_verified(&verified, evidence, prepared).unwrap()
        }
    }

    #[cfg(feature = "std")]
    fn seal_shared_prepared_genesis_for_test(
        verified: &VerifiedSystemAgentGenesis,
        admission_evidence: SystemAgentGenesisEvidence,
        prepared: ReplayPreparedGenesis,
    ) -> ReplaySealedGenesis {
        let ReplayOperation::Management { request } = &prepared.create.operation else {
            unreachable!()
        };
        let LifecycleRequest::Authorized { request, .. } = request else {
            unreachable!()
        };
        let LifecycleRequest::Create(config) = request.as_ref() else {
            unreachable!()
        };
        assert_eq!(config.identity.profile, AgentProfile::Shared);
        assert!(config.replicas.contains(&prepared.replica));
        let root_admission = verified.admission_record();
        let root_anchor = verified.root_anchor().clone();
        assert_eq!(root_admission.evidence(), verified.evidence_id());
        assert_eq!(admission_evidence.id(), verified.evidence_id());
        assert_eq!(verified.space(), prepared.create.runtime.space);
        assert_eq!(verified.system_agent(), prepared.create.runtime.agent);
        assert_eq!(verified.authority_binding(), config.authority.commitment());
        assert_eq!(
            verified.genesis_intent(),
            prepared.expectations.genesis_intent()
        );
        assert_eq!(
            verified.runtime_binding(),
            prepared.expectations.runtime_binding()
        );
        assert_eq!(
            verified.post_create_state(),
            prepared.expectations.post_create_state()
        );
        assert_eq!(
            verified.artifact_closure(),
            prepared.expectations.artifact_closure()
        );
        assert_eq!(verified.sequence(), prepared.expectations.sequence());

        let admission_record = AgentGenesisAdmissionRecord::root_bootstrap(root_admission).unwrap();

        let genesis = AgentJournalGenesis {
            admission: admission_record.id(),
            create: prepared.create,
        };
        genesis.validate().unwrap();
        let genesis_id = genesis.id();
        let artifacts = ArtifactClosure {
            genesis: genesis_id,
            artifacts: prepared.artifacts,
        };
        artifacts.validate().unwrap();
        let post_create = prepared.post_create;
        let replica = prepared.replica;
        let empty_frontier = MergeFrontier {
            genesis: genesis_id,
            events: Vec::new(),
        };
        ReplaySealedGenesis {
            genesis,
            post_create,
            empty_frontier,
            ordered_invocations: InvocationIndexManifest::empty(
                genesis_id,
                InvocationOwnershipScope::Ordered,
            ),
            merge_invocations: InvocationIndexManifest::empty(
                genesis_id,
                InvocationOwnershipScope::Merge,
            ),
            local_invocations: InvocationIndexManifest::empty(
                genesis_id,
                InvocationOwnershipScope::Local(replica.node),
            ),
            artifacts,
            root_anchor,
            root_admission_record: root_admission,
            admission_record,
            admission_evidence,
            replica,
        }
    }

    #[cfg(feature = "std")]
    fn prepare_shared_genesis_for_test(
        create: ReplayInput,
        replica: AgentReplica,
        executor: &mut ExactCreateRejectInvocations,
    ) -> ReplayPreparedGenesis {
        create.validate().unwrap();
        validate_position::<(), ()>(&create, ReplayPosition::Genesis).unwrap();
        let ReplayOperation::Management { request } = &create.operation else {
            unreachable!()
        };
        let LifecycleRequest::Authorized { request, .. } = request else {
            unreachable!()
        };
        let LifecycleRequest::Create(config) = request.as_ref() else {
            unreachable!()
        };
        assert_eq!(config.identity.profile, AgentProfile::Shared);
        assert!(config.replicas.contains(&replica));

        let before = RuntimeState::default();
        executor
            .authenticate(&create, &before, ReplayPosition::Genesis)
            .unwrap();
        let transition = executor
            .execute(&create, &before, ReplayPosition::Genesis)
            .unwrap();
        validate_transition::<(), ()>(
            &create,
            &before,
            &transition,
            ReplayPosition::Genesis,
            &create.runtime,
            false,
            false,
            None,
            None,
        )
        .unwrap();
        assert_eq!(transition.disposition, ReplayDisposition::Applied);
        assert!(transition.result.is_none());
        assert_eq!(transition.next_runtime, create.runtime);
        let post_create = transition.state;
        let decoded = decode_standard_runtime_state(&post_create).unwrap();
        assert_eq!(decoded.config.as_ref(), Some(config));
        let artifacts = derive_standard_artifact_references::<core::convert::Infallible>(
            &create.runtime,
            &post_create,
        )
        .unwrap();
        let expectations = SystemAgentGenesisExpectations::new(
            create.runtime.commitment(),
            request.commitment(),
            system_genesis_post_create_state_commitment(&post_create).unwrap(),
            system_genesis_artifact_closure_commitment(&artifacts).unwrap(),
            match &create.operation {
                ReplayOperation::Management {
                    request: LifecycleRequest::Authorized { admission, .. },
                } => admission.receipt.claim.sequence,
                _ => unreachable!(),
            },
        )
        .unwrap();
        ReplayPreparedGenesis {
            create,
            replica,
            post_create,
            artifacts,
            expectations,
        }
    }

    #[cfg(feature = "std")]
    fn initialized_replay_store() -> MemoryAgentJournalStore {
        let sealed = admitted_genesis(0xb1);
        let node = admitted_config().replicas[0].node;
        let mut store = MemoryAgentJournalStore::new(admitted_runtime().agent, node).unwrap();
        store
            .put_blob(
                JournalBlobClass::CatalogArtifact,
                &admitted_runtime().package,
                b"replay-runtime-package",
            )
            .unwrap();
        assert!(store.initialize(&sealed).unwrap());
        store
    }

    #[cfg(feature = "std")]
    fn initialized_shared_replay_store() -> MemoryAgentJournalStore {
        let sealed = shared_admitted_genesis(0xc5);
        let config = shared_admitted_config();
        let node = config.replicas[0].node;
        let runtime = admitted_runtime();
        let mut store = MemoryAgentJournalStore::new(runtime.agent, node).unwrap();
        store
            .put_blob(
                JournalBlobClass::CatalogArtifact,
                &runtime.package,
                b"replay-runtime-package",
            )
            .unwrap();
        assert!(store.initialize(&sealed).unwrap());
        store
    }

    #[cfg(feature = "std")]
    fn publish_test_merge(
        store: &mut MemoryAgentJournalStore,
        executor: &mut ExactCreateRejectInvocations,
        materialized: &ReplayMaterialization,
        event: &MergeEvent,
    ) -> ReplayMaterialization {
        let prepared =
            match prepare_merge(store, executor, &NoPrunedOrderedBases, materialized, event)
                .unwrap()
            {
                ReplayPreparation::Ready(prepared) => prepared,
                ReplayPreparation::AlreadyCommitted(_) => panic!("fresh Merge event was committed"),
            };
        let (_, successor, _) = prepared.publish().unwrap();
        successor
    }

    #[cfg(feature = "std")]
    #[derive(Clone, Copy, Debug, PartialEq, Eq)]
    enum SharedClaimTamper {
        None,
        Admission,
        MergeProjection,
        MergeInvocations,
        Runtime,
        Control,
        Linear,
        OrderedInvocations,
        Artifacts,
        MergeFence,
        SealedInvocations,
        FenceAncestry,
    }

    #[cfg(feature = "std")]
    fn shared_test_committee(runtime: &RuntimeBinding) -> (AgentReplicaCommittee, Vec<SigningKey>) {
        const PEER_ID_PREFIX: [u8; 6] = [0x00, 0x24, 0x08, 0x01, 0x12, 0x20];
        let keys = [0xc2, 0xc3, 0xc4]
            .into_iter()
            .map(|byte| SigningKey::from_bytes(&[byte; 32]))
            .collect::<Vec<_>>();
        let mut members = keys
            .iter()
            .map(|key| {
                let mut peer_id = PEER_ID_PREFIX.to_vec();
                peer_id.extend_from_slice(&key.verifying_key().to_bytes());
                let public_key = key.verifying_key().to_bytes();
                AgentReplicaMember::new(
                    AgentReplica {
                        node: NodeId::of_authenticated_peer(&peer_id),
                        principal: PrincipalId::of_public_key(&public_key),
                        role: ReplicaRole::Voter,
                    },
                    peer_id.clone(),
                    public_key,
                    Some(derive_replica_raft_slot(&peer_id)),
                )
                .unwrap()
            })
            .collect::<Vec<_>>();
        members.sort_by_key(|member| member.replica().node);
        (
            AgentReplicaCommittee::new(runtime.space, runtime.agent, AgentProfile::Shared, members)
                .unwrap(),
            keys,
        )
    }

    #[cfg(feature = "std")]
    fn shared_lane_projection(
        genesis: AgentJournalGenesisId,
        runtime: RuntimeBinding,
        lane: PersistedLane,
        cursor: LaneCursor,
        state: &[u8],
    ) -> SharedLaneProjection {
        let manifest = derive_lane_state::<(), ()>(genesis, runtime, lane, cursor, state).unwrap();
        SharedLaneProjection::new(manifest.id(), manifest.state).unwrap()
    }

    #[cfg(feature = "std")]
    fn shared_claim_for_test(
        committee: AgentReplicaCommitteeId,
        entry: &OrderedEntry,
        observed: &ReplayMaterialization,
        successor: &ReplayMaterialization,
        tamper: SharedClaimTamper,
    ) -> OrderedCommitClaim {
        assert_eq!(observed.merge_frontier(), entry.merge_frontier);
        assert_eq!(successor.ordered_base().head, Some(entry.id()));
        let mut admission = observed.heads().admission;
        let mut merge = shared_lane_projection(
            entry.genesis,
            entry.input.runtime.clone(),
            PersistedLane::Merge,
            LaneCursor::Merge {
                frontier: entry.merge_frontier,
            },
            &observed.state().merge,
        );
        let mut merge_invocations = observed.heads().merge_invocations;
        let mut runtime = successor.runtime().clone();
        let mut control = shared_lane_projection(
            entry.genesis,
            runtime.clone(),
            PersistedLane::Control,
            LaneCursor::Ordered {
                base: successor.ordered_base(),
            },
            &successor.state().control,
        );
        let mut linear = shared_lane_projection(
            entry.genesis,
            runtime.clone(),
            PersistedLane::Linear,
            LaneCursor::Ordered {
                base: successor.ordered_base(),
            },
            &successor.state().linear,
        );
        let mut ordered_invocations = successor.heads().ordered_invocations;
        let mut artifacts = successor.artifacts().id();
        let mut merge_fence = successor.heads().merge_fence;
        let mut sealed_merge = successor.heads().merge_seal.map(|seal| {
            let fence = successor.fence.as_ref().unwrap();
            SharedSealedMergeProjection::new(
                seal,
                fence.frontier,
                merge.clone(),
                successor.merge_boundary_invocations,
            )
            .unwrap()
        });
        let mut fence_ancestry = successor.fence_ancestry.commitment();

        match tamper {
            SharedClaimTamper::None => {}
            SharedClaimTamper::Admission => {
                admission = AgentGenesisAdmissionId::from_bytes([0xd1; 32]);
            }
            SharedClaimTamper::MergeProjection => {
                merge = SharedLaneProjection::new(
                    LaneStateId([0xd2; 32]),
                    BlobRef::of_bytes(b"tampered merge projection"),
                )
                .unwrap();
                if let Some(sealed) = sealed_merge.as_ref() {
                    sealed_merge = Some(
                        SharedSealedMergeProjection::new(
                            sealed.seal(),
                            sealed.frontier(),
                            merge.clone(),
                            sealed.invocations(),
                        )
                        .unwrap(),
                    );
                }
            }
            SharedClaimTamper::MergeInvocations => {
                merge_invocations = InvocationIndexId([0xd3; 32]);
            }
            SharedClaimTamper::Runtime => {
                runtime.deployment = DeploymentId([0xd4; 32]);
            }
            SharedClaimTamper::Control => {
                control = SharedLaneProjection::new(
                    LaneStateId([0xd5; 32]),
                    BlobRef::of_bytes(b"tampered control projection"),
                )
                .unwrap();
            }
            SharedClaimTamper::Linear => {
                linear = SharedLaneProjection::new(
                    LaneStateId([0xd6; 32]),
                    BlobRef::of_bytes(b"tampered linear projection"),
                )
                .unwrap();
            }
            SharedClaimTamper::OrderedInvocations => {
                ordered_invocations = InvocationIndexId([0xd7; 32]);
            }
            SharedClaimTamper::Artifacts => {
                artifacts = ArtifactClosureId([0xd8; 32]);
            }
            SharedClaimTamper::MergeFence => {
                merge_fence = OrderedBase::post_genesis();
                sealed_merge = None;
            }
            SharedClaimTamper::SealedInvocations => {
                let sealed = sealed_merge.as_ref().unwrap();
                sealed_merge = Some(
                    SharedSealedMergeProjection::new(
                        sealed.seal(),
                        sealed.frontier(),
                        sealed.lane().clone(),
                        InvocationIndexId([0xd9; 32]),
                    )
                    .unwrap(),
                );
            }
            SharedClaimTamper::FenceAncestry => fence_ancestry = Hash([0xda; 32]),
        }

        OrderedCommitClaim::new(
            entry.genesis,
            admission,
            committee,
            1,
            1,
            successor.ordered_base(),
            entry.merge_frontier,
            merge,
            merge_invocations,
            runtime,
            control,
            linear,
            ordered_invocations,
            artifacts,
            merge_fence,
            sealed_merge,
            fence_ancestry,
        )
        .unwrap()
    }

    #[cfg(feature = "std")]
    fn shared_qc_for_test(
        committee: &AgentReplicaCommittee,
        keys: &[SigningKey],
        claim: OrderedCommitClaim,
    ) -> ReplicaQuorumCertificate {
        let message = ReplicaQuorumCertificate::signing_message(committee.id(), claim.commitment());
        let mut signatures = keys[..committee.quorum_threshold()]
            .iter()
            .map(|key| {
                let mut peer_id = vec![0x00, 0x24, 0x08, 0x01, 0x12, 0x20];
                peer_id.extend_from_slice(&key.verifying_key().to_bytes());
                ReplicaCommitSignature::new(
                    NodeId::of_authenticated_peer(&peer_id),
                    key.sign(&message.0).to_bytes(),
                )
                .unwrap()
            })
            .collect::<Vec<_>>();
        signatures.sort_by_key(ReplicaCommitSignature::signer);
        ReplicaQuorumCertificate::new(claim, signatures).unwrap()
    }

    #[cfg(feature = "std")]
    struct TestCommittedRaftLog {
        index: u64,
        term: u64,
        payload: Vec<u8>,
    }

    #[cfg(feature = "std")]
    impl DurableAgentRaftLogWitness for TestCommittedRaftLog {
        type Error = core::convert::Infallible;

        fn read_committed_payload(
            &self,
            index: u64,
        ) -> Result<Option<(u64, u64, u64, Vec<u8>)>, Self::Error> {
            Ok((index == self.index)
                .then(|| (self.index, self.term, self.index, self.payload.clone())))
        }
    }

    #[cfg(all(feature = "std", feature = "storage"))]
    fn committed_shared_for_test(
        entry: OrderedEntry,
        materialized: &ReplayMaterialization,
        journal_store: JournalStoreInstanceId,
    ) -> Result<CommittedSharedOrdered, ReplayValidationError> {
        let (committee, _) = shared_test_committee(&entry.input.runtime);
        let route = AgentRouteKey::new(
            entry.input.runtime.space,
            entry.input.runtime.agent,
            entry.genesis,
            materialized.heads().admission,
            committee.id(),
        )
        .unwrap();
        let command = AgentRaftCommand::Ordered {
            route,
            artifact_batch: None,
            entry,
        };
        let witness = TestCommittedRaftLog {
            index: 1,
            term: 1,
            payload: command.encode(),
        };
        let committed = CommittedAgentRaftEntry::from_durable_log(&witness, 1).unwrap();
        let directory = std::env::temp_dir().join(alloc::format!(
            "vos_shared_replay_reservation_{}_{}",
            std::process::id(),
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_nanos(),
        ));
        std::fs::create_dir_all(&directory).unwrap();
        let database =
            alloc::sync::Arc::new(Database::create(directory.join("evidence.redb")).unwrap());
        let local_node = committee.members()[0].replica().node;
        let ledger = AgentRaftEvidenceLedger::open(
            database,
            route,
            committee.clone(),
            local_node,
            journal_store,
        )
        .unwrap();
        let reserved = ledger.reserve_ordered_application(&committed).unwrap();
        let token =
            CommittedSharedOrdered::from_reserved_raft_application(reserved, &committee, None);
        drop(ledger);
        let _ = std::fs::remove_dir_all(directory);
        token
    }

    #[cfg(all(feature = "std", feature = "storage"))]
    fn committed_placeholder_for_test(
        entry: OrderedEntry,
        materialized: &ReplayMaterialization,
        journal_store: JournalStoreInstanceId,
    ) -> Result<CommittedSharedOrdered, ReplayValidationError> {
        committed_shared_for_test(entry, materialized, journal_store)
    }

    #[cfg(feature = "std")]
    fn persist_projection_seal(
        store: &mut MemoryAgentJournalStore,
        materialized: &ReplayMaterialization,
        frontier: MergeFrontierId,
        merge: &[u8],
    ) -> MergeSealId {
        let state = BlobRef::of_bytes(merge);
        store
            .put_blob(JournalBlobClass::LaneState, &state, merge)
            .unwrap();
        let manifest = derive_lane_state::<(), ()>(
            materialized.heads().genesis,
            materialized.runtime().clone(),
            PersistedLane::Merge,
            LaneCursor::Merge { frontier },
            merge,
        )
        .unwrap();
        store.put(&manifest).unwrap();
        let seal = MergeSeal {
            genesis: materialized.heads().genesis,
            frontier,
            ordered_base: materialized.ordered_base(),
            merge_state: manifest.id(),
        };
        store.put(&seal).unwrap();
        seal.id()
    }

    #[cfg(feature = "std")]
    fn initialized_linear_replay_store() -> LinearReplayStore {
        let inner = initialized_replay_store();
        let heads = inner.heads().unwrap().unwrap();
        LinearReplayStore {
            inner,
            heads,
            history_nodes: BTreeMap::new(),
        }
    }

    #[cfg(feature = "std")]
    fn quota_invocation(mode: MethodMode, ordinal: u64) -> ReplayInput {
        let mut input = admitted_invocation(mode, 0xec);
        let ReplayOperation::Invoke {
            invocation,
            authority,
            ..
        } = &mut input.operation
        else {
            unreachable!()
        };
        let mut invocation_id = [0x61; 32];
        invocation_id[24..].copy_from_slice(&ordinal.to_be_bytes());
        invocation.invocation = InvocationId(invocation_id);
        invocation.message = ordinal.to_le_bytes().to_vec();
        authority.claim.authorization = invocation.authorization_message();
        assert!(input.validate().is_ok());
        input
    }

    #[cfg(feature = "std")]
    fn quota_anchor_bytes(tag: u8, ordinal: u64) -> [u8; 32] {
        let mut bytes = [tag; 32];
        bytes[24..].copy_from_slice(&ordinal.to_be_bytes());
        bytes
    }

    /// Install a storage-closed, authenticated index at exactly the live
    /// identity ceiling without consuming replay suffix entries. The journal
    /// anchors are deliberately orphaned: this helper tests capacity before a
    /// prospective publication, while the Linear store's synthetic head lets
    /// the preparation path authenticate the exact full manifest.
    #[cfg(feature = "std")]
    fn seed_full_invocation_scope(
        store: &mut LinearReplayStore,
        materialized: &mut ReplayMaterialization,
        mode: MethodMode,
    ) -> ReplayInput {
        let scope = match mode {
            MethodMode::Linear => InvocationOwnershipScope::Ordered,
            MethodMode::Merge => InvocationOwnershipScope::Merge,
            MethodMode::Local => InvocationOwnershipScope::Local(materialized.heads.node),
            MethodMode::Query | MethodMode::LinearizableQuery | MethodMode::LocalQuery => {
                panic!("quota fixture requires a durable invocation scope")
            }
        };
        let mut anchored_inputs = Vec::new();
        for ordinal in 1..=MAX_INVOCATION_INDEX_LIVE_ENTRIES {
            let input = quota_invocation(mode, ordinal);
            let anchor = match scope {
                InvocationOwnershipScope::Ordered => {
                    let entry = OrderedEntry {
                        genesis: materialized.heads.genesis,
                        index: 1,
                        parent: None,
                        merge_frontier: materialized.heads.merge_frontier,
                        merge_seal: None,
                        input: input.clone(),
                    };
                    assert!(entry.validate().is_ok());
                    store.put(&entry).unwrap();
                    InvocationOutcomeAnchor::Ordered { entry: entry.id() }
                }
                InvocationOwnershipScope::Local(node) => {
                    let entry = LocalEntry {
                        genesis: materialized.heads.genesis,
                        node,
                        revision: 1,
                        parent: None,
                        ordered_base: materialized.ordered_base(),
                        merge_frontier: materialized.heads.merge_frontier,
                        input: input.clone(),
                    };
                    assert!(entry.validate().is_ok());
                    store.put(&entry).unwrap();
                    InvocationOutcomeAnchor::Local { entry: entry.id() }
                }
                InvocationOwnershipScope::Merge => {
                    let event = MergeEvent {
                        genesis: materialized.heads.genesis,
                        committee: None,
                        author: materialized.heads.node,
                        ordered_base: materialized.ordered_base(),
                        causal_height: 1,
                        parents: Vec::new(),
                        input: input.clone(),
                        signature: vec![0xdd; ED25519_SIGNATURE_BYTES],
                    };
                    assert!(event.validate().is_ok());
                    store.put(&event).unwrap();
                    InvocationOutcomeAnchor::Merge {
                        source_event: event.id(),
                        finalizing_entry: OrderedEntryId(quota_anchor_bytes(0x62, ordinal)),
                        seal: MergeSealId(quota_anchor_bytes(0x63, ordinal)),
                    }
                }
            };
            anchored_inputs.push((input, anchor));
        }

        let roots = materialized.invocation_indexes();
        let before = materialized.state.clone();
        let mut indexes = InvocationIndexes::open(store, roots.0, roots.1, roots.2).unwrap();
        let mut owners = Vec::with_capacity(anchored_inputs.len());
        for (input, anchor) in &anchored_inputs {
            let ReplayOperation::Invoke { invocation, .. } = &input.operation else {
                unreachable!()
            };
            let key = InvocationOwnershipKey {
                scope,
                invocation: invocation.invocation,
            };
            let result_state = match scope {
                InvocationOwnershipScope::Merge => {
                    let InvocationOutcomeAnchor::Merge { source_event, .. } = *anchor else {
                        unreachable!()
                    };
                    InvocationResultState::PendingMerge { source_event }
                }
                InvocationOwnershipScope::Ordered | InvocationOwnershipScope::Local(_) => {
                    let after = clock_only_state(input, &before);
                    let outcome = InvocationOutcomeRecord::from_runtime_states(
                        materialized.heads.genesis,
                        scope,
                        *anchor,
                        input,
                        &before,
                        &after,
                        Err(ActorExecutionError::NotFound),
                    )
                    .unwrap();
                    let reference = indexes.persist_outcome(&outcome).unwrap();
                    InvocationResultState::Retained {
                        disposition: outcome.disposition(),
                        outcome: reference,
                    }
                }
            };
            owners.push((
                key,
                InvocationOwnershipValue {
                    scope,
                    request_commitment: invocation.commitment(),
                    first_input: input.id(),
                    lane: input.persisted_lane(),
                    node: match scope {
                        InvocationOwnershipScope::Local(node) => Some(node),
                        InvocationOwnershipScope::Ordered | InvocationOwnershipScope::Merge => None,
                    },
                    result_state,
                },
            ));
        }
        let full_root = indexes.record_batch(scope, &owners).unwrap();
        let manifest = *indexes.manifest(scope).unwrap();
        assert_eq!(manifest.entries, MAX_INVOCATION_INDEX_LIVE_ENTRIES);
        drop(indexes);

        let mut heads = store.heads.clone();
        let previous = heads.id();
        heads.publication_revision += 1;
        heads.previous = Some(previous);
        match scope {
            InvocationOwnershipScope::Ordered => heads.ordered_invocations = full_root,
            InvocationOwnershipScope::Merge => heads.merge_invocations = full_root,
            InvocationOwnershipScope::Local(_) => heads.local_invocations = full_root,
        }
        assert!(heads.validate().is_ok());
        store.heads = heads.clone();
        materialized.heads_id = heads.id();
        materialized.heads = heads;
        anchored_inputs[0].0.clone()
    }

    #[derive(Default)]
    struct RejectingExecutor {
        calls: usize,
        authentications: usize,
    }

    struct RejectingAuthenticationExecutor;

    impl ReplayExecutor for RejectingAuthenticationExecutor {
        type Error = ();

        fn verify_merge_event(&mut self, _event: &MergeEvent) -> Result<bool, Self::Error> {
            Ok(true)
        }

        fn authenticate(
            &mut self,
            _input: &ReplayInput,
            _before: &RuntimeState,
            _position: ReplayPosition,
        ) -> Result<(), Self::Error> {
            Err(())
        }

        fn execute(
            &mut self,
            _input: &ReplayInput,
            _before: &RuntimeState,
            _position: ReplayPosition,
        ) -> Result<ReplayTransition, Self::Error> {
            Err(())
        }
    }

    impl ReplayExecutor for RejectingExecutor {
        type Error = ();

        fn verify_merge_event(&mut self, _event: &MergeEvent) -> Result<bool, Self::Error> {
            Ok(true)
        }

        fn authenticate(
            &mut self,
            input: &ReplayInput,
            _before: &RuntimeState,
            _position: ReplayPosition,
        ) -> Result<(), Self::Error> {
            self.authentications += 1;
            let signature: &[u8] = match &input.operation {
                ReplayOperation::Invoke { authority, .. }
                | ReplayOperation::Acknowledge { authority, .. } => authority.signature.as_slice(),
                ReplayOperation::CleanInvoke { authorization, .. } => {
                    let crate::agent_sdk::InvocationAuthorization::AuthorityReceipt(authority) =
                        authorization
                    else {
                        return Err(());
                    };
                    authority.signature.as_slice()
                }
                ReplayOperation::Management { .. } | ReplayOperation::SealMerge => return Ok(()),
            };
            signature
                .first()
                .copied()
                .filter(|byte| *byte == 0x55)
                .map(|_| ())
                .ok_or(())
        }

        fn execute(
            &mut self,
            input: &ReplayInput,
            before: &RuntimeState,
            _position: ReplayPosition,
        ) -> Result<ReplayTransition, Self::Error> {
            self.calls += 1;
            Ok(ReplayTransition {
                state: clock_only_state(input, before),
                disposition: ReplayDisposition::Rejected,
                result: Some(Err(ActorExecutionError::NotFound)),
                next_runtime: input.runtime.clone(),
                products: ReplayProducts::default(),
            })
        }
    }

    #[derive(Default)]
    struct RetainedRecoveryExecutor {
        executions: usize,
        authentications: usize,
    }

    impl ReplayExecutor for RetainedRecoveryExecutor {
        type Error = ();

        fn verify_merge_event(&mut self, _event: &MergeEvent) -> Result<bool, Self::Error> {
            Ok(true)
        }

        fn authenticate(
            &mut self,
            _input: &ReplayInput,
            _before: &RuntimeState,
            _position: ReplayPosition,
        ) -> Result<(), Self::Error> {
            self.authentications += 1;
            Ok(())
        }

        fn execute(
            &mut self,
            input: &ReplayInput,
            before: &RuntimeState,
            _position: ReplayPosition,
        ) -> Result<ReplayTransition, Self::Error> {
            self.executions += 1;
            Ok(ReplayTransition {
                state: clock_only_state(input, before),
                disposition: ReplayDisposition::Rejected,
                result: Some(Err(ActorExecutionError::NotFound)),
                next_runtime: input.runtime.clone(),
                products: ReplayProducts::default(),
            })
        }
    }

    struct UncommittedRefusalExecutor {
        error: ActorExecutionError,
        authentications: usize,
        executions: usize,
        merge_verifications: usize,
        mutate_state: bool,
        emit_products: bool,
    }

    impl UncommittedRefusalExecutor {
        fn exact(error: ActorExecutionError) -> Self {
            Self {
                error,
                authentications: 0,
                executions: 0,
                merge_verifications: 0,
                mutate_state: false,
                emit_products: false,
            }
        }
    }

    impl ReplayExecutor for UncommittedRefusalExecutor {
        type Error = ();

        fn verify_merge_event(&mut self, _event: &MergeEvent) -> Result<bool, Self::Error> {
            self.merge_verifications += 1;
            Ok(true)
        }

        fn authenticate(
            &mut self,
            _input: &ReplayInput,
            _before: &RuntimeState,
            _position: ReplayPosition,
        ) -> Result<(), Self::Error> {
            self.authentications += 1;
            Ok(())
        }

        fn execute(
            &mut self,
            input: &ReplayInput,
            before: &RuntimeState,
            _position: ReplayPosition,
        ) -> Result<ReplayTransition, Self::Error> {
            self.executions += 1;
            let mut state = before.clone();
            if self.mutate_state {
                state.control.push(0xff);
            }
            Ok(ReplayTransition {
                state,
                disposition: ReplayDisposition::Rejected,
                result: Some(Err(self.error)),
                next_runtime: input.runtime.clone(),
                products: ReplayProducts {
                    effects: self.emit_products,
                    ..ReplayProducts::default()
                },
            })
        }
    }

    struct ProductExecutor;

    impl ReplayExecutor for ProductExecutor {
        type Error = ();

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
            Ok(ReplayTransition {
                state: before.clone(),
                disposition: ReplayDisposition::Applied,
                result: Some(successful_result(input)),
                next_runtime: input.runtime.clone(),
                products: ReplayProducts {
                    effects: true,
                    ..ReplayProducts::default()
                },
            })
        }
    }

    fn build_ordered(count: u64, retained_after: u64) -> (MemorySource, OrderedBase, OrderedBase) {
        let genesis = AgentJournalGenesisId([0x61; 32]);
        let merge_frontier = MergeFrontier {
            genesis,
            events: Vec::new(),
        }
        .id();
        let mut source = MemorySource::default();
        let mut parent = None;
        let mut checkpoint = OrderedBase::post_genesis();
        for index in 1..=count {
            let entry = OrderedEntry {
                genesis,
                index,
                parent,
                merge_frontier,
                merge_seal: None,
                input: input(MethodMode::Linear),
            };
            let id = entry.id();
            if index == retained_after {
                checkpoint = OrderedBase {
                    index,
                    head: Some(id),
                };
            }
            if index > retained_after {
                source.ordered.insert(id, entry);
            }
            parent = Some(id);
        }
        (
            source,
            checkpoint,
            OrderedBase {
                index: count,
                head: parent,
            },
        )
    }

    #[test]
    fn long_ordered_history_replays_a_short_checkpoint_suffix() {
        let genesis = AgentJournalGenesisId([0x61; 32]);
        let (source, checkpoint, target) = build_ordered(2_000, 1_900);
        let replay = load_ordered_suffix(&source, genesis, checkpoint, target).unwrap();
        assert_eq!(replay.entries().len(), 100);
        assert!(replay.contains_base(target));
    }

    #[test]
    fn ordered_suffix_over_the_bound_fails_closed() {
        let genesis = AgentJournalGenesisId([0x61; 32]);
        let (source, checkpoint, target) = build_ordered(1_025, 0);
        assert!(matches!(
            load_ordered_suffix(&source, genesis, checkpoint, target),
            Err(ReplayError::ReplayLimit)
        ));
    }

    #[test]
    fn long_local_history_replays_a_short_checkpoint_suffix() {
        let genesis = AgentJournalGenesisId([0x62; 32]);
        let node = NodeId([0x63; 32]);
        let merge_frontier = MergeFrontier {
            genesis,
            events: Vec::new(),
        }
        .id();
        let mut source = MemorySource::default();
        let mut parent = None;
        let mut checkpoint_head = None;
        for revision in 1..=2_000 {
            let entry = LocalEntry {
                genesis,
                node,
                revision,
                parent,
                ordered_base: OrderedBase::post_genesis(),
                merge_frontier,
                input: input(MethodMode::Local),
            };
            let id = entry.id();
            if revision == 1_900 {
                checkpoint_head = Some(id);
            }
            if revision > 1_900 {
                source.local.insert(id, entry);
            }
            parent = Some(id);
        }
        let replay = load_local_suffix(
            &source,
            genesis,
            node,
            1_900,
            checkpoint_head,
            2_000,
            parent,
        )
        .unwrap();
        assert_eq!(replay.entries().len(), 100);
    }

    #[test]
    fn merge_suffix_stops_at_retained_sealed_tip() {
        let genesis = AgentJournalGenesisId([0x64; 32]);
        let mut source = MemorySource::default();
        let mut parent = None;
        let mut checkpoint_tip = None;
        let mut checkpoint_height = 0;
        for height in 1..=2_000 {
            let event = MergeEvent {
                genesis,
                committee: None,
                author: NodeId([0x65; 32]),
                ordered_base: OrderedBase::post_genesis(),
                causal_height: height,
                parents: parent.into_iter().collect(),
                input: input(MethodMode::Merge),
                signature: vec![0x66; ED25519_SIGNATURE_BYTES],
            };
            let id = event.id();
            if height == 1_900 {
                checkpoint_tip = Some(id);
                checkpoint_height = height;
                source.events.insert(id, event);
            } else if height > 1_900 {
                source.events.insert(id, event);
            }
            parent = Some(id);
        }
        let checkpoint_frontier = MergeFrontier {
            genesis,
            events: vec![checkpoint_tip.unwrap()],
        };
        let checkpoint_id = checkpoint_frontier.id();
        source.frontiers.insert(checkpoint_id, checkpoint_frontier);
        let target_frontier = MergeFrontier {
            genesis,
            events: vec![parent.unwrap()],
        };
        let target_id = target_frontier.id();
        source.frontiers.insert(target_id, target_frontier);

        let base = load_structural_merge_base(&source, genesis, checkpoint_id).unwrap();
        assert_eq!(base.roots.len(), 1);
        assert_eq!(base.roots[0].id, checkpoint_tip.unwrap());
        assert_eq!(base.roots[0].causal_height, checkpoint_height);
        let replay = load_structural_merge_suffix(&source, &base, target_id).unwrap();
        assert_eq!(replay.events().len(), 100);
    }

    #[test]
    fn ownership_duplicates_and_divergence_advance_ordered_runtime() {
        let genesis = AgentJournalGenesisId([0x71; 32]);
        let mut machine = ReplayMachine::from_genesis(genesis, runtime()).unwrap();
        let mut executor = RejectingExecutor::default();
        let before = standard_before();
        let merge_frontier = MergeFrontierId([0x72; 32]);
        let first = input(MethodMode::Linear);
        let first_id = OrderedEntryId([0x73; 32]);
        let step = machine
            .apply::<_, ()>(
                &mut executor,
                &first,
                &before,
                ReplayPosition::Ordered {
                    id: first_id,
                    index: 1,
                    merge_frontier,
                    merge_seal: None,
                },
            )
            .unwrap();
        assert_eq!(
            step.outcome(),
            ReplayStepOutcome::Applied(ReplayDisposition::Rejected)
        );
        let ordered_key = InvocationOwnershipKey {
            scope: InvocationOwnershipScope::Ordered,
            invocation: InvocationId([0x51; 32]),
        };
        let InvocationIndexLookup::Live(owner) =
            machine.ownership.lookup(ordered_key).unwrap().unwrap()
        else {
            panic!("fresh invocation must remain live");
        };
        assert!(matches!(
            owner.result_state,
            InvocationResultState::Retained {
                disposition: InvocationDisposition::Rejected,
                ..
            }
        ));
        assert_eq!(owner.disposition(), Some(InvocationDisposition::Rejected));

        let duplicate_id = OrderedEntryId([0x74; 32]);
        let duplicate = machine
            .apply::<_, ()>(
                &mut executor,
                &first,
                &before,
                ReplayPosition::Ordered {
                    id: duplicate_id,
                    index: 2,
                    merge_frontier,
                    merge_seal: None,
                },
            )
            .unwrap();
        assert_eq!(duplicate.outcome(), ReplayStepOutcome::ExactDuplicate);
        assert!(
            machine
                .runtime_at(OrderedBase {
                    index: 2,
                    head: Some(duplicate_id),
                })
                .is_some()
        );

        let divergent = input_with_message(MethodMode::Linear, vec![2]);
        let divergent_id = OrderedEntryId([0x75; 32]);
        let divergent = machine
            .apply::<_, ()>(
                &mut executor,
                &divergent,
                &before,
                ReplayPosition::Ordered {
                    id: divergent_id,
                    index: 3,
                    merge_frontier,
                    merge_seal: None,
                },
            )
            .unwrap();
        assert_eq!(divergent.outcome(), ReplayStepOutcome::DivergentInvocation);
        assert!(
            machine
                .runtime_at(OrderedBase {
                    index: 3,
                    head: Some(divergent_id),
                })
                .is_some()
        );
        assert_eq!(executor.calls, 1);

        let local = input(MethodMode::Local);
        let local_step = machine
            .apply::<_, ()>(
                &mut executor,
                &local,
                &before,
                ReplayPosition::Local {
                    id: LocalEntryId([0x76; 32]),
                    node: NodeId([0x77; 32]),
                    revision: 1,
                    ordered_base: OrderedBase::post_genesis(),
                    merge_frontier,
                },
            )
            .unwrap();
        assert_eq!(
            local_step.outcome(),
            ReplayStepOutcome::Applied(ReplayDisposition::Rejected)
        );
        assert_eq!(executor.calls, 2);
    }

    #[test]
    fn ownership_shortcuts_authenticate_before_advancing_the_journal() {
        let genesis = AgentJournalGenesisId([0x78; 32]);
        let mut machine = ReplayMachine::from_genesis(genesis, runtime()).unwrap();
        let mut executor = RejectingExecutor::default();
        let before = standard_before();
        let merge_frontier = MergeFrontierId([0x79; 32]);
        let first = input(MethodMode::Linear);
        let first_id = OrderedEntryId([0x7a; 32]);
        machine
            .apply::<_, ()>(
                &mut executor,
                &first,
                &before,
                ReplayPosition::Ordered {
                    id: first_id,
                    index: 1,
                    merge_frontier,
                    merge_seal: None,
                },
            )
            .unwrap();
        assert_eq!(executor.calls, 1);
        assert_eq!(executor.authentications, 1);

        // The request commitment is still exact, but the content-addressed
        // retry carries a forged receipt. It must fail before the duplicate
        // shortcut can advance the ordered runtime.
        let mut forged_duplicate = first.clone();
        let ReplayOperation::Invoke { authority, .. } = &mut forged_duplicate.operation else {
            unreachable!();
        };
        authority.signature[0] = 0x56;
        let duplicate_id = OrderedEntryId([0x7b; 32]);
        assert!(matches!(
            machine.apply::<_, ()>(
                &mut executor,
                &forged_duplicate,
                &before,
                ReplayPosition::Ordered {
                    id: duplicate_id,
                    index: 2,
                    merge_frontier,
                    merge_seal: None,
                },
            ),
            Err(ReplayError::Executor(()))
        ));
        assert!(
            machine
                .runtime_at(OrderedBase {
                    index: 2,
                    head: Some(duplicate_id),
                })
                .is_none()
        );

        // A forged divergent reuse is rejected at the same boundary and does
        // not become durable denial-of-service input either.
        let mut forged_divergent = input_with_message(MethodMode::Linear, vec![2]);
        let ReplayOperation::Invoke { authority, .. } = &mut forged_divergent.operation else {
            unreachable!();
        };
        authority.signature[0] = 0x56;
        let divergent_id = OrderedEntryId([0x7c; 32]);
        assert!(matches!(
            machine.apply::<_, ()>(
                &mut executor,
                &forged_divergent,
                &before,
                ReplayPosition::Ordered {
                    id: divergent_id,
                    index: 2,
                    merge_frontier,
                    merge_seal: None,
                },
            ),
            Err(ReplayError::Executor(()))
        ));
        assert!(
            machine
                .runtime_at(OrderedBase {
                    index: 2,
                    head: Some(divergent_id),
                })
                .is_none()
        );
        assert_eq!(executor.calls, 1);
        assert_eq!(executor.authentications, 3);
    }

    #[test]
    fn retained_retry_survives_actor_retirement_and_runtime_capability_downgrade() {
        let genesis = AgentJournalGenesisId([0x7d; 32]);
        let mut machine = ReplayMachine::from_genesis(genesis, runtime()).unwrap();
        let mut executor = RetainedRecoveryExecutor::default();
        let merge_frontier = MergeFrontierId([0x7e; 32]);
        let invocation = input(MethodMode::Linear);
        let first_id = OrderedEntryId([0x7f; 32]);
        let first = machine
            .apply::<_, ()>(
                &mut executor,
                &invocation,
                &standard_before(),
                ReplayPosition::Ordered {
                    id: first_id,
                    index: 1,
                    merge_frontier,
                    merge_seal: None,
                },
            )
            .unwrap();
        assert_eq!(
            first.outcome(),
            ReplayStepOutcome::Applied(ReplayDisposition::Rejected)
        );
        let first_decoded = decode_standard_runtime_state(first.state()).unwrap();
        assert_eq!(first_decoded.lane_revisions.linear_authority_slot, Some(1));

        // Terminal outcomes live in the authenticated external record, not
        // the guest result table. Recovery remains possible after a later
        // lifecycle transition removes the target actor entirely and a later
        // runtime package drops the now-unused Linear capability.
        let mut retired = first_decoded;
        retired.actors.clear();
        retired.config.as_mut().unwrap().capabilities.lanes = LaneSet::NONE;
        let retired_state = encode_standard_runtime_state(&retired);
        assert!(StandardAgentRuntime::restore(retired.clone()).is_ok());

        let mut retry_invocation = invocation.clone();
        let ReplayOperation::Invoke { observed_slot, .. } = &mut retry_invocation.operation else {
            unreachable!()
        };
        *observed_slot = 2;

        let retry_id = OrderedEntryId([0x80; 32]);
        let retry = machine
            .apply::<_, ()>(
                &mut executor,
                &retry_invocation,
                &retired_state,
                ReplayPosition::Ordered {
                    id: retry_id,
                    index: 2,
                    merge_frontier,
                    merge_seal: None,
                },
            )
            .unwrap();
        assert_eq!(retry.outcome(), ReplayStepOutcome::ExactDuplicate);
        let retry_state = decode_standard_runtime_state(retry.state()).unwrap();
        assert_eq!(
            retry_state.config.unwrap().capabilities.lanes,
            LaneSet::NONE
        );
        assert_eq!(retry_state.lane_revisions.linear_authority_slot, Some(2));
        assert_eq!(retry.ownership_delta, InvocationIndexDelta::NONE);
        assert!(
            machine
                .runtime_at(OrderedBase {
                    index: 2,
                    head: Some(retry_id),
                })
                .is_some()
        );
        assert_eq!(executor.authentications, 2);
        assert_eq!(executor.executions, 1);
    }

    #[test]
    fn seal_merge_is_an_ordered_protocol_noop_not_executor_work() {
        let genesis = AgentJournalGenesisId([0x81; 32]);
        let mut machine = ReplayMachine::from_genesis(genesis, runtime()).unwrap();
        let mut executor = RetainedRecoveryExecutor::default();
        let before = standard_before();
        let input = ReplayInput {
            runtime: runtime(),
            operation: ReplayOperation::SealMerge,
        };
        let step = machine
            .apply::<_, ()>(
                &mut executor,
                &input,
                &before,
                ReplayPosition::Ordered {
                    id: OrderedEntryId([0x82; 32]),
                    index: 1,
                    merge_frontier: MergeFrontierId([0x83; 32]),
                    merge_seal: Some(MergeSealId([0x84; 32])),
                },
            )
            .unwrap();
        assert_eq!(
            step.outcome(),
            ReplayStepOutcome::Applied(ReplayDisposition::Applied)
        );
        assert_eq!(step.state(), &before);
        assert!(step.result().is_none());
        assert_eq!(executor.authentications, 0);
        assert_eq!(executor.executions, 0);
    }

    #[test]
    fn standard_exact_outcome_and_acknowledgement_reject_result_lane_tampering() {
        let invoke = input(MethodMode::Linear);
        let before = standard_before();
        let result = successful_result(&invoke);
        let with_result = with_exact_standard_result(&invoke, &before);

        // A fresh Done transition must install the complete scoped guest
        // result. An external outcome object is not a substitute for this
        // guest-owned lifecycle record.
        assert!(
            validate_standard_invocation_successor::<(), ()>(
                &invoke,
                &before,
                &with_result,
                &result,
                false,
                false,
            )
            .is_ok()
        );
        assert!(matches!(
            validate_standard_invocation_successor::<(), ()>(
                &invoke, &before, &before, &result, false, false,
            ),
            Err(ReplayError::TerminalMutation)
        ));

        let mut wrong_result = decode_standard_runtime_state(&with_result).unwrap();
        wrong_result.invocation_results[0].request = Hash([0xe0; 32]);
        let wrong_result = encode_standard_runtime_state(&wrong_result);
        assert!(matches!(
            validate_standard_invocation_successor::<(), ()>(
                &invoke,
                &before,
                &wrong_result,
                &result,
                false,
                false,
            ),
            Err(ReplayError::TerminalMutation)
        ));

        // Retained recovery preserves that exact result and may advance only
        // the owning result lane's authority-slot high-water mark.
        let retained_after = clock_only_state(&invoke, &with_result);
        assert!(
            validate_standard_invocation_successor::<(), ()>(
                &invoke,
                &with_result,
                &retained_after,
                &result,
                true,
                true,
            )
            .is_ok()
        );
        assert!(matches!(
            validate_standard_invocation_successor::<(), ()>(
                &invoke,
                &with_result,
                &clock_only_state(&invoke, &before),
                &result,
                true,
                true,
            ),
            Err(ReplayError::TerminalMutation)
        ));

        // Durable terminal errors are the same exact H-only transition and
        // must never manufacture a guest result.
        let rejected = Err(ActorExecutionError::NotFound);
        let rejected_after = clock_only_state(&invoke, &before);
        assert!(
            validate_standard_invocation_successor::<(), ()>(
                &invoke,
                &before,
                &rejected_after,
                &rejected,
                false,
                true,
            )
            .is_ok()
        );
        assert!(matches!(
            validate_standard_invocation_successor::<(), ()>(
                &invoke,
                &before,
                &with_result,
                &rejected,
                false,
                true,
            ),
            Err(ReplayError::TerminalMutation)
        ));

        let ReplayOperation::Invoke {
            invocation,
            authority,
            ..
        } = invoke.operation.clone()
        else {
            unreachable!()
        };
        let acknowledgement = ReplayInput {
            runtime: invoke.runtime.clone(),
            operation: ReplayOperation::Acknowledge {
                invocation,
                authority,
            },
        };
        let outcome = InvocationOutcomeRecord::from_runtime_states(
            AgentJournalGenesisId([0xe1; 32]),
            InvocationOwnershipScope::Ordered,
            InvocationOutcomeAnchor::Ordered {
                entry: OrderedEntryId([0xe2; 32]),
            },
            &invoke,
            &before,
            &with_result,
            result,
        )
        .unwrap();
        assert!(
            validate_standard_acknowledgement_successor::<(), ()>(
                &acknowledgement,
                &with_result,
                &before,
                false,
                &outcome,
            )
            .is_ok()
        );
        assert!(matches!(
            validate_standard_acknowledgement_successor::<(), ()>(
                &acknowledgement,
                &with_result,
                &with_result,
                false,
                &outcome,
            ),
            Err(ReplayError::TerminalMutation)
        ));

        let mut ack_tamper = decode_standard_runtime_state(&before).unwrap();
        ack_tamper.authority_slot_high_water = Some(9);
        assert!(
            validate_standard_acknowledgement_successor::<(), ()>(
                &acknowledgement,
                &with_result,
                &encode_standard_runtime_state(&ack_tamper),
                false,
                &outcome,
            )
            .is_err()
        );
    }

    #[test]
    fn exact_outcome_status_and_error_allowlist_is_fail_closed() {
        let input = input(MethodMode::Linear);
        let before = standard_before();
        let after = clock_only_state(&input, &before);
        let position = ReplayPosition::Ordered {
            id: OrderedEntryId([0xe3; 32]),
            index: 1,
            merge_frontier: MergeFrontierId([0xe4; 32]),
            merge_seal: None,
        };
        for (status, disposition) in [
            (
                ActorExecutionStatus::Forbidden,
                ReplayDisposition::Forbidden,
            ),
            (ActorExecutionStatus::Panicked, ReplayDisposition::Panicked),
            (ActorExecutionStatus::OutOfGas, ReplayDisposition::OutOfGas),
        ] {
            let Ok(mut reply) = successful_result(&input) else {
                unreachable!()
            };
            reply.status = status;
            let transition = ReplayTransition {
                state: after.clone(),
                disposition,
                result: Some(Ok(reply)),
                next_runtime: input.runtime.clone(),
                products: ReplayProducts::default(),
            };
            assert!(
                validate_transition::<(), ()>(
                    &input,
                    &before,
                    &transition,
                    position,
                    &input.runtime,
                    false,
                    false,
                    None,
                    None,
                )
                .is_ok()
            );
        }

        for error in [
            ActorExecutionError::NotFound,
            ActorExecutionError::StaleIncarnation,
            ActorExecutionError::Suspended,
            ActorExecutionError::StaleDeployment,
            ActorExecutionError::WrongProgram,
            ActorExecutionError::UnsupportedMethod,
            ActorExecutionError::InvalidInput,
            ActorExecutionError::InvalidActorOutput,
            ActorExecutionError::UnsupportedHostCall(u64::MAX),
        ] {
            let transition = ReplayTransition {
                state: after.clone(),
                disposition: ReplayDisposition::Rejected,
                result: Some(Err(error)),
                next_runtime: input.runtime.clone(),
                products: ReplayProducts::default(),
            };
            assert!(
                validate_transition::<(), ()>(
                    &input,
                    &before,
                    &transition,
                    position,
                    &input.runtime,
                    false,
                    false,
                    None,
                    None,
                )
                .is_ok(),
                "{error:?}"
            );
        }
        for error in [
            ActorExecutionError::NotCreated,
            ActorExecutionError::UnsupportedResultStorage,
            ActorExecutionError::MissingState,
            ActorExecutionError::InvalidAvailability,
            ActorExecutionError::DivergentInvocation,
            ActorExecutionError::ResultCapacity,
            ActorExecutionError::InvalidAuthorization,
            ActorExecutionError::AuthorityExpired,
            ActorExecutionError::AuthoritySlotRegressed,
        ] {
            let transition = ReplayTransition {
                state: after.clone(),
                disposition: ReplayDisposition::Rejected,
                result: Some(Err(error)),
                next_runtime: input.runtime.clone(),
                products: ReplayProducts::default(),
            };
            assert!(matches!(
                validate_transition::<(), ()>(
                    &input,
                    &before,
                    &transition,
                    position,
                    &input.runtime,
                    false,
                    false,
                    None,
                    None,
                ),
                Err(ReplayError::InvalidRecord)
            ));
        }
        for error in [
            ActorExecutionError::UnsupportedResultStorage,
            ActorExecutionError::MissingState,
            ActorExecutionError::InvalidAvailability,
            ActorExecutionError::ResultCapacity,
            ActorExecutionError::AuthorityExpired,
            ActorExecutionError::AuthoritySlotRegressed,
        ] {
            assert!(is_uncommitted_refusal(error), "{error:?}");
        }
        for error in [
            ActorExecutionError::NotCreated,
            ActorExecutionError::NotFound,
            ActorExecutionError::StaleIncarnation,
            ActorExecutionError::Suspended,
            ActorExecutionError::StaleDeployment,
            ActorExecutionError::WrongProgram,
            ActorExecutionError::UnsupportedMethod,
            ActorExecutionError::InvalidInput,
            ActorExecutionError::InvalidActorOutput,
            ActorExecutionError::DivergentInvocation,
            ActorExecutionError::InvalidAuthorization,
            ActorExecutionError::UnsupportedHostCall(1),
        ] {
            assert!(!is_uncommitted_refusal(error), "{error:?}");
        }
    }

    #[test]
    fn fresh_uncommitted_refusal_requires_an_exact_noop() {
        let input = input(MethodMode::Linear);
        let before = standard_before();
        let position = ReplayPosition::Ordered {
            id: OrderedEntryId([0xe5; 32]),
            index: 1,
            merge_frontier: MergeFrontierId([0xe6; 32]),
            merge_seal: None,
        };
        for error in [
            ActorExecutionError::UnsupportedResultStorage,
            ActorExecutionError::MissingState,
            ActorExecutionError::InvalidAvailability,
            ActorExecutionError::ResultCapacity,
            ActorExecutionError::AuthorityExpired,
            ActorExecutionError::AuthoritySlotRegressed,
        ] {
            let mut machine =
                ReplayMachine::from_genesis(AgentJournalGenesisId([0xe7; 32]), runtime()).unwrap();
            let mut executor = UncommittedRefusalExecutor::exact(error);
            assert_eq!(
                machine.apply::<_, ()>(&mut executor, &input, &before, position),
                Err(ReplayError::UncommittedInvocation(error))
            );
            assert_eq!(executor.authentications, 1);
            assert_eq!(executor.executions, 1);
            assert!(
                machine
                    .ownership
                    .lookup(invocation_ownership_key(
                        position,
                        match &input.operation {
                            ReplayOperation::Invoke { invocation, .. } => invocation.invocation,
                            _ => unreachable!(),
                        },
                    ))
                    .unwrap()
                    .is_none()
            );
        }

        let mut state_tamper =
            UncommittedRefusalExecutor::exact(ActorExecutionError::AuthoritySlotRegressed);
        state_tamper.mutate_state = true;
        let mut machine =
            ReplayMachine::from_genesis(AgentJournalGenesisId([0xe8; 32]), runtime()).unwrap();
        assert!(matches!(
            machine.apply::<_, ()>(&mut state_tamper, &input, &before, position),
            Err(ReplayError::TerminalMutation)
        ));

        let mut product_tamper =
            UncommittedRefusalExecutor::exact(ActorExecutionError::ResultCapacity);
        product_tamper.emit_products = true;
        let mut machine =
            ReplayMachine::from_genesis(AgentJournalGenesisId([0xe9; 32]), runtime()).unwrap();
        assert!(matches!(
            machine.apply::<_, ()>(&mut product_tamper, &input, &before, position),
            Err(ReplayError::ForbiddenMergeProducts)
        ));

        let mut excluded = UncommittedRefusalExecutor::exact(ActorExecutionError::NotCreated);
        let mut machine =
            ReplayMachine::from_genesis(AgentJournalGenesisId([0xea; 32]), runtime()).unwrap();
        assert!(matches!(
            machine.apply::<_, ()>(&mut excluded, &input, &before, position),
            Err(ReplayError::InvalidRecord)
        ));
        assert_eq!(
            historical_replay_error(ReplayError::<(), ()>::UncommittedInvocation(
                ActorExecutionError::AuthorityExpired,
            )),
            ReplayError::InvalidRecord
        );
    }

    #[test]
    fn acknowledgement_without_authenticated_owner_fails_before_execution() {
        let genesis = AgentJournalGenesisId([0x81; 32]);
        let mut machine = ReplayMachine::from_genesis(genesis, runtime()).unwrap();
        let mut executor = RejectingExecutor::default();
        let mut acknowledge = input(MethodMode::Linear);
        let ReplayOperation::Invoke {
            invocation,
            authority,
            ..
        } = acknowledge.operation
        else {
            unreachable!();
        };
        acknowledge.operation = ReplayOperation::Acknowledge {
            invocation,
            authority,
        };
        assert!(matches!(
            machine.apply::<_, ()>(
                &mut executor,
                &acknowledge,
                &RuntimeState::default(),
                ReplayPosition::Ordered {
                    id: OrderedEntryId([0x82; 32]),
                    index: 1,
                    merge_frontier: MergeFrontierId([0x83; 32]),
                    merge_seal: None,
                },
            ),
            Err(ReplayError::InvocationOwnership(
                InvocationOwnershipError::Unauthenticated
            ))
        ));
        assert_eq!(executor.calls, 0);
    }

    #[test]
    fn ordered_and_local_products_fail_closed_until_they_join_the_cas() {
        let genesis = AgentJournalGenesisId([0x84; 32]);
        let frontier = MergeFrontierId([0x85; 32]);
        for (mode, position) in [
            (
                MethodMode::Linear,
                ReplayPosition::Ordered {
                    id: OrderedEntryId([0x86; 32]),
                    index: 1,
                    merge_frontier: frontier,
                    merge_seal: None,
                },
            ),
            (
                MethodMode::Local,
                ReplayPosition::Local {
                    id: LocalEntryId([0x87; 32]),
                    node: NodeId([0x88; 32]),
                    revision: 1,
                    ordered_base: OrderedBase::post_genesis(),
                    merge_frontier: frontier,
                },
            ),
        ] {
            let mut machine = ReplayMachine::from_genesis(genesis, runtime()).unwrap();
            assert!(matches!(
                machine.apply::<_, ()>(
                    &mut ProductExecutor,
                    &input(mode),
                    &RuntimeState::default(),
                    position,
                ),
                Err(ReplayError::ForbiddenMergeProducts)
            ));
        }
    }

    #[test]
    fn high_state_ordered_suffix_has_an_aggregate_snapshot_bound() {
        let mut snapshots = MaterializedOrderedSnapshots::default();
        for index in 1..=16_u64 {
            let mut id = [0_u8; 32];
            id[24..].copy_from_slice(&index.to_be_bytes());
            snapshots
                .insert(
                    OrderedBase {
                        index,
                        head: Some(OrderedEntryId(id)),
                    },
                    MaterializedOrderedSnapshot {
                        runtime: runtime(),
                        control: vec![0x11; MAX_RUNTIME_STATE_BYTES],
                        linear: Vec::new(),
                    },
                )
                .unwrap();
        }
        assert_eq!(snapshots.len(), 16);
        assert_eq!(snapshots.bytes, MAX_MATERIALIZED_ORDERED_SNAPSHOT_BYTES);
        assert!(matches!(
            snapshots.insert(
                OrderedBase {
                    index: 17,
                    head: Some(OrderedEntryId([0x89; 32])),
                },
                MaterializedOrderedSnapshot {
                    runtime: runtime(),
                    control: vec![0x22; MAX_RUNTIME_STATE_BYTES],
                    linear: Vec::new(),
                },
            ),
            Err(ReplayError::ReplayLimit)
        ));
        assert_eq!(snapshots.len(), 16);
    }

    #[test]
    fn fence_evidence_cannot_jump_to_a_detached_ordered_fork() {
        let genesis = AgentJournalGenesisId([0x8a; 32]);
        let frontier = MergeFrontier {
            genesis,
            events: Vec::new(),
        }
        .id();
        let first = OrderedEntry {
            genesis,
            index: 1,
            parent: None,
            merge_frontier: frontier,
            merge_seal: None,
            input: input(MethodMode::Linear),
        };
        let second = OrderedEntry {
            genesis,
            index: 2,
            parent: Some(first.id()),
            merge_frontier: frontier,
            merge_seal: None,
            input: input_with_message(MethodMode::Linear, vec![2]),
        };
        let third = OrderedEntry {
            genesis,
            index: 3,
            parent: Some(second.id()),
            merge_frontier: frontier,
            merge_seal: None,
            input: input_with_message(MethodMode::Linear, vec![3]),
        };
        let evidence = FenceAncestryEvidence::post_genesis(genesis)
            .unwrap()
            .advance_ordered(&first, OrderedBase::post_genesis())
            .unwrap()
            .advance_ordered(&second, OrderedBase::post_genesis())
            .unwrap();
        let detached_fence = OrderedBase {
            index: 1,
            head: Some(OrderedEntryId([0x8b; 32])),
        };
        assert!(matches!(
            evidence.advance_ordered(&third, detached_fence),
            Err(ReplayError::InvalidFence)
        ));
    }

    #[test]
    fn four_individually_bounded_lanes_cannot_exceed_the_aggregate_limit() {
        let component = MAX_RUNTIME_STATE_BYTES / 4 + 1;
        let before = RuntimeState {
            control: vec![0x11; component],
            linear: vec![0x22; component],
            merge: vec![0x33; component],
            local: vec![0x44; component],
        };
        let mut machine =
            ReplayMachine::from_genesis(AgentJournalGenesisId([0x85; 32]), runtime()).unwrap();
        let mut executor = RejectingExecutor::default();
        assert!(matches!(
            machine.apply::<_, ()>(
                &mut executor,
                &input(MethodMode::Linear),
                &before,
                ReplayPosition::Ordered {
                    id: OrderedEntryId([0x86; 32]),
                    index: 1,
                    merge_frontier: MergeFrontierId([0x87; 32]),
                    merge_seal: None,
                },
            ),
            Err(ReplayError::ReplayLimit)
        ));
        assert_eq!(executor.calls, 0);
    }

    #[cfg(feature = "std")]
    #[test]
    fn composite_suffix_budget_is_shared_across_all_lanes() {
        assert!(aggregate::test_composite_entry_budget(512, 256, 256).is_ok());
        assert!(matches!(
            aggregate::test_composite_entry_budget(512, 256, 257),
            Err(ReplayError::ReplayLimit)
        ));
    }

    #[cfg(feature = "std")]
    #[test]
    fn system_authority_management_is_bare_and_never_generic_authorized() {
        let sealed = admitted_genesis(0xc0);
        let command = admitted_finalize_for_test(&sealed, 2);
        let bare = authority_finalize_input(&sealed, command.clone());
        bare.validate().unwrap();
        assert_eq!(ReplayInput::decode(&bare.encode()).unwrap(), bare);

        let ReplayOperation::Management {
            request: LifecycleRequest::Authorized { admission, .. },
        } = &sealed.genesis().create.operation
        else {
            unreachable!()
        };
        let wrapped = ReplayInput {
            runtime: sealed.genesis().runtime().clone(),
            operation: ReplayOperation::Management {
                request: LifecycleRequest::Authorized {
                    admission: admission.clone(),
                    request: alloc::boxed::Box::new(LifecycleRequest::FinalizeSystemAuthority(
                        command,
                    )),
                },
            },
        };
        assert_eq!(
            wrapped.validate(),
            Err(crate::service::wire::DecodeError::NonCanonical)
        );
        assert_eq!(
            ReplayInput::decode(&wrapped.encode()),
            Err(crate::service::wire::DecodeError::NonCanonical)
        );
    }

    #[cfg(feature = "std")]
    #[test]
    fn root_replay_identity_rejects_a_later_system_authorized_seal() {
        let mut sealed = admitted_genesis(0xc6);
        let fixture = admitted_finalize_fixture(&sealed, 2, None);
        let identity = sealed.replayed_root_identity().unwrap();
        assert_eq!(identity.genesis(), sealed.genesis().id());
        assert_eq!(identity.outer_admission(), sealed.genesis().admission);

        sealed.admission_record = fixture.later_admission;
        assert!(matches!(
            sealed.replayed_root_identity(),
            Err(ReplayError::ScopeMismatch)
        ));
    }

    #[cfg(feature = "std")]
    #[test]
    fn raw_genesis_replay_cannot_acquire_system_authority_scope() {
        let sealed = admitted_genesis(0xc7);
        let input = authority_finalize_input(&sealed, admitted_finalize_for_test(&sealed, 2));
        let mut machine =
            ReplayMachine::from_genesis(sealed.genesis().id(), sealed.genesis().runtime().clone())
                .unwrap();
        let mut executor = ExactCreateRejectInvocations::default();
        assert!(matches!(
            machine.apply::<_, ()>(
                &mut executor,
                &input,
                sealed.post_create(),
                ReplayPosition::Ordered {
                    id: OrderedEntryId([0xc8; 32]),
                    index: 1,
                    merge_frontier: sealed.empty_frontier().id(),
                    merge_seal: Some(MergeSealId([0xc9; 32])),
                },
            ),
            Err(ReplayError::ScopeMismatch)
        ));
        assert_eq!(executor.executions, 0);
    }

    #[cfg(feature = "std")]
    #[test]
    fn scoped_replay_selects_reply_bound_native_authority_write() {
        let sealed = admitted_genesis(0xca);
        let input = authority_finalize_input(&sealed, admitted_finalize_for_test(&sealed, 2));
        let mut machine =
            ReplayMachine::from_replayed_root_genesis(&sealed, sealed.genesis().runtime().clone())
                .unwrap();
        let mut executor = ExactCreateRejectInvocations::default();
        let step = machine
            .apply::<_, ()>(
                &mut executor,
                &input,
                sealed.post_create(),
                ReplayPosition::Ordered {
                    id: OrderedEntryId([0xcb; 32]),
                    index: 1,
                    merge_frontier: sealed.empty_frontier().id(),
                    merge_seal: Some(MergeSealId([0xcc; 32])),
                },
            )
            .unwrap();
        let write = step.system_authority_write.as_ref().unwrap();
        let ReplayOperation::Management { request } = &input.operation else {
            unreachable!()
        };
        assert_eq!(write.operation(), request.commitment());
        assert!(matches!(
            write.result(),
            LifecycleReply::SystemAuthorityFinalized(
                crate::agent::system_authority::SystemAuthorityFinalizeOutcome::Admitted(_)
            )
        ));
        assert!(matches!(
            write.selected(),
            StandardSystemAuthorityWrite::Finalize { .. }
        ));
    }

    #[cfg(feature = "std")]
    #[test]
    fn wrong_scope_and_invalid_direct_authority_commands_never_prepare() {
        let sealed = admitted_genesis(0xcd);
        let foreign = admitted_finalize_fixture(
            &sealed,
            2,
            Some((
                AgentJournalGenesisId::new([0xce; 32]),
                AgentGenesisAdmissionId::from_bytes([0xcf; 32]),
            )),
        );
        let wrong_scope = authority_finalize_input(&sealed, foreign.command);
        let stale = authority_finalize_input(&sealed, admitted_finalize_for_test(&sealed, 1));
        let position = ReplayPosition::Ordered {
            id: OrderedEntryId([0xd0; 32]),
            index: 1,
            merge_frontier: sealed.empty_frontier().id(),
            merge_seal: Some(MergeSealId([0xd1; 32])),
        };
        for input in [wrong_scope, stale] {
            let mut machine = ReplayMachine::from_replayed_root_genesis(
                &sealed,
                sealed.genesis().runtime().clone(),
            )
            .unwrap();
            let mut executor = ExactCreateRejectInvocations::default();
            assert!(matches!(
                machine.apply::<_, ()>(&mut executor, &input, sealed.post_create(), position),
                Err(ReplayError::InvalidManagementTransition)
            ));
        }
    }

    #[cfg(feature = "std")]
    #[test]
    fn custom_executor_authority_write_cannot_cross_generic_publish_seam() {
        let sealed = admitted_genesis(0xd2);
        let node = admitted_config().replicas[0].node;
        let mut store = MemoryAgentJournalStore::new(admitted_runtime().agent, node).unwrap();
        store
            .put_blob(
                JournalBlobClass::CatalogArtifact,
                &admitted_runtime().package,
                b"replay-runtime-package",
            )
            .unwrap();
        assert!(store.initialize(&sealed).unwrap());
        let mut executor = ExactCreateRejectInvocations::default();
        let mut materialized =
            materialize_current(&mut store, &mut executor, &NoPrunedOrderedBases).unwrap();
        materialized.attach_replayed_root(&sealed).unwrap();
        let merge_seal = persist_merge_seal(&mut store, &materialized);
        let entry = OrderedEntry {
            genesis: materialized.heads().genesis,
            index: 1,
            parent: None,
            merge_frontier: materialized.merge_frontier(),
            merge_seal: Some(merge_seal),
            input: authority_finalize_input(&sealed, admitted_finalize_for_test(&sealed, 2)),
        };
        let heads_before = store.heads().unwrap().unwrap();
        let prepared =
            match prepare_ordered(&mut store, &mut executor, &materialized, &entry).unwrap() {
                ReplayPreparation::Ready(prepared) => prepared,
                ReplayPreparation::AlreadyCommitted(_) => unreachable!(),
            };
        let write = prepared.sealed.system_authority_write().unwrap();
        assert!(matches!(
            write.result(),
            LifecycleReply::SystemAuthorityFinalized(_)
        ));
        let StandardSystemAuthorityWrite::Finalize { history, .. } = write.selected() else {
            unreachable!()
        };
        let authority_nodes = history
            .nodes()
            .iter()
            .map(|node| node.id())
            .collect::<Vec<_>>();
        let direct = prepared.sealed.clone();
        drop(prepared);
        assert_eq!(store.publish(&direct), Err(JournalStoreError::NonCanonical));
        assert_eq!(store.heads().unwrap().unwrap(), heads_before);
        assert!(authority_nodes.iter().all(|id| {
            store
                .load_system_authority_decision_node(*id)
                .unwrap()
                .is_none()
        }));
        assert!(store.get::<OrderedEntry>(entry.id()).unwrap().is_none());

        let invalid = OrderedEntry {
            genesis: materialized.heads().genesis,
            index: 1,
            parent: None,
            merge_frontier: materialized.merge_frontier(),
            merge_seal: Some(merge_seal),
            input: authority_finalize_input(&sealed, admitted_finalize_for_test(&sealed, 1)),
        };
        assert!(matches!(
            prepare_ordered(&mut store, &mut executor, &materialized, &invalid),
            Err(ReplayError::InvalidManagementTransition)
        ));
        assert_eq!(store.heads().unwrap().unwrap(), heads_before);
    }

    #[cfg(all(feature = "std", feature = "storage"))]
    #[test]
    fn memory_clone_drops_root_provenance_while_original_remains_reverified() {
        let sealed = admitted_genesis(0xd6);
        let node = admitted_config().replicas[0].node;
        let mut store = MemoryAgentJournalStore::new(admitted_runtime().agent, node).unwrap();
        store
            .put_blob(
                JournalBlobClass::CatalogArtifact,
                &admitted_runtime().package,
                b"replay-runtime-package",
            )
            .unwrap();
        assert!(store.initialize(&sealed).unwrap());
        assert_eq!(
            store.replayed_root_identity(),
            Some(sealed.replayed_root_identity().unwrap())
        );

        let mut transplanted = store.clone();
        assert_ne!(transplanted.instance_id(), store.instance_id());
        assert_eq!(transplanted.replayed_root_identity(), None);
        let mut executor = ExactCreateRejectInvocations::default();
        assert!(matches!(
            materialize_current_reverified(&mut transplanted, &mut executor, &NoPrunedOrderedBases,),
            Err(ReplayError::Source(
                ReplayMaterializationSourceError::Journal(JournalStoreError::Unavailable)
            ))
        ));

        let materialized =
            materialize_current_reverified(&mut store, &mut executor, &NoPrunedOrderedBases)
                .unwrap();
        assert_eq!(
            materialized.replayed_root(),
            Some(sealed.replayed_root_identity().unwrap())
        );
    }

    #[cfg(all(feature = "std", feature = "storage"))]
    #[test]
    fn fresh_rotation_publishes_dependencies_then_retires_exact_receipt() {
        let sealed = admitted_genesis(0xd7);
        let node = admitted_config().replicas[0].node;
        let mut store = MemoryAgentJournalStore::new(admitted_runtime().agent, node).unwrap();
        store
            .put_blob(
                JournalBlobClass::CatalogArtifact,
                &admitted_runtime().package,
                b"replay-runtime-package",
            )
            .unwrap();
        assert!(store.initialize(&sealed).unwrap());

        let mut executor = ExactCreateRejectInvocations::default();
        let predecessor =
            materialize_current_reverified(&mut store, &mut executor, &NoPrunedOrderedBases)
                .unwrap();
        let identity = predecessor.replayed_root().unwrap();
        let scope = SystemAuthorityJournalScope::from_replayed_root(&identity).unwrap();
        let decoded = decode_standard_runtime_state(predecessor.state()).unwrap();
        let authority = decoded.system_authority.unwrap();
        let retiring = authority.current_committee().clone();
        let (_, keys) = admitted_root_material(&admitted_config());
        let incoming = rotated_committee(&retiring, &keys);
        let transition = SystemAuthorityRotationClaim::new(
            authority.root_anchor(),
            authority.root_anchor_config_version(),
            authority.root_anchor_config(),
            scope.commitment(authority.root_anchor()).unwrap(),
            &retiring,
            &incoming,
            2,
            3,
        )
        .unwrap();
        let request = SystemAuthorityRotationReservationRequest::new(
            retiring.clone(),
            incoming.clone(),
            transition,
        )
        .unwrap();
        let predecessor_control = derive_lane_state::<(), ()>(
            predecessor.heads().genesis,
            predecessor.runtime().clone(),
            PersistedLane::Control,
            LaneCursor::Ordered {
                base: predecessor.ordered_base(),
            },
            &predecessor.state().control,
        )
        .unwrap()
        .id();
        let view = ReplayedSystemAuthorityView::from_authenticated_replay(
            scope,
            &authority,
            store.instance_id(),
            predecessor.heads_id(),
            predecessor_control,
        )
        .unwrap();

        let directory = std::env::temp_dir().join(alloc::format!(
            "vos_authority_publication_{}_{}",
            std::process::id(),
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_nanos(),
        ));
        std::fs::create_dir_all(&directory).unwrap();
        let database =
            alloc::sync::Arc::new(Database::create(directory.join("evidence.redb")).unwrap());
        let local_signer = AuthoritySignerId::of_raw_ed25519(&keys[0].verifying_key().to_bytes());
        let local_node = retiring.member(local_signer).unwrap().node();
        let ledger = SystemAuthorityEvidenceLedger::open(
            database.clone(),
            view.route(),
            store.instance_id(),
            local_node,
            local_signer,
        )
        .unwrap();
        let reserved = ledger
            .reserve_or_reconcile(&view, request)
            .unwrap()
            .into_reserved();
        retain_rotation_qc_leg(
            &ledger,
            &reserved,
            SystemAuthorityCommitteeLeg::Retiring,
            &retiring,
            &keys,
        );
        retain_rotation_qc_leg(
            &ledger,
            &reserved,
            SystemAuthorityCommitteeLeg::Incoming,
            &incoming,
            &keys,
        );
        let certificate = ledger
            .joint_rotation_certificate(&reserved)
            .unwrap()
            .unwrap();
        let command = SystemAuthorityRotation::new(
            incoming.clone(),
            certificate,
            SystemAuthorityRotationProof::vacant(incoming.epoch(), vec![]).unwrap(),
        )
        .unwrap();
        let merge_seal = persist_merge_seal(&mut store, &predecessor);
        let entry = OrderedEntry {
            genesis: predecessor.heads().genesis,
            index: 1,
            parent: None,
            merge_frontier: predecessor.merge_frontier(),
            merge_seal: Some(merge_seal),
            input: ReplayInput {
                runtime: predecessor.runtime().clone(),
                operation: ReplayOperation::Management {
                    request: LifecycleRequest::RotateSystemAuthority(command),
                },
            },
        };
        let heads_before = store.heads().unwrap().unwrap();
        let prepared =
            match prepare_ordered(&mut store, &mut executor, &predecessor, &entry).unwrap() {
                ReplayPreparation::Ready(prepared) => prepared,
                ReplayPreparation::AlreadyCommitted(_) => unreachable!(),
            };
        let StandardSystemAuthorityWrite::Rotation { record, history } =
            prepared.sealed.system_authority_write().unwrap().selected()
        else {
            unreachable!()
        };
        let record = record.clone();
        let root = history.root();
        let generic = prepared.sealed.clone();
        assert_eq!(
            prepared.store.publish(&generic),
            Err(JournalStoreError::NonCanonical)
        );
        assert_eq!(prepared.store.heads().unwrap(), Some(heads_before));
        assert!(
            prepared
                .store
                .load_system_authority_rotation_node(record.leaf_id())
                .unwrap()
                .is_none()
        );

        let prepared = prepared
            .prepare_system_authority_rotation(reserved)
            .unwrap();
        let published = prepared
            .publish_system_authority_rotation(ledger.owner())
            .unwrap();
        assert_eq!(published.facts().record(), &record);
        assert_eq!(published.facts().root(), root);
        assert!(ledger.recover_pending_claim().unwrap().is_some());
        let (publication, successor, _) =
            ledger.owner().retire_published_rotation(published).unwrap();
        assert!(publication.heads_advanced);
        assert_eq!(store.heads().unwrap().unwrap().id(), successor.heads_id());
        assert!(ledger.recover_pending_claim().unwrap().is_none());
        assert_eq!(
            store
                .load_system_authority_rotation_node(record.leaf_id())
                .unwrap(),
            Some(SystemAuthorityRotationNode::Leaf(record.clone()))
        );
        assert_eq!(
            prove_rotation(root, record.new_epoch(), |id| {
                store
                    .load_system_authority_rotation_node(id)
                    .map(|node| node.map(|node| node.encode()))
            })
            .unwrap()
            .occupied_record(),
            Some(&record)
        );
        assert!(
            store
                .load_system_authority_committee_record(record.old_committee())
                .unwrap()
                .is_some()
        );
        assert!(
            store
                .load_system_authority_committee_record(record.new_committee())
                .unwrap()
                .is_some()
        );
        drop(ledger);
        drop(database);
        std::fs::remove_dir_all(directory).unwrap();
    }

    #[cfg(all(feature = "std", feature = "storage"))]
    #[test]
    fn fresh_catalog_publishes_exact_history_and_retry_cannot_reserve_a_second_cas() {
        let CatalogPublicationFixture {
            mut store,
            mut executor,
            predecessor,
            ledger,
            reserved,
            entry,
            database,
            directory,
        } = catalog_publication_fixture(0x42);
        let stale_reservation = reserved.clone();
        let heads_before = store.heads().unwrap().unwrap();
        let prepared =
            match prepare_ordered(&mut store, &mut executor, &predecessor, &entry).unwrap() {
                ReplayPreparation::Ready(prepared) => prepared,
                ReplayPreparation::AlreadyCommitted(_) => unreachable!(),
            };
        let StandardSystemAuthorityWrite::Catalog {
            record: Some(record),
            history,
        } = prepared.sealed.system_authority_write().unwrap().selected()
        else {
            unreachable!()
        };
        let record = record.clone();
        let root = history.root();
        assert!(history.inserted());
        let generic = prepared.sealed.clone();
        assert_eq!(
            prepared.store.publish(&generic),
            Err(JournalStoreError::NonCanonical)
        );
        assert_eq!(prepared.store.heads().unwrap(), Some(heads_before));
        assert!(
            prepared
                .store
                .load_system_authority_catalog_record(record.id())
                .unwrap()
                .is_none()
        );

        let prepared = prepared.prepare_system_authority_catalog(reserved).unwrap();
        let facts = prepared.publication_facts().unwrap();
        assert_eq!(facts.record(), &record);
        assert_eq!(facts.root(), root);
        assert_ne!(facts.storage_plan(), Hash::ZERO);
        let published = prepared
            .publish_system_authority_catalog(ledger.owner())
            .unwrap();
        assert!(ledger.recover_pending_claim().unwrap().is_some());
        let (publication, successor, _) =
            ledger.owner().retire_published_catalog(published).unwrap();
        assert!(publication.heads_advanced);
        assert_eq!(store.heads().unwrap().unwrap().id(), successor.heads_id());
        assert!(ledger.recover_pending_claim().unwrap().is_none());
        assert_eq!(
            store
                .load_system_authority_catalog_record(record.id())
                .unwrap(),
            Some(record.clone())
        );
        let occupied = prove_catalog(root, record.operation_id(), |id| {
            store
                .load_system_authority_catalog_node(id)
                .map(|node| node.map(|node| node.encode()))
        })
        .unwrap();
        assert_eq!(occupied.occupied_record_id(), Some(record.id()));

        // A historical response-loss retry is resolved by the occupied
        // OperationId record. Replay may reconstruct its deterministic reply,
        // but the fresh reservation/publication constructor rejects it before
        // any second dependency staging or Heads CAS.
        let retry =
            SystemAuthorityCatalogFinalize::new(record.receipt().clone(), occupied).unwrap();
        let merge_seal = persist_merge_seal(&mut store, &successor);
        let retry_entry = OrderedEntry {
            genesis: successor.heads().genesis,
            index: successor.heads().ordered_index + 1,
            parent: successor.heads().ordered_head,
            merge_frontier: successor.merge_frontier(),
            merge_seal: Some(merge_seal),
            input: ReplayInput {
                runtime: successor.runtime().clone(),
                operation: ReplayOperation::Management {
                    request: LifecycleRequest::FinalizeCatalog(retry),
                },
            },
        };
        let retry_prepared =
            match prepare_ordered(&mut store, &mut executor, &successor, &retry_entry).unwrap() {
                ReplayPreparation::Ready(prepared) => prepared,
                ReplayPreparation::AlreadyCommitted(_) => unreachable!(),
            };
        let StandardSystemAuthorityWrite::Catalog { history, .. } = retry_prepared
            .sealed
            .system_authority_write()
            .unwrap()
            .selected()
        else {
            unreachable!()
        };
        assert!(!history.inserted());
        assert!(matches!(
            retry_prepared.prepare_system_authority_catalog(stale_reservation),
            Err(JournalStoreError::NonCanonical)
        ));
        assert_eq!(store.heads().unwrap().unwrap().id(), successor.heads_id());

        drop(ledger);
        drop(database);
        std::fs::remove_dir_all(directory).unwrap();
    }

    #[cfg(all(feature = "std", feature = "storage"))]
    #[test]
    fn first_catalog_after_rotation_consumes_marker_and_wrong_sequence_is_no_write() {
        let RotationPublicationFixture {
            mut store,
            mut executor,
            predecessor,
            ledger,
            reserved,
            entry,
            database,
            directory,
        } = rotation_publication_fixture(0x45);
        let (_, keys) = admitted_root_material(&admitted_config());
        let prepared =
            match prepare_ordered(&mut store, &mut executor, &predecessor, &entry).unwrap() {
                ReplayPreparation::Ready(prepared) => prepared,
                ReplayPreparation::AlreadyCommitted(_) => unreachable!(),
            }
            .prepare_system_authority_rotation(reserved)
            .unwrap();
        let published = prepared
            .publish_system_authority_rotation(ledger.owner())
            .unwrap();
        let (_, rotated, _) = ledger.owner().retire_published_rotation(published).unwrap();
        let (_, rotated_view) = materialized_system_authority_view(&store, &rotated).unwrap();
        let first = rotated_view.rotation_first_sequence().unwrap();
        assert_eq!(rotated_view.committee_sequence_high_water(), first - 1);
        assert!(ledger.recover_pending_claim().unwrap().is_none());

        let committee = rotated_view.committee().clone();
        let wrong_operation = OperationId([0x46; 32]);
        let wrong_fact = catalog_fact_for_authority(
            rotated_view.authority_state(),
            wrong_operation,
            first + 1,
            0x47,
        );
        let wrong_request = SystemAuthorityCatalogReservationRequest::new(
            committee.clone(),
            wrong_fact,
            SystemAuthorityCatalogProof::vacant(wrong_operation, vec![]).unwrap(),
        )
        .unwrap();
        let heads_before = store.heads().unwrap().unwrap();
        assert!(matches!(
            ledger.reserve_catalog_or_reconcile(&rotated_view, wrong_request),
            Err(SystemAuthorityLedgerError::Wire(_))
        ));
        assert_eq!(store.heads().unwrap(), Some(heads_before.clone()));
        assert!(ledger.recover_pending_claim().unwrap().is_none());
        assert!(!ledger.is_fail_stopped().unwrap());

        let operation = OperationId([0x48; 32]);
        let fact =
            catalog_fact_for_authority(rotated_view.authority_state(), operation, first, 0x49);
        let proof = SystemAuthorityCatalogProof::vacant(operation, vec![]).unwrap();
        let request = SystemAuthorityCatalogReservationRequest::new(
            committee.clone(),
            fact.clone(),
            proof.clone(),
        )
        .unwrap();
        let reserved = ledger
            .reserve_catalog_or_reconcile(&rotated_view, request)
            .unwrap()
            .into_reserved();
        retain_rotation_qc_leg(
            &ledger,
            &reserved,
            SystemAuthorityCommitteeLeg::Current,
            &committee,
            &keys,
        );
        let certificate = ledger
            .owner()
            .certificate(&reserved, SystemAuthorityCommitteeLeg::Current)
            .unwrap()
            .unwrap();
        let receipt = FinalizedCatalogMutationReceipt::new(
            fact,
            certificate,
            rotated_view
                .authority_state()
                .catalog_binding_record()
                .unwrap(),
            &committee,
        )
        .unwrap();
        let command = SystemAuthorityCatalogFinalize::new(receipt, proof).unwrap();
        let catalog_entry = catalog_ordered_entry(&mut store, &rotated, command);
        let prepared =
            match prepare_ordered(&mut store, &mut executor, &rotated, &catalog_entry).unwrap() {
                ReplayPreparation::Ready(prepared) => prepared,
                ReplayPreparation::AlreadyCommitted(_) => unreachable!(),
            };
        let write = prepared.sealed.system_authority_write().unwrap();
        assert_eq!(
            write.predecessor_authority().rotation_first_sequence(),
            Some(first)
        );
        assert_eq!(
            write
                .predecessor_authority()
                .committee_sequence_high_water(),
            first - 1
        );
        assert_eq!(write.successor_authority().rotation_first_sequence(), None);
        assert_eq!(
            write.successor_authority().committee_sequence_high_water(),
            first
        );
        let prepared = prepared.prepare_system_authority_catalog(reserved).unwrap();
        let published = prepared
            .publish_system_authority_catalog(ledger.owner())
            .unwrap();
        let (_, successor, _) = ledger.owner().retire_published_catalog(published).unwrap();
        let (_, successor_view) = materialized_system_authority_view(&store, &successor).unwrap();
        assert_eq!(successor_view.rotation_first_sequence(), None);
        assert_eq!(successor_view.committee_sequence_high_water(), first);
        assert_eq!(successor_view.committee(), &committee);
        assert!(ledger.recover_pending_claim().unwrap().is_none());

        drop(ledger);
        drop(database);
        std::fs::remove_dir_all(directory).unwrap();
    }

    #[cfg(all(feature = "std", feature = "storage"))]
    #[test]
    fn occupied_catalog_retry_and_conflict_preserve_post_rotation_marker_without_writes() {
        let CatalogPublicationFixture {
            mut store,
            mut executor,
            predecessor,
            ledger,
            reserved,
            entry,
            database,
            directory,
        } = catalog_publication_fixture(0x4a);
        let prepared =
            match prepare_ordered(&mut store, &mut executor, &predecessor, &entry).unwrap() {
                ReplayPreparation::Ready(prepared) => prepared,
                ReplayPreparation::AlreadyCommitted(_) => unreachable!(),
            }
            .prepare_system_authority_catalog(reserved)
            .unwrap();
        let original_record = prepared.publication_facts().unwrap().record().clone();
        let published = prepared
            .publish_system_authority_catalog(ledger.owner())
            .unwrap();
        let (_, after_catalog, _) = ledger.owner().retire_published_catalog(published).unwrap();

        let (_, keys) = admitted_root_material(&admitted_config());
        let rotated = publish_test_rotation(
            &mut store,
            &mut executor,
            &after_catalog,
            &ledger,
            &keys,
            3,
            4,
        );
        let (scope, rotated_view) = materialized_system_authority_view(&store, &rotated).unwrap();
        assert_eq!(rotated_view.committee_sequence_high_water(), 3);
        assert_eq!(rotated_view.rotation_first_sequence(), Some(4));
        let occupied = prove_catalog(
            rotated_view.authority_state().catalog_history_root(),
            original_record.operation_id(),
            |id| {
                store
                    .load_system_authority_catalog_node(id)
                    .map(|node| node.map(|node| node.encode()))
            },
        )
        .unwrap();
        assert_eq!(occupied.occupied_record_id(), Some(original_record.id()));
        assert!(
            SystemAuthorityCatalogReservationRequest::new(
                rotated_view.committee().clone(),
                original_record.receipt().fact().clone(),
                occupied.clone(),
            )
            .is_err()
        );

        let exact = SystemAuthorityCatalogFinalize::new(
            original_record.receipt().clone(),
            occupied.clone(),
        )
        .unwrap();
        let exact_entry = catalog_ordered_entry(&mut store, &rotated, exact);
        let heads_before = store.heads().unwrap().unwrap();
        {
            let prepared =
                match prepare_ordered(&mut store, &mut executor, &rotated, &exact_entry).unwrap() {
                    ReplayPreparation::Ready(prepared) => prepared,
                    ReplayPreparation::AlreadyCommitted(_) => unreachable!(),
                };
            let write = prepared.sealed.system_authority_write().unwrap();
            let StandardSystemAuthorityWrite::Catalog { record, history } = write.selected() else {
                unreachable!()
            };
            assert_eq!(record.as_ref(), Some(&original_record));
            assert!(!history.inserted());
            assert_eq!(
                write.predecessor_authority().rotation_first_sequence(),
                Some(4)
            );
            assert_eq!(
                write.successor_authority().rotation_first_sequence(),
                Some(4)
            );
            assert_eq!(write.predecessor_authority(), write.successor_authority());
            let generic = prepared.sealed.clone();
            assert_eq!(
                prepared.store.publish(&generic),
                Err(JournalStoreError::NonCanonical)
            );
        }
        assert_eq!(store.heads().unwrap(), Some(heads_before.clone()));
        assert!(ledger.recover_pending_claim().unwrap().is_none());

        let divergent_fact = catalog_fact_for_authority(
            rotated_view.authority_state(),
            original_record.operation_id(),
            4,
            0x4b,
        );
        let divergent_receipt =
            signed_catalog_receipt(divergent_fact.clone(), rotated_view.committee(), &keys);
        let divergent_record = SystemAuthorityCatalogRecord::new(
            divergent_receipt.clone(),
            rotated_view
                .authority_state()
                .catalog_binding_record()
                .unwrap(),
            rotated_view.committee(),
        )
        .unwrap();
        assert_ne!(divergent_record.id(), original_record.id());
        assert!(
            store
                .load_system_authority_catalog_record(divergent_record.id())
                .unwrap()
                .is_none()
        );
        assert!(
            SystemAuthorityCatalogReservationRequest::new(
                rotated_view.committee().clone(),
                divergent_fact,
                occupied.clone(),
            )
            .is_err()
        );
        let conflict = SystemAuthorityCatalogFinalize::new(divergent_receipt, occupied).unwrap();
        let conflict_entry = catalog_ordered_entry(&mut store, &rotated, conflict);
        {
            let prepared = match prepare_ordered(
                &mut store,
                &mut executor,
                &rotated,
                &conflict_entry,
            )
            .unwrap()
            {
                ReplayPreparation::Ready(prepared) => prepared,
                ReplayPreparation::AlreadyCommitted(_) => unreachable!(),
            };
            let write = prepared.sealed.system_authority_write().unwrap();
            let StandardSystemAuthorityWrite::Catalog { record, history } = write.selected() else {
                unreachable!()
            };
            assert!(record.is_none());
            assert!(!history.inserted());
            assert!(matches!(
                write.result(),
                LifecycleReply::CatalogFinalized(outcome) if outcome.operation_conflicted()
            ));
            assert_eq!(
                write.predecessor_authority().rotation_first_sequence(),
                Some(4)
            );
            assert_eq!(
                write.successor_authority().rotation_first_sequence(),
                Some(4)
            );
            assert_eq!(write.predecessor_authority(), write.successor_authority());
            let generic = prepared.sealed.clone();
            assert_eq!(
                prepared.store.publish(&generic),
                Err(JournalStoreError::NonCanonical)
            );
        }
        assert_eq!(store.heads().unwrap(), Some(heads_before));
        assert!(
            store
                .load_system_authority_catalog_record(divergent_record.id())
                .unwrap()
                .is_none()
        );
        assert!(ledger.recover_pending_claim().unwrap().is_none());

        // The retry/conflict paths used the authenticated post-rotation state,
        // but neither could consume its one-shot marker without a fresh vacant
        // reservation and an exact durable publication.
        let (_, durable_view) = materialized_system_authority_view(&store, &rotated).unwrap();
        assert_eq!(durable_view.committee_sequence_high_water(), 3);
        assert_eq!(durable_view.rotation_first_sequence(), Some(4));
        assert_eq!(
            durable_view.authority_state().journal_binding(),
            Some(scope.binding())
        );

        drop(ledger);
        drop(database);
        std::fs::remove_dir_all(directory).unwrap();
    }

    #[cfg(all(feature = "std", feature = "storage"))]
    #[test]
    fn cold_catalog_pre_cas_intent_resumes_and_retires_without_a_signer() {
        let CatalogPublicationFixture {
            mut store,
            mut executor,
            predecessor,
            ledger,
            reserved,
            entry,
            database,
            directory,
        } = catalog_publication_fixture(0x43);
        let route = ledger.route();
        let local_node = ledger.local_node();
        let journal_store = ledger.journal_store();
        let retained = reserved.clone();
        let prepared =
            match prepare_ordered(&mut store, &mut executor, &predecessor, &entry).unwrap() {
                ReplayPreparation::Ready(prepared) => prepared,
                ReplayPreparation::AlreadyCommitted(_) => unreachable!(),
            }
            .prepare_system_authority_catalog(reserved)
            .unwrap();
        let facts = prepared.publication_facts().unwrap();
        let predecessor_heads = predecessor.heads_id();
        let certificate = ledger
            .owner()
            .certificate(&retained, SystemAuthorityCommitteeLeg::Current)
            .unwrap()
            .unwrap();
        let injected = ledger
            .owner()
            .with_active_catalog_publication_reservation(&retained, &certificate, &facts, || {
                Err::<(), _>(JournalStoreError::Unavailable)
            })
            .unwrap();
        assert_eq!(injected, Err(JournalStoreError::Unavailable));
        drop(prepared);
        drop(retained);
        drop(predecessor);
        drop(executor);
        let database_path = directory.join("evidence.redb");
        drop(ledger);
        drop(database);

        let database = alloc::sync::Arc::new(Database::open(&database_path).unwrap());
        let owner = SystemAuthorityLedgerRouteOwner::open(
            database.clone(),
            route,
            journal_store,
            local_node,
        )
        .unwrap();
        let mut materializer = ExactCreateRejectInvocations::default();
        let predecessor =
            materialize_current_reverified(&mut store, &mut materializer, &NoPrunedOrderedBases)
                .unwrap();
        assert_eq!(predecessor.heads_id(), predecessor_heads);
        let pending = owner.recover_pending_claim().unwrap().unwrap();
        assert!(pending.catalog_request().is_some());
        assert_eq!(
            pending.expected_successor_heads(),
            Some(facts.successor_heads())
        );
        let mut divergent = RejectingAuthenticationExecutor;
        assert!(matches!(
            recover_pending_system_authority_catalog(
                &mut store,
                &mut divergent,
                predecessor.clone(),
                pending,
                &owner,
            ),
            Err(SystemAuthorityRecoveryError::Replay(_))
        ));
        assert_eq!(store.heads().unwrap().unwrap().id(), predecessor_heads);
        let pending = owner.recover_pending_claim().unwrap().unwrap();
        let mut executor = ExactCreateRejectInvocations::default();
        let retired = match recover_pending_system_authority_catalog(
            &mut store,
            &mut executor,
            predecessor,
            pending,
            &owner,
        )
        .unwrap()
        {
            PendingSystemAuthorityCatalogRecovery::Retired(retired) => retired,
            PendingSystemAuthorityCatalogRecovery::Pending(_) => unreachable!(),
        };
        assert_eq!(
            retired.materialization().heads_id(),
            facts.successor_heads()
        );
        assert!(retired.publication().unwrap().heads_advanced);
        assert_eq!(
            store.heads().unwrap().unwrap().id(),
            facts.successor_heads()
        );
        assert!(owner.recover_pending_claim().unwrap().is_none());

        drop(owner);
        drop(database);
        std::fs::remove_dir_all(directory).unwrap();
    }

    #[cfg(all(feature = "std", feature = "storage"))]
    #[test]
    fn cold_catalog_successor_recovers_and_retires_exact_intent() {
        let CatalogPublicationFixture {
            mut store,
            mut executor,
            predecessor,
            ledger,
            reserved,
            entry,
            database,
            directory,
        } = catalog_publication_fixture(0x44);
        let route = ledger.route();
        let local_node = ledger.local_node();
        let journal_store = ledger.journal_store();
        let prepared =
            match prepare_ordered(&mut store, &mut executor, &predecessor, &entry).unwrap() {
                ReplayPreparation::Ready(prepared) => prepared,
                ReplayPreparation::AlreadyCommitted(_) => unreachable!(),
            }
            .prepare_system_authority_catalog(reserved)
            .unwrap();
        let published = prepared
            .publish_system_authority_catalog(ledger.owner())
            .unwrap();
        let expected_successor = published.facts().successor_heads();
        drop(published);

        // Simulate process loss after the catalog dependencies and Heads CAS
        // are durable, but before the exact publication intent is retired.
        let database_path = directory.join("evidence.redb");
        drop(ledger);
        drop(database);
        let database = alloc::sync::Arc::new(Database::open(&database_path).unwrap());
        let owner = SystemAuthorityLedgerRouteOwner::open(
            database.clone(),
            route,
            journal_store,
            local_node,
        )
        .unwrap();
        let current =
            materialize_current_reverified(&mut store, &mut executor, &NoPrunedOrderedBases)
                .unwrap();
        assert_eq!(current.heads_id(), expected_successor);
        let pending = owner.recover_pending_claim().unwrap().unwrap();
        let retired = match recover_pending_system_authority_catalog(
            &mut store,
            &mut executor,
            current,
            pending,
            &owner,
        )
        .unwrap()
        {
            PendingSystemAuthorityCatalogRecovery::Retired(retired) => retired,
            PendingSystemAuthorityCatalogRecovery::Pending(_) => unreachable!(),
        };
        assert!(retired.publication().is_none());
        assert_eq!(retired.materialization().heads_id(), expected_successor);
        assert_eq!(store.heads().unwrap().unwrap().id(), expected_successor);
        assert!(owner.recover_pending_claim().unwrap().is_none());

        drop(owner);
        drop(database);
        std::fs::remove_dir_all(directory).unwrap();
    }

    #[cfg(all(feature = "std", feature = "storage"))]
    #[test]
    fn cold_catalog_recovery_rejects_tampered_write_and_history_without_retirement() {
        let CatalogPublicationFixture {
            mut store,
            mut executor,
            predecessor,
            ledger,
            reserved,
            entry,
            database,
            directory,
        } = catalog_publication_fixture(0x4c);
        let prepared =
            match prepare_ordered(&mut store, &mut executor, &predecessor, &entry).unwrap() {
                ReplayPreparation::Ready(prepared) => prepared,
                ReplayPreparation::AlreadyCommitted(_) => unreachable!(),
            }
            .prepare_system_authority_catalog(reserved)
            .unwrap();
        let published = prepared
            .publish_system_authority_catalog(ledger.owner())
            .unwrap();
        drop(published);
        let current =
            materialize_current_reverified(&mut store, &mut executor, &NoPrunedOrderedBases)
                .unwrap();

        let mut tampered_operation = current.clone();
        tampered_operation
            .final_system_authority_write
            .as_mut()
            .unwrap()
            .write
            .operation = Hash([0x4d; 32]);
        let pending = ledger.recover_pending_claim().unwrap().unwrap();
        assert!(matches!(
            recover_pending_system_authority_catalog(
                &mut store,
                &mut executor,
                tampered_operation,
                pending,
                ledger.owner(),
            ),
            Err(SystemAuthorityRecoveryError::Journal(
                JournalStoreError::NonCanonical
            ))
        ));
        assert!(ledger.recover_pending_claim().unwrap().is_some());

        // Replace the fresh inserted history with a separately valid exact-
        // retry plan. Every record and proof remains individually canonical,
        // but it is not the storage closure committed by the durable intent.
        let decoded = decode_standard_runtime_state(current.state()).unwrap();
        let authority = decoded.system_authority.unwrap();
        let identity = current.replayed_root().unwrap();
        let scope = SystemAuthorityJournalScope::from_replayed_root(&identity).unwrap();
        let final_write = current.final_system_authority_write.as_ref().unwrap();
        let ReplayOperation::Management {
            request: LifecycleRequest::FinalizeCatalog(command),
        } = &final_write.entry.input.operation
        else {
            unreachable!()
        };
        let StandardSystemAuthorityWrite::Catalog {
            record: Some(record),
            ..
        } = final_write.write.selected()
        else {
            unreachable!()
        };
        let occupied = prove_catalog(
            authority.catalog_history_root(),
            record.operation_id(),
            |id| {
                store
                    .load_system_authority_catalog_node(id)
                    .map(|node| node.map(|node| node.encode()))
            },
        )
        .unwrap();
        let retry =
            SystemAuthorityCatalogFinalize::new(command.receipt().clone(), occupied).unwrap();
        let retry_transition = authority.apply_catalog_finalize(scope, &retry).unwrap();
        assert!(retry_transition.outcome().exact_retry());
        assert!(!retry_transition.history().inserted());
        let mut tampered_history = current.clone();
        let materialized_write = tampered_history
            .final_system_authority_write
            .as_mut()
            .unwrap();
        materialized_write.write.selected = StandardSystemAuthorityWrite::Catalog {
            record: Some(record.clone()),
            history: retry_transition.history().clone(),
        };
        let pending = ledger.recover_pending_claim().unwrap().unwrap();
        assert!(matches!(
            recover_pending_system_authority_catalog(
                &mut store,
                &mut executor,
                tampered_history,
                pending,
                ledger.owner(),
            ),
            Err(SystemAuthorityRecoveryError::Journal(
                JournalStoreError::NonCanonical
            ))
        ));
        assert!(ledger.recover_pending_claim().unwrap().is_some());

        let pending = ledger.recover_pending_claim().unwrap().unwrap();
        let retired = match recover_pending_system_authority_catalog(
            &mut store,
            &mut executor,
            current,
            pending,
            ledger.owner(),
        )
        .unwrap()
        {
            PendingSystemAuthorityCatalogRecovery::Retired(retired) => retired,
            PendingSystemAuthorityCatalogRecovery::Pending(_) => unreachable!(),
        };
        assert!(retired.publication().is_none());
        assert!(ledger.recover_pending_claim().unwrap().is_none());

        drop(ledger);
        drop(database);
        std::fs::remove_dir_all(directory).unwrap();
    }

    #[cfg(all(feature = "std", feature = "storage"))]
    #[test]
    fn cold_catalog_recovery_rejects_a_later_unrelated_head_and_retains_intent() {
        let CatalogPublicationFixture {
            mut store,
            mut executor,
            predecessor,
            ledger,
            reserved,
            entry,
            database,
            directory,
        } = catalog_publication_fixture(0x4e);
        let prepared =
            match prepare_ordered(&mut store, &mut executor, &predecessor, &entry).unwrap() {
                ReplayPreparation::Ready(prepared) => prepared,
                ReplayPreparation::AlreadyCommitted(_) => unreachable!(),
            }
            .prepare_system_authority_catalog(reserved)
            .unwrap();
        let published = prepared
            .publish_system_authority_catalog(ledger.owner())
            .unwrap();
        let exact_successor = published.facts().successor_heads();
        drop(published);
        let current =
            materialize_current_reverified(&mut store, &mut executor, &NoPrunedOrderedBases)
                .unwrap();
        assert_eq!(current.heads_id(), exact_successor);
        let checkpoint = prepare_checkpoint(&mut store, &current).unwrap();
        let (_, later, _) = checkpoint.publish().unwrap();
        assert_ne!(later.heads_id(), exact_successor);
        assert_eq!(later.heads().previous, Some(exact_successor));

        let pending = ledger.recover_pending_claim().unwrap().unwrap();
        assert!(matches!(
            recover_pending_system_authority_catalog(
                &mut store,
                &mut executor,
                later,
                pending,
                ledger.owner(),
            ),
            Err(SystemAuthorityRecoveryError::Journal(
                JournalStoreError::Conflict
            ))
        ));
        let pending = ledger.recover_pending_claim().unwrap().unwrap();
        assert_eq!(pending.expected_successor_heads(), Some(exact_successor));

        drop(ledger);
        drop(database);
        std::fs::remove_dir_all(directory).unwrap();
    }

    #[cfg(all(feature = "std", feature = "storage"))]
    #[test]
    fn cold_pre_cas_intent_resumes_and_retires_without_a_signer() {
        let RotationPublicationFixture {
            mut store,
            mut executor,
            predecessor,
            ledger,
            reserved,
            entry,
            database,
            directory,
        } = rotation_publication_fixture(0xd8);
        let route = ledger.route();
        let local_node = ledger.local_node();
        let journal_store = ledger.journal_store();
        let retained = reserved.clone();
        let prepared =
            match prepare_ordered(&mut store, &mut executor, &predecessor, &entry).unwrap() {
                ReplayPreparation::Ready(prepared) => prepared,
                ReplayPreparation::AlreadyCommitted(_) => unreachable!(),
            }
            .prepare_system_authority_rotation(reserved)
            .unwrap();
        let facts = prepared.publication_facts().unwrap();
        let predecessor_heads = predecessor.heads_id();
        let certificate = ledger
            .joint_rotation_certificate(&retained)
            .unwrap()
            .unwrap();
        let injected = ledger
            .owner()
            .with_active_publication_reservation(&retained, &certificate, &facts, || {
                Err::<(), _>(JournalStoreError::Unavailable)
            })
            .unwrap();
        assert_eq!(injected, Err(JournalStoreError::Unavailable));
        drop(prepared);
        drop(retained);
        drop(predecessor);
        drop(executor);
        let database_path = directory.join("evidence.redb");
        drop(ledger);
        drop(database);

        // Reopen only the signer-independent route owner. No Reserved bearer
        // or signer child survives the simulated process loss.
        let database = alloc::sync::Arc::new(Database::open(&database_path).unwrap());
        let owner = SystemAuthorityLedgerRouteOwner::open(
            database.clone(),
            route,
            journal_store,
            local_node,
        )
        .unwrap();
        let mut materializer = ExactCreateRejectInvocations::default();
        let predecessor =
            materialize_current_reverified(&mut store, &mut materializer, &NoPrunedOrderedBases)
                .unwrap();
        assert_eq!(predecessor.heads_id(), predecessor_heads);
        let pending = owner.recover_pending_claim().unwrap().unwrap();
        assert_eq!(pending.predecessor_heads(), predecessor.heads_id());
        assert_eq!(
            pending.expected_successor_heads(),
            Some(facts.successor_heads())
        );
        assert_eq!(store.heads().unwrap().unwrap().id(), predecessor.heads_id());
        let mut divergent = RejectingAuthenticationExecutor;
        assert!(matches!(
            recover_pending_system_authority_rotation(
                &mut store,
                &mut divergent,
                predecessor.clone(),
                pending,
                &owner,
            ),
            Err(SystemAuthorityRecoveryError::Replay(_))
        ));
        assert_eq!(store.heads().unwrap().unwrap().id(), predecessor_heads);
        let pending = owner.recover_pending_claim().unwrap().unwrap();
        assert_eq!(
            pending.expected_successor_heads(),
            Some(facts.successor_heads())
        );
        let mut executor = ExactCreateRejectInvocations::default();
        let retired = match recover_pending_system_authority_rotation(
            &mut store,
            &mut executor,
            predecessor.clone(),
            pending,
            &owner,
        )
        .unwrap()
        {
            PendingSystemAuthorityRotationRecovery::Retired(retired) => retired,
            PendingSystemAuthorityRotationRecovery::Pending(_) => unreachable!(),
        };
        assert_eq!(
            retired.materialization().heads_id(),
            facts.successor_heads()
        );
        assert!(retired.publication().unwrap().heads_advanced);
        assert_eq!(
            store.heads().unwrap().unwrap().id(),
            facts.successor_heads()
        );
        assert!(owner.recover_pending_claim().unwrap().is_none());

        drop(owner);
        drop(database);
        std::fs::remove_dir_all(directory).unwrap();
    }

    #[cfg(all(feature = "std", feature = "storage"))]
    #[test]
    fn cold_pre_cas_resume_rejects_missing_intent_merge_seal_and_retains_pending() {
        let RotationPublicationFixture {
            mut store,
            mut executor,
            predecessor,
            ledger,
            reserved,
            entry,
            database,
            directory,
        } = rotation_publication_fixture(0xdc);
        let retained = reserved.clone();
        let mut missing_dependency = entry.clone();
        let prepared =
            match prepare_ordered(&mut store, &mut executor, &predecessor, &entry).unwrap() {
                ReplayPreparation::Ready(prepared) => prepared,
                ReplayPreparation::AlreadyCommitted(_) => unreachable!(),
            }
            .prepare_system_authority_rotation(reserved)
            .unwrap();
        let facts = prepared.publication_facts().unwrap();
        let certificate = ledger
            .owner()
            .joint_rotation_certificate(&retained)
            .unwrap()
            .unwrap();
        assert_eq!(
            ledger
                .owner()
                .with_active_publication_reservation(
                    &retained,
                    &certificate,
                    &facts,
                    || Err::<(), _>(JournalStoreError::Unavailable),
                )
                .unwrap(),
            Err(JournalStoreError::Unavailable)
        );
        drop(prepared);
        missing_dependency.merge_seal = Some(MergeSealId([0xed; 32]));
        ledger
            .owner()
            .replace_pending_ordered_entry_for_test(missing_dependency)
            .unwrap();

        let heads_before = store.heads().unwrap().unwrap();
        let pending = ledger.owner().recover_pending_claim().unwrap().unwrap();
        let mut cold_executor = ExactCreateRejectInvocations::default();
        assert!(matches!(
            recover_pending_system_authority_rotation(
                &mut store,
                &mut cold_executor,
                predecessor,
                pending,
                ledger.owner(),
            ),
            Err(SystemAuthorityRecoveryError::Replay(_))
        ));
        assert_eq!(store.heads().unwrap(), Some(heads_before));
        assert!(ledger.owner().recover_pending_claim().unwrap().is_some());

        drop(ledger);
        drop(database);
        std::fs::remove_dir_all(directory).unwrap();
    }

    #[cfg(all(feature = "std", feature = "storage"))]
    #[test]
    fn cold_immediate_rotation_successor_recovers_and_retires_exact_intent() {
        let RotationPublicationFixture {
            mut store,
            mut executor,
            predecessor,
            ledger,
            reserved,
            entry,
            database,
            directory,
        } = rotation_publication_fixture(0xd9);
        let route = ledger.route();
        let local_node = ledger.local_node();
        let journal_store = ledger.journal_store();
        let prepared =
            match prepare_ordered(&mut store, &mut executor, &predecessor, &entry).unwrap() {
                ReplayPreparation::Ready(prepared) => prepared,
                ReplayPreparation::AlreadyCommitted(_) => unreachable!(),
            }
            .prepare_system_authority_rotation(reserved)
            .unwrap();
        let published = prepared
            .publish_system_authority_rotation(ledger.owner())
            .unwrap();
        let expected_successor = published.facts().successor_heads();
        drop(published);

        // Memory journal durability is simulated by retaining the physical
        // store while discarding all process-local replay and ledger objects.
        let database_path = directory.join("evidence.redb");
        drop(ledger);
        drop(database);
        let database = alloc::sync::Arc::new(Database::open(&database_path).unwrap());
        let owner = SystemAuthorityLedgerRouteOwner::open(
            database.clone(),
            route,
            journal_store,
            local_node,
        )
        .unwrap();
        let current =
            materialize_current_reverified(&mut store, &mut executor, &NoPrunedOrderedBases)
                .unwrap();
        assert_eq!(current.heads_id(), expected_successor);
        let pending = owner.recover_pending_claim().unwrap().unwrap();
        let retired = match recover_pending_system_authority_rotation(
            &mut store,
            &mut executor,
            current,
            pending,
            &owner,
        )
        .unwrap()
        {
            PendingSystemAuthorityRotationRecovery::Retired(retired) => retired,
            PendingSystemAuthorityRotationRecovery::Pending(_) => unreachable!(),
        };
        assert!(retired.publication().is_none());
        assert_eq!(retired.materialization().heads_id(), expected_successor);
        assert_eq!(store.heads().unwrap().unwrap().id(), expected_successor);
        assert!(owner.recover_pending_claim().unwrap().is_none());

        drop(owner);
        drop(database);
        std::fs::remove_dir_all(directory).unwrap();
    }

    #[cfg(all(feature = "std", feature = "storage"))]
    #[test]
    fn cold_rotation_recovery_rejects_tampered_replay_write_without_retirement() {
        let RotationPublicationFixture {
            mut store,
            mut executor,
            predecessor,
            ledger,
            reserved,
            entry,
            database,
            directory,
        } = rotation_publication_fixture(0xda);
        let prepared =
            match prepare_ordered(&mut store, &mut executor, &predecessor, &entry).unwrap() {
                ReplayPreparation::Ready(prepared) => prepared,
                ReplayPreparation::AlreadyCommitted(_) => unreachable!(),
            }
            .prepare_system_authority_rotation(reserved)
            .unwrap();
        let published = prepared
            .publish_system_authority_rotation(ledger.owner())
            .unwrap();
        drop(published);
        let current =
            materialize_current_reverified(&mut store, &mut executor, &NoPrunedOrderedBases)
                .unwrap();
        let mut tampered = current.clone();
        tampered
            .final_system_authority_write
            .as_mut()
            .unwrap()
            .write
            .operation = Hash([0x5a; 32]);
        let pending = ledger.recover_pending_claim().unwrap().unwrap();
        assert!(matches!(
            recover_pending_system_authority_rotation(
                &mut store,
                &mut executor,
                tampered,
                pending,
                ledger.owner(),
            ),
            Err(SystemAuthorityRecoveryError::Journal(
                JournalStoreError::NonCanonical
            ))
        ));
        assert!(ledger.recover_pending_claim().unwrap().is_some());

        let pending = ledger.recover_pending_claim().unwrap().unwrap();
        let retired = match recover_pending_system_authority_rotation(
            &mut store,
            &mut executor,
            current,
            pending,
            ledger.owner(),
        )
        .unwrap()
        {
            PendingSystemAuthorityRotationRecovery::Retired(retired) => retired,
            PendingSystemAuthorityRotationRecovery::Pending(_) => unreachable!(),
        };
        assert!(retired.publication().is_none());
        assert!(ledger.recover_pending_claim().unwrap().is_none());

        drop(ledger);
        drop(database);
        std::fs::remove_dir_all(directory).unwrap();
    }

    #[cfg(all(feature = "std", feature = "storage"))]
    #[test]
    fn cold_rotation_recovery_rejects_a_later_unrelated_head() {
        let RotationPublicationFixture {
            mut store,
            mut executor,
            predecessor,
            ledger,
            reserved,
            entry,
            database,
            directory,
        } = rotation_publication_fixture(0xdb);
        let prepared =
            match prepare_ordered(&mut store, &mut executor, &predecessor, &entry).unwrap() {
                ReplayPreparation::Ready(prepared) => prepared,
                ReplayPreparation::AlreadyCommitted(_) => unreachable!(),
            }
            .prepare_system_authority_rotation(reserved)
            .unwrap();
        let published = prepared
            .publish_system_authority_rotation(ledger.owner())
            .unwrap();
        let exact_successor = published.facts().successor_heads();
        drop(published);
        let current =
            materialize_current_reverified(&mut store, &mut executor, &NoPrunedOrderedBases)
                .unwrap();
        assert_eq!(current.heads_id(), exact_successor);
        let checkpoint = prepare_checkpoint(&mut store, &current).unwrap();
        let (_, later, _) = checkpoint.publish().unwrap();
        assert_ne!(later.heads_id(), exact_successor);
        assert_eq!(later.heads().previous, Some(exact_successor));

        let pending = ledger.recover_pending_claim().unwrap().unwrap();
        assert!(matches!(
            recover_pending_system_authority_rotation(
                &mut store,
                &mut executor,
                later,
                pending,
                ledger.owner(),
            ),
            Err(SystemAuthorityRecoveryError::Journal(
                JournalStoreError::Conflict
            ))
        ));
        assert!(ledger.recover_pending_claim().unwrap().is_some());

        drop(ledger);
        drop(database);
        std::fs::remove_dir_all(directory).unwrap();
    }

    #[cfg(feature = "std")]
    #[test]
    fn checkpoint_constructor_does_not_inherit_root_authority_provenance() {
        let sealed = admitted_genesis(0xd3);
        let node = admitted_config().replicas[0].node;
        let mut store = MemoryAgentJournalStore::new(admitted_runtime().agent, node).unwrap();
        store
            .put_blob(
                JournalBlobClass::CatalogArtifact,
                &admitted_runtime().package,
                b"replay-runtime-package",
            )
            .unwrap();
        assert!(store.initialize(&sealed).unwrap());
        let mut executor = ExactCreateRejectInvocations::default();
        let materialized =
            materialize_current(&mut store, &mut executor, &NoPrunedOrderedBases).unwrap();
        let prepared = prepare_checkpoint(&mut store, &materialized).unwrap();
        let checkpoint = prepared.sealed.checkpoint.clone().unwrap();
        drop(prepared);
        let ownership = GenesisInvocationOwnership {
            genesis: sealed.genesis().id(),
            entries: BTreeMap::new(),
            history: BTreeMap::new(),
            outcomes: BTreeMap::new(),
        };
        let mut machine = ReplayMachine::from_checkpoint(&checkpoint, ownership, None).unwrap();
        assert!(machine.replayed_root.is_none());
        let input = authority_finalize_input(&sealed, admitted_finalize_for_test(&sealed, 2));
        assert!(matches!(
            machine.apply::<_, ()>(
                &mut executor,
                &input,
                materialized.state(),
                ReplayPosition::Ordered {
                    id: OrderedEntryId([0xd4; 32]),
                    index: 1,
                    merge_frontier: materialized.merge_frontier(),
                    merge_seal: Some(MergeSealId([0xd5; 32])),
                },
            ),
            Err(ReplayError::ScopeMismatch)
        ));
    }

    #[cfg(feature = "std")]
    #[test]
    fn sealed_genesis_initialization_binds_exact_create_closure() {
        let sealed = admitted_genesis(0xc1);
        let AgentGenesisAdmissionRecord::RootBootstrap(root_admission) = sealed.admission_record()
        else {
            panic!("system bootstrap must carry the tagged root admission")
        };
        assert_eq!(root_admission, sealed.root_admission_record());
        assert_eq!(root_admission.id(), sealed.root_admission_id());
        assert_ne!(
            sealed.root_admission_id(),
            SystemAgentGenesisAdmissionId::ZERO
        );
        assert_ne!(sealed.genesis().admission, AgentGenesisAdmissionId::ZERO);
        assert_ne!(sealed.genesis().id(), AgentJournalGenesisId::ZERO);
        assert_eq!(sealed.genesis().admission, sealed.admission_record().id());
        assert_ne!(
            sealed.genesis().admission.as_bytes(),
            root_admission.id().as_bytes()
        );
        let node = admitted_config().replicas[0].node;
        let mut store = MemoryAgentJournalStore::new(admitted_runtime().agent, node).unwrap();
        store
            .put_blob(
                JournalBlobClass::CatalogArtifact,
                &admitted_runtime().package,
                b"replay-runtime-package",
            )
            .unwrap();

        assert!(store.initialize(&sealed).unwrap());
        assert!(!store.initialize(&sealed).unwrap());
        assert_eq!(store.genesis().unwrap().as_ref(), Some(sealed.genesis()));
        assert_eq!(store.heads().unwrap().unwrap(), sealed.initial_heads());

        let conflicting_admission = admitted_genesis(0xc2);
        assert_eq!(
            store.initialize(&conflicting_admission),
            Err(crate::agent::journal_store::JournalStoreError::Conflict)
        );

        let foreign_node = NodeId([0xc3; 32]);
        let mut foreign_store =
            MemoryAgentJournalStore::new(admitted_runtime().agent, foreign_node).unwrap();
        foreign_store
            .put_blob(
                JournalBlobClass::CatalogArtifact,
                &admitted_runtime().package,
                b"replay-runtime-package",
            )
            .unwrap();
        assert_eq!(
            foreign_store.initialize(&sealed),
            Err(crate::agent::journal_store::JournalStoreError::ScopeMismatch)
        );

        let mut wrong_principal = admitted_genesis(0xc4);
        wrong_principal.replica.principal = PrincipalId([0xc5; 32]);
        let mut principal_store =
            MemoryAgentJournalStore::new(admitted_runtime().agent, node).unwrap();
        principal_store
            .put_blob(
                JournalBlobClass::CatalogArtifact,
                &admitted_runtime().package,
                b"replay-runtime-package",
            )
            .unwrap();
        assert_eq!(
            principal_store.initialize(&wrong_principal),
            Err(crate::agent::journal_store::JournalStoreError::ScopeMismatch)
        );

        let mut executor = ExactCreateRejectInvocations::default();
        let materialized =
            materialize_current(&mut store, &mut executor, &NoPrunedOrderedBases).unwrap();
        assert_eq!(materialized.state(), sealed.post_create());
        assert_eq!(materialized.local_cursor(), (node, 0, None));
        assert_eq!(executor.executions, 1);
    }

    #[cfg(feature = "std")]
    #[test]
    fn checkpoint_seals_the_physical_local_lane_at_revision_zero() {
        let mut store = initialized_replay_store();
        let mut executor = ExactCreateRejectInvocations::default();
        let mut materialized =
            materialize_current(&mut store, &mut executor, &NoPrunedOrderedBases).unwrap();
        assert_eq!(materialized.local_cursor().1, 0);
        assert!(materialized.local_cursor().2.is_none());

        for _ in 0..3 {
            let prepared = prepare_checkpoint(&mut store, &materialized).unwrap();
            let (_publication, successor, execution) = prepared.publish().unwrap();
            assert!(execution.is_empty());
            assert!(successor.heads().checkpoint.is_some());
            assert_eq!(successor.local_cursor(), materialized.local_cursor());
            assert_eq!(successor.ordered_snapshots.len(), 1);

            let reopened =
                materialize_current(&mut store, &mut executor, &NoPrunedOrderedBases).unwrap();
            assert_eq!(reopened.heads(), successor.heads());
            assert_eq!(reopened.state(), successor.state());
            assert_eq!(reopened.local_cursor().1, 0);
            assert!(reopened.local_cursor().2.is_none());
            assert_eq!(reopened.ordered_snapshots.len(), 1);
            materialized = reopened;
        }
    }

    #[cfg(feature = "std")]
    #[test]
    fn live_suffix_limit_matches_reopen_and_checkpoint_resets_it() {
        let mut store = initialized_linear_replay_store();
        let mut executor = ExactCreateRejectInvocations::default();
        let mut materialized =
            materialize_current(&mut store, &mut executor, &NoPrunedOrderedBases).unwrap();
        let repeated = admitted_invocation(MethodMode::Linear, 0xcc);

        for index in 1..=MAX_REPLAY_SUFFIX_ENTRIES as u64 {
            let entry = OrderedEntry {
                genesis: materialized.heads().genesis,
                index,
                parent: materialized.heads().ordered_head,
                merge_frontier: materialized.merge_frontier(),
                merge_seal: None,
                input: repeated.clone(),
            };
            let prepared =
                match prepare_ordered(&mut store, &mut executor, &materialized, &entry).unwrap() {
                    ReplayPreparation::Ready(prepared) => prepared,
                    ReplayPreparation::AlreadyCommitted(_) => unreachable!(),
                };
            let (_publication, successor, _) = prepared.publish().unwrap();
            materialized = successor;
        }

        let reopened =
            materialize_current(&mut store, &mut executor, &NoPrunedOrderedBases).unwrap();
        assert_eq!(reopened.heads(), materialized.heads());
        assert_eq!(reopened.suffix_budget.entries, MAX_REPLAY_SUFFIX_ENTRIES);
        let overflow = OrderedEntry {
            genesis: reopened.heads().genesis,
            index: MAX_REPLAY_SUFFIX_ENTRIES as u64 + 1,
            parent: reopened.heads().ordered_head,
            merge_frontier: reopened.merge_frontier(),
            merge_seal: None,
            input: repeated.clone(),
        };
        let executions_before_overflow = executor.executions;
        assert!(matches!(
            prepare_ordered(&mut store, &mut executor, &reopened, &overflow),
            Err(ReplayError::ReplayLimit)
        ));
        assert_eq!(executor.executions, executions_before_overflow);

        let checkpoint = prepare_checkpoint(&mut store, &reopened).unwrap();
        let (_publication, checkpointed, _) = checkpoint.publish().unwrap();
        assert_eq!(checkpointed.suffix_budget.entries, 0);
        assert_eq!(checkpointed.ordered_snapshots.len(), 1);

        let prepared =
            match prepare_ordered(&mut store, &mut executor, &checkpointed, &overflow).unwrap() {
                ReplayPreparation::Ready(prepared) => prepared,
                ReplayPreparation::AlreadyCommitted(_) => unreachable!(),
            };
        let (_publication, successor, _) = prepared.publish().unwrap();
        let reopened =
            materialize_current(&mut store, &mut executor, &NoPrunedOrderedBases).unwrap();
        assert_eq!(reopened.heads(), successor.heads());
        assert_eq!(reopened.suffix_budget.entries, 1);
    }

    #[cfg(feature = "std")]
    #[test]
    fn pending_merge_reserves_finalizer_capacity_across_all_lanes() {
        let mut store = initialized_linear_replay_store();
        let mut executor = ExactCreateRejectInvocations::default();
        let mut materialized =
            materialize_current(&mut store, &mut executor, &NoPrunedOrderedBases).unwrap();
        let repeated = admitted_invocation(MethodMode::Linear, 0xcd);

        // Leave exactly two entry slots: one for the Merge source and one for
        // its mandatory ordered finalizer.
        for index in 1..=(MAX_REPLAY_SUFFIX_ENTRIES as u64 - 2) {
            let entry = OrderedEntry {
                genesis: materialized.heads().genesis,
                index,
                parent: materialized.heads().ordered_head,
                merge_frontier: materialized.merge_frontier(),
                merge_seal: None,
                input: repeated.clone(),
            };
            let prepared =
                match prepare_ordered(&mut store, &mut executor, &materialized, &entry).unwrap() {
                    ReplayPreparation::Ready(prepared) => prepared,
                    ReplayPreparation::AlreadyCommitted(_) => unreachable!(),
                };
            let (_publication, successor, _) = prepared.publish().unwrap();
            materialized = successor;
        }
        assert_eq!(
            materialized.suffix_budget.entries,
            MAX_REPLAY_SUFFIX_ENTRIES - 2
        );

        let source = MergeEvent {
            genesis: materialized.heads().genesis,
            committee: None,
            author: materialized.heads().node,
            ordered_base: materialized.ordered_base(),
            causal_height: 1,
            parents: Vec::new(),
            input: admitted_invocation(MethodMode::Merge, 0xce),
            signature: vec![0xce; ED25519_SIGNATURE_BYTES],
        };
        let prepared = match prepare_merge(
            &mut store,
            &mut executor,
            &NoPrunedOrderedBases,
            &materialized,
            &source,
        )
        .unwrap()
        {
            ReplayPreparation::Ready(prepared) => prepared,
            ReplayPreparation::AlreadyCommitted(_) => unreachable!(),
        };
        let (_publication, published_after_source, results) = prepared.publish().unwrap();
        assert!(results.is_empty());
        assert_eq!(
            published_after_source.suffix_budget.entries,
            MAX_REPLAY_SUFFIX_ENTRIES - 1
        );
        let after_source =
            materialize_current(&mut store, &mut executor, &NoPrunedOrderedBases).unwrap();
        assert_eq!(after_source.heads(), published_after_source.heads());
        assert_eq!(
            after_source.suffix_budget.entries,
            MAX_REPLAY_SUFFIX_ENTRIES - 1
        );

        let next_merge = MergeEvent {
            genesis: after_source.heads().genesis,
            committee: None,
            author: after_source.heads().node,
            ordered_base: after_source.ordered_base(),
            causal_height: 2,
            parents: vec![source.id()],
            input: admitted_invocation(MethodMode::Merge, 0xcf),
            signature: vec![0xcf; ED25519_SIGNATURE_BYTES],
        };
        let next_ordered = OrderedEntry {
            genesis: after_source.heads().genesis,
            index: after_source.heads().ordered_index + 1,
            parent: after_source.heads().ordered_head,
            merge_frontier: after_source.merge_frontier(),
            merge_seal: None,
            input: admitted_invocation(MethodMode::Linear, 0xd0),
        };
        let next_local = LocalEntry {
            genesis: after_source.heads().genesis,
            node: after_source.heads().node,
            revision: after_source.heads().local_revision + 1,
            parent: after_source.heads().local_head,
            ordered_base: after_source.ordered_base(),
            merge_frontier: after_source.merge_frontier(),
            input: admitted_invocation(MethodMode::Local, 0xd1),
        };
        let heads_before_rejections = store.heads().unwrap().unwrap();
        let executions_before_rejections = executor.executions;
        let verifications_before_rejections = executor.merge_verifications;
        assert!(matches!(
            prepare_merge(
                &mut store,
                &mut executor,
                &NoPrunedOrderedBases,
                &after_source,
                &next_merge,
            ),
            Err(ReplayError::ReplayLimit)
        ));
        assert!(matches!(
            prepare_ordered(&mut store, &mut executor, &after_source, &next_ordered,),
            Err(ReplayError::ReplayLimit)
        ));
        assert!(matches!(
            prepare_local(&mut store, &mut executor, &after_source, &next_local),
            Err(ReplayError::ReplayLimit)
        ));
        assert_eq!(executor.executions, executions_before_rejections);
        assert_eq!(
            executor.merge_verifications,
            verifications_before_rejections
        );
        assert_eq!(store.heads().unwrap().unwrap(), heads_before_rejections);

        let seal = persist_merge_seal(&mut store, &after_source);
        let finalizer = OrderedEntry {
            genesis: after_source.heads().genesis,
            index: after_source.heads().ordered_index + 1,
            parent: after_source.heads().ordered_head,
            merge_frontier: after_source.merge_frontier(),
            merge_seal: Some(seal),
            input: ReplayInput {
                runtime: after_source.runtime().clone(),
                operation: ReplayOperation::SealMerge,
            },
        };
        let prepared =
            match prepare_ordered(&mut store, &mut executor, &after_source, &finalizer).unwrap() {
                ReplayPreparation::Ready(prepared) => prepared,
                ReplayPreparation::AlreadyCommitted(_) => unreachable!(),
            };
        let (_publication, finalized, executions) = prepared.publish().unwrap();
        assert_eq!(executions.len(), 2);
        assert_eq!(finalized.suffix_budget.entries, MAX_REPLAY_SUFFIX_ENTRIES);

        let checkpoint = prepare_checkpoint(&mut store, &finalized).unwrap();
        let (_publication, checkpointed, executions) = checkpoint.publish().unwrap();
        assert!(executions.is_empty());
        assert_eq!(checkpointed.suffix_budget.entries, 0);

        // The checkpoint reset restores capacity for the next source. Its
        // ordered base is the retained post-finalizer snapshot, while the
        // parent remains the sealed Merge root.
        let after_reset = MergeEvent {
            ordered_base: checkpointed.ordered_base(),
            ..next_merge
        };
        let prepared = match prepare_merge(
            &mut store,
            &mut executor,
            &NoPrunedOrderedBases,
            &checkpointed,
            &after_reset,
        )
        .unwrap()
        {
            ReplayPreparation::Ready(prepared) => prepared,
            ReplayPreparation::AlreadyCommitted(_) => unreachable!(),
        };
        let (_publication, after_reset, executions) = prepared.publish().unwrap();
        assert!(executions.is_empty());
        assert_eq!(after_reset.suffix_budget.entries, 1);
    }

    #[cfg(feature = "std")]
    #[test]
    fn live_uncommitted_refusals_never_publish_or_claim_ownership() {
        let cases = [
            (
                MethodMode::Linear,
                ActorExecutionError::UnsupportedResultStorage,
            ),
            (MethodMode::Local, ActorExecutionError::MissingState),
            (MethodMode::Merge, ActorExecutionError::InvalidAvailability),
            (MethodMode::Linear, ActorExecutionError::ResultCapacity),
            (MethodMode::Local, ActorExecutionError::AuthorityExpired),
            (
                MethodMode::Merge,
                ActorExecutionError::AuthoritySlotRegressed,
            ),
        ];
        for (offset, (mode, expected)) in cases.into_iter().enumerate() {
            let mut store = initialized_replay_store();
            let mut materializer = ExactCreateRejectInvocations::default();
            let materialized =
                materialize_current(&mut store, &mut materializer, &NoPrunedOrderedBases).unwrap();
            let heads_before = store.heads().unwrap().unwrap();
            let input = admitted_invocation(mode, 0xb0 + offset as u8);
            let mut executor = UncommittedRefusalExecutor::exact(expected);
            let error = match mode {
                MethodMode::Linear => {
                    let entry = OrderedEntry {
                        genesis: materialized.heads().genesis,
                        index: 1,
                        parent: None,
                        merge_frontier: materialized.merge_frontier(),
                        merge_seal: None,
                        input: input.clone(),
                    };
                    let id = entry.id();
                    let error =
                        match prepare_ordered(&mut store, &mut executor, &materialized, &entry) {
                            Err(error) => error,
                            Ok(_) => panic!("uncommitted refusal prepared an Ordered publication"),
                        };
                    assert!(
                        AgentJournalStore::get::<OrderedEntry>(&store, id)
                            .unwrap()
                            .is_none()
                    );
                    error
                }
                MethodMode::Local => {
                    let entry = LocalEntry {
                        genesis: materialized.heads().genesis,
                        node: materialized.heads().node,
                        revision: 1,
                        parent: None,
                        ordered_base: materialized.ordered_base(),
                        merge_frontier: materialized.merge_frontier(),
                        input: input.clone(),
                    };
                    let id = entry.id();
                    let error =
                        match prepare_local(&mut store, &mut executor, &materialized, &entry) {
                            Err(error) => error,
                            Ok(_) => panic!("uncommitted refusal prepared a Local publication"),
                        };
                    assert!(
                        AgentJournalStore::get::<LocalEntry>(&store, id)
                            .unwrap()
                            .is_none()
                    );
                    error
                }
                MethodMode::Merge => {
                    let event = MergeEvent {
                        genesis: materialized.heads().genesis,
                        committee: None,
                        author: materialized.heads().node,
                        ordered_base: materialized.ordered_base(),
                        causal_height: 1,
                        parents: Vec::new(),
                        input: input.clone(),
                        signature: vec![0xbb; ED25519_SIGNATURE_BYTES],
                    };
                    let id = event.id();
                    let error = match prepare_merge(
                        &mut store,
                        &mut executor,
                        &NoPrunedOrderedBases,
                        &materialized,
                        &event,
                    ) {
                        Err(error) => error,
                        Ok(_) => panic!("uncommitted refusal prepared a Merge publication"),
                    };
                    assert!(
                        AgentJournalStore::get::<MergeEvent>(&store, id)
                            .unwrap()
                            .is_none()
                    );
                    error
                }
                MethodMode::Query | MethodMode::LinearizableQuery | MethodMode::LocalQuery => {
                    unreachable!()
                }
            };
            assert_eq!(error, ReplayError::UncommittedInvocation(expected));
            assert_eq!(executor.authentications, 1);
            assert_eq!(executor.executions, 1);
            assert_eq!(store.heads().unwrap().unwrap(), heads_before);

            let ReplayOperation::Invoke { invocation, .. } = &input.operation else {
                unreachable!()
            };
            let scope = match mode {
                MethodMode::Linear => InvocationOwnershipScope::Ordered,
                MethodMode::Merge => InvocationOwnershipScope::Merge,
                MethodMode::Local => InvocationOwnershipScope::Local(heads_before.node),
                MethodMode::Query | MethodMode::LinearizableQuery | MethodMode::LocalQuery => {
                    unreachable!()
                }
            };
            let indexes = InvocationIndexes::open(
                &mut store,
                heads_before.ordered_invocations,
                heads_before.merge_invocations,
                heads_before.local_invocations,
            )
            .unwrap();
            assert!(
                InvocationOwnership::lookup(
                    &indexes,
                    InvocationOwnershipKey {
                        scope,
                        invocation: invocation.invocation,
                    },
                )
                .unwrap()
                .is_none()
            );
        }
    }

    #[cfg(feature = "std")]
    #[test]
    fn full_invocation_scope_refuses_the_257th_before_execution_or_cas() {
        for mode in [MethodMode::Linear, MethodMode::Local, MethodMode::Merge] {
            let mut store = initialized_linear_replay_store();
            let mut executor = ExactCreateRejectInvocations::default();
            let mut materialized =
                materialize_current(&mut store, &mut executor, &NoPrunedOrderedBases).unwrap();
            let retained = seed_full_invocation_scope(&mut store, &mut materialized, mode);
            let full_heads = store.heads().unwrap().unwrap();
            assert_eq!(materialized.heads(), &full_heads);

            let fresh = quota_invocation(mode, MAX_INVOCATION_INDEX_LIVE_ENTRIES + 1);
            let executions_before = executor.executions;
            let error = match mode {
                MethodMode::Linear => {
                    let entry = OrderedEntry {
                        genesis: full_heads.genesis,
                        index: full_heads.ordered_index + 1,
                        parent: full_heads.ordered_head,
                        merge_frontier: full_heads.merge_frontier,
                        merge_seal: None,
                        input: fresh,
                    };
                    let id = entry.id();
                    let error =
                        match prepare_ordered(&mut store, &mut executor, &materialized, &entry) {
                            Err(error) => error,
                            Ok(_) => panic!("257th Ordered owner prepared a publication"),
                        };
                    assert!(store.get::<OrderedEntry>(id).unwrap().is_none());
                    error
                }
                MethodMode::Local => {
                    let entry = LocalEntry {
                        genesis: full_heads.genesis,
                        node: full_heads.node,
                        revision: full_heads.local_revision + 1,
                        parent: full_heads.local_head,
                        ordered_base: materialized.ordered_base(),
                        merge_frontier: full_heads.merge_frontier,
                        input: fresh,
                    };
                    let id = entry.id();
                    let error =
                        match prepare_local(&mut store, &mut executor, &materialized, &entry) {
                            Err(error) => error,
                            Ok(_) => panic!("257th Local owner prepared a publication"),
                        };
                    assert!(store.get::<LocalEntry>(id).unwrap().is_none());
                    error
                }
                MethodMode::Merge => {
                    let event = MergeEvent {
                        genesis: full_heads.genesis,
                        committee: None,
                        author: full_heads.node,
                        ordered_base: materialized.ordered_base(),
                        causal_height: 1,
                        parents: Vec::new(),
                        input: fresh,
                        signature: vec![0xde; ED25519_SIGNATURE_BYTES],
                    };
                    let id = event.id();
                    let error = match prepare_merge(
                        &mut store,
                        &mut executor,
                        &NoPrunedOrderedBases,
                        &materialized,
                        &event,
                    ) {
                        Err(error) => error,
                        Ok(_) => panic!("257th Merge owner prepared a publication"),
                    };
                    assert!(store.get::<MergeEvent>(id).unwrap().is_none());
                    error
                }
                MethodMode::Query | MethodMode::LinearizableQuery | MethodMode::LocalQuery => {
                    unreachable!()
                }
            };
            assert_eq!(
                error,
                ReplayError::UncommittedInvocation(ActorExecutionError::ResultCapacity)
            );
            assert_eq!(executor.executions, executions_before);
            assert_eq!(store.heads().unwrap().unwrap(), full_heads);

            // Capacity gates only a genuinely new owner. Exact retained
            // retries and acknowledgements of existing direct outcomes still
            // prepare without guest execution at the ceiling.
            match mode {
                MethodMode::Linear => {
                    let retry = OrderedEntry {
                        genesis: full_heads.genesis,
                        index: full_heads.ordered_index + 1,
                        parent: full_heads.ordered_head,
                        merge_frontier: full_heads.merge_frontier,
                        merge_seal: None,
                        input: retained.clone(),
                    };
                    let prepared =
                        match prepare_ordered(&mut store, &mut executor, &materialized, &retry)
                            .unwrap()
                        {
                            ReplayPreparation::Ready(prepared) => prepared,
                            ReplayPreparation::AlreadyCommitted(_) => unreachable!(),
                        };
                    drop(prepared);
                    let acknowledgement = OrderedEntry {
                        input: admitted_acknowledgement(&retained),
                        ..retry
                    };
                    let prepared = match prepare_ordered(
                        &mut store,
                        &mut executor,
                        &materialized,
                        &acknowledgement,
                    )
                    .unwrap()
                    {
                        ReplayPreparation::Ready(prepared) => prepared,
                        ReplayPreparation::AlreadyCommitted(_) => unreachable!(),
                    };
                    drop(prepared);
                }
                MethodMode::Local => {
                    let retry = LocalEntry {
                        genesis: full_heads.genesis,
                        node: full_heads.node,
                        revision: full_heads.local_revision + 1,
                        parent: full_heads.local_head,
                        ordered_base: materialized.ordered_base(),
                        merge_frontier: full_heads.merge_frontier,
                        input: retained.clone(),
                    };
                    let prepared =
                        match prepare_local(&mut store, &mut executor, &materialized, &retry)
                            .unwrap()
                        {
                            ReplayPreparation::Ready(prepared) => prepared,
                            ReplayPreparation::AlreadyCommitted(_) => unreachable!(),
                        };
                    drop(prepared);
                    let acknowledgement = LocalEntry {
                        input: admitted_acknowledgement(&retained),
                        ..retry
                    };
                    let prepared = match prepare_local(
                        &mut store,
                        &mut executor,
                        &materialized,
                        &acknowledgement,
                    )
                    .unwrap()
                    {
                        ReplayPreparation::Ready(prepared) => prepared,
                        ReplayPreparation::AlreadyCommitted(_) => unreachable!(),
                    };
                    drop(prepared);
                }
                MethodMode::Merge => {}
                MethodMode::Query | MethodMode::LinearizableQuery | MethodMode::LocalQuery => {
                    unreachable!()
                }
            }
            assert_eq!(executor.executions, executions_before);
            assert_eq!(store.heads().unwrap().unwrap(), full_heads);
        }
    }

    #[cfg(feature = "std")]
    #[test]
    fn divergent_recovery_requires_a_reachable_publication() {
        let mut store = initialized_replay_store();
        let mut executor = ExactCreateRejectInvocations::default();
        let base = materialize_current(&mut store, &mut executor, &NoPrunedOrderedBases).unwrap();
        let original = OrderedEntry {
            genesis: base.heads().genesis,
            index: 1,
            parent: None,
            merge_frontier: base.merge_frontier(),
            merge_seal: None,
            input: admitted_invocation(MethodMode::Linear, 0xd3),
        };
        let prepared = match prepare_ordered(&mut store, &mut executor, &base, &original).unwrap() {
            ReplayPreparation::Ready(prepared) => prepared,
            ReplayPreparation::AlreadyCommitted(_) => unreachable!(),
        };
        let (_publication, retained, _) = prepared.publish().unwrap();

        let divergent_input = divergent_invocation_input(&original.input, 0x01);
        let divergent = OrderedEntry {
            genesis: retained.heads().genesis,
            index: 2,
            parent: Some(original.id()),
            merge_frontier: retained.merge_frontier(),
            merge_seal: None,
            input: divergent_input.clone(),
        };
        let prepared =
            match prepare_ordered(&mut store, &mut executor, &retained, &divergent).unwrap() {
                ReplayPreparation::Ready(prepared) => prepared,
                ReplayPreparation::AlreadyCommitted(_) => unreachable!(),
            };
        let (_publication, divergent_head, executions) = prepared.publish().unwrap();
        assert_eq!(executions.len(), 1);
        assert_eq!(
            executions[0].outcome(),
            ReplayStepOutcome::DivergentInvocation
        );
        let divergent_position = ReplayPosition::Ordered {
            id: divergent.id(),
            index: divergent.index,
            merge_frontier: divergent.merge_frontier,
            merge_seal: divergent.merge_seal,
        };
        assert_eq!(
            recover_invocation(
                &mut store,
                &divergent_head,
                &divergent.input,
                divergent_position,
            )
            .unwrap(),
            ReplayInvocationRecovery::Divergent
        );

        // Both a byte-exact duplicate and another mismatching request may be
        // staged as valid objects. Neither crossed the heads CAS, so neither
        // may disclose the authenticated owner's divergent state.
        let exact_orphan = OrderedEntry {
            genesis: divergent_head.heads().genesis,
            index: 3,
            parent: Some(divergent.id()),
            merge_frontier: divergent_head.merge_frontier(),
            merge_seal: None,
            input: divergent_input,
        };
        let mismatched_orphan = OrderedEntry {
            input: divergent_invocation_input(&exact_orphan.input, 0x02),
            ..exact_orphan.clone()
        };
        for orphan in [exact_orphan, mismatched_orphan] {
            store.put(&orphan).unwrap();
            assert_eq!(
                recover_invocation(
                    &mut store,
                    &divergent_head,
                    &orphan.input,
                    ReplayPosition::Ordered {
                        id: orphan.id(),
                        index: orphan.index,
                        merge_frontier: orphan.merge_frontier,
                        merge_seal: orphan.merge_seal,
                    },
                )
                .unwrap(),
                ReplayInvocationRecovery::NotCommitted
            );
        }
    }

    #[cfg(feature = "std")]
    #[test]
    fn checkpoint_gc_preserves_retained_outcome_anchor_recovery() {
        let mut store = initialized_replay_store();
        let mut executor = ExactCreateRejectInvocations::default();
        let mut materialized =
            materialize_current(&mut store, &mut executor, &NoPrunedOrderedBases).unwrap();
        let retained = OrderedEntry {
            genesis: materialized.heads().genesis,
            index: 1,
            parent: None,
            merge_frontier: materialized.merge_frontier(),
            merge_seal: None,
            input: admitted_invocation(MethodMode::Linear, 0xd4),
        };
        for entry in [
            retained.clone(),
            OrderedEntry {
                genesis: materialized.heads().genesis,
                index: 2,
                parent: Some(retained.id()),
                merge_frontier: materialized.merge_frontier(),
                merge_seal: None,
                input: admitted_invocation(MethodMode::Linear, 0xd5),
            },
        ] {
            let prepared =
                match prepare_ordered(&mut store, &mut executor, &materialized, &entry).unwrap() {
                    ReplayPreparation::Ready(prepared) => prepared,
                    ReplayPreparation::AlreadyCommitted(_) => unreachable!(),
                };
            let (_publication, successor, _) = prepared.publish().unwrap();
            materialized = successor;
        }
        assert_ne!(materialized.heads().ordered_head, Some(retained.id()));
        let checkpoint = prepare_checkpoint(&mut store, &materialized).unwrap();
        let (_publication, checkpointed, _) = checkpoint.publish().unwrap();
        let limits = GcLimits {
            max_index_nodes: 10_000,
            max_marked_objects: 10_000,
            max_marked_blobs: 10_000,
            max_scanned_files: 10_000,
            max_scanned_bytes: 64 * 1024 * 1024,
            max_unlinks_per_run: 10_000,
        };
        let gc = store
            .collect_garbage(checkpointed.heads().id(), limits)
            .unwrap();
        assert!(gc.complete);
        let reopened =
            materialize_current(&mut store, &mut executor, &NoPrunedOrderedBases).unwrap();
        assert_eq!(reopened.heads(), checkpointed.heads());
        assert_eq!(
            recover_invocation(
                &mut store,
                &reopened,
                &retained.input,
                ReplayPosition::Ordered {
                    id: retained.id(),
                    index: retained.index,
                    merge_frontier: retained.merge_frontier,
                    merge_seal: retained.merge_seal,
                },
            )
            .unwrap(),
            ReplayInvocationRecovery::Retained(Err(ActorExecutionError::NotFound))
        );
    }

    #[cfg(feature = "std")]
    #[test]
    fn direct_acknowledgement_archives_through_checkpoint_gc_and_frees_the_live_slot() {
        let mut store = initialized_replay_store();
        let mut executor = ExactCreateRejectInvocations::default();
        let base = materialize_current(&mut store, &mut executor, &NoPrunedOrderedBases).unwrap();
        let original = OrderedEntry {
            genesis: base.heads().genesis,
            index: 1,
            parent: None,
            merge_frontier: base.merge_frontier(),
            merge_seal: None,
            input: admitted_invocation(MethodMode::Linear, 0xd6),
        };
        let prepared = match prepare_ordered(&mut store, &mut executor, &base, &original).unwrap() {
            ReplayPreparation::Ready(prepared) => prepared,
            ReplayPreparation::AlreadyCommitted(_) => unreachable!(),
        };
        let (_publication, retained, _) = prepared.publish().unwrap();
        let acknowledgement = OrderedEntry {
            genesis: retained.heads().genesis,
            index: 2,
            parent: Some(original.id()),
            merge_frontier: retained.merge_frontier(),
            merge_seal: None,
            input: admitted_acknowledgement(&original.input),
        };
        let prepared = match prepare_ordered(&mut store, &mut executor, &retained, &acknowledgement)
            .unwrap()
        {
            ReplayPreparation::Ready(prepared) => prepared,
            ReplayPreparation::AlreadyCommitted(_) => unreachable!(),
        };
        let (_publication, acknowledged, _) = prepared.publish().unwrap();

        let mut reopened =
            materialize_current(&mut store, &mut executor, &NoPrunedOrderedBases).unwrap();
        assert_eq!(reopened.heads(), acknowledged.heads());
        let key = InvocationOwnershipKey {
            scope: InvocationOwnershipScope::Ordered,
            invocation: InvocationId([0xd6; 32]),
        };
        {
            let indexes = InvocationIndexes::open(
                &mut store,
                reopened.heads().ordered_invocations,
                reopened.heads().merge_invocations,
                reopened.heads().local_invocations,
            )
            .unwrap();
            let manifest = indexes.manifest(InvocationOwnershipScope::Ordered).unwrap();
            assert_eq!(manifest.entries, 0);
            assert!(manifest.history_root.is_some());
            let Some(InvocationIndexLookup::Archived(fact)) =
                InvocationOwnership::lookup(&indexes, key).unwrap()
            else {
                panic!("acknowledgement did not move the owner into history")
            };
            assert_eq!(
                fact.request_commitment(),
                invocation_identity(&original.input).unwrap().1
            );
        }
        for (input, entry) in [
            (&original.input, &original),
            (&acknowledgement.input, &acknowledgement),
        ] {
            assert_eq!(
                recover_invocation(
                    &mut store,
                    &reopened,
                    input,
                    ReplayPosition::Ordered {
                        id: entry.id(),
                        index: entry.index,
                        merge_frontier: entry.merge_frontier,
                        merge_seal: entry.merge_seal,
                    },
                )
                .unwrap(),
                ReplayInvocationRecovery::Acknowledged
            );
        }

        let checkpoint = prepare_checkpoint(&mut store, &reopened).unwrap();
        let (_publication, checkpointed, _) = checkpoint.publish().unwrap();
        let limits = GcLimits {
            max_index_nodes: 10_000,
            max_marked_objects: 10_000,
            max_marked_blobs: 10_000,
            max_scanned_files: 10_000,
            max_scanned_bytes: 64 * 1024 * 1024,
            max_unlinks_per_run: 10_000,
        };
        while !store
            .collect_garbage(checkpointed.heads().id(), limits)
            .unwrap()
            .complete
        {}
        reopened = materialize_current(&mut store, &mut executor, &NoPrunedOrderedBases).unwrap();

        let executions_before_retry = executor.executions;
        let exact_retry = OrderedEntry {
            genesis: reopened.heads().genesis,
            index: reopened.heads().ordered_index + 1,
            parent: reopened.heads().ordered_head,
            merge_frontier: reopened.merge_frontier(),
            merge_seal: None,
            input: original.input.clone(),
        };
        let prepared =
            match prepare_ordered(&mut store, &mut executor, &reopened, &exact_retry).unwrap() {
                ReplayPreparation::Ready(prepared) => prepared,
                ReplayPreparation::AlreadyCommitted(_) => unreachable!(),
            };
        let (_publication, exact_successor, executions) = prepared.publish().unwrap();
        assert_eq!(executor.executions, executions_before_retry);
        assert_eq!(executions.len(), 1);
        assert_eq!(executions[0].outcome(), ReplayStepOutcome::ExactDuplicate);
        assert_eq!(
            recover_invocation(
                &mut store,
                &exact_successor,
                &exact_retry.input,
                ReplayPosition::Ordered {
                    id: exact_retry.id(),
                    index: exact_retry.index,
                    merge_frontier: exact_retry.merge_frontier,
                    merge_seal: exact_retry.merge_seal,
                },
            )
            .unwrap(),
            ReplayInvocationRecovery::Acknowledged
        );

        let divergent = OrderedEntry {
            genesis: exact_successor.heads().genesis,
            index: exact_successor.heads().ordered_index + 1,
            parent: exact_successor.heads().ordered_head,
            merge_frontier: exact_successor.merge_frontier(),
            merge_seal: None,
            input: divergent_invocation_input(&original.input, 0x01),
        };
        let prepared =
            match prepare_ordered(&mut store, &mut executor, &exact_successor, &divergent).unwrap()
            {
                ReplayPreparation::Ready(prepared) => prepared,
                ReplayPreparation::AlreadyCommitted(_) => unreachable!(),
            };
        let (_publication, divergent_successor, executions) = prepared.publish().unwrap();
        assert_eq!(executor.executions, executions_before_retry);
        assert_eq!(executions.len(), 1);
        assert_eq!(
            executions[0].outcome(),
            ReplayStepOutcome::DivergentInvocation
        );

        let fresh = OrderedEntry {
            genesis: divergent_successor.heads().genesis,
            index: divergent_successor.heads().ordered_index + 1,
            parent: divergent_successor.heads().ordered_head,
            merge_frontier: divergent_successor.merge_frontier(),
            merge_seal: None,
            input: admitted_invocation(MethodMode::Linear, 0xd7),
        };
        let prepared =
            match prepare_ordered(&mut store, &mut executor, &divergent_successor, &fresh).unwrap()
            {
                ReplayPreparation::Ready(prepared) => prepared,
                ReplayPreparation::AlreadyCommitted(_) => unreachable!(),
            };
        let (_publication, fresh_successor, _) = prepared.publish().unwrap();
        let indexes = InvocationIndexes::open(
            &mut store,
            fresh_successor.heads().ordered_invocations,
            fresh_successor.heads().merge_invocations,
            fresh_successor.heads().local_invocations,
        )
        .unwrap();
        assert_eq!(
            indexes
                .manifest(InvocationOwnershipScope::Ordered)
                .unwrap()
                .entries,
            1
        );
        assert!(matches!(
            InvocationOwnership::lookup(&indexes, key).unwrap(),
            Some(InvocationIndexLookup::Archived(_))
        ));
    }

    #[cfg(feature = "std")]
    #[test]
    fn prepare_publish_reopen_and_response_loss_retry_are_exact() {
        let mut store = initialized_replay_store();
        let mut executor = ExactCreateRejectInvocations::default();
        let mut materialized =
            materialize_current(&mut store, &mut executor, &NoPrunedOrderedBases).unwrap();
        let empty_frontier = materialized.merge_frontier();

        let ordered = OrderedEntry {
            genesis: materialized.heads().genesis,
            index: 1,
            parent: None,
            merge_frontier: empty_frontier,
            merge_seal: None,
            input: admitted_invocation(MethodMode::Linear, 0xd1),
        };
        let prepared = match prepare_ordered(&mut store, &mut executor, &materialized, &ordered)
            .unwrap()
        {
            ReplayPreparation::Ready(prepared) => prepared,
            ReplayPreparation::AlreadyCommitted(_) => panic!("fresh ordered input was committed"),
        };
        let (_publication, _lost_successor, published_execution) = prepared.publish().unwrap();
        assert_eq!(published_execution.len(), 1);
        assert_eq!(
            published_execution[0].outcome(),
            ReplayStepOutcome::Applied(ReplayDisposition::Rejected)
        );
        assert_eq!(
            published_execution[0].result(),
            Some(&Err(ActorExecutionError::NotFound))
        );
        assert!(published_execution[0].products().is_empty());
        assert_eq!(published_execution[0].input(), ordered.input.id());

        // Simulate loss of the publication response: reopen from durable
        // heads, then recover the exact committed input without executing it.
        materialized =
            materialize_current(&mut store, &mut executor, &NoPrunedOrderedBases).unwrap();
        let executions_before_retry = executor.executions;
        let retry = prepare_ordered(&mut store, &mut executor, &materialized, &ordered).unwrap();
        let recovery = match retry {
            ReplayPreparation::AlreadyCommitted(recovery) => recovery,
            ReplayPreparation::Ready(_) => panic!("exact retry prepared a second transition"),
        };
        assert_eq!(recovery.input(), ordered.input.id());
        assert!(matches!(
            recovery.position(),
            ReplayPosition::Ordered { id, index: 1, .. } if id == ordered.id()
        ));
        assert_eq!(executor.executions, executions_before_retry);
        let recovery_position = recovery.position();
        assert_eq!(
            recover_invocation(&mut store, &materialized, &ordered.input, recovery_position,)
                .unwrap(),
            ReplayInvocationRecovery::Retained(Err(ActorExecutionError::NotFound))
        );
        assert_eq!(executor.executions, executions_before_retry);

        // Supplying the complete request is not authorization to disclose
        // its retained result. The receipt is authenticated against the
        // exact committed position before the ownership index is consulted.
        let mut forged = ordered.input.clone();
        let ReplayOperation::Invoke { authority, .. } = &mut forged.operation else {
            unreachable!();
        };
        authority.signature[0] = 0x56;
        assert_eq!(
            recover_invocation(&mut store, &materialized, &forged, recovery_position,).unwrap(),
            ReplayInvocationRecovery::NotCommitted
        );

        // Checkpoint compaction retains the authenticated outcome/index and
        // its content-addressed anchor, but only the checkpoint's current
        // ordered snapshot. Response recovery therefore must not depend on
        // resolving the source entry's historical pre-state.
        let checkpoint = prepare_checkpoint(&mut store, &materialized).unwrap();
        checkpoint.publish().unwrap();
        materialized =
            materialize_current(&mut store, &mut executor, &NoPrunedOrderedBases).unwrap();
        assert_eq!(materialized.ordered_snapshots.len(), 1);
        assert_eq!(
            recover_invocation(&mut store, &materialized, &ordered.input, recovery_position,)
                .unwrap(),
            ReplayInvocationRecovery::Retained(Err(ActorExecutionError::NotFound))
        );

        // Merely prewriting another valid content-addressed entry containing
        // the same authenticated input does not make it a disclosure anchor.
        // It is neither the outcome's permanent anchor nor part of the
        // authenticated post-checkpoint suffix.
        let orphan = OrderedEntry {
            genesis: materialized.heads().genesis,
            index: 2,
            parent: Some(ordered.id()),
            merge_frontier: materialized.merge_frontier(),
            merge_seal: None,
            input: ordered.input.clone(),
        };
        store.put(&orphan).unwrap();
        assert_eq!(
            recover_invocation(
                &mut store,
                &materialized,
                &orphan.input,
                ReplayPosition::Ordered {
                    id: orphan.id(),
                    index: orphan.index,
                    merge_frontier: orphan.merge_frontier,
                    merge_seal: orphan.merge_seal,
                },
            )
            .unwrap(),
            ReplayInvocationRecovery::NotCommitted
        );

        let local = LocalEntry {
            genesis: materialized.heads().genesis,
            node: materialized.heads().node,
            revision: 1,
            parent: None,
            ordered_base: materialized.ordered_base(),
            merge_frontier: materialized.merge_frontier(),
            input: admitted_invocation(MethodMode::Local, 0xd1),
        };
        let prepared =
            match prepare_local(&mut store, &mut executor, &materialized, &local).unwrap() {
                ReplayPreparation::Ready(prepared) => prepared,
                ReplayPreparation::AlreadyCommitted(_) => panic!("fresh Local input was committed"),
            };
        let (_publication, successor, _) = prepared.publish().unwrap();
        materialized = successor;

        let merge = MergeEvent {
            genesis: materialized.heads().genesis,
            committee: None,
            author: materialized.heads().node,
            ordered_base: materialized.ordered_base(),
            causal_height: 1,
            parents: Vec::new(),
            input: admitted_invocation(MethodMode::Merge, 0xd1),
            signature: vec![0xd2; ED25519_SIGNATURE_BYTES],
        };
        let prepared = match prepare_merge(
            &mut store,
            &mut executor,
            &NoPrunedOrderedBases,
            &materialized,
            &merge,
        )
        .unwrap()
        {
            ReplayPreparation::Ready(prepared) => prepared,
            ReplayPreparation::AlreadyCommitted(_) => panic!("fresh Merge input was committed"),
        };
        let (_publication, _successor, _) = prepared.publish().unwrap();
        materialized =
            materialize_current(&mut store, &mut executor, &NoPrunedOrderedBases).unwrap();
        assert_eq!(materialized.heads().ordered_head, Some(ordered.id()));
        assert_eq!(materialized.heads().local_head, Some(local.id()));
        assert!(materialized.merge_ancestry.contains(&merge.id()));

        // The same InvocationId is independently owned in all three scopes.
        let heads = materialized.heads().clone();
        let indexes = InvocationIndexes::open(
            &mut store,
            heads.ordered_invocations,
            heads.merge_invocations,
            heads.local_invocations,
        )
        .unwrap();
        for scope in [
            InvocationOwnershipScope::Ordered,
            InvocationOwnershipScope::Merge,
            InvocationOwnershipScope::Local(heads.node),
        ] {
            let lookup = InvocationOwnership::lookup(
                &indexes,
                InvocationOwnershipKey {
                    scope,
                    invocation: InvocationId([0xd1; 32]),
                },
            )
            .unwrap()
            .unwrap();
            let InvocationIndexLookup::Live(owner) = lookup else {
                panic!("fresh scope owner must remain live");
            };
            assert_eq!(owner.scope, scope);
            match scope {
                InvocationOwnershipScope::Merge => assert!(matches!(
                    owner.result_state,
                    InvocationResultState::PendingMerge { source_event }
                        if source_event == merge.id()
                )),
                InvocationOwnershipScope::Ordered | InvocationOwnershipScope::Local(_) => {
                    assert!(matches!(
                        owner.result_state,
                        InvocationResultState::Retained {
                            disposition: InvocationDisposition::Rejected,
                            ..
                        }
                    ));
                    assert_eq!(owner.disposition(), Some(InvocationDisposition::Rejected));
                }
            }
        }
        drop(indexes);

        // Publication APIs fail closed rather than executing against bytes
        // from an older pinned Merge snapshot.
        let executions_before_bad_pins = executor.executions;
        let stale_local = LocalEntry {
            genesis: heads.genesis,
            node: heads.node,
            revision: 2,
            parent: heads.local_head,
            ordered_base: materialized.ordered_base(),
            merge_frontier: empty_frontier,
            input: admitted_invocation(MethodMode::Local, 0xd3),
        };
        assert!(matches!(
            prepare_local(&mut store, &mut executor, &materialized, &stale_local),
            Err(ReplayError::InvalidRecord)
        ));
        let stale_ordered = OrderedEntry {
            genesis: heads.genesis,
            index: heads.ordered_index + 1,
            parent: heads.ordered_head,
            merge_frontier: empty_frontier,
            merge_seal: None,
            input: admitted_invocation(MethodMode::Linear, 0xd4),
        };
        assert!(matches!(
            prepare_ordered(&mut store, &mut executor, &materialized, &stale_ordered),
            Err(ReplayError::InvalidRecord)
        ));
        assert_eq!(executor.executions, executions_before_bad_pins);
    }

    #[cfg(feature = "std")]
    #[test]
    fn dropped_store_bound_session_cannot_publish_its_staged_ownership_root() {
        let mut store = initialized_replay_store();
        let mut executor = ExactCreateRejectInvocations::default();
        let base = materialize_current(&mut store, &mut executor, &NoPrunedOrderedBases).unwrap();
        let make_entry = |discriminator| OrderedEntry {
            genesis: base.heads().genesis,
            index: 1,
            parent: None,
            merge_frontier: base.merge_frontier(),
            merge_seal: None,
            input: admitted_invocation(MethodMode::Linear, discriminator),
        };
        let losing_entry = make_entry(0xe1);
        let winning_entry = make_entry(0xe2);
        let losing = match prepare_ordered(&mut store, &mut executor, &base, &losing_entry).unwrap()
        {
            ReplayPreparation::Ready(prepared) => prepared,
            ReplayPreparation::AlreadyCommitted(_) => unreachable!(),
        };
        // Dropping the exclusive session releases the store without making
        // its prewritten candidate path reachable from durable heads.
        drop(losing);
        let winning =
            match prepare_ordered(&mut store, &mut executor, &base, &winning_entry).unwrap() {
                ReplayPreparation::Ready(prepared) => prepared,
                ReplayPreparation::AlreadyCommitted(_) => unreachable!(),
            };
        let (_publication, winning_state, _) = winning.publish().unwrap();
        let durable_after_winner = store.heads().unwrap().unwrap();
        assert_eq!(durable_after_winner, *winning_state.heads());

        let reopened =
            materialize_current(&mut store, &mut executor, &NoPrunedOrderedBases).unwrap();
        assert_eq!(reopened.heads(), &durable_after_winner);
        let heads = reopened.heads().clone();
        let indexes = InvocationIndexes::open(
            &mut store,
            heads.ordered_invocations,
            heads.merge_invocations,
            heads.local_invocations,
        )
        .unwrap();
        assert!(
            InvocationOwnership::lookup(
                &indexes,
                InvocationOwnershipKey {
                    scope: InvocationOwnershipScope::Ordered,
                    invocation: InvocationId([0xe1; 32]),
                },
            )
            .unwrap()
            .is_none()
        );
        assert!(
            InvocationOwnership::lookup(
                &indexes,
                InvocationOwnershipKey {
                    scope: InvocationOwnershipScope::Ordered,
                    invocation: InvocationId([0xe2; 32]),
                },
            )
            .unwrap()
            .is_some()
        );
    }

    #[cfg(feature = "std")]
    #[test]
    fn merge_reorder_seal_and_pending_acknowledgement_are_exact() {
        let mut store = initialized_replay_store();
        let mut executor = ExactCreateRejectInvocations::default();
        let base = materialize_current(&mut store, &mut executor, &NoPrunedOrderedBases).unwrap();
        let event = |discriminator| MergeEvent {
            genesis: base.heads().genesis,
            committee: None,
            author: base.heads().node,
            ordered_base: base.ordered_base(),
            causal_height: 1,
            parents: Vec::new(),
            input: admitted_invocation(MethodMode::Merge, discriminator),
            signature: vec![discriminator; ED25519_SIGNATURE_BYTES],
        };
        let left = event(0xf1);
        let right = event(0xf2);
        let expected_finalized_inputs = vec![left.input.id(), right.input.id()];
        let acknowledged_source = left.clone();
        let (first_event, second_event) = if left.id() > right.id() {
            (left, right)
        } else {
            (right, left)
        };

        let first = match prepare_merge(
            &mut store,
            &mut executor,
            &NoPrunedOrderedBases,
            &base,
            &first_event,
        )
        .unwrap()
        {
            ReplayPreparation::Ready(prepared) => prepared,
            ReplayPreparation::AlreadyCommitted(_) => unreachable!(),
        };
        let (_publication, after_first, first_results) = first.publish().unwrap();
        assert!(first_results.is_empty());
        executor.merge_execution_order.clear();

        let second_id = second_event.id();
        let first_id = after_first.merge_roots[0].id;
        assert!(second_id < first_id);
        let second = match prepare_merge(
            &mut store,
            &mut executor,
            &NoPrunedOrderedBases,
            &after_first,
            &second_event,
        )
        .unwrap()
        {
            ReplayPreparation::Ready(prepared) => prepared,
            ReplayPreparation::AlreadyCommitted(_) => unreachable!(),
        };
        assert_eq!(executor.merge_execution_order, vec![second_id, first_id]);
        let (_publication, successor, second_results) = second.publish().unwrap();
        assert!(second_results.is_empty());
        let mut reopened =
            materialize_current(&mut store, &mut executor, &NoPrunedOrderedBases).unwrap();
        assert_eq!(reopened.heads(), successor.heads());
        assert_eq!(
            reopened
                .merge_roots
                .iter()
                .map(|root| root.id)
                .collect::<Vec<_>>(),
            vec![second_id, first_id]
        );

        let source_position = ReplayPosition::Merge {
            id: acknowledged_source.id(),
            causal_height: acknowledged_source.causal_height,
            ordered_base: acknowledged_source.ordered_base,
        };
        assert_eq!(
            recover_invocation(
                &mut store,
                &reopened,
                &acknowledged_source.input,
                source_position,
            )
            .unwrap(),
            ReplayInvocationRecovery::Pending
        );
        let exact_source_orphan = MergeEvent {
            signature: vec![0xf5; ED25519_SIGNATURE_BYTES],
            ..acknowledged_source.clone()
        };
        let mismatched_source_orphan = MergeEvent {
            input: divergent_invocation_input(&acknowledged_source.input, 0x01),
            signature: vec![0xf6; ED25519_SIGNATURE_BYTES],
            ..acknowledged_source.clone()
        };
        let source_orphans = [exact_source_orphan, mismatched_source_orphan];
        for orphan in &source_orphans {
            store.put(orphan).unwrap();
            assert_eq!(
                recover_invocation(&mut store, &reopened, &orphan.input, merge_position(orphan),)
                    .unwrap(),
                ReplayInvocationRecovery::NotCommitted
            );
        }
        assert!(prepare_checkpoint(&mut store, &reopened).is_err());

        // The ordered fence is the sole publication boundary for every
        // provisional Merge result. It rebuilds the complete suffix, writes
        // outcomes first, then installs one deterministic ownership batch.
        let first_seal = persist_merge_seal(&mut store, &reopened);
        let first_fence = OrderedEntry {
            genesis: reopened.heads().genesis,
            index: 1,
            parent: None,
            merge_frontier: reopened.merge_frontier(),
            merge_seal: Some(first_seal),
            input: ReplayInput {
                runtime: reopened.runtime().clone(),
                operation: ReplayOperation::SealMerge,
            },
        };
        let prepared =
            match prepare_ordered(&mut store, &mut executor, &reopened, &first_fence).unwrap() {
                ReplayPreparation::Ready(prepared) => prepared,
                ReplayPreparation::AlreadyCommitted(_) => unreachable!(),
            };
        let (_publication, after_first_seal, finalized) = prepared.publish().unwrap();
        assert_eq!(finalized.len(), 3);
        assert!(finalized[0].result().is_none());
        assert_eq!(
            finalized[1..]
                .iter()
                .map(ReplayExecutionResult::input)
                .collect::<Vec<_>>(),
            expected_finalized_inputs
        );
        assert!(
            finalized[1..].iter().all(|execution| {
                execution.result() == Some(&Err(ActorExecutionError::NotFound))
            })
        );
        reopened = materialize_current(&mut store, &mut executor, &NoPrunedOrderedBases).unwrap();
        assert_eq!(reopened.heads(), after_first_seal.heads());
        assert_eq!(
            recover_invocation(
                &mut store,
                &reopened,
                &acknowledged_source.input,
                source_position,
            )
            .unwrap(),
            ReplayInvocationRecovery::Retained(Err(ActorExecutionError::NotFound))
        );

        let mut parents = vec![first_id, second_id];
        parents.sort_unstable();
        let acknowledgement = MergeEvent {
            genesis: reopened.heads().genesis,
            committee: None,
            author: reopened.heads().node,
            ordered_base: reopened.ordered_base(),
            causal_height: 2,
            parents,
            input: admitted_acknowledgement(&acknowledged_source.input),
            signature: vec![0xf4; ED25519_SIGNATURE_BYTES],
        };
        let acknowledgement_position = ReplayPosition::Merge {
            id: acknowledgement.id(),
            causal_height: acknowledgement.causal_height,
            ordered_base: acknowledgement.ordered_base,
        };
        let exact_acknowledgement_orphan = MergeEvent {
            signature: vec![0xf7; ED25519_SIGNATURE_BYTES],
            ..acknowledgement.clone()
        };
        let mismatched_acknowledgement_orphan = MergeEvent {
            input: divergent_invocation_input(&acknowledgement.input, 0x02),
            signature: vec![0xf8; ED25519_SIGNATURE_BYTES],
            ..acknowledgement.clone()
        };
        let acknowledgement_orphans = [
            exact_acknowledgement_orphan,
            mismatched_acknowledgement_orphan,
        ];
        for orphan in &acknowledgement_orphans {
            store.put(orphan).unwrap();
        }
        let prepared = match prepare_merge(
            &mut store,
            &mut executor,
            &NoPrunedOrderedBases,
            &reopened,
            &acknowledgement,
        )
        .unwrap()
        {
            ReplayPreparation::Ready(prepared) => prepared,
            ReplayPreparation::AlreadyCommitted(_) => unreachable!(),
        };
        let (_publication, after_ack, pending_results) = prepared.publish().unwrap();
        assert!(pending_results.is_empty());
        reopened = materialize_current(&mut store, &mut executor, &NoPrunedOrderedBases).unwrap();
        assert_eq!(reopened.heads(), after_ack.heads());
        assert_eq!(
            recover_invocation(
                &mut store,
                &reopened,
                &acknowledgement.input,
                acknowledgement_position,
            )
            .unwrap(),
            ReplayInvocationRecovery::Pending
        );
        for orphan in source_orphans.iter().chain(&acknowledgement_orphans) {
            assert_eq!(
                recover_invocation(&mut store, &reopened, &orphan.input, merge_position(orphan),)
                    .unwrap(),
                ReplayInvocationRecovery::NotCommitted
            );
        }
        assert_eq!(
            recover_invocation(
                &mut store,
                &reopened,
                &acknowledged_source.input,
                source_position,
            )
            .unwrap(),
            ReplayInvocationRecovery::Pending
        );

        let second_seal = persist_merge_seal(&mut store, &reopened);
        let second_fence = OrderedEntry {
            genesis: reopened.heads().genesis,
            index: 2,
            parent: reopened.heads().ordered_head,
            merge_frontier: reopened.merge_frontier(),
            merge_seal: Some(second_seal),
            input: ReplayInput {
                runtime: reopened.runtime().clone(),
                operation: ReplayOperation::SealMerge,
            },
        };
        let prepared =
            match prepare_ordered(&mut store, &mut executor, &reopened, &second_fence).unwrap() {
                ReplayPreparation::Ready(prepared) => prepared,
                ReplayPreparation::AlreadyCommitted(_) => unreachable!(),
            };
        let (_publication, acknowledged, final_ack_results) = prepared.publish().unwrap();
        // Ack finalization changes only the authenticated owner leaf; it
        // never republishes the application result.
        assert_eq!(final_ack_results.len(), 1);
        assert!(final_ack_results[0].result().is_none());
        reopened = materialize_current(&mut store, &mut executor, &NoPrunedOrderedBases).unwrap();
        assert_eq!(reopened.heads(), acknowledged.heads());
        for (input, position) in [
            (&acknowledged_source.input, source_position),
            (&acknowledgement.input, acknowledgement_position),
        ] {
            assert_eq!(
                recover_invocation(&mut store, &reopened, input, position,).unwrap(),
                ReplayInvocationRecovery::Acknowledged
            );
        }
        for orphan in source_orphans.iter().chain(&acknowledgement_orphans) {
            assert_eq!(
                recover_invocation(&mut store, &reopened, &orphan.input, merge_position(orphan),)
                    .unwrap(),
                ReplayInvocationRecovery::NotCommitted
            );
        }

        // Seal-only entries are a progress mechanism for pending Merge work,
        // not a way to advance ordered history with repeated empty fences.
        let empty_seal = persist_merge_seal(&mut store, &reopened);
        let empty_fence = OrderedEntry {
            genesis: reopened.heads().genesis,
            index: 3,
            parent: reopened.heads().ordered_head,
            merge_frontier: reopened.merge_frontier(),
            merge_seal: Some(empty_seal),
            input: ReplayInput {
                runtime: reopened.runtime().clone(),
                operation: ReplayOperation::SealMerge,
            },
        };
        assert!(matches!(
            prepare_ordered(&mut store, &mut executor, &reopened, &empty_fence),
            Err(ReplayError::InvalidFence)
        ));
        let checkpoint = prepare_checkpoint(&mut store, &reopened).unwrap();
        checkpoint.publish().unwrap();
    }

    #[cfg(feature = "std")]
    #[test]
    fn canonical_checkpoint_rejects_shared_profile_without_snapshot_certificate() {
        let mut store = initialized_shared_replay_store();
        let mut executor = ExactCreateRejectInvocations::default();
        let materialized =
            materialize_current(&mut store, &mut executor, &NoPrunedOrderedBases).unwrap();
        let heads = store.heads().unwrap().unwrap();

        assert!(matches!(
            prepare_checkpoint(&mut store, &materialized),
            Err(ReplayError::InvalidRecord)
        ));
        assert_eq!(store.heads().unwrap().unwrap(), heads);
    }

    #[cfg(all(feature = "std", feature = "storage"))]
    #[test]
    fn shared_reservation_rejects_byte_identical_memory_store_transplant() {
        let mut authorized = initialized_shared_replay_store();
        let mut transplant = authorized.clone();
        assert_ne!(authorized.instance_id(), transplant.instance_id());

        let mut authorized_executor = ExactCreateRejectInvocations::default();
        let mut transplant_executor = ExactCreateRejectInvocations::default();
        let authorized_state = materialize_current(
            &mut authorized,
            &mut authorized_executor,
            &NoPrunedOrderedBases,
        )
        .unwrap();
        let transplant_state = materialize_current(
            &mut transplant,
            &mut transplant_executor,
            &NoPrunedOrderedBases,
        )
        .unwrap();
        assert_eq!(authorized_state, transplant_state);

        let entry = OrderedEntry {
            genesis: authorized_state.heads().genesis,
            index: 1,
            parent: None,
            merge_frontier: authorized_state.merge_frontier(),
            merge_seal: None,
            input: admitted_invocation(MethodMode::Linear, 0x6f),
        };
        let committed =
            committed_shared_for_test(entry, &authorized_state, authorized.instance_id()).unwrap();
        let transplant_heads = transplant.heads().unwrap().unwrap();
        assert!(matches!(
            prepare_shared_ordered(
                &mut transplant,
                &mut transplant_executor,
                &NoPrunedOrderedBases,
                &transplant_state,
                committed,
            ),
            Err(ReplayError::InvalidRecord)
        ));
        assert_eq!(transplant.heads().unwrap().unwrap(), transplant_heads);
    }

    #[cfg(feature = "std")]
    #[test]
    fn shared_replay_rejects_ordered_artifact_batch_without_publication_receipt() {
        let mut store = initialized_shared_replay_store();
        let mut executor = ExactCreateRejectInvocations::default();
        let materialized =
            materialize_current(&mut store, &mut executor, &NoPrunedOrderedBases).unwrap();
        let heads = store.heads().unwrap().unwrap();
        let entry = OrderedEntry {
            genesis: heads.genesis,
            index: 1,
            parent: None,
            merge_frontier: heads.merge_frontier,
            merge_seal: None,
            input: admitted_invocation(MethodMode::Linear, 0x70),
        };
        let (committee, _) = shared_test_committee(&entry.input.runtime);
        let route = AgentRouteKey::new(
            entry.input.runtime.space,
            entry.input.runtime.agent,
            entry.genesis,
            heads.admission,
            committee.id(),
        )
        .unwrap();
        let command = AgentRaftCommand::Ordered {
            route,
            artifact_batch: Some(ArtifactBatchId::from_bytes([0xa7; 32])),
            entry,
        };
        let witness = TestCommittedRaftLog {
            index: 1,
            term: 1,
            payload: command.encode(),
        };
        let committed = CommittedAgentRaftEntry::from_durable_log(&witness, 1).unwrap();
        let reserved = ReservedAgentRaftApplication::reserved_for_test(
            committed,
            heads.node,
            store.instance_id(),
        );
        assert!(matches!(
            CommittedSharedOrdered::from_reserved_raft_application(
                reserved,
                &committee,
                #[cfg(feature = "storage")]
                None,
            ),
            Err(ReplayError::InvalidRecord)
        ));
        assert_eq!(store.heads().unwrap().unwrap(), heads);
        assert_eq!(materialized.heads(), &heads);
    }

    #[cfg(all(feature = "std", feature = "storage"))]
    #[test]
    fn shared_ordered_pinned_projection_preserves_each_replica_active_merge() {
        let initial = initialized_shared_replay_store();
        let mut oracle_store = initial.clone();
        let mut left_store = initial.clone();
        let mut right_store = initial;
        let mut oracle_executor = ExactCreateRejectInvocations::default();
        let mut left_executor = ExactCreateRejectInvocations::default();
        let mut right_executor = ExactCreateRejectInvocations::default();
        let oracle_base = materialize_current(
            &mut oracle_store,
            &mut oracle_executor,
            &NoPrunedOrderedBases,
        )
        .unwrap();
        let left_base =
            materialize_current(&mut left_store, &mut left_executor, &NoPrunedOrderedBases)
                .unwrap();
        let right_base =
            materialize_current(&mut right_store, &mut right_executor, &NoPrunedOrderedBases)
                .unwrap();
        assert_eq!(left_base.heads(), right_base.heads());

        let event = |discriminator| MergeEvent {
            genesis: left_base.heads().genesis,
            committee: None,
            author: left_base.heads().node,
            ordered_base: left_base.ordered_base(),
            causal_height: 1,
            parents: Vec::new(),
            input: admitted_invocation(MethodMode::Merge, discriminator),
            signature: vec![discriminator; ED25519_SIGNATURE_BYTES],
        };
        let pinned_event = event(0x71);
        let left_active_event = event(0x72);
        let right_active_event = event(0x73);
        let pinned_frontier = MergeFrontier {
            genesis: left_base.heads().genesis,
            events: vec![pinned_event.id()],
        };
        for store in [&mut left_store, &mut right_store] {
            store.put(&pinned_event).unwrap();
            store.put(&pinned_frontier).unwrap();
        }
        let pinned_projection = publish_test_merge(
            &mut oracle_store,
            &mut oracle_executor,
            &oracle_base,
            &pinned_event,
        );
        assert_eq!(pinned_projection.merge_frontier(), pinned_frontier.id());
        let left_active = publish_test_merge(
            &mut left_store,
            &mut left_executor,
            &left_base,
            &left_active_event,
        );
        let right_active = publish_test_merge(
            &mut right_store,
            &mut right_executor,
            &right_base,
            &right_active_event,
        );
        assert_ne!(left_active.merge_frontier(), pinned_frontier.id());
        assert_ne!(right_active.merge_frontier(), pinned_frontier.id());
        let left_merge_before = left_active.state().merge.clone();
        let right_merge_before = right_active.state().merge.clone();
        let left_local_before = (
            left_active.state().local.clone(),
            left_active.heads().local_head,
            left_active.heads().local_revision,
            left_active.heads().local_invocations,
            left_active.heads().checkpoint,
        );
        let right_local_before = (
            right_active.state().local.clone(),
            right_active.heads().local_head,
            right_active.heads().local_revision,
            right_active.heads().local_invocations,
            right_active.heads().checkpoint,
        );

        let entry = OrderedEntry {
            genesis: left_active.heads().genesis,
            index: 1,
            parent: None,
            merge_frontier: pinned_frontier.id(),
            merge_seal: None,
            input: admitted_invocation(MethodMode::Linear, 0x74),
        };
        let expected = match prepare_ordered(
            &mut oracle_store,
            &mut oracle_executor,
            &pinned_projection,
            &entry,
        )
        .unwrap()
        {
            ReplayPreparation::Ready(prepared) => prepared,
            ReplayPreparation::AlreadyCommitted(_) => unreachable!(),
        };
        let (_, expected_successor, _) = expected.publish().unwrap();
        let (committee, committee_keys) = shared_test_committee(&entry.input.runtime);
        let expected_claim = shared_claim_for_test(
            committee.id(),
            &entry,
            &pinned_projection,
            &expected_successor,
            SharedClaimTamper::None,
        );
        let committed_left =
            committed_shared_for_test(entry.clone(), &left_active, left_store.instance_id())
                .unwrap();
        let left = match prepare_shared_ordered(
            &mut left_store,
            &mut left_executor,
            &NoPrunedOrderedBases,
            &left_active,
            committed_left,
        )
        .unwrap()
        {
            SharedReplayPreparation::Ready(prepared) => prepared,
            SharedReplayPreparation::AlreadyCommitted { .. } => unreachable!(),
        };
        let (_, left_successor, _, left_receipt) = left.publish_shared().unwrap();
        let committed_right =
            committed_shared_for_test(entry.clone(), &right_active, right_store.instance_id())
                .unwrap();
        let right = match prepare_shared_ordered(
            &mut right_store,
            &mut right_executor,
            &NoPrunedOrderedBases,
            &right_active,
            committed_right,
        )
        .unwrap()
        {
            SharedReplayPreparation::Ready(prepared) => prepared,
            SharedReplayPreparation::AlreadyCommitted { .. } => unreachable!(),
        };
        let (_, right_successor, _, right_receipt) = right.publish_shared().unwrap();
        assert_eq!(left_receipt.claim(), right_receipt.claim());
        assert_eq!(left_receipt.claim(), &expected_claim);

        let exact_certificate =
            shared_qc_for_test(&committee, &committee_keys, left_receipt.claim().clone());
        exact_certificate
            .verify(&committee, left_receipt.claim())
            .unwrap();
        for tamper in [
            SharedClaimTamper::Admission,
            SharedClaimTamper::MergeProjection,
            SharedClaimTamper::MergeInvocations,
            SharedClaimTamper::Runtime,
            SharedClaimTamper::Control,
            SharedClaimTamper::Linear,
            SharedClaimTamper::OrderedInvocations,
            SharedClaimTamper::Artifacts,
            SharedClaimTamper::FenceAncestry,
        ] {
            let tampered = shared_claim_for_test(
                committee.id(),
                &entry,
                &pinned_projection,
                &expected_successor,
                tamper,
            );
            let certificate = shared_qc_for_test(&committee, &committee_keys, tampered.clone());
            certificate.verify(&committee, &tampered).unwrap();
            assert!(
                certificate
                    .verify(&committee, left_receipt.claim())
                    .is_err()
            );
        }

        assert_eq!(left_successor.state().merge, left_merge_before);
        assert_eq!(right_successor.state().merge, right_merge_before);
        assert_eq!(
            (
                left_successor.state().local.clone(),
                left_successor.heads().local_head,
                left_successor.heads().local_revision,
                left_successor.heads().local_invocations,
                left_successor.heads().checkpoint,
            ),
            left_local_before
        );
        assert_eq!(
            (
                right_successor.state().local.clone(),
                right_successor.heads().local_head,
                right_successor.heads().local_revision,
                right_successor.heads().local_invocations,
                right_successor.heads().checkpoint,
            ),
            right_local_before
        );
        assert_eq!(
            left_successor.state().control,
            right_successor.state().control
        );
        assert_eq!(
            left_successor.state().linear,
            right_successor.state().linear
        );
        assert_eq!(
            left_successor.heads().ordered_invocations,
            right_successor.heads().ordered_invocations
        );
        assert_eq!(left_successor.heads().ordered_head, Some(entry.id()));
        assert_eq!(right_successor.heads().ordered_head, Some(entry.id()));

        let reopened_left =
            materialize_current(&mut left_store, &mut left_executor, &NoPrunedOrderedBases)
                .unwrap();
        let reopened_right =
            materialize_current(&mut right_store, &mut right_executor, &NoPrunedOrderedBases)
                .unwrap();
        assert_eq!(reopened_left, left_successor);
        assert_eq!(reopened_right, right_successor);

        let executions_before_retry = left_executor.executions;
        let committed_retry =
            committed_shared_for_test(entry.clone(), &reopened_left, left_store.instance_id())
                .unwrap();
        match prepare_shared_ordered(
            &mut left_store,
            &mut left_executor,
            &NoPrunedOrderedBases,
            &reopened_left,
            committed_retry,
        )
        .unwrap()
        {
            SharedReplayPreparation::Ready(_) => {
                panic!("exact Shared retry prepared a second transition")
            }
            SharedReplayPreparation::AlreadyCommitted {
                recovery,
                publication,
            } => {
                assert_eq!(recovery.input(), entry.input.id());
                assert_eq!(publication.claim(), left_receipt.claim());
                assert_eq!(publication.entry(), left_receipt.entry());
                assert_eq!(publication.successor(), left_receipt.successor());
                assert_eq!(
                    publication.raft_payload_commitment(),
                    left_receipt.raft_payload_commitment()
                );
            }
        }
        assert_eq!(left_executor.executions, executions_before_retry);
    }

    #[cfg(all(feature = "std", feature = "storage"))]
    #[test]
    fn shared_ordered_missing_or_noncausal_pinned_frontier_fails_closed() {
        let mut store = initialized_shared_replay_store();
        let mut executor = ExactCreateRejectInvocations::default();
        let base = materialize_current(&mut store, &mut executor, &NoPrunedOrderedBases).unwrap();
        let missing = MergeFrontierId([0x81; 32]);
        let missing_entry = OrderedEntry {
            genesis: base.heads().genesis,
            index: 1,
            parent: None,
            merge_frontier: missing,
            merge_seal: None,
            input: admitted_invocation(MethodMode::Linear, 0x82),
        };
        let missing_commit =
            committed_placeholder_for_test(missing_entry, &base, store.instance_id()).unwrap();
        assert!(matches!(
            prepare_shared_ordered(
                &mut store,
                &mut executor,
                &NoPrunedOrderedBases,
                &base,
                missing_commit,
            ),
            Err(ReplayError::MissingMergeFrontier(id)) if id == missing
        ));

        let causal_parent = MergeEvent {
            genesis: base.heads().genesis,
            committee: None,
            author: base.heads().node,
            ordered_base: base.ordered_base(),
            causal_height: 1,
            parents: Vec::new(),
            input: admitted_invocation(MethodMode::Merge, 0x83),
            signature: vec![0x83; ED25519_SIGNATURE_BYTES],
        };
        let noncausal = MergeEvent {
            genesis: base.heads().genesis,
            committee: None,
            author: base.heads().node,
            ordered_base: base.ordered_base(),
            causal_height: 3,
            parents: vec![causal_parent.id()],
            input: admitted_invocation(MethodMode::Merge, 0x85),
            signature: vec![0x85; ED25519_SIGNATURE_BYTES],
        };
        let frontier = MergeFrontier {
            genesis: base.heads().genesis,
            events: vec![noncausal.id()],
        };
        store.put(&causal_parent).unwrap();
        store.put(&noncausal).unwrap();
        store.put(&frontier).unwrap();
        let noncausal_entry = OrderedEntry {
            genesis: base.heads().genesis,
            index: 1,
            parent: None,
            merge_frontier: frontier.id(),
            merge_seal: None,
            input: admitted_invocation(MethodMode::Linear, 0x84),
        };
        let noncausal_commit =
            committed_placeholder_for_test(noncausal_entry, &base, store.instance_id()).unwrap();
        assert!(matches!(
            prepare_shared_ordered(
                &mut store,
                &mut executor,
                &NoPrunedOrderedBases,
                &base,
                noncausal_commit,
            ),
            Err(ReplayError::InvalidCausalHeight)
        ));
        assert_eq!(store.heads().unwrap().unwrap(), *base.heads());
    }

    #[cfg(all(feature = "std", feature = "storage"))]
    #[test]
    fn shared_fence_rejects_excluded_pending_owner_and_accepts_full_frontier() {
        let mut store = initialized_shared_replay_store();
        let mut executor = ExactCreateRejectInvocations::default();
        let base = materialize_current(&mut store, &mut executor, &NoPrunedOrderedBases).unwrap();
        let event = |discriminator| MergeEvent {
            genesis: base.heads().genesis,
            committee: None,
            author: base.heads().node,
            ordered_base: base.ordered_base(),
            causal_height: 1,
            parents: Vec::new(),
            input: admitted_invocation(MethodMode::Merge, discriminator),
            signature: vec![discriminator; ED25519_SIGNATURE_BYTES],
        };
        let retained = event(0x91);
        let excluded = event(0x92);
        let after_retained = publish_test_merge(&mut store, &mut executor, &base, &retained);
        let mut excluding_oracle_store = store.clone();
        let mut excluding_oracle_executor = ExactCreateRejectInvocations::default();
        let active = publish_test_merge(&mut store, &mut executor, &after_retained, &excluded);
        let retained_frontier = after_retained.merge_frontier();
        let retained_seal = persist_projection_seal(
            &mut store,
            &active,
            retained_frontier,
            &after_retained.state().merge,
        );
        let oracle_retained_seal = persist_projection_seal(
            &mut excluding_oracle_store,
            &after_retained,
            retained_frontier,
            &after_retained.state().merge,
        );
        assert_eq!(oracle_retained_seal, retained_seal);
        let excluding_entry = OrderedEntry {
            genesis: active.heads().genesis,
            index: 1,
            parent: None,
            merge_frontier: retained_frontier,
            merge_seal: Some(retained_seal),
            input: ReplayInput {
                runtime: active.runtime().clone(),
                operation: ReplayOperation::SealMerge,
            },
        };
        let excluding_expected = match prepare_ordered(
            &mut excluding_oracle_store,
            &mut excluding_oracle_executor,
            &after_retained,
            &excluding_entry,
        )
        .unwrap()
        {
            ReplayPreparation::Ready(prepared) => prepared,
            ReplayPreparation::AlreadyCommitted(_) => unreachable!(),
        };
        let (_, _excluding_successor, _) = excluding_expected.publish().unwrap();
        let excluding_commit =
            committed_shared_for_test(excluding_entry, &active, store.instance_id()).unwrap();
        assert!(matches!(
            prepare_shared_ordered(
                &mut store,
                &mut executor,
                &NoPrunedOrderedBases,
                &active,
                excluding_commit,
            ),
            Err(ReplayError::InvalidFence)
        ));
        assert_eq!(store.heads().unwrap().unwrap(), *active.heads());
        assert_eq!(
            recover_invocation(
                &mut store,
                &active,
                &excluded.input,
                merge_position(&excluded),
            )
            .unwrap(),
            ReplayInvocationRecovery::Pending
        );

        let mut inclusive_oracle_store = store.clone();
        let mut inclusive_oracle_executor = ExactCreateRejectInvocations::default();
        let inclusive_seal = persist_merge_seal(&mut store, &active);
        let oracle_inclusive_seal = persist_merge_seal(&mut inclusive_oracle_store, &active);
        assert_eq!(oracle_inclusive_seal, inclusive_seal);
        let inclusive_entry = OrderedEntry {
            genesis: active.heads().genesis,
            index: 1,
            parent: None,
            merge_frontier: active.merge_frontier(),
            merge_seal: Some(inclusive_seal),
            input: ReplayInput {
                runtime: active.runtime().clone(),
                operation: ReplayOperation::SealMerge,
            },
        };
        let inclusive_expected = match prepare_ordered(
            &mut inclusive_oracle_store,
            &mut inclusive_oracle_executor,
            &active,
            &inclusive_entry,
        )
        .unwrap()
        {
            ReplayPreparation::Ready(prepared) => prepared,
            ReplayPreparation::AlreadyCommitted(_) => unreachable!(),
        };
        let (_, inclusive_successor, _) = inclusive_expected.publish().unwrap();
        let (committee, committee_keys) = shared_test_committee(&inclusive_entry.input.runtime);
        let expected_claim = shared_claim_for_test(
            committee.id(),
            &inclusive_entry,
            &active,
            &inclusive_successor,
            SharedClaimTamper::None,
        );
        let inclusive_commit =
            committed_shared_for_test(inclusive_entry.clone(), &active, store.instance_id())
                .unwrap();
        let prepared = match prepare_shared_ordered(
            &mut store,
            &mut executor,
            &NoPrunedOrderedBases,
            &active,
            inclusive_commit,
        )
        .unwrap()
        {
            SharedReplayPreparation::Ready(prepared) => prepared,
            SharedReplayPreparation::AlreadyCommitted { .. } => unreachable!(),
        };
        let (_, fenced, finalized, receipt) = prepared.publish_shared().unwrap();
        assert_eq!(receipt.entry(), inclusive_entry.id());
        assert_eq!(receipt.claim(), &expected_claim);
        assert_eq!(fenced.merge_frontier(), active.merge_frontier());
        assert_eq!(fenced.heads().merge_fence.index, inclusive_entry.index);
        assert_eq!(finalized.len(), 3);
        let reopened =
            materialize_current(&mut store, &mut executor, &NoPrunedOrderedBases).unwrap();
        assert_eq!(reopened.heads(), fenced.heads());
        assert_eq!(reopened.state(), fenced.state());
        assert_eq!(reopened.merge_roots, fenced.merge_roots);
        assert_eq!(reopened.merge_boundary_roots, fenced.merge_boundary_roots);
        assert_eq!(
            reopened.merge_boundary_invocations,
            fenced.merge_boundary_invocations
        );
        assert_eq!(reopened.merge_ancestry, fenced.merge_ancestry);

        let exact_certificate =
            shared_qc_for_test(&committee, &committee_keys, receipt.claim().clone());
        exact_certificate
            .verify(&committee, receipt.claim())
            .unwrap();
        for tamper in [
            SharedClaimTamper::MergeFence,
            SharedClaimTamper::SealedInvocations,
        ] {
            let tampered = shared_claim_for_test(
                committee.id(),
                &inclusive_entry,
                &active,
                &inclusive_successor,
                tamper,
            );
            let certificate = shared_qc_for_test(&committee, &committee_keys, tampered.clone());
            certificate.verify(&committee, &tampered).unwrap();
            assert!(certificate.verify(&committee, receipt.claim()).is_err());
        }

        let executions_before_retry = executor.executions;
        let committed_retry =
            committed_shared_for_test(inclusive_entry.clone(), &reopened, store.instance_id())
                .unwrap();
        match prepare_shared_ordered(
            &mut store,
            &mut executor,
            &NoPrunedOrderedBases,
            &reopened,
            committed_retry,
        )
        .unwrap()
        {
            SharedReplayPreparation::Ready(_) => {
                panic!("exact Shared fence retry prepared a second transition")
            }
            SharedReplayPreparation::AlreadyCommitted {
                recovery,
                publication,
            } => {
                assert_eq!(recovery.input(), inclusive_entry.input.id());
                assert_eq!(publication.claim(), receipt.claim());
                assert_eq!(publication.entry(), receipt.entry());
                assert_eq!(publication.successor(), receipt.successor());
                assert_eq!(
                    publication.raft_payload_commitment(),
                    receipt.raft_payload_commitment()
                );
            }
        }
        assert_eq!(executor.executions, executions_before_retry);
    }

    #[cfg(feature = "std")]
    #[test]
    fn empty_checkpoint_accepts_two_concurrent_parentless_merge_roots() {
        let mut store = initialized_replay_store();
        let mut executor = ExactCreateRejectInvocations::default();
        let base = materialize_current(&mut store, &mut executor, &NoPrunedOrderedBases).unwrap();
        let checkpoint = prepare_checkpoint(&mut store, &base).unwrap();
        let (_publication, checkpointed, _) = checkpoint.publish().unwrap();
        assert!(checkpointed.merge_boundary_roots.is_empty());

        let root = |discriminator| MergeEvent {
            genesis: checkpointed.heads().genesis,
            committee: None,
            author: checkpointed.heads().node,
            ordered_base: checkpointed.ordered_base(),
            causal_height: 1,
            parents: Vec::new(),
            input: admitted_invocation(MethodMode::Merge, discriminator),
            signature: vec![discriminator; ED25519_SIGNATURE_BYTES],
        };
        let left = root(0xe8);
        let right = root(0xe9);
        let first = match prepare_merge(
            &mut store,
            &mut executor,
            &NoPrunedOrderedBases,
            &checkpointed,
            &left,
        )
        .unwrap()
        {
            ReplayPreparation::Ready(prepared) => prepared,
            ReplayPreparation::AlreadyCommitted(_) => unreachable!(),
        };
        let (_publication, after_first, _) = first.publish().unwrap();
        let second = match prepare_merge(
            &mut store,
            &mut executor,
            &NoPrunedOrderedBases,
            &after_first,
            &right,
        )
        .unwrap()
        {
            ReplayPreparation::Ready(prepared) => prepared,
            ReplayPreparation::AlreadyCommitted(_) => unreachable!(),
        };
        let (_publication, successor, _) = second.publish().unwrap();
        let reopened =
            materialize_current(&mut store, &mut executor, &NoPrunedOrderedBases).unwrap();
        assert_eq!(reopened.heads(), successor.heads());
        assert_eq!(reopened.merge_roots.len(), 2);
        assert!(reopened.merge_ancestry.contains(&left.id()));
        assert!(reopened.merge_ancestry.contains(&right.id()));
    }
}
