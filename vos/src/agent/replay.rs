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

use super::committee::{
    RootAnchorRecord, SystemAgentGenesisAdmissionId, SystemAgentGenesisAdmissionRecord,
    SystemAgentGenesisEvidence, VerifiedSystemAgentGenesis,
};
use super::execution::MAX_RUNTIME_STATE_BYTES;
#[cfg(feature = "std")]
use super::invocation_index::InvocationIndexes;
use super::journal::{
    AgentJournalGenesis, AgentJournalGenesisId, ArtifactClosure, ArtifactClosureId,
    CanonicalJournalRecord, CheckpointId, CheckpointLane, CheckpointManifest,
    InvocationDisposition, InvocationIndexId, InvocationIndexManifest, InvocationOwnershipKey,
    InvocationOwnershipScope, InvocationOwnershipValue, InvocationResultState, JournalHeads,
    JournalHeadsId, LaneCursor, LaneStateId, LaneStateManifest, LocalEntry, LocalEntryId,
    MergeEvent, MergeEventId, MergeFrontier, MergeFrontierId, MergeSeal, MergeSealId, OrderedBase,
    OrderedEntry, OrderedEntryId, PersistedLane, ReplayInput, ReplayOperation, RuntimeBinding,
    system_genesis_post_create_state_commitment,
};
#[cfg(feature = "std")]
use super::journal_store::{
    AgentJournalStore, JournalBlobClass, JournalPublication, JournalStoreError,
};
use super::standard::StandardAgentRuntime;
use super::wire::{RuntimeState, decode_standard_runtime_state, encode_standard_runtime_state};
use super::{AgentReplica, AgentRuntime, InvocationResultStorage, LifecycleRequest, StateLane};
use crate::service::wire::ServiceWire;
use crate::service::{BlobRef, Hash, InvocationId, NodeId};

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
/// Merge replay must leave every field false. Its immediate response is the
/// journal receipt/frontier produced by the host, never a guest-owned reply.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct ReplayProducts {
    pub durable_actor_reply: bool,
    pub effects: bool,
    pub calls: bool,
    pub schedules: bool,
    pub proofs: bool,
}

impl ReplayProducts {
    pub const fn is_empty(self) -> bool {
        !self.durable_actor_reply && !self.effects && !self.calls && !self.schedules && !self.proofs
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
    /// Runtime selected after this operation. It changes only after a
    /// successfully applied `UpgradeRuntime` management entry.
    pub next_runtime: RuntimeBinding,
    pub products: ReplayProducts,
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

    /// Recover an already-retained invocation without entering application
    /// code. The transition may advance only the owning result component's
    /// deterministic authority-slot high-water and must reproduce an Applied
    /// result under the same runtime. Replay calls this only after an
    /// authenticated ownership lookup proves the request commitment exact.
    fn recover_retained(
        &mut self,
        input: &ReplayInput,
        before: &RuntimeState,
        position: ReplayPosition,
    ) -> Result<ReplayTransition, Self::Error>;

    fn execute(
        &mut self,
        input: &ReplayInput,
        before: &RuntimeState,
        position: ReplayPosition,
    ) -> Result<ReplayTransition, Self::Error>;
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
    fn map_source<NextSourceError>(
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
            Self::InvocationOwnership(error) => ReplayError::InvocationOwnership(error),
        }
    }

    fn map_executor<NextExecutorError>(
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
            Self::InvocationOwnership(error) => ReplayError::InvocationOwnership(error),
        }
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
/// ordered lifecycle mutation. The returned fence becomes effective when the
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
        || !matches!(entry.input.operation, ReplayOperation::Management { .. })
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

/// Validated successor of one replay step.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ReplayStep {
    state: RuntimeState,
    runtime: RuntimeBinding,
    outcome: ReplayStepOutcome,
    products: ReplayProducts,
    input: super::journal::ReplayInputId,
    position: ReplayPosition,
    ownership_delta: InvocationIndexDelta,
    merge_authenticated: bool,
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

    const fn execution_result(&self) -> ReplayExecutionResult {
        ReplayExecutionResult {
            outcome: self.outcome,
            products: self.products,
            input: self.input,
            position: self.position,
        }
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum InvocationIndexDelta {
    None,
    Insert { scope: InvocationOwnershipScope },
    Acknowledge { scope: InvocationOwnershipScope },
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

/// Root-admitted, exactly executed clean-generation journal bootstrap.
///
/// Production construction remains deliberately unavailable until the system
/// Agent's QC/root-bootstrap adapter lands. Storage may inspect this closure,
/// but cannot manufacture one from a merely self-canonical genesis record.
pub struct ReplaySealedGenesis {
    genesis: AgentJournalGenesis,
    post_create: RuntimeState,
    empty_frontier: MergeFrontier,
    ordered_invocations: InvocationIndexManifest,
    merge_invocations: InvocationIndexManifest,
    local_invocations: InvocationIndexManifest,
    artifacts: ArtifactClosure,
    root_anchor: RootAnchorRecord,
    admission_record: SystemAgentGenesisAdmissionRecord,
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

    pub const fn admission_record(&self) -> SystemAgentGenesisAdmissionRecord {
        self.admission_record
    }

    pub fn admission_evidence(&self) -> &SystemAgentGenesisEvidence {
        &self.admission_evidence
    }

    pub fn admission_commitment(&self) -> Hash {
        self.genesis.admission.as_hash()
    }

    pub const fn replica(&self) -> AgentReplica {
        self.replica
    }

    /// Mint the sole production bootstrap capability from a root/QC-verified
    /// system-Agent admission and the exact replayed Create transition.
    /// Decoded evidence, a self-canonical genesis, or caller-supplied state is
    /// never sufficient on its own.
    pub(crate) fn from_verified<E: ReplayExecutor>(
        verified: &VerifiedSystemAgentGenesis,
        admission_evidence: SystemAgentGenesisEvidence,
        genesis: AgentJournalGenesis,
        replica: AgentReplica,
        executor: &mut E,
    ) -> Result<Self, ReplayError<core::convert::Infallible, E::Error>> {
        genesis.validate().map_err(|_| ReplayError::InvalidRecord)?;
        let ReplayOperation::Management { request } = &genesis.create.operation else {
            return Err(ReplayError::InvalidRecord);
        };
        let LifecycleRequest::Authorized { request, .. } = request else {
            return Err(ReplayError::InvalidRecord);
        };
        let LifecycleRequest::Create(config) = request.as_ref() else {
            return Err(ReplayError::InvalidRecord);
        };
        let admission_record = verified.admission_record();
        let root_anchor = verified.root_anchor().clone();
        if verified.admission_id() != genesis.admission
            || verified.admission_commitment() != genesis.admission.as_hash()
            || admission_record.id() != genesis.admission
            || admission_record.evidence() != verified.evidence_id()
            || admission_record.root_anchor() != root_anchor.id()
            || admission_record.root_anchor_config_version() != root_anchor.config_version()
            || admission_record.root_anchor_config() != root_anchor.config_commitment()
            || admission_evidence.id() != verified.evidence_id()
            || verified.space() != genesis.runtime().space
            || verified.system_agent() != genesis.runtime().agent
            || verified.authority_binding() != config.authority.commitment()
            || verified.genesis_intent()
                != genesis
                    .genesis_intent()
                    .map_err(|_| ReplayError::InvalidRecord)?
            || verified.runtime_binding() != genesis.runtime().commitment()
            || verified.sequence()
                != genesis
                    .genesis_authority_sequence()
                    .map_err(|_| ReplayError::InvalidRecord)?
            || !config.replicas.contains(&replica)
        {
            return Err(ReplayError::InvalidRecord);
        }

        let genesis_id = genesis.id();
        let mut machine = ReplayMachine::from_genesis(genesis_id, genesis.runtime().clone())
            .map_err(ReplayError::InvocationOwnership)?;
        let step = machine.apply::<_, core::convert::Infallible>(
            executor,
            &genesis.create,
            &RuntimeState::default(),
            ReplayPosition::Genesis,
        )?;
        if step.outcome != ReplayStepOutcome::Applied(ReplayDisposition::Applied)
            || step.runtime != *genesis.runtime()
        {
            return Err(ReplayError::InvalidRecord);
        }
        let post_create = step.state;
        let decoded =
            decode_standard_runtime_state(&post_create).map_err(|_| ReplayError::InvalidRecord)?;
        if decoded.config.as_ref() != Some(config)
            || !decoded
                .config
                .as_ref()
                .is_some_and(|state_config| state_config.replicas.contains(&replica))
            || system_genesis_post_create_state_commitment(&post_create)
                .map_err(|_| ReplayError::InvalidRecord)?
                != verified.post_create_state()
        {
            return Err(ReplayError::InvalidRecord);
        }
        let artifacts = derive_standard_artifact_closure::<core::convert::Infallible>(
            genesis_id,
            &step.runtime,
            &post_create,
        )
        .map_err(|error| error.map_executor(|never| match never {}))?;
        if artifacts
            .system_genesis_commitment()
            .map_err(|_| ReplayError::InvalidRecord)?
            != verified.artifact_closure()
        {
            return Err(ReplayError::InvalidRecord);
        }
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
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ReplaySealedPublication {
    expected: JournalHeadsId,
    next: JournalHeads,
    anchor: ReplayPublicationAnchor,
    checkpoint: Option<ReplaySealedCheckpoint>,
    fence_ancestry: FenceAncestryEvidence,
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
    state: RuntimeState,
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
}

/// One prepared CAS and the only successor materialization which may become
/// usable if that CAS succeeds. `publish` consumes the session on every path;
/// a conflict therefore discards all staged root IDs.
pub struct ReplayPreparedPublication {
    sealed: ReplaySealedPublication,
    successor: ReplayMaterialization,
    execution: Option<ReplayExecutionResult>,
}

/// Authenticated execution facts carried by a prepared journal publication.
/// The durable reply itself remains in the scoped invocation-result state of
/// the returned successor materialization; these fields tell the driver
/// exactly which result to recover without re-executing the input.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct ReplayExecutionResult {
    outcome: ReplayStepOutcome,
    products: ReplayProducts,
    input: super::journal::ReplayInputId,
    position: ReplayPosition,
}

impl ReplayExecutionResult {
    pub const fn outcome(self) -> ReplayStepOutcome {
        self.outcome
    }

    pub const fn products(self) -> ReplayProducts {
        self.products
    }

    pub const fn input(self) -> super::journal::ReplayInputId {
        self.input
    }

    pub const fn position(self) -> ReplayPosition {
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

impl ReplayCommittedRecovery {
    pub const fn input(self) -> super::journal::ReplayInputId {
        self.input
    }

    pub const fn position(self) -> ReplayPosition {
        self.position
    }
}

impl ReplayPreparedPublication {
    pub const fn execution(&self) -> Option<ReplayExecutionResult> {
        self.execution
    }

    #[cfg(feature = "std")]
    pub fn publish<S: AgentJournalStore>(
        self,
        store: &mut S,
    ) -> Result<
        (
            JournalPublication,
            ReplayMaterialization,
            Option<ReplayExecutionResult>,
        ),
        JournalStoreError,
    > {
        let publication = store.publish(&self.sealed)?;
        Ok((publication, self.successor, self.execution))
    }
}

/// Preparing an exact anchor already visible at the authenticated head is an
/// idempotent response-loss retry and performs no second CAS.
#[allow(clippy::large_enum_variant)]
pub enum ReplayPreparation {
    Ready(ReplayPreparedPublication),
    AlreadyCommitted(ReplayCommittedRecovery),
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

    pub(crate) const fn fence_ancestry(&self) -> &FenceAncestryEvidence {
        &self.fence_ancestry
    }
}

/// Failure while consulting checkpoint-authenticated InvocationId ownership.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum InvocationOwnershipError {
    Unavailable,
    Unauthenticated,
    Conflict,
}

/// Exact ownership index used across checkpoint compaction. Implementations
/// must authenticate `lookup` against the invocation-index root committed by
/// the opened head/checkpoint. `record` stages a request commitment and its
/// acknowledgement status for the same atomic publication as successor lane
/// manifests.
pub trait InvocationOwnership {
    fn lookup(
        &self,
        key: InvocationOwnershipKey,
    ) -> Result<Option<InvocationOwnershipValue>, InvocationOwnershipError>;

    fn record(
        &mut self,
        key: InvocationOwnershipKey,
        value: InvocationOwnershipValue,
    ) -> Result<(), InvocationOwnershipError>;

    /// Content identity of the currently staged authenticated index. Replay
    /// publication is unavailable until a non-empty index implementation can
    /// return its exact manifest ID.
    fn index_id(
        &self,
        scope: InvocationOwnershipScope,
    ) -> Result<InvocationIndexId, InvocationOwnershipError>;
}

/// In-memory ownership used only while replaying from immutable genesis.
/// Checkpoint recovery must supply its authenticated index implementation.
pub struct GenesisInvocationOwnership {
    genesis: AgentJournalGenesisId,
    entries: BTreeMap<InvocationOwnershipKey, InvocationOwnershipValue>,
}

impl InvocationOwnership for GenesisInvocationOwnership {
    fn lookup(
        &self,
        key: InvocationOwnershipKey,
    ) -> Result<Option<InvocationOwnershipValue>, InvocationOwnershipError> {
        Ok(self.entries.get(&key).copied())
    }

    fn record(
        &mut self,
        key: InvocationOwnershipKey,
        value: InvocationOwnershipValue,
    ) -> Result<(), InvocationOwnershipError> {
        match self.entries.get(&key) {
            Some(existing) if *existing == value => Ok(()),
            Some(existing)
                if existing.request_commitment == value.request_commitment
                    && existing.result_state == InvocationResultState::Retained
                    && value.result_state == InvocationResultState::Acknowledged
                    && existing.scope == value.scope
                    && existing.first_input == value.first_input
                    && existing.lane == value.lane
                    && existing.node == value.node
                    && existing.disposition == value.disposition =>
            {
                self.entries.insert(key, value);
                Ok(())
            }
            Some(_) => Err(InvocationOwnershipError::Conflict),
            None => {
                self.entries.insert(key, value);
                Ok(())
            }
        }
    }

    fn index_id(
        &self,
        scope: InvocationOwnershipScope,
    ) -> Result<InvocationIndexId, InvocationOwnershipError> {
        if self.entries.keys().any(|key| key.scope == scope) {
            return Err(InvocationOwnershipError::Unavailable);
        }
        Ok(InvocationIndexManifest::empty(self.genesis, scope).id())
    }
}

/// Stateful transition validator shared by ordered, Merge, and Local replay.
pub struct ReplayMachine<Ownership> {
    genesis: AgentJournalGenesisId,
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
            runtime: runtime.clone(),
            runtime_history: BTreeMap::from([(OrderedBase::post_genesis(), runtime)]),
            ownership: GenesisInvocationOwnership {
                genesis,
                entries: BTreeMap::new(),
            },
            fence: None,
        })
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
        let step = self.apply(
            executor,
            &entry.input,
            before,
            ReplayPosition::Ordered {
                id,
                index: entry.index,
                merge_frontier: entry.merge_frontier,
                merge_seal: entry.merge_seal,
            },
        )?;
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

        // Authority admission precedes every ownership shortcut. In
        // particular, a forged receipt with an otherwise exact request
        // commitment cannot advance a journal position as a duplicate or
        // divergence without entering the executor's authenticated boundary.
        executor
            .authenticate(input, before, position)
            .map_err(ReplayError::Executor)?;

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
        let mut retained_recovery = false;
        let mut ownership_delta = InvocationIndexDelta::None;
        if let Some((key, request, operation)) = invocation_owner {
            if let Some(seen) = self
                .ownership
                .lookup(key)
                .map_err(ReplayError::InvocationOwnership)?
            {
                if seen.validate().is_err()
                    || seen.scope != key.scope
                    || seen.lane != input.persisted_lane()
                    || seen.node
                        != match key.scope {
                            InvocationOwnershipScope::Local(node) => Some(node),
                            InvocationOwnershipScope::Ordered | InvocationOwnershipScope::Merge => {
                                None
                            }
                        }
                {
                    return Err(ReplayError::InvocationOwnership(
                        InvocationOwnershipError::Unauthenticated,
                    ));
                }
                prior_owner = Some(seen);
                if seen.request_commitment != request {
                    self.advance_noop_position(position, &execution_runtime);
                    return Ok(ReplayStep {
                        state: before.clone(),
                        runtime: execution_runtime.clone(),
                        outcome: ReplayStepOutcome::DivergentInvocation,
                        products: ReplayProducts::default(),
                        input: input.id(),
                        position,
                        ownership_delta: InvocationIndexDelta::None,
                        merge_authenticated: false,
                    });
                }
                retained_recovery = operation == InvocationOwnershipOperation::Invoke
                    && seen.result_state == InvocationResultState::Retained;
                let duplicate = seen.result_state != InvocationResultState::Retained;
                if duplicate {
                    self.advance_noop_position(position, &execution_runtime);
                    return Ok(ReplayStep {
                        state: before.clone(),
                        runtime: execution_runtime.clone(),
                        outcome: ReplayStepOutcome::ExactDuplicate,
                        products: ReplayProducts::default(),
                        input: input.id(),
                        position,
                        ownership_delta: InvocationIndexDelta::None,
                        merge_authenticated: false,
                    });
                }
            } else if operation == InvocationOwnershipOperation::Acknowledge {
                return Err(ReplayError::InvocationOwnership(
                    InvocationOwnershipError::Unauthenticated,
                ));
            }
        }

        let transition = if retained_recovery {
            executor.recover_retained(input, before, position)
        } else {
            executor.execute(input, before, position)
        }
        .map_err(ReplayError::Executor)?;
        validate_runtime_state_bound(&transition.state)?;
        validate_transition(input, before, &transition, position, &execution_runtime)?;
        if retained_recovery && transition.disposition != ReplayDisposition::Applied {
            return Err(ReplayError::InvocationOwnership(
                InvocationOwnershipError::Unauthenticated,
            ));
        }
        if let Some((key, request, operation)) = invocation_owner {
            // The first durable disposition owns this identity even when
            // execution is forbidden, panics, or runs out of gas.
            let value = match (operation, prior_owner) {
                (InvocationOwnershipOperation::Invoke, None) => Some(InvocationOwnershipValue {
                    scope: key.scope,
                    request_commitment: request,
                    first_input: input.id(),
                    lane: input.persisted_lane(),
                    node: match key.scope {
                        InvocationOwnershipScope::Local(node) => Some(node),
                        InvocationOwnershipScope::Ordered | InvocationOwnershipScope::Merge => None,
                    },
                    disposition: invocation_disposition(transition.disposition),
                    result_state: if transition.disposition == ReplayDisposition::Applied {
                        InvocationResultState::Retained
                    } else {
                        InvocationResultState::Terminal
                    },
                }),
                (InvocationOwnershipOperation::Acknowledge, Some(mut existing))
                    if transition.disposition == ReplayDisposition::Applied =>
                {
                    existing.result_state = InvocationResultState::Acknowledged;
                    Some(existing)
                }
                (InvocationOwnershipOperation::Invoke, Some(_)) => None,
                (InvocationOwnershipOperation::Acknowledge, None) => {
                    return Err(ReplayError::InvocationOwnership(
                        InvocationOwnershipError::Unauthenticated,
                    ));
                }
                (InvocationOwnershipOperation::Acknowledge, _) => None,
            };
            if let Some(value) = value {
                ownership_delta = match operation {
                    InvocationOwnershipOperation::Invoke => {
                        InvocationIndexDelta::Insert { scope: key.scope }
                    }
                    InvocationOwnershipOperation::Acknowledge => {
                        InvocationIndexDelta::Acknowledge { scope: key.scope }
                    }
                };
                self.ownership
                    .record(key, value)
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
            products: transition.products,
            input: input.id(),
            position,
            ownership_delta,
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
                    products: ReplayProducts::default(),
                    input: event.input.id(),
                    position,
                    ownership_delta: InvocationIndexDelta::None,
                    merge_authenticated: true,
                });
            }
        }
        let mut step = self.apply(
            executor,
            &event.input,
            before,
            ReplayPosition::Merge {
                id,
                causal_height: event.causal_height,
                ordered_base: event.ordered_base,
            },
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
        let fence_ancestry = successor_fence_ancestry(materialization, &next, false, Some(entry))?;
        Ok(ReplaySealedPublication {
            expected: current.id(),
            next,
            anchor: ReplayPublicationAnchor::Ordered(entry.clone()),
            checkpoint: None,
            fence_ancestry,
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
        let fence_ancestry = successor_fence_ancestry(materialization, &next, false, None)?;
        Ok(ReplaySealedPublication {
            expected: current.id(),
            next,
            anchor: ReplayPublicationAnchor::Local(entry.clone()),
            checkpoint: None,
            fence_ancestry,
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
        self.validate_publication_indexes(current, &next, step.ownership_delta)?;
        let fence_ancestry = successor_fence_ancestry(materialization, &next, false, None)?;
        Ok(ReplaySealedPublication {
            expected: current.id(),
            next,
            anchor: ReplayPublicationAnchor::Merge {
                event: event.clone(),
                frontier: replay.frontier.clone(),
            },
            checkpoint: None,
            fence_ancestry,
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
            let changed = matches!(
                delta,
                InvocationIndexDelta::Insert {
                    scope: changed,
                } | InvocationIndexDelta::Acknowledge { scope: changed }
                    if changed == scope
            );
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
    }
    artifacts.sort_unstable_by_key(|artifact| (artifact.hash, artifact.len));
    artifacts.dedup_by_key(|artifact| (artifact.hash, artifact.len));
    let closure = ArtifactClosure { genesis, artifacts };
    if closure.validate().is_err() {
        return Err(ReplayError::InvalidRecord);
    }
    Ok(closure)
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
            ) && (matches!(input.operation, ReplayOperation::Management { .. })
                == merge_seal.is_some())
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
        ReplayOperation::Management { .. } => None,
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

fn validate_transition<SourceError, ExecutorError>(
    input: &ReplayInput,
    before: &RuntimeState,
    transition: &ReplayTransition,
    position: ReplayPosition,
    current_runtime: &RuntimeBinding,
) -> Result<(), ReplayError<SourceError, ExecutorError>> {
    // Runtime side products are not yet content-addressed members of the
    // journal CAS. Accepting them here would make a crash able to lose or
    // duplicate replies/effects even when state replay is exact.
    if !transition.products.is_empty() {
        return Err(ReplayError::ForbiddenMergeProducts);
    }
    let invocation_rejected = transition.disposition == ReplayDisposition::Rejected
        && !matches!(input.operation, ReplayOperation::Management { .. });
    if transition.disposition.is_terminal_noop() || invocation_rejected {
        if transition.state != *before
            || transition.next_runtime != *current_runtime
            || !transition.products.is_empty()
        {
            return Err(ReplayError::TerminalMutation);
        }
    } else {
        validate_runtime_successor(input, transition, current_runtime)?;
        validate_lane_mutation(
            input,
            before,
            &transition.state,
            transition.disposition,
            position,
        )?;
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
) -> Result<(), ReplayError<SourceError, ExecutorError>> {
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
        return validate_standard_management_transition(input, before, after, disposition);
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
        Ok(())
    }
}

fn validate_standard_management_transition<SourceError, ExecutorError>(
    input: &ReplayInput,
    before: &RuntimeState,
    after: &RuntimeState,
    disposition: ReplayDisposition,
) -> Result<(), ReplayError<SourceError, ExecutorError>> {
    let ReplayOperation::Management { request } = &input.operation else {
        return Err(ReplayError::InvalidPosition);
    };
    let decoded = decode_standard_runtime_state(before)
        .map_err(|_| ReplayError::InvalidManagementTransition)?;
    let mut runtime = StandardAgentRuntime::restore(decoded)
        .map_err(|_| ReplayError::InvalidManagementTransition)?;
    let result = runtime.apply(request.clone());
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
    Ok(())
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
    admission: SystemAgentGenesisAdmissionId,
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
        let replay = load_merge_suffix(store, current, target).map_err(lift_replay)?;
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
        let next = successor_merge_base(current, &replay).map_err(lift_validation)?;
        ancestry.extend(replay.events().iter().map(|(id, _)| *id));
        *current = next;
        actions.push(MaterializationAction::Merge {
            replay,
            roots: current.roots().to_vec(),
            ancestry: ancestry.clone(),
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
            || !matches!(entry.input.operation, ReplayOperation::Management { .. })
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
        let mut merge_boundary_ancestry = base.merge_ancestry.clone();
        let mut merge_boundary_state = state.merge.clone();
        let mut merge_boundary_invocations = base.merge_invocations;
        let mut current_roots = base.merge.roots().to_vec();
        let mut current_ancestry = base.merge_ancestry;
        let mut local_revision = base.local_revision;
        let mut local_head = base.local_head;

        if let Some(input) = base.genesis_input {
            let step = machine.apply::<_, ReplayMaterializationSourceError<R::Error>>(
                executor,
                &input,
                &state,
                ReplayPosition::Genesis,
            )?;
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
                } => {
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
                            >(executor, &plan.ordered, *id, event, &before)?;
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
                    let step = machine.apply::<_, ReplayMaterializationSourceError<R::Error>>(
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
                    )?;
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
                    let step = machine.apply::<_, ReplayMaterializationSourceError<R::Error>>(
                        executor,
                        &entry.input,
                        &state,
                        ReplayPosition::Ordered {
                            id,
                            index: entry.index,
                            merge_frontier: entry.merge_frontier,
                            merge_seal: entry.merge_seal,
                        },
                    )?;
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
                        merge_boundary_ancestry = current_ancestry.clone();
                        merge_boundary_state = state.merge.clone();
                        merge_boundary_invocations = InvocationOwnership::index_id(
                            &machine.ownership,
                            InvocationOwnershipScope::Merge,
                        )
                        .map_err(ReplayError::InvocationOwnership)?;
                    }
                }
            }
        }

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
            state,
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
        execute_plan(store, executor, resolver, heads, base, plan)
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

    pub(crate) fn prepare_ordered<S, E>(
        store: &mut S,
        executor: &mut E,
        materialization: &ReplayMaterialization,
        entry: &OrderedEntry,
    ) -> Result<ReplayPreparation, MaterializeError<core::convert::Infallible, E::Error>>
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
        let indexes = InvocationIndexes::open(
            store,
            current.ordered_invocations,
            current.merge_invocations,
            current.local_invocations,
        )
        .map_err(|_| ReplayError::InvocationOwnership(InvocationOwnershipError::Unauthenticated))?;
        let mut machine = ReplayMachine::from_materialization(materialization, indexes)
            .map_err(ReplayError::InvocationOwnership)?;
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
        let step = machine
            .apply::<_, ReplayMaterializationSourceError<core::convert::Infallible>>(
                executor,
                &entry.input,
                &materialization.state,
                ReplayPosition::Ordered {
                    id,
                    index: entry.index,
                    merge_frontier: entry.merge_frontier,
                    merge_seal: entry.merge_seal,
                },
            )?;
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
        let execution = step.execution_result();

        let mut snapshots = materialization.ordered_snapshots.clone();
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
            sealed,
            successor: ReplayMaterialization {
                heads_id: next.id(),
                heads: next,
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
            execution: Some(execution),
        }))
    }

    pub(crate) fn prepare_local<S, E>(
        store: &mut S,
        executor: &mut E,
        materialization: &ReplayMaterialization,
        entry: &LocalEntry,
    ) -> Result<ReplayPreparation, MaterializeError<core::convert::Infallible, E::Error>>
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
        let mut machine = ReplayMachine::from_materialization(materialization, indexes)
            .map_err(ReplayError::InvocationOwnership)?;
        let step = machine
            .apply::<_, ReplayMaterializationSourceError<core::convert::Infallible>>(
                executor,
                &entry.input,
                &materialization.state,
                ReplayPosition::Local {
                    id,
                    node: entry.node,
                    revision: entry.revision,
                    ordered_base: entry.ordered_base,
                    merge_frontier: entry.merge_frontier,
                },
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
        let execution = step.execution_result();
        let mut state = materialization.state.clone();
        state.local = step.state.local;
        validate_runtime_state_bound(&state)?;
        let artifacts =
            successor_artifacts::<S, core::convert::Infallible, E>(store, &next, &state)?;
        Ok(ReplayPreparation::Ready(ReplayPreparedPublication {
            sealed,
            successor: ReplayMaterialization {
                heads_id: next.id(),
                heads: next,
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
            execution: Some(execution),
        }))
    }

    pub(crate) fn prepare_merge<S, E, R>(
        store: &mut S,
        executor: &mut E,
        resolver: &R,
        materialization: &ReplayMaterialization,
        event: &MergeEvent,
    ) -> Result<ReplayPreparation, MaterializeError<R::Error, E::Error>>
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
                .verify_and_apply_merge::<E, ReplayMaterializationSourceError<R::Error>>(
                    executor, &ordered, *event_id, retained, &before,
                )?;
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
        let execution = step.execution_result();
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
            sealed,
            successor: ReplayMaterialization {
                heads_id: next.id(),
                heads: next,
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
            execution: Some(execution),
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

    pub(crate) fn prepare_checkpoint<S>(
        store: &mut S,
        materialization: &ReplayMaterialization,
    ) -> Result<
        ReplayPreparedPublication,
        MaterializeError<core::convert::Infallible, core::convert::Infallible>,
    >
    where
        S: AgentJournalStore + ReplaySource<Error = JournalStoreError>,
    {
        require_current_materialization(store, materialization)?;
        let current = &materialization.heads;
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
            checkpoint: Some(checkpoint),
            fence_ancestry: fence_ancestry.clone(),
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
            sealed,
            successor: ReplayMaterialization {
                heads_id: next.id(),
                heads: next,
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
            execution: None,
        })
    }
}

#[cfg(feature = "std")]
#[allow(unused_imports)]
pub(crate) use aggregate::{
    MaterializeError, materialize_current, prepare_checkpoint, prepare_local, prepare_merge,
    prepare_ordered,
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
    #[cfg(feature = "std")]
    use crate::agent::committee::{
        AuthorityCommittee, AuthorityCommitteeMember, AuthorityMemberRole,
        AuthorityQuorumCertificate, AuthoritySignature, AuthoritySignerId, RootAnchorRecord,
        SystemAgentGenesisClaim, SystemAgentGenesisEvidence, SystemAgentGenesisExpectations,
        TrustedRootAnchor,
    };
    #[cfg(feature = "std")]
    use crate::agent::contract::RuntimePackageContract;
    use crate::agent::execution::{ActorInvocation, ActorInvocationAuth};
    #[cfg(feature = "std")]
    use crate::agent::invocation_index::InvocationIndexStore;
    #[cfg(feature = "std")]
    use crate::agent::journal_store::{
        AgentJournalStore, JournalBlobClass, JournalPublication, JournalStoreError,
        MemoryAgentJournalStore,
    };
    #[cfg(feature = "std")]
    use crate::agent::{
        AgentConfig, AgentIdentity, AgentProfile, AgentReplica, LaneSet,
        LifecycleAuthorityAdmission, ReplicaRole, RuntimeCapabilities,
    };
    use crate::service::{
        ActorId, AgentId, CapabilityId, CredentialId, DeploymentId, PrincipalId, ProducerId,
        ProgramId, SpaceId,
    };
    #[cfg(feature = "std")]
    use ed25519_dalek::{Signer as _, SigningKey};

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
    impl AgentJournalStore for LinearReplayStore {
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

    fn input(mode: MethodMode) -> ReplayInput {
        input_with_message(mode, vec![1])
    }

    fn input_with_message(mode: MethodMode, message: Vec<u8>) -> ReplayInput {
        let invocation = ActorInvocation {
            invocation: InvocationId([0x51; 32]),
            actor: ActorId([0x52; 32]),
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

    #[cfg(feature = "std")]
    fn admitted_authority_key() -> SigningKey {
        SigningKey::from_bytes(&[0x90; 32])
    }

    #[cfg(feature = "std")]
    fn admitted_authority() -> AgentAuthorityBinding {
        let public_key =
            ed25519_public_key_wire(admitted_authority_key().verifying_key().to_bytes());
        AgentAuthorityBinding {
            agent: AgentId([0x89; 32]),
            actor: ActorId([0x8a; 32]),
            deployment: DeploymentId([0x8b; 32]),
            program: ProgramId([0x8c; 32]),
            producer: ProducerId::of_public_key(&public_key),
            public_key,
        }
    }

    #[cfg(feature = "std")]
    fn admitted_config() -> AgentConfig {
        let space = SpaceId([0x91; 32]);
        let owner = PrincipalId([0x92; 32]);
        let creation_nonce = Hash([0x93; 32]);
        let agent = AgentId::derive(space, owner, creation_nonce.as_bytes());
        AgentConfig {
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
        }
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
    fn admitted_create_input() -> ReplayInput {
        let runtime = admitted_runtime();
        let inner = LifecycleRequest::Create(admitted_config());
        let claim = AgentAuthorityClaim {
            authority: admitted_authority(),
            space: runtime.space,
            agent: runtime.agent,
            principal: admitted_config().identity.owner,
            credential: CredentialId([0x98; 32]),
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
            _input: &ReplayInput,
            _before: &RuntimeState,
            _position: ReplayPosition,
        ) -> Result<(), Self::Error> {
            Ok(())
        }

        fn recover_retained(
            &mut self,
            input: &ReplayInput,
            before: &RuntimeState,
            position: ReplayPosition,
        ) -> Result<ReplayTransition, Self::Error> {
            self.execute(input, before, position)
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
                    next_runtime: input.runtime.clone(),
                    products: ReplayProducts::default(),
                });
            }
            Ok(ReplayTransition {
                state: before.clone(),
                disposition: ReplayDisposition::Rejected,
                next_runtime: input.runtime.clone(),
                products: ReplayProducts::default(),
            })
        }
    }

    /// Test-only root admission. It still runs the exact Create transition
    /// through ReplayMachine and derives the complete artifact closure; it
    /// exposes no callable constructor in non-test code.
    #[cfg(feature = "std")]
    pub(crate) fn admitted_genesis(admission: u8) -> ReplaySealedGenesis {
        // The admission ID is derived only after the cycle-free intent and
        // exact Create outputs have been certified. A temporary nonzero ID is
        // used solely to execute the same request and derive those outputs;
        // their authority commitments explicitly exclude the final genesis
        // scope.
        let mut genesis = AgentJournalGenesis {
            admission: SystemAgentGenesisAdmissionId::from_bytes([admission; 32]),
            create: admitted_create_input(),
        };
        assert!(genesis.validate().is_ok());
        let genesis_id = genesis.id();
        let mut machine = ReplayMachine::from_genesis(genesis_id, admitted_runtime()).unwrap();
        let mut executor = ExactCreateRejectInvocations::default();
        let step = machine
            .apply::<_, ()>(
                &mut executor,
                &genesis.create,
                &RuntimeState::default(),
                ReplayPosition::Genesis,
            )
            .unwrap();
        assert_eq!(
            step.outcome(),
            ReplayStepOutcome::Applied(ReplayDisposition::Applied)
        );
        let artifacts = derive_standard_artifact_closure::<core::convert::Infallible>(
            genesis_id,
            &step.runtime,
            &step.state,
        )
        .unwrap();
        let inner_create = match &genesis.create.operation {
            ReplayOperation::Management {
                request: LifecycleRequest::Authorized { request, .. },
            } => request.commitment(),
            _ => unreachable!(),
        };
        let expected = SystemAgentGenesisExpectations::new(
            genesis.runtime().commitment(),
            inner_create,
            system_genesis_post_create_state_commitment(&step.state).unwrap(),
            artifacts.system_genesis_commitment().unwrap(),
            genesis.genesis_authority_sequence().unwrap(),
        )
        .unwrap();
        let signing_keys = [
            SigningKey::from_bytes(&[admission; 32]),
            SigningKey::from_bytes(&[admission.wrapping_add(1); 32]),
            SigningKey::from_bytes(&[admission.wrapping_add(2); 32]),
        ];
        let mut members = signing_keys
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
        let authority_binding = admitted_config().authority.commitment();
        let committee =
            AuthorityCommittee::new(genesis.runtime().space, authority_binding, 1, None, members)
                .unwrap();
        let root = RootAnchorRecord::new(
            u64::from(admission) + 1,
            genesis.runtime().space,
            genesis.runtime().agent,
            authority_binding,
            Hash([admission.wrapping_add(3); 32]),
            committee.clone(),
        )
        .unwrap();
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
        genesis.admission = verified.admission_id();
        let replica = admitted_config().replicas[0];
        ReplaySealedGenesis::from_verified(&verified, evidence, genesis, replica, &mut executor)
            .unwrap()
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
    fn initialized_linear_replay_store() -> LinearReplayStore {
        let inner = initialized_replay_store();
        let heads = inner.heads().unwrap().unwrap();
        LinearReplayStore { inner, heads }
    }

    #[derive(Default)]
    struct RejectingExecutor {
        calls: usize,
        authentications: usize,
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
            let signature = match &input.operation {
                ReplayOperation::Invoke { authority, .. }
                | ReplayOperation::Acknowledge { authority, .. } => &authority.signature,
                ReplayOperation::Management { .. } => return Ok(()),
            };
            signature
                .first()
                .copied()
                .filter(|byte| *byte == 0x55)
                .map(|_| ())
                .ok_or(())
        }

        fn recover_retained(
            &mut self,
            input: &ReplayInput,
            before: &RuntimeState,
            position: ReplayPosition,
        ) -> Result<ReplayTransition, Self::Error> {
            self.execute(input, before, position)
        }

        fn execute(
            &mut self,
            input: &ReplayInput,
            before: &RuntimeState,
            _position: ReplayPosition,
        ) -> Result<ReplayTransition, Self::Error> {
            self.calls += 1;
            Ok(ReplayTransition {
                state: before.clone(),
                disposition: ReplayDisposition::Rejected,
                next_runtime: input.runtime.clone(),
                products: ReplayProducts::default(),
            })
        }
    }

    #[derive(Default)]
    struct RetainedRecoveryExecutor {
        executions: usize,
        recoveries: usize,
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

        fn recover_retained(
            &mut self,
            input: &ReplayInput,
            before: &RuntimeState,
            _position: ReplayPosition,
        ) -> Result<ReplayTransition, Self::Error> {
            self.recoveries += 1;
            let mut state = before.clone();
            state.linear.push(2);
            Ok(ReplayTransition {
                state,
                disposition: ReplayDisposition::Applied,
                next_runtime: input.runtime.clone(),
                products: ReplayProducts::default(),
            })
        }

        fn execute(
            &mut self,
            input: &ReplayInput,
            before: &RuntimeState,
            _position: ReplayPosition,
        ) -> Result<ReplayTransition, Self::Error> {
            self.executions += 1;
            let mut state = before.clone();
            state.linear.push(1);
            Ok(ReplayTransition {
                state,
                disposition: ReplayDisposition::Applied,
                next_runtime: input.runtime.clone(),
                products: ReplayProducts::default(),
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

        fn recover_retained(
            &mut self,
            input: &ReplayInput,
            before: &RuntimeState,
            position: ReplayPosition,
        ) -> Result<ReplayTransition, Self::Error> {
            self.execute(input, before, position)
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
                next_runtime: input.runtime.clone(),
                products: ReplayProducts {
                    durable_actor_reply: true,
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
    fn ownership_tombstones_duplicates_and_divergence_advance_ordered_runtime() {
        let genesis = AgentJournalGenesisId([0x71; 32]);
        let mut machine = ReplayMachine::from_genesis(genesis, runtime()).unwrap();
        let mut executor = RejectingExecutor::default();
        let before = RuntimeState::default();
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
        let owner = machine.ownership.lookup(ordered_key).unwrap().unwrap();
        assert_eq!(owner.result_state, InvocationResultState::Terminal);
        assert_eq!(owner.disposition, InvocationDisposition::Rejected);

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
        let before = RuntimeState::default();
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
    fn retained_retry_executes_recovery_and_commits_its_clock_successor() {
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
                &RuntimeState::default(),
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
            ReplayStepOutcome::Applied(ReplayDisposition::Applied)
        );
        assert_eq!(first.state().linear, vec![1]);

        let retry_id = OrderedEntryId([0x80; 32]);
        let retry = machine
            .apply::<_, ()>(
                &mut executor,
                &invocation,
                first.state(),
                ReplayPosition::Ordered {
                    id: retry_id,
                    index: 2,
                    merge_frontier,
                    merge_seal: None,
                },
            )
            .unwrap();
        assert_eq!(retry.outcome(), ReplayStepOutcome::ExactDuplicate);
        assert_eq!(retry.state().linear, vec![1, 2]);
        assert_eq!(retry.ownership_delta, InvocationIndexDelta::None);
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
        assert_eq!(executor.recoveries, 1);
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
    fn sealed_genesis_initialization_binds_exact_create_closure() {
        let sealed = admitted_genesis(0xc1);
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
            let (_publication, successor, execution) = prepared.publish(&mut store).unwrap();
            assert!(execution.is_none());
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
            let (_publication, successor, _) = prepared.publish(&mut store).unwrap();
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
        let (_publication, checkpointed, _) = checkpoint.publish(&mut store).unwrap();
        assert_eq!(checkpointed.suffix_budget.entries, 0);
        assert_eq!(checkpointed.ordered_snapshots.len(), 1);

        let prepared =
            match prepare_ordered(&mut store, &mut executor, &checkpointed, &overflow).unwrap() {
                ReplayPreparation::Ready(prepared) => prepared,
                ReplayPreparation::AlreadyCommitted(_) => unreachable!(),
            };
        let (_publication, successor, _) = prepared.publish(&mut store).unwrap();
        let reopened =
            materialize_current(&mut store, &mut executor, &NoPrunedOrderedBases).unwrap();
        assert_eq!(reopened.heads(), successor.heads());
        assert_eq!(reopened.suffix_budget.entries, 1);
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
        let execution = prepared.execution().unwrap();
        assert_eq!(
            execution.outcome(),
            ReplayStepOutcome::Applied(ReplayDisposition::Rejected)
        );
        assert!(execution.products().is_empty());
        assert_eq!(execution.input(), ordered.input.id());
        let (_publication, _lost_successor, published_execution) =
            prepared.publish(&mut store).unwrap();
        assert_eq!(published_execution, Some(execution));

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
        let (_publication, successor, _) = prepared.publish(&mut store).unwrap();
        materialized = successor;

        let merge = MergeEvent {
            genesis: materialized.heads().genesis,
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
        let (_publication, _successor, _) = prepared.publish(&mut store).unwrap();
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
            let owner = InvocationOwnership::lookup(
                &indexes,
                InvocationOwnershipKey {
                    scope,
                    invocation: InvocationId([0xd1; 32]),
                },
            )
            .unwrap()
            .unwrap();
            assert_eq!(owner.scope, scope);
            assert_eq!(owner.disposition, InvocationDisposition::Rejected);
            assert_eq!(owner.result_state, InvocationResultState::Terminal);
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
    fn failed_cas_cannot_publish_a_staged_ownership_root() {
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
        let winning =
            match prepare_ordered(&mut store, &mut executor, &base, &winning_entry).unwrap() {
                ReplayPreparation::Ready(prepared) => prepared,
                ReplayPreparation::AlreadyCommitted(_) => unreachable!(),
            };
        let (_publication, winning_state, _) = winning.publish(&mut store).unwrap();
        let durable_after_winner = store.heads().unwrap().unwrap();
        assert_eq!(durable_after_winner, *winning_state.heads());

        assert_eq!(
            losing.publish(&mut store).map(|_| ()),
            Err(crate::agent::journal_store::JournalStoreError::Conflict)
        );
        assert_eq!(store.heads().unwrap().unwrap(), durable_after_winner);

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
    fn concurrent_merge_arrival_is_rebuilt_in_canonical_id_order() {
        let mut store = initialized_replay_store();
        let mut executor = ExactCreateRejectInvocations::default();
        let base = materialize_current(&mut store, &mut executor, &NoPrunedOrderedBases).unwrap();
        let event = |discriminator| MergeEvent {
            genesis: base.heads().genesis,
            author: base.heads().node,
            ordered_base: base.ordered_base(),
            causal_height: 1,
            parents: Vec::new(),
            input: admitted_invocation(MethodMode::Merge, discriminator),
            signature: vec![discriminator; ED25519_SIGNATURE_BYTES],
        };
        let left = event(0xf1);
        let right = event(0xf2);
        let (first, second) = if left.id() > right.id() {
            (left, right)
        } else {
            (right, left)
        };

        let first = match prepare_merge(
            &mut store,
            &mut executor,
            &NoPrunedOrderedBases,
            &base,
            &first,
        )
        .unwrap()
        {
            ReplayPreparation::Ready(prepared) => prepared,
            ReplayPreparation::AlreadyCommitted(_) => unreachable!(),
        };
        let (_publication, after_first, _) = first.publish(&mut store).unwrap();
        executor.merge_execution_order.clear();

        let second_id = second.id();
        let first_id = after_first.merge_roots[0].id;
        assert!(second_id < first_id);
        let second = match prepare_merge(
            &mut store,
            &mut executor,
            &NoPrunedOrderedBases,
            &after_first,
            &second,
        )
        .unwrap()
        {
            ReplayPreparation::Ready(prepared) => prepared,
            ReplayPreparation::AlreadyCommitted(_) => unreachable!(),
        };
        assert_eq!(executor.merge_execution_order, vec![second_id, first_id]);
        let (_publication, successor, _) = second.publish(&mut store).unwrap();
        let reopened =
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
    }

    #[cfg(feature = "std")]
    #[test]
    fn empty_checkpoint_accepts_two_concurrent_parentless_merge_roots() {
        let mut store = initialized_replay_store();
        let mut executor = ExactCreateRejectInvocations::default();
        let base = materialize_current(&mut store, &mut executor, &NoPrunedOrderedBases).unwrap();
        let checkpoint = prepare_checkpoint(&mut store, &base).unwrap();
        let (_publication, checkpointed, _) = checkpoint.publish(&mut store).unwrap();
        assert!(checkpointed.merge_boundary_roots.is_empty());

        let root = |discriminator| MergeEvent {
            genesis: checkpointed.heads().genesis,
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
        let (_publication, after_first, _) = first.publish(&mut store).unwrap();
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
        let (_publication, successor, _) = second.publish(&mut store).unwrap();
        let reopened =
            materialize_current(&mut store, &mut executor, &NoPrunedOrderedBases).unwrap();
        assert_eq!(reopened.heads(), successor.heads());
        assert_eq!(reopened.merge_roots.len(), 2);
        assert!(reopened.merge_ancestry.contains(&left.id()));
        assert!(reopened.merge_ancestry.contains(&right.id()));
    }
}
