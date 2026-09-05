//! Bounded crash-safe persistence for canonical Agent lane journals.
//!
//! The journal is input truth. Runtime lane images, Merge seals, and
//! checkpoints are immutable derived objects; only the small `heads` envelope
//! is replaced. A filesystem publication first makes its canonical anchor
//! durable, then fully writes and syncs a private inode before atomically
//! exposing `heads.next`, renames that stage over `heads`, and finally syncs
//! the Agent directory. No recovery path promotes a staged head without
//! decoding it, recomputing its identity, and proving its predecessor.

use std::collections::{BTreeMap, BTreeSet};
#[cfg(target_os = "linux")]
use std::ffi::{CStr, CString};
#[cfg(test)]
use std::fs;
use std::fs::File;
#[cfg(target_os = "linux")]
use std::io::{ErrorKind, Read, Write};
#[cfg(target_os = "linux")]
use std::os::fd::{AsRawFd, FromRawFd as _};
#[cfg(target_os = "linux")]
use std::os::unix::ffi::OsStrExt as _;
#[cfg(target_os = "linux")]
use std::os::unix::fs::{FileExt as UnixFileExt, MetadataExt as _};
use std::path::{Component, Path, PathBuf};
use std::sync::Arc;
use std::sync::atomic::{AtomicU64, Ordering};

#[cfg(target_os = "linux")]
use fs2::FileExt;
#[cfg(all(target_os = "linux", feature = "storage"))]
use redb::Database;

use super::committee::{
    MAX_ROOT_ANCHOR_RECORD_BYTES, MAX_SYSTEM_GENESIS_EVIDENCE_BYTES, RootAnchorRecord,
    SystemAgentGenesisAdmissionRecord, SystemAgentGenesisEvidence,
};
use super::execution::MAX_RUNTIME_STATE_BYTES;
use super::genesis::{AgentGenesisAdmissionRecord, MAX_AGENT_GENESIS_ADMISSION_BYTES};
use super::invocation_history::{
    InvocationHistoryError, InvocationHistoryNode, InvocationHistoryStore,
    InvocationHistoryWritePlan, MAX_INVOCATION_HISTORY_INSERTIONS,
    MAX_INVOCATION_HISTORY_NODE_BYTES, MAX_INVOCATION_HISTORY_PLAN_NODE_BYTES,
    MAX_INVOCATION_HISTORY_PLAN_NODES, MAX_INVOCATION_HISTORY_RETIRED_NODES,
    MAX_INVOCATION_HISTORY_WRITE_PLAN_BYTES,
};
use super::invocation_index::{
    DEFAULT_INVOCATION_INDEX_NODE_LIMIT, InvocationIndexError, InvocationIndexNode,
    InvocationIndexStore, InvocationOutcomeStore, collect_manifest_reachability,
    validate_manifest_root,
};
use super::journal::{
    AgentJournalGenesis, AgentJournalGenesisId, ArtifactClosure, CanonicalJournalRecord,
    CheckpointId, CheckpointManifest, InvocationHistoryNodeId, InvocationIndexId,
    InvocationIndexManifest, InvocationIndexNodeId, InvocationOutcomeAnchor, InvocationOutcomeId,
    InvocationOutcomeRecord, InvocationOwnershipScope, JournalHeads, JournalHeadsId,
    JournalObjectId, JournalStorageClass, LaneCursor, LaneStateId, LaneStateManifest, LocalEntry,
    LocalEntryId, MAX_ARTIFACT_CLOSURE_BYTES, MAX_ARTIFACT_CLOSURE_ENTRIES,
    MAX_ARTIFACT_CLOSURE_REFERENCED_BYTES, MAX_CHECKPOINT_MANIFEST_BYTES,
    MAX_INVOCATION_INDEX_MANIFEST_BYTES, MAX_INVOCATION_INDEX_NODE_BYTES,
    MAX_INVOCATION_OUTCOME_BYTES, MAX_JOURNAL_RECORD_BYTES, MAX_REPLAY_INPUT_BYTES,
    MAX_REPLAY_SUFFIX_BYTES, MAX_REPLAY_SUFFIX_ENTRIES, MergeEvent, MergeEventId, MergeFrontier,
    MergeFrontierId, MergeSeal, MergeSealId, OrderedBase, OrderedEntry, OrderedEntryId,
    PersistedLane, ReplayOperation, system_genesis_post_create_state_commitment,
};
use super::replay::{
    ReplayPublicationAnchor, ReplayPublicationMode, ReplaySealedGenesis, ReplaySealedLocalGenesis,
    ReplaySealedPublication, ReplaySealedSharedMergeProjection, ReplaySystemAuthorityStoragePlan,
    ReplayedRootJournalIdentity,
};
use super::shared_commit::{MAX_ORDERED_COMMIT_CLAIM_BYTES, OrderedCommitClaim};
use super::shared_raft::JournalStoreInstanceId;
use super::standard::StandardSystemAuthorityWrite;
use super::system_authority::{
    MAX_SYSTEM_AUTHORITY_CATALOG_NODE_BYTES, MAX_SYSTEM_AUTHORITY_CATALOG_RECORD_BYTES,
    MAX_SYSTEM_AUTHORITY_CATALOG_RECORDS, MAX_SYSTEM_AUTHORITY_CATALOG_TREE_NODES,
    MAX_SYSTEM_AUTHORITY_COMMITTEE_RECORD_BYTES, MAX_SYSTEM_AUTHORITY_DECISION_NODE_BYTES,
    MAX_SYSTEM_AUTHORITY_DECISION_TREE_NODES, MAX_SYSTEM_AUTHORITY_ROTATION_NODE_BYTES,
    MAX_SYSTEM_AUTHORITY_ROTATION_TREE_NODES, MAX_SYSTEM_AUTHORITY_ROTATIONS,
    SystemAuthorityCatalogNode, SystemAuthorityCatalogNodeId, SystemAuthorityCatalogRecord,
    SystemAuthorityCatalogRecordId, SystemAuthorityCommitteeId, SystemAuthorityCommitteeRecord,
    SystemAuthorityDecisionNode, SystemAuthorityDecisionNodeId, SystemAuthorityRotationNode,
    SystemAuthorityRotationNodeId, prove_catalog, prove_rotation,
};
#[cfg(all(target_os = "linux", feature = "storage"))]
use super::system_authority_ledger::{SystemAuthorityLedgerError, SystemAuthorityLedgerRouteOwner};
use super::wire::{RuntimeState, decode_standard_runtime_state};
use super::{LifecycleReply, LifecycleRequest};
use crate::service::wire::{DecodeError, Decoder, Encoder, ServiceWire};
use crate::service::{AgentId, BlobRef, Hash, NodeId};

/// Result of one idempotent journal publication.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct JournalPublication {
    /// At least one immutable publication anchor/closure object was created.
    pub object_created: bool,
    /// The durable head pointer changed. This is false for an exact retry
    /// after an ambiguous successful publication.
    pub heads_advanced: bool,
}

const MAX_SHARED_ORDERED_COMMIT_BINDING_BYTES: usize = MAX_ORDERED_COMMIT_CLAIM_BYTES + 288;
const MAX_SHARED_ORDERED_COMMIT_BINDINGS: usize = 4_096;
const MAX_SHARED_ORDERED_COMMIT_FILES: usize = 2 * MAX_SHARED_ORDERED_COMMIT_BINDINGS;
const SHARED_ORDERED_COMMIT_DIRECTORY: &str = "shared-ordered-commits";

/// Durable, immutable bridge from a published Agent-journal entry back to the
/// exact Shared Raft authority which selected it.
///
/// This binding deliberately remains outside checkpoint reachability for now:
/// Shared checkpoint/GC must fail closed until it can retain the complete
/// claim/QC audit closure (or a replacement checkpoint certificate).
#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) struct SharedOrderedCommitBinding {
    journal_store: JournalStoreInstanceId,
    entry: OrderedEntryId,
    claim: OrderedCommitClaim,
    raft_payload_commitment: Hash,
}

impl SharedOrderedCommitBinding {
    fn new(
        journal_store: JournalStoreInstanceId,
        entry: OrderedEntryId,
        claim: OrderedCommitClaim,
        raft_payload_commitment: Hash,
    ) -> Result<Self, JournalStoreError> {
        let binding = Self {
            journal_store,
            entry,
            claim,
            raft_payload_commitment,
        };
        binding.validate()?;
        Ok(binding)
    }

    fn validate(&self) -> Result<(), JournalStoreError> {
        if self.entry == OrderedEntryId::ZERO
            || self.claim.validate().is_err()
            || self.claim.ordered().head != Some(self.entry)
            || self.raft_payload_commitment == Hash::ZERO
        {
            Err(JournalStoreError::Corrupt)
        } else {
            Ok(())
        }
    }

    pub(crate) const fn journal_store(&self) -> JournalStoreInstanceId {
        self.journal_store
    }

    pub(crate) const fn entry(&self) -> OrderedEntryId {
        self.entry
    }

    pub(crate) const fn claim(&self) -> &OrderedCommitClaim {
        &self.claim
    }

    pub(crate) const fn raft_payload_commitment(&self) -> Hash {
        self.raft_payload_commitment
    }
}

impl ServiceWire for SharedOrderedCommitBinding {
    const MAGIC: [u8; 4] = *b"AGCB";

    fn encode_body(&self, output: &mut Vec<u8>) {
        let mut encoder = Encoder(output);
        encoder.fixed(self.journal_store.as_bytes());
        encoder.fixed(self.entry.as_bytes());
        encoder.bytes(&self.claim.encode());
        encoder.fixed(&self.raft_payload_commitment.0);
    }

    fn decode_body(decoder: &mut Decoder<'_>) -> Result<Self, DecodeError> {
        let binding = Self {
            journal_store: JournalStoreInstanceId::from_bytes(decoder.fixed()?)
                .ok_or(DecodeError::NonCanonical)?,
            entry: OrderedEntryId(decoder.fixed()?),
            claim: OrderedCommitClaim::decode(&decoder.bytes()?)?,
            raft_payload_commitment: Hash(decoder.fixed()?),
        };
        binding.validate().map_err(|_| DecodeError::NonCanonical)?;
        Ok(binding)
    }
}

fn decode_shared_ordered_commit_binding(
    bytes: &[u8],
    expected: OrderedEntryId,
) -> Result<SharedOrderedCommitBinding, JournalStoreError> {
    if bytes.len() > MAX_SHARED_ORDERED_COMMIT_BINDING_BYTES {
        return Err(JournalStoreError::Corrupt);
    }
    let binding =
        SharedOrderedCommitBinding::decode(bytes).map_err(|_| JournalStoreError::Corrupt)?;
    if binding.entry != expected || binding.encode() != bytes {
        return Err(JournalStoreError::Corrupt);
    }
    binding.validate()?;
    Ok(binding)
}

fn validate_shared_ordered_commit_scope(
    binding: &SharedOrderedCommitBinding,
    heads: &JournalHeads,
    journal_store: JournalStoreInstanceId,
) -> Result<(), JournalStoreError> {
    let claim = binding.claim();
    if binding.journal_store() != journal_store
        || claim.genesis() != heads.genesis
        || claim.admission().as_bytes() != heads.admission.as_bytes()
        || claim.space() != heads.runtime.space
        || claim.agent() != heads.runtime.agent
    {
        Err(JournalStoreError::ScopeMismatch)
    } else {
        Ok(())
    }
}

/// Crate-private authority namespace used only by Shared replay and the
/// sealed publication implementations below. There is intentionally no raw
/// public journal API for installing these bindings.
pub(crate) trait SharedOrderedCommitStore: AgentJournalStore {
    fn shared_ordered_commit(
        &self,
        entry: OrderedEntryId,
    ) -> Result<Option<SharedOrderedCommitBinding>, JournalStoreError>;

    fn persist_shared_ordered_commit(
        &mut self,
        binding: &SharedOrderedCommitBinding,
    ) -> Result<bool, JournalStoreError>;
}

/// Typed, content-addressed persistence for permanent live-system authority
/// history.
///
/// This seam deliberately exposes neither raw bytes nor enumeration. Replay
/// may only install already-validated typed objects and follow authenticated
/// node/committee IDs. These objects are permanent audit history and are not
/// checkpoint-GC candidates.
pub(crate) trait SystemAuthorityHistoryStore: AgentJournalStore {
    fn load_system_authority_decision_node(
        &self,
        id: SystemAuthorityDecisionNodeId,
    ) -> Result<Option<SystemAuthorityDecisionNode>, JournalStoreError>;

    fn persist_system_authority_decision_node(
        &mut self,
        node: &SystemAuthorityDecisionNode,
    ) -> Result<(), JournalStoreError>;

    fn load_system_authority_rotation_node(
        &self,
        id: SystemAuthorityRotationNodeId,
    ) -> Result<Option<SystemAuthorityRotationNode>, JournalStoreError>;

    fn persist_system_authority_rotation_node(
        &mut self,
        node: &SystemAuthorityRotationNode,
    ) -> Result<(), JournalStoreError>;

    fn load_system_authority_catalog_node(
        &self,
        id: SystemAuthorityCatalogNodeId,
    ) -> Result<Option<SystemAuthorityCatalogNode>, JournalStoreError>;

    fn persist_system_authority_catalog_node(
        &mut self,
        node: &SystemAuthorityCatalogNode,
    ) -> Result<(), JournalStoreError>;

    fn load_system_authority_catalog_record(
        &self,
        id: SystemAuthorityCatalogRecordId,
    ) -> Result<Option<SystemAuthorityCatalogRecord>, JournalStoreError>;

    fn persist_system_authority_catalog_record(
        &mut self,
        record: &SystemAuthorityCatalogRecord,
    ) -> Result<(), JournalStoreError>;

    fn load_system_authority_committee_record(
        &self,
        id: SystemAuthorityCommitteeId,
    ) -> Result<Option<SystemAuthorityCommitteeRecord>, JournalStoreError>;

    fn persist_system_authority_committee_record(
        &mut self,
        record: &SystemAuthorityCommitteeRecord,
    ) -> Result<(), JournalStoreError>;
}

/// Private publication path for a replay transition already bound to the
/// exact durable system-authority reservation.
///
/// The public [`AgentJournalStore::publish`] path always rejects a sealed
/// authority write. Only replay's non-clonable prepared holder can call this
/// seam with the independently validated typed dependency closure.
pub(crate) trait SystemAuthorityPublicationStore: SystemAuthorityHistoryStore {
    fn publish_system_authority(
        &mut self,
        publication: &ReplaySealedPublication,
        storage: &ReplaySystemAuthorityStoragePlan,
    ) -> Result<JournalPublication, JournalStoreError>;
}

/// Process-local proof that this store was initialized or reopened from the
/// independently reverified root seal. The identity is never reconstructed
/// from persisted Heads or admission IDs.
pub(crate) trait ReverifiedRootJournalStore: AgentJournalStore {
    fn replayed_root_identity(&self) -> Option<ReplayedRootJournalIdentity>;

    /// Re-establish the final directory durability barrier immediately before
    /// a never-exposed generation is armed. Filesystem stores use this on a
    /// retry whose last initialization rename may have succeeded even though
    /// its directory sync reported failure.
    fn sync_unexposed_generation(&self) -> Result<(), JournalStoreError> {
        Ok(())
    }
}

/// Caller-selected work budget for an explicit authority-history scrub.
///
/// Normal reopen never enumerates these protocol-scale permanent namespaces.
/// An operator may request a bounded streaming scrub separately; exhausting
/// either budget fails closed without retaining a directory-sized buffer.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) struct SystemAuthorityHistoryScrubLimits {
    pub(crate) max_namespace_entries: usize,
    pub(crate) max_file_reads: usize,
    pub(crate) max_bytes_read: u64,
}

/// Completed explicit scrub accounting.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) struct SystemAuthorityHistoryScrubReport {
    pub(crate) namespace_entries: usize,
    pub(crate) private_partial_entries: usize,
    pub(crate) file_reads: usize,
    pub(crate) bytes_read: u64,
    pub(crate) decision_records: usize,
    pub(crate) rotation_records: usize,
    pub(crate) catalog_nodes: usize,
    pub(crate) catalog_records: usize,
    pub(crate) committee_records: usize,
}

/// Explicit work budgets for one checkpoint-governed collection pass.
///
/// The scan bounds apply before a durable intent is installed. Once installed,
/// `max_unlinks_per_run` is a resumable batch size: callers repeat collection
/// with the same expected heads until [`JournalGc::complete`] is true.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) struct GcLimits {
    pub(crate) max_index_nodes: usize,
    pub(crate) max_marked_objects: usize,
    pub(crate) max_marked_blobs: usize,
    pub(crate) max_scanned_files: usize,
    pub(crate) max_scanned_bytes: u64,
    pub(crate) max_unlinks_per_run: usize,
}

/// Result of one bounded garbage-collection pass.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) struct JournalGc {
    pub(crate) objects_removed: usize,
    pub(crate) blobs_removed: usize,
    pub(crate) aliases_removed: usize,
    pub(crate) resumed: bool,
    pub(crate) complete: bool,
}

/// Administrative collection boundary kept separate from normal journal
/// mutation so replay-only store implementations need not expose physical GC.
pub(crate) trait AgentJournalGarbageCollection: AgentJournalStore {
    fn collect_garbage(
        &mut self,
        expected_heads: JournalHeadsId,
        limits: GcLimits,
    ) -> Result<JournalGc, JournalStoreError>;
}

/// Physical namespace for opaque bytes authenticated by a journal manifest.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum JournalBlobClass {
    /// Exact opaque bytes named by [`LaneStateManifest::state`].
    LaneState,
    /// Packages, programs, schemas, policies, and other catalog closure
    /// objects named by [`ArtifactClosure::artifacts`].
    CatalogArtifact,
}

fn blob_maximum(class: JournalBlobClass) -> usize {
    match class {
        JournalBlobClass::LaneState => MAX_RUNTIME_STATE_BYTES,
        JournalBlobClass::CatalogArtifact => MAX_ARTIFACT_CLOSURE_BYTES,
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum JournalStoreError {
    InvalidPath,
    ScopeMismatch,
    DirectoryInUse,
    /// A clean-generation `.agent` directory must never be opened beside the
    /// retired whole-image generation.
    LegacyGeneration,
    NotInitialized,
    Conflict,
    /// A durable collection intent gates every journal mutation until its
    /// bounded sweep has been resumed to completion.
    GcPending,
    InvalidClass,
    NonCanonical,
    LimitExceeded,
    /// A bounded authenticated-history retirement backlog must be covered by
    /// a fresh checkpoint and collected before another history publication.
    Backpressure,
    MissingObject,
    Corrupt,
    Unavailable,
}

impl core::fmt::Display for JournalStoreError {
    fn fmt(&self, formatter: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        write!(formatter, "agent journal store: {self:?}")
    }
}

impl std::error::Error for JournalStoreError {}

/// Cloneable read-only capability for catalog artifacts.
///
/// A resolver is intentionally separate from [`AgentJournalStore`]: replay
/// may hold it while the journal itself is mutably borrowed for publication.
/// Implementations must authenticate both the content reference and the
/// storage capability used to obtain the bytes.
pub(crate) trait CatalogBlobResolver: Clone + Send + Sync {
    fn load_catalog(&self, reference: &BlobRef) -> Result<Option<Vec<u8>>, JournalStoreError>;
}

/// Factory for a resolver whose lifetime is independent of a mutable store
/// borrow.
pub(crate) trait CatalogBlobResolverFactory {
    type Resolver: CatalogBlobResolver;

    fn catalog_blob_resolver(&self) -> Result<Self::Resolver, JournalStoreError>;
}

/// Typed persistence boundary shared by Local, Raft, and causal adapters.
///
/// There is deliberately no unbounded enumeration operation. Replay starts
/// from authenticated heads or a checkpoint and follows typed parent IDs.
/// Content objects are never removed through this interface: later garbage
/// collection must first prove that a checkpoint covers the retained suffix.
pub trait AgentJournalStore:
    InvocationOutcomeStore<Error = JournalStoreError>
    + InvocationHistoryStore<Error = JournalStoreError>
{
    /// Stable for one live physical journal slot and different for an
    /// independently constructed or copied store.
    fn instance_id(&self) -> JournalStoreInstanceId;

    /// Install immutable genesis and its empty head envelope. Exact retries
    /// are idempotent. Implementations may durably retain a validated partial
    /// initialization after an I/O failure; retrying this method completes it.
    fn initialize(&mut self, genesis: &ReplaySealedGenesis) -> Result<bool, JournalStoreError>;

    fn genesis(&self) -> Result<Option<AgentJournalGenesis>, JournalStoreError>;

    fn heads(&self) -> Result<Option<JournalHeads>, JournalStoreError>;

    /// Complete deferred crash cleanup after a caller has authenticated the
    /// current materialized heads. In-memory and already-recovered stores are
    /// no-ops; descriptor-backed exposed stores use this boundary so no
    /// repair precedes replay validation.
    fn finish_reverified_open(&mut self) -> Result<(), JournalStoreError> {
        Ok(())
    }

    /// Store one immutable canonical object. Genesis and heads use their
    /// dedicated publication boundaries and are rejected here.
    fn put<R: CanonicalJournalRecord>(&mut self, record: &R) -> Result<bool, JournalStoreError>;

    fn get<R: CanonicalJournalRecord>(&self, id: R::Id) -> Result<Option<R>, JournalStoreError>;

    /// Persist bytes before installing any manifest which references them.
    fn put_blob(
        &mut self,
        class: JournalBlobClass,
        reference: &BlobRef,
        bytes: &[u8],
    ) -> Result<bool, JournalStoreError>;

    fn load_blob(
        &self,
        class: JournalBlobClass,
        reference: &BlobRef,
    ) -> Result<Option<Vec<u8>>, JournalStoreError>;

    /// Publish one replay-sealed anchor and its one-step successor head.
    ///
    /// Typed closure objects carried by the token are installed by this call.
    /// The Shared ordered pinned-Merge projection is also installed here as
    /// one sealed blob-before-manifest dependency; other referenced raw blobs
    /// must already be durable through [`Self::put_blob`].
    /// The opaque token can only be minted by exact replay, so callers cannot
    /// ask storage to infer lifecycle, ownership, or checkpoint semantics from
    /// independently assembled records.
    fn publish(
        &mut self,
        publication: &ReplaySealedPublication,
    ) -> Result<JournalPublication, JournalStoreError>;
}

/// Unforgeable authority to remove one catalog blob created while journal
/// heads were exactly `predecessor`. Fields are private to this storage
/// module; callers can only obtain a token from the atomic staging method and
/// must consume it to roll back.
pub(crate) struct UnpublishedCatalogBlob {
    store: JournalStoreInstanceId,
    predecessor: JournalHeadsId,
    reference: BlobRef,
}

/// Crate-private staging transaction used by the Local lifecycle driver.
/// Preexisting content yields no token and can therefore never be deleted by
/// rollback. Memory and pinned-file stores implement the same capability.
pub(crate) trait UnpublishedCatalogBlobStore: AgentJournalStore {
    fn stage_catalog_blob(
        &mut self,
        predecessor: JournalHeadsId,
        reference: &BlobRef,
        bytes: &[u8],
    ) -> Result<Option<UnpublishedCatalogBlob>, JournalStoreError>;

    fn rollback_catalog_blob(
        &mut self,
        token: UnpublishedCatalogBlob,
    ) -> Result<(), JournalStoreError>;
}

const GC_INTENT_NAME: &str = "gc-intent";
const GC_INTENT_STAGE_NAME: &str = "gc-intent.next";
const MAX_GC_INTENT_BYTES: usize = 100;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
struct GcIntent {
    heads: JournalHeadsId,
    checkpoint: CheckpointId,
}

impl GcIntent {
    fn validate(self) -> Result<Self, JournalStoreError> {
        if self.heads == JournalHeadsId::ZERO || self.checkpoint == CheckpointId::ZERO {
            return Err(JournalStoreError::Corrupt);
        }
        Ok(self)
    }
}

impl ServiceWire for GcIntent {
    const MAGIC: [u8; 4] = *b"AGGI";

    fn encode_body(&self, output: &mut Vec<u8>) {
        let mut encoder = Encoder(output);
        encoder.fixed(self.heads.as_bytes());
        encoder.fixed(self.checkpoint.as_bytes());
    }

    fn decode_body(decoder: &mut Decoder<'_>) -> Result<Self, DecodeError> {
        let intent = Self {
            heads: JournalHeadsId(decoder.fixed()?),
            checkpoint: CheckpointId(decoder.fixed()?),
        };
        if intent.heads == JournalHeadsId::ZERO || intent.checkpoint == CheckpointId::ZERO {
            return Err(DecodeError::NonCanonical);
        }
        Ok(intent)
    }
}

fn decode_gc_intent(bytes: &[u8]) -> Result<GcIntent, JournalStoreError> {
    if bytes.len() > MAX_GC_INTENT_BYTES {
        return Err(JournalStoreError::Corrupt);
    }
    let intent = GcIntent::decode(bytes).map_err(|_| JournalStoreError::Corrupt)?;
    if intent.encode() != bytes {
        return Err(JournalStoreError::Corrupt);
    }
    intent.validate()
}

const HISTORY_DIRECTORY: &str = "invocation-history";
const HISTORY_NODES_DIRECTORY: &str = "invocation-history/nodes";
const HISTORY_CANDIDATE_DIRECTORY: &str = "invocation-history/candidate";
const HISTORY_CANDIDATE_INTENT_NAME: &str = "candidate-intent";
const HISTORY_CANDIDATE_INTENT_STAGE_NAME: &str = "candidate-intent.next";
const HISTORY_RETIREMENTS_NAME: &str = "retirements";
const HISTORY_RETIREMENTS_STAGE_NAME: &str = "retirements.next";
const MAX_HISTORY_PUBLICATION_PLANS: usize = 3;
const MAX_HISTORY_RETIREMENT_PUBLICATIONS: usize = 64;
const MAX_HISTORY_RETIREMENT_BACKLOG_IDS: usize = 4 * MAX_INVOCATION_HISTORY_RETIRED_NODES;
const MAX_HISTORY_CANDIDATE_INTENT_BYTES: usize = 4 * 1024 * 1024;
const MAX_HISTORY_RETIREMENT_QUEUE_BYTES: usize = 16 * 1024 * 1024;
const HISTORY_CANDIDATE_DOMAIN: &[u8] = b"vos/agent/journal/history-candidate/v1";
const HISTORY_QUEUE_DOMAIN: &[u8] = b"vos/agent/journal/history-retirement-queue/v1";

fn encode_history_scope(encoder: &mut Encoder<'_>, scope: InvocationOwnershipScope) {
    match scope {
        InvocationOwnershipScope::Ordered => encoder.u8(0),
        InvocationOwnershipScope::Merge => encoder.u8(1),
        InvocationOwnershipScope::Local(node) => {
            encoder.u8(2);
            encoder.fixed(node.as_bytes());
        }
    }
}

fn decode_history_scope(
    decoder: &mut Decoder<'_>,
) -> Result<InvocationOwnershipScope, DecodeError> {
    let scope = match decoder.u8()? {
        0 => InvocationOwnershipScope::Ordered,
        1 => InvocationOwnershipScope::Merge,
        2 => InvocationOwnershipScope::Local(NodeId(decoder.fixed()?)),
        _ => return Err(DecodeError::InvalidTag),
    };
    scope.validate()?;
    Ok(scope)
}

fn encode_history_root(encoder: &mut Encoder<'_>, root: &Option<InvocationHistoryNodeId>) {
    encoder.option(root, |encoder, root| encoder.fixed(root.as_bytes()));
}

fn decode_history_root(
    decoder: &mut Decoder<'_>,
) -> Result<Option<InvocationHistoryNodeId>, DecodeError> {
    decoder.option(|decoder| Ok(InvocationHistoryNodeId(decoder.fixed()?)))
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
struct HistoryRoots {
    ordered: Option<InvocationHistoryNodeId>,
    merge: Option<InvocationHistoryNodeId>,
    local: Option<InvocationHistoryNodeId>,
}

impl HistoryRoots {
    const fn get(self, scope: InvocationOwnershipScope) -> Option<InvocationHistoryNodeId> {
        match scope {
            InvocationOwnershipScope::Ordered => self.ordered,
            InvocationOwnershipScope::Merge => self.merge,
            InvocationOwnershipScope::Local(_) => self.local,
        }
    }

    fn validate(self) -> Result<Self, JournalStoreError> {
        if [self.ordered, self.merge, self.local]
            .into_iter()
            .flatten()
            .any(|root| root == InvocationHistoryNodeId::ZERO)
        {
            Err(JournalStoreError::Corrupt)
        } else {
            Ok(self)
        }
    }

    fn encode_to(&self, encoder: &mut Encoder<'_>) {
        encode_history_root(encoder, &self.ordered);
        encode_history_root(encoder, &self.merge);
        encode_history_root(encoder, &self.local);
    }

    fn decode_from(decoder: &mut Decoder<'_>) -> Result<Self, DecodeError> {
        let roots = Self {
            ordered: decode_history_root(decoder)?,
            merge: decode_history_root(decoder)?,
            local: decode_history_root(decoder)?,
        };
        if [roots.ordered, roots.merge, roots.local]
            .into_iter()
            .flatten()
            .any(|root| root == InvocationHistoryNodeId::ZERO)
        {
            return Err(DecodeError::NonCanonical);
        }
        Ok(roots)
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
struct HistoryRetirementRecord {
    expected_heads: JournalHeadsId,
    next_heads: JournalHeadsId,
    publication_revision: u64,
    expected_roots: HistoryRoots,
    next_roots: HistoryRoots,
    retired_node_ids: Vec<InvocationHistoryNodeId>,
    retired_cursor: u32,
}

impl HistoryRetirementRecord {
    fn validate(&self) -> Result<(), JournalStoreError> {
        self.expected_roots.validate()?;
        self.next_roots.validate()?;
        if self.expected_heads == JournalHeadsId::ZERO
            || self.next_heads == JournalHeadsId::ZERO
            || self.expected_heads == self.next_heads
            || self.publication_revision == 0
            || self.expected_roots == self.next_roots
            || self.retired_node_ids.len() > MAX_INVOCATION_HISTORY_RETIRED_NODES
            || self.retired_cursor as usize > self.retired_node_ids.len()
            || self
                .retired_node_ids
                .iter()
                .any(|id| *id == InvocationHistoryNodeId::ZERO)
            || self
                .retired_node_ids
                .windows(2)
                .any(|pair| pair[0] >= pair[1])
        {
            return Err(JournalStoreError::Corrupt);
        }
        Ok(())
    }

    fn encode_to(&self, encoder: &mut Encoder<'_>) {
        encoder.fixed(self.expected_heads.as_bytes());
        encoder.fixed(self.next_heads.as_bytes());
        encoder.u64(self.publication_revision);
        self.expected_roots.encode_to(encoder);
        self.next_roots.encode_to(encoder);
        encoder.list(&self.retired_node_ids, |encoder, id| {
            encoder.fixed(id.as_bytes())
        });
        encoder.u32(self.retired_cursor);
    }

    fn decode_from(decoder: &mut Decoder<'_>) -> Result<Self, DecodeError> {
        let record = Self {
            expected_heads: JournalHeadsId(decoder.fixed()?),
            next_heads: JournalHeadsId(decoder.fixed()?),
            publication_revision: decoder.u64()?,
            expected_roots: HistoryRoots::decode_from(decoder)?,
            next_roots: HistoryRoots::decode_from(decoder)?,
            retired_node_ids: decoder
                .list(|decoder| Ok(InvocationHistoryNodeId(decoder.fixed()?)))?,
            retired_cursor: decoder.u32()?,
        };
        record.validate().map_err(|_| DecodeError::NonCanonical)?;
        Ok(record)
    }

    fn remaining(&self) -> &[InvocationHistoryNodeId] {
        &self.retired_node_ids[self.retired_cursor as usize..]
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
struct HistoryRetirementQueue {
    genesis: AgentJournalGenesisId,
    node: NodeId,
    records: Vec<HistoryRetirementRecord>,
}

impl HistoryRetirementQueue {
    const fn empty(genesis: AgentJournalGenesisId, node: NodeId) -> Self {
        Self {
            genesis,
            node,
            records: Vec::new(),
        }
    }

    fn validate(&self) -> Result<(), JournalStoreError> {
        if self.genesis == AgentJournalGenesisId::ZERO
            || self.node == NodeId::ZERO
            || self.records.len() > MAX_HISTORY_RETIREMENT_PUBLICATIONS
        {
            return Err(JournalStoreError::Corrupt);
        }
        let mut outstanding = 0usize;
        let mut all_retired = BTreeSet::new();
        for (index, record) in self.records.iter().enumerate() {
            record.validate()?;
            if index != 0 {
                let previous = &self.records[index - 1];
                if previous.publication_revision >= record.publication_revision
                    || previous.next_roots != record.expected_roots
                {
                    return Err(JournalStoreError::Corrupt);
                }
            }
            outstanding = outstanding
                .checked_add(record.remaining().len())
                .ok_or(JournalStoreError::LimitExceeded)?;
            for id in record.remaining() {
                if !all_retired.insert(*id) {
                    return Err(JournalStoreError::Corrupt);
                }
            }
        }
        if outstanding > MAX_HISTORY_RETIREMENT_BACKLOG_IDS {
            return Err(JournalStoreError::Corrupt);
        }
        Ok(())
    }

    fn commitment(&self) -> Hash {
        Hash::digest(HISTORY_QUEUE_DOMAIN, &[&self.encode()])
    }

    fn preflight_append(&self, record: &HistoryRetirementRecord) -> Result<(), JournalStoreError> {
        self.validate()?;
        record.validate()?;
        if let Some(tail) = self.records.last()
            && (tail.publication_revision >= record.publication_revision
                || tail.next_roots != record.expected_roots)
        {
            return Err(JournalStoreError::Corrupt);
        }
        let outstanding = self
            .records
            .iter()
            .try_fold(0usize, |count, record| {
                count.checked_add(record.remaining().len())
            })
            .and_then(|count| count.checked_add(record.remaining().len()))
            .ok_or(JournalStoreError::LimitExceeded)?;
        if self.records.len() == MAX_HISTORY_RETIREMENT_PUBLICATIONS
            || outstanding > MAX_HISTORY_RETIREMENT_BACKLOG_IDS
        {
            return Err(JournalStoreError::Backpressure);
        }
        Ok(())
    }
}

impl ServiceWire for HistoryRetirementQueue {
    const MAGIC: [u8; 4] = *b"IHRQ";

    fn encode_body(&self, output: &mut Vec<u8>) {
        let mut encoder = Encoder(output);
        encoder.fixed(self.genesis.as_bytes());
        encoder.fixed(self.node.as_bytes());
        encoder.list(&self.records, |encoder, record| record.encode_to(encoder));
    }

    fn decode_body(decoder: &mut Decoder<'_>) -> Result<Self, DecodeError> {
        let queue = Self {
            genesis: AgentJournalGenesisId(decoder.fixed()?),
            node: NodeId(decoder.fixed()?),
            records: decoder.list(HistoryRetirementRecord::decode_from)?,
        };
        queue.validate().map_err(|_| DecodeError::NonCanonical)?;
        Ok(queue)
    }
}

fn advance_history_retirement_queue(
    queue: &HistoryRetirementQueue,
    maximum_ids: usize,
) -> Result<(HistoryRetirementQueue, Vec<InvocationHistoryNodeId>), JournalStoreError> {
    queue.validate()?;
    let mut next = queue.clone();
    let mut ids = Vec::new();
    loop {
        let Some(record) = next.records.first_mut() else {
            break;
        };
        if record.remaining().is_empty() {
            next.records.remove(0);
            continue;
        }
        if ids.len() == maximum_ids {
            break;
        }
        ids.push(record.remaining()[0]);
        record.retired_cursor += 1;
    }
    next.validate()?;
    Ok((next, ids))
}

fn history_retirement_stage_delta(
    committed: &HistoryRetirementQueue,
    staged: &HistoryRetirementQueue,
) -> Result<Vec<InvocationHistoryNodeId>, JournalStoreError> {
    committed.validate()?;
    staged.validate()?;
    if committed.genesis != staged.genesis || committed.node != staged.node {
        return Err(JournalStoreError::Corrupt);
    }
    if staged.records.len() > committed.records.len() {
        return Err(JournalStoreError::Corrupt);
    }
    let removed = committed.records.len() - staged.records.len();
    let mut ids = Vec::new();
    for record in &committed.records[..removed] {
        ids.extend_from_slice(record.remaining());
    }
    if staged.records.is_empty() {
        return Ok(ids);
    }
    let committed_first = &committed.records[removed];
    let staged_first = &staged.records[0];
    if staged_first.retired_cursor < committed_first.retired_cursor {
        return Err(JournalStoreError::Corrupt);
    }
    let mut expected_first = committed_first.clone();
    expected_first.retired_cursor = staged_first.retired_cursor;
    if expected_first != *staged_first || committed.records[removed + 1..] != staged.records[1..] {
        return Err(JournalStoreError::Corrupt);
    }
    ids.extend_from_slice(
        &committed_first.retired_node_ids
            [committed_first.retired_cursor as usize..staged_first.retired_cursor as usize],
    );
    Ok(ids)
}

#[derive(Clone, Debug, PartialEq, Eq)]
struct HistoryCandidatePlanDescriptor {
    scope: InvocationOwnershipScope,
    hash: Hash,
    encoded_bytes: u64,
}

#[derive(Clone, Debug, PartialEq, Eq)]
struct HistoryCandidateIntent {
    queue_commitment: Hash,
    retirement: HistoryRetirementRecord,
    plans: Vec<HistoryCandidatePlanDescriptor>,
}

impl HistoryCandidateIntent {
    fn validate(&self) -> Result<(), JournalStoreError> {
        self.retirement.validate()?;
        if self.queue_commitment == Hash::ZERO
            || self.plans.is_empty()
            || self.plans.len() > MAX_HISTORY_PUBLICATION_PLANS
            || self
                .plans
                .windows(2)
                .any(|pair| pair[0].scope >= pair[1].scope)
            || self.plans.iter().any(|plan| {
                plan.hash == Hash::ZERO
                    || plan.encoded_bytes == 0
                    || plan.encoded_bytes > MAX_INVOCATION_HISTORY_WRITE_PLAN_BYTES as u64
            })
        {
            return Err(JournalStoreError::Corrupt);
        }
        Ok(())
    }
}

impl ServiceWire for HistoryCandidateIntent {
    const MAGIC: [u8; 4] = *b"IHCI";

    fn encode_body(&self, output: &mut Vec<u8>) {
        let mut encoder = Encoder(output);
        encoder.fixed(self.queue_commitment.as_bytes());
        self.retirement.encode_to(&mut encoder);
        encoder.list(&self.plans, |encoder, plan| {
            encode_history_scope(encoder, plan.scope);
            encoder.fixed(plan.hash.as_bytes());
            encoder.u64(plan.encoded_bytes);
        });
    }

    fn decode_body(decoder: &mut Decoder<'_>) -> Result<Self, DecodeError> {
        let intent = Self {
            queue_commitment: Hash(decoder.fixed()?),
            retirement: HistoryRetirementRecord::decode_from(decoder)?,
            plans: decoder.list(|decoder| {
                Ok(HistoryCandidatePlanDescriptor {
                    scope: decode_history_scope(decoder)?,
                    hash: Hash(decoder.fixed()?),
                    encoded_bytes: decoder.u64()?,
                })
            })?,
        };
        intent.validate().map_err(|_| DecodeError::NonCanonical)?;
        Ok(intent)
    }
}

#[derive(Clone, Debug)]
struct HistoryCandidateOverlay {
    intent: HistoryCandidateIntent,
    plans: Vec<InvocationHistoryWritePlan>,
    nodes: BTreeMap<InvocationHistoryNodeId, Vec<u8>>,
}

fn decode_history_queue(bytes: &[u8]) -> Result<HistoryRetirementQueue, JournalStoreError> {
    if bytes.len() > MAX_HISTORY_RETIREMENT_QUEUE_BYTES {
        return Err(JournalStoreError::Corrupt);
    }
    let queue = HistoryRetirementQueue::decode(bytes).map_err(|_| JournalStoreError::Corrupt)?;
    if queue.encode() != bytes {
        return Err(JournalStoreError::Corrupt);
    }
    queue.validate()?;
    Ok(queue)
}

fn decode_history_candidate_intent(
    bytes: &[u8],
) -> Result<HistoryCandidateIntent, JournalStoreError> {
    if bytes.len() > MAX_HISTORY_CANDIDATE_INTENT_BYTES {
        return Err(JournalStoreError::Corrupt);
    }
    let intent = HistoryCandidateIntent::decode(bytes).map_err(|_| JournalStoreError::Corrupt)?;
    if intent.encode() != bytes {
        return Err(JournalStoreError::Corrupt);
    }
    intent.validate()?;
    Ok(intent)
}

fn decode_history_plan(bytes: &[u8]) -> Result<InvocationHistoryWritePlan, JournalStoreError> {
    if bytes.len() > MAX_INVOCATION_HISTORY_WRITE_PLAN_BYTES {
        return Err(JournalStoreError::Corrupt);
    }
    let plan = InvocationHistoryWritePlan::decode(bytes).map_err(|_| JournalStoreError::Corrupt)?;
    if plan.encode() != bytes {
        return Err(JournalStoreError::Corrupt);
    }
    Ok(plan)
}

fn history_roots_for_heads<S: AgentJournalStore>(
    store: &S,
    heads: &JournalHeads,
) -> Result<HistoryRoots, JournalStoreError> {
    let ordered = require_record::<S, InvocationIndexManifest>(store, heads.ordered_invocations)?;
    let merge = require_record::<S, InvocationIndexManifest>(store, heads.merge_invocations)?;
    let local = require_record::<S, InvocationIndexManifest>(store, heads.local_invocations)?;
    if ordered.genesis != heads.genesis
        || ordered.scope != InvocationOwnershipScope::Ordered
        || merge.genesis != heads.genesis
        || merge.scope != InvocationOwnershipScope::Merge
        || local.genesis != heads.genesis
        || local.scope != InvocationOwnershipScope::Local(heads.node)
    {
        return Err(JournalStoreError::Corrupt);
    }
    HistoryRoots {
        ordered: ordered.history_root,
        merge: merge.history_root,
        local: local.history_root,
    }
    .validate()
}

fn build_history_candidate<S: AgentJournalStore>(
    store: &S,
    current: &JournalHeads,
    next: &JournalHeads,
    plans: &[InvocationHistoryWritePlan],
    queue: &HistoryRetirementQueue,
) -> Result<Option<HistoryCandidateOverlay>, JournalStoreError> {
    let expected_roots = history_roots_for_heads(store, current)?;
    let next_roots = history_roots_for_heads(store, next)?;
    if plans.is_empty() {
        return if expected_roots == next_roots {
            Ok(None)
        } else {
            Err(JournalStoreError::NonCanonical)
        };
    }
    if plans.len() > MAX_HISTORY_PUBLICATION_PLANS
        || plans
            .windows(2)
            .any(|pair| pair[0].scope() >= pair[1].scope())
        || queue.genesis != current.genesis
        || queue.node != current.node
    {
        return Err(JournalStoreError::NonCanonical);
    }

    let mut insertions = 0usize;
    let mut plan_nodes = 0usize;
    let mut plan_node_bytes = 0usize;
    let mut retired = Vec::new();
    let mut overlay_nodes = BTreeMap::new();
    let mut descriptors = Vec::new();
    for plan in plans {
        if plan.genesis() != current.genesis
            || plan.expected_root() != expected_roots.get(plan.scope())
            || plan.root() != next_roots.get(plan.scope())
            || plan.expected_root() == plan.root()
        {
            return Err(JournalStoreError::NonCanonical);
        }
        plan.validate(store).map_err(map_invocation_history_error)?;
        insertions = insertions
            .checked_add(plan.inserted_facts().len())
            .ok_or(JournalStoreError::LimitExceeded)?;
        plan_nodes = plan_nodes
            .checked_add(plan.overlay_nodes().len())
            .ok_or(JournalStoreError::LimitExceeded)?;
        for write in plan.overlay_nodes() {
            plan_node_bytes = plan_node_bytes
                .checked_add(write.bytes().len())
                .ok_or(JournalStoreError::LimitExceeded)?;
            match overlay_nodes.insert(write.id(), write.bytes().to_vec()) {
                Some(existing) if existing != write.bytes() => {
                    return Err(JournalStoreError::Corrupt);
                }
                _ => {}
            }
        }
        retired.extend_from_slice(plan.retired_node_ids());
        let bytes = plan.encode();
        descriptors.push(HistoryCandidatePlanDescriptor {
            scope: plan.scope(),
            hash: Hash::digest(HISTORY_CANDIDATE_DOMAIN, &[&bytes]),
            encoded_bytes: bytes.len() as u64,
        });
    }
    if insertions > MAX_INVOCATION_HISTORY_INSERTIONS
        || plan_nodes > MAX_INVOCATION_HISTORY_PLAN_NODES
        || plan_node_bytes > MAX_INVOCATION_HISTORY_PLAN_NODE_BYTES
    {
        return Err(JournalStoreError::LimitExceeded);
    }
    retired.sort_unstable();
    if retired.len() > MAX_INVOCATION_HISTORY_RETIRED_NODES
        || retired.windows(2).any(|pair| pair[0] == pair[1])
    {
        return Err(JournalStoreError::NonCanonical);
    }
    for scope in [
        InvocationOwnershipScope::Ordered,
        InvocationOwnershipScope::Merge,
        InvocationOwnershipScope::Local(current.node),
    ] {
        let changed = expected_roots.get(scope) != next_roots.get(scope);
        let planned = plans
            .binary_search_by_key(&scope, |plan| plan.scope())
            .is_ok();
        if changed != planned {
            return Err(JournalStoreError::NonCanonical);
        }
    }
    let retirement = HistoryRetirementRecord {
        expected_heads: current.id(),
        next_heads: next.id(),
        publication_revision: next.publication_revision,
        expected_roots,
        next_roots,
        retired_node_ids: retired,
        retired_cursor: 0,
    };
    queue.preflight_append(&retirement)?;
    let intent = HistoryCandidateIntent {
        queue_commitment: queue.commitment(),
        retirement,
        plans: descriptors,
    };
    intent.validate()?;
    Ok(Some(HistoryCandidateOverlay {
        intent,
        plans: plans.to_vec(),
        nodes: overlay_nodes,
    }))
}

fn validate_idempotent_history_plans<S: AgentJournalStore>(
    store: &S,
    current: &JournalHeads,
    plans: &[InvocationHistoryWritePlan],
) -> Result<(), JournalStoreError> {
    let roots = history_roots_for_heads(store, current)?;
    if plans.len() > MAX_HISTORY_PUBLICATION_PLANS
        || plans
            .windows(2)
            .any(|pair| pair[0].scope() >= pair[1].scope())
    {
        return Err(JournalStoreError::NonCanonical);
    }
    for plan in plans {
        if plan.genesis() != current.genesis || plan.root() != roots.get(plan.scope()) {
            return Err(JournalStoreError::NonCanonical);
        }
        for write in plan.overlay_nodes() {
            let bytes = store
                .load_history_node(write.id())?
                .ok_or(JournalStoreError::MissingObject)?;
            if bytes != write.bytes() {
                return Err(JournalStoreError::Corrupt);
            }
        }
    }
    Ok(())
}

fn publication_is_exact_retry(
    current: &JournalHeads,
    expected: JournalHeadsId,
    next: &JournalHeads,
) -> Result<bool, JournalStoreError> {
    if current.id() != expected && current.id() != next.id() {
        return Err(JournalStoreError::Conflict);
    }
    Ok(current.id() == next.id())
}

#[derive(Debug)]
struct GcMark {
    objects: BTreeSet<(JournalStorageClass, [u8; 32])>,
    blobs: BTreeSet<(JournalBlobClass, Hash)>,
    max_objects: usize,
    max_blobs: usize,
}

impl GcMark {
    fn new(limits: GcLimits) -> Self {
        Self {
            objects: BTreeSet::new(),
            blobs: BTreeSet::new(),
            max_objects: limits.max_marked_objects,
            max_blobs: limits.max_marked_blobs,
        }
    }

    fn object<R: CanonicalJournalRecord>(&mut self, id: R::Id) -> Result<(), JournalStoreError> {
        if self.objects.insert((R::STORAGE_CLASS, *id.as_bytes()))
            && self.objects.len() > self.max_objects
        {
            return Err(JournalStoreError::LimitExceeded);
        }
        Ok(())
    }

    fn blob(
        &mut self,
        class: JournalBlobClass,
        reference: &BlobRef,
    ) -> Result<(), JournalStoreError> {
        validate_blob_reference(class, reference)?;
        if self.blobs.insert((class, reference.hash)) && self.blobs.len() > self.max_blobs {
            return Err(JournalStoreError::LimitExceeded);
        }
        Ok(())
    }
}

#[derive(Clone, Debug)]
struct EncodedObject {
    class: JournalStorageClass,
    id: [u8; 32],
    bytes: Vec<u8>,
}

fn class_maximum(class: JournalStorageClass) -> usize {
    match class {
        JournalStorageClass::ReplayInput => MAX_REPLAY_INPUT_BYTES,
        JournalStorageClass::Genesis
        | JournalStorageClass::OrderedEntry
        | JournalStorageClass::LocalEntry
        | JournalStorageClass::MergeEvent => MAX_JOURNAL_RECORD_BYTES,
        JournalStorageClass::ArtifactClosure => MAX_ARTIFACT_CLOSURE_BYTES,
        JournalStorageClass::InvocationIndex => MAX_INVOCATION_INDEX_MANIFEST_BYTES,
        JournalStorageClass::MergeFrontier
        | JournalStorageClass::MergeSeal
        | JournalStorageClass::LaneState
        | JournalStorageClass::Checkpoint
        | JournalStorageClass::Heads => MAX_CHECKPOINT_MANIFEST_BYTES,
        JournalStorageClass::InvocationIndexNode => MAX_INVOCATION_INDEX_NODE_BYTES,
        JournalStorageClass::InvocationOutcome => MAX_INVOCATION_OUTCOME_BYTES,
        JournalStorageClass::InvocationHistoryNode => MAX_INVOCATION_HISTORY_NODE_BYTES,
    }
}

fn supplied_decode_error(error: DecodeError) -> JournalStoreError {
    match error {
        DecodeError::LimitExceeded => JournalStoreError::LimitExceeded,
        _ => JournalStoreError::NonCanonical,
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord)]
enum AuthorityStorageClass {
    RootAnchor,
    GenesisEvidence,
    GenesisAdmission,
    SystemDecision,
    SystemRotation,
    SystemCatalogNode,
    SystemCatalogRecord,
    SystemCommittee,
}

trait CanonicalAuthorityRecord: Clone + PartialEq + ServiceWire {
    const STORAGE_CLASS: AuthorityStorageClass;
    const DIRECTORY: &'static str;
    const MAXIMUM: usize;

    fn storage_id(&self) -> [u8; 32];
}

impl CanonicalAuthorityRecord for RootAnchorRecord {
    const STORAGE_CLASS: AuthorityStorageClass = AuthorityStorageClass::RootAnchor;
    const DIRECTORY: &'static str = "authority/root-anchors";
    const MAXIMUM: usize = MAX_ROOT_ANCHOR_RECORD_BYTES;

    fn storage_id(&self) -> [u8; 32] {
        *self.id().as_bytes()
    }
}

impl CanonicalAuthorityRecord for SystemAgentGenesisEvidence {
    const STORAGE_CLASS: AuthorityStorageClass = AuthorityStorageClass::GenesisEvidence;
    const DIRECTORY: &'static str = "authority/genesis-evidence";
    const MAXIMUM: usize = MAX_SYSTEM_GENESIS_EVIDENCE_BYTES;

    fn storage_id(&self) -> [u8; 32] {
        *self.id().as_bytes()
    }
}

impl CanonicalAuthorityRecord for AgentGenesisAdmissionRecord {
    const STORAGE_CLASS: AuthorityStorageClass = AuthorityStorageClass::GenesisAdmission;
    const DIRECTORY: &'static str = "authority/genesis-admissions";
    const MAXIMUM: usize = MAX_AGENT_GENESIS_ADMISSION_BYTES;

    fn storage_id(&self) -> [u8; 32] {
        *self.id().as_bytes()
    }
}

const AUTHORITY_SYSTEM_DECISIONS_DIRECTORY: &str = "authority/system-decisions";
const AUTHORITY_SYSTEM_ROTATIONS_DIRECTORY: &str = "authority/system-rotations";
const AUTHORITY_SYSTEM_CATALOG_NODES_DIRECTORY: &str = "authority/system-catalog-nodes";
const AUTHORITY_SYSTEM_CATALOG_RECORDS_DIRECTORY: &str = "authority/system-catalog-records";
const AUTHORITY_SYSTEM_COMMITTEES_DIRECTORY: &str = "authority/system-committees";
const MAX_SYSTEM_AUTHORITY_COMMITTEE_RECORDS: usize = MAX_SYSTEM_AUTHORITY_ROTATIONS as usize + 1;

impl CanonicalAuthorityRecord for SystemAuthorityDecisionNode {
    const STORAGE_CLASS: AuthorityStorageClass = AuthorityStorageClass::SystemDecision;
    const DIRECTORY: &'static str = AUTHORITY_SYSTEM_DECISIONS_DIRECTORY;
    const MAXIMUM: usize = MAX_SYSTEM_AUTHORITY_DECISION_NODE_BYTES;

    fn storage_id(&self) -> [u8; 32] {
        *self.id().as_bytes()
    }
}

impl CanonicalAuthorityRecord for SystemAuthorityRotationNode {
    const STORAGE_CLASS: AuthorityStorageClass = AuthorityStorageClass::SystemRotation;
    const DIRECTORY: &'static str = AUTHORITY_SYSTEM_ROTATIONS_DIRECTORY;
    const MAXIMUM: usize = MAX_SYSTEM_AUTHORITY_ROTATION_NODE_BYTES;

    fn storage_id(&self) -> [u8; 32] {
        *self.id().as_bytes()
    }
}

impl CanonicalAuthorityRecord for SystemAuthorityCatalogNode {
    const STORAGE_CLASS: AuthorityStorageClass = AuthorityStorageClass::SystemCatalogNode;
    const DIRECTORY: &'static str = AUTHORITY_SYSTEM_CATALOG_NODES_DIRECTORY;
    const MAXIMUM: usize = MAX_SYSTEM_AUTHORITY_CATALOG_NODE_BYTES;

    fn storage_id(&self) -> [u8; 32] {
        *self.id().as_bytes()
    }
}

impl CanonicalAuthorityRecord for SystemAuthorityCatalogRecord {
    const STORAGE_CLASS: AuthorityStorageClass = AuthorityStorageClass::SystemCatalogRecord;
    const DIRECTORY: &'static str = AUTHORITY_SYSTEM_CATALOG_RECORDS_DIRECTORY;
    const MAXIMUM: usize = MAX_SYSTEM_AUTHORITY_CATALOG_RECORD_BYTES;

    fn storage_id(&self) -> [u8; 32] {
        *self.id().as_bytes()
    }
}

impl CanonicalAuthorityRecord for SystemAuthorityCommitteeRecord {
    const STORAGE_CLASS: AuthorityStorageClass = AuthorityStorageClass::SystemCommittee;
    const DIRECTORY: &'static str = AUTHORITY_SYSTEM_COMMITTEES_DIRECTORY;
    const MAXIMUM: usize = MAX_SYSTEM_AUTHORITY_COMMITTEE_RECORD_BYTES;

    fn storage_id(&self) -> [u8; 32] {
        *self.id().as_bytes()
    }
}

fn decode_authority_record<R: CanonicalAuthorityRecord>(
    bytes: &[u8],
    expected: [u8; 32],
) -> Result<R, JournalStoreError> {
    if expected == [0; 32] || bytes.len() > R::MAXIMUM {
        return Err(JournalStoreError::Corrupt);
    }
    let record = R::decode(bytes).map_err(|_| JournalStoreError::Corrupt)?;
    if record.storage_id() != expected || record.encode() != bytes {
        return Err(JournalStoreError::Corrupt);
    }
    Ok(record)
}

fn encode_object<R: CanonicalJournalRecord>(
    record: &R,
) -> Result<EncodedObject, JournalStoreError> {
    record.validate().map_err(supplied_decode_error)?;
    let bytes = record.encode();
    if bytes.len() > class_maximum(R::STORAGE_CLASS) {
        return Err(JournalStoreError::LimitExceeded);
    }
    // Do not trust even an in-memory producer: prove strict round-trip
    // canonicality and rederive its content identity before touching a store.
    let decoded = R::decode(&bytes).map_err(supplied_decode_error)?;
    decoded.validate().map_err(supplied_decode_error)?;
    if decoded.encode() != bytes || decoded.id() != record.id() {
        return Err(JournalStoreError::NonCanonical);
    }
    Ok(EncodedObject {
        class: R::STORAGE_CLASS,
        id: *record.id().as_bytes(),
        bytes,
    })
}

fn decode_object<R: CanonicalJournalRecord>(
    bytes: &[u8],
    expected: R::Id,
) -> Result<R, JournalStoreError> {
    if bytes.len() > class_maximum(R::STORAGE_CLASS) {
        return Err(JournalStoreError::Corrupt);
    }
    let decoded = R::decode(bytes).map_err(|_| JournalStoreError::Corrupt)?;
    decoded.validate().map_err(|_| JournalStoreError::Corrupt)?;
    if decoded.id() != expected || decoded.encode() != bytes {
        return Err(JournalStoreError::Corrupt);
    }
    Ok(decoded)
}

fn ensure_readable_content_class(class: JournalStorageClass) -> Result<(), JournalStoreError> {
    if matches!(
        class,
        JournalStorageClass::Genesis | JournalStorageClass::Heads
    ) {
        Err(JournalStoreError::InvalidClass)
    } else {
        Ok(())
    }
}

fn ensure_writable_content_class(class: JournalStorageClass) -> Result<(), JournalStoreError> {
    if class == JournalStorageClass::InvocationHistoryNode {
        Err(JournalStoreError::InvalidClass)
    } else {
        ensure_readable_content_class(class)
    }
}

fn ensure_publication_class(class: JournalStorageClass) -> Result<(), JournalStoreError> {
    if matches!(
        class,
        JournalStorageClass::OrderedEntry
            | JournalStorageClass::LocalEntry
            | JournalStorageClass::MergeEvent
            | JournalStorageClass::Checkpoint
    ) {
        Ok(())
    } else {
        Err(JournalStoreError::InvalidClass)
    }
}

fn decode_anchor<T: CanonicalJournalRecord, R: CanonicalJournalRecord>(
    anchor: &R,
) -> Result<T, JournalStoreError> {
    T::decode(&anchor.encode()).map_err(|_| JournalStoreError::NonCanonical)
}

fn ordered_base(heads: &JournalHeads) -> OrderedBase {
    OrderedBase {
        index: heads.ordered_index,
        head: heads.ordered_head,
    }
}

fn validate_publication_shape<R: CanonicalJournalRecord>(
    current: &JournalHeads,
    anchor: &R,
    next: &JournalHeads,
) -> Result<(), JournalStoreError> {
    validate_publication_shape_with_mode(current, anchor, next, ReplayPublicationMode::Canonical)
}

fn validate_publication_shape_with_mode<R: CanonicalJournalRecord>(
    current: &JournalHeads,
    anchor: &R,
    next: &JournalHeads,
    mode: ReplayPublicationMode,
) -> Result<(), JournalStoreError> {
    match R::STORAGE_CLASS {
        JournalStorageClass::OrderedEntry => {
            let entry = decode_anchor::<OrderedEntry, _>(anchor)?;
            let entry_base = OrderedBase {
                index: entry.index,
                head: Some(entry.id()),
            };
            let (expected_frontier, expected_merge_invocations, expected_fence, expected_seal) =
                match mode {
                    ReplayPublicationMode::Canonical => {
                        let (fence, seal) = if entry.merge_seal.is_some() {
                            (entry_base, entry.merge_seal)
                        } else {
                            (current.merge_fence, current.merge_seal)
                        };
                        (
                            current.merge_frontier,
                            entry
                                .merge_seal
                                .is_none()
                                .then_some(current.merge_invocations),
                            fence,
                            seal,
                        )
                    }
                    ReplayPublicationMode::SharedOrderedPreserveMerge => {
                        if entry.merge_seal.is_some() {
                            return Err(JournalStoreError::NonCanonical);
                        }
                        (
                            current.merge_frontier,
                            Some(current.merge_invocations),
                            current.merge_fence,
                            current.merge_seal,
                        )
                    }
                    ReplayPublicationMode::SharedOrderedInstallFence => {
                        if entry.merge_seal.is_none() {
                            return Err(JournalStoreError::NonCanonical);
                        }
                        (entry.merge_frontier, None, entry_base, entry.merge_seal)
                    }
                };
            let canonical_frontier = match mode {
                ReplayPublicationMode::Canonical => entry.merge_frontier == current.merge_frontier,
                ReplayPublicationMode::SharedOrderedPreserveMerge
                | ReplayPublicationMode::SharedOrderedInstallFence => true,
            };
            if entry.genesis != current.genesis
                || entry.input.runtime != current.runtime
                || entry.parent != current.ordered_head
                || entry.index
                    != current
                        .ordered_index
                        .checked_add(1)
                        .ok_or(JournalStoreError::LimitExceeded)?
                || !canonical_frontier
                || next.ordered_head != Some(entry.id())
                || next.ordered_index != entry.index
                || next.merge_frontier != expected_frontier
                || next.merge_fence != expected_fence
                || next.merge_seal != expected_seal
                || expected_merge_invocations
                    .is_some_and(|expected| next.merge_invocations != expected)
                || next.local_invocations != current.local_invocations
                || next.local_head != current.local_head
                || next.local_revision != current.local_revision
                || next.checkpoint != current.checkpoint
            {
                return Err(JournalStoreError::NonCanonical);
            }
        }
        JournalStorageClass::LocalEntry => {
            if mode != ReplayPublicationMode::Canonical {
                return Err(JournalStoreError::NonCanonical);
            }
            let entry = decode_anchor::<LocalEntry, _>(anchor)?;
            if entry.genesis != current.genesis
                || entry.input.runtime != current.runtime
                || entry.node != current.node
                || entry.parent != current.local_head
                || entry.revision
                    != current
                        .local_revision
                        .checked_add(1)
                        .ok_or(JournalStoreError::LimitExceeded)?
                || entry.ordered_base != ordered_base(current)
                || entry.merge_frontier != current.merge_frontier
                || next.local_head != Some(entry.id())
                || next.local_revision != entry.revision
                || next.ordered_head != current.ordered_head
                || next.ordered_index != current.ordered_index
                || next.merge_frontier != current.merge_frontier
                || next.merge_fence != current.merge_fence
                || next.merge_seal != current.merge_seal
                || next.runtime != current.runtime
                || next.ordered_invocations != current.ordered_invocations
                || next.merge_invocations != current.merge_invocations
                || next.checkpoint != current.checkpoint
            {
                return Err(JournalStoreError::NonCanonical);
            }
        }
        JournalStorageClass::MergeEvent => {
            if mode != ReplayPublicationMode::Canonical {
                return Err(JournalStoreError::NonCanonical);
            }
            let event = decode_anchor::<MergeEvent, _>(anchor)?;
            if event.genesis != current.genesis
                || event.input.runtime != current.runtime
                || next.ordered_head != current.ordered_head
                || next.ordered_index != current.ordered_index
                || next.merge_frontier == current.merge_frontier
                || next.merge_fence != current.merge_fence
                || next.merge_seal != current.merge_seal
                || next.runtime != current.runtime
                || next.ordered_invocations != current.ordered_invocations
                || next.local_invocations != current.local_invocations
                || next.local_head != current.local_head
                || next.local_revision != current.local_revision
                || next.checkpoint != current.checkpoint
            {
                return Err(JournalStoreError::NonCanonical);
            }
        }
        JournalStorageClass::Checkpoint => {
            if mode != ReplayPublicationMode::Canonical {
                return Err(JournalStoreError::NonCanonical);
            }
            let checkpoint = decode_anchor::<CheckpointManifest, _>(anchor)?;
            if checkpoint.genesis != current.genesis
                || checkpoint.runtime != current.runtime
                || checkpoint.publication_revision != current.publication_revision
                || checkpoint.ordered_head != current.ordered_head
                || checkpoint.ordered_index != current.ordered_index
                || checkpoint.merge_frontier != current.merge_frontier
                || checkpoint.merge_fence != current.merge_fence
                || checkpoint.merge_seal != current.merge_seal
                || checkpoint.ordered_invocations != current.ordered_invocations
                || checkpoint.merge_invocations != current.merge_invocations
                || next.checkpoint != Some(checkpoint.id())
                || next.ordered_head != current.ordered_head
                || next.ordered_index != current.ordered_index
                || next.merge_frontier != current.merge_frontier
                || next.merge_fence != current.merge_fence
                || next.merge_seal != current.merge_seal
                || next.runtime != current.runtime
                || next.ordered_invocations != current.ordered_invocations
                || next.merge_invocations != current.merge_invocations
                || next.local_invocations != current.local_invocations
                || next.local_head != current.local_head
                || next.local_revision != current.local_revision
            {
                return Err(JournalStoreError::NonCanonical);
            }
        }
        _ => return Err(JournalStoreError::InvalidClass),
    }
    Ok(())
}

fn validate_blob_reference(
    class: JournalBlobClass,
    reference: &BlobRef,
) -> Result<(), JournalStoreError> {
    if reference.hash == Hash::ZERO || reference.len > blob_maximum(class) as u64 {
        return Err(JournalStoreError::LimitExceeded);
    }
    Ok(())
}

fn validate_supplied_blob(
    class: JournalBlobClass,
    reference: &BlobRef,
    bytes: &[u8],
) -> Result<(), JournalStoreError> {
    validate_blob_reference(class, reference)?;
    if reference.len != bytes.len() as u64 || !reference.matches(bytes) {
        return Err(JournalStoreError::NonCanonical);
    }
    Ok(())
}

fn validate_stored_blob(
    class: JournalBlobClass,
    reference: &BlobRef,
    bytes: &[u8],
) -> Result<(), JournalStoreError> {
    if reference.len > blob_maximum(class) as u64
        || reference.len != bytes.len() as u64
        || !reference.matches(bytes)
    {
        return Err(JournalStoreError::Corrupt);
    }
    Ok(())
}

fn genesis_state_component(state: &RuntimeState, lane: PersistedLane) -> &[u8] {
    match lane {
        PersistedLane::Control => &state.control,
        PersistedLane::Linear => &state.linear,
        PersistedLane::Merge => &state.merge,
        PersistedLane::Local => &state.local,
    }
}

/// Phase-one authority dispatch. Root bootstrap is fully reverified here;
/// ordinary `SystemAuthorized` records remain fail-closed until the live
/// system Agent can mint the opaque post-finalization capability required by
/// the ordinary-genesis verifier. A valid unsupported variant is therefore
/// unavailable, not corrupt authority data.
fn phase_one_root_admission(
    admission: &AgentGenesisAdmissionRecord,
) -> Result<&SystemAgentGenesisAdmissionRecord, JournalStoreError> {
    match admission {
        AgentGenesisAdmissionRecord::RootBootstrap(admission) => Ok(admission),
        AgentGenesisAdmissionRecord::SystemAuthorized { .. } => Err(JournalStoreError::Unavailable),
    }
}

struct SealedGenesisShape {
    initial: JournalHeads,
    local_invocations: InvocationIndexManifest,
    lanes: [LaneStateManifest; 4],
}

fn validate_authority_links(
    genesis: &AgentJournalGenesis,
    root: &RootAnchorRecord,
    evidence: &SystemAgentGenesisEvidence,
    admission: &AgentGenesisAdmissionRecord,
) -> Result<(), JournalStoreError> {
    let root_admission = phase_one_root_admission(admission)?;
    let root_id = root.id();
    let evidence_id = evidence.id();
    let admission_id = admission.id();
    decode_authority_record::<RootAnchorRecord>(&root.encode(), *root_id.as_bytes())?;
    decode_authority_record::<SystemAgentGenesisEvidence>(
        &evidence.encode(),
        *evidence_id.as_bytes(),
    )?;
    decode_authority_record::<AgentGenesisAdmissionRecord>(
        &admission.encode(),
        *admission_id.as_bytes(),
    )?;

    let claim = evidence.claim();
    if admission_id != genesis.admission
        || root_admission.root_anchor() != root_id
        || root_admission.root_anchor_config_version() != root.config_version()
        || root_admission.root_anchor_config() != root.config_commitment()
        || root_admission.evidence() != evidence_id
        || root_admission.claim() != claim.authority_claim()
        || claim.root_anchor() != root_id
        || claim.root_anchor_config_version() != root.config_version()
        || claim.root_anchor_config() != root.config_commitment()
        || claim.space() != root.space()
        || claim.system_agent() != root.system_agent()
        || claim.authority_binding() != root.authority_binding()
        || claim.root_certification() != root.root_certification()
        || claim.space() != genesis.runtime().space
        || claim.system_agent() != genesis.runtime().agent
        || claim.genesis_intent()
            != genesis
                .genesis_intent()
                .map_err(|_| JournalStoreError::Corrupt)?
        || claim.runtime_binding() != genesis.runtime().commitment()
        || claim.sequence()
            != genesis
                .genesis_authority_sequence()
                .map_err(|_| JournalStoreError::Corrupt)?
        || evidence
            .certificate()
            .verify(root.initial_committee(), claim.authority_claim())
            .is_err()
    {
        return Err(JournalStoreError::Corrupt);
    }
    Ok(())
}

fn validate_sealed_authority_shape(sealed: &ReplaySealedGenesis) -> Result<(), JournalStoreError> {
    let genesis = sealed.genesis();
    let root = sealed.root_anchor();
    let evidence = sealed.admission_evidence();
    let admission = sealed.admission_record();
    validate_authority_links(genesis, root, evidence, admission)
        .map_err(|_| JournalStoreError::NonCanonical)?;
    let claim = evidence.claim();
    if sealed.admission_commitment() != genesis.admission.as_hash()
        || claim.post_create_state()
            != system_genesis_post_create_state_commitment(sealed.post_create())
                .map_err(|_| JournalStoreError::NonCanonical)?
        || claim.artifact_closure()
            != sealed
                .artifacts()
                .system_genesis_commitment()
                .map_err(|_| JournalStoreError::NonCanonical)?
    {
        return Err(JournalStoreError::NonCanonical);
    }
    Ok(())
}

/// Defensively prove that every storage-visible member of the opaque
/// admission token is the exact clean-generation closure. The token remains
/// the semantic authority: this check deliberately does not re-execute the
/// admitted Create operation or invent a second trust decision in storage.
fn validate_sealed_genesis_shape(
    sealed: &ReplaySealedGenesis,
    agent: AgentId,
    node: NodeId,
) -> Result<SealedGenesisShape, JournalStoreError> {
    validate_sealed_authority_shape(sealed)?;
    let genesis = sealed.genesis();
    encode_object(genesis)?;
    if genesis.runtime().agent != agent || sealed.admission_commitment() == Hash::ZERO {
        return Err(JournalStoreError::ScopeMismatch);
    }

    let post_create = sealed.post_create();
    if post_create
        .encoded_len()
        .is_none_or(|len| len > MAX_RUNTIME_STATE_BYTES)
    {
        return Err(JournalStoreError::LimitExceeded);
    }
    let decoded =
        decode_standard_runtime_state(post_create).map_err(|_| JournalStoreError::NonCanonical)?;
    let config = decoded.config.ok_or(JournalStoreError::NonCanonical)?;
    if config.validate().is_err()
        || sealed.replica().node != node
        || !config
            .replicas
            .iter()
            .any(|replica| *replica == sealed.replica())
    {
        return Err(JournalStoreError::ScopeMismatch);
    }

    let expected_frontier = MergeFrontier {
        genesis: genesis.id(),
        events: Vec::new(),
    };
    if sealed.empty_frontier() != &expected_frontier {
        return Err(JournalStoreError::NonCanonical);
    }
    encode_object(sealed.empty_frontier())?;

    let expected_ordered =
        InvocationIndexManifest::empty(genesis.id(), InvocationOwnershipScope::Ordered);
    let expected_merge =
        InvocationIndexManifest::empty(genesis.id(), InvocationOwnershipScope::Merge);
    let local_invocations = sealed.local_invocations().clone();
    if sealed.ordered_invocations() != &expected_ordered
        || sealed.merge_invocations() != &expected_merge
        || local_invocations
            != InvocationIndexManifest::empty(genesis.id(), InvocationOwnershipScope::Local(node))
    {
        return Err(JournalStoreError::NonCanonical);
    }
    encode_object(sealed.ordered_invocations())?;
    encode_object(sealed.merge_invocations())?;
    encode_object(&local_invocations)?;

    let artifacts = sealed.artifacts();
    encode_object(artifacts)?;
    if artifacts.genesis != genesis.id()
        || !artifacts
            .artifacts
            .iter()
            .any(|artifact| artifact == &genesis.runtime().package)
    {
        return Err(JournalStoreError::NonCanonical);
    }

    let lanes = [
        sealed.lane_manifest(PersistedLane::Control),
        sealed.lane_manifest(PersistedLane::Linear),
        sealed.lane_manifest(PersistedLane::Merge),
        sealed.lane_manifest(PersistedLane::Local),
    ];
    for lane in &lanes {
        encode_object(lane)?;
        let bytes = genesis_state_component(post_create, lane.lane);
        if lane.genesis != genesis.id()
            || lane.runtime != *genesis.runtime()
            || lane.state != BlobRef::of_bytes(bytes)
        {
            return Err(JournalStoreError::NonCanonical);
        }
    }

    let initial = sealed.initial_heads();
    encode_object(&initial)?;
    if initial
        != JournalHeads::initial(
            genesis.id(),
            genesis.admission,
            node,
            sealed.empty_frontier().id(),
            genesis.runtime().clone(),
        )
        || initial.ordered_invocations != sealed.ordered_invocations().id()
        || initial.merge_invocations != sealed.merge_invocations().id()
        || initial.local_invocations != local_invocations.id()
    {
        return Err(JournalStoreError::NonCanonical);
    }

    Ok(SealedGenesisShape {
        initial,
        local_invocations,
        lanes,
    })
}

/// Validate the storage-visible closure of an opaque ordinary-Local genesis
/// seal.  Authority is deliberately different from root bootstrap: the seal
/// has already crossed the live receipt/package trust boundary, and storage
/// proves its exact derived admission rather than looking for a system
/// authority ledger owner.
fn validate_sealed_local_genesis_shape(
    sealed: &ReplaySealedLocalGenesis,
    agent: AgentId,
    node: NodeId,
) -> Result<SealedGenesisShape, JournalStoreError> {
    sealed
        .validate()
        .map_err(|_| JournalStoreError::NonCanonical)?;
    let genesis = sealed.genesis();
    encode_object(genesis)?;
    if genesis.runtime().agent != agent
        || sealed.replica().node != node
        || sealed.admission().node() != node
        || sealed.admission_commitment() == Hash::ZERO
    {
        return Err(JournalStoreError::ScopeMismatch);
    }

    let post_create = sealed.post_create();
    if post_create
        .encoded_len()
        .is_none_or(|len| len > MAX_RUNTIME_STATE_BYTES)
    {
        return Err(JournalStoreError::LimitExceeded);
    }
    let decoded =
        decode_standard_runtime_state(post_create).map_err(|_| JournalStoreError::NonCanonical)?;
    let config = decoded.config.ok_or(JournalStoreError::NonCanonical)?;
    if config.validate().is_err()
        || config.identity.profile != super::AgentProfile::Local
        || config.system_authority_genesis.is_some()
        || config.replicas.as_slice() != [sealed.replica()]
    {
        return Err(JournalStoreError::ScopeMismatch);
    }

    let expected_frontier = MergeFrontier {
        genesis: genesis.id(),
        events: Vec::new(),
    };
    if sealed.empty_frontier() != &expected_frontier {
        return Err(JournalStoreError::NonCanonical);
    }
    encode_object(sealed.empty_frontier())?;

    let expected_ordered =
        InvocationIndexManifest::empty(genesis.id(), InvocationOwnershipScope::Ordered);
    let expected_merge =
        InvocationIndexManifest::empty(genesis.id(), InvocationOwnershipScope::Merge);
    let local_invocations = sealed.local_invocations().clone();
    if sealed.ordered_invocations() != &expected_ordered
        || sealed.merge_invocations() != &expected_merge
        || local_invocations
            != InvocationIndexManifest::empty(genesis.id(), InvocationOwnershipScope::Local(node))
    {
        return Err(JournalStoreError::NonCanonical);
    }
    encode_object(sealed.ordered_invocations())?;
    encode_object(sealed.merge_invocations())?;
    encode_object(&local_invocations)?;

    let artifacts = sealed.artifacts();
    encode_object(artifacts)?;
    if artifacts.genesis != genesis.id()
        || !artifacts
            .artifacts
            .iter()
            .any(|artifact| artifact == &genesis.runtime().package)
    {
        return Err(JournalStoreError::NonCanonical);
    }

    let lanes = [
        sealed.lane_manifest(PersistedLane::Control),
        sealed.lane_manifest(PersistedLane::Linear),
        sealed.lane_manifest(PersistedLane::Merge),
        sealed.lane_manifest(PersistedLane::Local),
    ];
    for lane in &lanes {
        encode_object(lane)?;
        let bytes = genesis_state_component(post_create, lane.lane);
        if lane.genesis != genesis.id()
            || lane.runtime != *genesis.runtime()
            || lane.state != BlobRef::of_bytes(bytes)
        {
            return Err(JournalStoreError::NonCanonical);
        }
    }

    let initial = sealed.initial_heads();
    encode_object(&initial)?;
    if initial
        != JournalHeads::initial(
            genesis.id(),
            genesis.admission,
            node,
            sealed.empty_frontier().id(),
            genesis.runtime().clone(),
        )
        || initial.ordered_invocations != sealed.ordered_invocations().id()
        || initial.merge_invocations != sealed.merge_invocations().id()
        || initial.local_invocations != local_invocations.id()
    {
        return Err(JournalStoreError::NonCanonical);
    }

    Ok(SealedGenesisShape {
        initial,
        local_invocations,
        lanes,
    })
}

fn require_record<S, R>(store: &S, id: R::Id) -> Result<R, JournalStoreError>
where
    S: AgentJournalStore,
    R: CanonicalJournalRecord,
{
    store.get::<R>(id)?.ok_or(JournalStoreError::MissingObject)
}

fn require_blob<S: AgentJournalStore>(
    store: &S,
    class: JournalBlobClass,
    reference: &BlobRef,
) -> Result<(), JournalStoreError> {
    if store.load_blob(class, reference)?.is_none() {
        return Err(JournalStoreError::MissingObject);
    }
    Ok(())
}

fn validate_lane_state<S: AgentJournalStore>(
    store: &S,
    id: super::journal::LaneStateId,
) -> Result<LaneStateManifest, JournalStoreError> {
    let manifest = require_record::<S, LaneStateManifest>(store, id)?;
    require_blob(store, JournalBlobClass::LaneState, &manifest.state)?;
    Ok(manifest)
}

fn validate_artifact_closure<S: AgentJournalStore>(
    store: &S,
    id: super::journal::ArtifactClosureId,
    genesis: super::journal::AgentJournalGenesisId,
) -> Result<(), JournalStoreError> {
    let closure = require_record::<S, ArtifactClosure>(store, id)?;
    let referenced_bytes = closure
        .artifacts
        .iter()
        .try_fold(0_u64, |bytes, artifact| bytes.checked_add(artifact.len))
        .ok_or(JournalStoreError::LimitExceeded)?;
    if closure.genesis != genesis
        || closure.artifacts.len() > MAX_ARTIFACT_CLOSURE_ENTRIES
        || referenced_bytes > MAX_ARTIFACT_CLOSURE_REFERENCED_BYTES
    {
        return Err(JournalStoreError::Corrupt);
    }
    for reference in &closure.artifacts {
        require_blob(store, JournalBlobClass::CatalogArtifact, reference)?;
    }
    Ok(())
}

fn validate_invocation_index<S: AgentJournalStore>(
    store: &S,
    id: InvocationIndexId,
    genesis: super::journal::AgentJournalGenesisId,
    scope: InvocationOwnershipScope,
) -> Result<InvocationIndexManifest, JournalStoreError> {
    let manifest = require_record::<S, InvocationIndexManifest>(store, id)?;
    if manifest.genesis != genesis || manifest.scope != scope {
        return Err(JournalStoreError::Corrupt);
    }
    validate_manifest_root(store, id, &manifest).map_err(map_invocation_index_error)?;
    Ok(manifest)
}

fn map_invocation_index_error(error: InvocationIndexError<JournalStoreError>) -> JournalStoreError {
    match error {
        InvocationIndexError::Storage(error) => error,
        InvocationIndexError::MissingManifest(_)
        | InvocationIndexError::MissingNode(_)
        | InvocationIndexError::MissingHistoryNode(_)
        | InvocationIndexError::MissingOutcome(_) => JournalStoreError::MissingObject,
        InvocationIndexError::PathLimit
        | InvocationIndexError::NodeLimit
        | InvocationIndexError::Capacity => JournalStoreError::LimitExceeded,
        InvocationIndexError::CorruptManifest
        | InvocationIndexError::CorruptNode(_)
        | InvocationIndexError::CorruptHistoryNode(_)
        | InvocationIndexError::CorruptOutcome(_)
        | InvocationIndexError::CorruptHistory
        | InvocationIndexError::GenesisMismatch
        | InvocationIndexError::ScopeMismatch
        | InvocationIndexError::SummaryMismatch
        | InvocationIndexError::NonCanonicalTree
        | InvocationIndexError::Cycle
        | InvocationIndexError::SharedNode
        | InvocationIndexError::ObjectCollision
        | InvocationIndexError::StoreViolation
        | InvocationIndexError::Conflict
        | InvocationIndexError::InvalidTransition => JournalStoreError::Corrupt,
    }
}

fn map_invocation_history_error(
    error: InvocationHistoryError<JournalStoreError>,
) -> JournalStoreError {
    match error {
        InvocationHistoryError::Storage(error) => error,
        InvocationHistoryError::MissingNode(_) => JournalStoreError::MissingObject,
        InvocationHistoryError::PathLimit
        | InvocationHistoryError::NodeLimit
        | InvocationHistoryError::PlanLimit => JournalStoreError::LimitExceeded,
        InvocationHistoryError::CorruptNode(_)
        | InvocationHistoryError::GenesisMismatch
        | InvocationHistoryError::ScopeMismatch
        | InvocationHistoryError::SummaryMismatch
        | InvocationHistoryError::NonCanonicalTree
        | InvocationHistoryError::Cycle
        | InvocationHistoryError::ObjectCollision(_)
        | InvocationHistoryError::Conflict
        | InvocationHistoryError::InvalidFact
        | InvocationHistoryError::InvalidPlan => JournalStoreError::Corrupt,
    }
}

fn validate_checkpoint_closure<S: AgentJournalStore>(
    store: &S,
    checkpoint: &CheckpointManifest,
) -> Result<(), JournalStoreError> {
    let genesis = store.genesis()?.ok_or(JournalStoreError::NotInitialized)?;
    if genesis.id() != checkpoint.genesis
        || genesis.admission != checkpoint.admission
        || checkpoint.runtime.space != genesis.runtime().space
        || checkpoint.runtime.agent != genesis.runtime().agent
    {
        return Err(JournalStoreError::Corrupt);
    }
    validate_invocation_index(
        store,
        checkpoint.ordered_invocations,
        checkpoint.genesis,
        InvocationOwnershipScope::Ordered,
    )?;
    validate_invocation_index(
        store,
        checkpoint.merge_invocations,
        checkpoint.genesis,
        InvocationOwnershipScope::Merge,
    )?;
    validate_merge_fence_structure(
        store,
        checkpoint.genesis,
        checkpoint.merge_fence,
        checkpoint.merge_seal,
    )?;
    let closure = require_record::<S, ArtifactClosure>(store, checkpoint.artifacts)?;
    if closure.genesis != checkpoint.genesis
        || !closure
            .artifacts
            .iter()
            .any(|artifact| artifact == &checkpoint.runtime.package)
    {
        return Err(JournalStoreError::Corrupt);
    }
    validate_artifact_closure(store, checkpoint.artifacts, checkpoint.genesis)?;
    if checkpoint.lanes.len() != 4
        || [
            PersistedLane::Control,
            PersistedLane::Linear,
            PersistedLane::Merge,
            PersistedLane::Local,
        ]
        .into_iter()
        .any(|required| {
            checkpoint
                .lanes
                .iter()
                .filter(|lane| lane.lane == required)
                .count()
                != 1
        })
    {
        return Err(JournalStoreError::Corrupt);
    }
    for lane in &checkpoint.lanes {
        let manifest = validate_lane_state(store, lane.state)?;
        if manifest.genesis != checkpoint.genesis
            || manifest.runtime != checkpoint.runtime
            || manifest.lane != lane.lane
        {
            return Err(JournalStoreError::Corrupt);
        }
        match (&lane.lane, &lane.node, &manifest.cursor) {
            (
                PersistedLane::Control | PersistedLane::Linear,
                None,
                LaneCursor::Ordered { base },
            ) if base.index == checkpoint.ordered_index && base.head == checkpoint.ordered_head => {
            }
            (PersistedLane::Merge, None, LaneCursor::Merge { frontier })
                if *frontier == checkpoint.merge_frontier => {}
            (PersistedLane::Local, Some(expected_node), LaneCursor::Local { node, .. })
                if node == expected_node => {}
            _ => return Err(JournalStoreError::Corrupt),
        }
        if let Some(index) = lane.invocations {
            validate_invocation_index(
                store,
                index,
                checkpoint.genesis,
                InvocationOwnershipScope::Local(lane.node.ok_or(JournalStoreError::Corrupt)?),
            )?;
        }
    }
    Ok(())
}

fn validate_checkpoint_publication<S: AgentJournalStore>(
    store: &S,
    current: &JournalHeads,
    checkpoint: &CheckpointManifest,
) -> Result<(), JournalStoreError> {
    if checkpoint.runtime != current.runtime
        || checkpoint.ordered_invocations != current.ordered_invocations
        || checkpoint.merge_invocations != current.merge_invocations
        || checkpoint
            .lanes
            .iter()
            .any(|lane| lane.lane == PersistedLane::Local && lane.node != Some(current.node))
    {
        return Err(JournalStoreError::NonCanonical);
    }
    let local_lane = checkpoint
        .lanes
        .iter()
        .find(|lane| lane.lane == PersistedLane::Local && lane.node == Some(current.node))
        .ok_or(JournalStoreError::NonCanonical)?;
    let manifest = require_record::<S, LaneStateManifest>(store, local_lane.state)?;
    if local_lane.invocations != Some(current.local_invocations)
        || !matches!(
            manifest.cursor,
            LaneCursor::Local { node, revision, head }
                if node == current.node
                    && revision == current.local_revision
                    && head == current.local_head
        )
    {
        return Err(JournalStoreError::NonCanonical);
    }
    validate_checkpoint_closure(store, checkpoint)?;
    Ok(())
}

fn validate_gc_limits(limits: GcLimits) -> Result<(), JournalStoreError> {
    if limits.max_marked_objects == 0
        || limits.max_marked_blobs == 0
        || limits.max_scanned_files == 0
        || limits.max_scanned_bytes == 0
        || limits.max_unlinks_per_run == 0
    {
        return Err(JournalStoreError::LimitExceeded);
    }
    Ok(())
}

fn fresh_gc_checkpoint<S: AgentJournalStore>(
    store: &S,
    expected_heads: JournalHeadsId,
) -> Result<(JournalHeads, CheckpointManifest), JournalStoreError> {
    let heads = store.heads()?.ok_or(JournalStoreError::NotInitialized)?;
    if heads.id() != expected_heads {
        return Err(JournalStoreError::Conflict);
    }
    let checkpoint_id = heads.checkpoint.ok_or(JournalStoreError::Conflict)?;
    let checkpoint = require_record::<S, CheckpointManifest>(store, checkpoint_id)?;
    let next_revision = checkpoint
        .publication_revision
        .checked_add(1)
        .ok_or(JournalStoreError::LimitExceeded)?;
    if checkpoint.id() != checkpoint_id
        || next_revision != heads.publication_revision
        || checkpoint.genesis != heads.genesis
        || checkpoint.admission != heads.admission
        || checkpoint.runtime != heads.runtime
        || checkpoint.ordered_head != heads.ordered_head
        || checkpoint.ordered_index != heads.ordered_index
        || checkpoint.merge_frontier != heads.merge_frontier
        || checkpoint.merge_fence != heads.merge_fence
        || checkpoint.merge_seal != heads.merge_seal
        || checkpoint.ordered_invocations != heads.ordered_invocations
        || checkpoint.merge_invocations != heads.merge_invocations
    {
        return Err(JournalStoreError::Conflict);
    }
    let local = checkpoint
        .lanes
        .iter()
        .find(|lane| lane.lane == PersistedLane::Local)
        .ok_or(JournalStoreError::Corrupt)?;
    let local_state = require_record::<S, LaneStateManifest>(store, local.state)?;
    if local.node != Some(heads.node)
        || local.invocations != Some(heads.local_invocations)
        || !matches!(
            local_state.cursor,
            LaneCursor::Local { node, revision, head }
                if node == heads.node
                    && revision == heads.local_revision
                    && head == heads.local_head
        )
    {
        return Err(JournalStoreError::Conflict);
    }
    for lane in &checkpoint.lanes {
        let state = require_record::<S, LaneStateManifest>(store, lane.state)?;
        let exact_cursor = match (&lane.lane, &state.cursor) {
            (PersistedLane::Control | PersistedLane::Linear, LaneCursor::Ordered { base }) => {
                base.index == heads.ordered_index && base.head == heads.ordered_head
            }
            (PersistedLane::Merge, LaneCursor::Merge { frontier }) => {
                *frontier == heads.merge_frontier
            }
            (
                PersistedLane::Local,
                LaneCursor::Local {
                    node,
                    revision,
                    head,
                },
            ) => {
                *node == heads.node
                    && *revision == heads.local_revision
                    && *head == heads.local_head
            }
            _ => false,
        };
        if !exact_cursor {
            return Err(JournalStoreError::Conflict);
        }
    }
    validate_checkpoint_closure(store, &checkpoint)?;
    validate_head_targets(store, &heads)?;
    Ok((heads, checkpoint))
}

fn mark_catalog_blob<S: AgentJournalStore>(
    store: &S,
    mark: &mut GcMark,
    reference: &BlobRef,
) -> Result<(), JournalStoreError> {
    require_blob(store, JournalBlobClass::CatalogArtifact, reference)?;
    mark.blob(JournalBlobClass::CatalogArtifact, reference)
}

fn mark_lane_state<S: AgentJournalStore>(
    store: &S,
    mark: &mut GcMark,
    id: LaneStateId,
) -> Result<LaneStateManifest, JournalStoreError> {
    let state = validate_lane_state(store, id)?;
    mark.object::<LaneStateManifest>(id)?;
    mark.blob(JournalBlobClass::LaneState, &state.state)?;
    mark_catalog_blob(store, mark, &state.runtime.package)?;
    Ok(state)
}

fn mark_merge_frontier_tips<S: AgentJournalStore>(
    store: &S,
    mark: &mut GcMark,
    genesis: super::journal::AgentJournalGenesisId,
    id: MergeFrontierId,
) -> Result<MergeFrontier, JournalStoreError> {
    let frontier = require_record::<S, MergeFrontier>(store, id)?;
    if frontier.genesis != genesis {
        return Err(JournalStoreError::Corrupt);
    }
    mark.object::<MergeFrontier>(id)?;
    for event_id in &frontier.events {
        let event = require_record::<S, MergeEvent>(store, *event_id)?;
        if event.genesis != genesis {
            return Err(JournalStoreError::Corrupt);
        }
        mark.object::<MergeEvent>(*event_id)?;
        mark_catalog_blob(store, mark, &event.input.runtime.package)?;
    }
    Ok(frontier)
}

fn mark_outcome_anchor<S: AgentJournalStore>(
    store: &S,
    mark: &mut GcMark,
    outcome: &InvocationOutcomeRecord,
) -> Result<(), JournalStoreError> {
    match outcome.anchor {
        InvocationOutcomeAnchor::Ordered { entry } => {
            let entry = require_record::<S, OrderedEntry>(store, entry)?;
            if entry.genesis != outcome.genesis
                || outcome.validate_for(&entry.input).is_err()
                || outcome.key.scope != InvocationOwnershipScope::Ordered
            {
                return Err(JournalStoreError::Corrupt);
            }
            mark.object::<OrderedEntry>(entry.id())?;
            mark_catalog_blob(store, mark, &entry.input.runtime.package)?;
        }
        InvocationOutcomeAnchor::Local { entry } => {
            let entry = require_record::<S, LocalEntry>(store, entry)?;
            let InvocationOwnershipScope::Local(node) = outcome.key.scope else {
                return Err(JournalStoreError::Corrupt);
            };
            if entry.genesis != outcome.genesis
                || entry.node != node
                || outcome.validate_for(&entry.input).is_err()
            {
                return Err(JournalStoreError::Corrupt);
            }
            mark.object::<LocalEntry>(entry.id())?;
            mark_catalog_blob(store, mark, &entry.input.runtime.package)?;
        }
        InvocationOutcomeAnchor::Merge {
            source_event,
            finalizing_entry,
            seal,
        } => {
            let source = require_record::<S, MergeEvent>(store, source_event)?;
            let finalizing = require_record::<S, OrderedEntry>(store, finalizing_entry)?;
            let sealed = require_record::<S, MergeSeal>(store, seal)?;
            let expected_base = OrderedBase {
                index: finalizing
                    .index
                    .checked_sub(1)
                    .ok_or(JournalStoreError::Corrupt)?,
                head: finalizing.parent,
            };
            if outcome.key.scope != InvocationOwnershipScope::Merge
                || source.genesis != outcome.genesis
                || finalizing.genesis != outcome.genesis
                || sealed.genesis != outcome.genesis
                || outcome.validate_for(&source.input).is_err()
                || finalizing.merge_seal != Some(seal)
                || sealed.frontier != finalizing.merge_frontier
                || sealed.ordered_base != expected_base
            {
                return Err(JournalStoreError::Corrupt);
            }
            mark.object::<MergeEvent>(source_event)?;
            mark.object::<OrderedEntry>(finalizing_entry)?;
            mark.object::<MergeSeal>(seal)?;
            mark_catalog_blob(store, mark, &source.input.runtime.package)?;
            mark_catalog_blob(store, mark, &finalizing.input.runtime.package)?;
        }
    }
    Ok(())
}

fn mark_invocation_index<S: AgentJournalStore>(
    store: &S,
    mark: &mut GcMark,
    id: InvocationIndexId,
    genesis: super::journal::AgentJournalGenesisId,
    scope: InvocationOwnershipScope,
    max_nodes: usize,
) -> Result<(), JournalStoreError> {
    let manifest = require_record::<S, InvocationIndexManifest>(store, id)?;
    if manifest.genesis != genesis || manifest.scope != scope {
        return Err(JournalStoreError::Corrupt);
    }
    let reachable = collect_manifest_reachability(store, id, &manifest, max_nodes)
        .map_err(map_invocation_index_error)?;
    mark.object::<InvocationIndexManifest>(id)?;
    for node in reachable.nodes {
        mark.object::<InvocationIndexNode>(node)?;
    }
    for id in reachable.outcomes {
        let outcome = require_record::<S, InvocationOutcomeRecord>(store, id)?;
        if outcome.genesis != genesis {
            return Err(JournalStoreError::Corrupt);
        }
        mark_outcome_anchor(store, mark, &outcome)?;
        mark.object::<InvocationOutcomeRecord>(id)?;
    }
    Ok(())
}

fn build_gc_mark<S: AgentJournalStore>(
    store: &S,
    expected_heads: JournalHeadsId,
    limits: GcLimits,
) -> Result<(GcIntent, GcMark), JournalStoreError> {
    validate_gc_limits(limits)?;
    let (heads, checkpoint) = fresh_gc_checkpoint(store, expected_heads)?;
    let mut mark = GcMark::new(limits);
    mark.object::<CheckpointManifest>(checkpoint.id())?;

    let genesis = store.genesis()?.ok_or(JournalStoreError::NotInitialized)?;
    mark_catalog_blob(store, &mut mark, &genesis.runtime().package)?;
    mark_catalog_blob(store, &mut mark, &heads.runtime.package)?;

    let artifacts = require_record::<S, ArtifactClosure>(store, checkpoint.artifacts)?;
    if artifacts.genesis != heads.genesis {
        return Err(JournalStoreError::Corrupt);
    }
    mark.object::<ArtifactClosure>(checkpoint.artifacts)?;
    for artifact in &artifacts.artifacts {
        mark_catalog_blob(store, &mut mark, artifact)?;
    }
    for lane in &checkpoint.lanes {
        mark_lane_state(store, &mut mark, lane.state)?;
    }

    if let Some(id) = heads.ordered_head {
        let entry = require_record::<S, OrderedEntry>(store, id)?;
        if entry.genesis != heads.genesis || entry.index != heads.ordered_index {
            return Err(JournalStoreError::Corrupt);
        }
        mark.object::<OrderedEntry>(id)?;
        mark_catalog_blob(store, &mut mark, &entry.input.runtime.package)?;
    }
    if let Some(id) = heads.local_head {
        let entry = require_record::<S, LocalEntry>(store, id)?;
        if entry.genesis != heads.genesis
            || entry.node != heads.node
            || entry.revision != heads.local_revision
        {
            return Err(JournalStoreError::Corrupt);
        }
        mark.object::<LocalEntry>(id)?;
        mark_catalog_blob(store, &mut mark, &entry.input.runtime.package)?;
    }
    mark_merge_frontier_tips(store, &mut mark, heads.genesis, heads.merge_frontier)?;
    if heads.merge_fence != OrderedBase::post_genesis() {
        let fence = heads.merge_fence.head.ok_or(JournalStoreError::Corrupt)?;
        let entry = require_record::<S, OrderedEntry>(store, fence)?;
        let seal_id = heads.merge_seal.ok_or(JournalStoreError::Corrupt)?;
        let seal = require_record::<S, MergeSeal>(store, seal_id)?;
        if entry.genesis != heads.genesis
            || entry.index != heads.merge_fence.index
            || entry.merge_seal != Some(seal_id)
            || seal.genesis != heads.genesis
        {
            return Err(JournalStoreError::Corrupt);
        }
        mark.object::<OrderedEntry>(fence)?;
        mark.object::<MergeSeal>(seal_id)?;
        mark_catalog_blob(store, &mut mark, &entry.input.runtime.package)?;
        mark_merge_frontier_tips(store, &mut mark, heads.genesis, seal.frontier)?;
        mark_lane_state(store, &mut mark, seal.merge_state)?;
    }

    mark_invocation_index(
        store,
        &mut mark,
        heads.ordered_invocations,
        heads.genesis,
        InvocationOwnershipScope::Ordered,
        limits.max_index_nodes,
    )?;
    mark_invocation_index(
        store,
        &mut mark,
        heads.merge_invocations,
        heads.genesis,
        InvocationOwnershipScope::Merge,
        limits.max_index_nodes,
    )?;
    mark_invocation_index(
        store,
        &mut mark,
        heads.local_invocations,
        heads.genesis,
        InvocationOwnershipScope::Local(heads.node),
        limits.max_index_nodes,
    )?;

    Ok((
        GcIntent {
            heads: expected_heads,
            checkpoint: checkpoint.id(),
        },
        mark,
    ))
}

fn validate_history_retirement_coverage<S: AgentJournalStore>(
    store: &S,
    expected_heads: JournalHeadsId,
    queue: &HistoryRetirementQueue,
) -> Result<(), JournalStoreError> {
    queue.validate()?;
    if queue.records.is_empty() {
        return Ok(());
    }
    let (heads, checkpoint) = fresh_gc_checkpoint(store, expected_heads)?;
    if queue.genesis != heads.genesis || queue.node != heads.node {
        return Err(JournalStoreError::Corrupt);
    }
    let roots = history_roots_for_heads(store, &heads)?;
    let tail = queue.records.last().ok_or(JournalStoreError::Corrupt)?;
    if tail.next_roots != roots
        || queue
            .records
            .iter()
            .any(|record| record.publication_revision > checkpoint.publication_revision)
    {
        return Err(JournalStoreError::Conflict);
    }
    Ok(())
}

fn ordered_base_is_ancestor<S: AgentJournalStore>(
    store: &S,
    genesis: super::journal::AgentJournalGenesisId,
    ordered_head: Option<super::journal::OrderedEntryId>,
    ordered_index: u64,
    target: OrderedBase,
) -> Result<bool, JournalStoreError> {
    target.validate().map_err(supplied_decode_error)?;
    if target.index > ordered_index {
        return Ok(false);
    }
    let mut id = ordered_head;
    let mut index = ordered_index;
    let mut entries = 0_usize;
    let mut bytes = 0_usize;
    loop {
        if index == target.index {
            return Ok(id == target.head);
        }
        let current_id = id.ok_or(JournalStoreError::Corrupt)?;
        let entry = require_record::<S, OrderedEntry>(store, current_id)?;
        if entry.genesis != genesis || entry.index != index {
            return Err(JournalStoreError::Corrupt);
        }
        entries = entries
            .checked_add(1)
            .ok_or(JournalStoreError::LimitExceeded)?;
        bytes = bytes
            .checked_add(entry.encode().len())
            .ok_or(JournalStoreError::LimitExceeded)?;
        if entries > MAX_REPLAY_SUFFIX_ENTRIES || bytes > MAX_REPLAY_SUFFIX_BYTES {
            return Err(JournalStoreError::LimitExceeded);
        }
        id = entry.parent;
        index = index.checked_sub(1).ok_or(JournalStoreError::Corrupt)?;
    }
}

fn local_base_is_ancestor<S: AgentJournalStore>(
    store: &S,
    genesis: super::journal::AgentJournalGenesisId,
    node: NodeId,
    local_head: Option<LocalEntryId>,
    local_revision: u64,
    target_head: Option<LocalEntryId>,
    target_revision: u64,
) -> Result<bool, JournalStoreError> {
    if target_revision > local_revision
        || (target_revision == 0) != target_head.is_none()
        || target_head == Some(LocalEntryId::ZERO)
    {
        return Ok(false);
    }
    let mut id = local_head;
    let mut revision = local_revision;
    let mut entries = 0_usize;
    let mut bytes = 0_usize;
    loop {
        if revision == target_revision {
            return Ok(id == target_head);
        }
        let current_id = id.ok_or(JournalStoreError::Corrupt)?;
        let entry = require_record::<S, LocalEntry>(store, current_id)?;
        if entry.genesis != genesis || entry.node != node || entry.revision != revision {
            return Err(JournalStoreError::Corrupt);
        }
        entries = entries
            .checked_add(1)
            .ok_or(JournalStoreError::LimitExceeded)?;
        bytes = bytes
            .checked_add(entry.encode().len())
            .ok_or(JournalStoreError::LimitExceeded)?;
        if entries > MAX_REPLAY_SUFFIX_ENTRIES || bytes > MAX_REPLAY_SUFFIX_BYTES {
            return Err(JournalStoreError::LimitExceeded);
        }
        id = entry.parent;
        revision = revision.checked_sub(1).ok_or(JournalStoreError::Corrupt)?;
    }
}

#[derive(Debug)]
struct ValidatedMergeDag {
    events: BTreeMap<MergeEventId, MergeEvent>,
    /// Authenticated retained tips at which parent traversal stops. Their
    /// heights were checked before compaction and are therefore inputs to the
    /// retained suffix, not claims reconstructed from possibly-pruned parents.
    boundary: BTreeSet<MergeEventId>,
}

impl ValidatedMergeDag {
    fn ancestors_of(
        &self,
        roots: &[MergeEventId],
    ) -> Result<BTreeSet<MergeEventId>, JournalStoreError> {
        let mut ancestors = BTreeSet::new();
        let mut stack = Vec::new();
        for root in roots {
            let event = self.events.get(root).ok_or(JournalStoreError::Corrupt)?;
            if !self.boundary.contains(root) {
                stack.extend(event.parents.iter().copied());
            }
        }
        while let Some(id) = stack.pop() {
            if !ancestors.insert(id) {
                continue;
            }
            if self.boundary.contains(&id) {
                continue;
            }
            let event = self.events.get(&id).ok_or(JournalStoreError::Corrupt)?;
            stack.extend(event.parents.iter().copied());
        }
        Ok(ancestors)
    }

    fn canonical_frontier(
        &self,
        candidates: &[MergeEventId],
    ) -> Result<Vec<MergeEventId>, JournalStoreError> {
        let ancestors = self.ancestors_of(candidates)?;
        let mut frontier = candidates
            .iter()
            .copied()
            .filter(|candidate| !ancestors.contains(candidate))
            .collect::<Vec<_>>();
        frontier.sort_unstable();
        frontier.dedup();
        Ok(frontier)
    }

    fn contains_at_or_below(
        &self,
        roots: &[MergeEventId],
        target: MergeEventId,
    ) -> Result<bool, JournalStoreError> {
        Ok(roots.contains(&target) || self.ancestors_of(roots)?.contains(&target))
    }

    fn every_path_attaches_to(
        &self,
        root: MergeEventId,
        retained: &ValidatedMergeDag,
    ) -> Result<bool, JournalStoreError> {
        let mut seen = BTreeSet::new();
        let mut stack = vec![root];
        while let Some(id) = stack.pop() {
            if retained.events.contains_key(&id) || !seen.insert(id) {
                continue;
            }
            let event = self.events.get(&id).ok_or(JournalStoreError::Corrupt)?;
            if event.parents.is_empty() {
                return Ok(false);
            }
            stack.extend(event.parents.iter().copied());
        }
        Ok(true)
    }
}

fn load_validated_merge_dag<S: AgentJournalStore>(
    store: &S,
    genesis: super::journal::AgentJournalGenesisId,
    roots: &[MergeEventId],
    boundary: &BTreeSet<MergeEventId>,
) -> Result<ValidatedMergeDag, JournalStoreError> {
    let mut events = BTreeMap::new();
    let mut stack = roots.to_vec();
    let mut bytes = 0_usize;
    while let Some(id) = stack.pop() {
        if events.contains_key(&id) {
            continue;
        }
        let event = require_record::<S, MergeEvent>(store, id)?;
        if event.genesis != genesis {
            return Err(JournalStoreError::Corrupt);
        }
        bytes = bytes
            .checked_add(event.encode().len())
            .ok_or(JournalStoreError::LimitExceeded)?;
        if events.len() >= MAX_REPLAY_SUFFIX_ENTRIES || bytes > MAX_REPLAY_SUFFIX_BYTES {
            return Err(JournalStoreError::LimitExceeded);
        }
        if !boundary.contains(&id) {
            stack.extend(event.parents.iter().copied());
        }
        events.insert(id, event);
    }
    if !boundary.iter().all(|id| events.contains_key(id)) {
        return Err(JournalStoreError::Corrupt);
    }
    for (id, event) in &events {
        if boundary.contains(id) {
            continue;
        }
        let expected_height = if event.parents.is_empty() {
            1
        } else {
            event
                .parents
                .iter()
                .map(|parent| {
                    events
                        .get(parent)
                        .map(|event| event.causal_height)
                        .ok_or(JournalStoreError::Corrupt)
                })
                .collect::<Result<Vec<_>, _>>()?
                .into_iter()
                .max()
                .ok_or(JournalStoreError::Corrupt)?
                .checked_add(1)
                .ok_or(JournalStoreError::LimitExceeded)?
        };
        if event.causal_height != expected_height {
            return Err(JournalStoreError::Corrupt);
        }
    }
    Ok(ValidatedMergeDag {
        events,
        boundary: boundary.clone(),
    })
}

fn validate_frontier<S: AgentJournalStore>(
    store: &S,
    frontier: &MergeFrontier,
    boundary: &BTreeSet<MergeEventId>,
) -> Result<ValidatedMergeDag, JournalStoreError> {
    let dag = load_validated_merge_dag(store, frontier.genesis, &frontier.events, boundary)?;
    if dag.canonical_frontier(&frontier.events)? != frontier.events {
        return Err(JournalStoreError::Corrupt);
    }
    Ok(dag)
}

#[derive(Debug)]
struct RetainedMergeBoundary {
    tips: BTreeSet<MergeEventId>,
}

fn retained_merge_boundary<S: AgentJournalStore>(
    store: &S,
    heads: &JournalHeads,
) -> Result<RetainedMergeBoundary, JournalStoreError> {
    // A checkpoint taken after the latest lifecycle fence is the newest
    // authenticated compaction boundary. If the lifecycle fence advanced
    // after that checkpoint, its retained seal is newer instead.
    let boundary_frontier = if let Some(checkpoint_id) = heads.checkpoint {
        let checkpoint = require_record::<S, CheckpointManifest>(store, checkpoint_id)?;
        if checkpoint.genesis != heads.genesis
            || checkpoint.merge_fence.index > heads.merge_fence.index
        {
            return Err(JournalStoreError::Corrupt);
        }
        if checkpoint.merge_fence == heads.merge_fence {
            Some(checkpoint.merge_frontier)
        } else {
            heads
                .merge_seal
                .map(|seal| require_record::<S, MergeSeal>(store, seal))
                .transpose()?
                .map(|seal| seal.frontier)
        }
    } else {
        heads
            .merge_seal
            .map(|seal| require_record::<S, MergeSeal>(store, seal))
            .transpose()?
            .map(|seal| seal.frontier)
    };
    let Some(frontier_id) = boundary_frontier else {
        return Ok(RetainedMergeBoundary {
            tips: BTreeSet::new(),
        });
    };
    let frontier = require_record::<S, MergeFrontier>(store, frontier_id)?;
    if frontier.genesis != heads.genesis {
        return Err(JournalStoreError::Corrupt);
    }
    // Boundary tips themselves remain immutable retained objects. Their
    // internal ancestry may already have been collected, so do not descend.
    let tips = frontier.events.iter().copied().collect::<BTreeSet<_>>();
    validate_frontier(store, &frontier, &tips)?;
    Ok(RetainedMergeBoundary { tips })
}

/// Validate the objects named by a fence, but do not confer ordered ancestry.
/// Ancestry is established by a replay-sealed publication token. On Local
/// cold recovery, the exact checkpoint named by the owned durable descriptor
/// is the transitive trust boundary; Shared mode replaces that trust step
/// with the QC committed by `FenceAncestryEvidence`.
fn validate_merge_fence_structure<S: AgentJournalStore>(
    store: &S,
    genesis: super::journal::AgentJournalGenesisId,
    fence: OrderedBase,
    seal_id: Option<super::journal::MergeSealId>,
) -> Result<(), JournalStoreError> {
    if fence == OrderedBase::post_genesis() {
        return if seal_id.is_none() {
            Ok(())
        } else {
            Err(JournalStoreError::Corrupt)
        };
    }
    let fence_entry =
        require_record::<S, OrderedEntry>(store, fence.head.ok_or(JournalStoreError::Corrupt)?)?;
    let seal_id = seal_id.ok_or(JournalStoreError::Corrupt)?;
    let seal = require_record::<S, MergeSeal>(store, seal_id)?;
    if fence_entry.genesis != genesis
        || fence_entry.index != fence.index
        || fence_entry.merge_seal != Some(seal_id)
        || seal.genesis != genesis
        || seal.frontier != fence_entry.merge_frontier
        || seal.ordered_base
            != (OrderedBase {
                index: fence_entry.index.saturating_sub(1),
                head: fence_entry.parent,
            })
    {
        return Err(JournalStoreError::Corrupt);
    }
    let frontier = require_record::<S, MergeFrontier>(store, seal.frontier)?;
    if frontier.genesis != genesis {
        return Err(JournalStoreError::Corrupt);
    }
    let sealed_tips = frontier.events.iter().copied().collect::<BTreeSet<_>>();
    validate_frontier(store, &frontier, &sealed_tips)?;
    let state = validate_lane_state(store, seal.merge_state)?;
    if state.genesis != genesis
        || state.lane != PersistedLane::Merge
        || !matches!(
            state.cursor,
            LaneCursor::Merge { frontier } if frontier == seal.frontier
        )
    {
        return Err(JournalStoreError::Corrupt);
    }
    Ok(())
}

fn validate_head_targets<S: AgentJournalStore>(
    store: &S,
    heads: &JournalHeads,
) -> Result<(), JournalStoreError> {
    let genesis = store.genesis()?.ok_or(JournalStoreError::NotInitialized)?;
    if genesis.id() != heads.genesis
        || genesis.admission != heads.admission
        || heads.runtime.space != genesis.runtime().space
        || heads.runtime.agent != genesis.runtime().agent
        || genesis.runtime().agent == AgentId::ZERO
    {
        return Err(JournalStoreError::Corrupt);
    }
    require_blob(
        store,
        JournalBlobClass::CatalogArtifact,
        &heads.runtime.package,
    )?;
    validate_invocation_index(
        store,
        heads.ordered_invocations,
        heads.genesis,
        InvocationOwnershipScope::Ordered,
    )?;
    validate_invocation_index(
        store,
        heads.merge_invocations,
        heads.genesis,
        InvocationOwnershipScope::Merge,
    )?;
    validate_invocation_index(
        store,
        heads.local_invocations,
        heads.genesis,
        InvocationOwnershipScope::Local(heads.node),
    )?;

    validate_merge_fence_structure(store, heads.genesis, heads.merge_fence, heads.merge_seal)?;
    if let Some(id) = heads.ordered_head {
        let entry = require_record::<S, OrderedEntry>(store, id)?;
        if entry.genesis != heads.genesis || entry.index != heads.ordered_index {
            return Err(JournalStoreError::Corrupt);
        }
    }
    if let Some(id) = heads.local_head {
        let entry = require_record::<S, LocalEntry>(store, id)?;
        if entry.genesis != heads.genesis
            || entry.node != heads.node
            || entry.revision != heads.local_revision
        {
            return Err(JournalStoreError::Corrupt);
        }
    }
    let (ordered_boundary, local_boundary_head, local_boundary_revision, checkpoint_covers_fence) =
        if let Some(id) = heads.checkpoint {
            let checkpoint = require_record::<S, CheckpointManifest>(store, id)?;
            if checkpoint.genesis != heads.genesis
                || checkpoint.publication_revision >= heads.publication_revision
            {
                return Err(JournalStoreError::Corrupt);
            }
            validate_checkpoint_closure(store, &checkpoint)?;
            let local = checkpoint
                .lanes
                .iter()
                .find(|lane| lane.lane == PersistedLane::Local);
            let (local_head, local_revision) = if let Some(lane) = local {
                if lane.node != Some(heads.node) {
                    return Err(JournalStoreError::Corrupt);
                }
                let state = require_record::<S, LaneStateManifest>(store, lane.state)?;
                match state.cursor {
                    LaneCursor::Local {
                        node,
                        revision,
                        head,
                    } if node == heads.node => (head, revision),
                    _ => return Err(JournalStoreError::Corrupt),
                }
            } else {
                (None, 0)
            };
            (
                OrderedBase {
                    index: checkpoint.ordered_index,
                    head: checkpoint.ordered_head,
                },
                local_head,
                local_revision,
                checkpoint.merge_fence == heads.merge_fence,
            )
        } else {
            (OrderedBase::post_genesis(), None, 0, false)
        };
    if !ordered_base_is_ancestor(
        store,
        heads.genesis,
        heads.ordered_head,
        heads.ordered_index,
        ordered_boundary,
    )? {
        return Err(JournalStoreError::Corrupt);
    }
    if !checkpoint_covers_fence
        && !ordered_base_is_ancestor(
            store,
            heads.genesis,
            heads.ordered_head,
            heads.ordered_index,
            heads.merge_fence,
        )?
    {
        return Err(JournalStoreError::Corrupt);
    }
    if !local_base_is_ancestor(
        store,
        heads.genesis,
        heads.node,
        heads.local_head,
        heads.local_revision,
        local_boundary_head,
        local_boundary_revision,
    )? {
        return Err(JournalStoreError::Corrupt);
    }
    let frontier = require_record::<S, MergeFrontier>(store, heads.merge_frontier)?;
    if frontier.genesis != heads.genesis {
        return Err(JournalStoreError::Corrupt);
    }
    if heads.publication_revision == 0
        && (!frontier.events.is_empty() || heads.merge_seal.is_some())
    {
        return Err(JournalStoreError::Corrupt);
    }
    let boundary = retained_merge_boundary(store, heads)?;
    validate_frontier(store, &frontier, &boundary.tips)?;
    Ok(())
}

fn validate_anchor_dependencies<S, R>(
    store: &S,
    current: &JournalHeads,
    anchor: &R,
    next: &JournalHeads,
) -> Result<(), JournalStoreError>
where
    S: AgentJournalStore,
    R: CanonicalJournalRecord,
{
    if R::STORAGE_CLASS == JournalStorageClass::MergeEvent {
        let event = decode_anchor::<MergeEvent, _>(anchor)?;
        if event.ordered_base.index < current.merge_fence.index
            || event.ordered_base.index > current.ordered_index
        {
            return Err(JournalStoreError::NonCanonical);
        }
        let current_frontier = require_record::<S, MergeFrontier>(store, current.merge_frontier)?;
        let next_frontier = require_record::<S, MergeFrontier>(store, next.merge_frontier)?;
        if current_frontier.genesis != current.genesis || next_frontier.genesis != current.genesis {
            return Err(JournalStoreError::Corrupt);
        }
        let boundary = retained_merge_boundary(store, current)?;
        let current_dag = validate_frontier(store, &current_frontier, &boundary.tips)?;
        let mut candidates = current_frontier.events.clone();
        candidates.push(event.id());
        candidates.sort_unstable();
        candidates.dedup();
        let dag = load_validated_merge_dag(store, current.genesis, &candidates, &boundary.tips)?;
        if !boundary.tips.is_empty() && !dag.every_path_attaches_to(event.id(), &current_dag)? {
            // After a compacting checkpoint or lifecycle seal, every path in
            // an imported branch must terminate in the retained boundary or
            // current suffix. A still-present pre-boundary object is not proof
            // that a pruned internal parent was admissible.
            return Err(JournalStoreError::NonCanonical);
        }
        if dag.contains_at_or_below(&current_frontier.events, event.id())? {
            // An already reachable EventId is an exact no-op and must use the
            // idempotent `next == current` publication path.
            return Err(JournalStoreError::Conflict);
        }
        if dag.canonical_frontier(&candidates)? != next_frontier.events {
            return Err(JournalStoreError::NonCanonical);
        }
    } else if R::STORAGE_CLASS == JournalStorageClass::Checkpoint {
        let checkpoint = decode_anchor::<CheckpointManifest, _>(anchor)?;
        validate_checkpoint_publication(store, current, &checkpoint)?;
    }
    Ok(())
}

fn validate_idempotent_anchor<S, R>(
    store: &S,
    current: &JournalHeads,
    anchor: &R,
) -> Result<(), JournalStoreError>
where
    S: AgentJournalStore,
    R: CanonicalJournalRecord,
{
    let matches = match R::STORAGE_CLASS {
        JournalStorageClass::OrderedEntry => {
            Some(decode_anchor::<OrderedEntry, _>(anchor)?.id()) == current.ordered_head
        }
        JournalStorageClass::LocalEntry => {
            Some(decode_anchor::<LocalEntry, _>(anchor)?.id()) == current.local_head
        }
        JournalStorageClass::Checkpoint => {
            Some(decode_anchor::<CheckpointManifest, _>(anchor)?.id()) == current.checkpoint
        }
        JournalStorageClass::MergeEvent => {
            let event = decode_anchor::<MergeEvent, _>(anchor)?;
            let frontier = require_record::<S, MergeFrontier>(store, current.merge_frontier)?;
            let boundary = retained_merge_boundary(store, current)?;
            let dag = validate_frontier(store, &frontier, &boundary.tips)?;
            dag.contains_at_or_below(&frontier.events, event.id())?
        }
        _ => false,
    };
    if matches {
        Ok(())
    } else {
        Err(JournalStoreError::Conflict)
    }
}

fn validate_sealed_fence_ancestry<S: AgentJournalStore>(
    store: &S,
    publication: &ReplaySealedPublication,
) -> Result<(), JournalStoreError> {
    let current = store.heads()?.ok_or(JournalStoreError::NotInitialized)?;
    let next = publication.next();
    let evidence = publication.fence_ancestry();
    let canonical_head = OrderedBase {
        index: next.ordered_index,
        head: next.ordered_head,
    };
    if current.id() != publication.expected() && current != *next {
        return Err(JournalStoreError::Conflict);
    }
    if next.validate().is_err()
        || !evidence.validate()
        || evidence.genesis() != next.genesis
        || evidence.canonical_head() != canonical_head
        || evidence.fence() != next.merge_fence
        || evidence.commitment() == Hash::ZERO
    {
        return Err(JournalStoreError::NonCanonical);
    }

    match publication.anchor() {
        ReplayPublicationAnchor::Checkpoint(checkpoint) => {
            let sealed = publication
                .checkpoint_validation()
                .ok_or(JournalStoreError::NonCanonical)?;
            if sealed.fence_ancestry() != evidence
                || evidence.checkpoint_base() != canonical_head
                || checkpoint.ordered_index != canonical_head.index
                || checkpoint.ordered_head != canonical_head.head
                || checkpoint.merge_fence != evidence.fence()
            {
                return Err(JournalStoreError::NonCanonical);
            }
        }
        ReplayPublicationAnchor::Ordered(_)
        | ReplayPublicationAnchor::Local(_)
        | ReplayPublicationAnchor::Merge { .. } => {
            if publication.checkpoint_validation().is_some() {
                return Err(JournalStoreError::NonCanonical);
            }
            let replay_boundary = if let Some(checkpoint_id) = current.checkpoint {
                let checkpoint = require_record::<S, CheckpointManifest>(store, checkpoint_id)?;
                if checkpoint.id() != checkpoint_id || checkpoint.genesis != current.genesis {
                    return Err(JournalStoreError::Corrupt);
                }
                OrderedBase {
                    index: checkpoint.ordered_index,
                    head: checkpoint.ordered_head,
                }
            } else {
                OrderedBase::post_genesis()
            };
            if evidence.checkpoint_base() != replay_boundary {
                return Err(JournalStoreError::NonCanonical);
            }
        }
    }
    Ok(())
}

fn validate_shared_merge_projection<'a>(
    publication: &'a ReplaySealedPublication,
) -> Result<Option<&'a ReplaySealedSharedMergeProjection>, JournalStoreError> {
    let projection = publication.shared_merge_projection();
    match publication.mode() {
        ReplayPublicationMode::Canonical => {
            if projection.is_some() {
                return Err(JournalStoreError::NonCanonical);
            }
            Ok(None)
        }
        ReplayPublicationMode::SharedOrderedPreserveMerge
        | ReplayPublicationMode::SharedOrderedInstallFence => {
            let projection = projection.ok_or(JournalStoreError::NonCanonical)?;
            let entry = match publication.anchor() {
                ReplayPublicationAnchor::Ordered(entry) => entry,
                ReplayPublicationAnchor::Local(_)
                | ReplayPublicationAnchor::Merge { .. }
                | ReplayPublicationAnchor::Checkpoint(_) => {
                    return Err(JournalStoreError::NonCanonical);
                }
            };
            let manifest = projection.manifest();
            if entry.validate().is_err()
                || manifest.validate().is_err()
                || entry.genesis != publication.next().genesis
                || publication.next().ordered_head != Some(entry.id())
                || manifest.genesis != entry.genesis
                || manifest.runtime != entry.input.runtime
                || manifest.lane != PersistedLane::Merge
                || !matches!(
                    &manifest.cursor,
                    LaneCursor::Merge { frontier } if *frontier == entry.merge_frontier
                )
            {
                return Err(JournalStoreError::NonCanonical);
            }
            validate_supplied_blob(
                JournalBlobClass::LaneState,
                &manifest.state,
                projection.state(),
            )?;
            Ok(Some(projection))
        }
    }
}

fn validate_shared_ordered_commit(
    publication: &ReplaySealedPublication,
) -> Result<Option<SharedOrderedCommitBinding>, JournalStoreError> {
    let sealed = publication.shared_ordered_commit();
    match publication.mode() {
        ReplayPublicationMode::Canonical => {
            if sealed.is_some() {
                return Err(JournalStoreError::NonCanonical);
            }
            Ok(None)
        }
        ReplayPublicationMode::SharedOrderedPreserveMerge
        | ReplayPublicationMode::SharedOrderedInstallFence => {
            let sealed = sealed.ok_or(JournalStoreError::NonCanonical)?;
            let entry = match publication.anchor() {
                ReplayPublicationAnchor::Ordered(entry) => entry,
                ReplayPublicationAnchor::Local(_)
                | ReplayPublicationAnchor::Merge { .. }
                | ReplayPublicationAnchor::Checkpoint(_) => {
                    return Err(JournalStoreError::NonCanonical);
                }
            };
            let claim = sealed.claim();
            let projection = publication
                .shared_merge_projection()
                .ok_or(JournalStoreError::NonCanonical)?;
            let manifest = projection.manifest();
            let committed = OrderedBase {
                index: entry.index,
                head: Some(entry.id()),
            };
            if claim.validate().is_err()
                || claim.genesis() != entry.genesis
                || claim.admission().as_bytes() != publication.next().admission.as_bytes()
                || claim.ordered() != committed
                || claim.merge_frontier() != entry.merge_frontier
                || claim.merge().manifest() != manifest.id()
                || claim.merge().state() != &manifest.state
                || claim.runtime() != &publication.next().runtime
                || claim.ordered_invocations() != publication.next().ordered_invocations
                || claim.merge_fence() != publication.next().merge_fence
                || claim.merge_seal() != publication.next().merge_seal
                || sealed.raft_payload_commitment() == Hash::ZERO
            {
                return Err(JournalStoreError::NonCanonical);
            }
            SharedOrderedCommitBinding::new(
                sealed.journal_store(),
                entry.id(),
                claim.clone(),
                sealed.raft_payload_commitment(),
            )
            .map(Some)
            .map_err(|_| JournalStoreError::NonCanonical)
        }
    }
}

fn stage_shared_merge_projection<S: AgentJournalStore>(
    store: &mut S,
    publication: &ReplaySealedPublication,
) -> Result<bool, JournalStoreError> {
    let Some(projection) = validate_shared_merge_projection(publication)? else {
        return Ok(false);
    };
    let manifest = projection.manifest();
    let state = projection.state();

    // State bytes become durable before the immutable manifest which names
    // them. Both are read back through the store interface before any anchor
    // or successor head can be installed.
    let mut created = store.put_blob(JournalBlobClass::LaneState, &manifest.state, state)?;
    created |= store.put(manifest)?;
    if store.get::<LaneStateManifest>(manifest.id())?.as_ref() != Some(manifest)
        || store
            .load_blob(JournalBlobClass::LaneState, &manifest.state)?
            .as_deref()
            != Some(state)
    {
        return Err(JournalStoreError::Corrupt);
    }
    Ok(created)
}

fn stage_shared_ordered_commit<S: SharedOrderedCommitStore>(
    store: &mut S,
    binding: &SharedOrderedCommitBinding,
) -> Result<bool, JournalStoreError> {
    let created = store.persist_shared_ordered_commit(binding)?;
    if store.shared_ordered_commit(binding.entry())?.as_ref() != Some(binding) {
        return Err(JournalStoreError::Corrupt);
    }
    Ok(created)
}

fn persist_and_read_back_authority_record<S, R>(
    store: &mut S,
    record: &R,
    load: impl Fn(&S, R::Id) -> Result<Option<R>, JournalStoreError>,
    persist: impl Fn(&mut S, &R) -> Result<(), JournalStoreError>,
) -> Result<bool, JournalStoreError>
where
    S: SystemAuthorityHistoryStore,
    R: Clone + PartialEq,
    R::Id: Copy,
    R: AuthorityRecordId,
{
    let id = record.authority_id();
    let created = load(store, id)?.is_none();
    persist(store, record)?;
    if load(store, id)?.as_ref() != Some(record) {
        return Err(JournalStoreError::Corrupt);
    }
    Ok(created)
}

trait AuthorityRecordId {
    type Id;

    fn authority_id(&self) -> Self::Id;
}

impl AuthorityRecordId for SystemAuthorityDecisionNode {
    type Id = SystemAuthorityDecisionNodeId;

    fn authority_id(&self) -> Self::Id {
        self.id()
    }
}

impl AuthorityRecordId for SystemAuthorityRotationNode {
    type Id = SystemAuthorityRotationNodeId;

    fn authority_id(&self) -> Self::Id {
        self.id()
    }
}

impl AuthorityRecordId for SystemAuthorityCatalogNode {
    type Id = SystemAuthorityCatalogNodeId;

    fn authority_id(&self) -> Self::Id {
        self.id()
    }
}

impl AuthorityRecordId for SystemAuthorityCatalogRecord {
    type Id = SystemAuthorityCatalogRecordId;

    fn authority_id(&self) -> Self::Id {
        self.id()
    }
}

impl AuthorityRecordId for SystemAuthorityCommitteeRecord {
    type Id = SystemAuthorityCommitteeId;

    fn authority_id(&self) -> Self::Id {
        self.id()
    }
}

fn validate_authority_committee_closure(
    records: &[SystemAuthorityCommitteeRecord],
) -> Result<(), JournalStoreError> {
    if records.is_empty() || records.windows(2).any(|pair| pair[0].id() >= pair[1].id()) {
        return Err(JournalStoreError::NonCanonical);
    }
    Ok(())
}

const MAX_SYSTEM_AUTHORITY_CATALOG_PATH_NODES: usize = 257;

fn catalog_outcome_matches_record(
    outcome: super::system_authority::SystemAuthorityCatalogFinalizeOutcome,
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

fn load_catalog_record_required<S: SystemAuthorityHistoryStore>(
    store: &S,
    id: SystemAuthorityCatalogRecordId,
) -> Result<SystemAuthorityCatalogRecord, JournalStoreError> {
    store
        .load_system_authority_catalog_record(id)?
        .ok_or(JournalStoreError::MissingObject)
}

fn prove_stored_catalog<S: SystemAuthorityHistoryStore>(
    store: &S,
    root: SystemAuthorityCatalogNodeId,
    operation: crate::service::OperationId,
) -> Result<super::system_authority::SystemAuthorityCatalogProof, JournalStoreError> {
    prove_catalog(root, operation, |id| {
        store
            .load_system_authority_catalog_node(id)
            .map(|node| node.map(|node| node.encode()))
    })
    .map_err(|_| JournalStoreError::Corrupt)
}

fn stage_system_authority_catalog_dependencies<S: SystemAuthorityHistoryStore>(
    store: &mut S,
    command: &super::system_authority::SystemAuthorityCatalogFinalize,
    record: Option<&SystemAuthorityCatalogRecord>,
    history: &super::system_authority::SystemAuthorityCatalogWritePlan,
    outcome: super::system_authority::SystemAuthorityCatalogFinalizeOutcome,
) -> Result<bool, JournalStoreError> {
    command
        .validate()
        .map_err(|_| JournalStoreError::NonCanonical)?;
    let operation = command.operation_id();
    if outcome.operation() != operation
        || history.previous_root() == SystemAuthorityCatalogNodeId::ZERO
        || history.root() == SystemAuthorityCatalogNodeId::ZERO
        || command
            .proof()
            .root()
            .map_err(|_| JournalStoreError::NonCanonical)?
            != history.previous_root()
    {
        return Err(JournalStoreError::NonCanonical);
    }

    let prior = prove_stored_catalog(store, history.previous_root(), operation)?;
    if &prior != command.proof() {
        return Err(JournalStoreError::Corrupt);
    }

    if !history.inserted() {
        if history.root() != history.previous_root()
            || !history.nodes().is_empty()
            || !history.retired_node_ids().is_empty()
        {
            return Err(JournalStoreError::NonCanonical);
        }
        let occupied = command
            .proof()
            .occupied_record_id()
            .ok_or(JournalStoreError::NonCanonical)?;
        let stored = load_catalog_record_required(store, occupied)?;
        if stored.operation_id() != operation {
            return Err(JournalStoreError::Corrupt);
        }
        return match record {
            Some(record)
                if occupied == record.id()
                    && stored == *record
                    && record.receipt() == command.receipt()
                    && catalog_outcome_matches_record(outcome, record, true) =>
            {
                Ok(false)
            }
            None if outcome.operation_conflicted()
                && outcome.occupied_record_id() == Some(occupied)
                && stored.receipt() != command.receipt() =>
            {
                Ok(false)
            }
            _ => Err(JournalStoreError::NonCanonical),
        };
    }

    let record = record.ok_or(JournalStoreError::NonCanonical)?;
    if command.proof().occupied_record_id().is_some()
        || outcome.operation_conflicted()
        || outcome.exact_retry()
        || record.receipt() != command.receipt()
        || !catalog_outcome_matches_record(outcome, record, false)
        || history.root() == history.previous_root()
        || history.nodes().len() != MAX_SYSTEM_AUTHORITY_CATALOG_PATH_NODES
        || history.retired_node_ids().len() >= MAX_SYSTEM_AUTHORITY_CATALOG_PATH_NODES
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

    // Every displaced path node remains permanent audit history. Prove that
    // the write plan names only already-durable nodes before creating any
    // successor dependency.
    for id in history.retired_node_ids() {
        if store.load_system_authority_catalog_node(*id)?.is_none() {
            return Err(JournalStoreError::MissingObject);
        }
    }

    // The separately addressable receipt precedes the sparse nodes which
    // commit to its ID. This lets conflict and exact-retry recovery resolve
    // an occupied proof without scanning or trusting incoming receipt bytes.
    let mut created = persist_and_read_back_authority_record(
        store,
        record,
        SystemAuthorityHistoryStore::load_system_authority_catalog_record,
        SystemAuthorityHistoryStore::persist_system_authority_catalog_record,
    )?;
    for node in history.nodes() {
        created |= persist_and_read_back_authority_record(
            store,
            node,
            SystemAuthorityHistoryStore::load_system_authority_catalog_node,
            SystemAuthorityHistoryStore::persist_system_authority_catalog_node,
        )?;
    }

    let installed = prove_stored_catalog(store, history.root(), operation)?;
    if installed.occupied_record_id() != Some(record.id()) {
        return Err(JournalStoreError::Corrupt);
    }
    for id in history.retired_node_ids() {
        if store.load_system_authority_catalog_node(*id)?.is_none() {
            return Err(JournalStoreError::Corrupt);
        }
    }
    Ok(created)
}

fn stage_system_authority_dependencies<S: SystemAuthorityPublicationStore>(
    store: &mut S,
    publication: &ReplaySealedPublication,
    storage: &ReplaySystemAuthorityStoragePlan,
) -> Result<bool, JournalStoreError> {
    if publication.mode() != ReplayPublicationMode::Canonical
        || publication.shared_ordered_commit().is_some()
        || publication.shared_merge_projection().is_some()
        || !matches!(publication.anchor(), ReplayPublicationAnchor::Ordered(_))
    {
        return Err(JournalStoreError::NonCanonical);
    }
    let write = publication
        .system_authority_write()
        .ok_or(JournalStoreError::NonCanonical)?;
    if let (
        StandardSystemAuthorityWrite::Catalog { record, history },
        LifecycleReply::CatalogFinalized(outcome),
    ) = (write.selected(), write.result())
    {
        let ReplayPublicationAnchor::Ordered(entry) = publication.anchor() else {
            return Err(JournalStoreError::NonCanonical);
        };
        let ReplayOperation::Management {
            request: LifecycleRequest::FinalizeCatalog(command),
        } = &entry.input.operation
        else {
            return Err(JournalStoreError::NonCanonical);
        };
        let storage_history = storage
            .catalog_history()
            .ok_or(JournalStoreError::NonCanonical)?;
        let record = record.as_ref().ok_or(JournalStoreError::NonCanonical)?;
        let committee_records = storage.committee_records();
        if !history.inserted()
            || storage_history.record() != record
            || storage_history.root() != history.root()
            || committee_records.len() != 1
            || committee_records[0].id().as_bytes() != &record.receipt().certificate().committee().0
            || record
                .verify(
                    command.receipt().fact().intent().binding(),
                    committee_records[0].committee(),
                )
                .is_err()
        {
            return Err(JournalStoreError::NonCanonical);
        }
        let mut created = persist_and_read_back_authority_record(
            store,
            &committee_records[0],
            SystemAuthorityHistoryStore::load_system_authority_committee_record,
            SystemAuthorityHistoryStore::persist_system_authority_committee_record,
        )?;
        created |= stage_system_authority_catalog_dependencies(
            store,
            command,
            Some(record),
            history,
            *outcome,
        )?;
        return Ok(created);
    }
    let rotation_history = storage
        .rotation_history()
        .ok_or(JournalStoreError::NonCanonical)?;
    validate_authority_committee_closure(storage.committee_records())?;

    let mut created = false;
    let exact_retry = match (write.selected(), write.result()) {
        (
            StandardSystemAuthorityWrite::Rotation { record, history },
            LifecycleReply::SystemAuthorityRotated {
                rotation,
                epoch,
                exact_retry,
            },
        ) => {
            if record != rotation_history.record()
                || record.id() != *rotation
                || record.new_epoch() != *epoch
                || history.root() != rotation_history.root()
                || history.previous_root() == SystemAuthorityRotationNodeId::ZERO
                || history.root() == SystemAuthorityRotationNodeId::ZERO
                || history.inserted() == *exact_retry
                || *exact_retry
                || !history.inserted()
                || storage.committee_records().len() != 2
                || storage.committee_records()[0].id()
                    != record.old_committee().min(record.new_committee())
                || storage.committee_records()[1].id()
                    != record.old_committee().max(record.new_committee())
            {
                return Err(JournalStoreError::NonCanonical);
            }
            if history.nodes().is_empty()
                || history
                    .nodes()
                    .windows(2)
                    .any(|pair| pair[0].id() >= pair[1].id())
                || history
                    .nodes()
                    .iter()
                    .all(|node| node.id() != history.root())
                || history
                    .nodes()
                    .iter()
                    .all(|node| node != &SystemAuthorityRotationNode::Leaf(record.clone()))
                || history.committee_records() != storage.committee_records()
            {
                return Err(JournalStoreError::NonCanonical);
            }
            for node in history.nodes() {
                created |= persist_and_read_back_authority_record(
                    store,
                    node,
                    SystemAuthorityHistoryStore::load_system_authority_rotation_node,
                    SystemAuthorityHistoryStore::persist_system_authority_rotation_node,
                )?;
            }
            *exact_retry
        }
        _ => return Err(JournalStoreError::NonCanonical),
    };

    let ReplayPublicationAnchor::Ordered(entry) = publication.anchor() else {
        return Err(JournalStoreError::NonCanonical);
    };
    let ReplayOperation::Management {
        request: LifecycleRequest::RotateSystemAuthority(command),
    } = &entry.input.operation
    else {
        return Err(JournalStoreError::NonCanonical);
    };
    let lookup = prove_rotation(
        rotation_history.root(),
        rotation_history.record().new_epoch(),
        |id| {
            store
                .load_system_authority_rotation_node(id)
                .map(|node| node.map(|node| node.encode()))
        },
    )
    .map_err(|_| JournalStoreError::Corrupt)?;
    if lookup.occupied_record() != Some(rotation_history.record())
        || (exact_retry && lookup.proof() != command.proof())
    {
        return Err(JournalStoreError::Corrupt);
    }

    for record in storage.committee_records() {
        if exact_retry {
            if store
                .load_system_authority_committee_record(record.id())?
                .as_ref()
                != Some(record)
            {
                return Err(JournalStoreError::MissingObject);
            }
        } else {
            created |= persist_and_read_back_authority_record(
                store,
                record,
                SystemAuthorityHistoryStore::load_system_authority_committee_record,
                SystemAuthorityHistoryStore::persist_system_authority_committee_record,
            )?;
        }
    }
    Ok(created)
}

fn stage_sealed_dependencies<S: SharedOrderedCommitStore>(
    store: &mut S,
    publication: &ReplaySealedPublication,
) -> Result<bool, JournalStoreError> {
    validate_sealed_fence_ancestry(store, publication)?;
    // Validate the complete Shared authority/projection pair before either
    // immutable dependency is written. Persistence order then guarantees the
    // pinned projection and replay-derived Raft binding precede head exposure.
    validate_shared_merge_projection(publication)?;
    let shared_commit = validate_shared_ordered_commit(publication)?;
    let mut created = stage_shared_merge_projection(store, publication)?;
    if let Some(binding) = &shared_commit {
        created |= stage_shared_ordered_commit(store, binding)?;
    }
    let mut outcome_ids = BTreeSet::new();
    for sealed in publication.outcomes() {
        let record = sealed.record();
        if !outcome_ids.insert(record.id())
            || record
                .validate_for_genesis(publication.next().genesis, sealed.input())
                .is_err()
        {
            return Err(JournalStoreError::NonCanonical);
        }
        // Exact result bytes must be immutable and readable before a
        // successor invocation-index root which references them can become
        // visible through `heads`.
        created |= store.put(record)?;
    }
    match publication.anchor() {
        ReplayPublicationAnchor::Merge { frontier, .. } => {
            if publication.checkpoint_validation().is_some()
                || frontier.id() != publication.next().merge_frontier
            {
                return Err(JournalStoreError::NonCanonical);
            }
            created |= store.put(frontier)?;
        }
        ReplayPublicationAnchor::Checkpoint(manifest) => {
            let sealed = publication
                .checkpoint_validation()
                .ok_or(JournalStoreError::NonCanonical)?;
            if sealed.manifest() != manifest
                || sealed.artifacts().id() != manifest.artifacts
                || sealed.lanes().len() != manifest.lanes.len()
                || !sealed
                    .lanes()
                    .iter()
                    .zip(&manifest.lanes)
                    .all(|((lane, state), expected)| lane == expected && state.id() == lane.state)
            {
                return Err(JournalStoreError::NonCanonical);
            }
            for (_, state) in sealed.lanes() {
                created |= store.put(state)?;
            }
            created |= store.put(sealed.artifacts())?;
            for (id, index) in sealed.invocation_indexes() {
                if index.id() != *id {
                    return Err(JournalStoreError::NonCanonical);
                }
                created |= store.put(index)?;
            }
        }
        ReplayPublicationAnchor::Ordered(_) | ReplayPublicationAnchor::Local(_) => {
            if publication.checkpoint_validation().is_some() {
                return Err(JournalStoreError::NonCanonical);
            }
        }
    }
    Ok(created)
}

/// Process-local reference implementation used by deterministic replay and
/// storage-adapter tests.
#[derive(Debug)]
pub struct MemoryAgentJournalStore {
    instance_id: JournalStoreInstanceId,
    agent: AgentId,
    node: NodeId,
    genesis_admission: Option<Hash>,
    genesis: Option<Vec<u8>>,
    heads: Option<Vec<u8>>,
    authority: BTreeMap<(AuthorityStorageClass, [u8; 32]), Vec<u8>>,
    shared_ordered_commits: BTreeMap<OrderedEntryId, Vec<u8>>,
    objects: BTreeMap<(JournalStorageClass, [u8; 32]), Vec<u8>>,
    history_nodes: BTreeMap<InvocationHistoryNodeId, Vec<u8>>,
    history_retirements: Option<HistoryRetirementQueue>,
    // Copy-on-write keeps already-issued catalog resolver snapshots immutable
    // while preserving cheap candidate clones for rollback-safe publication.
    blobs: Arc<BTreeMap<(JournalBlobClass, Hash), Vec<u8>>>,
    gc_intent: Option<GcIntent>,
    replayed_root: Option<ReplayedRootJournalIdentity>,
}

static NEXT_MEMORY_JOURNAL_STORE_INSTANCE: AtomicU64 = AtomicU64::new(1);

fn new_memory_journal_store_instance(
    agent: AgentId,
    node: NodeId,
) -> Result<JournalStoreInstanceId, JournalStoreError> {
    let mut entropy = [0_u8; 32];
    getrandom::getrandom(&mut entropy).map_err(|_| JournalStoreError::Unavailable)?;
    JournalStoreInstanceId::from_bytes(
        Hash::digest(
            b"vos/agent/journal-store/memory-instance",
            &[&agent.0, &node.0, &entropy],
        )
        .0,
    )
    .ok_or(JournalStoreError::Unavailable)
}

fn cloned_memory_journal_store_instance(parent: JournalStoreInstanceId) -> JournalStoreInstanceId {
    let sequence = NEXT_MEMORY_JOURNAL_STORE_INSTANCE
        .fetch_update(Ordering::Relaxed, Ordering::Relaxed, |value| {
            value.checked_add(1)
        })
        .expect("memory journal-store instance counter exhausted");
    JournalStoreInstanceId::from_bytes(
        Hash::digest(
            b"vos/agent/journal-store/memory-clone-instance",
            &[parent.as_bytes(), &sequence.to_le_bytes()],
        )
        .0,
    )
    .expect("memory journal-store instance commitment is nonzero")
}

impl Clone for MemoryAgentJournalStore {
    /// A public clone is an independently mutable in-memory store, so it must
    /// not inherit a Shared application capability for the source instance.
    fn clone(&self) -> Self {
        let mut cloned =
            self.copy_with_instance(cloned_memory_journal_store_instance(self.instance_id));
        // A public clone is a different physical journal capability. Root
        // provenance is process-local and may only come from that clone's own
        // independently reverified initialize/open boundary.
        cloned.replayed_root = None;
        cloned
    }
}

/// Immutable snapshot of an in-memory catalog namespace.
#[derive(Clone, Debug)]
pub(crate) struct MemoryCatalogBlobResolver {
    blobs: Arc<BTreeMap<(JournalBlobClass, Hash), Vec<u8>>>,
}

impl CatalogBlobResolver for MemoryCatalogBlobResolver {
    fn load_catalog(&self, reference: &BlobRef) -> Result<Option<Vec<u8>>, JournalStoreError> {
        validate_blob_reference(JournalBlobClass::CatalogArtifact, reference)?;
        self.blobs
            .get(&(JournalBlobClass::CatalogArtifact, reference.hash))
            .map(|bytes| {
                validate_stored_blob(JournalBlobClass::CatalogArtifact, reference, bytes)?;
                Ok(bytes.clone())
            })
            .transpose()
    }
}

impl CatalogBlobResolverFactory for MemoryAgentJournalStore {
    type Resolver = MemoryCatalogBlobResolver;

    fn catalog_blob_resolver(&self) -> Result<Self::Resolver, JournalStoreError> {
        Ok(MemoryCatalogBlobResolver {
            blobs: Arc::clone(&self.blobs),
        })
    }
}

impl MemoryAgentJournalStore {
    pub fn new(agent: AgentId, node: NodeId) -> Result<Self, JournalStoreError> {
        if agent == AgentId::ZERO || node == NodeId::ZERO {
            return Err(JournalStoreError::ScopeMismatch);
        }
        Ok(Self {
            instance_id: new_memory_journal_store_instance(agent, node)?,
            agent,
            node,
            genesis_admission: None,
            genesis: None,
            heads: None,
            authority: BTreeMap::new(),
            shared_ordered_commits: BTreeMap::new(),
            objects: BTreeMap::new(),
            history_nodes: BTreeMap::new(),
            history_retirements: None,
            blobs: Arc::new(BTreeMap::new()),
            gc_intent: None,
            replayed_root: None,
        })
    }

    fn copy_with_instance(&self, instance_id: JournalStoreInstanceId) -> Self {
        Self {
            instance_id,
            agent: self.agent,
            node: self.node,
            genesis_admission: self.genesis_admission,
            genesis: self.genesis.clone(),
            heads: self.heads.clone(),
            authority: self.authority.clone(),
            shared_ordered_commits: self.shared_ordered_commits.clone(),
            objects: self.objects.clone(),
            history_nodes: self.history_nodes.clone(),
            history_retirements: self.history_retirements.clone(),
            blobs: Arc::clone(&self.blobs),
            gc_intent: self.gc_intent,
            replayed_root: self.replayed_root,
        }
    }

    /// Transactional copy for one publication attempt. Unlike public Clone,
    /// this candidate remains the same logical journal instance and replaces
    /// `self` only after the complete transition validates.
    fn candidate_clone(&self) -> Self {
        self.copy_with_instance(self.instance_id)
    }

    fn ensure_no_gc_pending(&self) -> Result<(), JournalStoreError> {
        if self.gc_intent.is_some() {
            Err(JournalStoreError::GcPending)
        } else {
            Ok(())
        }
    }

    fn validate_scope(&self, genesis: &AgentJournalGenesis) -> Result<(), JournalStoreError> {
        if genesis.runtime().agent != self.agent {
            return Err(JournalStoreError::ScopeMismatch);
        }
        Ok(())
    }

    fn history_queue(
        &self,
        genesis: AgentJournalGenesisId,
    ) -> Result<&HistoryRetirementQueue, JournalStoreError> {
        let queue = self
            .history_retirements
            .as_ref()
            .ok_or(JournalStoreError::NotInitialized)?;
        queue.validate()?;
        if queue.genesis != genesis || queue.node != self.node {
            return Err(JournalStoreError::Corrupt);
        }
        Ok(queue)
    }

    fn install_history_candidate(
        &mut self,
        overlay: &HistoryCandidateOverlay,
    ) -> Result<bool, JournalStoreError> {
        let mut created = false;
        for plan in &overlay.plans {
            for write in plan.overlay_nodes() {
                match self.history_nodes.get(&write.id()) {
                    Some(bytes) if bytes == write.bytes() => {}
                    Some(_) => return Err(JournalStoreError::Corrupt),
                    None if write.needs_write() => {
                        let node =
                            decode_object::<InvocationHistoryNode>(write.bytes(), write.id())?;
                        self.history_nodes.insert(node.id(), write.bytes().to_vec());
                        created = true;
                    }
                    None => return Err(JournalStoreError::Corrupt),
                }
            }
        }
        Ok(created)
    }

    fn enqueue_history_retirement(
        &mut self,
        intent: &HistoryCandidateIntent,
    ) -> Result<(), JournalStoreError> {
        let queue = self
            .history_retirements
            .as_mut()
            .ok_or(JournalStoreError::NotInitialized)?;
        if queue.commitment() != intent.queue_commitment {
            return Err(JournalStoreError::Corrupt);
        }
        queue.preflight_append(&intent.retirement)?;
        queue.records.push(intent.retirement.clone());
        queue.validate()
    }

    fn persist_authority<R: CanonicalAuthorityRecord>(
        &mut self,
        record: &R,
    ) -> Result<bool, JournalStoreError> {
        self.ensure_no_gc_pending()?;
        let id = record.storage_id();
        let bytes = record.encode();
        decode_authority_record::<R>(&bytes, id)?;
        let key = (R::STORAGE_CLASS, id);
        if let Some(existing) = self.authority.get(&key) {
            decode_authority_record::<R>(existing, id)?;
            return if existing == &bytes {
                Ok(false)
            } else {
                Err(JournalStoreError::Corrupt)
            };
        }
        self.authority.insert(key, bytes);
        Ok(true)
    }

    fn read_authority<R: CanonicalAuthorityRecord>(
        &self,
        expected: [u8; 32],
    ) -> Result<Option<R>, JournalStoreError> {
        if expected == [0; 32] {
            return Err(JournalStoreError::Corrupt);
        }
        self.authority
            .get(&(R::STORAGE_CLASS, expected))
            .map(|bytes| decode_authority_record::<R>(bytes, expected))
            .transpose()
    }

    fn persist_authority_with_readback<R: CanonicalAuthorityRecord>(
        &mut self,
        record: &R,
    ) -> Result<(), JournalStoreError> {
        let id = record.storage_id();
        self.persist_authority(record)?;
        if self.read_authority::<R>(id)?.as_ref() != Some(record) {
            return Err(JournalStoreError::Corrupt);
        }
        Ok(())
    }

    fn object_bytes<R: CanonicalJournalRecord>(&self, id: R::Id) -> Option<&[u8]> {
        if R::STORAGE_CLASS == JournalStorageClass::InvocationHistoryNode {
            return self
                .history_nodes
                .get(&InvocationHistoryNodeId(*id.as_bytes()))
                .map(Vec::as_slice);
        }
        self.objects
            .get(&(R::STORAGE_CLASS, *id.as_bytes()))
            .map(Vec::as_slice)
    }

    fn publish_anchor_with_mode<R: CanonicalJournalRecord>(
        &mut self,
        expected: JournalHeadsId,
        anchor: &R,
        next: &JournalHeads,
        mode: ReplayPublicationMode,
    ) -> Result<JournalPublication, JournalStoreError> {
        self.ensure_no_gc_pending()?;
        ensure_publication_class(R::STORAGE_CLASS)?;
        let encoded_anchor = encode_object(anchor)?;
        let encoded_next = encode_object(next)?;
        let current = self.heads()?.ok_or(JournalStoreError::NotInitialized)?;

        if current.id() == next.id() {
            let existing = self
                .objects
                .get(&(encoded_anchor.class, encoded_anchor.id))
                .ok_or(JournalStoreError::Corrupt)?;
            if existing != &encoded_anchor.bytes {
                return Err(JournalStoreError::Corrupt);
            }
            validate_head_targets(self, &current)?;
            validate_idempotent_anchor(self, &current, anchor)?;
            return Ok(JournalPublication {
                object_created: false,
                heads_advanced: false,
            });
        }
        if current.id() != expected {
            return Err(JournalStoreError::Conflict);
        }
        validate_head_targets(self, &current)?;
        current
            .validate_successor(next)
            .map_err(supplied_decode_error)?;
        validate_publication_shape_with_mode(&current, anchor, next, mode)?;

        // Build the candidate in a clone so an in-memory reference has the
        // same all-or-nothing head visibility as the filesystem head swap.
        let mut candidate = self.candidate_clone();
        let object_created = candidate.put(anchor)?;
        validate_anchor_dependencies(&candidate, &current, anchor, next)?;
        validate_head_targets(&candidate, next)?;
        candidate.heads = Some(encoded_next.bytes);
        *self = candidate;
        Ok(JournalPublication {
            object_created,
            heads_advanced: true,
        })
    }

    fn publish_anchor<R: CanonicalJournalRecord>(
        &mut self,
        expected: JournalHeadsId,
        anchor: &R,
        next: &JournalHeads,
    ) -> Result<JournalPublication, JournalStoreError> {
        self.publish_anchor_with_mode(expected, anchor, next, ReplayPublicationMode::Canonical)
    }

    fn publish_sealed_internal(
        &mut self,
        publication: &ReplaySealedPublication,
        authority: Option<&ReplaySystemAuthorityStoragePlan>,
    ) -> Result<JournalPublication, JournalStoreError> {
        match (publication.system_authority_write(), authority) {
            (None, None) | (Some(_), Some(_)) => {}
            _ => return Err(JournalStoreError::NonCanonical),
        }
        self.ensure_no_gc_pending()?;
        let expected = publication.expected();
        let next = publication.next();
        let current = self.heads()?.ok_or(JournalStoreError::NotInitialized)?;
        let exact_retry = publication_is_exact_retry(&current, expected, next)?;
        if exact_retry {
            validate_idempotent_history_plans(self, &current, publication.history_plans())?;
        }
        let overlay = if exact_retry {
            None
        } else {
            let queue = self.history_queue(current.genesis)?.clone();
            build_history_candidate(self, &current, next, publication.history_plans(), &queue)?
        };

        // Build the complete candidate in a private clone. Authority history
        // is exact-read back before the anchor CAS and again after the
        // candidate's head has advanced, but is not exposed if validation or
        // the CAS fails.
        let mut candidate = self.candidate_clone();
        let history_created = overlay
            .as_ref()
            .map(|overlay| candidate.install_history_candidate(overlay))
            .transpose()?
            .unwrap_or(false);
        let authority_created = authority
            .map(|plan| stage_system_authority_dependencies(&mut candidate, publication, plan))
            .transpose()?
            .unwrap_or(false);
        let dependency_created = stage_sealed_dependencies(&mut candidate, publication)?;
        let mut result =
            match publication.anchor() {
                ReplayPublicationAnchor::Ordered(entry) => {
                    candidate.publish_anchor_with_mode(expected, entry, next, publication.mode())?
                }
                ReplayPublicationAnchor::Local(entry) => {
                    candidate.publish_anchor_with_mode(expected, entry, next, publication.mode())?
                }
                ReplayPublicationAnchor::Merge { event, .. } => {
                    candidate.publish_anchor_with_mode(expected, event, next, publication.mode())?
                }
                ReplayPublicationAnchor::Checkpoint(checkpoint) => candidate
                    .publish_anchor_with_mode(expected, checkpoint, next, publication.mode())?,
            };
        if result.heads_advanced
            && let Some(overlay) = &overlay
        {
            candidate.enqueue_history_retirement(&overlay.intent)?;
        }
        if let Some(plan) = authority {
            stage_system_authority_dependencies(&mut candidate, publication, plan)?;
        }
        *self = candidate;
        result.object_created |= authority_created || dependency_created || history_created;
        Ok(result)
    }

    #[cfg(test)]
    fn initialize_raw_for_test(
        &mut self,
        genesis: &AgentJournalGenesis,
    ) -> Result<bool, JournalStoreError> {
        self.ensure_no_gc_pending()?;
        let encoded = encode_object(genesis)?;
        self.validate_scope(genesis)?;
        if self
            .load_blob(
                JournalBlobClass::CatalogArtifact,
                &genesis.runtime().package,
            )?
            .is_none()
        {
            return Err(JournalStoreError::MissingObject);
        }
        let empty_frontier = MergeFrontier {
            genesis: genesis.id(),
            events: Vec::new(),
        };
        let ordered_invocations =
            InvocationIndexManifest::empty(genesis.id(), InvocationOwnershipScope::Ordered);
        let merge_invocations =
            InvocationIndexManifest::empty(genesis.id(), InvocationOwnershipScope::Merge);
        let local_invocations = InvocationIndexManifest::empty(
            genesis.id(),
            InvocationOwnershipScope::Local(self.node),
        );
        let initial = JournalHeads::initial(
            genesis.id(),
            genesis.admission,
            self.node,
            empty_frontier.id(),
            genesis.runtime().clone(),
        );
        let encoded_heads = encode_object(&initial)?;
        let test_admission = genesis.admission.as_hash();

        if self
            .genesis_admission
            .is_some_and(|existing| existing != test_admission)
            || self
                .genesis
                .as_ref()
                .is_some_and(|existing| existing != &encoded.bytes)
            || self
                .heads
                .as_ref()
                .is_some_and(|existing| existing != &encoded_heads.bytes)
        {
            return Err(JournalStoreError::Conflict);
        }
        let created = self.genesis.is_none() || self.heads.is_none();
        let mut candidate = self.candidate_clone();
        candidate.put(&empty_frontier)?;
        candidate.put(&ordered_invocations)?;
        candidate.put(&merge_invocations)?;
        candidate.put(&local_invocations)?;
        candidate.genesis_admission = Some(test_admission);
        candidate.genesis = Some(encoded.bytes);
        candidate.heads = Some(encoded_heads.bytes);
        candidate.history_retirements =
            Some(HistoryRetirementQueue::empty(genesis.id(), self.node));
        candidate.replayed_root = None;
        validate_head_targets(&candidate, &initial)?;
        *self = candidate;
        Ok(created)
    }
}

impl AgentJournalStore for MemoryAgentJournalStore {
    fn instance_id(&self) -> JournalStoreInstanceId {
        self.instance_id
    }

    fn initialize(&mut self, sealed: &ReplaySealedGenesis) -> Result<bool, JournalStoreError> {
        self.ensure_no_gc_pending()?;
        let shape = validate_sealed_genesis_shape(sealed, self.agent, self.node)?;
        let replayed_root = sealed
            .replayed_root_identity()
            .map_err(|_| JournalStoreError::ScopeMismatch)?;
        let genesis = sealed.genesis();
        let encoded = encode_object(genesis)?;
        let encoded_heads = encode_object(&shape.initial)?;
        for reference in &sealed.artifacts().artifacts {
            require_blob(self, JournalBlobClass::CatalogArtifact, reference)?;
        }
        if self
            .genesis_admission
            .is_some_and(|existing| existing != sealed.admission_commitment())
            || self
                .genesis
                .as_ref()
                .is_some_and(|existing| existing != &encoded.bytes)
            || self
                .heads
                .as_ref()
                .is_some_and(|existing| existing != &encoded_heads.bytes)
            || self
                .replayed_root
                .is_some_and(|existing| existing != replayed_root)
        {
            return Err(JournalStoreError::Conflict);
        }
        let created = self.genesis.is_none() || self.heads.is_none();
        let mut candidate = self.candidate_clone();
        candidate.persist_authority(sealed.root_anchor())?;
        candidate.persist_authority(sealed.admission_evidence())?;
        candidate.persist_authority(sealed.admission_record())?;
        candidate.put(sealed.empty_frontier())?;
        candidate.put(sealed.ordered_invocations())?;
        candidate.put(sealed.merge_invocations())?;
        candidate.put(&shape.local_invocations)?;
        candidate.put(sealed.artifacts())?;
        for lane in &shape.lanes {
            candidate.put_blob(
                JournalBlobClass::LaneState,
                &lane.state,
                genesis_state_component(sealed.post_create(), lane.lane),
            )?;
            candidate.put(lane)?;
        }
        candidate.genesis_admission = Some(sealed.admission_commitment());
        candidate.genesis = Some(encoded.bytes);
        candidate.heads = Some(encoded_heads.bytes);
        candidate.history_retirements =
            Some(HistoryRetirementQueue::empty(genesis.id(), self.node));
        candidate.replayed_root = Some(replayed_root);
        validate_head_targets(&candidate, &shape.initial)?;
        *self = candidate;
        Ok(created)
    }

    fn genesis(&self) -> Result<Option<AgentJournalGenesis>, JournalStoreError> {
        self.genesis
            .as_deref()
            .map(|bytes| {
                let decoded =
                    AgentJournalGenesis::decode(bytes).map_err(|_| JournalStoreError::Corrupt)?;
                decode_object(bytes, decoded.id())
            })
            .transpose()
    }

    fn heads(&self) -> Result<Option<JournalHeads>, JournalStoreError> {
        self.heads
            .as_deref()
            .map(|bytes| {
                let decoded =
                    JournalHeads::decode(bytes).map_err(|_| JournalStoreError::Corrupt)?;
                let decoded = decode_object::<JournalHeads>(bytes, decoded.id())?;
                if decoded.node != self.node {
                    return Err(JournalStoreError::ScopeMismatch);
                }
                Ok(decoded)
            })
            .transpose()
    }

    fn put<R: CanonicalJournalRecord>(&mut self, record: &R) -> Result<bool, JournalStoreError> {
        self.ensure_no_gc_pending()?;
        ensure_writable_content_class(R::STORAGE_CLASS)?;
        let encoded = encode_object(record)?;
        let key = (encoded.class, encoded.id);
        match self.objects.get(&key) {
            Some(existing) if existing == &encoded.bytes => Ok(false),
            Some(_) => Err(JournalStoreError::Corrupt),
            None => {
                self.objects.insert(key, encoded.bytes);
                Ok(true)
            }
        }
    }

    fn get<R: CanonicalJournalRecord>(&self, id: R::Id) -> Result<Option<R>, JournalStoreError> {
        ensure_readable_content_class(R::STORAGE_CLASS)?;
        self.object_bytes::<R>(id)
            .map(|bytes| decode_object(bytes, id))
            .transpose()
    }

    fn put_blob(
        &mut self,
        class: JournalBlobClass,
        reference: &BlobRef,
        bytes: &[u8],
    ) -> Result<bool, JournalStoreError> {
        self.ensure_no_gc_pending()?;
        validate_supplied_blob(class, reference, bytes)?;
        let key = (class, reference.hash);
        match self.blobs.get(&key) {
            Some(existing) if existing == bytes => Ok(false),
            Some(_) => Err(JournalStoreError::Corrupt),
            None => {
                Arc::make_mut(&mut self.blobs).insert(key, bytes.to_vec());
                Ok(true)
            }
        }
    }

    fn load_blob(
        &self,
        class: JournalBlobClass,
        reference: &BlobRef,
    ) -> Result<Option<Vec<u8>>, JournalStoreError> {
        validate_blob_reference(class, reference)?;
        self.blobs
            .get(&(class, reference.hash))
            .map(|bytes| {
                validate_stored_blob(class, reference, bytes)?;
                Ok(bytes.clone())
            })
            .transpose()
    }

    fn publish(
        &mut self,
        publication: &ReplaySealedPublication,
    ) -> Result<JournalPublication, JournalStoreError> {
        self.publish_sealed_internal(publication, None)
    }
}

impl UnpublishedCatalogBlobStore for MemoryAgentJournalStore {
    fn stage_catalog_blob(
        &mut self,
        predecessor: JournalHeadsId,
        reference: &BlobRef,
        bytes: &[u8],
    ) -> Result<Option<UnpublishedCatalogBlob>, JournalStoreError> {
        if self.heads()?.ok_or(JournalStoreError::NotInitialized)?.id() != predecessor {
            return Err(JournalStoreError::Conflict);
        }
        self.put_blob(JournalBlobClass::CatalogArtifact, reference, bytes)
            .map(|created| {
                created.then(|| UnpublishedCatalogBlob {
                    store: self.instance_id(),
                    predecessor,
                    reference: reference.clone(),
                })
            })
    }

    fn rollback_catalog_blob(
        &mut self,
        token: UnpublishedCatalogBlob,
    ) -> Result<(), JournalStoreError> {
        self.ensure_no_gc_pending()?;
        if token.store != self.instance_id()
            || self.heads()?.ok_or(JournalStoreError::NotInitialized)?.id() != token.predecessor
        {
            return Err(JournalStoreError::Conflict);
        }
        let key = (JournalBlobClass::CatalogArtifact, token.reference.hash);
        let bytes = self.blobs.get(&key).ok_or(JournalStoreError::Corrupt)?;
        validate_stored_blob(JournalBlobClass::CatalogArtifact, &token.reference, bytes)?;
        Arc::make_mut(&mut self.blobs).remove(&key);
        Ok(())
    }
}

impl SharedOrderedCommitStore for MemoryAgentJournalStore {
    fn shared_ordered_commit(
        &self,
        entry: OrderedEntryId,
    ) -> Result<Option<SharedOrderedCommitBinding>, JournalStoreError> {
        if entry == OrderedEntryId::ZERO {
            return Err(JournalStoreError::Corrupt);
        }
        let binding = self
            .shared_ordered_commits
            .get(&entry)
            .map(|bytes| decode_shared_ordered_commit_binding(bytes, entry))
            .transpose()?;
        if let Some(binding) = &binding {
            let heads = self.heads()?.ok_or(JournalStoreError::NotInitialized)?;
            validate_shared_ordered_commit_scope(binding, &heads, self.instance_id())?;
        }
        Ok(binding)
    }

    fn persist_shared_ordered_commit(
        &mut self,
        binding: &SharedOrderedCommitBinding,
    ) -> Result<bool, JournalStoreError> {
        self.ensure_no_gc_pending()?;
        binding.validate()?;
        let heads = self.heads()?.ok_or(JournalStoreError::NotInitialized)?;
        validate_shared_ordered_commit_scope(binding, &heads, self.instance_id())?;
        let bytes = binding.encode();
        if bytes.len() > MAX_SHARED_ORDERED_COMMIT_BINDING_BYTES {
            return Err(JournalStoreError::LimitExceeded);
        }
        match self.shared_ordered_commits.get(&binding.entry) {
            Some(existing) => {
                decode_shared_ordered_commit_binding(existing, binding.entry)?;
                if existing == &bytes {
                    Ok(false)
                } else {
                    Err(JournalStoreError::Conflict)
                }
            }
            None => {
                if self.shared_ordered_commits.len() == MAX_SHARED_ORDERED_COMMIT_BINDINGS {
                    return Err(JournalStoreError::LimitExceeded);
                }
                self.shared_ordered_commits.insert(binding.entry, bytes);
                Ok(true)
            }
        }
    }
}

impl SystemAuthorityHistoryStore for MemoryAgentJournalStore {
    fn load_system_authority_decision_node(
        &self,
        id: SystemAuthorityDecisionNodeId,
    ) -> Result<Option<SystemAuthorityDecisionNode>, JournalStoreError> {
        self.read_authority(*id.as_bytes())
    }

    fn persist_system_authority_decision_node(
        &mut self,
        node: &SystemAuthorityDecisionNode,
    ) -> Result<(), JournalStoreError> {
        self.persist_authority_with_readback(node)
    }

    fn load_system_authority_rotation_node(
        &self,
        id: SystemAuthorityRotationNodeId,
    ) -> Result<Option<SystemAuthorityRotationNode>, JournalStoreError> {
        self.read_authority(*id.as_bytes())
    }

    fn persist_system_authority_rotation_node(
        &mut self,
        node: &SystemAuthorityRotationNode,
    ) -> Result<(), JournalStoreError> {
        self.persist_authority_with_readback(node)
    }

    fn load_system_authority_catalog_node(
        &self,
        id: SystemAuthorityCatalogNodeId,
    ) -> Result<Option<SystemAuthorityCatalogNode>, JournalStoreError> {
        self.read_authority(*id.as_bytes())
    }

    fn persist_system_authority_catalog_node(
        &mut self,
        node: &SystemAuthorityCatalogNode,
    ) -> Result<(), JournalStoreError> {
        self.persist_authority_with_readback(node)
    }

    fn load_system_authority_catalog_record(
        &self,
        id: SystemAuthorityCatalogRecordId,
    ) -> Result<Option<SystemAuthorityCatalogRecord>, JournalStoreError> {
        self.read_authority(*id.as_bytes())
    }

    fn persist_system_authority_catalog_record(
        &mut self,
        record: &SystemAuthorityCatalogRecord,
    ) -> Result<(), JournalStoreError> {
        self.persist_authority_with_readback(record)
    }

    fn load_system_authority_committee_record(
        &self,
        id: SystemAuthorityCommitteeId,
    ) -> Result<Option<SystemAuthorityCommitteeRecord>, JournalStoreError> {
        self.read_authority(*id.as_bytes())
    }

    fn persist_system_authority_committee_record(
        &mut self,
        record: &SystemAuthorityCommitteeRecord,
    ) -> Result<(), JournalStoreError> {
        self.persist_authority_with_readback(record)
    }
}

impl SystemAuthorityPublicationStore for MemoryAgentJournalStore {
    fn publish_system_authority(
        &mut self,
        publication: &ReplaySealedPublication,
        storage: &ReplaySystemAuthorityStoragePlan,
    ) -> Result<JournalPublication, JournalStoreError> {
        self.publish_sealed_internal(publication, Some(storage))
    }
}

impl ReverifiedRootJournalStore for MemoryAgentJournalStore {
    fn replayed_root_identity(&self) -> Option<ReplayedRootJournalIdentity> {
        self.replayed_root
    }
}

impl InvocationHistoryStore for MemoryAgentJournalStore {
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
                decode_object::<InvocationHistoryNode>(bytes, id)?;
                Ok(bytes.clone())
            })
            .transpose()
    }
}

impl AgentJournalGarbageCollection for MemoryAgentJournalStore {
    fn collect_garbage(
        &mut self,
        expected_heads: JournalHeadsId,
        limits: GcLimits,
    ) -> Result<JournalGc, JournalStoreError> {
        let (intent, mark) = build_gc_mark(self, expected_heads, limits)?;
        let history_queue = self
            .history_retirements
            .as_ref()
            .ok_or(JournalStoreError::NotInitialized)?
            .clone();
        validate_history_retirement_coverage(self, expected_heads, &history_queue)?;
        // The complete named retirement batch is authenticated before the GC
        // intent is installed. A missing/tampered stale node is corruption;
        // permanent history is never discovered by sweeping its namespace.
        for record in &history_queue.records {
            for id in record.remaining() {
                let bytes = self
                    .history_nodes
                    .get(id)
                    .ok_or(JournalStoreError::Corrupt)?;
                decode_object::<InvocationHistoryNode>(bytes, *id)?;
            }
        }
        let resumed = match self.gc_intent {
            Some(existing) if existing == intent => true,
            Some(_) => return Err(JournalStoreError::Corrupt),
            None => false,
        };

        let mut scanned_files = 0_usize;
        let mut scanned_bytes = 0_u64;
        for bytes in self.objects.values().chain(self.blobs.values()) {
            scanned_files = scanned_files
                .checked_add(1)
                .ok_or(JournalStoreError::LimitExceeded)?;
            scanned_bytes = scanned_bytes
                .checked_add(
                    u64::try_from(bytes.len()).map_err(|_| JournalStoreError::LimitExceeded)?,
                )
                .ok_or(JournalStoreError::LimitExceeded)?;
            if scanned_files > limits.max_scanned_files || scanned_bytes > limits.max_scanned_bytes
            {
                return Err(JournalStoreError::LimitExceeded);
            }
        }

        let garbage_objects = self
            .objects
            .keys()
            .filter(|key| !mark.objects.contains(key))
            .copied()
            .collect::<Vec<_>>();
        let garbage_blobs = self
            .blobs
            .keys()
            .filter(|key| !mark.blobs.contains(key))
            .copied()
            .collect::<Vec<_>>();
        self.gc_intent = Some(intent);

        let mut remaining = limits.max_unlinks_per_run;
        let mut objects_removed = 0_usize;
        let queue = self
            .history_retirements
            .as_mut()
            .ok_or(JournalStoreError::Corrupt)?;
        while let Some(record) = queue.records.first_mut() {
            if record.remaining().is_empty() {
                queue.records.remove(0);
                continue;
            }
            if remaining == 0 {
                break;
            }
            let id = record.remaining()[0];
            if self.history_nodes.remove(&id).is_none() {
                return Err(JournalStoreError::Corrupt);
            }
            record.retired_cursor += 1;
            objects_removed += 1;
            remaining -= 1;
        }
        let mut normal_objects_removed = 0_usize;
        for key in garbage_objects.iter().take(remaining) {
            if self.objects.remove(key).is_some() {
                objects_removed += 1;
                normal_objects_removed += 1;
                remaining -= 1;
            }
        }
        let mut blobs_removed = 0_usize;
        if remaining != 0 {
            let blobs = Arc::make_mut(&mut self.blobs);
            for key in garbage_blobs.iter().take(remaining) {
                if blobs.remove(key).is_some() {
                    blobs_removed += 1;
                    remaining -= 1;
                }
            }
        }
        let complete = queue.records.is_empty()
            && normal_objects_removed == garbage_objects.len()
            && blobs_removed == garbage_blobs.len();
        if complete {
            self.gc_intent = None;
        }
        Ok(JournalGc {
            objects_removed,
            blobs_removed,
            aliases_removed: 0,
            resumed,
            complete,
        })
    }
}

#[cfg(target_os = "linux")]
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
struct FileIdentity {
    device: u64,
    inode: u64,
}

#[cfg(target_os = "linux")]
impl FileIdentity {
    fn of(file: &File) -> Result<Self, JournalStoreError> {
        let metadata = file
            .metadata()
            .map_err(|_| JournalStoreError::Unavailable)?;
        Ok(Self {
            device: metadata.dev(),
            inode: metadata.ino(),
        })
    }
}

#[cfg(target_os = "linux")]
fn file_journal_store_instance_id(
    root: &Path,
    agent: AgentId,
    node: NodeId,
    stable_lock_nonce: &[u8; STABLE_LOCK_NONCE_BYTES],
) -> Result<JournalStoreInstanceId, JournalStoreError> {
    JournalStoreInstanceId::from_bytes(
        Hash::digest(
            b"vos/agent/journal-store/file-instance",
            &[
                root.as_os_str().as_bytes(),
                &agent.0,
                &node.0,
                stable_lock_nonce,
            ],
        )
        .0,
    )
    .ok_or(JournalStoreError::Corrupt)
}

#[cfg(target_os = "linux")]
const GC_OBJECT_NAMESPACES: &[(JournalStorageClass, &str)] = &[
    (JournalStorageClass::ReplayInput, "records/replay-inputs"),
    (JournalStorageClass::OrderedEntry, "records/ordered"),
    (JournalStorageClass::LocalEntry, "records/local"),
    (JournalStorageClass::MergeEvent, "records/merge-events"),
    (
        JournalStorageClass::MergeFrontier,
        "records/merge-frontiers",
    ),
    (JournalStorageClass::MergeSeal, "records/merge-seals"),
    (JournalStorageClass::LaneState, "lane-state/manifests"),
    (JournalStorageClass::ArtifactClosure, "artifact-closures"),
    (
        JournalStorageClass::InvocationIndex,
        "invocation-index/manifests",
    ),
    (
        JournalStorageClass::InvocationIndexNode,
        "invocation-index/nodes",
    ),
    (
        JournalStorageClass::InvocationOutcome,
        "invocation-outcomes",
    ),
    (JournalStorageClass::Checkpoint, "checkpoints"),
];

#[cfg(target_os = "linux")]
const GC_BLOB_NAMESPACES: &[(JournalBlobClass, &str)] = &[
    (JournalBlobClass::LaneState, "lane-state/blobs"),
    (JournalBlobClass::CatalogArtifact, "catalog/blobs"),
];

#[cfg(target_os = "linux")]
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum FileGcKind {
    Object(JournalStorageClass),
    Blob(JournalBlobClass),
}

#[cfg(target_os = "linux")]
#[derive(Clone, Debug)]
struct FileGcEntry {
    directory: &'static str,
    name: String,
    id: [u8; 32],
    identity: FileIdentity,
    bytes: u64,
    alias: bool,
    kind: FileGcKind,
}

#[cfg(target_os = "linux")]
impl FileGcEntry {
    fn is_live(&self, mark: &GcMark) -> bool {
        if self.alias {
            return false;
        }
        match self.kind {
            FileGcKind::Object(class) => mark.objects.contains(&(class, self.id)),
            FileGcKind::Blob(class) => mark.blobs.contains(&(class, Hash(self.id))),
        }
    }
}

#[cfg(target_os = "linux")]
fn decode_hex_32(name: &[u8]) -> Option<[u8; 32]> {
    if name.len() != 64 {
        return None;
    }
    let mut bytes = [0_u8; 32];
    for (index, pair) in name.chunks_exact(2).enumerate() {
        bytes[index] = (decode_nibble(pair[0])? << 4) | decode_nibble(pair[1])?;
    }
    Some(bytes)
}

#[cfg(target_os = "linux")]
fn scan_gc_directory(
    directory: &File,
    directory_key: &'static str,
    kind: FileGcKind,
    maximum: usize,
    limits: GcLimits,
    scanned_files: &mut usize,
    scanned_bytes: &mut u64,
    entries: &mut Vec<FileGcEntry>,
) -> Result<(), JournalStoreError> {
    // `fdopendir` consumes its descriptor; scan a duplicate of the pinned
    // capability and close the stream before any unlink pass begins.
    // SAFETY: `fcntl` receives a live descriptor and returns a fresh one.
    let duplicate = unsafe { libc::fcntl(directory.as_raw_fd(), libc::F_DUPFD_CLOEXEC, 0) };
    if duplicate < 0 {
        return Err(JournalStoreError::Unavailable);
    }
    // SAFETY: ownership of `duplicate` transfers to the DIR stream.
    let stream = unsafe { libc::fdopendir(duplicate) };
    if stream.is_null() {
        // SAFETY: failed `fdopendir` did not consume the descriptor.
        unsafe { libc::close(duplicate) };
        return Err(JournalStoreError::Unavailable);
    }
    // SAFETY: the stream is live through `closedir` below.
    unsafe { libc::rewinddir(stream) };
    let scan = loop {
        // SAFETY: Linux exposes a thread-local errno pointer.
        unsafe { *libc::__errno_location() = 0 };
        // SAFETY: the stream remains live until the scan finishes.
        let entry = unsafe { libc::readdir(stream) };
        if entry.is_null() {
            // SAFETY: Linux exposes a thread-local errno pointer.
            let errno = unsafe { *libc::__errno_location() };
            break if errno == 0 {
                Ok(())
            } else {
                Err(JournalStoreError::Unavailable)
            };
        }
        // SAFETY: a successful directory entry has a NUL-terminated name.
        let raw = unsafe { CStr::from_ptr((*entry).d_name.as_ptr()) }.to_bytes();
        if raw == b"." || raw == b".." {
            continue;
        }
        let (stem, alias) = raw
            .strip_suffix(b".next")
            .map_or((raw, false), |stem| (stem, true));
        let Some(id) = decode_hex_32(stem) else {
            break Err(JournalStoreError::Corrupt);
        };
        let Ok(name) = std::str::from_utf8(raw) else {
            break Err(JournalStoreError::Corrupt);
        };
        let status = match stat_at(directory, &c_name(name)?) {
            Ok(Some(status)) => status,
            Ok(None) => break Err(JournalStoreError::Corrupt),
            Err(_) => break Err(JournalStoreError::Unavailable),
        };
        // SAFETY: `geteuid` has no preconditions or borrowed state.
        let effective_user = unsafe { libc::geteuid() };
        if status.st_mode & libc::S_IFMT != libc::S_IFREG
            || status.st_uid != effective_user
            || status.st_mode & 0o022 != 0
            || status.st_size < 0
            || status.st_size as u64 > maximum as u64
        {
            break Err(JournalStoreError::Corrupt);
        }
        *scanned_files = scanned_files
            .checked_add(1)
            .ok_or(JournalStoreError::LimitExceeded)?;
        *scanned_bytes = scanned_bytes
            .checked_add(status.st_size as u64)
            .ok_or(JournalStoreError::LimitExceeded)?;
        if *scanned_files > limits.max_scanned_files || *scanned_bytes > limits.max_scanned_bytes {
            break Err(JournalStoreError::LimitExceeded);
        }
        entries
            .try_reserve(1)
            .map_err(|_| JournalStoreError::LimitExceeded)?;
        entries.push(FileGcEntry {
            directory: directory_key,
            name: name.to_owned(),
            id,
            identity: status_identity(&status),
            bytes: status.st_size as u64,
            alias,
            kind,
        });
    };
    // SAFETY: `closedir` consumes the live stream and its descriptor.
    let closed = unsafe { libc::closedir(stream) };
    if closed != 0 {
        return Err(JournalStoreError::Unavailable);
    }
    scan
}

#[cfg(target_os = "linux")]
struct PinnedDirectory {
    file: File,
    parent: Option<usize>,
    name: CString,
    identity: FileIdentity,
}

#[cfg(target_os = "linux")]
impl PinnedDirectory {
    fn try_clone(&self) -> Result<Self, JournalStoreError> {
        Ok(Self {
            file: self
                .file
                .try_clone()
                .map_err(|_| JournalStoreError::Unavailable)?,
            parent: self.parent,
            name: self.name.clone(),
            identity: self.identity,
        })
    }
}

#[cfg(target_os = "linux")]
struct AbsoluteDirectoryCapability {
    filesystem_root: File,
    components: Vec<PinnedDirectory>,
}

#[cfg(target_os = "linux")]
impl AbsoluteDirectoryCapability {
    fn open(path: &Path) -> Result<Self, JournalStoreError> {
        if !path.is_absolute() {
            return Err(JournalStoreError::InvalidPath);
        }
        let filesystem_root = open_directory_path(Path::new("/"))?;
        validate_safe_ancestor_directory(&filesystem_root)?;
        let mut value = Self {
            filesystem_root,
            components: Vec::new(),
        };
        for component in path.components() {
            let Component::Normal(name) = component else {
                if matches!(component, Component::RootDir) {
                    continue;
                }
                return Err(JournalStoreError::InvalidPath);
            };
            let name = name.to_str().ok_or(JournalStoreError::InvalidPath)?;
            let parent = value.components.len().checked_sub(1);
            if let Some(parent) = parent {
                value.verify(parent)?;
            }
            let directory = open_directory_at(value.last_file(), name)?;
            validate_safe_ancestor_directory(&directory)?;
            let identity = FileIdentity::of(&directory)?;
            value.components.push(PinnedDirectory {
                file: directory,
                parent,
                name: c_name(name)?,
                identity,
            });
            value.verify(value.components.len() - 1)?;
        }
        Ok(value)
    }

    fn last_file(&self) -> &File {
        self.components
            .last()
            .map_or(&self.filesystem_root, |component| &component.file)
    }

    fn verify(&self, index: usize) -> Result<(), JournalStoreError> {
        let component = self
            .components
            .get(index)
            .ok_or(JournalStoreError::Corrupt)?;
        let parent = if let Some(parent) = component.parent {
            self.verify(parent)?;
            &self.components[parent].file
        } else {
            &self.filesystem_root
        };
        validate_safe_ancestor_directory(&component.file)?;
        verify_directory_entry(parent, &component.name, component.identity)
    }

    fn get(&self) -> Result<&File, JournalStoreError> {
        if let Some(last) = self.components.len().checked_sub(1) {
            self.verify(last)?;
        }
        Ok(self.last_file())
    }

    /// Duplicate already-pinned descriptors. This deliberately performs no
    /// path lookup, directory reopen, or lock acquisition.
    fn try_clone(&self) -> Result<Self, JournalStoreError> {
        let filesystem_root = self
            .filesystem_root
            .try_clone()
            .map_err(|_| JournalStoreError::Unavailable)?;
        let components = self
            .components
            .iter()
            .map(PinnedDirectory::try_clone)
            .collect::<Result<Vec<_>, _>>()?;
        let cloned = Self {
            filesystem_root,
            components,
        };
        cloned.get()?;
        Ok(cloned)
    }
}

/// A pinned Linux directory tree. Every data operation is relative to one of
/// these descriptors. The namespace slot for each pinned directory is checked
/// before use, so replacing `root` or any internal component is detected; a
/// swap racing after the check still cannot redirect the descriptor-relative
/// operation.
#[cfg(target_os = "linux")]
struct DirectoryCapabilities {
    journal_parent: AbsoluteDirectoryCapability,
    directories: Vec<PinnedDirectory>,
    indexes: BTreeMap<&'static str, usize>,
}

#[cfg(target_os = "linux")]
impl DirectoryCapabilities {
    fn new(
        journal_parent: AbsoluteDirectoryCapability,
        root_name: CString,
        root: File,
    ) -> Result<Self, JournalStoreError> {
        validate_owned_directory(&root)?;
        let root_identity = FileIdentity::of(&root)?;
        let mut indexes = BTreeMap::new();
        indexes.insert("", 0);
        Ok(Self {
            journal_parent,
            directories: vec![PinnedDirectory {
                file: root,
                parent: None,
                name: root_name,
                identity: root_identity,
            }],
            indexes,
        })
    }

    fn add(
        &mut self,
        key: &'static str,
        parent_key: &'static str,
        name: &'static str,
    ) -> Result<(), JournalStoreError> {
        let parent = *self
            .indexes
            .get(parent_key)
            .ok_or(JournalStoreError::Corrupt)?;
        self.verify(parent)?;
        ensure_directory_at(&self.directories[parent].file, name)?;
        let file = open_directory_at(&self.directories[parent].file, name)?;
        validate_owned_directory(&file)?;
        let identity = FileIdentity::of(&file)?;
        let index = self.directories.len();
        self.directories.push(PinnedDirectory {
            file,
            parent: Some(parent),
            name: c_name(name)?,
            identity,
        });
        if self.indexes.insert(key, index).is_some() {
            return Err(JournalStoreError::Corrupt);
        }
        Ok(())
    }

    /// Pin an already-existing directory without creating or repairing its
    /// namespace entry. Exposed journal startup uses this path until the
    /// authenticated heads and full replay have been validated.
    fn add_existing(
        &mut self,
        key: &'static str,
        parent_key: &'static str,
        name: &'static str,
    ) -> Result<(), JournalStoreError> {
        let parent = *self
            .indexes
            .get(parent_key)
            .ok_or(JournalStoreError::Corrupt)?;
        self.verify(parent)?;
        let file = open_directory_at(&self.directories[parent].file, name)?;
        validate_owned_directory(&file)?;
        let identity = FileIdentity::of(&file)?;
        let index = self.directories.len();
        self.directories.push(PinnedDirectory {
            file,
            parent: Some(parent),
            name: c_name(name)?,
            identity,
        });
        if self.indexes.insert(key, index).is_some() {
            return Err(JournalStoreError::Corrupt);
        }
        Ok(())
    }

    fn verify(&self, index: usize) -> Result<(), JournalStoreError> {
        let directory = self
            .directories
            .get(index)
            .ok_or(JournalStoreError::Corrupt)?;
        validate_owned_directory(&directory.file)?;
        if let Some(parent) = directory.parent {
            self.verify(parent)?;
            verify_directory_entry(
                &self.directories[parent].file,
                &directory.name,
                directory.identity,
            )
        } else {
            let journal_parent = self.journal_parent.get()?;
            verify_directory_entry(journal_parent, &directory.name, directory.identity)
        }
    }

    fn get(&self, key: &'static str) -> Result<&File, JournalStoreError> {
        let index = *self.indexes.get(key).ok_or(JournalStoreError::Corrupt)?;
        self.verify(index)?;
        Ok(&self.directories[index].file)
    }

    fn sync(&self, key: &'static str) -> Result<(), JournalStoreError> {
        self.get(key)?
            .sync_all()
            .map_err(|_| JournalStoreError::Unavailable)
    }

    /// Duplicate the complete descriptor-pinned namespace without resolving
    /// any path component again.
    fn try_clone(&self) -> Result<Self, JournalStoreError> {
        let cloned = Self {
            journal_parent: self.journal_parent.try_clone()?,
            directories: self
                .directories
                .iter()
                .map(PinnedDirectory::try_clone)
                .collect::<Result<Vec<_>, _>>()?,
            indexes: self.indexes.clone(),
        };
        cloned.get("catalog/blobs")?;
        Ok(cloned)
    }
}

#[cfg(not(target_os = "linux"))]
struct DirectoryCapabilities;

/// One-writer filesystem journal rooted at `<full-agent-id>.agent`.
///
/// `stable_lock_path` must have the deterministic leaf
/// `<full-agent-id>.agent-lock`; its parent may differ from `root`'s parent and
/// is also the authority-ledger parent. Callers cannot select an alternate
/// lock for the same Agent. The external stable lock and authority ledger are
/// one permanent freshness domain: neither may be rolled back, replaced, or
/// restored with a backup of the replaceable journal root. The lock's exact
/// 32-byte nonce is durable store-instance state. Ordinary Local stores append
/// the exact 32-byte creation-intent commitment once their genesis has been
/// reverified; that suffix is the non-rollbackable exposure witness. Opening
/// acquires the lock
/// before initializing or reading that nonce and before creating, repairing,
/// or otherwise mutating anything below `root`.
///
/// On Linux, the daemon user is the filesystem trust domain: the lock, Agent
/// root, authority files, and every internal directory must be owned by the
/// effective UID and must not be group/other-writable. Both absolute ancestor
/// chains are pinned one component at a time, must be owned by root or the
/// daemon user, and must be non-writable by group/other except for a sticky
/// directory such as `/tmp`.
/// This makes leaf-name publication safe against less-privileged principals;
/// a process running under the daemon's own UID is intentionally inside the
/// same trust boundary.
/// Other operating systems fail closed until an equivalent capability-safe
/// implementation is provided.
pub struct FileAgentJournalStore {
    root: PathBuf,
    instance_id: JournalStoreInstanceId,
    agent: AgentId,
    node: NodeId,
    directories: DirectoryCapabilities,
    history_candidate: Option<HistoryCandidateOverlay>,
    replayed_root: Option<ReplayedRootJournalIdentity>,
    startup_recovery_pending: bool,
    #[cfg(target_os = "linux")]
    authority_parent: AbsoluteDirectoryCapability,
    #[cfg(target_os = "linux")]
    stable_lock_name: CString,
    #[cfg(target_os = "linux")]
    stable_lock_identity: FileIdentity,
    #[cfg(target_os = "linux")]
    stable_lock_nonce: [u8; STABLE_LOCK_NONCE_BYTES],
    #[cfg(target_os = "linux")]
    local_exposure: Option<Hash>,
    _stable_lock: File,
}

/// Stable authority slot acquired before the replaceable Agent journal root is
/// opened or created. The journal and authority parents are independently
/// pinned. Production root startup uses this split capability to open and
/// validate the system-authority evidence ledger before any recovery or layout
/// mutation below `<agent>.agent` can occur.
#[cfg(target_os = "linux")]
pub(crate) struct FileAgentJournalSlot {
    root: PathBuf,
    root_name: CString,
    instance_id: JournalStoreInstanceId,
    agent: AgentId,
    node: NodeId,
    journal_parent: AbsoluteDirectoryCapability,
    authority_parent: AbsoluteDirectoryCapability,
    generation_exists: bool,
    stable_lock_name: CString,
    stable_lock_identity: FileIdentity,
    stable_lock_nonce: [u8; STABLE_LOCK_NONCE_BYTES],
    stable_lock: File,
    fresh_ledger_stage: Option<(File, FileIdentity)>,
}

/// Stable filesystem slot for an ordinary Local Agent.
///
/// Freshness and exposure are owned by the host's durable Local-genesis
/// intent/marker pair, so this slot deliberately has no system-authority
/// ledger sidecar and cannot mint a root mutation owner.
#[cfg(target_os = "linux")]
pub(crate) struct FileLocalAgentJournalSlot {
    root: PathBuf,
    root_name: CString,
    instance_id: JournalStoreInstanceId,
    agent: AgentId,
    node: NodeId,
    journal_parent: AbsoluteDirectoryCapability,
    authority_parent: AbsoluteDirectoryCapability,
    generation_exists: bool,
    stable_lock_name: CString,
    stable_lock_identity: FileIdentity,
    stable_lock_nonce: [u8; STABLE_LOCK_NONCE_BYTES],
    intent: Hash,
    exposure_committed: bool,
    stable_lock: File,
}

#[cfg(all(target_os = "linux", feature = "storage"))]
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum FileSystemAuthorityLedgerOpenMode {
    /// This process won the descriptor-relative `O_EXCL` creation of the
    /// staged sidecar before it created the stable journal lock.
    FreshStage,
    /// A prior process durably created the staged sidecar but crashed before
    /// publishing it. Only this staged freshness witness may be initialized.
    ExistingStage,
    /// The canonical sidecar already exists. It is always a strict,
    /// zero-initialization reopen, even when no Agent journal is visible.
    ExistingCanonical,
}

const SYSTEM_AUTHORITY_LEDGER_SUFFIX: &str = ".system-authority-ledger.redb";

pub(crate) fn system_authority_ledger_file_name(agent: AgentId) -> String {
    format!(
        "{}{}",
        encode_hex(agent.as_bytes()),
        SYSTEM_AUTHORITY_LEDGER_SUFFIX
    )
}

/// Descriptor-pinned canonical authority sidecar. The retained file and
/// parent capability let Host prove that redb still names the exact live
/// inode before every root mutation instead of continuing on a detached file
/// after a path replacement.
#[cfg(all(target_os = "linux", feature = "storage"))]
pub(crate) struct FileSystemAuthorityLedger {
    database: Arc<Database>,
    journal_store: JournalStoreInstanceId,
    agent: AgentId,
    local_node: NodeId,
    authority_parent: AbsoluteDirectoryCapability,
    canonical_name: CString,
    stage_name: CString,
    identity: FileIdentity,
    file: File,
    mode: FileSystemAuthorityLedgerOpenMode,
    stage_alias: bool,
}

/// One-shot, opaque authority-owner opening capability for an exact pinned
/// sidecar. Its private ledger retains both the database handle and the
/// filesystem-proven open policy, so callers cannot combine staged
/// initialization authority with a canonical database.
#[cfg(all(target_os = "linux", feature = "storage"))]
pub(crate) struct FileSystemAuthorityLedgerOwnerOpen {
    ledger: FileSystemAuthorityLedger,
}

/// Result of consuming [`FileSystemAuthorityLedgerOwnerOpen`]. Keeping the
/// ledger/owner pair opaque prevents a caller from rebinding the owner to a
/// different sidecar before the slot verifies its sealed route identity.
#[cfg(all(target_os = "linux", feature = "storage"))]
pub(crate) struct OpenedFileSystemAuthorityLedgerOwner {
    ledger: FileSystemAuthorityLedger,
    owner: Arc<SystemAuthorityLedgerRouteOwner>,
}

/// Unforgeable permit for the database-level owner constructor. The raw
/// constructor must be reachable across these sibling modules, but no caller
/// outside this module can construct or extract this private-field value.
#[cfg(all(target_os = "linux", feature = "storage"))]
pub(crate) struct FileSystemAuthorityLedgerOwnerOpenPermit(());

/// Opaque proof that the exact pinned canonical sidecar was opened by the
/// signer-independent owner for this physical journal slot. Host retains this
/// pair for the lifetime of every mutable root handle.
#[cfg(all(target_os = "linux", feature = "storage"))]
pub(crate) struct BoundFileSystemAuthorityLedgerOwner {
    ledger: FileSystemAuthorityLedger,
    owner: Arc<SystemAuthorityLedgerRouteOwner>,
}

/// Unforgeable, callback-scoped proof of the exposure state observed while
/// the authority owner's startup writer is held. The private active borrow
/// prevents callers from retaining the capability after that writer is
/// released, while the bound-owner borrow pins the exact sidecar inode and
/// route used by [`FileAgentJournalSlot::open_reverified`].
#[cfg(all(target_os = "linux", feature = "storage"))]
pub(crate) struct BoundFileSystemAuthorityStartup<'owner, 'active> {
    authority: &'owner BoundFileSystemAuthorityLedgerOwner,
    journal_exposure_committed: bool,
    _active: &'active (),
}

#[cfg(all(target_os = "linux", feature = "storage"))]
impl BoundFileSystemAuthorityStartup<'_, '_> {
    pub(crate) const fn journal_exposure_is_committed(&self) -> bool {
        self.journal_exposure_committed
    }
}

#[cfg(target_os = "linux")]
impl FileAgentJournalSlot {
    /// Acquire the stable external journal slot without opening, creating, or
    /// recovering anything below `<agent>.agent`.
    ///
    /// Freshness is made durable before the lock can become visible: a new
    /// deployment first creates and fsyncs the authority sidecar's `.next`
    /// inode, then creates the stable lock and its nonce. A lock with neither
    /// canonical nor staged sidecar is consequently ambiguous deletion and is
    /// rejected rather than treated as a new deployment.
    pub(crate) fn acquire(
        root: impl Into<PathBuf>,
        stable_lock_path: impl Into<PathBuf>,
        node: NodeId,
    ) -> Result<Self, JournalStoreError> {
        Self::acquire_inner(root.into(), stable_lock_path.into(), node, None)
    }

    /// Acquire using the exact journal and authority parent descriptors
    /// already pinned by the outer Host lease. Path resolution remains useful
    /// for retaining the complete ancestor chain, but it must reproduce these
    /// identities before this function may create or repair any slot entry.
    pub(crate) fn acquire_with_pinned_parents(
        root: impl Into<PathBuf>,
        stable_lock_path: impl Into<PathBuf>,
        node: NodeId,
        pinned_journal_parent: &File,
        pinned_authority_parent: &File,
    ) -> Result<Self, JournalStoreError> {
        Self::acquire_inner(
            root.into(),
            stable_lock_path.into(),
            node,
            Some((pinned_journal_parent, pinned_authority_parent)),
        )
    }

    fn acquire_inner(
        root: PathBuf,
        stable_lock_path: PathBuf,
        node: NodeId,
        pinned_parents: Option<(&File, &File)>,
    ) -> Result<Self, JournalStoreError> {
        if node == NodeId::ZERO {
            return Err(JournalStoreError::ScopeMismatch);
        }
        let requested_root = clean_absolute_path(root)?;
        let agent = agent_from_root_path(&requested_root)?;
        let root_parent = requested_root
            .parent()
            .ok_or(JournalStoreError::InvalidPath)?
            .to_path_buf();
        let root_leaf = requested_root
            .file_name()
            .and_then(|name| name.to_str())
            .ok_or(JournalStoreError::InvalidPath)?;
        let canonical_root = root_parent.join(root_leaf);
        let root_name = c_name(root_leaf)?;

        let stable_lock_path = clean_absolute_path(stable_lock_path)?;
        if stable_lock_path.starts_with(&canonical_root) {
            return Err(JournalStoreError::InvalidPath);
        }
        let expected_lock_leaf = canonical_root
            .with_extension("agent-lock")
            .file_name()
            .and_then(|name| name.to_str())
            .ok_or(JournalStoreError::InvalidPath)?
            .to_owned();
        let stable_lock_leaf = stable_lock_path
            .file_name()
            .and_then(|name| name.to_str())
            .ok_or(JournalStoreError::InvalidPath)?;
        if stable_lock_leaf != expected_lock_leaf {
            return Err(JournalStoreError::InvalidPath);
        }
        let authority_parent_path = stable_lock_path
            .parent()
            .ok_or(JournalStoreError::InvalidPath)?
            .to_path_buf();
        let stable_lock_name = c_name(stable_lock_leaf)?;
        let ledger_leaf = system_authority_ledger_file_name(agent);
        let ledger_name = c_name(&ledger_leaf)?;
        let ledger_stage_name = c_name(&sibling_next_name(&ledger_leaf))?;

        let journal_parent = AbsoluteDirectoryCapability::open(&root_parent)?;
        let authority_parent = AbsoluteDirectoryCapability::open(&authority_parent_path)?;
        let journal_parent_directory = journal_parent.get()?;
        let authority_parent_directory = authority_parent.get()?;
        if let Some((pinned_journal_parent, pinned_authority_parent)) = pinned_parents {
            validate_owned_directory(pinned_journal_parent)?;
            validate_owned_directory(pinned_authority_parent)?;
            if FileIdentity::of(journal_parent_directory)?
                != FileIdentity::of(pinned_journal_parent)?
                || FileIdentity::of(authority_parent_directory)?
                    != FileIdentity::of(pinned_authority_parent)?
            {
                return Err(JournalStoreError::Corrupt);
            }
        }
        reject_legacy_generation_at(journal_parent_directory, agent)?;

        let mut generation = stat_at(journal_parent_directory, &root_name)
            .map_err(|_| JournalStoreError::Unavailable)?;
        let mut canonical = stat_at(authority_parent_directory, &ledger_name)
            .map_err(|_| JournalStoreError::Unavailable)?;
        let mut stage = stat_at(authority_parent_directory, &ledger_stage_name)
            .map_err(|_| JournalStoreError::Unavailable)?;
        let lock = stat_at(authority_parent_directory, &stable_lock_name)
            .map_err(|_| JournalStoreError::Unavailable)?;

        validate_slot_entry_shapes(
            generation.as_ref(),
            canonical.as_ref(),
            stage.as_ref(),
            lock.as_ref(),
        )?;
        validate_pre_lock_stage_freshness(stage.as_ref(), lock.as_ref())?;

        // The only state allowed to mint freshness is a completely empty
        // external slot. The staged inode is durable before the stable lock
        // can appear, so a lock-only crash state can never be produced here.
        let mut fresh_ledger_stage = None;
        if generation.is_none() && canonical.is_none() && stage.is_none() && lock.is_none() {
            match create_empty_exclusive_regular_at(authority_parent_directory, &ledger_stage_name)
            {
                Ok(file) => {
                    validate_owned_regular_file(&file)?;
                    let identity = FileIdentity::of(&file)?;
                    file.sync_all()
                        .and_then(|()| authority_parent_directory.sync_all())
                        .map_err(|_| JournalStoreError::Unavailable)?;
                    verify_regular_entry(authority_parent_directory, &ledger_stage_name, identity)?;
                    fresh_ledger_stage = Some((file, identity));
                }
                Err(error) if error.raw_os_error() == Some(libc::EEXIST) => {}
                Err(_) => return Err(JournalStoreError::Unavailable),
            }
        }

        // Re-read after the O_EXCL race before deciding whether creation of a
        // lock is authorized by the staged freshness witness.
        generation = stat_at(journal_parent_directory, &root_name)
            .map_err(|_| JournalStoreError::Unavailable)?;
        canonical = stat_at(authority_parent_directory, &ledger_name)
            .map_err(|_| JournalStoreError::Unavailable)?;
        stage = stat_at(authority_parent_directory, &ledger_stage_name)
            .map_err(|_| JournalStoreError::Unavailable)?;
        let lock = stat_at(authority_parent_directory, &stable_lock_name)
            .map_err(|_| JournalStoreError::Unavailable)?;
        validate_slot_entry_shapes(
            generation.as_ref(),
            canonical.as_ref(),
            stage.as_ref(),
            lock.as_ref(),
        )?;
        validate_pre_lock_stage_freshness(stage.as_ref(), lock.as_ref())?;
        if let Some((file, identity)) = &fresh_ledger_stage {
            validate_owned_regular_file(file)?;
            match stage.as_ref() {
                Some(stage) if status_identity(stage) == *identity => {
                    verify_regular_entry(
                        authority_parent_directory,
                        &ledger_stage_name,
                        *identity,
                    )?;
                }
                // Another process can win the lock, publish the exact inode,
                // and release it before this process acquires the lock. That
                // is an existing canonical reopen, never fresh authority.
                None if canonical
                    .as_ref()
                    .is_some_and(|canonical| status_identity(canonical) == *identity) =>
                {
                    fresh_ledger_stage = None;
                }
                _ => return Err(JournalStoreError::Corrupt),
            }
        }

        // A pre-existing empty stage is the durable freshness witness for
        // every retry before redb initialization. Re-sync the inode and its
        // directory before creating or repairing nonce bytes; the previous
        // attempt may have returned after either sync failed.
        if fresh_ledger_stage.is_none()
            && generation.is_none()
            && canonical.is_none()
            && stage.as_ref().is_some_and(|stage| stage.st_size == 0)
        {
            resync_pristine_ledger_stage(
                authority_parent_directory,
                &ledger_stage_name,
                stage.as_ref().expect("checked staged freshness witness"),
            )?;
        }

        if generation.is_some() && canonical.is_none()
            || generation.is_some() && lock.is_none()
            || canonical.is_some() && lock.is_none()
            || generation.is_some() && canonical.is_none() && stage.is_some()
            || generation.is_none() && canonical.is_none() && stage.is_none() && lock.is_some()
        {
            return Err(JournalStoreError::Corrupt);
        }

        let (stable_lock, stable_lock_nonce) = if lock.is_some() {
            // A staged-only slot is the sole state in which an empty lock is
            // a legitimate crash remnant: creation publishes the durable
            // ledger stage before creating and filling the lock nonce.  A
            // canonical ledger or Agent generation never carries authority
            // to repair a truncated lock.
            open_existing_stable_lock_at(
                authority_parent_directory,
                stable_lock_leaf,
                generation.is_none()
                    && canonical.is_none()
                    && stage.as_ref().is_some_and(|stage| stage.st_size == 0),
            )?
        } else {
            if generation.is_some() || canonical.is_some() || stage.is_none() {
                return Err(JournalStoreError::Corrupt);
            }
            create_stable_lock_at(authority_parent_directory, stable_lock_leaf)?
        };
        let stable_lock_identity = FileIdentity::of(&stable_lock)?;
        verify_regular_entry(
            authority_parent_directory,
            &stable_lock_name,
            stable_lock_identity,
        )?;
        require_single_link(&stable_lock)?;

        // The stable lock serializes every state transition below. Re-read the
        // complete cross-parent matrix now that no competing Host can publish
        // the authority stage or create the journal root.
        generation = stat_at(journal_parent_directory, &root_name)
            .map_err(|_| JournalStoreError::Unavailable)?;
        canonical = stat_at(authority_parent_directory, &ledger_name)
            .map_err(|_| JournalStoreError::Unavailable)?;
        stage = stat_at(authority_parent_directory, &ledger_stage_name)
            .map_err(|_| JournalStoreError::Unavailable)?;
        let lock = stat_at(authority_parent_directory, &stable_lock_name)
            .map_err(|_| JournalStoreError::Unavailable)?;
        validate_slot_entry_shapes(
            generation.as_ref(),
            canonical.as_ref(),
            stage.as_ref(),
            lock.as_ref(),
        )?;
        if generation.is_some() && canonical.is_none()
            || canonical.is_none() && stage.is_none()
            || generation.is_some() && canonical.is_none()
        {
            return Err(JournalStoreError::Corrupt);
        }
        verify_regular_entry(
            authority_parent_directory,
            &stable_lock_name,
            stable_lock_identity,
        )?;
        require_single_link(&stable_lock)?;
        verify_stable_lock_nonce(&stable_lock, &stable_lock_nonce)?;

        let instance_id =
            file_journal_store_instance_id(&canonical_root, agent, node, &stable_lock_nonce)?;
        Ok(Self {
            root: canonical_root,
            root_name,
            instance_id,
            agent,
            node,
            journal_parent,
            authority_parent,
            generation_exists: generation.is_some(),
            stable_lock_name,
            stable_lock_identity,
            stable_lock_nonce,
            stable_lock,
            fresh_ledger_stage,
        })
    }

    pub(crate) const fn instance_id(&self) -> JournalStoreInstanceId {
        self.instance_id
    }

    pub(crate) const fn node(&self) -> NodeId {
        self.node
    }

    pub(crate) const fn generation_exists(&self) -> bool {
        self.generation_exists
    }

    #[cfg(feature = "storage")]
    pub(crate) fn open_system_authority_ledger(
        &self,
    ) -> Result<FileSystemAuthorityLedger, JournalStoreError> {
        self.verify_lock()?;
        let parent = self.authority_parent.get()?;
        let canonical_leaf = system_authority_ledger_file_name(self.agent);
        let stage_leaf = sibling_next_name(&canonical_leaf);
        let canonical_name = c_name(&canonical_leaf)?;
        let stage_name = c_name(&stage_leaf)?;
        let canonical =
            stat_at(parent, &canonical_name).map_err(|_| JournalStoreError::Unavailable)?;
        let stage = stat_at(parent, &stage_name).map_err(|_| JournalStoreError::Unavailable)?;
        validate_slot_entry_shapes(None, canonical.as_ref(), stage.as_ref(), None)?;

        if self.generation_exists && canonical.is_none() {
            return Err(JournalStoreError::Corrupt);
        }
        let (mode, stage_alias, file, identity) = match (canonical, stage) {
            (Some(canonical), Some(stage)) => {
                if status_identity(&canonical) != status_identity(&stage) {
                    return Err(JournalStoreError::Corrupt);
                }
                let file = open_owned_regular_at(parent, &canonical_name)?;
                let identity = FileIdentity::of(&file)?;
                if identity != status_identity(&canonical) {
                    return Err(JournalStoreError::Corrupt);
                }
                (
                    FileSystemAuthorityLedgerOpenMode::ExistingCanonical,
                    true,
                    file,
                    identity,
                )
            }
            (Some(canonical), None) => {
                let file = open_owned_regular_at(parent, &canonical_name)?;
                let identity = FileIdentity::of(&file)?;
                if identity != status_identity(&canonical) {
                    return Err(JournalStoreError::Corrupt);
                }
                (
                    FileSystemAuthorityLedgerOpenMode::ExistingCanonical,
                    false,
                    file,
                    identity,
                )
            }
            (None, Some(stage)) if !self.generation_exists => {
                let file = if let Some((fresh, identity)) = &self.fresh_ledger_stage {
                    if status_identity(&stage) != *identity {
                        return Err(JournalStoreError::Corrupt);
                    }
                    verify_regular_entry(parent, &stage_name, *identity)?;
                    fresh
                        .try_clone()
                        .map_err(|_| JournalStoreError::Unavailable)?
                } else {
                    open_owned_regular_at(parent, &stage_name)?
                };
                let identity = FileIdentity::of(&file)?;
                if identity != status_identity(&stage) {
                    return Err(JournalStoreError::Corrupt);
                }
                (
                    if self.fresh_ledger_stage.is_some() {
                        FileSystemAuthorityLedgerOpenMode::FreshStage
                    } else {
                        FileSystemAuthorityLedgerOpenMode::ExistingStage
                    },
                    true,
                    file,
                    identity,
                )
            }
            _ => return Err(JournalStoreError::Corrupt),
        };

        require_link_count(
            &file,
            if mode == FileSystemAuthorityLedgerOpenMode::ExistingCanonical && stage_alias {
                2
            } else {
                1
            },
        )?;

        let database = match mode {
            FileSystemAuthorityLedgerOpenMode::FreshStage
            | FileSystemAuthorityLedgerOpenMode::ExistingStage => Database::builder().create_file(
                file.try_clone()
                    .map_err(|_| JournalStoreError::Unavailable)?,
            ),
            FileSystemAuthorityLedgerOpenMode::ExistingCanonical => {
                Database::open(proc_fd_path(&file))
            }
        }
        .map_err(|_| JournalStoreError::Corrupt)?;
        let ledger = FileSystemAuthorityLedger {
            database: Arc::new(database),
            journal_store: self.instance_id,
            agent: self.agent,
            local_node: self.node,
            authority_parent: self.authority_parent.try_clone()?,
            canonical_name,
            stage_name,
            identity,
            file,
            mode,
            stage_alias,
        };
        ledger.verify_open_aliases()?;
        self.verify_lock()?;
        Ok(ledger)
    }

    #[cfg(feature = "storage")]
    pub(crate) fn bind_system_authority_ledger_owner(
        &self,
        opened: OpenedFileSystemAuthorityLedgerOwner,
        sealed: &ReplaySealedGenesis,
    ) -> Result<BoundFileSystemAuthorityLedgerOwner, JournalStoreError> {
        let OpenedFileSystemAuthorityLedgerOwner { ledger, owner } = opened;
        self.verify_lock()?;
        if !owner.owns_database(&ledger.database)
            || owner.journal_store() != self.instance_id
            || owner.local_node() != self.node
            || owner.route()
                != sealed
                    .system_authority_ledger_route()
                    .map_err(|_| JournalStoreError::ScopeMismatch)?
        {
            return Err(JournalStoreError::ScopeMismatch);
        }
        let bound = ledger.bind_owner(owner)?;
        bound.verify()?;
        self.verify_lock()?;
        Ok(bound)
    }

    /// Consume the already-locked external slot and open or create the Agent
    /// journal only after the canonical authority sidecar has been published.
    /// Production invokes this closure under the route owner's dedicated
    /// startup-recovery writer; no store escapes if subsequent reconciliation
    /// fails.
    #[cfg(feature = "storage")]
    pub(crate) fn open_reverified(
        self,
        sealed: &ReplaySealedGenesis,
        startup: &BoundFileSystemAuthorityStartup<'_, '_>,
        strict_unexposed: bool,
    ) -> Result<FileAgentJournalStore, JournalStoreError> {
        let authority_ledger = startup.authority;
        self.verify_lock()?;
        authority_ledger.verify()?;
        if authority_ledger.owner.journal_store() != self.instance_id
            || authority_ledger.owner.local_node() != self.node
            || authority_ledger.owner.route()
                != sealed
                    .system_authority_ledger_route()
                    .map_err(|_| JournalStoreError::ScopeMismatch)?
        {
            return Err(JournalStoreError::ScopeMismatch);
        }
        let authority_ledger_file = &authority_ledger.ledger;
        let authority_parent = self.authority_parent.get()?;
        let ledger_leaf = system_authority_ledger_file_name(self.agent);
        let ledger_name = c_name(&ledger_leaf)?;
        let ledger_stage_name = c_name(&sibling_next_name(&ledger_leaf))?;
        let ledger = stat_at(authority_parent, &ledger_name)
            .map_err(|_| JournalStoreError::Unavailable)?
            .ok_or(JournalStoreError::Corrupt)?;
        validate_slot_entry_shapes(None, Some(&ledger), None, None)?;
        if authority_ledger_file.canonical_name != ledger_name
            || authority_ledger_file.identity != status_identity(&ledger)
            || FileIdentity::of(authority_ledger_file.authority_parent.get()?)?
                != FileIdentity::of(authority_parent)?
        {
            return Err(JournalStoreError::Corrupt);
        }
        if stat_at(authority_parent, &ledger_stage_name)
            .map_err(|_| JournalStoreError::Unavailable)?
            .is_some()
        {
            return Err(JournalStoreError::Corrupt);
        }

        // Inspect every recognized fixed anchor before cleanup or layout
        // creation.  An exposed generation must already be complete.  A
        // never-exposed generation may resume only an exact monotonic prefix
        // of this sealed genesis; a complete prefix is reopened read-only so
        // it cannot be changed before the outer Arm/exposure transaction.
        let unexposed_complete = if startup.journal_exposure_committed {
            false
        } else {
            self.preflight_unexposed_generation_prefix(sealed)?
        };
        if !startup.journal_exposure_committed && strict_unexposed && !unexposed_complete {
            return Err(JournalStoreError::Corrupt);
        }
        let read_only_open = startup.journal_exposure_committed || unexposed_complete;
        if startup.journal_exposure_committed {
            self.preflight_exposed_generation(sealed)?;
        }

        let root_leaf = self
            .root_name
            .to_str()
            .map_err(|_| JournalStoreError::InvalidPath)?;
        let journal_parent = self.journal_parent.get()?;
        reject_legacy_generation_at(journal_parent, self.agent)?;
        if !read_only_open {
            ensure_directory_at(journal_parent, root_leaf)?;
        }
        let root_directory = open_directory_at(journal_parent, root_leaf)?;
        validate_owned_directory(&root_directory)?;
        verify_regular_entry(
            authority_parent,
            &self.stable_lock_name,
            self.stable_lock_identity,
        )?;
        if !read_only_open {
            discard_private_stages_at(&root_directory, is_fixed_private_stage_name)?;
        }
        validate_directory_names(
            &root_directory,
            &[
                "records",
                "checkpoints",
                "lane-state",
                "artifact-closures",
                "invocation-index",
                "invocation-outcomes",
                SHARED_ORDERED_COMMIT_DIRECTORY,
                HISTORY_DIRECTORY,
                "catalog",
                "authority",
                "genesis-admission",
                "genesis-admission.next",
                "genesis",
                "genesis.next",
                "heads",
                "heads.next",
                GC_INTENT_NAME,
                GC_INTENT_STAGE_NAME,
            ],
        )?;

        let directories =
            DirectoryCapabilities::new(self.journal_parent, self.root_name, root_directory)?;
        let mut store = FileAgentJournalStore {
            root: self.root,
            instance_id: self.instance_id,
            agent: self.agent,
            node: self.node,
            directories,
            history_candidate: None,
            replayed_root: None,
            startup_recovery_pending: startup.journal_exposure_committed,
            authority_parent: self.authority_parent,
            stable_lock_name: self.stable_lock_name,
            stable_lock_identity: self.stable_lock_identity,
            stable_lock_nonce: self.stable_lock_nonce,
            local_exposure: None,
            _stable_lock: self.stable_lock,
        };
        store.validate_recovery_state()?;
        if read_only_open {
            store.open_existing_layout()?;
        } else {
            store.ensure_layout()?;
            store.recover_history_state()?;
        }
        store.validate_authority_recovery(Some(sealed), false)?;
        store.replayed_root = Some(
            sealed
                .replayed_root_identity()
                .map_err(|_| JournalStoreError::ScopeMismatch)?,
        );
        if let Some(heads) = store.heads()? {
            validate_head_targets(&store, &heads)?;
        }
        if let Some(staged) = store.read_fixed::<JournalHeads>("", "heads.next")? {
            validate_head_targets(&store, &staged)?;
        }
        authority_ledger.verify()?;
        if authority_ledger.owner.journal_store() != store.instance_id
            || authority_ledger.owner.local_node() != store.node
            || authority_ledger.owner.route()
                != sealed
                    .system_authority_ledger_route()
                    .map_err(|_| JournalStoreError::ScopeMismatch)?
        {
            return Err(JournalStoreError::ScopeMismatch);
        }
        Ok(store)
    }

    /// Read-only admission of a never-exposed first-initialization prefix.
    /// Every visible recognized stage/canonical must contain the exact sealed
    /// initial value, and later anchors require their canonical predecessor.
    /// The boolean reports the exact complete, stage-free generation.
    fn preflight_unexposed_generation_prefix(
        &self,
        sealed: &ReplaySealedGenesis,
    ) -> Result<bool, JournalStoreError> {
        if !self.generation_exists {
            return Ok(false);
        }
        let parent = self.journal_parent.get()?;
        let root_leaf = self
            .root_name
            .to_str()
            .map_err(|_| JournalStoreError::InvalidPath)?;
        let root_directory = open_directory_at(parent, root_leaf)?;
        validate_owned_directory(&root_directory)?;
        let root_identity = FileIdentity::of(&root_directory)?;
        verify_directory_entry(parent, &self.root_name, root_identity)?;
        validate_unexposed_initialization_namespace(&root_directory)?;

        validate_initialization_anchor_links(&root_directory, "genesis-admission", true)?;
        validate_initialization_anchor_links(&root_directory, "genesis", true)?;
        validate_initialization_anchor_links(&root_directory, "heads", false)?;

        let admission = read_pinned_bounded_regular_at(
            &root_directory,
            "genesis-admission",
            core::mem::size_of::<Hash>(),
        )?;
        let staged_admission = read_pinned_bounded_regular_at(
            &root_directory,
            "genesis-admission.next",
            core::mem::size_of::<Hash>(),
        )?;
        for value in [&admission, &staged_admission].into_iter().flatten() {
            if value.as_slice() != sealed.admission_commitment().as_bytes() {
                return Err(JournalStoreError::ScopeMismatch);
            }
        }

        let genesis = read_pinned_bounded_regular_at(
            &root_directory,
            "genesis",
            class_maximum(JournalStorageClass::Genesis),
        )?;
        let staged_genesis = read_pinned_bounded_regular_at(
            &root_directory,
            "genesis.next",
            class_maximum(JournalStorageClass::Genesis),
        )?;
        for value in [&genesis, &staged_genesis].into_iter().flatten() {
            let decoded = decode_object::<AgentJournalGenesis>(value, sealed.genesis().id())?;
            if decoded != *sealed.genesis() {
                return Err(JournalStoreError::ScopeMismatch);
            }
        }

        let heads = read_pinned_bounded_regular_at(
            &root_directory,
            "heads",
            class_maximum(JournalStorageClass::Heads),
        )?;
        let staged_heads = read_pinned_bounded_regular_at(
            &root_directory,
            "heads.next",
            class_maximum(JournalStorageClass::Heads),
        )?;
        let initial_heads = sealed.initial_heads();
        for value in [&heads, &staged_heads].into_iter().flatten() {
            let decoded = JournalHeads::decode(value).map_err(|_| JournalStoreError::Corrupt)?;
            let decoded = decode_object::<JournalHeads>(value, decoded.id())?;
            if decoded != initial_heads {
                return Err(JournalStoreError::ScopeMismatch);
            }
        }

        let has_genesis = genesis.is_some() || staged_genesis.is_some();
        let has_heads = heads.is_some() || staged_heads.is_some();
        if has_genesis && admission.is_none()
            || has_heads && genesis.is_none()
            || staged_admission.is_some() && (has_genesis || has_heads)
            || staged_genesis.is_some() && has_heads
        {
            return Err(JournalStoreError::Corrupt);
        }

        validate_initialization_anchor_links(&root_directory, "genesis-admission", true)?;
        validate_initialization_anchor_links(&root_directory, "genesis", true)?;
        validate_initialization_anchor_links(&root_directory, "heads", false)?;
        validate_unexposed_initialization_namespace(&root_directory)?;
        verify_directory_entry(parent, &self.root_name, root_identity)?;
        Ok(admission.is_some()
            && genesis.is_some()
            && heads.is_some()
            && staged_admission.is_none()
            && staged_genesis.is_none()
            && staged_heads.is_none())
    }

    fn preflight_exposed_generation(
        &self,
        sealed: &ReplaySealedGenesis,
    ) -> Result<(), JournalStoreError> {
        if !self.generation_exists {
            return Err(JournalStoreError::Corrupt);
        }
        let parent = self.journal_parent.get()?;
        let root_leaf = self
            .root_name
            .to_str()
            .map_err(|_| JournalStoreError::InvalidPath)?;
        let root_directory = open_directory_at(parent, root_leaf)?;
        validate_owned_directory(&root_directory)?;
        let root_identity = FileIdentity::of(&root_directory)?;
        verify_directory_entry(parent, &self.root_name, root_identity)?;

        validate_initialization_anchor_links(&root_directory, "genesis-admission", true)?;
        validate_initialization_anchor_links(&root_directory, "genesis", true)?;
        validate_initialization_anchor_links(&root_directory, "heads", false)?;

        for stage in ["genesis-admission.next", "genesis.next", "heads.next"] {
            if stat_at(&root_directory, &c_name(stage)?)
                .map_err(|_| JournalStoreError::Unavailable)?
                .is_some()
            {
                return Err(JournalStoreError::Corrupt);
            }
        }

        let admission = read_pinned_bounded_regular_at(
            &root_directory,
            "genesis-admission",
            core::mem::size_of::<Hash>(),
        )?
        .ok_or(JournalStoreError::Corrupt)?;
        if admission.as_slice() != sealed.admission_commitment().as_bytes() {
            return Err(JournalStoreError::ScopeMismatch);
        }

        let genesis = read_pinned_bounded_regular_at(
            &root_directory,
            "genesis",
            class_maximum(JournalStorageClass::Genesis),
        )?
        .ok_or(JournalStoreError::Corrupt)?;
        let decoded_genesis =
            decode_object::<AgentJournalGenesis>(&genesis, sealed.genesis().id())?;
        if decoded_genesis != *sealed.genesis() {
            return Err(JournalStoreError::ScopeMismatch);
        }

        let heads = read_pinned_bounded_regular_at(
            &root_directory,
            "heads",
            class_maximum(JournalStorageClass::Heads),
        )?
        .ok_or(JournalStoreError::Corrupt)?;
        let decoded_heads = JournalHeads::decode(&heads).map_err(|_| JournalStoreError::Corrupt)?;
        let decoded_heads = decode_object::<JournalHeads>(&heads, decoded_heads.id())?;
        if decoded_heads.genesis != sealed.genesis().id()
            || decoded_heads.admission != sealed.genesis().admission
            || decoded_heads.node != self.node
            || decoded_heads.runtime.agent != self.agent
        {
            return Err(JournalStoreError::ScopeMismatch);
        }

        validate_directory_names(
            &root_directory,
            &[
                "records",
                "checkpoints",
                "lane-state",
                "artifact-closures",
                "invocation-index",
                "invocation-outcomes",
                SHARED_ORDERED_COMMIT_DIRECTORY,
                HISTORY_DIRECTORY,
                "catalog",
                "authority",
                "genesis-admission",
                "genesis-admission.next",
                "genesis",
                "genesis.next",
                "heads",
                "heads.next",
                GC_INTENT_NAME,
                GC_INTENT_STAGE_NAME,
            ],
        )?;

        validate_initialization_anchor_links(&root_directory, "genesis-admission", true)?;
        validate_initialization_anchor_links(&root_directory, "genesis", true)?;
        validate_initialization_anchor_links(&root_directory, "heads", false)?;
        verify_directory_entry(parent, &self.root_name, root_identity)?;
        Ok(())
    }

    fn verify_lock(&self) -> Result<(), JournalStoreError> {
        verify_regular_entry(
            self.authority_parent.get()?,
            &self.stable_lock_name,
            self.stable_lock_identity,
        )?;
        require_single_link(&self.stable_lock)?;
        verify_stable_lock_nonce(&self.stable_lock, &self.stable_lock_nonce)
    }
}

#[cfg(target_os = "linux")]
impl FileLocalAgentJournalSlot {
    /// Acquire an ordinary Local slot only after Host has made the exact
    /// creation intent durable.  Consequently a missing stable lock may be
    /// created, while a lock without that host-owned intent never reaches
    /// this API.
    pub(crate) fn acquire_with_pinned_parents(
        root: impl Into<PathBuf>,
        stable_lock_path: impl Into<PathBuf>,
        node: NodeId,
        intent: Hash,
        pinned_journal_parent: &File,
        pinned_authority_parent: &File,
    ) -> Result<Self, JournalStoreError> {
        if node == NodeId::ZERO || intent == Hash::ZERO {
            return Err(JournalStoreError::ScopeMismatch);
        }
        let requested_root = clean_absolute_path(root.into())?;
        let agent = agent_from_root_path(&requested_root)?;
        let root_parent = requested_root
            .parent()
            .ok_or(JournalStoreError::InvalidPath)?
            .to_path_buf();
        let root_leaf = requested_root
            .file_name()
            .and_then(|name| name.to_str())
            .ok_or(JournalStoreError::InvalidPath)?;
        let canonical_root = root_parent.join(root_leaf);
        let root_name = c_name(root_leaf)?;

        let stable_lock_path = clean_absolute_path(stable_lock_path.into())?;
        if stable_lock_path.starts_with(&canonical_root) {
            return Err(JournalStoreError::InvalidPath);
        }
        let expected_lock_leaf = canonical_root
            .with_extension("agent-lock")
            .file_name()
            .and_then(|name| name.to_str())
            .ok_or(JournalStoreError::InvalidPath)?
            .to_owned();
        let stable_lock_leaf = stable_lock_path
            .file_name()
            .and_then(|name| name.to_str())
            .ok_or(JournalStoreError::InvalidPath)?;
        if stable_lock_leaf != expected_lock_leaf {
            return Err(JournalStoreError::InvalidPath);
        }
        let authority_parent_path = stable_lock_path
            .parent()
            .ok_or(JournalStoreError::InvalidPath)?
            .to_path_buf();
        let stable_lock_name = c_name(stable_lock_leaf)?;
        let journal_parent = AbsoluteDirectoryCapability::open(&root_parent)?;
        let authority_parent = AbsoluteDirectoryCapability::open(&authority_parent_path)?;
        validate_owned_directory(pinned_journal_parent)?;
        validate_owned_directory(pinned_authority_parent)?;
        if FileIdentity::of(journal_parent.get()?)? != FileIdentity::of(pinned_journal_parent)?
            || FileIdentity::of(authority_parent.get()?)?
                != FileIdentity::of(pinned_authority_parent)?
        {
            return Err(JournalStoreError::Corrupt);
        }
        reject_legacy_generation_at(journal_parent.get()?, agent)?;

        let generation = stat_at(journal_parent.get()?, &root_name)
            .map_err(|_| JournalStoreError::Unavailable)?;
        let lock = stat_at(authority_parent.get()?, &stable_lock_name)
            .map_err(|_| JournalStoreError::Unavailable)?;
        validate_slot_entry_shapes(generation.as_ref(), None, None, lock.as_ref())?;
        let (stable_lock, stable_lock_nonce, exposure_committed) = match lock {
            Some(_) => open_existing_local_stable_lock_at(
                authority_parent.get()?,
                stable_lock_leaf,
                generation.is_none(),
                generation.is_some(),
                intent,
            )?,
            None => {
                if generation.is_some() {
                    return Err(JournalStoreError::Corrupt);
                }
                create_local_stable_lock_at(authority_parent.get()?, stable_lock_leaf, intent)?
            }
        };
        let stable_lock_identity = FileIdentity::of(&stable_lock)?;
        verify_regular_entry(
            authority_parent.get()?,
            &stable_lock_name,
            stable_lock_identity,
        )?;
        require_single_link(&stable_lock)?;
        if verify_local_stable_lock(&stable_lock, &stable_lock_nonce, intent)? != exposure_committed
        {
            return Err(JournalStoreError::Corrupt);
        }
        let generation = stat_at(journal_parent.get()?, &root_name)
            .map_err(|_| JournalStoreError::Unavailable)?;
        validate_slot_entry_shapes(
            generation.as_ref(),
            None,
            None,
            Some(
                &stat_at(authority_parent.get()?, &stable_lock_name)
                    .map_err(|_| JournalStoreError::Unavailable)?
                    .ok_or(JournalStoreError::Corrupt)?,
            ),
        )?;
        let instance_id =
            file_journal_store_instance_id(&canonical_root, agent, node, &stable_lock_nonce)?;
        Ok(Self {
            root: canonical_root,
            root_name,
            instance_id,
            agent,
            node,
            journal_parent,
            authority_parent,
            generation_exists: generation.is_some(),
            stable_lock_name,
            stable_lock_identity,
            stable_lock_nonce,
            intent,
            exposure_committed,
            stable_lock,
        })
    }

    pub(crate) fn generation_exists(&self) -> bool {
        self.generation_exists
    }

    /// Open or resume an ordinary Local generation under its exact opaque
    /// admission. `exposed` is the separately durable Host marker; an
    /// exposed store must already be complete, while an unexposed store may
    /// resume only a monotonic prefix of this seal.
    pub(crate) fn open(
        self,
        sealed: &ReplaySealedLocalGenesis,
        externally_exposed: bool,
    ) -> Result<FileAgentJournalStore, JournalStoreError> {
        self.verify_lock()?;
        if externally_exposed && !self.exposure_committed {
            return Err(JournalStoreError::Corrupt);
        }
        let exposed = externally_exposed || self.exposure_committed;
        let unexposed_complete = if exposed {
            false
        } else {
            self.preflight_unexposed_generation_prefix(sealed)?
        };
        if exposed {
            self.preflight_exposed_generation(sealed)?;
        }
        let read_only_open = exposed || unexposed_complete;
        let root_leaf = self
            .root_name
            .to_str()
            .map_err(|_| JournalStoreError::InvalidPath)?;
        let journal_parent = self.journal_parent.get()?;
        reject_legacy_generation_at(journal_parent, self.agent)?;
        if !read_only_open {
            ensure_directory_at(journal_parent, root_leaf)?;
        }
        let root_directory = open_directory_at(journal_parent, root_leaf)?;
        validate_owned_directory(&root_directory)?;
        verify_regular_entry(
            self.authority_parent.get()?,
            &self.stable_lock_name,
            self.stable_lock_identity,
        )?;
        if !read_only_open {
            discard_private_stages_at(&root_directory, is_fixed_private_stage_name)?;
        }
        validate_directory_names(
            &root_directory,
            &[
                "records",
                "checkpoints",
                "lane-state",
                "artifact-closures",
                "invocation-index",
                "invocation-outcomes",
                SHARED_ORDERED_COMMIT_DIRECTORY,
                HISTORY_DIRECTORY,
                "catalog",
                "authority",
                "genesis-admission",
                "genesis-admission.next",
                "genesis",
                "genesis.next",
                "heads",
                "heads.next",
                GC_INTENT_NAME,
                GC_INTENT_STAGE_NAME,
            ],
        )?;
        let directories =
            DirectoryCapabilities::new(self.journal_parent, self.root_name, root_directory)?;
        let mut store = FileAgentJournalStore {
            root: self.root,
            instance_id: self.instance_id,
            agent: self.agent,
            node: self.node,
            directories,
            history_candidate: None,
            replayed_root: None,
            // A complete but not-yet-exposed generation was opened without
            // mutation. Defer its private-stage cleanup until replay has
            // authenticated the exact genesis just like an exposed reopen.
            startup_recovery_pending: read_only_open,
            authority_parent: self.authority_parent,
            stable_lock_name: self.stable_lock_name,
            stable_lock_identity: self.stable_lock_identity,
            stable_lock_nonce: self.stable_lock_nonce,
            local_exposure: Some(self.intent),
            _stable_lock: self.stable_lock,
        };
        store.validate_recovery_state()?;
        if read_only_open {
            store.open_existing_layout()?;
        } else {
            store.ensure_layout()?;
            store.recover_history_state()?;
        }
        store.validate_local_authority_recovery(sealed)?;
        if let Some(heads) = store.heads()? {
            validate_head_targets(&store, &heads)?;
        }
        if let Some(staged) = store.read_fixed::<JournalHeads>("", "heads.next")? {
            validate_head_targets(&store, &staged)?;
        }
        store.verify_lock()?;
        Ok(store)
    }

    fn preflight_unexposed_generation_prefix(
        &self,
        sealed: &ReplaySealedLocalGenesis,
    ) -> Result<bool, JournalStoreError> {
        if !self.generation_exists {
            return Ok(false);
        }
        let parent = self.journal_parent.get()?;
        let root_leaf = self
            .root_name
            .to_str()
            .map_err(|_| JournalStoreError::InvalidPath)?;
        let root_directory = open_directory_at(parent, root_leaf)?;
        validate_owned_directory(&root_directory)?;
        let root_identity = FileIdentity::of(&root_directory)?;
        verify_directory_entry(parent, &self.root_name, root_identity)?;
        validate_unexposed_initialization_namespace(&root_directory)?;
        validate_initialization_anchor_links(&root_directory, "genesis-admission", true)?;
        validate_initialization_anchor_links(&root_directory, "genesis", true)?;
        validate_initialization_anchor_links(&root_directory, "heads", false)?;

        let admission = read_pinned_bounded_regular_at(
            &root_directory,
            "genesis-admission",
            core::mem::size_of::<Hash>(),
        )?;
        let staged_admission = read_pinned_bounded_regular_at(
            &root_directory,
            "genesis-admission.next",
            core::mem::size_of::<Hash>(),
        )?;
        for value in [&admission, &staged_admission].into_iter().flatten() {
            if value.as_slice() != sealed.admission_commitment().as_bytes() {
                return Err(JournalStoreError::ScopeMismatch);
            }
        }
        let genesis = read_pinned_bounded_regular_at(
            &root_directory,
            "genesis",
            class_maximum(JournalStorageClass::Genesis),
        )?;
        let staged_genesis = read_pinned_bounded_regular_at(
            &root_directory,
            "genesis.next",
            class_maximum(JournalStorageClass::Genesis),
        )?;
        for value in [&genesis, &staged_genesis].into_iter().flatten() {
            let decoded = decode_object::<AgentJournalGenesis>(value, sealed.genesis().id())?;
            if decoded != *sealed.genesis() {
                return Err(JournalStoreError::ScopeMismatch);
            }
        }
        let heads = read_pinned_bounded_regular_at(
            &root_directory,
            "heads",
            class_maximum(JournalStorageClass::Heads),
        )?;
        let staged_heads = read_pinned_bounded_regular_at(
            &root_directory,
            "heads.next",
            class_maximum(JournalStorageClass::Heads),
        )?;
        let initial_heads = sealed.initial_heads();
        for value in [&heads, &staged_heads].into_iter().flatten() {
            let decoded = JournalHeads::decode(value).map_err(|_| JournalStoreError::Corrupt)?;
            let decoded = decode_object::<JournalHeads>(value, decoded.id())?;
            if decoded != initial_heads {
                return Err(JournalStoreError::ScopeMismatch);
            }
        }
        let has_genesis = genesis.is_some() || staged_genesis.is_some();
        let has_heads = heads.is_some() || staged_heads.is_some();
        if has_genesis && admission.is_none()
            || has_heads && genesis.is_none()
            || staged_admission.is_some() && (has_genesis || has_heads)
            || staged_genesis.is_some() && has_heads
        {
            return Err(JournalStoreError::Corrupt);
        }
        validate_initialization_anchor_links(&root_directory, "genesis-admission", true)?;
        validate_initialization_anchor_links(&root_directory, "genesis", true)?;
        validate_initialization_anchor_links(&root_directory, "heads", false)?;
        validate_unexposed_initialization_namespace(&root_directory)?;
        verify_directory_entry(parent, &self.root_name, root_identity)?;
        Ok(admission.is_some()
            && genesis.is_some()
            && heads.is_some()
            && staged_admission.is_none()
            && staged_genesis.is_none()
            && staged_heads.is_none())
    }

    fn preflight_exposed_generation(
        &self,
        sealed: &ReplaySealedLocalGenesis,
    ) -> Result<(), JournalStoreError> {
        if !self.generation_exists {
            return Err(JournalStoreError::Corrupt);
        }
        let parent = self.journal_parent.get()?;
        let root_leaf = self
            .root_name
            .to_str()
            .map_err(|_| JournalStoreError::InvalidPath)?;
        let root_directory = open_directory_at(parent, root_leaf)?;
        validate_owned_directory(&root_directory)?;
        let root_identity = FileIdentity::of(&root_directory)?;
        verify_directory_entry(parent, &self.root_name, root_identity)?;
        validate_initialization_anchor_links(&root_directory, "genesis-admission", true)?;
        validate_initialization_anchor_links(&root_directory, "genesis", true)?;
        validate_initialization_anchor_links(&root_directory, "heads", false)?;
        for stage in ["genesis-admission.next", "genesis.next", "heads.next"] {
            if stat_at(&root_directory, &c_name(stage)?)
                .map_err(|_| JournalStoreError::Unavailable)?
                .is_some()
            {
                return Err(JournalStoreError::Corrupt);
            }
        }
        let admission = read_pinned_bounded_regular_at(
            &root_directory,
            "genesis-admission",
            core::mem::size_of::<Hash>(),
        )?
        .ok_or(JournalStoreError::Corrupt)?;
        if admission.as_slice() != sealed.admission_commitment().as_bytes() {
            return Err(JournalStoreError::ScopeMismatch);
        }
        let genesis = read_pinned_bounded_regular_at(
            &root_directory,
            "genesis",
            class_maximum(JournalStorageClass::Genesis),
        )?
        .ok_or(JournalStoreError::Corrupt)?;
        let decoded_genesis =
            decode_object::<AgentJournalGenesis>(&genesis, sealed.genesis().id())?;
        if decoded_genesis != *sealed.genesis() {
            return Err(JournalStoreError::ScopeMismatch);
        }
        let heads = read_pinned_bounded_regular_at(
            &root_directory,
            "heads",
            class_maximum(JournalStorageClass::Heads),
        )?
        .ok_or(JournalStoreError::Corrupt)?;
        let decoded_heads = JournalHeads::decode(&heads).map_err(|_| JournalStoreError::Corrupt)?;
        let decoded_heads = decode_object::<JournalHeads>(&heads, decoded_heads.id())?;
        if decoded_heads.genesis != sealed.genesis().id()
            || decoded_heads.admission != sealed.genesis().admission
            || decoded_heads.node != self.node
            || decoded_heads.runtime.agent != self.agent
        {
            return Err(JournalStoreError::ScopeMismatch);
        }
        validate_directory_names(
            &root_directory,
            &[
                "records",
                "checkpoints",
                "lane-state",
                "artifact-closures",
                "invocation-index",
                "invocation-outcomes",
                SHARED_ORDERED_COMMIT_DIRECTORY,
                HISTORY_DIRECTORY,
                "catalog",
                "authority",
                "genesis-admission",
                "genesis-admission.next",
                "genesis",
                "genesis.next",
                "heads",
                "heads.next",
                GC_INTENT_NAME,
                GC_INTENT_STAGE_NAME,
            ],
        )?;
        validate_initialization_anchor_links(&root_directory, "genesis-admission", true)?;
        validate_initialization_anchor_links(&root_directory, "genesis", true)?;
        validate_initialization_anchor_links(&root_directory, "heads", false)?;
        verify_directory_entry(parent, &self.root_name, root_identity)?;
        Ok(())
    }

    fn verify_lock(&self) -> Result<(), JournalStoreError> {
        verify_regular_entry(
            self.authority_parent.get()?,
            &self.stable_lock_name,
            self.stable_lock_identity,
        )?;
        require_single_link(&self.stable_lock)?;
        if verify_local_stable_lock(&self.stable_lock, &self.stable_lock_nonce, self.intent)?
            != self.exposure_committed
        {
            return Err(JournalStoreError::Corrupt);
        }
        Ok(())
    }
}

#[cfg(all(target_os = "linux", feature = "storage"))]
impl FileSystemAuthorityLedger {
    /// Consume this pinned sidecar and mint its sole owner-opening
    /// capability. The database and its filesystem-derived open policy never
    /// cross this opaque boundary independently.
    pub(crate) fn into_owner_open(self) -> FileSystemAuthorityLedgerOwnerOpen {
        FileSystemAuthorityLedgerOwnerOpen { ledger: self }
    }

    #[cfg(test)]
    const fn mode(&self) -> FileSystemAuthorityLedgerOpenMode {
        self.mode
    }

    #[cfg(test)]
    fn database(&self) -> Arc<Database> {
        Arc::clone(&self.database)
    }

    fn bind_owner(
        mut self,
        owner: Arc<SystemAuthorityLedgerRouteOwner>,
    ) -> Result<BoundFileSystemAuthorityLedgerOwner, JournalStoreError> {
        if !owner.owns_database(&self.database) {
            return Err(JournalStoreError::Corrupt);
        }
        self.finish_owner_open()?;
        if JournalStoreInstanceId::from_bytes(*owner.journal_store().as_bytes()).is_none()
            || owner.local_node() == NodeId::ZERO
        {
            return Err(JournalStoreError::Corrupt);
        }
        Ok(BoundFileSystemAuthorityLedgerOwner {
            ledger: self,
            owner,
        })
    }

    fn verify_open_aliases(&self) -> Result<(), JournalStoreError> {
        validate_owned_regular_file(&self.file)?;
        let parent = self.authority_parent.get()?;
        match self.mode {
            FileSystemAuthorityLedgerOpenMode::ExistingCanonical => {
                verify_regular_entry(parent, &self.canonical_name, self.identity)?;
                if self.stage_alias {
                    verify_regular_entry(parent, &self.stage_name, self.identity)?;
                }
            }
            FileSystemAuthorityLedgerOpenMode::FreshStage
            | FileSystemAuthorityLedgerOpenMode::ExistingStage => {
                verify_regular_entry(parent, &self.stage_name, self.identity)?;
                if stat_at(parent, &self.canonical_name)
                    .map_err(|_| JournalStoreError::Unavailable)?
                    .is_some()
                {
                    return Err(JournalStoreError::Corrupt);
                }
            }
        }
        Ok(())
    }

    /// Publish a validated staged database or clean an exact hard-link alias
    /// left by a crash between canonical link and stage removal.
    pub(crate) fn finish_owner_open(&mut self) -> Result<(), JournalStoreError> {
        self.verify_open_aliases()?;
        let parent = self.authority_parent.get()?;
        self.file
            .sync_all()
            .map_err(|_| JournalStoreError::Unavailable)?;
        match self.mode {
            FileSystemAuthorityLedgerOpenMode::FreshStage
            | FileSystemAuthorityLedgerOpenMode::ExistingStage => {
                link_file_at_cstr(parent, &self.stage_name, &self.canonical_name)
                    .map_err(|_| JournalStoreError::Unavailable)?;
                parent
                    .sync_all()
                    .map_err(|_| JournalStoreError::Unavailable)?;
                verify_regular_entry(parent, &self.canonical_name, self.identity)?;
                verify_regular_entry(parent, &self.stage_name, self.identity)?;
                unlink_file_at_cstr(parent, &self.stage_name)?;
                parent
                    .sync_all()
                    .map_err(|_| JournalStoreError::Unavailable)?;
                self.mode = FileSystemAuthorityLedgerOpenMode::ExistingCanonical;
                self.stage_alias = false;
            }
            FileSystemAuthorityLedgerOpenMode::ExistingCanonical if self.stage_alias => {
                unlink_file_at_cstr(parent, &self.stage_name)?;
                parent
                    .sync_all()
                    .map_err(|_| JournalStoreError::Unavailable)?;
                self.stage_alias = false;
            }
            FileSystemAuthorityLedgerOpenMode::ExistingCanonical => {
                // Re-establish directory durability even when the stage name
                // is already absent. A prior retry may have successfully
                // unlinked that alias and then lost the result of its parent
                // sync; canonical-only existence does not prove the unlink
                // survived a crash.
                parent
                    .sync_all()
                    .map_err(|_| JournalStoreError::Unavailable)?;
            }
        }
        self.verify()
    }

    pub(crate) fn verify(&self) -> Result<(), JournalStoreError> {
        if self.mode != FileSystemAuthorityLedgerOpenMode::ExistingCanonical || self.stage_alias {
            return Err(JournalStoreError::Corrupt);
        }
        validate_owned_regular_file(&self.file)?;
        verify_regular_entry(
            self.authority_parent.get()?,
            &self.canonical_name,
            self.identity,
        )?;
        let metadata = self
            .file
            .metadata()
            .map_err(|_| JournalStoreError::Unavailable)?;
        if metadata.nlink() != 1 {
            return Err(JournalStoreError::Corrupt);
        }
        if stat_at(self.authority_parent.get()?, &self.stage_name)
            .map_err(|_| JournalStoreError::Unavailable)?
            .is_some()
        {
            return Err(JournalStoreError::Corrupt);
        }
        Ok(())
    }
}

#[cfg(all(target_os = "linux", feature = "storage"))]
impl FileSystemAuthorityLedgerOwnerOpen {
    /// Consume the exact ledger/policy pair under the route owner's public
    /// opaque-token constructor. Only this module can mint the permit needed
    /// to reach its database-level implementation.
    pub(crate) fn open_owner(
        self,
        route: super::system_authority_ledger::SystemAuthorityLedgerRoute,
    ) -> Result<OpenedFileSystemAuthorityLedgerOwner, SystemAuthorityLedgerError> {
        if route.system_agent() != self.ledger.agent {
            return Err(SystemAuthorityLedgerError::ConfigurationMismatch);
        }
        let allow_staged_initialization = matches!(
            self.ledger.mode,
            FileSystemAuthorityLedgerOpenMode::FreshStage
                | FileSystemAuthorityLedgerOpenMode::ExistingStage
        );
        let owner = SystemAuthorityLedgerRouteOwner::open_file_database(
            FileSystemAuthorityLedgerOwnerOpenPermit(()),
            Arc::clone(&self.ledger.database),
            route,
            self.ledger.journal_store,
            self.ledger.local_node,
            allow_staged_initialization,
        )?;
        Ok(OpenedFileSystemAuthorityLedgerOwner {
            ledger: self.ledger,
            owner,
        })
    }
}

#[cfg(all(target_os = "linux", feature = "storage"))]
enum BoundJournalInitializationError<E> {
    Ledger(SystemAuthorityLedgerError),
    Operation(E),
}

#[cfg(all(target_os = "linux", feature = "storage"))]
impl BoundFileSystemAuthorityLedgerOwner {
    pub(crate) fn route(&self) -> super::system_authority_ledger::SystemAuthorityLedgerRoute {
        self.owner.route()
    }

    pub(crate) fn journal_store(&self) -> JournalStoreInstanceId {
        self.owner.journal_store()
    }

    pub(crate) fn local_node(&self) -> NodeId {
        self.owner.local_node()
    }

    pub(crate) fn verify(&self) -> Result<(), JournalStoreError> {
        if !self.owner.owns_database(&self.ledger.database) {
            return Err(JournalStoreError::Corrupt);
        }
        self.ledger.verify()
    }

    fn verify_for_ledger(&self) -> Result<(), SystemAuthorityLedgerError> {
        self.verify()
            .map_err(|_| SystemAuthorityLedgerError::CorruptLedger)
    }

    pub(crate) fn journal_exposure_is_committed(&self) -> Result<bool, SystemAuthorityLedgerError> {
        self.verify_for_ledger()?;
        let result = self.owner.journal_exposure_is_committed();
        self.verify_for_ledger()?;
        result
    }

    /// Hold the ledger's single initialization writer across the complete
    /// journal driver operation. The permanent exposure marker is committed
    /// only after an `Ok` result and successful pinned-inode checks on both
    /// sides of the operation.
    pub(crate) fn with_unexposed_journal_initialization<T, E>(
        &self,
        system_genesis: AgentJournalGenesisId,
        operation: impl FnOnce() -> Result<T, E>,
    ) -> Result<Result<T, E>, SystemAuthorityLedgerError> {
        self.verify_for_ledger()?;
        let guarded = self
            .owner
            .with_unexposed_journal_initialization(system_genesis, || {
                self.verify_for_ledger()
                    .map_err(BoundJournalInitializationError::Ledger)?;
                let result = operation();
                self.verify_for_ledger()
                    .map_err(BoundJournalInitializationError::Ledger)?;
                result.map_err(BoundJournalInitializationError::Operation)
            });
        self.verify_for_ledger()?;
        match guarded? {
            Ok(value) => Ok(Ok(value)),
            Err(BoundJournalInitializationError::Ledger(error)) => Err(error),
            Err(BoundJournalInitializationError::Operation(error)) => Ok(Err(error)),
        }
    }

    /// The one ordinary root-mutation gate. The pinned sidecar is verified on
    /// both sides of the owner's held redb writer, and the raw owner is never
    /// exposed to Host callers.
    pub(crate) fn with_root_mutation<T>(
        &self,
        operation: impl FnOnce() -> T,
    ) -> Result<T, SystemAuthorityLedgerError> {
        self.verify_for_ledger()?;
        self.owner.with_no_pending_root_mutation(|| {
            self.verify_for_ledger()?;
            let result = operation();
            self.verify_for_ledger()?;
            Ok(result)
        })?
    }

    /// Permit only deterministic store-open recovery while Pending remains
    /// possible. Cold publication/retirement runs later under its own owner
    /// writer, so this method must never be nested inside the ordinary gate.
    pub(crate) fn with_startup_root_recovery<T>(
        &self,
        operation: impl FnOnce(&BoundFileSystemAuthorityStartup<'_, '_>) -> T,
    ) -> Result<T, SystemAuthorityLedgerError> {
        self.verify_for_ledger()?;
        self.owner
            .with_startup_root_recovery(|journal_exposure_committed| {
                self.verify_for_ledger()?;
                let active = ();
                let startup = BoundFileSystemAuthorityStartup {
                    authority: self,
                    journal_exposure_committed,
                    _active: &active,
                };
                let result = operation(&startup);
                self.verify_for_ledger()?;
                Ok(result)
            })?
    }

    /// Execute signer-independent cold reconciliation against the bound
    /// owner. This does not hold an outer writer: the replay bridge acquires
    /// its specialized pending-recovery writer through this borrowed owner.
    pub(crate) fn with_recovery_owner<T>(
        &self,
        operation: impl FnOnce(&SystemAuthorityLedgerRouteOwner) -> T,
    ) -> Result<T, SystemAuthorityLedgerError> {
        self.verify_for_ledger()?;
        if !self.owner.journal_exposure_is_committed()? {
            return Err(SystemAuthorityLedgerError::JournalExposureRequired);
        }
        let result = operation(&self.owner);
        self.verify_for_ledger()?;
        if !self.owner.journal_exposure_is_committed()? {
            return Err(SystemAuthorityLedgerError::JournalExposureRequired);
        }
        Ok(result)
    }
}

/// Read-only catalog capability detached from the mutable filesystem store.
///
/// On Linux this owns duplicates of the already-open namespace descriptors
/// and of the stable-lock descriptor. Duplicating the latter keeps the same
/// open-file-description lock alive if the writer handle is dropped.
#[cfg(target_os = "linux")]
struct FileCatalogCapability {
    directories: DirectoryCapabilities,
    authority_parent: AbsoluteDirectoryCapability,
    stable_lock_name: CString,
    stable_lock_identity: FileIdentity,
    stable_lock_nonce: [u8; STABLE_LOCK_NONCE_BYTES],
    local_exposure: Option<Hash>,
    stable_lock: File,
}

#[cfg(target_os = "linux")]
impl FileCatalogCapability {
    fn verify(&self) -> Result<(), JournalStoreError> {
        validate_owned_regular_file(&self.stable_lock)?;
        verify_regular_entry(
            self.authority_parent.get()?,
            &self.stable_lock_name,
            self.stable_lock_identity,
        )?;
        require_single_link(&self.stable_lock)?;
        verify_generation_stable_lock(
            &self.stable_lock,
            &self.stable_lock_nonce,
            self.local_exposure,
        )?;
        self.directories.get("catalog/blobs")?;
        Ok(())
    }

    fn load_catalog(&self, reference: &BlobRef) -> Result<Option<Vec<u8>>, JournalStoreError> {
        validate_blob_reference(JournalBlobClass::CatalogArtifact, reference)?;
        self.verify()?;
        let directory = self.directories.get("catalog/blobs")?;
        let name = encode_hex(reference.hash.as_bytes());
        let staged = sibling_next_name(&name);
        if let Some(bytes) = read_pinned_bounded_regular_at(
            directory,
            &staged,
            blob_maximum(JournalBlobClass::CatalogArtifact),
        )? {
            validate_stored_blob(JournalBlobClass::CatalogArtifact, reference, &bytes)?;
        }
        let bytes = read_pinned_bounded_regular_at(
            directory,
            &name,
            blob_maximum(JournalBlobClass::CatalogArtifact),
        )?;

        // Revalidate every pinned namespace slot and the stable lock after
        // the bounded O_NOFOLLOW read. If a slot raced with the read, bytes
        // came from the pinned descriptor but are still rejected because the
        // capability no longer denotes the authenticated live namespace.
        self.verify()?;
        let Some(bytes) = bytes else {
            return Ok(None);
        };
        validate_stored_blob(JournalBlobClass::CatalogArtifact, reference, &bytes)?;
        Ok(Some(bytes))
    }
}

#[cfg(target_os = "linux")]
#[derive(Clone)]
pub(crate) struct FileCatalogBlobResolver {
    capability: Arc<FileCatalogCapability>,
}

#[cfg(target_os = "linux")]
impl core::fmt::Debug for FileCatalogBlobResolver {
    fn fmt(&self, formatter: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        formatter
            .debug_struct("FileCatalogBlobResolver")
            .finish_non_exhaustive()
    }
}

#[cfg(not(target_os = "linux"))]
#[derive(Clone, Debug)]
pub(crate) struct FileCatalogBlobResolver;

impl CatalogBlobResolver for FileCatalogBlobResolver {
    fn load_catalog(&self, reference: &BlobRef) -> Result<Option<Vec<u8>>, JournalStoreError> {
        #[cfg(not(target_os = "linux"))]
        {
            let _ = reference;
            Err(JournalStoreError::Unavailable)
        }
        #[cfg(target_os = "linux")]
        {
            self.capability.load_catalog(reference)
        }
    }
}

impl CatalogBlobResolverFactory for FileAgentJournalStore {
    type Resolver = FileCatalogBlobResolver;

    fn catalog_blob_resolver(&self) -> Result<Self::Resolver, JournalStoreError> {
        #[cfg(not(target_os = "linux"))]
        {
            Err(JournalStoreError::Unavailable)
        }
        #[cfg(target_os = "linux")]
        {
            // Validate before and after duplicating descriptors so a
            // concurrent namespace replacement cannot mint a resolver for a
            // stale capability while appearing current.
            self.verify_lock()?;
            self.directories.get("catalog/blobs")?;
            let capability = FileCatalogCapability {
                directories: self.directories.try_clone()?,
                authority_parent: self.authority_parent.try_clone()?,
                stable_lock_name: self.stable_lock_name.clone(),
                stable_lock_identity: self.stable_lock_identity,
                stable_lock_nonce: self.stable_lock_nonce,
                local_exposure: self.local_exposure,
                stable_lock: self
                    ._stable_lock
                    .try_clone()
                    .map_err(|_| JournalStoreError::Unavailable)?,
            };
            capability.verify()?;
            Ok(FileCatalogBlobResolver {
                capability: Arc::new(capability),
            })
        }
    }
}

impl core::fmt::Debug for FileAgentJournalStore {
    fn fmt(&self, formatter: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        formatter
            .debug_struct("FileAgentJournalStore")
            .field("root", &self.root)
            .field("agent", &self.agent)
            .field("node", &self.node)
            .finish_non_exhaustive()
    }
}

impl FileAgentJournalStore {
    /// Install an ordinary Local genesis which was authenticated and exactly
    /// executed by replay.  This path intentionally persists no root anchor,
    /// bootstrap evidence, or system-authority ownership capability.
    pub(crate) fn initialize_local(
        &mut self,
        sealed: &ReplaySealedLocalGenesis,
    ) -> Result<bool, JournalStoreError> {
        self.ensure_no_gc_pending()?;
        let shape = validate_sealed_local_genesis_shape(sealed, self.agent, self.node)?;
        if self.replayed_root.is_some() {
            return Err(JournalStoreError::ScopeMismatch);
        }
        let genesis = sealed.genesis();
        let encoded = encode_object(genesis)?;
        for reference in &sealed.artifacts().artifacts {
            require_blob(self, JournalBlobClass::CatalogArtifact, reference)?;
        }
        for existing in [
            self.read_admission("genesis-admission")?,
            self.read_admission("genesis-admission.next")?,
        ]
        .into_iter()
        .flatten()
        {
            if existing != sealed.admission_commitment() {
                return Err(JournalStoreError::Conflict);
            }
        }
        for existing in [
            self.read_fixed::<AgentJournalGenesis>("", "genesis")?,
            self.read_fixed::<AgentJournalGenesis>("", "genesis.next")?,
        ]
        .into_iter()
        .flatten()
        {
            if existing != *genesis {
                return Err(JournalStoreError::Conflict);
            }
        }
        for existing in [
            self.read_fixed::<JournalHeads>("", "heads")?,
            self.read_fixed::<JournalHeads>("", "heads.next")?,
        ]
        .into_iter()
        .flatten()
        {
            if existing != shape.initial {
                return Err(JournalStoreError::Conflict);
            }
        }
        self.persist_admission(sealed.admission_commitment())?;
        self.persist_object(sealed.empty_frontier())?;
        self.persist_object(sealed.ordered_invocations())?;
        self.persist_object(sealed.merge_invocations())?;
        self.persist_object(&shape.local_invocations)?;
        self.persist_object(sealed.artifacts())?;
        for lane in &shape.lanes {
            self.persist_blob(
                JournalBlobClass::LaneState,
                &lane.state,
                genesis_state_component(sealed.post_create(), lane.lane),
            )?;
            self.persist_object(lane)?;
        }
        let genesis_created = persist_immutable_at(
            self.directory("")?,
            "genesis",
            &encoded.bytes,
            class_maximum(JournalStorageClass::Genesis),
            |bytes| {
                let decoded =
                    AgentJournalGenesis::decode(bytes).map_err(|_| JournalStoreError::Corrupt)?;
                decode_object::<AgentJournalGenesis>(bytes, decoded.id()).map(|_| ())
            },
        )?;
        let heads_created = self.install_initial_heads(&shape.initial)?;
        validate_head_targets(self, &shape.initial)?;
        Ok(genesis_created || heads_created)
    }

    /// Irreversibly bind an ordinary Local generation's successful replay to
    /// its exact host-owned creation intent. The stable-lock suffix is made
    /// durable before Host publishes the separately discoverable exposure
    /// marker, so deleting or rolling that marker back cannot make an
    /// already-exposed generation eligible for initialization repair.
    #[cfg(target_os = "linux")]
    pub(crate) fn commit_local_exposure(
        &mut self,
        sealed: &ReplaySealedLocalGenesis,
        intent: Hash,
    ) -> Result<(), JournalStoreError> {
        if intent == Hash::ZERO
            || self.local_exposure != Some(intent)
            || self.replayed_root.is_some()
        {
            return Err(JournalStoreError::ScopeMismatch);
        }
        validate_sealed_local_genesis_shape(sealed, self.agent, self.node)?;

        // Cleanup for a read-only reopen is permitted only after the driver
        // has authenticated and replayed its current head closure.
        self.finish_deferred_startup_recovery()?;
        if self.read_admission("genesis-admission")? != Some(sealed.admission_commitment())
            || self.read_admission("genesis-admission.next")?.is_some()
            || self.read_fixed::<AgentJournalGenesis>("", "genesis")?
                != Some(sealed.genesis().clone())
            || self
                .read_fixed::<AgentJournalGenesis>("", "genesis.next")?
                .is_some()
            || self.read_fixed::<JournalHeads>("", "heads.next")?.is_some()
        {
            return Err(JournalStoreError::Corrupt);
        }
        let heads = self.heads()?.ok_or(JournalStoreError::Corrupt)?;
        if heads.genesis != sealed.genesis().id() || heads.node != self.node {
            return Err(JournalStoreError::ScopeMismatch);
        }
        validate_head_targets(self, &heads)?;
        self.sync_unexposed_generation()?;
        commit_local_stable_lock_exposure(
            &self._stable_lock,
            self.authority_parent.get()?,
            &self.stable_lock_nonce,
            intent,
        )?;
        self.verify_lock()
    }

    #[cfg(test)]
    fn open(
        root: impl Into<PathBuf>,
        stable_lock_path: impl Into<PathBuf>,
        node: NodeId,
    ) -> Result<Self, JournalStoreError> {
        #[cfg(not(target_os = "linux"))]
        {
            let _ = (root.into(), stable_lock_path.into(), node);
            return Err(JournalStoreError::Unavailable);
        }
        #[cfg(target_os = "linux")]
        {
            Self::open_linux(root.into(), stable_lock_path.into(), node, None, false)
        }
    }

    /// Reopen an initialized journal only after the independently pinned root
    /// adapter has reproduced the exact sealed genesis capability.
    #[cfg(test)]
    fn open_reverified(
        root: impl Into<PathBuf>,
        stable_lock_path: impl Into<PathBuf>,
        node: NodeId,
        sealed: &ReplaySealedGenesis,
    ) -> Result<Self, JournalStoreError> {
        #[cfg(not(target_os = "linux"))]
        {
            let _ = (root.into(), stable_lock_path.into(), node, sealed);
            return Err(JournalStoreError::Unavailable);
        }
        #[cfg(target_os = "linux")]
        {
            Self::open_linux(
                root.into(),
                stable_lock_path.into(),
                node,
                Some(sealed),
                false,
            )
        }
    }

    #[cfg(all(test, target_os = "linux"))]
    fn open_unverified_for_test(
        root: impl Into<PathBuf>,
        stable_lock_path: impl Into<PathBuf>,
        node: NodeId,
    ) -> Result<Self, JournalStoreError> {
        Self::open_linux(root.into(), stable_lock_path.into(), node, None, true)
    }

    #[cfg(all(test, target_os = "linux"))]
    fn open_linux(
        root: PathBuf,
        stable_lock_path: PathBuf,
        node: NodeId,
        sealed: Option<&ReplaySealedGenesis>,
        allow_unverified_for_test: bool,
    ) -> Result<Self, JournalStoreError> {
        if node == NodeId::ZERO {
            return Err(JournalStoreError::ScopeMismatch);
        }
        let requested_root = clean_absolute_path(root)?;
        let agent = agent_from_root_path(&requested_root)?;
        let root_parent = requested_root
            .parent()
            .ok_or(JournalStoreError::InvalidPath)?
            .to_path_buf();
        let root_name = requested_root
            .file_name()
            .and_then(|name| name.to_str())
            .ok_or(JournalStoreError::InvalidPath)?;
        let canonical_root = root_parent.join(root_name);

        let stable_lock_path = clean_absolute_path(stable_lock_path)?;
        if stable_lock_path.starts_with(&canonical_root) {
            return Err(JournalStoreError::InvalidPath);
        }
        let expected_lock_leaf = canonical_root
            .with_extension("agent-lock")
            .file_name()
            .and_then(|name| name.to_str())
            .ok_or(JournalStoreError::InvalidPath)?
            .to_owned();
        let stable_lock_name = stable_lock_path
            .file_name()
            .and_then(|name| name.to_str())
            .ok_or(JournalStoreError::InvalidPath)?;
        if stable_lock_name != expected_lock_leaf {
            return Err(JournalStoreError::InvalidPath);
        }
        let authority_parent_path = stable_lock_path
            .parent()
            .ok_or(JournalStoreError::InvalidPath)?
            .to_path_buf();
        let journal_parent = AbsoluteDirectoryCapability::open(&root_parent)?;
        let authority_parent = AbsoluteDirectoryCapability::open(&authority_parent_path)?;
        let (stable_lock, stable_lock_nonce) =
            open_stable_lock_at(authority_parent.get()?, stable_lock_name)?;
        let stable_lock_identity = FileIdentity::of(&stable_lock)?;
        let stable_lock_name = c_name(stable_lock_name)?;
        verify_regular_entry(
            authority_parent.get()?,
            &stable_lock_name,
            stable_lock_identity,
        )?;

        // Nothing below the replaceable root is touched before ownership of
        // its stable external slot has been won.
        reject_legacy_generation_at(journal_parent.get()?, agent)?;
        ensure_directory_at(journal_parent.get()?, root_name)?;
        let root_directory = open_directory_at(journal_parent.get()?, root_name)?;
        validate_owned_directory(&root_directory)?;
        verify_regular_entry(
            authority_parent.get()?,
            &stable_lock_name,
            stable_lock_identity,
        )?;
        discard_private_stages_at(&root_directory, is_fixed_private_stage_name)?;
        validate_directory_names(
            &root_directory,
            &[
                "records",
                "checkpoints",
                "lane-state",
                "artifact-closures",
                "invocation-index",
                "invocation-outcomes",
                SHARED_ORDERED_COMMIT_DIRECTORY,
                HISTORY_DIRECTORY,
                "catalog",
                "authority",
                "genesis-admission",
                "genesis-admission.next",
                "genesis",
                "genesis.next",
                "heads",
                "heads.next",
                GC_INTENT_NAME,
                GC_INTENT_STAGE_NAME,
            ],
        )?;
        let directories =
            DirectoryCapabilities::new(journal_parent, c_name(root_name)?, root_directory)?;

        let mut store = Self {
            instance_id: file_journal_store_instance_id(
                &canonical_root,
                agent,
                node,
                &stable_lock_nonce,
            )?,
            root: canonical_root,
            agent,
            node,
            directories,
            history_candidate: None,
            replayed_root: None,
            startup_recovery_pending: false,
            authority_parent,
            stable_lock_name,
            stable_lock_identity,
            stable_lock_nonce,
            local_exposure: None,
            _stable_lock: stable_lock,
        };
        store.validate_recovery_state()?;
        store.ensure_layout()?;
        store.recover_history_state()?;
        store.validate_authority_recovery(sealed, allow_unverified_for_test)?;
        store.replayed_root = sealed
            .map(ReplaySealedGenesis::replayed_root_identity)
            .transpose()
            .map_err(|_| JournalStoreError::ScopeMismatch)?;
        if let Some(heads) = store.heads()? {
            validate_head_targets(&store, &heads)?;
        }
        if let Some(staged) = store.read_fixed::<JournalHeads>("", "heads.next")? {
            validate_head_targets(&store, &staged)?;
        }
        Ok(store)
    }

    pub fn root(&self) -> &Path {
        &self.root
    }

    #[cfg(target_os = "linux")]
    fn verify_lock(&self) -> Result<(), JournalStoreError> {
        verify_regular_entry(
            self.authority_parent.get()?,
            &self.stable_lock_name,
            self.stable_lock_identity,
        )?;
        require_single_link(&self._stable_lock)?;
        verify_generation_stable_lock(
            &self._stable_lock,
            &self.stable_lock_nonce,
            self.local_exposure,
        )
        .map(|_| ())
    }

    fn read_gc_intent_file(&self, name: &str) -> Result<Option<GcIntent>, JournalStoreError> {
        let Some(bytes) = read_bounded_regular_at(self.directory("")?, name, MAX_GC_INTENT_BYTES)?
        else {
            return Ok(None);
        };
        decode_gc_intent(&bytes).map(Some)
    }

    fn gc_intent(&self) -> Result<Option<GcIntent>, JournalStoreError> {
        let committed = self.read_gc_intent_file(GC_INTENT_NAME)?;
        let staged = self.read_gc_intent_file(GC_INTENT_STAGE_NAME)?;
        match (committed, staged) {
            (Some(committed), Some(staged)) if committed != staged => {
                Err(JournalStoreError::Corrupt)
            }
            (Some(intent), _) | (None, Some(intent)) => Ok(Some(intent)),
            (None, None) => Ok(None),
        }
    }

    fn ensure_no_gc_pending(&self) -> Result<(), JournalStoreError> {
        if self.gc_intent()?.is_some() {
            Err(JournalStoreError::GcPending)
        } else {
            Ok(())
        }
    }

    #[cfg(target_os = "linux")]
    fn directory(&self, key: &'static str) -> Result<&File, JournalStoreError> {
        self.verify_lock()?;
        self.directories.get(key)
    }

    #[cfg(not(target_os = "linux"))]
    fn directory(&self, _key: &'static str) -> Result<&File, JournalStoreError> {
        Err(JournalStoreError::Unavailable)
    }

    fn ensure_layout(&mut self) -> Result<(), JournalStoreError> {
        self.open_layout(true)
    }

    /// Pin and validate the complete initialized layout without creating,
    /// unlinking, syncing, or otherwise repairing any entry.
    fn open_existing_layout(&mut self) -> Result<(), JournalStoreError> {
        self.open_layout(false)
    }

    fn finish_deferred_startup_recovery(&mut self) -> Result<(), JournalStoreError> {
        if !self.startup_recovery_pending {
            return Ok(());
        }
        self.verify_lock()?;
        discard_private_stages_at(self.directories.get("")?, is_fixed_private_stage_name)?;
        discard_private_stages_at(
            self.directories.get(HISTORY_DIRECTORY)?,
            is_history_fixed_private_stage_name,
        )?;
        discard_private_stages_at(
            self.directories.get(HISTORY_CANDIDATE_DIRECTORY)?,
            is_history_candidate_private_stage_name,
        )?;
        for key in [
            "records/replay-inputs",
            "records/ordered",
            "records/local",
            "records/merge-events",
            "records/merge-frontiers",
            "records/merge-seals",
            "checkpoints",
            "lane-state/manifests",
            "lane-state/blobs",
            "artifact-closures",
            "invocation-index/manifests",
            "invocation-index/nodes",
            "invocation-outcomes",
            SHARED_ORDERED_COMMIT_DIRECTORY,
            "catalog/blobs",
            "authority/root-anchors",
            "authority/genesis-evidence",
            "authority/genesis-admissions",
        ] {
            discard_private_stages_at(self.directories.get(key)?, is_content_private_stage_name)?;
        }
        self.recover_history_state()?;
        self.validate_recovery_state()?;
        self.startup_recovery_pending = false;
        self.verify_lock()
    }

    fn open_layout(&mut self, allow_repair: bool) -> Result<(), JournalStoreError> {
        #[cfg(not(target_os = "linux"))]
        return Err(JournalStoreError::Unavailable);
        #[cfg(target_os = "linux")]
        {
            self.verify_lock()?;
            for (key, parent, name) in [
                ("records", "", "records"),
                ("checkpoints", "", "checkpoints"),
                ("lane-state", "", "lane-state"),
                ("artifact-closures", "", "artifact-closures"),
                ("invocation-index", "", "invocation-index"),
                ("invocation-outcomes", "", "invocation-outcomes"),
                (
                    SHARED_ORDERED_COMMIT_DIRECTORY,
                    "",
                    SHARED_ORDERED_COMMIT_DIRECTORY,
                ),
                (HISTORY_DIRECTORY, "", HISTORY_DIRECTORY),
                ("catalog", "", "catalog"),
                ("authority", "", "authority"),
            ] {
                if allow_repair {
                    self.directories.add(key, parent, name)?;
                } else {
                    self.directories.add_existing(key, parent, name)?;
                }
            }
            if allow_repair {
                discard_private_stages_at(
                    self.directories.get(HISTORY_DIRECTORY)?,
                    is_history_fixed_private_stage_name,
                )?;
            }
            validate_directory_names(
                self.directories.get("records")?,
                &[
                    "replay-inputs",
                    "ordered",
                    "local",
                    "merge-events",
                    "merge-frontiers",
                    "merge-seals",
                ],
            )?;
            validate_directory_names(self.directories.get("lane-state")?, &["manifests", "blobs"])?;
            validate_directory_names(
                self.directories.get("invocation-index")?,
                &["manifests", "nodes"],
            )?;
            validate_directory_names(
                self.directories.get(HISTORY_DIRECTORY)?,
                &[
                    "nodes",
                    "candidate",
                    HISTORY_CANDIDATE_INTENT_NAME,
                    HISTORY_CANDIDATE_INTENT_STAGE_NAME,
                    HISTORY_RETIREMENTS_NAME,
                    HISTORY_RETIREMENTS_STAGE_NAME,
                ],
            )?;
            validate_directory_names(self.directories.get("catalog")?, &["blobs"])?;
            validate_directory_names(
                self.directories.get("authority")?,
                &[
                    "root-anchors",
                    "genesis-evidence",
                    "genesis-admissions",
                    "system-decisions",
                    "system-rotations",
                    "system-catalog-nodes",
                    "system-catalog-records",
                    "system-committees",
                ],
            )?;
            for (key, parent, name) in [
                ("records/replay-inputs", "records", "replay-inputs"),
                ("records/ordered", "records", "ordered"),
                ("records/local", "records", "local"),
                ("records/merge-events", "records", "merge-events"),
                ("records/merge-frontiers", "records", "merge-frontiers"),
                ("records/merge-seals", "records", "merge-seals"),
                ("lane-state/manifests", "lane-state", "manifests"),
                ("lane-state/blobs", "lane-state", "blobs"),
                (
                    "invocation-index/manifests",
                    "invocation-index",
                    "manifests",
                ),
                ("invocation-index/nodes", "invocation-index", "nodes"),
                (HISTORY_NODES_DIRECTORY, HISTORY_DIRECTORY, "nodes"),
                (HISTORY_CANDIDATE_DIRECTORY, HISTORY_DIRECTORY, "candidate"),
                ("catalog/blobs", "catalog", "blobs"),
                ("authority/root-anchors", "authority", "root-anchors"),
                (
                    "authority/genesis-evidence",
                    "authority",
                    "genesis-evidence",
                ),
                (
                    "authority/genesis-admissions",
                    "authority",
                    "genesis-admissions",
                ),
                (
                    AUTHORITY_SYSTEM_DECISIONS_DIRECTORY,
                    "authority",
                    "system-decisions",
                ),
                (
                    AUTHORITY_SYSTEM_ROTATIONS_DIRECTORY,
                    "authority",
                    "system-rotations",
                ),
                (
                    AUTHORITY_SYSTEM_CATALOG_NODES_DIRECTORY,
                    "authority",
                    "system-catalog-nodes",
                ),
                (
                    AUTHORITY_SYSTEM_CATALOG_RECORDS_DIRECTORY,
                    "authority",
                    "system-catalog-records",
                ),
                (
                    AUTHORITY_SYSTEM_COMMITTEES_DIRECTORY,
                    "authority",
                    "system-committees",
                ),
            ] {
                if allow_repair {
                    self.directories.add(key, parent, name)?;
                } else {
                    self.directories.add_existing(key, parent, name)?;
                }
            }
            if allow_repair {
                discard_private_stages_at(
                    self.directories.get(HISTORY_CANDIDATE_DIRECTORY)?,
                    is_history_candidate_private_stage_name,
                )?;
            }
            let history_nodes = self.directories.get(HISTORY_NODES_DIRECTORY)?;
            let shard_names = (0_u16..=255)
                .map(|value| format!("{value:02x}"))
                .collect::<Vec<_>>();
            for shard in &shard_names {
                if allow_repair {
                    ensure_directory_at(history_nodes, shard)?;
                } else {
                    let shard = open_directory_at(history_nodes, shard)?;
                    validate_owned_directory(&shard)?;
                }
            }
            let shard_name_refs = shard_names.iter().map(String::as_str).collect::<Vec<_>>();
            validate_directory_names(history_nodes, &shard_name_refs)?;
            validate_directory_names(
                self.directories.get(HISTORY_CANDIDATE_DIRECTORY)?,
                &[
                    "plan-0",
                    "plan-0.next",
                    "plan-1",
                    "plan-1.next",
                    "plan-2",
                    "plan-2.next",
                ],
            )?;
            for key in [
                "records/replay-inputs",
                "records/ordered",
                "records/local",
                "records/merge-events",
                "records/merge-frontiers",
                "records/merge-seals",
                "checkpoints",
                "lane-state/manifests",
                "lane-state/blobs",
                "artifact-closures",
                "invocation-index/manifests",
                "invocation-index/nodes",
                "invocation-outcomes",
                SHARED_ORDERED_COMMIT_DIRECTORY,
                "catalog/blobs",
                "authority/root-anchors",
                "authority/genesis-evidence",
                "authority/genesis-admissions",
            ] {
                if allow_repair {
                    discard_private_stages_at(
                        self.directories.get(key)?,
                        is_content_private_stage_name,
                    )?;
                }
            }
            self.audit_shared_ordered_commit_directory()?;
            if allow_repair {
                for key in [
                    "records",
                    "lane-state",
                    "invocation-index",
                    SHARED_ORDERED_COMMIT_DIRECTORY,
                    "catalog",
                    "authority",
                    AUTHORITY_SYSTEM_DECISIONS_DIRECTORY,
                    AUTHORITY_SYSTEM_ROTATIONS_DIRECTORY,
                    AUTHORITY_SYSTEM_CATALOG_NODES_DIRECTORY,
                    AUTHORITY_SYSTEM_CATALOG_RECORDS_DIRECTORY,
                    AUTHORITY_SYSTEM_COMMITTEES_DIRECTORY,
                    HISTORY_CANDIDATE_DIRECTORY,
                    HISTORY_NODES_DIRECTORY,
                    HISTORY_DIRECTORY,
                    "",
                ] {
                    self.directories.sync(key)?;
                }
            }
            Ok(())
        }
    }

    fn read_history_queue_file(
        &self,
        name: &str,
    ) -> Result<Option<HistoryRetirementQueue>, JournalStoreError> {
        let Some(bytes) = read_bounded_regular_at(
            self.directory(HISTORY_DIRECTORY)?,
            name,
            MAX_HISTORY_RETIREMENT_QUEUE_BYTES,
        )?
        else {
            return Ok(None);
        };
        decode_history_queue(&bytes).map(Some)
    }

    fn history_queue(
        &self,
        genesis: AgentJournalGenesisId,
    ) -> Result<HistoryRetirementQueue, JournalStoreError> {
        if self
            .read_history_queue_file(HISTORY_RETIREMENTS_STAGE_NAME)?
            .is_some()
        {
            return Err(JournalStoreError::GcPending);
        }
        let queue = self
            .read_history_queue_file(HISTORY_RETIREMENTS_NAME)?
            .unwrap_or_else(|| HistoryRetirementQueue::empty(genesis, self.node));
        if queue.genesis != genesis || queue.node != self.node {
            return Err(JournalStoreError::Corrupt);
        }
        queue.validate()?;
        Ok(queue)
    }

    fn read_history_candidate_intent_file(
        &self,
        name: &str,
    ) -> Result<Option<HistoryCandidateIntent>, JournalStoreError> {
        let Some(bytes) = read_bounded_regular_at(
            self.directory(HISTORY_DIRECTORY)?,
            name,
            MAX_HISTORY_CANDIDATE_INTENT_BYTES,
        )?
        else {
            return Ok(None);
        };
        decode_history_candidate_intent(&bytes).map(Some)
    }

    fn read_history_candidate_plan(
        &self,
        index: usize,
        maximum: usize,
    ) -> Result<Option<InvocationHistoryWritePlan>, JournalStoreError> {
        let name = format!("plan-{index}");
        let Some(bytes) =
            read_bounded_regular_at(self.directory(HISTORY_CANDIDATE_DIRECTORY)?, &name, maximum)?
        else {
            return Ok(None);
        };
        decode_history_plan(&bytes).map(Some)
    }

    fn load_history_candidate_overlay(
        &self,
        intent: HistoryCandidateIntent,
    ) -> Result<HistoryCandidateOverlay, JournalStoreError> {
        intent.validate()?;
        let mut plans = Vec::new();
        let mut nodes = BTreeMap::new();
        let mut aggregate_bytes = 0usize;
        let mut insertions = 0usize;
        let mut retired = Vec::new();
        for (index, descriptor) in intent.plans.iter().enumerate() {
            let plan = self
                .read_history_candidate_plan(index, descriptor.encoded_bytes as usize)?
                .ok_or(JournalStoreError::Corrupt)?;
            let bytes = plan.encode();
            if bytes.len() as u64 != descriptor.encoded_bytes
                || Hash::digest(HISTORY_CANDIDATE_DOMAIN, &[&bytes]) != descriptor.hash
                || plan.scope() != descriptor.scope
                || plan.genesis() == AgentJournalGenesisId::ZERO
            {
                return Err(JournalStoreError::Corrupt);
            }
            aggregate_bytes = aggregate_bytes
                .checked_add(
                    plan.overlay_nodes()
                        .iter()
                        .map(|write| write.bytes().len())
                        .sum::<usize>(),
                )
                .ok_or(JournalStoreError::LimitExceeded)?;
            insertions = insertions
                .checked_add(plan.inserted_facts().len())
                .ok_or(JournalStoreError::LimitExceeded)?;
            for write in plan.overlay_nodes() {
                match nodes.insert(write.id(), write.bytes().to_vec()) {
                    Some(existing) if existing != write.bytes() => {
                        return Err(JournalStoreError::Corrupt);
                    }
                    _ => {}
                }
            }
            retired.extend_from_slice(plan.retired_node_ids());
            plans.push(plan);
        }
        for index in intent.plans.len()..MAX_HISTORY_PUBLICATION_PLANS {
            if self
                .read_history_candidate_plan(index, MAX_INVOCATION_HISTORY_WRITE_PLAN_BYTES)?
                .is_some()
            {
                return Err(JournalStoreError::Corrupt);
            }
        }
        for index in 0..MAX_HISTORY_PUBLICATION_PLANS {
            if read_bounded_regular_at(
                self.directory(HISTORY_CANDIDATE_DIRECTORY)?,
                &format!("plan-{index}.next"),
                MAX_INVOCATION_HISTORY_WRITE_PLAN_BYTES,
            )?
            .is_some()
            {
                return Err(JournalStoreError::Corrupt);
            }
        }
        if insertions > MAX_INVOCATION_HISTORY_INSERTIONS
            || nodes.len() > MAX_INVOCATION_HISTORY_PLAN_NODES
            || aggregate_bytes > MAX_INVOCATION_HISTORY_PLAN_NODE_BYTES
        {
            return Err(JournalStoreError::Corrupt);
        }
        retired.sort_unstable();
        if retired != intent.retirement.retired_node_ids
            || retired.windows(2).any(|pair| pair[0] == pair[1])
        {
            return Err(JournalStoreError::Corrupt);
        }
        for plan in &plans {
            if plan.expected_root() != intent.retirement.expected_roots.get(plan.scope())
                || plan.root() != intent.retirement.next_roots.get(plan.scope())
            {
                return Err(JournalStoreError::Corrupt);
            }
        }
        Ok(HistoryCandidateOverlay {
            intent,
            plans,
            nodes,
        })
    }

    #[cfg(target_os = "linux")]
    fn clear_history_candidate_files(&mut self) -> Result<(), JournalStoreError> {
        // The intent is the sole authority that makes the private plans
        // recoverable. Remove it first: a crash may then leave harmless plan
        // files which the no-intent recovery path discards. Removing plans
        // first could instead strand an authoritative intent with missing
        // provenance and make a safely aborted publication unreopenable.
        let history = self.directory(HISTORY_DIRECTORY)?;
        let mut intent_changed = false;
        intent_changed |= unlink_file_if_present_at(history, HISTORY_CANDIDATE_INTENT_STAGE_NAME)?;
        intent_changed |= unlink_file_if_present_at(history, HISTORY_CANDIDATE_INTENT_NAME)?;
        if intent_changed {
            history
                .sync_all()
                .map_err(|_| JournalStoreError::Unavailable)?;
        }
        let candidate = self.directory(HISTORY_CANDIDATE_DIRECTORY)?;
        let mut changed = false;
        for index in 0..MAX_HISTORY_PUBLICATION_PLANS {
            changed |= unlink_file_if_present_at(candidate, &format!("plan-{index}"))?;
            changed |= unlink_file_if_present_at(candidate, &format!("plan-{index}.next"))?;
        }
        if changed {
            candidate
                .sync_all()
                .map_err(|_| JournalStoreError::Unavailable)?;
        }
        self.history_candidate = None;
        Ok(())
    }

    #[cfg(target_os = "linux")]
    fn stage_history_candidate(
        &mut self,
        overlay: HistoryCandidateOverlay,
        publication_point: &mut impl FnMut(PublicationPoint) -> Result<(), JournalStoreError>,
    ) -> Result<(), JournalStoreError> {
        if let Some(existing) = &self.history_candidate {
            return if existing.intent == overlay.intent && existing.plans == overlay.plans {
                Ok(())
            } else {
                Err(JournalStoreError::Conflict)
            };
        }
        if self
            .read_history_candidate_intent_file(HISTORY_CANDIDATE_INTENT_NAME)?
            .is_some()
            || self
                .read_history_candidate_intent_file(HISTORY_CANDIDATE_INTENT_STAGE_NAME)?
                .is_some()
        {
            return Err(JournalStoreError::Corrupt);
        }
        let candidate = self.directory(HISTORY_CANDIDATE_DIRECTORY)?;
        for (index, plan) in overlay.plans.iter().enumerate() {
            let bytes = plan.encode();
            let name = format!("plan-{index}");
            persist_immutable_at(
                candidate,
                &name,
                &bytes,
                MAX_INVOCATION_HISTORY_WRITE_PLAN_BYTES,
                |stored| decode_history_plan(stored).map(|_| ()),
            )?;
        }
        let history = self.directory(HISTORY_DIRECTORY)?;
        create_synced_stage_at(
            history,
            HISTORY_CANDIDATE_INTENT_STAGE_NAME,
            &overlay.intent.encode(),
        )?;
        rename_file_at(
            history,
            HISTORY_CANDIDATE_INTENT_STAGE_NAME,
            HISTORY_CANDIDATE_INTENT_NAME,
        )?;
        history
            .sync_all()
            .map_err(|_| JournalStoreError::Unavailable)?;
        self.history_candidate = Some(overlay);
        publication_point(PublicationPoint::HistoryCandidateDurable)
    }

    #[cfg(target_os = "linux")]
    fn append_history_retirement(
        &self,
        overlay: &HistoryCandidateOverlay,
    ) -> Result<(), JournalStoreError> {
        let genesis = overlay
            .plans
            .first()
            .ok_or(JournalStoreError::Corrupt)?
            .genesis();
        let committed = self
            .read_history_queue_file(HISTORY_RETIREMENTS_NAME)?
            .unwrap_or_else(|| HistoryRetirementQueue::empty(genesis, self.node));
        if committed.genesis != genesis || committed.node != self.node {
            return Err(JournalStoreError::Corrupt);
        }
        let staged = self.read_history_queue_file(HISTORY_RETIREMENTS_STAGE_NAME)?;
        let already_appended = committed.records.last() == Some(&overlay.intent.retirement);
        if already_appended {
            if staged.is_some() {
                return Err(JournalStoreError::Corrupt);
            }
            return Ok(());
        }
        if committed.commitment() != overlay.intent.queue_commitment {
            return Err(JournalStoreError::Corrupt);
        }
        committed.preflight_append(&overlay.intent.retirement)?;
        let mut next = committed.clone();
        next.records.push(overlay.intent.retirement.clone());
        next.validate()?;
        if let Some(staged) = staged {
            if staged != next {
                return Err(JournalStoreError::Corrupt);
            }
            sync_regular_file_at(
                self.directory(HISTORY_DIRECTORY)?,
                HISTORY_RETIREMENTS_STAGE_NAME,
            )?;
        } else {
            create_synced_stage_at(
                self.directory(HISTORY_DIRECTORY)?,
                HISTORY_RETIREMENTS_STAGE_NAME,
                &next.encode(),
            )?;
        }
        rename_file_at(
            self.directory(HISTORY_DIRECTORY)?,
            HISTORY_RETIREMENTS_STAGE_NAME,
            HISTORY_RETIREMENTS_NAME,
        )?;
        self.directory(HISTORY_DIRECTORY)?
            .sync_all()
            .map_err(|_| JournalStoreError::Unavailable)
    }

    #[cfg(target_os = "linux")]
    fn finish_history_candidate(
        &mut self,
        publication_point: &mut impl FnMut(PublicationPoint) -> Result<(), JournalStoreError>,
    ) -> Result<bool, JournalStoreError> {
        let Some(overlay) = self.history_candidate.clone() else {
            return Ok(false);
        };
        let mut created = false;
        for plan in &overlay.plans {
            for write in plan.overlay_nodes() {
                match self.read_global_history_node(write.id())? {
                    Some(bytes) if bytes == write.bytes() => {
                        self.clear_exact_history_node_stage(write.id(), write.bytes())?;
                    }
                    Some(_) => return Err(JournalStoreError::Corrupt),
                    None if write.needs_write() => {
                        created |= self.persist_history_node(write.id(), write.bytes())?;
                    }
                    None => return Err(JournalStoreError::Corrupt),
                }
            }
        }
        publication_point(PublicationPoint::HistoryPromoted)?;
        self.append_history_retirement(&overlay)?;
        publication_point(PublicationPoint::HistoryRetirementDurable)?;
        self.clear_history_candidate_files()?;
        publication_point(PublicationPoint::HistoryCandidateCleared)?;
        Ok(created)
    }

    #[cfg(target_os = "linux")]
    fn recover_history_state(&mut self) -> Result<(), JournalStoreError> {
        let intent = self.read_history_candidate_intent_file(HISTORY_CANDIDATE_INTENT_NAME)?;
        let staged_intent =
            self.read_history_candidate_intent_file(HISTORY_CANDIDATE_INTENT_STAGE_NAME)?;
        if intent.is_none() {
            if staged_intent.is_some() {
                self.clear_history_candidate_files()?;
            } else {
                // Fully written plan files without a durable intent are a
                // private pre-publication stage and can never authenticate a
                // global object.
                self.clear_history_candidate_files()?;
            }
            if self
                .read_history_queue_file(HISTORY_RETIREMENTS_STAGE_NAME)?
                .is_some()
                && self.gc_intent()?.is_none()
            {
                return Err(JournalStoreError::Corrupt);
            }
            return Ok(());
        }
        if staged_intent.is_some() {
            return Err(JournalStoreError::Corrupt);
        }
        let overlay = self.load_history_candidate_overlay(intent.unwrap())?;
        self.history_candidate = Some(overlay.clone());
        for plan in &overlay.plans {
            plan.validate(self).map_err(map_invocation_history_error)?;
        }
        let current = self
            .read_fixed::<JournalHeads>("", "heads")?
            .ok_or(JournalStoreError::Corrupt)?;
        let staged = self.read_fixed::<JournalHeads>("", "heads.next")?;
        let expected = overlay.intent.retirement.expected_heads;
        let next = overlay.intent.retirement.next_heads;
        match (current.id(), staged.as_ref().map(JournalHeads::id)) {
            (head, None) if head == expected => {
                let genesis = overlay.plans[0].genesis();
                let queue = self.history_queue(genesis)?;
                if queue.commitment() != overlay.intent.queue_commitment {
                    return Err(JournalStoreError::Corrupt);
                }
                self.clear_history_candidate_files()
            }
            (head, Some(stage)) if head == expected && stage == next => Ok(()),
            (head, None) if head == next => {
                self.finish_history_candidate(&mut |_| Ok(())).map(|_| ())
            }
            _ => Err(JournalStoreError::Corrupt),
        }
    }

    fn object_directory(
        &self,
        class: JournalStorageClass,
    ) -> Result<&'static str, JournalStoreError> {
        let key = match class {
            JournalStorageClass::ReplayInput => "records/replay-inputs",
            JournalStorageClass::OrderedEntry => "records/ordered",
            JournalStorageClass::LocalEntry => "records/local",
            JournalStorageClass::MergeEvent => "records/merge-events",
            JournalStorageClass::MergeFrontier => "records/merge-frontiers",
            JournalStorageClass::MergeSeal => "records/merge-seals",
            JournalStorageClass::LaneState => "lane-state/manifests",
            JournalStorageClass::ArtifactClosure => "artifact-closures",
            JournalStorageClass::InvocationIndex => "invocation-index/manifests",
            JournalStorageClass::InvocationIndexNode => "invocation-index/nodes",
            JournalStorageClass::InvocationOutcome => "invocation-outcomes",
            JournalStorageClass::Checkpoint => "checkpoints",
            JournalStorageClass::Genesis
            | JournalStorageClass::Heads
            | JournalStorageClass::InvocationHistoryNode => {
                return Err(JournalStoreError::InvalidClass);
            }
        };
        Ok(key)
    }

    #[cfg(target_os = "linux")]
    fn history_shard_directory(
        &self,
        id: InvocationHistoryNodeId,
    ) -> Result<File, JournalStoreError> {
        if id == InvocationHistoryNodeId::ZERO {
            return Err(JournalStoreError::Corrupt);
        }
        let shard = format!("{:02x}", id.as_bytes()[0]);
        let directory = open_directory_at(self.directory(HISTORY_NODES_DIRECTORY)?, &shard)?;
        validate_owned_directory(&directory)?;
        Ok(directory)
    }

    #[cfg(target_os = "linux")]
    fn read_global_history_node(
        &self,
        id: InvocationHistoryNodeId,
    ) -> Result<Option<Vec<u8>>, JournalStoreError> {
        let directory = self.history_shard_directory(id)?;
        let name = encode_hex(id.as_bytes());
        let stage = sibling_next_name(&name);
        if let Some(bytes) =
            read_bounded_regular_at(&directory, &stage, MAX_INVOCATION_HISTORY_NODE_BYTES)?
        {
            decode_object::<InvocationHistoryNode>(&bytes, id)?;
        }
        let Some(bytes) =
            read_bounded_regular_at(&directory, &name, MAX_INVOCATION_HISTORY_NODE_BYTES)?
        else {
            return Ok(None);
        };
        decode_object::<InvocationHistoryNode>(&bytes, id)?;
        Ok(Some(bytes))
    }

    #[cfg(not(target_os = "linux"))]
    fn read_global_history_node(
        &self,
        _id: InvocationHistoryNodeId,
    ) -> Result<Option<Vec<u8>>, JournalStoreError> {
        Err(JournalStoreError::Unavailable)
    }

    #[cfg(target_os = "linux")]
    fn persist_history_node(
        &self,
        id: InvocationHistoryNodeId,
        bytes: &[u8],
    ) -> Result<bool, JournalStoreError> {
        decode_object::<InvocationHistoryNode>(bytes, id)?;
        let directory = self.history_shard_directory(id)?;
        persist_immutable_at(
            &directory,
            &encode_hex(id.as_bytes()),
            bytes,
            MAX_INVOCATION_HISTORY_NODE_BYTES,
            |stored| decode_object::<InvocationHistoryNode>(stored, id).map(|_| ()),
        )
    }

    #[cfg(target_os = "linux")]
    fn clear_exact_history_node_stage(
        &self,
        id: InvocationHistoryNodeId,
        expected: &[u8],
    ) -> Result<(), JournalStoreError> {
        let directory = self.history_shard_directory(id)?;
        let stage = sibling_next_name(&encode_hex(id.as_bytes()));
        let Some(bytes) =
            read_bounded_regular_at(&directory, &stage, MAX_INVOCATION_HISTORY_NODE_BYTES)?
        else {
            return Ok(());
        };
        decode_object::<InvocationHistoryNode>(&bytes, id)?;
        if bytes != expected {
            return Err(JournalStoreError::Corrupt);
        }
        unlink_file_at(&directory, &stage)?;
        directory
            .sync_all()
            .map_err(|_| JournalStoreError::Unavailable)
    }

    #[cfg(target_os = "linux")]
    fn unlink_history_node(
        &self,
        id: InvocationHistoryNodeId,
        missing_is_ok: bool,
    ) -> Result<bool, JournalStoreError> {
        let directory = self.history_shard_directory(id)?;
        let name = encode_hex(id.as_bytes());
        let stage = sibling_next_name(&name);
        let staged =
            read_bounded_regular_at(&directory, &stage, MAX_INVOCATION_HISTORY_NODE_BYTES)?;
        let bytes = read_bounded_regular_at(&directory, &name, MAX_INVOCATION_HISTORY_NODE_BYTES)?;
        if let Some(staged) = &staged {
            decode_object::<InvocationHistoryNode>(staged, id)?;
        }
        let Some(bytes) = bytes else {
            return if missing_is_ok && staged.is_none() {
                Ok(false)
            } else {
                Err(JournalStoreError::Corrupt)
            };
        };
        decode_object::<InvocationHistoryNode>(&bytes, id)?;
        if let Some(staged) = staged {
            if staged != bytes {
                return Err(JournalStoreError::Corrupt);
            }
            unlink_file_at(&directory, &stage)?;
            // Order alias retirement before removal of the canonical name.
            // Otherwise a power loss could recover a stage-only inode after
            // the retirement cursor has already authorized this ID.
            directory
                .sync_all()
                .map_err(|_| JournalStoreError::Unavailable)?;
        }
        unlink_file_at(&directory, &name)?;
        directory
            .sync_all()
            .map_err(|_| JournalStoreError::Unavailable)?;
        Ok(true)
    }

    fn blob_directory(&self, class: JournalBlobClass) -> &'static str {
        match class {
            JournalBlobClass::LaneState => "lane-state/blobs",
            JournalBlobClass::CatalogArtifact => "catalog/blobs",
        }
    }

    fn read_authority<R: CanonicalAuthorityRecord>(
        &self,
        expected: [u8; 32],
    ) -> Result<Option<R>, JournalStoreError> {
        if expected == [0; 32] {
            return Err(JournalStoreError::Corrupt);
        }
        let name = encode_hex(&expected);
        let staged = sibling_next_name(&name);
        let directory = self.directory(R::DIRECTORY)?;
        let staged = read_bounded_regular_at(directory, &staged, R::MAXIMUM)?
            .map(|bytes| decode_authority_record::<R>(&bytes, expected))
            .transpose()?;
        let committed = read_bounded_regular_at(directory, &name, R::MAXIMUM)?
            .map(|bytes| decode_authority_record::<R>(&bytes, expected))
            .transpose()?;
        if let (Some(staged), Some(committed)) = (&staged, &committed)
            && staged != committed
        {
            return Err(JournalStoreError::Corrupt);
        }
        Ok(committed)
    }

    fn persist_authority<R: CanonicalAuthorityRecord>(
        &self,
        record: &R,
    ) -> Result<bool, JournalStoreError> {
        self.ensure_no_gc_pending()?;
        let id = record.storage_id();
        let bytes = record.encode();
        decode_authority_record::<R>(&bytes, id)?;
        let directory = self.directory(R::DIRECTORY)?;
        let name = encode_hex(&id);
        let created = persist_immutable_at(directory, &name, &bytes, R::MAXIMUM, |stored| {
            decode_authority_record::<R>(stored, id).map(|_| ())
        })?;
        #[cfg(target_os = "linux")]
        {
            // Lazy open deliberately leaves private stages inert. A targeted
            // successful retry owns recovery for this exact ID, including the
            // case where a durable `.next` or canonical file already existed.
            let private = private_stage_name(&sibling_next_name(&name))?;
            if unlink_file_if_present_at(directory, &private)? {
                directory
                    .sync_all()
                    .map_err(|_| JournalStoreError::Unavailable)?;
            }
        }
        Ok(created)
    }

    fn persist_authority_with_readback<R: CanonicalAuthorityRecord>(
        &self,
        record: &R,
    ) -> Result<(), JournalStoreError> {
        let id = record.storage_id();
        self.persist_authority(record)?;
        if self.read_authority::<R>(id)?.as_ref() != Some(record) {
            return Err(JournalStoreError::Corrupt);
        }
        Ok(())
    }

    #[cfg(target_os = "linux")]
    fn read_authority_bytes_for_scrub<R: CanonicalAuthorityRecord>(
        directory: &File,
        name: &str,
        limits: SystemAuthorityHistoryScrubLimits,
        report: &mut SystemAuthorityHistoryScrubReport,
    ) -> Result<Option<Vec<u8>>, JournalStoreError> {
        if report.file_reads == limits.max_file_reads {
            return Err(JournalStoreError::LimitExceeded);
        }
        report.file_reads += 1;
        let remaining_bytes = limits
            .max_bytes_read
            .checked_sub(report.bytes_read)
            .ok_or(JournalStoreError::LimitExceeded)?;
        let Some(bytes) =
            read_bounded_regular_at_with_work_limit(directory, name, R::MAXIMUM, remaining_bytes)?
        else {
            return Ok(None);
        };
        let length = u64::try_from(bytes.len()).map_err(|_| JournalStoreError::LimitExceeded)?;
        report.bytes_read = report
            .bytes_read
            .checked_add(length)
            .ok_or(JournalStoreError::LimitExceeded)?;
        Ok(Some(bytes))
    }

    #[cfg(target_os = "linux")]
    fn read_authority_for_scrub<R: CanonicalAuthorityRecord>(
        directory: &File,
        name: &str,
        expected: [u8; 32],
        limits: SystemAuthorityHistoryScrubLimits,
        report: &mut SystemAuthorityHistoryScrubReport,
    ) -> Result<Option<R>, JournalStoreError> {
        Self::read_authority_bytes_for_scrub::<R>(directory, name, limits, report)?
            .map(|bytes| decode_authority_record::<R>(&bytes, expected))
            .transpose()
    }

    #[cfg(target_os = "linux")]
    fn scrub_authority_history_directory<R: CanonicalAuthorityRecord>(
        &self,
        maximum_records: usize,
        limits: SystemAuthorityHistoryScrubLimits,
        report: &mut SystemAuthorityHistoryScrubReport,
    ) -> Result<usize, JournalStoreError> {
        let maximum_names = maximum_records
            .checked_mul(3)
            .ok_or(JournalStoreError::LimitExceeded)?;
        let directory = self.directory(R::DIRECTORY)?;
        let mut records = 0_usize;
        visit_directory_names_bounded(directory, maximum_names, |name| {
            if report.namespace_entries == limits.max_namespace_entries {
                return Err(JournalStoreError::LimitExceeded);
            }
            report.namespace_entries += 1;
            let (stem, staged, private_partial) =
                if let Some(stem) = name.strip_suffix(PRIVATE_STAGE_SUFFIX) {
                    (stem, false, true)
                } else if let Some(stem) = name.strip_suffix(".next") {
                    (stem, true, false)
                } else {
                    (name, false, false)
                };
            let id = decode_hex_32(stem.as_bytes()).ok_or(JournalStoreError::Corrupt)?;
            if id == [0; 32] || encode_hex(&id) != stem {
                return Err(JournalStoreError::Corrupt);
            }
            if private_partial {
                Self::read_authority_bytes_for_scrub::<R>(directory, name, limits, report)?
                    .ok_or(JournalStoreError::Corrupt)?;
                report.private_partial_entries = report
                    .private_partial_entries
                    .checked_add(1)
                    .ok_or(JournalStoreError::LimitExceeded)?;
                return Ok(());
            }
            let record = Self::read_authority_for_scrub::<R>(directory, name, id, limits, report)?
                .ok_or(JournalStoreError::Corrupt)?;

            let counts_as_record = if staged {
                match Self::read_authority_for_scrub::<R>(directory, stem, id, limits, report)? {
                    Some(committed) if committed == record => false,
                    Some(_) => return Err(JournalStoreError::Corrupt),
                    None => true,
                }
            } else {
                true
            };
            if counts_as_record {
                records = records
                    .checked_add(1)
                    .ok_or(JournalStoreError::LimitExceeded)?;
                if records > maximum_records {
                    return Err(JournalStoreError::LimitExceeded);
                }
            }
            Ok(())
        })?;
        Ok(records)
    }

    #[cfg(target_os = "linux")]
    fn scrub_catalog_record_reference(
        &self,
        expected: &SystemAuthorityCatalogRecord,
        limits: SystemAuthorityHistoryScrubLimits,
        report: &mut SystemAuthorityHistoryScrubReport,
    ) -> Result<(), JournalStoreError> {
        let id = expected.id();
        let name = encode_hex(id.as_bytes());
        let staged_name = sibling_next_name(&name);
        let directory = self.directory(AUTHORITY_SYSTEM_CATALOG_RECORDS_DIRECTORY)?;
        let staged = Self::read_authority_for_scrub::<SystemAuthorityCatalogRecord>(
            directory,
            &staged_name,
            *id.as_bytes(),
            limits,
            report,
        )?;
        let committed = Self::read_authority_for_scrub::<SystemAuthorityCatalogRecord>(
            directory,
            &name,
            *id.as_bytes(),
            limits,
            report,
        )?;
        if let (Some(staged), Some(committed)) = (&staged, &committed)
            && staged != committed
        {
            return Err(JournalStoreError::Corrupt);
        }
        if committed.or(staged).as_ref() != Some(expected) {
            return Err(JournalStoreError::Corrupt);
        }
        Ok(())
    }

    #[cfg(target_os = "linux")]
    fn scrub_catalog_leaf_record_links(
        &self,
        limits: SystemAuthorityHistoryScrubLimits,
        report: &mut SystemAuthorityHistoryScrubReport,
    ) -> Result<(), JournalStoreError> {
        let maximum_names = MAX_SYSTEM_AUTHORITY_CATALOG_TREE_NODES
            .checked_mul(3)
            .ok_or(JournalStoreError::LimitExceeded)?;
        let directory = self.directory(AUTHORITY_SYSTEM_CATALOG_NODES_DIRECTORY)?;
        visit_directory_names_bounded(directory, maximum_names, |name| {
            if name.ends_with(PRIVATE_STAGE_SUFFIX) {
                return Ok(());
            }
            let stem = name.strip_suffix(".next").unwrap_or(name);
            let id = decode_hex_32(stem.as_bytes()).ok_or(JournalStoreError::Corrupt)?;
            if id == [0; 32] || encode_hex(&id) != stem {
                return Err(JournalStoreError::Corrupt);
            }
            let node = Self::read_authority_for_scrub::<SystemAuthorityCatalogNode>(
                directory, name, id, limits, report,
            )?
            .ok_or(JournalStoreError::Corrupt)?;
            if let SystemAuthorityCatalogNode::Leaf(record) = node {
                self.scrub_catalog_record_reference(&record, limits, report)?;
            }
            Ok(())
        })
        .map(|_| ())
    }

    /// Explicitly stream and authenticate every permanent authority-history
    /// object under caller-supplied work limits.
    ///
    /// This is intentionally not part of `open`: no namespace entry grants
    /// authority until an exact typed ID load validates it, and a mandatory
    /// protocol-scale scrub would make a valid large store unavailable.
    pub(crate) fn scrub_system_authority_history(
        &self,
        limits: SystemAuthorityHistoryScrubLimits,
    ) -> Result<SystemAuthorityHistoryScrubReport, JournalStoreError> {
        #[cfg(not(target_os = "linux"))]
        {
            let _ = limits;
            Err(JournalStoreError::Unavailable)
        }
        #[cfg(target_os = "linux")]
        {
            let mut report = SystemAuthorityHistoryScrubReport {
                namespace_entries: 0,
                private_partial_entries: 0,
                file_reads: 0,
                bytes_read: 0,
                decision_records: 0,
                rotation_records: 0,
                catalog_nodes: 0,
                catalog_records: 0,
                committee_records: 0,
            };
            let decision_records = self
                .scrub_authority_history_directory::<SystemAuthorityDecisionNode>(
                    MAX_SYSTEM_AUTHORITY_DECISION_TREE_NODES,
                    limits,
                    &mut report,
                )?;
            report.decision_records = decision_records;
            let rotation_records = self
                .scrub_authority_history_directory::<SystemAuthorityRotationNode>(
                    MAX_SYSTEM_AUTHORITY_ROTATION_TREE_NODES,
                    limits,
                    &mut report,
                )?;
            report.rotation_records = rotation_records;
            let catalog_nodes = self
                .scrub_authority_history_directory::<SystemAuthorityCatalogNode>(
                    MAX_SYSTEM_AUTHORITY_CATALOG_TREE_NODES,
                    limits,
                    &mut report,
                )?;
            report.catalog_nodes = catalog_nodes;
            self.scrub_catalog_leaf_record_links(limits, &mut report)?;
            let catalog_records = self
                .scrub_authority_history_directory::<SystemAuthorityCatalogRecord>(
                    MAX_SYSTEM_AUTHORITY_CATALOG_RECORDS as usize,
                    limits,
                    &mut report,
                )?;
            report.catalog_records = catalog_records;
            let committee_records = self
                .scrub_authority_history_directory::<SystemAuthorityCommitteeRecord>(
                    MAX_SYSTEM_AUTHORITY_COMMITTEE_RECORDS,
                    limits,
                    &mut report,
                )?;
            report.committee_records = committee_records;
            Ok(report)
        }
    }

    fn load_authority_closure(
        &self,
        genesis: &AgentJournalGenesis,
    ) -> Result<
        (
            RootAnchorRecord,
            SystemAgentGenesisEvidence,
            AgentGenesisAdmissionRecord,
        ),
        JournalStoreError,
    > {
        let admission = self
            .read_authority::<AgentGenesisAdmissionRecord>(*genesis.admission.as_bytes())?
            .ok_or(JournalStoreError::MissingObject)?;
        let root_admission = phase_one_root_admission(&admission)?;
        let evidence = self
            .read_authority::<SystemAgentGenesisEvidence>(*root_admission.evidence().as_bytes())?
            .ok_or(JournalStoreError::MissingObject)?;
        let root = self
            .read_authority::<RootAnchorRecord>(*root_admission.root_anchor().as_bytes())?
            .ok_or(JournalStoreError::MissingObject)?;
        validate_authority_links(genesis, &root, &evidence, &admission)?;
        Ok((root, evidence, admission))
    }

    fn validate_authority_recovery(
        &self,
        sealed: Option<&ReplaySealedGenesis>,
        allow_unverified_for_test: bool,
    ) -> Result<(), JournalStoreError> {
        let Some(genesis) = self.genesis()? else {
            return Ok(());
        };
        if allow_unverified_for_test {
            return Ok(());
        }

        // Load and validate the complete content-addressed chain before
        // reporting that a fresh trust capability is required. This keeps
        // missing/tampered storage distinguishable from an intact but
        // intentionally untrusted reopen.
        let (root, evidence, admission) = self.load_authority_closure(&genesis)?;
        let sealed = sealed.ok_or(JournalStoreError::Unavailable)?;
        validate_sealed_genesis_shape(sealed, self.agent, self.node)?;
        if sealed.genesis() != &genesis
            || sealed.root_anchor() != &root
            || sealed.admission_evidence() != &evidence
            || sealed.admission_record() != &admission
        {
            return Err(JournalStoreError::ScopeMismatch);
        }
        Ok(())
    }

    fn validate_local_authority_recovery(
        &self,
        sealed: &ReplaySealedLocalGenesis,
    ) -> Result<(), JournalStoreError> {
        validate_sealed_local_genesis_shape(sealed, self.agent, self.node)?;
        let Some(genesis) = self.genesis()? else {
            return Ok(());
        };
        if sealed.genesis() != &genesis
            || self.read_admission("genesis-admission")? != Some(sealed.admission_commitment())
        {
            return Err(JournalStoreError::ScopeMismatch);
        }
        Ok(())
    }

    fn read_fixed<R: CanonicalJournalRecord>(
        &self,
        directory: &'static str,
        name: &str,
    ) -> Result<Option<R>, JournalStoreError> {
        let Some(bytes) = read_bounded_regular_at(
            self.directory(directory)?,
            name,
            class_maximum(R::STORAGE_CLASS),
        )?
        else {
            return Ok(None);
        };
        let decoded = R::decode(&bytes).map_err(|_| JournalStoreError::Corrupt)?;
        let id = decoded.id();
        decode_object(&bytes, id).map(Some)
    }

    fn read_object<R: CanonicalJournalRecord>(
        &self,
        id: R::Id,
    ) -> Result<Option<R>, JournalStoreError> {
        ensure_readable_content_class(R::STORAGE_CLASS)?;
        if R::STORAGE_CLASS == JournalStorageClass::InvocationHistoryNode {
            let history_id = InvocationHistoryNodeId(*id.as_bytes());
            return self
                .load_history_node(history_id)?
                .map(|bytes| decode_object::<R>(&bytes, id))
                .transpose();
        }
        let directory = self.object_directory(R::STORAGE_CLASS)?;
        let name = encode_hex(id.as_bytes());
        let staged = sibling_next_name(&name);
        if let Some(bytes) = read_bounded_regular_at(
            self.directory(directory)?,
            &staged,
            class_maximum(R::STORAGE_CLASS),
        )? {
            // A crash stage is not visible, but it must still be an exact
            // canonical candidate for this content-addressed path.
            decode_object::<R>(&bytes, id)?;
        }
        let Some(bytes) = read_bounded_regular_at(
            self.directory(directory)?,
            &name,
            class_maximum(R::STORAGE_CLASS),
        )?
        else {
            return Ok(None);
        };
        decode_object(&bytes, id).map(Some)
    }

    fn persist_object<R: CanonicalJournalRecord>(
        &self,
        record: &R,
    ) -> Result<bool, JournalStoreError> {
        self.ensure_no_gc_pending()?;
        ensure_writable_content_class(R::STORAGE_CLASS)?;
        let encoded = encode_object(record)?;
        let directory = self.object_directory(encoded.class)?;
        persist_immutable_at(
            self.directory(directory)?,
            &encode_hex(&encoded.id),
            &encoded.bytes,
            class_maximum(encoded.class),
            |bytes| decode_object::<R>(bytes, record.id()).map(|_| ()),
        )
    }

    fn read_blob(
        &self,
        class: JournalBlobClass,
        reference: &BlobRef,
    ) -> Result<Option<Vec<u8>>, JournalStoreError> {
        validate_blob_reference(class, reference)?;
        let directory = self.blob_directory(class);
        let name = encode_hex(reference.hash.as_bytes());
        let staged = sibling_next_name(&name);
        if let Some(bytes) =
            read_bounded_regular_at(self.directory(directory)?, &staged, blob_maximum(class))?
        {
            validate_stored_blob(class, reference, &bytes)?;
        }
        let Some(bytes) =
            read_bounded_regular_at(self.directory(directory)?, &name, blob_maximum(class))?
        else {
            return Ok(None);
        };
        validate_stored_blob(class, reference, &bytes)?;
        Ok(Some(bytes))
    }

    fn persist_blob(
        &self,
        class: JournalBlobClass,
        reference: &BlobRef,
        bytes: &[u8],
    ) -> Result<bool, JournalStoreError> {
        self.ensure_no_gc_pending()?;
        validate_supplied_blob(class, reference, bytes)?;
        let directory = self.blob_directory(class);
        persist_immutable_at(
            self.directory(directory)?,
            &encode_hex(reference.hash.as_bytes()),
            bytes,
            blob_maximum(class),
            |stored| validate_stored_blob(class, reference, stored),
        )
    }

    fn read_shared_ordered_commit_binding(
        &self,
        entry: OrderedEntryId,
    ) -> Result<Option<SharedOrderedCommitBinding>, JournalStoreError> {
        if entry == OrderedEntryId::ZERO {
            return Err(JournalStoreError::Corrupt);
        }
        let directory = self.directory(SHARED_ORDERED_COMMIT_DIRECTORY)?;
        let name = encode_hex(entry.as_bytes());
        let staged = sibling_next_name(&name);
        let staged =
            read_bounded_regular_at(directory, &staged, MAX_SHARED_ORDERED_COMMIT_BINDING_BYTES)?
                .map(|bytes| decode_shared_ordered_commit_binding(&bytes, entry))
                .transpose()?;
        let committed =
            read_bounded_regular_at(directory, &name, MAX_SHARED_ORDERED_COMMIT_BINDING_BYTES)?
                .map(|bytes| decode_shared_ordered_commit_binding(&bytes, entry))
                .transpose()?;
        if let (Some(staged), Some(committed)) = (&staged, &committed)
            && staged != committed
        {
            return Err(JournalStoreError::Corrupt);
        }
        Ok(committed)
    }

    #[cfg(target_os = "linux")]
    fn audit_shared_ordered_commit_directory(&self) -> Result<usize, JournalStoreError> {
        let directory = self.directory(SHARED_ORDERED_COMMIT_DIRECTORY)?;
        let names = bounded_directory_names(directory, MAX_SHARED_ORDERED_COMMIT_FILES)?;
        let heads = self.heads()?;
        if heads.is_none() && !names.is_empty() {
            return Err(JournalStoreError::Corrupt);
        }
        let mut bindings: BTreeMap<
            OrderedEntryId,
            (
                Option<SharedOrderedCommitBinding>,
                Option<SharedOrderedCommitBinding>,
            ),
        > = BTreeMap::new();
        for name in names {
            let (stem, staged) = name
                .strip_suffix(".next")
                .map_or((name.as_str(), false), |stem| (stem, true));
            let raw = decode_hex_32(stem.as_bytes()).ok_or(JournalStoreError::Corrupt)?;
            let entry = OrderedEntryId(raw);
            if entry == OrderedEntryId::ZERO || encode_hex(entry.as_bytes()) != stem {
                return Err(JournalStoreError::Corrupt);
            }
            let bytes =
                read_bounded_regular_at(directory, &name, MAX_SHARED_ORDERED_COMMIT_BINDING_BYTES)?
                    .ok_or(JournalStoreError::Corrupt)?;
            let binding = decode_shared_ordered_commit_binding(&bytes, entry)?;
            let heads = heads.as_ref().ok_or(JournalStoreError::Corrupt)?;
            validate_shared_ordered_commit_scope(&binding, heads, self.instance_id())?;
            if binding.claim().ordered().index
                > heads
                    .ordered_index
                    .checked_add(1)
                    .ok_or(JournalStoreError::LimitExceeded)?
            {
                return Err(JournalStoreError::Corrupt);
            }
            if !bindings.contains_key(&entry)
                && bindings.len() == MAX_SHARED_ORDERED_COMMIT_BINDINGS
            {
                return Err(JournalStoreError::LimitExceeded);
            }
            let slot = bindings.entry(entry).or_default();
            let destination = if staged { &mut slot.1 } else { &mut slot.0 };
            if destination.replace(binding).is_some() {
                return Err(JournalStoreError::Corrupt);
            }
        }
        if bindings.values().any(|(committed, staged)| {
            matches!((committed, staged), (Some(committed), Some(staged)) if committed != staged)
        }) {
            return Err(JournalStoreError::Corrupt);
        }
        Ok(bindings.len())
    }

    fn persist_shared_ordered_commit_binding(
        &self,
        binding: &SharedOrderedCommitBinding,
    ) -> Result<bool, JournalStoreError> {
        self.ensure_no_gc_pending()?;
        binding.validate()?;
        let heads = self.heads()?.ok_or(JournalStoreError::NotInitialized)?;
        validate_shared_ordered_commit_scope(binding, &heads, self.instance_id())?;
        let bytes = binding.encode();
        if let Some(existing) = self.read_shared_ordered_commit_binding(binding.entry)? {
            return if existing == *binding {
                Ok(false)
            } else {
                Err(JournalStoreError::Conflict)
            };
        }
        if self.audit_shared_ordered_commit_directory()? == MAX_SHARED_ORDERED_COMMIT_BINDINGS {
            return Err(JournalStoreError::LimitExceeded);
        }
        persist_immutable_at(
            self.directory(SHARED_ORDERED_COMMIT_DIRECTORY)?,
            &encode_hex(binding.entry.as_bytes()),
            &bytes,
            MAX_SHARED_ORDERED_COMMIT_BINDING_BYTES,
            |stored| decode_shared_ordered_commit_binding(stored, binding.entry).map(|_| ()),
        )
    }

    fn read_admission(&self, name: &str) -> Result<Option<Hash>, JournalStoreError> {
        let Some(bytes) = read_bounded_regular_at(self.directory("")?, name, 32)? else {
            return Ok(None);
        };
        let bytes: [u8; 32] = bytes.try_into().map_err(|_| JournalStoreError::Corrupt)?;
        let commitment = Hash(bytes);
        if commitment == Hash::ZERO {
            return Err(JournalStoreError::Corrupt);
        }
        Ok(Some(commitment))
    }

    fn persist_admission(&self, commitment: Hash) -> Result<bool, JournalStoreError> {
        self.ensure_no_gc_pending()?;
        if commitment == Hash::ZERO {
            return Err(JournalStoreError::NonCanonical);
        }
        persist_immutable_at(
            self.directory("")?,
            "genesis-admission",
            commitment.as_bytes(),
            32,
            |stored| {
                if stored == commitment.as_bytes() {
                    Ok(())
                } else {
                    Err(JournalStoreError::Corrupt)
                }
            },
        )
    }

    fn validate_recovery_state(&self) -> Result<(), JournalStoreError> {
        self.gc_intent()?;
        let admission = self.read_admission("genesis-admission")?;
        let staged_admission = self.read_admission("genesis-admission.next")?;
        if let (Some(committed), Some(staged)) = (admission, staged_admission)
            && committed != staged
        {
            return Err(JournalStoreError::Corrupt);
        }

        let genesis = self.read_fixed::<AgentJournalGenesis>("", "genesis")?;
        let staged_genesis = self.read_fixed::<AgentJournalGenesis>("", "genesis.next")?;
        for value in [&genesis, &staged_genesis].into_iter().flatten() {
            if value.runtime().agent != self.agent {
                return Err(JournalStoreError::ScopeMismatch);
            }
            if admission != Some(value.admission.as_hash()) {
                return Err(JournalStoreError::Corrupt);
            }
        }
        if let (Some(committed), Some(staged)) = (&genesis, &staged_genesis)
            && committed != staged
        {
            return Err(JournalStoreError::Corrupt);
        }

        let heads = self.read_fixed::<JournalHeads>("", "heads")?;
        let staged_heads = self.read_fixed::<JournalHeads>("", "heads.next")?;
        if (genesis.is_some() || staged_genesis.is_some()) && admission.is_none()
            || genesis.is_none() && (heads.is_some() || staged_heads.is_some())
        {
            return Err(JournalStoreError::Corrupt);
        }
        if let Some(genesis) = &genesis {
            let genesis_id = genesis.id();
            for value in [&heads, &staged_heads].into_iter().flatten() {
                if value.genesis != genesis_id || value.node != self.node {
                    return Err(JournalStoreError::ScopeMismatch);
                }
            }
        }
        match (&heads, &staged_heads) {
            (Some(current), Some(staged)) => current
                .validate_successor(staged)
                .map_err(|_| JournalStoreError::Corrupt)?,
            (None, Some(staged)) if staged.publication_revision == 0 => {}
            (None, Some(_)) => return Err(JournalStoreError::Corrupt),
            _ => {}
        }
        Ok(())
    }

    fn install_initial_heads(&self, initial: &JournalHeads) -> Result<bool, JournalStoreError> {
        self.ensure_no_gc_pending()?;
        let encoded = encode_object(initial)?;
        let directory = self.directory("")?;
        if let Some(current) = self.read_fixed::<JournalHeads>("", "heads")? {
            if current == *initial {
                if let Some(staged) = self.read_fixed::<JournalHeads>("", "heads.next")? {
                    if staged != *initial {
                        return Err(JournalStoreError::Corrupt);
                    }
                    unlink_file_at(directory, "heads.next")?;
                    directory
                        .sync_all()
                        .map_err(|_| JournalStoreError::Unavailable)?;
                }
                return Ok(false);
            }
            return Err(JournalStoreError::Conflict);
        }
        match self.read_fixed::<JournalHeads>("", "heads.next")? {
            Some(staged) if staged == *initial => sync_regular_file_at(directory, "heads.next")?,
            Some(_) => return Err(JournalStoreError::Corrupt),
            None => create_synced_stage_at(directory, "heads.next", &encoded.bytes)?,
        }
        // Initialization is resumed only by an exact admission-sealed genesis
        // and empty head. `open` itself never promotes this stage.
        rename_file_at(directory, "heads.next", "heads")?;
        directory
            .sync_all()
            .map_err(|_| JournalStoreError::Unavailable)?;
        Ok(true)
    }

    fn publish_inner_with_mode<R, F>(
        &mut self,
        expected: JournalHeadsId,
        anchor: &R,
        next: &JournalHeads,
        mode: ReplayPublicationMode,
        mut publication_point: F,
    ) -> Result<JournalPublication, JournalStoreError>
    where
        R: CanonicalJournalRecord,
        F: FnMut(PublicationPoint) -> Result<(), JournalStoreError>,
    {
        self.ensure_no_gc_pending()?;
        ensure_publication_class(R::STORAGE_CLASS)?;
        let encoded_anchor = encode_object(anchor)?;
        let encoded_next = encode_object(next)?;
        let current = self.heads()?.ok_or(JournalStoreError::NotInitialized)?;
        if current.id() == next.id() {
            let existing = self
                .read_object::<R>(anchor.id())?
                .ok_or(JournalStoreError::Corrupt)?;
            if existing.encode() != encoded_anchor.bytes {
                return Err(JournalStoreError::Corrupt);
            }
            validate_head_targets(self, &current)?;
            validate_idempotent_anchor(self, &current, anchor)?;
            return Ok(JournalPublication {
                object_created: false,
                heads_advanced: false,
            });
        }
        if current.id() != expected {
            return Err(JournalStoreError::Conflict);
        }
        validate_head_targets(self, &current)?;
        current
            .validate_successor(next)
            .map_err(supplied_decode_error)?;
        validate_publication_shape_with_mode(&current, anchor, next, mode)?;

        let object_created = self.persist_object(anchor)?;
        publication_point(PublicationPoint::ObjectDurable)?;
        validate_anchor_dependencies(self, &current, anchor, next)?;
        validate_head_targets(self, next)?;

        let directory = self.directory("")?;
        match self.read_fixed::<JournalHeads>("", "heads.next")? {
            Some(staged) if staged == *next => sync_regular_file_at(directory, "heads.next")?,
            Some(staged) => {
                // The recovered candidate must itself be a valid successor;
                // it is safe to abandon only because the durable head still
                // equals this caller's CAS predecessor.
                current
                    .validate_successor(&staged)
                    .map_err(|_| JournalStoreError::Corrupt)?;
                unlink_file_at(directory, "heads.next")?;
                directory
                    .sync_all()
                    .map_err(|_| JournalStoreError::Unavailable)?;
                create_synced_stage_at(directory, "heads.next", &encoded_next.bytes)?;
            }
            None => create_synced_stage_at(directory, "heads.next", &encoded_next.bytes)?,
        }
        publication_point(PublicationPoint::HeadsStaged)?;

        let still_current = self.heads()?.ok_or(JournalStoreError::Corrupt)?;
        if still_current.id() != expected {
            return Err(JournalStoreError::Conflict);
        }
        rename_file_at(directory, "heads.next", "heads")?;
        directory
            .sync_all()
            .map_err(|_| JournalStoreError::Unavailable)?;
        publication_point(PublicationPoint::HeadsDurable)?;
        Ok(JournalPublication {
            object_created,
            heads_advanced: true,
        })
    }

    fn publish_inner<R, F>(
        &mut self,
        expected: JournalHeadsId,
        anchor: &R,
        next: &JournalHeads,
        publication_point: F,
    ) -> Result<JournalPublication, JournalStoreError>
    where
        R: CanonicalJournalRecord,
        F: FnMut(PublicationPoint) -> Result<(), JournalStoreError>,
    {
        self.publish_inner_with_mode(
            expected,
            anchor,
            next,
            ReplayPublicationMode::Canonical,
            publication_point,
        )
    }

    fn publish_anchor<R: CanonicalJournalRecord>(
        &mut self,
        expected: JournalHeadsId,
        anchor: &R,
        next: &JournalHeads,
    ) -> Result<JournalPublication, JournalStoreError> {
        self.publish_inner(expected, anchor, next, |_| Ok(()))
    }

    #[cfg(target_os = "linux")]
    fn stage_sealed_history_candidate(
        &mut self,
        expected: JournalHeadsId,
        next: &JournalHeads,
        plans: &[InvocationHistoryWritePlan],
        publication_point: &mut impl FnMut(PublicationPoint) -> Result<(), JournalStoreError>,
    ) -> Result<(bool, Option<HistoryCandidateOverlay>), JournalStoreError> {
        self.ensure_no_gc_pending()?;
        self.recover_history_state()?;
        let current = self.heads()?.ok_or(JournalStoreError::NotInitialized)?;
        let exact_retry = publication_is_exact_retry(&current, expected, next)?;
        if exact_retry {
            validate_idempotent_history_plans(self, &current, plans)?;
            return Ok((true, None));
        }

        let queue = self.history_queue(current.genesis)?;
        let overlay = build_history_candidate(self, &current, next, plans, &queue)?;
        if let Some(overlay) = overlay.clone() {
            self.stage_history_candidate(overlay, publication_point)?;
        } else if self.history_candidate.is_some() {
            return Err(JournalStoreError::Conflict);
        }
        Ok((false, overlay))
    }

    #[cfg(target_os = "linux")]
    fn publish_sealed_inner(
        &mut self,
        publication: &ReplaySealedPublication,
        authority: Option<&ReplaySystemAuthorityStoragePlan>,
        mut publication_point: impl FnMut(PublicationPoint) -> Result<(), JournalStoreError>,
    ) -> Result<JournalPublication, JournalStoreError> {
        match (publication.system_authority_write(), authority) {
            (None, None) | (Some(_), Some(_)) => {}
            _ => return Err(JournalStoreError::NonCanonical),
        }
        let expected = publication.expected();
        let next = publication.next();
        let (exact_retry, overlay) = self.stage_sealed_history_candidate(
            expected,
            next,
            publication.history_plans(),
            &mut publication_point,
        )?;
        if exact_retry {
            let authority_created = authority
                .map(|plan| stage_system_authority_dependencies(self, publication, plan))
                .transpose()?
                .unwrap_or(false);
            if authority.is_some() {
                publication_point(PublicationPoint::AuthorityDependenciesDurable)?;
            }
            let dependency_created = stage_sealed_dependencies(self, publication)?;
            let mut result = match publication.anchor() {
                ReplayPublicationAnchor::Ordered(entry) => self.publish_inner_with_mode(
                    expected,
                    entry,
                    next,
                    publication.mode(),
                    &mut publication_point,
                )?,
                ReplayPublicationAnchor::Local(entry) => self.publish_inner_with_mode(
                    expected,
                    entry,
                    next,
                    publication.mode(),
                    &mut publication_point,
                )?,
                ReplayPublicationAnchor::Merge { event, .. } => self.publish_inner_with_mode(
                    expected,
                    event,
                    next,
                    publication.mode(),
                    &mut publication_point,
                )?,
                ReplayPublicationAnchor::Checkpoint(checkpoint) => self.publish_inner_with_mode(
                    expected,
                    checkpoint,
                    next,
                    publication.mode(),
                    &mut publication_point,
                )?,
            };
            if let Some(plan) = authority {
                stage_system_authority_dependencies(self, publication, plan)?;
            }
            result.object_created |= authority_created || dependency_created;
            return Ok(result);
        }

        let attempted = (|| {
            let authority_created = authority
                .map(|plan| stage_system_authority_dependencies(self, publication, plan))
                .transpose()?
                .unwrap_or(false);
            if authority.is_some() {
                publication_point(PublicationPoint::AuthorityDependenciesDurable)?;
            }
            let dependency_created = stage_sealed_dependencies(self, publication)?;
            let mut result = match publication.anchor() {
                ReplayPublicationAnchor::Ordered(entry) => self.publish_inner_with_mode(
                    expected,
                    entry,
                    next,
                    publication.mode(),
                    &mut publication_point,
                )?,
                ReplayPublicationAnchor::Local(entry) => self.publish_inner_with_mode(
                    expected,
                    entry,
                    next,
                    publication.mode(),
                    &mut publication_point,
                )?,
                ReplayPublicationAnchor::Merge { event, .. } => self.publish_inner_with_mode(
                    expected,
                    event,
                    next,
                    publication.mode(),
                    &mut publication_point,
                )?,
                ReplayPublicationAnchor::Checkpoint(checkpoint) => self.publish_inner_with_mode(
                    expected,
                    checkpoint,
                    next,
                    publication.mode(),
                    &mut publication_point,
                )?,
            };
            if result.heads_advanced && overlay.is_some() {
                result.object_created |= self.finish_history_candidate(&mut publication_point)?;
            }
            if let Some(plan) = authority {
                stage_system_authority_dependencies(self, publication, plan)?;
            }
            result.object_created |= authority_created || dependency_created;
            Ok(result)
        })();
        if attempted.is_err() && overlay.is_some() {
            let durable = self.heads()?.ok_or(JournalStoreError::Corrupt)?;
            let staged = self.read_fixed::<JournalHeads>("", "heads.next")?;
            if durable.id() == expected && staged.is_none() {
                self.clear_history_candidate_files()?;
            } else if !((durable.id() == expected
                && staged.as_ref().is_some_and(|heads| heads.id() == next.id()))
                || (durable.id() == next.id() && staged.is_none()))
            {
                return Err(JournalStoreError::Corrupt);
            }
        }
        attempted
    }

    #[cfg(test)]
    fn initialize_raw_for_test(
        &mut self,
        genesis: &AgentJournalGenesis,
    ) -> Result<bool, JournalStoreError> {
        self.ensure_no_gc_pending()?;
        let encoded = encode_object(genesis)?;
        if genesis.runtime().agent != self.agent {
            return Err(JournalStoreError::ScopeMismatch);
        }
        require_blob(
            self,
            JournalBlobClass::CatalogArtifact,
            &genesis.runtime().package,
        )?;
        let test_admission = genesis.admission.as_hash();
        self.persist_admission(test_admission)?;
        let directory = self.directory("")?;
        let genesis_created = persist_immutable_at(
            directory,
            "genesis",
            &encoded.bytes,
            class_maximum(JournalStorageClass::Genesis),
            |bytes| {
                let decoded =
                    AgentJournalGenesis::decode(bytes).map_err(|_| JournalStoreError::Corrupt)?;
                decode_object::<AgentJournalGenesis>(bytes, decoded.id()).map(|_| ())
            },
        )?;
        let empty_frontier = MergeFrontier {
            genesis: genesis.id(),
            events: Vec::new(),
        };
        self.persist_object(&empty_frontier)?;
        self.persist_object(&InvocationIndexManifest::empty(
            genesis.id(),
            InvocationOwnershipScope::Ordered,
        ))?;
        self.persist_object(&InvocationIndexManifest::empty(
            genesis.id(),
            InvocationOwnershipScope::Merge,
        ))?;
        self.persist_object(&InvocationIndexManifest::empty(
            genesis.id(),
            InvocationOwnershipScope::Local(self.node),
        ))?;
        let initial = JournalHeads::initial(
            genesis.id(),
            genesis.admission,
            self.node,
            empty_frontier.id(),
            genesis.runtime().clone(),
        );
        let heads_created = self.install_initial_heads(&initial)?;
        validate_head_targets(self, &initial)?;
        Ok(genesis_created || heads_created)
    }

    #[cfg(target_os = "linux")]
    fn scan_gc_namespace(&self, limits: GcLimits) -> Result<Vec<FileGcEntry>, JournalStoreError> {
        let mut entries = Vec::new();
        let mut scanned_files = 0_usize;
        let mut scanned_bytes = 0_u64;
        for &(class, directory) in GC_OBJECT_NAMESPACES {
            scan_gc_directory(
                self.directory(directory)?,
                directory,
                FileGcKind::Object(class),
                class_maximum(class),
                limits,
                &mut scanned_files,
                &mut scanned_bytes,
                &mut entries,
            )?;
        }
        for &(class, directory) in GC_BLOB_NAMESPACES {
            scan_gc_directory(
                self.directory(directory)?,
                directory,
                FileGcKind::Blob(class),
                blob_maximum(class),
                limits,
                &mut scanned_files,
                &mut scanned_bytes,
                &mut entries,
            )?;
        }
        entries.sort_by(|left, right| {
            (left.directory, left.name.as_str()).cmp(&(right.directory, right.name.as_str()))
        });
        Ok(entries)
    }

    #[cfg(target_os = "linux")]
    fn history_queue_and_stage(
        &self,
        genesis: AgentJournalGenesisId,
    ) -> Result<
        (
            HistoryRetirementQueue,
            Option<(HistoryRetirementQueue, Vec<InvocationHistoryNodeId>)>,
        ),
        JournalStoreError,
    > {
        let committed = self
            .read_history_queue_file(HISTORY_RETIREMENTS_NAME)?
            .unwrap_or_else(|| HistoryRetirementQueue::empty(genesis, self.node));
        if committed.genesis != genesis || committed.node != self.node {
            return Err(JournalStoreError::Corrupt);
        }
        committed.validate()?;
        let staged = self.read_history_queue_file(HISTORY_RETIREMENTS_STAGE_NAME)?;
        let staged = staged
            .map(|staged| {
                let delta = history_retirement_stage_delta(&committed, &staged)?;
                Ok((staged, delta))
            })
            .transpose()?;
        Ok((committed, staged))
    }

    #[cfg(target_os = "linux")]
    fn validate_history_retirement_nodes(
        &self,
        queue: &HistoryRetirementQueue,
        authorized_missing: &[InvocationHistoryNodeId],
    ) -> Result<(), JournalStoreError> {
        let authorized_missing = authorized_missing.iter().copied().collect::<BTreeSet<_>>();
        for record in &queue.records {
            for id in record.remaining() {
                match self.read_global_history_node(*id)? {
                    Some(_) => {}
                    None if authorized_missing.contains(id) => {}
                    None => return Err(JournalStoreError::Corrupt),
                }
            }
        }
        Ok(())
    }

    #[cfg(target_os = "linux")]
    fn promote_history_retirement_stage(
        &self,
        staged: &HistoryRetirementQueue,
    ) -> Result<(), JournalStoreError> {
        let history = self.directory(HISTORY_DIRECTORY)?;
        rename_file_at(
            history,
            HISTORY_RETIREMENTS_STAGE_NAME,
            HISTORY_RETIREMENTS_NAME,
        )?;
        history
            .sync_all()
            .map_err(|_| JournalStoreError::Unavailable)?;
        if staged.records.is_empty() {
            unlink_file_at(history, HISTORY_RETIREMENTS_NAME)?;
            history
                .sync_all()
                .map_err(|_| JournalStoreError::Unavailable)?;
        }
        Ok(())
    }

    #[cfg(target_os = "linux")]
    fn resume_history_retirement_stage(
        &self,
        staged: &HistoryRetirementQueue,
        ids: &[InvocationHistoryNodeId],
        maximum: usize,
        publication_point: &mut impl FnMut(GcPoint) -> Result<(), JournalStoreError>,
    ) -> Result<(usize, bool), JournalStoreError> {
        let mut removed = 0usize;
        for id in ids {
            if self.read_global_history_node(*id)?.is_none() {
                // This also rejects a stage-only alias. Treating it as an
                // already removed object would let cursor promotion strand
                // an untracked permanent inode.
                self.unlink_history_node(*id, true)?;
                continue;
            }
            if removed == maximum {
                return Ok((removed, false));
            }
            self.unlink_history_node(*id, false)?;
            removed += 1;
        }
        publication_point(GcPoint::HistoryRetirementSweepDurable)?;
        self.promote_history_retirement_stage(staged)?;
        publication_point(GcPoint::HistoryRetirementCursorDurable)?;
        Ok((removed, true))
    }

    #[cfg(target_os = "linux")]
    fn advance_history_retirements(
        &self,
        queue: &HistoryRetirementQueue,
        maximum: usize,
        publication_point: &mut impl FnMut(GcPoint) -> Result<(), JournalStoreError>,
    ) -> Result<(usize, bool), JournalStoreError> {
        let (next, ids) = advance_history_retirement_queue(queue, maximum)?;
        if next == *queue {
            return Ok((0, true));
        }
        create_synced_stage_at(
            self.directory(HISTORY_DIRECTORY)?,
            HISTORY_RETIREMENTS_STAGE_NAME,
            &next.encode(),
        )?;
        publication_point(GcPoint::HistoryRetirementStaged)?;
        for id in &ids {
            self.unlink_history_node(*id, false)?;
        }
        publication_point(GcPoint::HistoryRetirementSweepDurable)?;
        self.promote_history_retirement_stage(&next)?;
        publication_point(GcPoint::HistoryRetirementCursorDurable)?;
        Ok((ids.len(), true))
    }

    #[cfg(target_os = "linux")]
    fn ensure_gc_intent_durable(
        &self,
        intent: GcIntent,
        publication_point: &mut impl FnMut(GcPoint) -> Result<(), JournalStoreError>,
    ) -> Result<bool, JournalStoreError> {
        let committed = self.read_gc_intent_file(GC_INTENT_NAME)?;
        let staged = self.read_gc_intent_file(GC_INTENT_STAGE_NAME)?;
        if committed.is_some_and(|existing| existing != intent)
            || staged.is_some_and(|existing| existing != intent)
        {
            return Err(JournalStoreError::Corrupt);
        }
        let resumed = committed.is_some() || staged.is_some();
        let root = self.directory("")?;
        if committed.is_some() {
            if staged.is_some() {
                unlink_file_at(root, GC_INTENT_STAGE_NAME)?;
                root.sync_all()
                    .map_err(|_| JournalStoreError::Unavailable)?;
            }
            publication_point(GcPoint::IntentDurable)?;
            return Ok(resumed);
        }
        if staged.is_none() {
            create_synced_stage_at(root, GC_INTENT_STAGE_NAME, &intent.encode())?;
        } else {
            sync_regular_file_at(root, GC_INTENT_STAGE_NAME)?;
        }
        publication_point(GcPoint::IntentStaged)?;
        let heads = self.heads()?.ok_or(JournalStoreError::Corrupt)?;
        if heads.id() != intent.heads
            || self.read_fixed::<JournalHeads>("", "heads.next")?.is_some()
        {
            return Err(JournalStoreError::Conflict);
        }
        rename_file_at(root, GC_INTENT_STAGE_NAME, GC_INTENT_NAME)?;
        root.sync_all()
            .map_err(|_| JournalStoreError::Unavailable)?;
        publication_point(GcPoint::IntentDurable)?;
        Ok(resumed)
    }

    #[cfg(target_os = "linux")]
    fn validate_gc_entry_unchanged(&self, entry: &FileGcEntry) -> Result<(), JournalStoreError> {
        let directory = self.directory(entry.directory)?;
        let name = c_name(&entry.name)?;
        verify_regular_entry(directory, &name, entry.identity)?;
        let status = stat_at(directory, &name)
            .map_err(|_| JournalStoreError::Unavailable)?
            .ok_or(JournalStoreError::Corrupt)?;
        if status_identity(&status) != entry.identity
            || status.st_size < 0
            || status.st_size as u64 != entry.bytes
        {
            return Err(JournalStoreError::Corrupt);
        }
        Ok(())
    }

    #[cfg(target_os = "linux")]
    fn collect_garbage_inner(
        &mut self,
        expected_heads: JournalHeadsId,
        limits: GcLimits,
        mut publication_point: impl FnMut(GcPoint) -> Result<(), JournalStoreError>,
    ) -> Result<JournalGc, JournalStoreError> {
        validate_gc_limits(limits)?;
        self.recover_history_state()?;
        if self.read_fixed::<JournalHeads>("", "heads.next")?.is_some() {
            return Err(JournalStoreError::Conflict);
        }
        let (intent, mark) = build_gc_mark(self, expected_heads, limits)?;
        let heads = self.heads()?.ok_or(JournalStoreError::NotInitialized)?;
        let (history_queue, staged_history) = self.history_queue_and_stage(heads.genesis)?;
        validate_history_retirement_coverage(self, expected_heads, &history_queue)?;
        let authorized_missing = staged_history
            .as_ref()
            .map_or(&[][..], |(_, ids)| ids.as_slice());
        self.validate_history_retirement_nodes(&history_queue, authorized_missing)?;

        // Pass one is exhaustive and non-mutating. No intent is installed and
        // no garbage is removed unless every namespace entry fits the caller's
        // file/byte bounds and is an owned regular canonical name.
        let scanned = self.scan_gc_namespace(limits)?;
        let garbage = scanned
            .into_iter()
            .filter(|entry| !entry.is_live(&mark))
            .collect::<Vec<_>>();
        let resumed = self.ensure_gc_intent_durable(intent, &mut publication_point)?;

        let mut remaining = limits.max_unlinks_per_run;
        let mut synced = BTreeSet::new();
        let mut objects_removed = 0_usize;
        let mut blobs_removed = 0_usize;
        let mut aliases_removed = 0_usize;
        if let Some((staged, ids)) = &staged_history {
            let (removed, promoted) = self.resume_history_retirement_stage(
                staged,
                ids,
                remaining,
                &mut publication_point,
            )?;
            objects_removed += removed;
            remaining -= removed;
            if !promoted {
                publication_point(GcPoint::SweepDurable)?;
                return Ok(JournalGc {
                    objects_removed,
                    blobs_removed,
                    aliases_removed,
                    resumed,
                    complete: false,
                });
            }
        }
        let queue = self
            .read_history_queue_file(HISTORY_RETIREMENTS_NAME)?
            .unwrap_or_else(|| HistoryRetirementQueue::empty(heads.genesis, self.node));
        let (removed, _) =
            self.advance_history_retirements(&queue, remaining, &mut publication_point)?;
        objects_removed += removed;
        remaining -= removed;

        // Normal GC deliberately never scans permanent history. Its exact
        // named retirements consume the same unlink budget, then the existing
        // second pass revalidates every ordinary inode immediately before
        // descriptor-relative removal.
        let batch = garbage.len().min(remaining);
        for entry in garbage.iter().take(batch) {
            self.validate_gc_entry_unchanged(entry)?;
            unlink_file_at(self.directory(entry.directory)?, &entry.name)?;
            synced.insert(entry.directory);
            if entry.alias {
                aliases_removed += 1;
            } else {
                match entry.kind {
                    FileGcKind::Object(_) => objects_removed += 1,
                    FileGcKind::Blob(_) => blobs_removed += 1,
                }
            }
        }
        for directory in synced {
            self.directory(directory)?
                .sync_all()
                .map_err(|_| JournalStoreError::Unavailable)?;
        }
        publication_point(GcPoint::SweepDurable)?;

        let queue_complete = self
            .read_history_queue_file(HISTORY_RETIREMENTS_NAME)?
            .is_none_or(|queue| queue.records.is_empty())
            && self
                .read_history_queue_file(HISTORY_RETIREMENTS_STAGE_NAME)?
                .is_none();
        let complete = queue_complete && batch == garbage.len();
        if complete {
            let root = self.directory("")?;
            unlink_file_if_present_at(root, GC_INTENT_STAGE_NAME)?;
            unlink_file_at(root, GC_INTENT_NAME)?;
            root.sync_all()
                .map_err(|_| JournalStoreError::Unavailable)?;
            publication_point(GcPoint::Complete)?;
        }
        Ok(JournalGc {
            objects_removed,
            blobs_removed,
            aliases_removed,
            resumed,
            complete,
        })
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum PublicationPoint {
    HistoryCandidateDurable,
    AuthorityDependenciesDurable,
    ObjectDurable,
    HeadsStaged,
    HeadsDurable,
    HistoryPromoted,
    HistoryRetirementDurable,
    HistoryCandidateCleared,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum GcPoint {
    IntentStaged,
    IntentDurable,
    HistoryRetirementStaged,
    HistoryRetirementSweepDurable,
    HistoryRetirementCursorDurable,
    SweepDurable,
    Complete,
}

impl InvocationHistoryStore for FileAgentJournalStore {
    type Error = JournalStoreError;

    fn load_history_node(
        &self,
        id: InvocationHistoryNodeId,
    ) -> Result<Option<Vec<u8>>, Self::Error> {
        if id == InvocationHistoryNodeId::ZERO {
            return Err(JournalStoreError::Corrupt);
        }
        if let Some(bytes) = self
            .history_candidate
            .as_ref()
            .and_then(|candidate| candidate.nodes.get(&id))
        {
            decode_object::<InvocationHistoryNode>(bytes, id)?;
            return Ok(Some(bytes.clone()));
        }
        self.read_global_history_node(id)
    }
}

impl AgentJournalStore for FileAgentJournalStore {
    fn instance_id(&self) -> JournalStoreInstanceId {
        self.instance_id
    }

    fn finish_reverified_open(&mut self) -> Result<(), JournalStoreError> {
        self.finish_deferred_startup_recovery()
    }

    fn initialize(&mut self, sealed: &ReplaySealedGenesis) -> Result<bool, JournalStoreError> {
        self.ensure_no_gc_pending()?;
        let shape = validate_sealed_genesis_shape(sealed, self.agent, self.node)?;
        let replayed_root = sealed
            .replayed_root_identity()
            .map_err(|_| JournalStoreError::ScopeMismatch)?;
        if self
            .replayed_root
            .is_some_and(|existing| existing != replayed_root)
        {
            return Err(JournalStoreError::ScopeMismatch);
        }
        let genesis = sealed.genesis();
        let encoded = encode_object(genesis)?;
        for reference in &sealed.artifacts().artifacts {
            require_blob(self, JournalBlobClass::CatalogArtifact, reference)?;
        }
        for existing in [
            self.read_admission("genesis-admission")?,
            self.read_admission("genesis-admission.next")?,
        ]
        .into_iter()
        .flatten()
        {
            if existing != sealed.admission_commitment() {
                return Err(JournalStoreError::Conflict);
            }
        }
        for existing in [
            self.read_fixed::<AgentJournalGenesis>("", "genesis")?,
            self.read_fixed::<AgentJournalGenesis>("", "genesis.next")?,
        ]
        .into_iter()
        .flatten()
        {
            if existing != *genesis {
                return Err(JournalStoreError::Conflict);
            }
        }
        for existing in [
            self.read_fixed::<JournalHeads>("", "heads")?,
            self.read_fixed::<JournalHeads>("", "heads.next")?,
        ]
        .into_iter()
        .flatten()
        {
            if existing != shape.initial {
                return Err(JournalStoreError::Conflict);
            }
        }
        self.persist_authority(sealed.root_anchor())?;
        self.persist_authority(sealed.admission_evidence())?;
        self.persist_authority(sealed.admission_record())?;
        self.persist_admission(sealed.admission_commitment())?;
        self.persist_object(sealed.empty_frontier())?;
        self.persist_object(sealed.ordered_invocations())?;
        self.persist_object(sealed.merge_invocations())?;
        self.persist_object(&shape.local_invocations)?;
        self.persist_object(sealed.artifacts())?;
        for lane in &shape.lanes {
            self.persist_blob(
                JournalBlobClass::LaneState,
                &lane.state,
                genesis_state_component(sealed.post_create(), lane.lane),
            )?;
            self.persist_object(lane)?;
        }
        let genesis_created = persist_immutable_at(
            self.directory("")?,
            "genesis",
            &encoded.bytes,
            class_maximum(JournalStorageClass::Genesis),
            |bytes| {
                let decoded =
                    AgentJournalGenesis::decode(bytes).map_err(|_| JournalStoreError::Corrupt)?;
                decode_object::<AgentJournalGenesis>(bytes, decoded.id()).map(|_| ())
            },
        )?;
        let heads_created = self.install_initial_heads(&shape.initial)?;
        validate_head_targets(self, &shape.initial)?;
        self.replayed_root = Some(replayed_root);
        Ok(genesis_created || heads_created)
    }

    fn genesis(&self) -> Result<Option<AgentJournalGenesis>, JournalStoreError> {
        if let Some(staged) = self.read_fixed::<AgentJournalGenesis>("", "genesis.next")?
            && staged.runtime().agent != self.agent
        {
            return Err(JournalStoreError::ScopeMismatch);
        }
        let value = self.read_fixed::<AgentJournalGenesis>("", "genesis")?;
        if let Some(value) = &value
            && value.runtime().agent != self.agent
        {
            return Err(JournalStoreError::ScopeMismatch);
        }
        Ok(value)
    }

    fn heads(&self) -> Result<Option<JournalHeads>, JournalStoreError> {
        let current = self.read_fixed::<JournalHeads>("", "heads")?;
        let staged = self.read_fixed::<JournalHeads>("", "heads.next")?;
        for value in [&current, &staged].into_iter().flatten() {
            if value.node != self.node {
                return Err(JournalStoreError::ScopeMismatch);
            }
        }
        if let (Some(current), Some(staged)) = (&current, &staged) {
            current
                .validate_successor(staged)
                .map_err(|_| JournalStoreError::Corrupt)?;
        }
        Ok(current)
    }

    fn put<R: CanonicalJournalRecord>(&mut self, record: &R) -> Result<bool, JournalStoreError> {
        self.ensure_no_gc_pending()?;
        self.persist_object(record)
    }

    fn get<R: CanonicalJournalRecord>(&self, id: R::Id) -> Result<Option<R>, JournalStoreError> {
        self.read_object(id)
    }

    fn put_blob(
        &mut self,
        class: JournalBlobClass,
        reference: &BlobRef,
        bytes: &[u8],
    ) -> Result<bool, JournalStoreError> {
        self.ensure_no_gc_pending()?;
        self.persist_blob(class, reference, bytes)
    }

    fn load_blob(
        &self,
        class: JournalBlobClass,
        reference: &BlobRef,
    ) -> Result<Option<Vec<u8>>, JournalStoreError> {
        self.read_blob(class, reference)
    }

    fn publish(
        &mut self,
        publication: &ReplaySealedPublication,
    ) -> Result<JournalPublication, JournalStoreError> {
        #[cfg(not(target_os = "linux"))]
        {
            let _ = publication;
            Err(JournalStoreError::Unavailable)
        }
        #[cfg(target_os = "linux")]
        {
            self.publish_sealed_inner(publication, None, |_| Ok(()))
        }
    }
}

impl UnpublishedCatalogBlobStore for FileAgentJournalStore {
    fn stage_catalog_blob(
        &mut self,
        predecessor: JournalHeadsId,
        reference: &BlobRef,
        bytes: &[u8],
    ) -> Result<Option<UnpublishedCatalogBlob>, JournalStoreError> {
        if self.heads()?.ok_or(JournalStoreError::NotInitialized)?.id() != predecessor {
            return Err(JournalStoreError::Conflict);
        }
        self.put_blob(JournalBlobClass::CatalogArtifact, reference, bytes)
            .map(|created| {
                created.then(|| UnpublishedCatalogBlob {
                    store: self.instance_id(),
                    predecessor,
                    reference: reference.clone(),
                })
            })
    }

    fn rollback_catalog_blob(
        &mut self,
        token: UnpublishedCatalogBlob,
    ) -> Result<(), JournalStoreError> {
        self.ensure_no_gc_pending()?;
        if token.store != self.instance_id()
            || self.heads()?.ok_or(JournalStoreError::NotInitialized)?.id() != token.predecessor
        {
            return Err(JournalStoreError::Conflict);
        }
        self.read_blob(JournalBlobClass::CatalogArtifact, &token.reference)?
            .ok_or(JournalStoreError::Corrupt)?;
        let directory = self.directory(self.blob_directory(JournalBlobClass::CatalogArtifact))?;
        let name = encode_hex(token.reference.hash.as_bytes());
        unlink_file_at(directory, &name)?;
        directory
            .sync_all()
            .map_err(|_| JournalStoreError::Unavailable)
    }
}

impl SharedOrderedCommitStore for FileAgentJournalStore {
    fn shared_ordered_commit(
        &self,
        entry: OrderedEntryId,
    ) -> Result<Option<SharedOrderedCommitBinding>, JournalStoreError> {
        let binding = self.read_shared_ordered_commit_binding(entry)?;
        if let Some(binding) = &binding {
            let heads = self.heads()?.ok_or(JournalStoreError::NotInitialized)?;
            validate_shared_ordered_commit_scope(binding, &heads, self.instance_id())?;
        }
        Ok(binding)
    }

    fn persist_shared_ordered_commit(
        &mut self,
        binding: &SharedOrderedCommitBinding,
    ) -> Result<bool, JournalStoreError> {
        self.persist_shared_ordered_commit_binding(binding)
    }
}

impl SystemAuthorityHistoryStore for FileAgentJournalStore {
    fn load_system_authority_decision_node(
        &self,
        id: SystemAuthorityDecisionNodeId,
    ) -> Result<Option<SystemAuthorityDecisionNode>, JournalStoreError> {
        self.read_authority(*id.as_bytes())
    }

    fn persist_system_authority_decision_node(
        &mut self,
        node: &SystemAuthorityDecisionNode,
    ) -> Result<(), JournalStoreError> {
        self.persist_authority_with_readback(node)
    }

    fn load_system_authority_rotation_node(
        &self,
        id: SystemAuthorityRotationNodeId,
    ) -> Result<Option<SystemAuthorityRotationNode>, JournalStoreError> {
        self.read_authority(*id.as_bytes())
    }

    fn persist_system_authority_rotation_node(
        &mut self,
        node: &SystemAuthorityRotationNode,
    ) -> Result<(), JournalStoreError> {
        self.persist_authority_with_readback(node)
    }

    fn load_system_authority_catalog_node(
        &self,
        id: SystemAuthorityCatalogNodeId,
    ) -> Result<Option<SystemAuthorityCatalogNode>, JournalStoreError> {
        self.read_authority(*id.as_bytes())
    }

    fn persist_system_authority_catalog_node(
        &mut self,
        node: &SystemAuthorityCatalogNode,
    ) -> Result<(), JournalStoreError> {
        self.persist_authority_with_readback(node)
    }

    fn load_system_authority_catalog_record(
        &self,
        id: SystemAuthorityCatalogRecordId,
    ) -> Result<Option<SystemAuthorityCatalogRecord>, JournalStoreError> {
        self.read_authority(*id.as_bytes())
    }

    fn persist_system_authority_catalog_record(
        &mut self,
        record: &SystemAuthorityCatalogRecord,
    ) -> Result<(), JournalStoreError> {
        self.persist_authority_with_readback(record)
    }

    fn load_system_authority_committee_record(
        &self,
        id: SystemAuthorityCommitteeId,
    ) -> Result<Option<SystemAuthorityCommitteeRecord>, JournalStoreError> {
        self.read_authority(*id.as_bytes())
    }

    fn persist_system_authority_committee_record(
        &mut self,
        record: &SystemAuthorityCommitteeRecord,
    ) -> Result<(), JournalStoreError> {
        self.persist_authority_with_readback(record)
    }
}

impl SystemAuthorityPublicationStore for FileAgentJournalStore {
    fn publish_system_authority(
        &mut self,
        publication: &ReplaySealedPublication,
        storage: &ReplaySystemAuthorityStoragePlan,
    ) -> Result<JournalPublication, JournalStoreError> {
        #[cfg(not(target_os = "linux"))]
        {
            let _ = (publication, storage);
            Err(JournalStoreError::Unavailable)
        }
        #[cfg(target_os = "linux")]
        {
            self.publish_sealed_inner(publication, Some(storage), |_| Ok(()))
        }
    }
}

impl ReverifiedRootJournalStore for FileAgentJournalStore {
    fn replayed_root_identity(&self) -> Option<ReplayedRootJournalIdentity> {
        self.replayed_root
    }

    fn sync_unexposed_generation(&self) -> Result<(), JournalStoreError> {
        self.verify_lock()?;
        self.directories.sync("")?;
        self.directories.get("")?;
        self.verify_lock()
    }
}

impl AgentJournalGarbageCollection for FileAgentJournalStore {
    fn collect_garbage(
        &mut self,
        expected_heads: JournalHeadsId,
        limits: GcLimits,
    ) -> Result<JournalGc, JournalStoreError> {
        #[cfg(not(target_os = "linux"))]
        {
            let _ = (expected_heads, limits);
            Err(JournalStoreError::Unavailable)
        }
        #[cfg(target_os = "linux")]
        {
            self.collect_garbage_inner(expected_heads, limits, |_| Ok(()))
        }
    }
}

macro_rules! impl_invocation_index_store {
    ($store:ty) => {
        impl InvocationIndexStore for $store {
            type Error = JournalStoreError;

            fn node_limit(&self) -> usize {
                DEFAULT_INVOCATION_INDEX_NODE_LIMIT
            }

            fn load_manifest(&self, id: InvocationIndexId) -> Result<Option<Vec<u8>>, Self::Error> {
                AgentJournalStore::get::<InvocationIndexManifest>(self, id)
                    .map(|record| record.map(|record| record.encode()))
            }

            fn load_node(&self, id: InvocationIndexNodeId) -> Result<Option<Vec<u8>>, Self::Error> {
                AgentJournalStore::get::<InvocationIndexNode>(self, id)
                    .map(|record| record.map(|record| record.encode()))
            }

            fn put_manifest(
                &mut self,
                id: InvocationIndexId,
                bytes: &[u8],
            ) -> Result<(), Self::Error> {
                let manifest = decode_object::<InvocationIndexManifest>(bytes, id)?;
                AgentJournalStore::put(self, &manifest).map(|_| ())
            }

            fn put_node(
                &mut self,
                id: InvocationIndexNodeId,
                bytes: &[u8],
            ) -> Result<(), Self::Error> {
                let node = decode_object::<InvocationIndexNode>(bytes, id)?;
                AgentJournalStore::put(self, &node).map(|_| ())
            }
        }

        impl InvocationOutcomeStore for $store {
            fn load_outcome(
                &self,
                id: InvocationOutcomeId,
            ) -> Result<Option<Vec<u8>>, Self::Error> {
                AgentJournalStore::get::<InvocationOutcomeRecord>(self, id)
                    .map(|record| record.map(|record| record.encode()))
            }

            fn put_outcome(
                &mut self,
                id: InvocationOutcomeId,
                bytes: &[u8],
            ) -> Result<(), Self::Error> {
                let outcome = decode_object::<InvocationOutcomeRecord>(bytes, id)?;
                AgentJournalStore::put(self, &outcome).map(|_| ())
            }
        }
    };
}

impl_invocation_index_store!(MemoryAgentJournalStore);
impl_invocation_index_store!(FileAgentJournalStore);

macro_rules! impl_replay_source {
    ($store:ty) => {
        impl super::replay::ReplaySource for $store {
            type Error = JournalStoreError;

            fn ordered(&self, id: OrderedEntryId) -> Result<Option<OrderedEntry>, Self::Error> {
                AgentJournalStore::get(self, id)
            }

            fn local(&self, id: LocalEntryId) -> Result<Option<LocalEntry>, Self::Error> {
                AgentJournalStore::get(self, id)
            }

            fn merge_event(&self, id: MergeEventId) -> Result<Option<MergeEvent>, Self::Error> {
                AgentJournalStore::get(self, id)
            }

            fn merge_frontier(
                &self,
                id: MergeFrontierId,
            ) -> Result<Option<MergeFrontier>, Self::Error> {
                AgentJournalStore::get(self, id)
            }

            fn merge_seal(&self, id: MergeSealId) -> Result<Option<MergeSeal>, Self::Error> {
                AgentJournalStore::get(self, id)
            }

            fn lane_state(
                &self,
                id: LaneStateId,
            ) -> Result<Option<LaneStateManifest>, Self::Error> {
                AgentJournalStore::get(self, id)
            }

            fn checkpoint(
                &self,
                id: CheckpointId,
            ) -> Result<Option<CheckpointManifest>, Self::Error> {
                AgentJournalStore::get(self, id)
            }

            fn artifact_closure(
                &self,
                id: super::journal::ArtifactClosureId,
            ) -> Result<Option<ArtifactClosure>, Self::Error> {
                AgentJournalStore::get(self, id)
            }

            fn invocation_index(
                &self,
                id: InvocationIndexId,
            ) -> Result<Option<InvocationIndexManifest>, Self::Error> {
                AgentJournalStore::get(self, id)
            }
        }
    };
}

impl_replay_source!(MemoryAgentJournalStore);
impl_replay_source!(FileAgentJournalStore);

#[cfg(test)]
#[allow(clippy::items_after_test_module)]
mod tests {
    use std::sync::atomic::{AtomicU64, Ordering};

    use ed25519_dalek::{Signer as _, SigningKey};

    use super::*;
    use crate::agent::authority::{
        ActorInvocationClaim, ActorInvocationReceipt, AgentAuthorityBinding, AgentAuthorityClaim,
        AgentAuthorityReceipt, ED25519_SIGNATURE_BYTES, ed25519_public_key_wire,
    };
    use crate::agent::catalog_finality::{
        CatalogBinding, CatalogMutation, CatalogMutationDisposition, CatalogMutationIntent,
        CatalogMutationKind, CatalogMutationResult, FinalizedCatalogMutationFact,
        FinalizedCatalogMutationReceipt,
    };
    use crate::agent::committee::{
        AuthorityClaimCommitment, AuthorityClaimDomain, AuthorityCommittee,
        AuthorityCommitteeMember, AuthorityMemberRole, AuthorityQuorumCertificate,
        AuthoritySignature, AuthoritySignerId, RootAnchorConfigCommitment, RootAnchorId,
    };
    use crate::agent::contract::RuntimePackageContract;
    use crate::agent::execution::{
        ActorExecutionReply, ActorExecutionStatus, ActorInvocation, ActorInvocationAuth,
        ActorObservation,
    };
    use crate::agent::genesis::{
        AgentGenesisAdmissionId, AgentGenesisDecisionId, AgentGenesisEvidenceId,
        AgentReplicaCommitteeId,
    };
    use crate::agent::invocation_index::{InvocationIndex, InvocationIndexLookup};
    use crate::agent::journal::{
        ArtifactClosureId, CheckpointLane, InvocationAcknowledgedFact, InvocationDisposition,
        InvocationOutcomeAnchor, InvocationOutcomeRecord, InvocationOwner, InvocationOwnershipKey,
        InvocationResultState, ReplayInput, ReplayOperation, RuntimeBinding,
    };
    use crate::agent::shared_commit::SharedLaneProjection;
    use crate::agent::system_authority::{
        SystemAuthorityCatalogFinalize, SystemAuthorityCatalogProof, SystemAuthorityGenesis,
        SystemAuthorityJournalScope, SystemAuthorityState,
    };
    use crate::agent::{
        AgentConfig, AgentIdentity, AgentProfile, AgentReplica, LaneSet,
        LifecycleAuthorityAdmission, LifecycleRequest, MethodMode, ReplicaRole,
        RuntimeCapabilities,
    };
    use crate::service::{
        ActorId, CapabilityId, CredentialId, DeploymentId, InvocationId, OperationId, PrincipalId,
        ProducerId, ProgramId, SpaceId,
    };

    static NEXT_TEST_DIRECTORY: AtomicU64 = AtomicU64::new(0);

    struct TestDirectory(PathBuf);

    impl TestDirectory {
        fn new(label: &str) -> Self {
            let sequence = NEXT_TEST_DIRECTORY.fetch_add(1, Ordering::Relaxed);
            let path = std::env::temp_dir().join(format!(
                "vos-agent-journal-{label}-{}-{sequence}",
                std::process::id()
            ));
            fs::create_dir(&path).unwrap();
            Self(path)
        }

        fn agent_root(&self, agent: AgentId) -> PathBuf {
            self.0
                .join(format!("{}.agent", encode_hex(agent.as_bytes())))
        }

        fn lock(&self, agent: AgentId) -> PathBuf {
            self.agent_root(agent).with_extension("agent-lock")
        }
    }

    impl Drop for TestDirectory {
        fn drop(&mut self) {
            let _ = fs::remove_dir_all(&self.0);
        }
    }

    fn authority_binding() -> AgentAuthorityBinding {
        let public_key = ed25519_public_key_wire([0x41; 32]);
        AgentAuthorityBinding {
            agent: AgentId([0xa1; 32]),
            actor: ActorId([0xa2; 32]),
            deployment: DeploymentId([0xa3; 32]),
            program: ProgramId([0xa4; 32]),
            producer: ProducerId::of_public_key(&public_key),
            public_key,
        }
    }

    fn config() -> AgentConfig {
        let space = SpaceId([1; 32]);
        let owner = PrincipalId([2; 32]);
        let creation_nonce = Hash([3; 32]);
        let agent = AgentId::derive(space, owner, creation_nonce.as_bytes());
        AgentConfig {
            identity: AgentIdentity {
                space,
                agent,
                owner,
                profile: AgentProfile::Local,
                runtime_deployment: DeploymentId([4; 32]),
                runtime_program: ProgramId([5; 32]),
                runtime_producer: ProducerId([6; 32]),
            },
            creation_nonce,
            authority: authority_binding(),
            system_authority_genesis: None,
            runtime_package: BlobRef::of_bytes(b"runtime-package"),
            runtime_contract: RuntimePackageContract::canonical(),
            capabilities: RuntimeCapabilities {
                lanes: LaneSet::ALL,
                scheduling: false,
                proofs: false,
                max_actors: 4096,
            },
            replicas: vec![AgentReplica {
                node: NodeId([7; 32]),
                principal: owner,
                role: ReplicaRole::Voter,
            }],
        }
    }

    fn runtime_binding() -> RuntimeBinding {
        let config = config();
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

    fn create_input() -> ReplayInput {
        let runtime = runtime_binding();
        let inner = LifecycleRequest::Create(config());
        let claim = AgentAuthorityClaim {
            authority: authority_binding(),
            space: runtime.space,
            agent: runtime.agent,
            principal: config().identity.owner,
            credential: CredentialId([8; 32]),
            capability: CapabilityId::named("agent.create.local"),
            operation: inner.commitment(),
            sequence: 1,
            valid_from: 10,
            valid_until: 20,
        };
        ReplayInput {
            runtime,
            operation: ReplayOperation::Management {
                request: LifecycleRequest::Authorized {
                    admission: LifecycleAuthorityAdmission {
                        receipt: AgentAuthorityReceipt {
                            claim,
                            signature: vec![9; ED25519_SIGNATURE_BYTES],
                        },
                        observed_slot: 15,
                    },
                    request: Box::new(inner),
                },
            },
        }
    }

    fn genesis() -> AgentJournalGenesis {
        AgentJournalGenesis {
            admission: AgentGenesisAdmissionId::from_bytes([0xf4; 32]),
            create: create_input(),
        }
    }

    fn phase_one_system_authorized_admission() -> AgentGenesisAdmissionRecord {
        AgentGenesisAdmissionRecord::SystemAuthorized {
            decision: AgentGenesisDecisionId::from_bytes([0x31; 32]),
            evidence: AgentGenesisEvidenceId::from_bytes([0x32; 32]),
            replicas: AgentReplicaCommitteeId::from_bytes([0x33; 32]),
            claim: AuthorityClaimCommitment::of_bytes(
                AuthorityClaimDomain::AgentGenesis,
                1,
                b"pending live-system finalization proof",
            ),
        }
    }

    fn invocation(mode: MethodMode, discriminator: u8) -> ActorInvocation {
        ActorInvocation {
            invocation: InvocationId([discriminator; 32]),
            actor: ActorId([0x12; 32]),
            incarnation: Hash([0x11; 32]),
            deployment: DeploymentId([0x13; 32]),
            program: ProgramId([0x14; 32]),
            mode,
            auth: ActorInvocationAuth::anonymous(),
            message: vec![1, 2, discriminator],
            availability: Vec::new(),
            gas: 1_000,
        }
    }

    fn invocation_receipt(invocation: &ActorInvocation) -> ActorInvocationReceipt {
        let runtime = runtime_binding();
        ActorInvocationReceipt {
            claim: ActorInvocationClaim {
                authority: authority_binding(),
                space: runtime.space,
                agent: runtime.agent,
                principal: None,
                credential: None,
                authorization: invocation.authorization_message(),
                auth: invocation.auth.clone(),
                valid_from: 10,
                valid_until: 20,
            },
            signature: vec![0x22; ED25519_SIGNATURE_BYTES],
        }
    }

    fn replay_input(mode: MethodMode, discriminator: u8) -> ReplayInput {
        let invocation = invocation(mode, discriminator);
        let authority = invocation_receipt(&invocation);
        ReplayInput {
            runtime: runtime_binding(),
            operation: ReplayOperation::Invoke {
                invocation,
                authority,
                observed_slot: 15,
            },
        }
    }

    fn management_input(discriminator: u8) -> ReplayInput {
        let runtime = runtime_binding();
        let inner = LifecycleRequest::Suspend {
            actor: ActorId([discriminator; 32]),
            expected_deployment: DeploymentId([discriminator.wrapping_add(1); 32]),
        };
        let claim = AgentAuthorityClaim {
            authority: authority_binding(),
            space: runtime.space,
            agent: runtime.agent,
            principal: config().identity.owner,
            credential: CredentialId([discriminator.wrapping_add(2); 32]),
            capability: CapabilityId::named("actor.lifecycle"),
            operation: inner.commitment(),
            sequence: discriminator as u64 + 1,
            valid_from: 10,
            valid_until: 20,
        };
        ReplayInput {
            runtime,
            operation: ReplayOperation::Management {
                request: LifecycleRequest::Authorized {
                    admission: LifecycleAuthorityAdmission {
                        receipt: AgentAuthorityReceipt {
                            claim,
                            signature: vec![discriminator; ED25519_SIGNATURE_BYTES],
                        },
                        observed_slot: 15,
                    },
                    request: Box::new(inner),
                },
            },
        }
    }

    trait RawTestInitialize {
        fn initialize_raw(
            &mut self,
            genesis: &AgentJournalGenesis,
        ) -> Result<bool, JournalStoreError>;
    }

    trait RawTestPublish: AgentJournalStore {
        fn publish_raw<R: CanonicalJournalRecord>(
            &mut self,
            expected: JournalHeadsId,
            anchor: &R,
            next: &JournalHeads,
        ) -> Result<JournalPublication, JournalStoreError>;
    }

    impl RawTestPublish for MemoryAgentJournalStore {
        fn publish_raw<R: CanonicalJournalRecord>(
            &mut self,
            expected: JournalHeadsId,
            anchor: &R,
            next: &JournalHeads,
        ) -> Result<JournalPublication, JournalStoreError> {
            self.publish_anchor(expected, anchor, next)
        }
    }

    impl RawTestPublish for FileAgentJournalStore {
        fn publish_raw<R: CanonicalJournalRecord>(
            &mut self,
            expected: JournalHeadsId,
            anchor: &R,
            next: &JournalHeads,
        ) -> Result<JournalPublication, JournalStoreError> {
            self.publish_anchor(expected, anchor, next)
        }
    }

    impl RawTestInitialize for MemoryAgentJournalStore {
        fn initialize_raw(
            &mut self,
            genesis: &AgentJournalGenesis,
        ) -> Result<bool, JournalStoreError> {
            self.initialize_raw_for_test(genesis)
        }
    }

    impl RawTestInitialize for FileAgentJournalStore {
        fn initialize_raw(
            &mut self,
            genesis: &AgentJournalGenesis,
        ) -> Result<bool, JournalStoreError> {
            self.initialize_raw_for_test(genesis)
        }
    }

    fn initialize<S: AgentJournalStore + RawTestInitialize>(
        store: &mut S,
        genesis: &AgentJournalGenesis,
    ) {
        store
            .put_blob(
                JournalBlobClass::CatalogArtifact,
                &genesis.runtime().package,
                b"runtime-package",
            )
            .unwrap();
        assert!(store.initialize_raw(genesis).unwrap());
    }

    fn gc_limits() -> GcLimits {
        GcLimits {
            max_index_nodes: DEFAULT_INVOCATION_INDEX_NODE_LIMIT,
            max_marked_objects: 10_000,
            max_marked_blobs: 10_000,
            max_scanned_files: 10_000,
            max_scanned_bytes: 64 * 1024 * 1024,
            max_unlinks_per_run: 10_000,
        }
    }

    fn install_fresh_checkpoint<S>(
        store: &mut S,
        genesis: &AgentJournalGenesis,
    ) -> (JournalHeads, CheckpointManifest)
    where
        S: AgentJournalStore + RawTestPublish,
    {
        let heads = store.heads().unwrap().unwrap();
        let state_bytes = b"gc-checkpoint-state";
        let state = BlobRef::of_bytes(state_bytes);
        store
            .put_blob(JournalBlobClass::LaneState, &state, state_bytes)
            .unwrap();
        let lanes = [
            (
                PersistedLane::Control,
                LaneCursor::Ordered {
                    base: ordered_base(&heads),
                },
            ),
            (
                PersistedLane::Linear,
                LaneCursor::Ordered {
                    base: ordered_base(&heads),
                },
            ),
            (
                PersistedLane::Merge,
                LaneCursor::Merge {
                    frontier: heads.merge_frontier,
                },
            ),
            (
                PersistedLane::Local,
                LaneCursor::Local {
                    node: heads.node,
                    revision: heads.local_revision,
                    head: heads.local_head,
                },
            ),
        ]
        .map(|(lane, cursor)| {
            let manifest = LaneStateManifest {
                genesis: genesis.id(),
                runtime: heads.runtime.clone(),
                lane,
                cursor,
                state: state.clone(),
            };
            store.put(&manifest).unwrap();
            manifest
        });
        let artifacts = ArtifactClosure {
            genesis: genesis.id(),
            artifacts: vec![genesis.runtime().package.clone()],
        };
        store.put(&artifacts).unwrap();
        let checkpoint = CheckpointManifest {
            genesis: genesis.id(),
            admission: genesis.admission,
            runtime: heads.runtime.clone(),
            publication_revision: heads.publication_revision,
            ordered_head: heads.ordered_head,
            ordered_index: heads.ordered_index,
            merge_frontier: heads.merge_frontier,
            merge_fence: heads.merge_fence,
            merge_seal: heads.merge_seal,
            ordered_invocations: heads.ordered_invocations,
            merge_invocations: heads.merge_invocations,
            lanes: vec![
                CheckpointLane {
                    lane: PersistedLane::Control,
                    node: None,
                    state: lanes[0].id(),
                    invocations: None,
                },
                CheckpointLane {
                    lane: PersistedLane::Linear,
                    node: None,
                    state: lanes[1].id(),
                    invocations: None,
                },
                CheckpointLane {
                    lane: PersistedLane::Merge,
                    node: None,
                    state: lanes[2].id(),
                    invocations: None,
                },
                CheckpointLane {
                    lane: PersistedLane::Local,
                    node: Some(heads.node),
                    state: lanes[3].id(),
                    invocations: Some(heads.local_invocations),
                },
            ],
            artifacts: artifacts.id(),
        };
        let next = JournalHeads {
            publication_revision: heads.publication_revision + 1,
            previous: Some(heads.id()),
            checkpoint: Some(checkpoint.id()),
            ..heads
        };
        store
            .publish_raw(next.previous.unwrap(), &checkpoint, &next)
            .unwrap();
        (next, checkpoint)
    }

    fn first_ordered(genesis: &AgentJournalGenesis, heads: &JournalHeads) -> OrderedEntry {
        OrderedEntry {
            genesis: genesis.id(),
            index: 1,
            parent: None,
            merge_frontier: heads.merge_frontier,
            merge_seal: None,
            input: replay_input(MethodMode::Linear, 0x31),
        }
    }

    fn ordered_successor(heads: &JournalHeads, entry: &OrderedEntry) -> JournalHeads {
        JournalHeads {
            publication_revision: heads.publication_revision + 1,
            previous: Some(heads.id()),
            ordered_head: Some(entry.id()),
            ordered_index: entry.index,
            ..heads.clone()
        }
    }

    fn shared_ordered_binding(
        genesis: &AgentJournalGenesis,
        heads: &JournalHeads,
        entry: &OrderedEntry,
        journal_store: JournalStoreInstanceId,
    ) -> SharedOrderedCommitBinding {
        let merge = SharedLaneProjection::new(
            LaneStateId([0xd1; 32]),
            BlobRef::of_bytes(b"shared merge projection"),
        )
        .unwrap();
        let control = SharedLaneProjection::new(
            LaneStateId([0xd2; 32]),
            BlobRef::of_bytes(b"shared control projection"),
        )
        .unwrap();
        let linear = SharedLaneProjection::new(
            LaneStateId([0xd3; 32]),
            BlobRef::of_bytes(b"shared linear projection"),
        )
        .unwrap();
        let claim = OrderedCommitClaim::new(
            genesis.id(),
            genesis.admission,
            AgentReplicaCommitteeId::from_bytes([0xd4; 32]),
            entry.index,
            1,
            OrderedBase {
                index: entry.index,
                head: Some(entry.id()),
            },
            entry.merge_frontier,
            merge,
            heads.merge_invocations,
            heads.runtime.clone(),
            control,
            linear,
            heads.ordered_invocations,
            ArtifactClosureId([0xd5; 32]),
            heads.merge_fence,
            None,
            Hash([0xd6; 32]),
        )
        .unwrap();
        SharedOrderedCommitBinding::new(journal_store, entry.id(), claim, Hash([0xd7; 32])).unwrap()
    }

    #[derive(Clone)]
    struct PreparedHistoryTransition {
        entry: OrderedEntry,
        next: JournalHeads,
        plan: InvocationHistoryWritePlan,
        key: InvocationOwnershipKey,
        fact: InvocationAcknowledgedFact,
    }

    fn prepare_history_transition<S>(
        store: &mut S,
        genesis: &AgentJournalGenesis,
        current: &JournalHeads,
        discriminator: u8,
    ) -> PreparedHistoryTransition
    where
        S: AgentJournalStore + InvocationIndexStore<Error = JournalStoreError>,
    {
        let input = replay_input(MethodMode::Linear, discriminator);
        let ReplayOperation::Invoke { invocation, .. } = &input.operation else {
            unreachable!()
        };
        let entry = OrderedEntry {
            genesis: genesis.id(),
            index: current.ordered_index.checked_add(1).unwrap(),
            parent: current.ordered_head,
            merge_frontier: current.merge_frontier,
            merge_seal: None,
            input: input.clone(),
        };
        let key = InvocationOwnershipKey {
            scope: InvocationOwnershipScope::Ordered,
            invocation: invocation.invocation,
        };
        let outcome = InvocationOutcomeRecord::from_runtime_states(
            genesis.id(),
            key.scope,
            InvocationOutcomeAnchor::Ordered { entry: entry.id() },
            &input,
            &RuntimeState::default(),
            &RuntimeState::default(),
            Ok(ActorExecutionReply {
                invocation: invocation.invocation,
                actor: invocation.actor,
                incarnation: invocation.incarnation,
                deployment: invocation.deployment,
                mode: invocation.mode,
                lane: invocation.mode.write_lane(),
                status: ActorExecutionStatus::Done,
                reply: vec![discriminator],
                gas_remaining: invocation.gas - 1,
                observation: ActorObservation::default(),
            }),
        )
        .unwrap();
        let mut index = InvocationIndex::open(store, current.ordered_invocations).unwrap();
        let outcome = index.persist_outcome(&outcome).unwrap();
        let owner = InvocationOwner {
            scope: key.scope,
            request_commitment: invocation.commitment(),
            first_input: input.id(),
            lane: PersistedLane::Linear,
            node: None,
            result_state: InvocationResultState::Retained {
                disposition: InvocationDisposition::Applied,
                outcome,
            },
        };
        index.record(key, owner).unwrap();
        index.archive(key, owner).unwrap();
        let ordered_invocations = index.id();
        let plan = index.history_write_plan().clone();
        let fact = InvocationAcknowledgedFact::from_owner(genesis.id(), key, owner).unwrap();
        drop(index);
        let next = JournalHeads {
            ordered_invocations,
            ..ordered_successor(current, &entry)
        };
        PreparedHistoryTransition {
            entry,
            next,
            plan,
            key,
            fact,
        }
    }

    fn build_test_history_candidate<S: AgentJournalStore>(
        store: &S,
        current: &JournalHeads,
        transition: &PreparedHistoryTransition,
        queue: &HistoryRetirementQueue,
    ) -> HistoryCandidateOverlay {
        build_history_candidate(
            store,
            current,
            &transition.next,
            core::slice::from_ref(&transition.plan),
            queue,
        )
        .unwrap()
        .unwrap()
    }

    fn saturated_history_queue(
        genesis: AgentJournalGenesisId,
        node: NodeId,
        tail: HistoryRoots,
    ) -> HistoryRetirementQueue {
        let alternate = HistoryRoots {
            ordered: Some(InvocationHistoryNodeId([0xe1; 32])),
            merge: tail.merge,
            local: tail.local,
        };
        assert_ne!(alternate, tail);
        let mut roots = tail;
        let mut records = Vec::new();
        for index in 0..MAX_HISTORY_RETIREMENT_PUBLICATIONS {
            let next_roots = if roots == tail { alternate } else { tail };
            records.push(HistoryRetirementRecord {
                expected_heads: JournalHeadsId([(index as u8).wrapping_add(1); 32]),
                next_heads: JournalHeadsId([(index as u8).wrapping_add(2); 32]),
                publication_revision: index as u64 + 1,
                expected_roots: roots,
                next_roots,
                retired_node_ids: Vec::new(),
                retired_cursor: 0,
            });
            roots = next_roots;
        }
        assert_eq!(roots, tail);
        let queue = HistoryRetirementQueue {
            genesis,
            node,
            records,
        };
        queue.validate().unwrap();
        queue
    }

    fn open_file_store(directory: &TestDirectory) -> FileAgentJournalStore {
        let config = config();
        FileAgentJournalStore::open_unverified_for_test(
            directory.agent_root(config.identity.agent),
            directory.lock(config.identity.agent),
            config.replicas[0].node,
        )
        .unwrap()
    }

    #[cfg(all(target_os = "linux", feature = "storage"))]
    fn acquire_system_authority_slot(
        directory: &TestDirectory,
        sealed: &ReplaySealedGenesis,
    ) -> FileAgentJournalSlot {
        let agent = sealed.genesis().runtime().agent;
        FileAgentJournalSlot::acquire(
            directory.agent_root(agent),
            directory.lock(agent),
            sealed.replica().node,
        )
        .unwrap()
    }

    #[cfg(all(target_os = "linux", feature = "storage"))]
    fn system_authority_ledger_paths(
        directory: &TestDirectory,
        agent: AgentId,
    ) -> (PathBuf, PathBuf) {
        let canonical = directory.0.join(system_authority_ledger_file_name(agent));
        let staged = PathBuf::from(format!("{}.next", canonical.display()));
        (canonical, staged)
    }

    #[cfg(all(target_os = "linux", feature = "storage"))]
    fn open_system_authority_owner_for_mode(
        _slot: &FileAgentJournalSlot,
        ledger: FileSystemAuthorityLedger,
        sealed: &ReplaySealedGenesis,
    ) -> OpenedFileSystemAuthorityLedgerOwner {
        SystemAuthorityLedgerRouteOwner::open_file(ledger.into_owner_open(), sealed).unwrap()
    }

    #[cfg(all(target_os = "linux", feature = "storage"))]
    fn bind_system_authority_ledger(
        slot: &FileAgentJournalSlot,
        sealed: &ReplaySealedGenesis,
    ) -> BoundFileSystemAuthorityLedgerOwner {
        let ledger = slot.open_system_authority_ledger().unwrap();
        let owner = open_system_authority_owner_for_mode(slot, ledger, sealed);
        slot.bind_system_authority_ledger_owner(owner, sealed)
            .unwrap()
    }

    #[cfg(all(target_os = "linux", feature = "storage"))]
    fn initialize_unexposed_system_authority_slot(
        slot: FileAgentJournalSlot,
        bound: &BoundFileSystemAuthorityLedgerOwner,
        sealed: &ReplaySealedGenesis,
    ) -> FileAgentJournalStore {
        let mut store = bound
            .with_startup_root_recovery(|startup| slot.open_reverified(sealed, startup, false))
            .unwrap()
            .unwrap();
        bound
            .with_unexposed_journal_initialization(sealed.genesis().id(), || {
                let package_bytes = b"replay-runtime-package";
                if sealed.artifacts().artifacts != vec![BlobRef::of_bytes(package_bytes)] {
                    return Err(JournalStoreError::Corrupt);
                }
                store.put_blob(
                    JournalBlobClass::CatalogArtifact,
                    &sealed.genesis().runtime().package,
                    package_bytes,
                )?;
                if !store.initialize(sealed)? {
                    return Err(JournalStoreError::Corrupt);
                }
                Ok(())
            })
            .unwrap()
            .unwrap();
        store
    }

    #[cfg(all(target_os = "linux", feature = "storage"))]
    fn initialize_system_authority_slot_without_exposure_marker(
        directory: &TestDirectory,
        sealed: &ReplaySealedGenesis,
    ) -> PathBuf {
        let slot = acquire_system_authority_slot(directory, sealed);
        let bound = bind_system_authority_ledger(&slot, sealed);
        let mut store = bound
            .with_startup_root_recovery(|startup| slot.open_reverified(sealed, startup, false))
            .unwrap()
            .unwrap();
        let package_bytes = b"replay-runtime-package";
        store
            .put_blob(
                JournalBlobClass::CatalogArtifact,
                &sealed.genesis().runtime().package,
                package_bytes,
            )
            .unwrap();
        assert!(store.initialize(sealed).unwrap());
        assert!(!bound.journal_exposure_is_committed().unwrap());
        let root = store.root().to_path_buf();
        drop(store);
        drop(bound);
        root
    }

    #[cfg(all(target_os = "linux", feature = "storage"))]
    fn snapshot_file_tree(root: &Path) -> Vec<(PathBuf, Option<Vec<u8>>)> {
        fn walk(root: &Path, directory: &Path, output: &mut Vec<(PathBuf, Option<Vec<u8>>)>) {
            let mut entries = fs::read_dir(directory)
                .unwrap()
                .map(|entry| entry.unwrap())
                .collect::<Vec<_>>();
            entries.sort_by_key(|entry| entry.file_name());
            for entry in entries {
                let path = entry.path();
                let relative = path.strip_prefix(root).unwrap().to_path_buf();
                let file_type = entry.file_type().unwrap();
                if file_type.is_dir() {
                    output.push((relative, None));
                    walk(root, &path, output);
                } else if file_type.is_file() {
                    output.push((relative, Some(fs::read(path).unwrap())));
                } else {
                    panic!("unexpected test namespace entry");
                }
            }
        }

        let mut output = Vec::new();
        walk(root, root, &mut output);
        output
    }

    #[cfg(all(target_os = "linux", feature = "storage"))]
    fn retain_root_files(root: &Path, retained: &[&str]) {
        for entry in fs::read_dir(root).unwrap() {
            let entry = entry.unwrap();
            if retained
                .iter()
                .any(|name| entry.file_name() == std::ffi::OsStr::new(name))
            {
                continue;
            }
            let path = entry.path();
            if entry.file_type().unwrap().is_dir() {
                fs::remove_dir_all(path).unwrap();
            } else {
                fs::remove_file(path).unwrap();
            }
        }
    }

    fn open_file_store_for_sealed(
        directory: &TestDirectory,
        sealed: &ReplaySealedGenesis,
    ) -> FileAgentJournalStore {
        FileAgentJournalStore::open(
            directory.agent_root(sealed.genesis().runtime().agent),
            directory.lock(sealed.genesis().runtime().agent),
            sealed.replica().node,
        )
        .unwrap()
    }

    fn reopen_file_store_reverified(
        directory: &TestDirectory,
        sealed: &ReplaySealedGenesis,
    ) -> Result<FileAgentJournalStore, JournalStoreError> {
        FileAgentJournalStore::open_reverified(
            directory.agent_root(sealed.genesis().runtime().agent),
            directory.lock(sealed.genesis().runtime().agent),
            sealed.replica().node,
            sealed,
        )
    }

    #[cfg(target_os = "linux")]
    fn history_node_path(root: &Path, id: InvocationHistoryNodeId) -> PathBuf {
        root.join(HISTORY_NODES_DIRECTORY)
            .join(format!("{:02x}", id.as_bytes()[0]))
            .join(encode_hex(id.as_bytes()))
    }

    #[cfg(target_os = "linux")]
    fn commit_file_history_transition(
        store: &mut FileAgentJournalStore,
        genesis: &AgentJournalGenesis,
        discriminator: u8,
    ) -> PreparedHistoryTransition {
        let current = store.heads().unwrap().unwrap();
        let transition = prepare_history_transition(store, genesis, &current, discriminator);
        let queue = store.history_queue(genesis.id()).unwrap();
        let history = build_test_history_candidate(store, &current, &transition, &queue);
        store
            .stage_history_candidate(history, &mut |_| Ok(()))
            .unwrap();
        store
            .publish_inner(
                current.id(),
                &transition.entry,
                &transition.next,
                |_| Ok(()),
            )
            .unwrap();
        store.finish_history_candidate(&mut |_| Ok(())).unwrap();
        transition
    }

    fn initialize_sealed_file_store(
        store: &mut FileAgentJournalStore,
        sealed: &ReplaySealedGenesis,
    ) {
        let package_bytes = b"replay-runtime-package";
        assert_eq!(
            sealed.artifacts().artifacts,
            vec![BlobRef::of_bytes(package_bytes)]
        );
        store
            .put_blob(
                JournalBlobClass::CatalogArtifact,
                &sealed.genesis().runtime().package,
                package_bytes,
            )
            .unwrap();
        assert!(store.initialize(sealed).unwrap());
    }

    fn authority_paths(
        root: &Path,
        sealed: &ReplaySealedGenesis,
    ) -> [(AuthorityStorageClass, PathBuf); 3] {
        [
            (
                AuthorityStorageClass::RootAnchor,
                root.join("authority/root-anchors")
                    .join(encode_hex(sealed.root_anchor().id().as_bytes())),
            ),
            (
                AuthorityStorageClass::GenesisEvidence,
                root.join("authority/genesis-evidence")
                    .join(encode_hex(sealed.admission_evidence().id().as_bytes())),
            ),
            (
                AuthorityStorageClass::GenesisAdmission,
                root.join("authority/genesis-admissions")
                    .join(encode_hex(sealed.admission_record().id().as_bytes())),
            ),
        ]
    }

    fn system_authority_history_fixture() -> (
        SystemAuthorityDecisionNode,
        SystemAuthorityRotationNode,
        SystemAuthorityCommitteeRecord,
    ) {
        let decision = SystemAuthorityDecisionNode::Branch {
            depth: 7,
            left: SystemAuthorityDecisionNodeId::from_bytes([0x41; 32]),
            right: SystemAuthorityDecisionNodeId::from_bytes([0x42; 32]),
        };
        let rotation = SystemAuthorityRotationNode::Branch {
            depth: 3,
            left: SystemAuthorityRotationNodeId::from_bytes([0x51; 32]),
            right: SystemAuthorityRotationNodeId::from_bytes([0x52; 32]),
        };
        let member = AuthorityCommitteeMember::new(
            NodeId([0x61; 32]),
            [0x62; 32],
            AuthorityMemberRole::Voter,
        )
        .unwrap();
        let committee =
            AuthorityCommittee::new(SpaceId([0x63; 32]), Hash([0x64; 32]), 1, None, vec![member])
                .unwrap();
        let committee = SystemAuthorityCommitteeRecord::new(committee).unwrap();
        (decision, rotation, committee)
    }

    fn system_authority_catalog_keys() -> Vec<SigningKey> {
        (0x31_u8..=0x33)
            .map(|byte| SigningKey::from_bytes(&[byte; 32]))
            .collect()
    }

    fn system_authority_catalog_committee(
        binding: CatalogBinding,
        keys: &[SigningKey],
    ) -> AuthorityCommittee {
        let mut members = keys
            .iter()
            .enumerate()
            .map(|(index, key)| {
                AuthorityCommitteeMember::new(
                    NodeId([(0x90_u8).wrapping_add(index as u8); 32]),
                    key.verifying_key().to_bytes(),
                    AuthorityMemberRole::Voter,
                )
                .unwrap()
            })
            .collect::<Vec<_>>();
        members.sort_by_key(AuthorityCommitteeMember::signer);
        AuthorityCommittee::new(
            binding.space(),
            binding.authority_binding(),
            1,
            None,
            members,
        )
        .unwrap()
    }

    #[allow(clippy::too_many_arguments)]
    fn system_authority_catalog_receipt(
        binding: CatalogBinding,
        committee: &AuthorityCommittee,
        keys: &[SigningKey],
        operation: OperationId,
        expected_authority_generation: Hash,
        expected_catalog_head: Hash,
        actual_authority_generation: Hash,
        actual_catalog_head: Hash,
        sequence: u64,
        mutation_byte: u8,
    ) -> FinalizedCatalogMutationReceipt {
        let intent = CatalogMutationIntent::new(
            binding,
            expected_authority_generation,
            expected_catalog_head,
            PrincipalId([0x79; 32]),
            CredentialId([0x7a; 32]),
            CapabilityId([0x7b; 32]),
            operation,
            CatalogMutation::new(CatalogMutationKind::UpdateMetadata, vec![mutation_byte; 8])
                .unwrap(),
        )
        .unwrap();
        let fact = FinalizedCatalogMutationFact::new(
            intent,
            actual_authority_generation,
            actual_catalog_head,
            CatalogMutationResult::new(
                CatalogMutationDisposition::Applied,
                vec![mutation_byte.wrapping_add(1); 8],
            )
            .unwrap(),
            sequence,
        )
        .unwrap();
        let message = AuthorityQuorumCertificate::signing_message(
            committee.authority_binding(),
            committee.epoch(),
            committee.commitment(),
            fact.authority_claim(),
        );
        let mut signatures = keys
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
        FinalizedCatalogMutationReceipt::new(fact, certificate, binding, committee).unwrap()
    }

    fn system_authority_catalog_fixture()
    -> (SystemAuthorityCatalogRecord, SystemAuthorityCatalogNode) {
        let binding = CatalogBinding::new(
            SpaceId([0x75; 32]),
            Hash([0x76; 32]),
            authority_binding().commitment(),
        )
        .unwrap();
        let keys = system_authority_catalog_keys();
        let committee = system_authority_catalog_committee(binding, &keys);
        let receipt = system_authority_catalog_receipt(
            binding,
            &committee,
            &keys,
            OperationId([0x7c; 32]),
            Hash([0x77; 32]),
            Hash([0x78; 32]),
            Hash([0x77; 32]),
            Hash([0x78; 32]),
            2,
            0x7d,
        );
        let record = SystemAuthorityCatalogRecord::new(receipt, binding, &committee).unwrap();
        let node = SystemAuthorityCatalogNode::Leaf(record.clone());
        (record, node)
    }

    fn system_authority_catalog_state_fixture() -> (
        SystemAuthorityState,
        SystemAuthorityJournalScope,
        AuthorityCommittee,
        Vec<SigningKey>,
    ) {
        let binding = CatalogBinding::new(
            SpaceId([0x75; 32]),
            Hash([0x76; 32]),
            authority_binding().commitment(),
        )
        .unwrap();
        let keys = system_authority_catalog_keys();
        let committee = system_authority_catalog_committee(binding, &keys);
        let genesis = SystemAuthorityGenesis::new(
            RootAnchorId::from_bytes([0x81; 32]),
            1,
            RootAnchorConfigCommitment::from_bytes([0x82; 32]),
            committee.clone(),
            1,
            binding.catalog_binding(),
            Hash([0x83; 32]),
            16,
            16,
            16,
        )
        .unwrap();
        let state = SystemAuthorityState::from_genesis(AgentId([0x84; 32]), &genesis).unwrap();
        let scope = SystemAuthorityJournalScope::for_test(
            AgentJournalGenesisId::new([0x85; 32]),
            AgentGenesisAdmissionId::from_bytes([0x86; 32]),
        )
        .unwrap();
        (state, scope, committee, keys)
    }

    #[cfg(target_os = "linux")]
    fn system_authority_history_path(root: &Path, directory: &str, id: &[u8; 32]) -> PathBuf {
        root.join(directory).join(encode_hex(id))
    }

    #[cfg(target_os = "linux")]
    const fn system_authority_history_scrub_limits() -> SystemAuthorityHistoryScrubLimits {
        SystemAuthorityHistoryScrubLimits {
            max_namespace_entries: 64,
            max_file_reads: 64,
            max_bytes_read: 4 * 1024 * 1024,
        }
    }

    #[test]
    fn memory_system_authority_history_is_typed_bounded_and_content_addressed() {
        let config = config();
        let mut store =
            MemoryAgentJournalStore::new(config.identity.agent, config.replicas[0].node).unwrap();
        let (decision, rotation, committee) = system_authority_history_fixture();

        assert_eq!(
            store.load_system_authority_decision_node(SystemAuthorityDecisionNodeId::from_bytes(
                [0x71; 32]
            )),
            Ok(None)
        );
        assert_eq!(
            store.load_system_authority_rotation_node(SystemAuthorityRotationNodeId::from_bytes(
                [0x72; 32]
            )),
            Ok(None)
        );
        assert_eq!(
            store.load_system_authority_committee_record(SystemAuthorityCommitteeId::from_bytes(
                [0x73; 32]
            )),
            Ok(None)
        );
        assert_eq!(
            store.load_system_authority_decision_node(SystemAuthorityDecisionNodeId::ZERO),
            Err(JournalStoreError::Corrupt)
        );

        store
            .persist_system_authority_decision_node(&decision)
            .unwrap();
        store
            .persist_system_authority_rotation_node(&rotation)
            .unwrap();
        store
            .persist_system_authority_committee_record(&committee)
            .unwrap();
        // Exact retries prove and retain the same canonical bytes.
        store
            .persist_system_authority_decision_node(&decision)
            .unwrap();
        assert_eq!(
            store.load_system_authority_decision_node(decision.id()),
            Ok(Some(decision.clone()))
        );
        assert_eq!(
            store.load_system_authority_rotation_node(rotation.id()),
            Ok(Some(rotation.clone()))
        );
        assert_eq!(
            store.load_system_authority_committee_record(committee.id()),
            Ok(Some(committee.clone()))
        );

        store.authority.insert(
            (
                AuthorityStorageClass::SystemRotation,
                *rotation.id().as_bytes(),
            ),
            b"tampered".to_vec(),
        );
        assert_eq!(
            store.load_system_authority_rotation_node(rotation.id()),
            Err(JournalStoreError::Corrupt)
        );
        store.authority.insert(
            (
                AuthorityStorageClass::SystemDecision,
                *decision.id().as_bytes(),
            ),
            vec![0; MAX_SYSTEM_AUTHORITY_DECISION_NODE_BYTES + 1],
        );
        assert_eq!(
            store.load_system_authority_decision_node(decision.id()),
            Err(JournalStoreError::Corrupt)
        );
        let wrong_committee_id = SystemAuthorityCommitteeId::from_bytes([0x74; 32]);
        store.authority.insert(
            (
                AuthorityStorageClass::SystemCommittee,
                *wrong_committee_id.as_bytes(),
            ),
            committee.encode(),
        );
        assert_eq!(
            store.load_system_authority_committee_record(wrong_committee_id),
            Err(JournalStoreError::Corrupt)
        );
    }

    #[test]
    fn memory_system_authority_catalog_history_retains_nodes_and_full_records() {
        let config = config();
        let mut store =
            MemoryAgentJournalStore::new(config.identity.agent, config.replicas[0].node).unwrap();
        let (record, node) = system_authority_catalog_fixture();

        assert_eq!(
            store.load_system_authority_catalog_node(node.id()),
            Ok(None)
        );
        assert_eq!(
            store.load_system_authority_catalog_record(record.id()),
            Ok(None)
        );
        store
            .persist_system_authority_catalog_record(&record)
            .unwrap();
        store.persist_system_authority_catalog_node(&node).unwrap();
        store
            .persist_system_authority_catalog_record(&record)
            .unwrap();
        store.persist_system_authority_catalog_node(&node).unwrap();
        assert_eq!(
            store.load_system_authority_catalog_record(record.id()),
            Ok(Some(record.clone()))
        );
        assert_eq!(
            store.load_system_authority_catalog_node(node.id()),
            Ok(Some(node.clone()))
        );

        store.authority.insert(
            (
                AuthorityStorageClass::SystemCatalogRecord,
                *record.id().as_bytes(),
            ),
            b"tampered".to_vec(),
        );
        assert_eq!(
            store.load_system_authority_catalog_record(record.id()),
            Err(JournalStoreError::Corrupt)
        );
        store.authority.insert(
            (
                AuthorityStorageClass::SystemCatalogNode,
                *node.id().as_bytes(),
            ),
            vec![0; MAX_SYSTEM_AUTHORITY_CATALOG_NODE_BYTES + 1],
        );
        assert_eq!(
            store.load_system_authority_catalog_node(node.id()),
            Err(JournalStoreError::Corrupt)
        );
    }

    #[test]
    fn catalog_staging_is_ordered_read_only_on_retry_and_retains_displaced_paths() {
        let config = config();
        let mut store =
            MemoryAgentJournalStore::new(config.identity.agent, config.replicas[0].node).unwrap();
        let (state, scope, committee, keys) = system_authority_catalog_state_fixture();
        let operation = OperationId([0x91; 32]);
        let receipt = system_authority_catalog_receipt(
            state.catalog_binding_record().unwrap(),
            &committee,
            &keys,
            operation,
            state.authority_generation(),
            state.catalog_head(),
            state.authority_generation(),
            state.catalog_head(),
            state.committee_sequence_high_water() + 1,
            0x92,
        );
        let fresh = SystemAuthorityCatalogFinalize::new(
            receipt.clone(),
            SystemAuthorityCatalogProof::vacant(operation, Vec::new()).unwrap(),
        )
        .unwrap();
        let transition = state.apply_catalog_finalize(scope, &fresh).unwrap();
        assert!(transition.history().inserted());
        assert!(
            stage_system_authority_catalog_dependencies(
                &mut store,
                &fresh,
                transition.record(),
                transition.history(),
                transition.outcome(),
            )
            .unwrap()
        );
        let next = transition.state().clone();
        let occupied =
            prove_stored_catalog(&store, next.catalog_history_root(), operation).unwrap();
        let exact = SystemAuthorityCatalogFinalize::new(receipt, occupied.clone()).unwrap();
        let exact_transition = next.apply_catalog_finalize(scope, &exact).unwrap();
        assert!(!exact_transition.history().inserted());
        assert!(exact_transition.outcome().exact_retry());
        let before_retry = store.authority.clone();
        assert!(
            !stage_system_authority_catalog_dependencies(
                &mut store,
                &exact,
                exact_transition.record(),
                exact_transition.history(),
                exact_transition.outcome(),
            )
            .unwrap()
        );
        assert_eq!(store.authority, before_retry);

        let divergent_receipt = system_authority_catalog_receipt(
            next.catalog_binding_record().unwrap(),
            &committee,
            &keys,
            operation,
            next.authority_generation(),
            next.catalog_head(),
            next.authority_generation(),
            next.catalog_head(),
            next.committee_sequence_high_water() + 1,
            0x93,
        );
        let divergent = SystemAuthorityCatalogFinalize::new(divergent_receipt, occupied).unwrap();
        let conflict = next.apply_catalog_finalize(scope, &divergent).unwrap();
        assert!(conflict.outcome().operation_conflicted());
        assert_eq!(conflict.record(), None);
        assert!(
            !stage_system_authority_catalog_dependencies(
                &mut store,
                &divergent,
                conflict.record(),
                conflict.history(),
                conflict.outcome(),
            )
            .unwrap()
        );
        assert_eq!(store.authority, before_retry);

        let second_operation = OperationId([0x94; 32]);
        let vacant =
            prove_stored_catalog(&store, next.catalog_history_root(), second_operation).unwrap();
        let second_receipt = system_authority_catalog_receipt(
            next.catalog_binding_record().unwrap(),
            &committee,
            &keys,
            second_operation,
            next.authority_generation(),
            next.catalog_head(),
            next.authority_generation(),
            next.catalog_head(),
            next.committee_sequence_high_water() + 1,
            0x95,
        );
        let second = SystemAuthorityCatalogFinalize::new(second_receipt, vacant).unwrap();
        let second_transition = next.apply_catalog_finalize(scope, &second).unwrap();
        assert!(!second_transition.history().retired_node_ids().is_empty());
        assert!(
            stage_system_authority_catalog_dependencies(
                &mut store,
                &second,
                second_transition.record(),
                second_transition.history(),
                second_transition.outcome(),
            )
            .unwrap()
        );
        for retired in second_transition.history().retired_node_ids() {
            assert!(
                store
                    .load_system_authority_catalog_node(*retired)
                    .unwrap()
                    .is_some()
            );
        }
        assert_eq!(
            prove_stored_catalog(
                &store,
                second_transition.state().catalog_history_root(),
                second_operation,
            )
            .unwrap()
            .occupied_record_id(),
            Some(second_transition.record().unwrap().id())
        );
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn file_system_authority_history_reopens_and_missing_stays_missing() {
        let directory = TestDirectory::new("system-authority-history-reopen");
        let (decision, rotation, committee) = system_authority_history_fixture();
        let mut store = open_file_store(&directory);
        store
            .persist_system_authority_decision_node(&decision)
            .unwrap();
        store
            .persist_system_authority_rotation_node(&rotation)
            .unwrap();
        store
            .persist_system_authority_committee_record(&committee)
            .unwrap();
        let paths = [
            system_authority_history_path(
                store.root(),
                AUTHORITY_SYSTEM_DECISIONS_DIRECTORY,
                decision.id().as_bytes(),
            ),
            system_authority_history_path(
                store.root(),
                AUTHORITY_SYSTEM_ROTATIONS_DIRECTORY,
                rotation.id().as_bytes(),
            ),
            system_authority_history_path(
                store.root(),
                AUTHORITY_SYSTEM_COMMITTEES_DIRECTORY,
                committee.id().as_bytes(),
            ),
        ];
        for path in &paths {
            assert!(path.is_file());
            assert!(!path.with_extension("next").exists());
        }
        drop(store);

        let mut reopened = open_file_store(&directory);
        assert_eq!(
            reopened.load_system_authority_decision_node(decision.id()),
            Ok(Some(decision.clone()))
        );
        assert_eq!(
            reopened.load_system_authority_rotation_node(rotation.id()),
            Ok(Some(rotation.clone()))
        );
        assert_eq!(
            reopened.load_system_authority_committee_record(committee.id()),
            Ok(Some(committee.clone()))
        );
        reopened
            .persist_system_authority_committee_record(&committee)
            .unwrap();
        drop(reopened);

        for path in &paths {
            fs::remove_file(path).unwrap();
        }
        let missing = open_file_store(&directory);
        assert_eq!(
            missing.load_system_authority_decision_node(decision.id()),
            Ok(None)
        );
        assert_eq!(
            missing.load_system_authority_rotation_node(rotation.id()),
            Ok(None)
        );
        assert_eq!(
            missing.load_system_authority_committee_record(committee.id()),
            Ok(None)
        );
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn file_system_authority_catalog_history_reopens_and_scrubs_both_namespaces() {
        let directory = TestDirectory::new("system-authority-catalog-history-reopen");
        let (record, node) = system_authority_catalog_fixture();
        let mut store = open_file_store(&directory);
        store
            .persist_system_authority_catalog_record(&record)
            .unwrap();
        store.persist_system_authority_catalog_node(&node).unwrap();
        let record_path = system_authority_history_path(
            store.root(),
            AUTHORITY_SYSTEM_CATALOG_RECORDS_DIRECTORY,
            record.id().as_bytes(),
        );
        let node_path = system_authority_history_path(
            store.root(),
            AUTHORITY_SYSTEM_CATALOG_NODES_DIRECTORY,
            node.id().as_bytes(),
        );
        assert!(record_path.is_file());
        assert!(node_path.is_file());
        drop(store);

        let reopened = open_file_store(&directory);
        assert_eq!(
            reopened.load_system_authority_catalog_record(record.id()),
            Ok(Some(record.clone()))
        );
        assert_eq!(
            reopened.load_system_authority_catalog_node(node.id()),
            Ok(Some(node.clone()))
        );
        let report = reopened
            .scrub_system_authority_history(system_authority_history_scrub_limits())
            .unwrap();
        assert_eq!(report.catalog_records, 1);
        assert_eq!(report.catalog_nodes, 1);
        drop(reopened);

        fs::remove_file(record_path).unwrap();
        let missing_record = open_file_store(&directory);
        assert_eq!(
            missing_record.scrub_system_authority_history(system_authority_history_scrub_limits()),
            Err(JournalStoreError::Corrupt)
        );
        assert_eq!(
            missing_record.load_system_authority_catalog_node(node.id()),
            Ok(Some(node.clone()))
        );
        drop(missing_record);

        fs::remove_file(node_path).unwrap();
        let missing = open_file_store(&directory);
        assert_eq!(
            missing.load_system_authority_catalog_record(record.id()),
            Ok(None)
        );
        assert_eq!(
            missing.load_system_authority_catalog_node(node.id()),
            Ok(None)
        );
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn file_system_authority_history_lazy_open_and_scrub_reject_tamper() {
        let (decision, rotation, committee) = system_authority_history_fixture();
        let (catalog_record, catalog_node) = system_authority_catalog_fixture();
        let targets = [
            (
                AUTHORITY_SYSTEM_DECISIONS_DIRECTORY,
                *decision.id().as_bytes(),
            ),
            (
                AUTHORITY_SYSTEM_ROTATIONS_DIRECTORY,
                *rotation.id().as_bytes(),
            ),
            (
                AUTHORITY_SYSTEM_CATALOG_NODES_DIRECTORY,
                *catalog_node.id().as_bytes(),
            ),
            (
                AUTHORITY_SYSTEM_CATALOG_RECORDS_DIRECTORY,
                *catalog_record.id().as_bytes(),
            ),
            (
                AUTHORITY_SYSTEM_COMMITTEES_DIRECTORY,
                *committee.id().as_bytes(),
            ),
        ];
        for (index, (authority_directory, id)) in targets.into_iter().enumerate() {
            let directory = TestDirectory::new(&format!("system-authority-history-tamper-{index}"));
            let mut store = open_file_store(&directory);
            store
                .persist_system_authority_decision_node(&decision)
                .unwrap();
            store
                .persist_system_authority_rotation_node(&rotation)
                .unwrap();
            store
                .persist_system_authority_catalog_record(&catalog_record)
                .unwrap();
            store
                .persist_system_authority_catalog_node(&catalog_node)
                .unwrap();
            store
                .persist_system_authority_committee_record(&committee)
                .unwrap();
            let path = system_authority_history_path(store.root(), authority_directory, &id);
            drop(store);
            fs::write(path, b"tampered authority history").unwrap();

            // Reopen authenticates topology and capabilities only. An inert,
            // unreferenced permanent object cannot make a large valid store
            // unavailable, but following its exact typed ID still fails
            // closed.
            let reopened = open_file_store(&directory);
            let loaded = match index {
                0 => reopened
                    .load_system_authority_decision_node(decision.id())
                    .map(|record| record.map(|_| ())),
                1 => reopened
                    .load_system_authority_rotation_node(rotation.id())
                    .map(|record| record.map(|_| ())),
                2 => reopened
                    .load_system_authority_catalog_node(catalog_node.id())
                    .map(|record| record.map(|_| ())),
                3 => reopened
                    .load_system_authority_catalog_record(catalog_record.id())
                    .map(|record| record.map(|_| ())),
                4 => reopened
                    .load_system_authority_committee_record(committee.id())
                    .map(|record| record.map(|_| ())),
                _ => unreachable!(),
            };
            assert_eq!(loaded, Err(JournalStoreError::Corrupt));
            assert_eq!(
                reopened.scrub_system_authority_history(system_authority_history_scrub_limits()),
                Err(JournalStoreError::Corrupt)
            );
        }

        let directory = TestDirectory::new("system-authority-history-name");
        let store = open_file_store(&directory);
        fs::write(
            store
                .root()
                .join(AUTHORITY_SYSTEM_DECISIONS_DIRECTORY)
                .join("not-a-content-id"),
            b"junk",
        )
        .unwrap();
        drop(store);
        let reopened = open_file_store(&directory);
        assert_eq!(
            reopened.scrub_system_authority_history(system_authority_history_scrub_limits()),
            Err(JournalStoreError::Corrupt)
        );
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn file_system_authority_history_lazy_load_and_scrub_enforce_each_wire_bound() {
        for (index, (authority_directory, maximum)) in [
            (
                AUTHORITY_SYSTEM_DECISIONS_DIRECTORY,
                MAX_SYSTEM_AUTHORITY_DECISION_NODE_BYTES,
            ),
            (
                AUTHORITY_SYSTEM_ROTATIONS_DIRECTORY,
                MAX_SYSTEM_AUTHORITY_ROTATION_NODE_BYTES,
            ),
            (
                AUTHORITY_SYSTEM_CATALOG_NODES_DIRECTORY,
                MAX_SYSTEM_AUTHORITY_CATALOG_NODE_BYTES,
            ),
            (
                AUTHORITY_SYSTEM_CATALOG_RECORDS_DIRECTORY,
                MAX_SYSTEM_AUTHORITY_CATALOG_RECORD_BYTES,
            ),
            (
                AUTHORITY_SYSTEM_COMMITTEES_DIRECTORY,
                MAX_SYSTEM_AUTHORITY_COMMITTEE_RECORD_BYTES,
            ),
        ]
        .into_iter()
        .enumerate()
        {
            let directory = TestDirectory::new(&format!("system-authority-history-bound-{index}"));
            let store = open_file_store(&directory);
            let id = [(0x81_u8).wrapping_add(index as u8); 32];
            let path = system_authority_history_path(store.root(), authority_directory, &id);
            fs::write(path, vec![0; maximum + 1]).unwrap();
            drop(store);

            let reopened = open_file_store(&directory);
            let loaded = match index {
                0 => reopened
                    .load_system_authority_decision_node(SystemAuthorityDecisionNodeId::from_bytes(
                        id,
                    ))
                    .map(|record| record.map(|_| ())),
                1 => reopened
                    .load_system_authority_rotation_node(SystemAuthorityRotationNodeId::from_bytes(
                        id,
                    ))
                    .map(|record| record.map(|_| ())),
                2 => reopened
                    .load_system_authority_catalog_node(SystemAuthorityCatalogNodeId::from_bytes(
                        id,
                    ))
                    .map(|record| record.map(|_| ())),
                3 => reopened
                    .load_system_authority_catalog_record(
                        SystemAuthorityCatalogRecordId::from_bytes(id),
                    )
                    .map(|record| record.map(|_| ())),
                4 => reopened
                    .load_system_authority_committee_record(SystemAuthorityCommitteeId::from_bytes(
                        id,
                    ))
                    .map(|record| record.map(|_| ())),
                _ => unreachable!(),
            };
            assert_eq!(loaded, Err(JournalStoreError::Corrupt));
            assert_eq!(
                reopened.scrub_system_authority_history(system_authority_history_scrub_limits()),
                Err(JournalStoreError::Corrupt)
            );
        }
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn file_system_authority_history_scrub_streams_aliases_partials_and_budgets() {
        let directory = TestDirectory::new("system-authority-history-streaming-scrub");
        let (decision, rotation, committee) = system_authority_history_fixture();
        let mut store = open_file_store(&directory);
        store
            .persist_system_authority_decision_node(&decision)
            .unwrap();
        store
            .persist_system_authority_rotation_node(&rotation)
            .unwrap();
        let decision_path = system_authority_history_path(
            store.root(),
            AUTHORITY_SYSTEM_DECISIONS_DIRECTORY,
            decision.id().as_bytes(),
        );
        let rotation_path = system_authority_history_path(
            store.root(),
            AUTHORITY_SYSTEM_ROTATIONS_DIRECTORY,
            rotation.id().as_bytes(),
        );
        let committee_path = system_authority_history_path(
            store.root(),
            AUTHORITY_SYSTEM_COMMITTEES_DIRECTORY,
            committee.id().as_bytes(),
        );
        let decision_stage = decision_path.with_extension("next");
        let rotation_stage = rotation_path.with_extension("next");
        let decision_partial = PathBuf::from(format!("{}.next.partial", decision_path.display()));
        let rotation_partial = PathBuf::from(format!("{}.next.partial", rotation_path.display()));
        let committee_partial = PathBuf::from(format!("{}.next.partial", committee_path.display()));
        fs::copy(&decision_path, &decision_stage).unwrap();
        fs::rename(&rotation_path, &rotation_stage).unwrap();
        fs::write(&decision_partial, b"interrupted equal-alias retry").unwrap();
        fs::write(&rotation_partial, b"interrupted stage-only retry").unwrap();
        fs::write(&committee_partial, b"interrupted partial-only retry").unwrap();
        drop(store);

        let mut reopened = open_file_store(&directory);
        // Lazy reopen does not enumerate or discard inert private partials.
        assert!(decision_partial.exists());
        assert!(rotation_partial.exists());
        assert!(committee_partial.exists());
        assert_eq!(
            reopened.load_system_authority_decision_node(decision.id()),
            Ok(Some(decision.clone()))
        );
        assert_eq!(
            reopened.load_system_authority_rotation_node(rotation.id()),
            Ok(None)
        );
        assert_eq!(
            reopened.load_system_authority_committee_record(committee.id()),
            Ok(None)
        );

        let report = reopened
            .scrub_system_authority_history(system_authority_history_scrub_limits())
            .unwrap();
        assert_eq!(report.namespace_entries, 6);
        assert_eq!(report.private_partial_entries, 3);
        assert_eq!(report.file_reads, 8);
        assert_eq!(report.decision_records, 1);
        assert_eq!(report.rotation_records, 1);
        assert_eq!(report.committee_records, 0);

        assert_eq!(
            reopened.scrub_system_authority_history(SystemAuthorityHistoryScrubLimits {
                max_namespace_entries: 5,
                ..system_authority_history_scrub_limits()
            }),
            Err(JournalStoreError::LimitExceeded)
        );
        assert_eq!(
            reopened.scrub_system_authority_history(SystemAuthorityHistoryScrubLimits {
                max_file_reads: 4,
                ..system_authority_history_scrub_limits()
            }),
            Err(JournalStoreError::LimitExceeded)
        );
        assert_eq!(
            reopened.scrub_system_authority_history(SystemAuthorityHistoryScrubLimits {
                max_bytes_read: 0,
                ..system_authority_history_scrub_limits()
            }),
            Err(JournalStoreError::LimitExceeded)
        );

        // A retry reconciles the exact ID without scanning the namespace and
        // removes a crash-left private sibling whether the canonical object
        // or only its durable public stage existed.
        reopened
            .persist_system_authority_decision_node(&decision)
            .unwrap();
        reopened
            .persist_system_authority_rotation_node(&rotation)
            .unwrap();
        assert!(!decision_stage.exists());
        assert!(!decision_partial.exists());
        assert!(rotation_path.exists());
        assert!(!rotation_stage.exists());
        assert!(!rotation_partial.exists());

        let divergent = SystemAuthorityDecisionNode::Branch {
            depth: 8,
            left: SystemAuthorityDecisionNodeId::from_bytes([0x91; 32]),
            right: SystemAuthorityDecisionNodeId::from_bytes([0x92; 32]),
        };
        fs::write(&decision_stage, divergent.encode()).unwrap();
        assert_eq!(
            reopened.load_system_authority_decision_node(decision.id()),
            Err(JournalStoreError::Corrupt)
        );
        assert_eq!(
            reopened.scrub_system_authority_history(system_authority_history_scrub_limits()),
            Err(JournalStoreError::Corrupt)
        );
    }

    #[test]
    fn memory_store_requires_blob_closure_and_publishes_idempotently() {
        let genesis = genesis();
        let config = config();
        let mut store =
            MemoryAgentJournalStore::new(config.identity.agent, config.replicas[0].node).unwrap();
        assert_eq!(
            store.initialize_raw_for_test(&genesis),
            Err(JournalStoreError::MissingObject)
        );
        initialize(&mut store, &genesis);

        let initial = store.heads().unwrap().unwrap();
        let entry = first_ordered(&genesis, &initial);
        let next = ordered_successor(&initial, &entry);
        assert_eq!(
            store.publish_anchor(initial.id(), &entry, &next).unwrap(),
            JournalPublication {
                object_created: true,
                heads_advanced: true,
            }
        );
        assert_eq!(store.heads().unwrap(), Some(next.clone()));
        assert_eq!(
            store.publish_anchor(initial.id(), &entry, &next).unwrap(),
            JournalPublication {
                object_created: false,
                heads_advanced: false,
            }
        );
    }

    #[test]
    fn system_authorized_admission_stays_closed_until_live_verifier_exists() {
        let admission = phase_one_system_authorized_admission();
        admission.validate().unwrap();
        assert_eq!(
            phase_one_root_admission(&admission),
            Err(JournalStoreError::Unavailable)
        );
    }

    #[test]
    fn memory_shared_ordered_commit_binding_is_immutable_and_idempotent() {
        let genesis = genesis();
        let config = config();
        let mut store =
            MemoryAgentJournalStore::new(config.identity.agent, config.replicas[0].node).unwrap();
        initialize(&mut store, &genesis);
        let heads = store.heads().unwrap().unwrap();
        let entry = first_ordered(&genesis, &heads);
        let binding = shared_ordered_binding(&genesis, &heads, &entry, store.instance_id());

        assert!(store.persist_shared_ordered_commit(&binding).unwrap());
        assert_eq!(
            store.shared_ordered_commit(entry.id()).unwrap(),
            Some(binding.clone())
        );
        assert!(!store.persist_shared_ordered_commit(&binding).unwrap());

        let conflicting = SharedOrderedCommitBinding::new(
            store.instance_id(),
            entry.id(),
            binding.claim().clone(),
            Hash([0xd8; 32]),
        )
        .unwrap();
        assert_eq!(
            store.persist_shared_ordered_commit(&conflicting),
            Err(JournalStoreError::Conflict)
        );
        assert_eq!(
            store.shared_ordered_commit(entry.id()).unwrap(),
            Some(binding)
        );
    }

    #[test]
    fn file_shared_ordered_commit_binding_survives_reopen_exactly() {
        let directory = TestDirectory::new("shared-ordered-commit");
        let genesis = genesis();
        let mut store = open_file_store(&directory);
        initialize(&mut store, &genesis);
        let heads = store.heads().unwrap().unwrap();
        let entry = first_ordered(&genesis, &heads);
        let binding = shared_ordered_binding(&genesis, &heads, &entry, store.instance_id());

        assert!(store.persist_shared_ordered_commit(&binding).unwrap());
        assert!(!store.persist_shared_ordered_commit(&binding).unwrap());
        drop(store);

        let mut reopened = open_file_store(&directory);
        assert_eq!(
            reopened.shared_ordered_commit(entry.id()).unwrap(),
            Some(binding.clone())
        );
        let conflicting = SharedOrderedCommitBinding::new(
            reopened.instance_id(),
            entry.id(),
            binding.claim().clone(),
            Hash([0xd9; 32]),
        )
        .unwrap();
        assert_eq!(
            reopened.persist_shared_ordered_commit(&conflicting),
            Err(JournalStoreError::Conflict)
        );
        assert_eq!(
            reopened.shared_ordered_commit(entry.id()).unwrap(),
            Some(binding)
        );
    }

    #[test]
    fn file_shared_ordered_commit_namespace_rejects_extra_entries_on_open() {
        let directory = TestDirectory::new("shared-ordered-commit-junk");
        let genesis = genesis();
        let mut store = open_file_store(&directory);
        initialize(&mut store, &genesis);
        let root = store.root().to_path_buf();
        drop(store);

        fs::write(
            root.join(SHARED_ORDERED_COMMIT_DIRECTORY).join("junk"),
            b"junk",
        )
        .unwrap();
        let config = config();
        assert!(matches!(
            FileAgentJournalStore::open_unverified_for_test(
                directory.agent_root(config.identity.agent),
                directory.lock(config.identity.agent),
                config.replicas[0].node,
            ),
            Err(JournalStoreError::Corrupt)
        ));
    }

    #[test]
    fn memory_history_candidate_rolls_back_on_stale_cas_and_commits_exact_fact() {
        let genesis = genesis();
        let config = config();
        let mut store =
            MemoryAgentJournalStore::new(config.identity.agent, config.replicas[0].node).unwrap();
        initialize(&mut store, &genesis);
        let current = store.heads().unwrap().unwrap();
        let transition = prepare_history_transition(&mut store, &genesis, &current, 0x35);
        let queue = store.history_queue(genesis.id()).unwrap().clone();
        let history = build_test_history_candidate(&store, &current, &transition, &queue);
        assert!(!history.nodes.is_empty());
        assert!(
            history
                .plans
                .iter()
                .flat_map(InvocationHistoryWritePlan::overlay_nodes)
                .all(|write| store.load_history_node(write.id()).unwrap().is_none())
        );

        let first_write = history.plans[0].overlay_nodes()[0].clone();
        let node = InvocationHistoryNode::decode(first_write.bytes()).unwrap();
        assert_eq!(node.id(), first_write.id());
        assert_eq!(
            store.put(&node),
            Err(JournalStoreError::InvalidClass),
            "generic content puts must not manufacture permanent history"
        );

        // Exercise the same copy-on-write shape as MemoryAgentJournalStore::publish:
        // a candidate may contain permanent nodes, but a failed CAS never swaps it
        // into the live store.
        let mut stale_candidate = store.clone();
        stale_candidate.install_history_candidate(&history).unwrap();
        let competing_entry = OrderedEntry {
            genesis: genesis.id(),
            index: 1,
            parent: None,
            merge_frontier: current.merge_frontier,
            merge_seal: None,
            input: replay_input(MethodMode::Linear, 0x36),
        };
        let competing = ordered_successor(&current, &competing_entry);
        stale_candidate
            .publish_anchor(current.id(), &competing_entry, &competing)
            .unwrap();
        assert_eq!(
            stale_candidate.publish_anchor(current.id(), &transition.entry, &transition.next,),
            Err(JournalStoreError::Conflict)
        );
        drop(stale_candidate);
        assert_eq!(store.heads().unwrap(), Some(current.clone()));
        assert!(store.history_nodes.is_empty());

        let mut committed = store.clone();
        committed.install_history_candidate(&history).unwrap();
        committed
            .publish_anchor(current.id(), &transition.entry, &transition.next)
            .unwrap();
        committed
            .enqueue_history_retirement(&history.intent)
            .unwrap();
        store = committed;
        assert_eq!(store.heads().unwrap(), Some(transition.next.clone()));
        let index = InvocationIndex::open(&mut store, transition.next.ordered_invocations).unwrap();
        assert_eq!(
            index.lookup(transition.key).unwrap(),
            Some(InvocationIndexLookup::Archived(transition.fact))
        );
        drop(index);
        assert_eq!(store.history_retirements.as_ref().unwrap().records.len(), 1);
    }

    #[test]
    fn history_retirement_backpressure_is_preflight_only() {
        let genesis = genesis();
        let config = config();
        let mut memory =
            MemoryAgentJournalStore::new(config.identity.agent, config.replicas[0].node).unwrap();
        initialize(&mut memory, &genesis);
        let current = memory.heads().unwrap().unwrap();
        let mut transition = prepare_history_transition(&mut memory, &genesis, &current, 0x37);
        let roots = history_roots_for_heads(&memory, &current).unwrap();
        let queue = saturated_history_queue(genesis.id(), current.node, roots);
        let fake_current = JournalHeads {
            publication_revision: MAX_HISTORY_RETIREMENT_PUBLICATIONS as u64,
            previous: Some(JournalHeadsId([0xd7; 32])),
            ..current.clone()
        };
        transition.next = JournalHeads {
            publication_revision: fake_current.publication_revision + 1,
            previous: Some(fake_current.id()),
            ..transition.next
        };
        let before_nodes = memory.history_nodes.clone();
        assert!(matches!(
            build_history_candidate(
                &memory,
                &fake_current,
                &transition.next,
                core::slice::from_ref(&transition.plan),
                &queue,
            ),
            Err(JournalStoreError::Backpressure)
        ));
        assert_eq!(memory.history_nodes, before_nodes);

        #[cfg(target_os = "linux")]
        {
            let directory = TestDirectory::new("history-backpressure");
            let mut file = open_file_store(&directory);
            initialize(&mut file, &genesis);
            let current = file.heads().unwrap().unwrap();
            let mut transition = prepare_history_transition(&mut file, &genesis, &current, 0x38);
            let roots = history_roots_for_heads(&file, &current).unwrap();
            let queue = saturated_history_queue(genesis.id(), current.node, roots);
            let fake_current = JournalHeads {
                publication_revision: MAX_HISTORY_RETIREMENT_PUBLICATIONS as u64,
                previous: Some(JournalHeadsId([0xd8; 32])),
                ..current
            };
            transition.next = JournalHeads {
                publication_revision: fake_current.publication_revision + 1,
                previous: Some(fake_current.id()),
                ..transition.next
            };
            create_synced_stage_at(
                file.directory("").unwrap(),
                "heads.limit.next",
                &fake_current.encode(),
            )
            .unwrap();
            rename_file_at(file.directory("").unwrap(), "heads.limit.next", "heads").unwrap();
            file.directory("").unwrap().sync_all().unwrap();
            create_synced_stage_at(
                file.directory(HISTORY_DIRECTORY).unwrap(),
                HISTORY_RETIREMENTS_STAGE_NAME,
                &queue.encode(),
            )
            .unwrap();
            rename_file_at(
                file.directory(HISTORY_DIRECTORY).unwrap(),
                HISTORY_RETIREMENTS_STAGE_NAME,
                HISTORY_RETIREMENTS_NAME,
            )
            .unwrap();
            file.directory(HISTORY_DIRECTORY)
                .unwrap()
                .sync_all()
                .unwrap();
            let heads_before = fs::read(file.root().join("heads")).unwrap();
            let queue_before = fs::read(
                file.root()
                    .join(HISTORY_DIRECTORY)
                    .join(HISTORY_RETIREMENTS_NAME),
            )
            .unwrap();
            let mut reached_write_point = false;
            assert!(matches!(
                file.stage_sealed_history_candidate(
                    fake_current.id(),
                    &transition.next,
                    core::slice::from_ref(&transition.plan),
                    &mut |_| {
                        reached_write_point = true;
                        Ok(())
                    },
                ),
                Err(JournalStoreError::Backpressure)
            ));
            assert!(!reached_write_point);
            assert_eq!(fs::read(file.root().join("heads")).unwrap(), heads_before);
            assert_eq!(
                fs::read(
                    file.root()
                        .join(HISTORY_DIRECTORY)
                        .join(HISTORY_RETIREMENTS_NAME),
                )
                .unwrap(),
                queue_before
            );
            assert!(
                fs::read_dir(file.root().join(HISTORY_CANDIDATE_DIRECTORY))
                    .unwrap()
                    .next()
                    .is_none()
            );
            assert!(
                transition
                    .plan
                    .overlay_nodes()
                    .iter()
                    .all(|write| file.read_global_history_node(write.id()).unwrap().is_none())
            );
        }
    }

    #[test]
    fn ordered_seal_alone_may_advance_merge_invocation_root() {
        let genesis = genesis();
        let config = config();
        let mut store =
            MemoryAgentJournalStore::new(config.identity.agent, config.replicas[0].node).unwrap();
        initialize(&mut store, &genesis);
        let current = store.heads().unwrap().unwrap();
        let changed_merge_root = InvocationIndexId([0xd1; 32]);

        let unsealed = first_ordered(&genesis, &current);
        let unsealed_next = JournalHeads {
            merge_invocations: changed_merge_root,
            ..ordered_successor(&current, &unsealed)
        };
        assert_eq!(
            validate_publication_shape(&current, &unsealed, &unsealed_next),
            Err(JournalStoreError::NonCanonical)
        );

        let seal = MergeSealId([0xd2; 32]);
        let sealed = OrderedEntry {
            input: management_input(0xd3),
            merge_seal: Some(seal),
            ..unsealed
        };
        let sealed_next = JournalHeads {
            publication_revision: current.publication_revision + 1,
            previous: Some(current.id()),
            ordered_head: Some(sealed.id()),
            ordered_index: sealed.index,
            merge_fence: OrderedBase {
                index: sealed.index,
                head: Some(sealed.id()),
            },
            merge_seal: Some(seal),
            merge_invocations: changed_merge_root,
            ..current.clone()
        };
        validate_publication_shape(&current, &sealed, &sealed_next).unwrap();
    }

    #[test]
    fn unpublished_catalog_tokens_preserve_preexisting_foreign_and_moved_head_content() {
        let genesis = genesis();
        let config = config();
        let mut store =
            MemoryAgentJournalStore::new(config.identity.agent, config.replicas[0].node).unwrap();
        initialize(&mut store, &genesis);
        let predecessor = store.heads().unwrap().unwrap().id();

        let preexisting = BlobRef::of_bytes(b"preexisting-catalog");
        assert!(
            store
                .put_blob(
                    JournalBlobClass::CatalogArtifact,
                    &preexisting,
                    b"preexisting-catalog",
                )
                .unwrap()
        );
        assert!(
            store
                .stage_catalog_blob(predecessor, &preexisting, b"preexisting-catalog")
                .unwrap()
                .is_none()
        );

        let first = BlobRef::of_bytes(b"first-new-catalog");
        let second = BlobRef::of_bytes(b"second-new-catalog");
        let first_token = store
            .stage_catalog_blob(predecessor, &first, b"first-new-catalog")
            .unwrap()
            .unwrap();
        let second_token = store
            .stage_catalog_blob(predecessor, &second, b"second-new-catalog")
            .unwrap()
            .unwrap();

        let mut foreign =
            MemoryAgentJournalStore::new(config.identity.agent, config.replicas[0].node).unwrap();
        initialize(&mut foreign, &genesis);
        let forged_for_foreign = UnpublishedCatalogBlob {
            store: store.instance_id(),
            predecessor,
            reference: first.clone(),
        };
        assert_eq!(
            foreign.rollback_catalog_blob(forged_for_foreign),
            Err(JournalStoreError::Conflict)
        );

        // Reverse rollback models a partial multi-blob staging failure. The
        // identical preexisting object never had a token and survives.
        store.rollback_catalog_blob(second_token).unwrap();
        store.rollback_catalog_blob(first_token).unwrap();
        assert_eq!(
            store.load_blob(JournalBlobClass::CatalogArtifact, &first),
            Ok(None)
        );
        assert_eq!(
            store.load_blob(JournalBlobClass::CatalogArtifact, &second),
            Ok(None)
        );
        assert_eq!(
            store.load_blob(JournalBlobClass::CatalogArtifact, &preexisting),
            Ok(Some(b"preexisting-catalog".to_vec()))
        );

        let moved = BlobRef::of_bytes(b"moved-head-catalog");
        let moved_token = store
            .stage_catalog_blob(predecessor, &moved, b"moved-head-catalog")
            .unwrap()
            .unwrap();
        let mut heads = store.heads().unwrap().unwrap();
        heads.publication_revision += 1;
        heads.previous = Some(predecessor);
        store.heads = Some(encode_object(&heads).unwrap().bytes);
        assert_eq!(
            store.rollback_catalog_blob(moved_token),
            Err(JournalStoreError::Conflict)
        );
        assert_eq!(
            store.load_blob(JournalBlobClass::CatalogArtifact, &moved),
            Ok(Some(b"moved-head-catalog".to_vec()))
        );
    }

    #[test]
    fn unreadable_heads_preserve_a_staged_catalog_blob_for_reopen_reconciliation() {
        let genesis = genesis();
        let config = config();
        let mut store =
            MemoryAgentJournalStore::new(config.identity.agent, config.replicas[0].node).unwrap();
        initialize(&mut store, &genesis);
        let predecessor = store.heads().unwrap().unwrap().id();
        let reference = BlobRef::of_bytes(b"ambiguous-catalog");
        let token = store
            .stage_catalog_blob(predecessor, &reference, b"ambiguous-catalog")
            .unwrap()
            .unwrap();
        store.heads = Some(vec![0xff]);
        assert_eq!(
            store.rollback_catalog_blob(token),
            Err(JournalStoreError::Corrupt)
        );
        assert_eq!(
            store.load_blob(JournalBlobClass::CatalogArtifact, &reference),
            Ok(Some(b"ambiguous-catalog".to_vec()))
        );
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn file_unpublished_catalog_token_unlinks_and_syncs_only_new_content() {
        let directory = TestDirectory::new("catalog-stage-rollback");
        let genesis = genesis();
        let mut store = open_file_store(&directory);
        initialize(&mut store, &genesis);
        let predecessor = store.heads().unwrap().unwrap().id();
        let reference = BlobRef::of_bytes(b"physical-unpublished-catalog");
        let token = store
            .stage_catalog_blob(predecessor, &reference, b"physical-unpublished-catalog")
            .unwrap()
            .unwrap();
        let path = store
            .root()
            .join("catalog/blobs")
            .join(encode_hex(reference.hash.as_bytes()));
        assert!(path.is_file());
        store.rollback_catalog_blob(token).unwrap();
        assert!(!path.exists());
        assert_eq!(
            store.load_blob(JournalBlobClass::CatalogArtifact, &reference),
            Ok(None)
        );
    }

    #[test]
    fn shared_ordered_splice_requires_replay_private_publication_mode() {
        let genesis = genesis();
        let config = config();
        let mut store =
            MemoryAgentJournalStore::new(config.identity.agent, config.replicas[0].node).unwrap();
        initialize(&mut store, &genesis);
        let current = store.heads().unwrap().unwrap();
        let pinned = MergeFrontierId([0xe1; 32]);
        let entry = OrderedEntry {
            merge_frontier: pinned,
            ..first_ordered(&genesis, &current)
        };
        let next = ordered_successor(&current, &entry);

        // Raw/local journal publication has no authority to interpret a
        // pinned Shared projection as a C/L-only splice.
        assert_eq!(
            validate_publication_shape(&current, &entry, &next),
            Err(JournalStoreError::NonCanonical)
        );
        validate_publication_shape_with_mode(
            &current,
            &entry,
            &next,
            ReplayPublicationMode::SharedOrderedPreserveMerge,
        )
        .unwrap();

        let seal = MergeSealId([0xe2; 32]);
        let fenced = OrderedEntry {
            input: management_input(0xe3),
            merge_seal: Some(seal),
            ..entry
        };
        let fenced_next = JournalHeads {
            publication_revision: current.publication_revision + 1,
            previous: Some(current.id()),
            ordered_head: Some(fenced.id()),
            ordered_index: fenced.index,
            merge_frontier: pinned,
            merge_fence: OrderedBase {
                index: fenced.index,
                head: Some(fenced.id()),
            },
            merge_seal: Some(seal),
            ..current.clone()
        };
        assert_eq!(
            validate_publication_shape(&current, &fenced, &fenced_next),
            Err(JournalStoreError::NonCanonical)
        );
        validate_publication_shape_with_mode(
            &current,
            &fenced,
            &fenced_next,
            ReplayPublicationMode::SharedOrderedInstallFence,
        )
        .unwrap();
    }

    #[test]
    fn memory_catalog_resolver_is_an_immutable_cow_snapshot() {
        let config = config();
        let mut store =
            MemoryAgentJournalStore::new(config.identity.agent, config.replicas[0].node).unwrap();
        let first_bytes = b"catalog snapshot first";
        let first = BlobRef::of_bytes(first_bytes);
        store
            .put_blob(JournalBlobClass::CatalogArtifact, &first, first_bytes)
            .unwrap();

        let snapshot = store.catalog_blob_resolver().unwrap();
        let second_bytes = b"catalog snapshot second";
        let second = BlobRef::of_bytes(second_bytes);
        store
            .put_blob(JournalBlobClass::CatalogArtifact, &second, second_bytes)
            .unwrap();

        assert_eq!(
            snapshot.load_catalog(&first).unwrap(),
            Some(first_bytes.to_vec())
        );
        assert_eq!(snapshot.load_catalog(&second).unwrap(), None);
        assert_eq!(
            store
                .catalog_blob_resolver()
                .unwrap()
                .load_catalog(&second)
                .unwrap(),
            Some(second_bytes.to_vec())
        );

        let rolled_back_bytes = b"catalog candidate rollback";
        let rolled_back = BlobRef::of_bytes(rolled_back_bytes);
        let mut candidate = store.clone();
        candidate
            .put_blob(
                JournalBlobClass::CatalogArtifact,
                &rolled_back,
                rolled_back_bytes,
            )
            .unwrap();
        assert_eq!(
            candidate
                .catalog_blob_resolver()
                .unwrap()
                .load_catalog(&rolled_back)
                .unwrap(),
            Some(rolled_back_bytes.to_vec())
        );
        drop(candidate);
        assert_eq!(
            store
                .catalog_blob_resolver()
                .unwrap()
                .load_catalog(&rolled_back)
                .unwrap(),
            None
        );

        let mut wrong_length = first.clone();
        wrong_length.len += 1;
        assert_eq!(
            snapshot.load_catalog(&wrong_length),
            Err(JournalStoreError::Corrupt)
        );
    }

    #[test]
    fn memory_gc_batches_gates_mutators_and_preserves_fresh_checkpoint() {
        let genesis = genesis();
        let config = config();
        let mut store =
            MemoryAgentJournalStore::new(config.identity.agent, config.replicas[0].node).unwrap();
        initialize(&mut store, &genesis);
        let (heads, checkpoint) = install_fresh_checkpoint(&mut store, &genesis);

        let first = replay_input(MethodMode::Linear, 0x91);
        let second = replay_input(MethodMode::Local, 0x92);
        store.put(&first).unwrap();
        store.put(&second).unwrap();
        let garbage_bytes = b"unreachable-catalog-blob";
        let garbage_blob = BlobRef::of_bytes(garbage_bytes);
        store
            .put_blob(
                JournalBlobClass::CatalogArtifact,
                &garbage_blob,
                garbage_bytes,
            )
            .unwrap();

        let mut limits = gc_limits();
        limits.max_unlinks_per_run = 1;
        let first_pass = store.collect_garbage(heads.id(), limits).unwrap();
        assert!(!first_pass.complete);
        assert!(!first_pass.resumed);
        assert_eq!(first_pass.objects_removed + first_pass.blobs_removed, 1);
        assert_eq!(
            store.put(&replay_input(MethodMode::Linear, 0x93)),
            Err(JournalStoreError::GcPending)
        );

        let mut passes = 1;
        loop {
            let pass = store.collect_garbage(heads.id(), limits).unwrap();
            passes += 1;
            assert!(pass.resumed);
            if pass.complete {
                break;
            }
        }
        assert_eq!(passes, 3);
        assert_eq!(store.get::<ReplayInput>(first.id()).unwrap(), None);
        assert_eq!(store.get::<ReplayInput>(second.id()).unwrap(), None);
        assert_eq!(
            store
                .load_blob(JournalBlobClass::CatalogArtifact, &garbage_blob)
                .unwrap(),
            None
        );
        assert_eq!(store.genesis().unwrap(), Some(genesis));
        assert_eq!(
            store.get::<CheckpointManifest>(checkpoint.id()).unwrap(),
            Some(checkpoint)
        );
        validate_head_targets(&store, &heads).unwrap();
        store.put(&replay_input(MethodMode::Linear, 0x94)).unwrap();
    }

    #[test]
    fn memory_gc_rejects_stale_checkpoint_and_preflight_limits_without_intent() {
        let genesis = genesis();
        let config = config();
        let mut limited =
            MemoryAgentJournalStore::new(config.identity.agent, config.replicas[0].node).unwrap();
        initialize(&mut limited, &genesis);
        let (heads, _) = install_fresh_checkpoint(&mut limited, &genesis);
        let mut limits = gc_limits();
        limits.max_scanned_files = 1;
        assert_eq!(
            limited.collect_garbage(heads.id(), limits),
            Err(JournalStoreError::LimitExceeded)
        );
        limited
            .put(&replay_input(MethodMode::Linear, 0x95))
            .unwrap();

        let mut stale =
            MemoryAgentJournalStore::new(config.identity.agent, config.replicas[0].node).unwrap();
        initialize(&mut stale, &genesis);
        let (checkpoint_heads, _) = install_fresh_checkpoint(&mut stale, &genesis);
        let entry = first_ordered(&genesis, &checkpoint_heads);
        let next = ordered_successor(&checkpoint_heads, &entry);
        stale
            .publish_anchor(checkpoint_heads.id(), &entry, &next)
            .unwrap();
        assert_eq!(
            stale.collect_garbage(next.id(), gc_limits()),
            Err(JournalStoreError::Conflict)
        );
        stale.put(&replay_input(MethodMode::Linear, 0x96)).unwrap();
    }

    #[test]
    fn memory_gc_keeps_live_outcome_and_history_fact_but_collects_acknowledged_outcome() {
        let genesis = genesis();
        let config = config();
        let mut store =
            MemoryAgentJournalStore::new(config.identity.agent, config.replicas[0].node).unwrap();
        initialize(&mut store, &genesis);
        let initial = store.heads().unwrap().unwrap();

        let input_one = replay_input(MethodMode::Linear, 0xa1);
        let ReplayOperation::Invoke {
            invocation: invocation_one,
            ..
        } = &input_one.operation
        else {
            unreachable!()
        };
        let entry_one = OrderedEntry {
            genesis: genesis.id(),
            index: 1,
            parent: None,
            merge_frontier: initial.merge_frontier,
            merge_seal: None,
            input: input_one.clone(),
        };
        let key_one = InvocationOwnershipKey {
            scope: InvocationOwnershipScope::Ordered,
            invocation: invocation_one.invocation,
        };
        let outcome_one = InvocationOutcomeRecord::from_runtime_states(
            genesis.id(),
            key_one.scope,
            InvocationOutcomeAnchor::Ordered {
                entry: entry_one.id(),
            },
            &input_one,
            &RuntimeState::default(),
            &RuntimeState::default(),
            Ok(ActorExecutionReply {
                invocation: invocation_one.invocation,
                actor: invocation_one.actor,
                incarnation: invocation_one.incarnation,
                deployment: invocation_one.deployment,
                mode: invocation_one.mode,
                lane: invocation_one.mode.write_lane(),
                status: ActorExecutionStatus::Done,
                reply: vec![1],
                gas_remaining: invocation_one.gas - 1,
                observation: ActorObservation::default(),
            }),
        )
        .unwrap();
        let root_one = {
            let mut index = InvocationIndex::open(&mut store, initial.ordered_invocations).unwrap();
            let reference = index.persist_outcome(&outcome_one).unwrap();
            index
                .record(
                    key_one,
                    InvocationOwner {
                        scope: key_one.scope,
                        request_commitment: invocation_one.commitment(),
                        first_input: input_one.id(),
                        lane: PersistedLane::Linear,
                        node: None,
                        result_state: InvocationResultState::Retained {
                            disposition: InvocationDisposition::Applied,
                            outcome: reference,
                        },
                    },
                )
                .unwrap();
            index.id()
        };
        let heads_one = JournalHeads {
            ordered_invocations: root_one,
            ..ordered_successor(&initial, &entry_one)
        };
        store
            .publish_anchor(initial.id(), &entry_one, &heads_one)
            .unwrap();

        let input_two = replay_input(MethodMode::Linear, 0xa2);
        let ReplayOperation::Invoke {
            invocation: invocation_two,
            authority: authority_two,
            ..
        } = &input_two.operation
        else {
            unreachable!()
        };
        let entry_two = OrderedEntry {
            genesis: genesis.id(),
            index: 2,
            parent: Some(entry_one.id()),
            merge_frontier: heads_one.merge_frontier,
            merge_seal: None,
            input: input_two.clone(),
        };
        let key_two = InvocationOwnershipKey {
            scope: InvocationOwnershipScope::Ordered,
            invocation: invocation_two.invocation,
        };
        let outcome_two = InvocationOutcomeRecord::from_runtime_states(
            genesis.id(),
            key_two.scope,
            InvocationOutcomeAnchor::Ordered {
                entry: entry_two.id(),
            },
            &input_two,
            &RuntimeState::default(),
            &RuntimeState::default(),
            Ok(ActorExecutionReply {
                invocation: invocation_two.invocation,
                actor: invocation_two.actor,
                incarnation: invocation_two.incarnation,
                deployment: invocation_two.deployment,
                mode: invocation_two.mode,
                lane: invocation_two.mode.write_lane(),
                status: ActorExecutionStatus::Done,
                reply: vec![2],
                gas_remaining: invocation_two.gas - 1,
                observation: ActorObservation::default(),
            }),
        )
        .unwrap();
        let (root_two, owner_two) = {
            let mut index = InvocationIndex::open(&mut store, root_one).unwrap();
            let reference = index.persist_outcome(&outcome_two).unwrap();
            let owner = InvocationOwner {
                scope: key_two.scope,
                request_commitment: invocation_two.commitment(),
                first_input: input_two.id(),
                lane: PersistedLane::Linear,
                node: None,
                result_state: InvocationResultState::Retained {
                    disposition: InvocationDisposition::Applied,
                    outcome: reference,
                },
            };
            index.record(key_two, owner).unwrap();
            (index.id(), owner)
        };
        let heads_two = JournalHeads {
            publication_revision: heads_one.publication_revision + 1,
            previous: Some(heads_one.id()),
            ordered_head: Some(entry_two.id()),
            ordered_index: entry_two.index,
            ordered_invocations: root_two,
            ..heads_one.clone()
        };
        store
            .publish_anchor(heads_one.id(), &entry_two, &heads_two)
            .unwrap();

        let acknowledgement = ReplayInput {
            runtime: input_two.runtime.clone(),
            operation: ReplayOperation::Acknowledge {
                invocation: invocation_two.clone(),
                authority: authority_two.clone(),
            },
        };
        let entry_three = OrderedEntry {
            genesis: genesis.id(),
            index: 3,
            parent: Some(entry_two.id()),
            merge_frontier: heads_two.merge_frontier,
            merge_seal: None,
            input: acknowledgement,
        };
        let (root_three, history_plan) = {
            let mut index = InvocationIndex::open(&mut store, root_two).unwrap();
            index.archive(key_two, owner_two).unwrap();
            (index.id(), index.history_write_plan().clone())
        };
        let heads_three = JournalHeads {
            publication_revision: heads_two.publication_revision + 1,
            previous: Some(heads_two.id()),
            ordered_head: Some(entry_three.id()),
            ordered_index: entry_three.index,
            ordered_invocations: root_three,
            ..heads_two.clone()
        };
        let queue = store.history_queue(genesis.id()).unwrap().clone();
        let history =
            build_history_candidate(&store, &heads_two, &heads_three, &[history_plan], &queue)
                .unwrap()
                .unwrap();
        store.install_history_candidate(&history).unwrap();
        store
            .publish_anchor(heads_three.previous.unwrap(), &entry_three, &heads_three)
            .unwrap();
        store.enqueue_history_retirement(&history.intent).unwrap();
        let (checkpoint_heads, _) = install_fresh_checkpoint(&mut store, &genesis);

        let result = store
            .collect_garbage(checkpoint_heads.id(), gc_limits())
            .unwrap();
        assert!(result.complete);
        assert_eq!(
            store.get::<OrderedEntry>(entry_one.id()).unwrap(),
            Some(entry_one)
        );
        assert_eq!(store.get::<OrderedEntry>(entry_two.id()).unwrap(), None);
        assert_eq!(
            store
                .get::<InvocationOutcomeRecord>(outcome_one.id())
                .unwrap(),
            Some(outcome_one.clone())
        );
        assert_eq!(
            store
                .get::<InvocationOutcomeRecord>(outcome_two.id())
                .unwrap(),
            None
        );
        let index = InvocationIndex::open(&mut store, root_three).unwrap();
        assert_eq!(index.outcome(key_one).unwrap(), Some(outcome_one));
        assert!(matches!(
            index.lookup(key_two).unwrap(),
            Some(InvocationIndexLookup::Archived(_))
        ));
    }

    #[test]
    fn checkpoint_publication_requires_every_raw_lane_and_catalog_blob() {
        let genesis = genesis();
        let config = config();
        let mut store =
            MemoryAgentJournalStore::new(config.identity.agent, config.replicas[0].node).unwrap();
        initialize(&mut store, &genesis);
        let initial = store.heads().unwrap().unwrap();
        let entry = first_ordered(&genesis, &initial);
        let ordered = ordered_successor(&initial, &entry);
        store
            .publish_anchor(initial.id(), &entry, &ordered)
            .unwrap();

        let local_entry = LocalEntry {
            genesis: genesis.id(),
            node: ordered.node,
            revision: 1,
            parent: None,
            ordered_base: ordered_base(&ordered),
            merge_frontier: ordered.merge_frontier,
            input: replay_input(MethodMode::Local, 0x32),
        };
        let coherent = JournalHeads {
            publication_revision: ordered.publication_revision + 1,
            previous: Some(ordered.id()),
            local_head: Some(local_entry.id()),
            local_revision: 1,
            ..ordered.clone()
        };
        store
            .publish_anchor(ordered.id(), &local_entry, &coherent)
            .unwrap();

        let state_bytes = b"canonical-control-lane";
        let state_reference = BlobRef::of_bytes(state_bytes);
        let control_lane = LaneStateManifest {
            genesis: genesis.id(),
            runtime: runtime_binding(),
            lane: PersistedLane::Control,
            cursor: LaneCursor::Ordered {
                base: ordered_base(&coherent),
            },
            state: state_reference.clone(),
        };
        store.put(&control_lane).unwrap();
        let linear_state_bytes = b"canonical-linear-lane";
        let linear_state_reference = BlobRef::of_bytes(linear_state_bytes);
        let linear_lane = LaneStateManifest {
            genesis: genesis.id(),
            runtime: runtime_binding(),
            lane: PersistedLane::Linear,
            cursor: LaneCursor::Ordered {
                base: ordered_base(&coherent),
            },
            state: linear_state_reference.clone(),
        };
        store.put(&linear_lane).unwrap();
        store
            .put_blob(
                JournalBlobClass::LaneState,
                &linear_state_reference,
                linear_state_bytes,
            )
            .unwrap();
        let merge_state_bytes = b"canonical-merge-lane";
        let merge_state_reference = BlobRef::of_bytes(merge_state_bytes);
        let merge_lane = LaneStateManifest {
            genesis: genesis.id(),
            runtime: runtime_binding(),
            lane: PersistedLane::Merge,
            cursor: LaneCursor::Merge {
                frontier: coherent.merge_frontier,
            },
            state: merge_state_reference.clone(),
        };
        store.put(&merge_lane).unwrap();
        store
            .put_blob(
                JournalBlobClass::LaneState,
                &merge_state_reference,
                merge_state_bytes,
            )
            .unwrap();
        let local_state_bytes = b"canonical-local-lane";
        let local_state_reference = BlobRef::of_bytes(local_state_bytes);
        let local_lane = LaneStateManifest {
            genesis: genesis.id(),
            runtime: runtime_binding(),
            lane: PersistedLane::Local,
            cursor: LaneCursor::Local {
                node: coherent.node,
                revision: coherent.local_revision,
                head: coherent.local_head,
            },
            state: local_state_reference.clone(),
        };
        store.put(&local_lane).unwrap();
        store
            .put_blob(
                JournalBlobClass::LaneState,
                &local_state_reference,
                local_state_bytes,
            )
            .unwrap();
        let closure = ArtifactClosure {
            genesis: genesis.id(),
            artifacts: vec![genesis.runtime().package.clone()],
        };
        store.put(&closure).unwrap();
        let checkpoint = CheckpointManifest {
            genesis: genesis.id(),
            admission: genesis.admission,
            runtime: runtime_binding(),
            publication_revision: coherent.publication_revision,
            ordered_head: coherent.ordered_head,
            ordered_index: coherent.ordered_index,
            merge_frontier: coherent.merge_frontier,
            merge_fence: coherent.merge_fence,
            merge_seal: coherent.merge_seal,
            ordered_invocations: coherent.ordered_invocations,
            merge_invocations: coherent.merge_invocations,
            lanes: vec![CheckpointLane {
                lane: PersistedLane::Control,
                node: None,
                state: control_lane.id(),
                invocations: None,
            }],
            artifacts: closure.id(),
        };
        let stale_local_next = JournalHeads {
            publication_revision: coherent.publication_revision + 1,
            previous: Some(coherent.id()),
            checkpoint: Some(checkpoint.id()),
            ..coherent.clone()
        };
        assert_eq!(
            store.publish_anchor(coherent.id(), &checkpoint, &stale_local_next),
            Err(JournalStoreError::NonCanonical)
        );
        assert_eq!(store.heads().unwrap(), Some(coherent.clone()));

        let checkpoint = CheckpointManifest {
            lanes: vec![
                CheckpointLane {
                    lane: PersistedLane::Control,
                    node: None,
                    state: control_lane.id(),
                    invocations: None,
                },
                CheckpointLane {
                    lane: PersistedLane::Linear,
                    node: None,
                    state: linear_lane.id(),
                    invocations: None,
                },
                CheckpointLane {
                    lane: PersistedLane::Merge,
                    node: None,
                    state: merge_lane.id(),
                    invocations: None,
                },
                CheckpointLane {
                    lane: PersistedLane::Local,
                    node: Some(coherent.node),
                    state: local_lane.id(),
                    invocations: Some(coherent.local_invocations),
                },
            ],
            ..checkpoint
        };
        let next = JournalHeads {
            checkpoint: Some(checkpoint.id()),
            ..stale_local_next
        };
        assert_eq!(
            store.publish_anchor(coherent.id(), &checkpoint, &next),
            Err(JournalStoreError::MissingObject)
        );
        store
            .put_blob(JournalBlobClass::LaneState, &state_reference, state_bytes)
            .unwrap();
        store
            .publish_anchor(coherent.id(), &checkpoint, &next)
            .unwrap();
        assert_eq!(store.heads().unwrap(), Some(next));
    }

    fn merge_event(
        genesis: &AgentJournalGenesis,
        parents: Vec<MergeEventId>,
        height: u64,
        discriminator: u8,
    ) -> MergeEvent {
        MergeEvent {
            genesis: genesis.id(),
            author: NodeId([discriminator; 32]),
            ordered_base: OrderedBase::post_genesis(),
            causal_height: height,
            parents,
            input: replay_input(MethodMode::Merge, discriminator),
            signature: vec![discriminator; ED25519_SIGNATURE_BYTES],
        }
    }

    fn merge_successor(
        store: &mut MemoryAgentJournalStore,
        heads: &JournalHeads,
        mut events: Vec<MergeEventId>,
    ) -> JournalHeads {
        events.sort_unstable();
        events.dedup();
        let frontier = MergeFrontier {
            genesis: heads.genesis,
            events,
        };
        store.put(&frontier).unwrap();
        JournalHeads {
            publication_revision: heads.publication_revision + 1,
            previous: Some(heads.id()),
            merge_frontier: frontier.id(),
            ..heads.clone()
        }
    }

    #[test]
    fn merge_publication_keeps_unrelated_tips_and_removes_only_ancestors() {
        let genesis = genesis();
        let config = config();
        let mut store =
            MemoryAgentJournalStore::new(config.identity.agent, config.replicas[0].node).unwrap();
        initialize(&mut store, &genesis);
        let initial = store.heads().unwrap().unwrap();

        let first = merge_event(&genesis, Vec::new(), 1, 0x41);
        let first_heads = merge_successor(&mut store, &initial, vec![first.id()]);
        store
            .publish_anchor(initial.id(), &first, &first_heads)
            .unwrap();

        let concurrent = merge_event(&genesis, Vec::new(), 1, 0x42);
        let mut concurrent_tips = vec![first.id(), concurrent.id()];
        concurrent_tips.sort_unstable();
        let concurrent_heads = merge_successor(&mut store, &first_heads, concurrent_tips);
        store
            .publish_anchor(first_heads.id(), &concurrent, &concurrent_heads)
            .unwrap();

        let descendant = merge_event(&genesis, vec![first.id()], 2, 0x43);
        let dropping = merge_successor(&mut store, &concurrent_heads, vec![descendant.id()]);
        assert_eq!(
            store.publish_anchor(concurrent_heads.id(), &descendant, &dropping),
            Err(JournalStoreError::NonCanonical)
        );
        assert_eq!(store.heads().unwrap(), Some(concurrent_heads.clone()));

        let mut correct_tips = vec![concurrent.id(), descendant.id()];
        correct_tips.sort_unstable();
        let correct = merge_successor(&mut store, &concurrent_heads, correct_tips);
        store
            .publish_anchor(concurrent_heads.id(), &descendant, &correct)
            .unwrap();
        assert_eq!(store.heads().unwrap(), Some(correct));
    }

    #[test]
    fn checkpoint_boundary_rejects_pruned_internal_merge_parents() {
        let genesis = genesis();
        let config = config();
        let mut store =
            MemoryAgentJournalStore::new(config.identity.agent, config.replicas[0].node).unwrap();
        initialize(&mut store, &genesis);
        let initial = store.heads().unwrap().unwrap();

        let internal = merge_event(&genesis, Vec::new(), 1, 0x51);
        let internal_heads = merge_successor(&mut store, &initial, vec![internal.id()]);
        store
            .publish_anchor(initial.id(), &internal, &internal_heads)
            .unwrap();
        let boundary_tip = merge_event(&genesis, vec![internal.id()], 2, 0x52);
        let boundary_heads = merge_successor(&mut store, &internal_heads, vec![boundary_tip.id()]);
        store
            .publish_anchor(internal_heads.id(), &boundary_tip, &boundary_heads)
            .unwrap();

        let state_bytes = b"checkpoint-control";
        let state = BlobRef::of_bytes(state_bytes);
        let control = LaneStateManifest {
            genesis: genesis.id(),
            runtime: boundary_heads.runtime.clone(),
            lane: PersistedLane::Control,
            cursor: LaneCursor::Ordered {
                base: ordered_base(&boundary_heads),
            },
            state: state.clone(),
        };
        store.put(&control).unwrap();
        let linear = LaneStateManifest {
            lane: PersistedLane::Linear,
            ..control.clone()
        };
        store.put(&linear).unwrap();
        let merge = LaneStateManifest {
            lane: PersistedLane::Merge,
            cursor: LaneCursor::Merge {
                frontier: boundary_heads.merge_frontier,
            },
            ..control.clone()
        };
        store.put(&merge).unwrap();
        let local = LaneStateManifest {
            lane: PersistedLane::Local,
            cursor: LaneCursor::Local {
                node: boundary_heads.node,
                revision: 0,
                head: None,
            },
            ..control.clone()
        };
        store.put(&local).unwrap();
        store
            .put_blob(JournalBlobClass::LaneState, &state, state_bytes)
            .unwrap();
        let artifacts = ArtifactClosure {
            genesis: genesis.id(),
            artifacts: vec![boundary_heads.runtime.package.clone()],
        };
        store.put(&artifacts).unwrap();
        let checkpoint = CheckpointManifest {
            genesis: genesis.id(),
            admission: genesis.admission,
            runtime: boundary_heads.runtime.clone(),
            publication_revision: boundary_heads.publication_revision,
            ordered_head: boundary_heads.ordered_head,
            ordered_index: boundary_heads.ordered_index,
            merge_frontier: boundary_heads.merge_frontier,
            merge_fence: boundary_heads.merge_fence,
            merge_seal: boundary_heads.merge_seal,
            ordered_invocations: boundary_heads.ordered_invocations,
            merge_invocations: boundary_heads.merge_invocations,
            lanes: vec![
                CheckpointLane {
                    lane: PersistedLane::Control,
                    node: None,
                    state: control.id(),
                    invocations: None,
                },
                CheckpointLane {
                    lane: PersistedLane::Linear,
                    node: None,
                    state: linear.id(),
                    invocations: None,
                },
                CheckpointLane {
                    lane: PersistedLane::Merge,
                    node: None,
                    state: merge.id(),
                    invocations: None,
                },
                CheckpointLane {
                    lane: PersistedLane::Local,
                    node: Some(boundary_heads.node),
                    state: local.id(),
                    invocations: Some(boundary_heads.local_invocations),
                },
            ],
            artifacts: artifacts.id(),
        };
        let checkpoint_heads = JournalHeads {
            publication_revision: boundary_heads.publication_revision + 1,
            previous: Some(boundary_heads.id()),
            checkpoint: Some(checkpoint.id()),
            ..boundary_heads.clone()
        };
        store
            .publish_anchor(boundary_heads.id(), &checkpoint, &checkpoint_heads)
            .unwrap();

        let stale_branch = merge_event(&genesis, vec![internal.id()], 2, 0x53);
        store.put(&stale_branch).unwrap();
        let stale_heads = merge_successor(
            &mut store,
            &checkpoint_heads,
            vec![boundary_tip.id(), stale_branch.id()],
        );
        assert_eq!(
            store.publish_anchor(checkpoint_heads.id(), &stale_branch, &stale_heads),
            Err(JournalStoreError::NonCanonical)
        );

        // Simulate GC below the authenticated checkpoint frontier. Reopening
        // and suffix validation must not require the pruned internal parent.
        store
            .objects
            .remove(&(JournalStorageClass::MergeEvent, *internal.id().as_bytes()));
        validate_head_targets(&store, &checkpoint_heads).unwrap();

        // A bounded imported branch may contain unpublished intermediate
        // events, provided every causal path reaches the retained suffix.
        let imported_parent = merge_event(&genesis, vec![boundary_tip.id()], 3, 0x54);
        store.put(&imported_parent).unwrap();
        let retained_child = merge_event(&genesis, vec![imported_parent.id()], 4, 0x55);
        let retained_heads =
            merge_successor(&mut store, &checkpoint_heads, vec![retained_child.id()]);
        store
            .publish_anchor(checkpoint_heads.id(), &retained_child, &retained_heads)
            .unwrap();
    }

    #[test]
    fn file_store_persists_and_resolves_nonempty_invocation_index() {
        let directory = TestDirectory::new("invocation-index");
        let genesis = genesis();
        let mut store = open_file_store(&directory);
        initialize(&mut store, &genesis);
        let heads = store.heads().unwrap().unwrap();
        let input = replay_input(MethodMode::Linear, 0x61);
        let ReplayOperation::Invoke { invocation, .. } = &input.operation else {
            unreachable!()
        };
        let key = InvocationOwnershipKey {
            scope: InvocationOwnershipScope::Ordered,
            invocation: invocation.invocation,
        };
        let mut index = InvocationIndex::open(&mut store, heads.ordered_invocations).unwrap();
        let outcome = InvocationOutcomeRecord::from_runtime_states(
            genesis.id(),
            key.scope,
            InvocationOutcomeAnchor::Ordered {
                entry: OrderedEntryId([0x62; 32]),
            },
            &input,
            &RuntimeState::default(),
            &RuntimeState::default(),
            Ok(ActorExecutionReply {
                invocation: invocation.invocation,
                actor: invocation.actor,
                incarnation: invocation.incarnation,
                deployment: invocation.deployment,
                mode: invocation.mode,
                lane: invocation.mode.write_lane(),
                status: ActorExecutionStatus::Done,
                reply: vec![0x63],
                gas_remaining: invocation.gas - 1,
                observation: ActorObservation::default(),
            }),
        )
        .unwrap();
        let expected_outcome = outcome.clone();
        let outcome = index.persist_outcome(&outcome).unwrap();
        let owner = InvocationOwner {
            scope: key.scope,
            request_commitment: invocation.commitment(),
            first_input: input.id(),
            lane: PersistedLane::Linear,
            node: None,
            result_state: InvocationResultState::Retained {
                disposition: InvocationDisposition::Applied,
                outcome,
            },
        };
        index.record(key, owner).unwrap();
        let index_id = index.id();
        assert_ne!(index_id, heads.ordered_invocations);
        let manifest = validate_invocation_index(
            &store,
            index_id,
            genesis.id(),
            InvocationOwnershipScope::Ordered,
        )
        .unwrap();
        assert!(manifest.root.is_some());

        drop(store);
        let mut reopened = open_file_store(&directory);
        validate_invocation_index(
            &reopened,
            index_id,
            genesis.id(),
            InvocationOwnershipScope::Ordered,
        )
        .unwrap();
        let reopened_index = InvocationIndex::open(&mut reopened, index_id).unwrap();
        assert_eq!(
            reopened_index.lookup(key).unwrap(),
            Some(InvocationIndexLookup::Live(owner))
        );
        assert_eq!(reopened_index.outcome(key).unwrap(), Some(expected_outcome));
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn file_history_candidate_recovers_every_durable_crash_state() {
        for crash_at in [
            PublicationPoint::HistoryCandidateDurable,
            PublicationPoint::ObjectDurable,
            PublicationPoint::HeadsStaged,
            PublicationPoint::HeadsDurable,
            PublicationPoint::HistoryPromoted,
            PublicationPoint::HistoryRetirementDurable,
            PublicationPoint::HistoryCandidateCleared,
        ] {
            let directory = TestDirectory::new("history-crash");
            let genesis = genesis();
            let mut store = open_file_store(&directory);
            initialize(&mut store, &genesis);
            let current = store.heads().unwrap().unwrap();
            let transition = prepare_history_transition(&mut store, &genesis, &current, 0x71);
            let queue = store.history_queue(genesis.id()).unwrap();
            let history = build_test_history_candidate(&store, &current, &transition, &queue);
            let writes = transition
                .plan
                .overlay_nodes()
                .iter()
                .map(|write| (write.id(), write.bytes().to_vec()))
                .collect::<Vec<_>>();
            let first = InvocationHistoryNode::decode(&writes[0].1).unwrap();
            assert_eq!(
                store.put(&first),
                Err(JournalStoreError::InvalidClass),
                "generic puts must reject the permanent namespace"
            );

            let mut crash = |point| {
                if point == crash_at {
                    Err(JournalStoreError::Unavailable)
                } else {
                    Ok(())
                }
            };
            let attempted = (|| {
                store.stage_history_candidate(history.clone(), &mut crash)?;
                store.publish_inner(
                    current.id(),
                    &transition.entry,
                    &transition.next,
                    &mut crash,
                )?;
                store.finish_history_candidate(&mut crash)?;
                Ok::<(), JournalStoreError>(())
            })();
            assert_eq!(attempted, Err(JournalStoreError::Unavailable));
            drop(store);

            let mut reopened = open_file_store(&directory);
            match crash_at {
                PublicationPoint::AuthorityDependenciesDurable => {
                    unreachable!("history-only publication has no authority dependency phase")
                }
                PublicationPoint::HistoryCandidateDurable | PublicationPoint::ObjectDurable => {
                    assert_eq!(reopened.heads().unwrap(), Some(current.clone()));
                    assert!(reopened.history_candidate.is_none());
                    assert!(
                        writes.iter().all(|(id, _)| reopened
                            .read_global_history_node(*id)
                            .unwrap()
                            .is_none())
                    );
                    let queue = reopened.history_queue(genesis.id()).unwrap();
                    let history =
                        build_test_history_candidate(&reopened, &current, &transition, &queue);
                    reopened
                        .stage_history_candidate(history, &mut |_| Ok(()))
                        .unwrap();
                    reopened
                        .publish_inner(
                            current.id(),
                            &transition.entry,
                            &transition.next,
                            |_| Ok(()),
                        )
                        .unwrap();
                    reopened.finish_history_candidate(&mut |_| Ok(())).unwrap();
                }
                PublicationPoint::HeadsStaged => {
                    assert_eq!(reopened.heads().unwrap(), Some(current.clone()));
                    assert!(reopened.history_candidate.is_some());
                    assert!(reopened.root().join("heads.next").is_file());
                    reopened
                        .publish_inner(
                            current.id(),
                            &transition.entry,
                            &transition.next,
                            |_| Ok(()),
                        )
                        .unwrap();
                    reopened.finish_history_candidate(&mut |_| Ok(())).unwrap();
                }
                PublicationPoint::HeadsDurable
                | PublicationPoint::HistoryPromoted
                | PublicationPoint::HistoryRetirementDurable
                | PublicationPoint::HistoryCandidateCleared => {
                    // Reopen completes candidate promotion and retirement
                    // publication before authenticating the new head target.
                    assert_eq!(reopened.heads().unwrap(), Some(transition.next.clone()));
                }
            }

            assert_eq!(reopened.heads().unwrap(), Some(transition.next.clone()));
            assert!(reopened.history_candidate.is_none());
            assert!(!reopened.root().join("heads.next").exists());
            assert!(
                fs::read_dir(reopened.root().join(HISTORY_CANDIDATE_DIRECTORY))
                    .unwrap()
                    .next()
                    .is_none()
            );
            assert!(
                !reopened
                    .root()
                    .join(HISTORY_DIRECTORY)
                    .join(HISTORY_CANDIDATE_INTENT_NAME)
                    .exists()
            );
            for (id, bytes) in &writes {
                assert_eq!(
                    reopened.read_global_history_node(*id).unwrap(),
                    Some(bytes.clone())
                );
                let path = history_node_path(reopened.root(), *id);
                assert!(path.is_file(), "history node must use its first-byte shard");
                assert!(!path.with_extension("next").exists());
            }
            let queue = reopened.history_queue(genesis.id()).unwrap();
            assert_eq!(queue.records.len(), 1);
            let index =
                InvocationIndex::open(&mut reopened, transition.next.ordered_invocations).unwrap();
            assert_eq!(
                index.lookup(transition.key).unwrap(),
                Some(InvocationIndexLookup::Archived(transition.fact))
            );
        }
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn file_history_stale_cas_is_zero_write_and_reopen_rejects_tampering() {
        let genesis = genesis();

        let stale_directory = TestDirectory::new("history-stale");
        let mut stale = open_file_store(&stale_directory);
        initialize(&mut stale, &genesis);
        let current = stale.heads().unwrap().unwrap();
        let transition = prepare_history_transition(&mut stale, &genesis, &current, 0x72);
        let competing_entry = OrderedEntry {
            genesis: genesis.id(),
            index: 1,
            parent: None,
            merge_frontier: current.merge_frontier,
            merge_seal: None,
            input: replay_input(MethodMode::Linear, 0x73),
        };
        let competing = ordered_successor(&current, &competing_entry);
        stale
            .publish_inner(current.id(), &competing_entry, &competing, |_| Ok(()))
            .unwrap();
        let durable = stale.heads().unwrap().unwrap();
        assert_eq!(durable, competing);
        let heads_before = fs::read(stale.root().join("heads")).unwrap();
        let mut reached_write_point = false;
        assert!(matches!(
            stale.stage_sealed_history_candidate(
                current.id(),
                &transition.next,
                core::slice::from_ref(&transition.plan),
                &mut |_| {
                    reached_write_point = true;
                    Ok(())
                },
            ),
            Err(JournalStoreError::Conflict)
        ));
        assert!(!reached_write_point);
        assert_eq!(fs::read(stale.root().join("heads")).unwrap(), heads_before);
        assert!(
            stale
                .read_history_queue_file(HISTORY_RETIREMENTS_NAME)
                .unwrap()
                .is_none()
        );
        assert!(transition.plan.overlay_nodes().iter().all(|write| {
            stale
                .read_global_history_node(write.id())
                .unwrap()
                .is_none()
        }));
        assert!(
            fs::read_dir(stale.root().join(HISTORY_CANDIDATE_DIRECTORY))
                .unwrap()
                .next()
                .is_none()
        );

        // Exact crash state after authority-first cleanup: once the intent is
        // durably absent, leftover plan provenance is private garbage and a
        // reopen must discard it without installing any global node.
        let cleanup_directory = TestDirectory::new("history-cleanup-crash");
        let mut cleanup = open_file_store(&cleanup_directory);
        initialize(&mut cleanup, &genesis);
        let current = cleanup.heads().unwrap().unwrap();
        let transition = prepare_history_transition(&mut cleanup, &genesis, &current, 0x76);
        let queue = cleanup.history_queue(genesis.id()).unwrap();
        let history = build_test_history_candidate(&cleanup, &current, &transition, &queue);
        cleanup
            .stage_history_candidate(history, &mut |_| Ok(()))
            .unwrap();
        let cleanup_plan = cleanup
            .root()
            .join(HISTORY_CANDIDATE_DIRECTORY)
            .join("plan-0");
        assert!(cleanup_plan.is_file());
        unlink_file_at(
            cleanup.directory(HISTORY_DIRECTORY).unwrap(),
            HISTORY_CANDIDATE_INTENT_NAME,
        )
        .unwrap();
        cleanup
            .directory(HISTORY_DIRECTORY)
            .unwrap()
            .sync_all()
            .unwrap();
        drop(cleanup);
        let cleanup = open_file_store(&cleanup_directory);
        assert!(!cleanup_plan.exists());
        assert_eq!(cleanup.heads().unwrap(), Some(current));
        assert!(transition.plan.overlay_nodes().iter().all(|write| {
            cleanup
                .read_global_history_node(write.id())
                .unwrap()
                .is_none()
        }));
        drop(cleanup);

        let plan_directory = TestDirectory::new("history-plan-tamper");
        let mut staged = open_file_store(&plan_directory);
        initialize(&mut staged, &genesis);
        let current = staged.heads().unwrap().unwrap();
        let transition = prepare_history_transition(&mut staged, &genesis, &current, 0x74);
        let queue = staged.history_queue(genesis.id()).unwrap();
        let history = build_test_history_candidate(&staged, &current, &transition, &queue);
        staged
            .stage_history_candidate(history, &mut |_| Ok(()))
            .unwrap();
        let plan_path = staged
            .root()
            .join(HISTORY_CANDIDATE_DIRECTORY)
            .join("plan-0");
        drop(staged);
        fs::write(plan_path, b"tampered candidate plan").unwrap();
        assert!(matches!(
            FileAgentJournalStore::open_unverified_for_test(
                plan_directory.agent_root(config().identity.agent),
                plan_directory.lock(config().identity.agent),
                config().replicas[0].node,
            ),
            Err(JournalStoreError::Corrupt)
        ));

        let node_directory = TestDirectory::new("history-node-tamper");
        let mut committed = open_file_store(&node_directory);
        initialize(&mut committed, &genesis);
        let transition = commit_file_history_transition(&mut committed, &genesis, 0x75);
        let root = transition.plan.root().unwrap();
        let node_path = history_node_path(committed.root(), root);
        drop(committed);
        fs::write(node_path, b"tampered permanent root").unwrap();
        assert!(matches!(
            FileAgentJournalStore::open_unverified_for_test(
                node_directory.agent_root(config().identity.agent),
                node_directory.lock(config().identity.agent),
                config().replicas[0].node,
            ),
            Err(JournalStoreError::Corrupt)
        ));
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn file_history_retirement_gc_resumes_crash_and_preserves_current_facts() {
        for crash_at in [
            GcPoint::HistoryRetirementStaged,
            GcPoint::HistoryRetirementSweepDurable,
            GcPoint::HistoryRetirementCursorDurable,
        ] {
            let directory = TestDirectory::new("history-retirement-gc");
            let genesis = genesis();
            let mut store = open_file_store(&directory);
            initialize(&mut store, &genesis);

            let transitions = (0x81..=0x85)
                .map(|discriminator| {
                    commit_file_history_transition(&mut store, &genesis, discriminator)
                })
                .collect::<Vec<_>>();
            let retired = transitions
                .iter()
                .flat_map(|transition| transition.plan.retired_node_ids().iter().copied())
                .collect::<Vec<_>>();
            assert!(
                !retired.is_empty(),
                "three or more Patricia insertions must replace a global path node"
            );
            assert!(
                retired
                    .iter()
                    .all(|id| store.read_global_history_node(*id).unwrap().is_some())
            );
            let final_root = transitions.last().unwrap().plan.root().unwrap();
            let final_root_bytes = store.read_global_history_node(final_root).unwrap().unwrap();

            let (checkpoint_heads, _) = install_fresh_checkpoint(&mut store, &genesis);
            let mut limits = gc_limits();
            limits.max_unlinks_per_run = 1;
            let queue = store.history_queue(genesis.id()).unwrap();
            let (_, first_batch) = advance_history_retirement_queue(&queue, 1).unwrap();
            assert_eq!(first_batch.len(), 1);
            let staged_path = history_node_path(store.root(), first_batch[0]);
            let staged_alias = staged_path.with_extension("next");
            fs::hard_link(&staged_path, &staged_alias).unwrap();
            assert_eq!(
                store.collect_garbage_inner(checkpoint_heads.id(), limits, |point| {
                    if point == crash_at {
                        Err(JournalStoreError::Unavailable)
                    } else {
                        Ok(())
                    }
                }),
                Err(JournalStoreError::Unavailable)
            );
            assert!(store.root().join(GC_INTENT_NAME).is_file());
            assert_eq!(
                store
                    .root()
                    .join(HISTORY_DIRECTORY)
                    .join(HISTORY_RETIREMENTS_STAGE_NAME)
                    .exists(),
                crash_at != GcPoint::HistoryRetirementCursorDurable
            );
            assert_eq!(
                store.put(&replay_input(MethodMode::Linear, 0x86)),
                Err(JournalStoreError::GcPending)
            );
            drop(store);

            let mut reopened = open_file_store(&directory);
            let mut passes = 0usize;
            loop {
                let result = reopened
                    .collect_garbage(checkpoint_heads.id(), limits)
                    .unwrap();
                passes += 1;
                assert!(result.resumed);
                if result.complete {
                    break;
                }
                assert!(passes < 256, "bounded GC failed to drain its durable work");
            }
            assert!(!staged_alias.exists());
            assert!(
                retired
                    .iter()
                    .all(|id| reopened.read_global_history_node(*id).unwrap().is_none())
            );
            assert_eq!(
                reopened.read_global_history_node(final_root).unwrap(),
                Some(final_root_bytes)
            );
            assert!(
                reopened
                    .read_history_queue_file(HISTORY_RETIREMENTS_NAME)
                    .unwrap()
                    .is_none()
            );
            assert!(
                reopened
                    .read_history_queue_file(HISTORY_RETIREMENTS_STAGE_NAME)
                    .unwrap()
                    .is_none()
            );
            let index =
                InvocationIndex::open(&mut reopened, checkpoint_heads.ordered_invocations).unwrap();
            for transition in &transitions {
                assert_eq!(
                    index.lookup(transition.key).unwrap(),
                    Some(InvocationIndexLookup::Archived(transition.fact))
                );
            }
        }
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn file_gc_resumes_a_crash_staged_intent_and_gates_mutators() {
        let directory = TestDirectory::new("gc-crash");
        let genesis = genesis();
        let mut store = open_file_store(&directory);
        initialize(&mut store, &genesis);
        let (heads, _) = install_fresh_checkpoint(&mut store, &genesis);
        let garbage = replay_input(MethodMode::Linear, 0xb1);
        store.put(&garbage).unwrap();
        let garbage_path = store
            .root()
            .join("records/replay-inputs")
            .join(encode_hex(garbage.id().as_bytes()));

        assert_eq!(
            store.collect_garbage_inner(heads.id(), gc_limits(), |point| {
                if point == GcPoint::IntentStaged {
                    Err(JournalStoreError::Unavailable)
                } else {
                    Ok(())
                }
            }),
            Err(JournalStoreError::Unavailable)
        );
        assert!(store.root().join(GC_INTENT_STAGE_NAME).is_file());
        assert_eq!(
            store.put(&replay_input(MethodMode::Linear, 0xb2)),
            Err(JournalStoreError::GcPending)
        );

        drop(store);
        let mut reopened = open_file_store(&directory);
        let result = reopened.collect_garbage(heads.id(), gc_limits()).unwrap();
        assert!(result.resumed);
        assert!(result.complete);
        assert!(!garbage_path.exists());
        assert!(!reopened.root().join(GC_INTENT_NAME).exists());
        assert!(!reopened.root().join(GC_INTENT_STAGE_NAME).exists());
        validate_head_targets(&reopened, &heads).unwrap();
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn file_gc_preflight_rejects_nonregular_entry_before_intent_or_deletion() {
        use std::os::unix::fs::symlink;

        let directory = TestDirectory::new("gc-symlink");
        let genesis = genesis();
        let mut store = open_file_store(&directory);
        initialize(&mut store, &genesis);
        let (heads, checkpoint) = install_fresh_checkpoint(&mut store, &genesis);
        let garbage = replay_input(MethodMode::Linear, 0xb3);
        store.put(&garbage).unwrap();
        let garbage_path = store
            .root()
            .join("records/replay-inputs")
            .join(encode_hex(garbage.id().as_bytes()));
        let hostile = store
            .root()
            .join("records/replay-inputs")
            .join(encode_hex(&[0xee; 32]));
        symlink(&garbage_path, &hostile).unwrap();

        assert_eq!(
            store.collect_garbage(heads.id(), gc_limits()),
            Err(JournalStoreError::Corrupt)
        );
        assert!(garbage_path.is_file());
        assert!(
            store
                .get::<CheckpointManifest>(checkpoint.id())
                .unwrap()
                .is_some()
        );
        assert!(!store.root().join(GC_INTENT_NAME).exists());
        assert!(!store.root().join(GC_INTENT_STAGE_NAME).exists());
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn file_gc_second_pass_rejects_namespace_replacement() {
        let directory = TestDirectory::new("gc-race");
        let genesis = genesis();
        let mut store = open_file_store(&directory);
        initialize(&mut store, &genesis);
        let (heads, _) = install_fresh_checkpoint(&mut store, &genesis);
        let garbage = replay_input(MethodMode::Linear, 0xb4);
        store.put(&garbage).unwrap();
        let garbage_path = store
            .root()
            .join("records/replay-inputs")
            .join(encode_hex(garbage.id().as_bytes()));
        let displaced = garbage_path.with_extension("displaced");
        let mut replaced = false;

        assert_eq!(
            store.collect_garbage_inner(heads.id(), gc_limits(), |point| {
                if point == GcPoint::IntentDurable && !replaced {
                    fs::rename(&garbage_path, &displaced).unwrap();
                    fs::write(&garbage_path, b"replacement-must-not-be-unlinked").unwrap();
                    replaced = true;
                }
                Ok(())
            }),
            Err(JournalStoreError::Corrupt)
        );
        assert_eq!(
            fs::read(&garbage_path).unwrap(),
            b"replacement-must-not-be-unlinked"
        );
        assert!(store.root().join(GC_INTENT_NAME).is_file());
        assert_eq!(
            store.put(&replay_input(MethodMode::Linear, 0xb5)),
            Err(JournalStoreError::GcPending)
        );
    }

    #[test]
    fn file_publication_recovers_each_durable_crash_boundary() {
        for crash_at in [
            PublicationPoint::ObjectDurable,
            PublicationPoint::HeadsStaged,
            PublicationPoint::HeadsDurable,
        ] {
            let directory = TestDirectory::new("crash");
            let genesis = genesis();
            let mut store = open_file_store(&directory);
            initialize(&mut store, &genesis);
            let initial = store.heads().unwrap().unwrap();
            let entry = first_ordered(&genesis, &initial);
            let next = ordered_successor(&initial, &entry);
            assert_eq!(
                store.publish_inner(initial.id(), &entry, &next, |point| {
                    if point == crash_at {
                        Err(JournalStoreError::Unavailable)
                    } else {
                        Ok(())
                    }
                }),
                Err(JournalStoreError::Unavailable)
            );
            drop(store);

            let mut reopened = open_file_store(&directory);
            let recovered = reopened.heads().unwrap().unwrap();
            if crash_at == PublicationPoint::HeadsDurable {
                assert_eq!(recovered, next);
            } else {
                assert_eq!(recovered, initial);
            }
            reopened
                .publish_anchor(initial.id(), &entry, &next)
                .unwrap();
            assert_eq!(reopened.heads().unwrap(), Some(next));
            assert!(!reopened.root().join("heads.next").exists());
        }
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn reopen_discards_partial_private_genesis_admission_and_heads_stages() {
        let directory = TestDirectory::new("partial-fixed-stage");
        let genesis = genesis();
        let store = open_file_store(&directory);
        let root = store.root().to_path_buf();
        for name in [
            "genesis-admission.next.partial",
            "genesis.next.partial",
            "heads.next.partial",
        ] {
            fs::write(root.join(name), b"short write").unwrap();
        }
        drop(store);

        let mut reopened = open_file_store(&directory);
        for name in [
            "genesis-admission.next.partial",
            "genesis.next.partial",
            "heads.next.partial",
        ] {
            assert!(!root.join(name).exists());
        }
        initialize(&mut reopened, &genesis);
        assert_eq!(reopened.genesis().unwrap(), Some(genesis));
        assert!(reopened.heads().unwrap().is_some());
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn reopen_rejects_mixed_legacy_genesis_and_heads_stages() {
        for (index, stage) in ["genesis.next", "heads.next"].into_iter().enumerate() {
            let directory = TestDirectory::new("legacy-fixed-stage");
            let genesis = genesis();
            let mut store = open_file_store(&directory);
            initialize(&mut store, &genesis);
            let mut legacy = if index == 0 {
                genesis.encode()
            } else {
                store.heads().unwrap().unwrap().encode()
            };
            legacy[..4].copy_from_slice(if index == 0 { b"AGJG" } else { b"AGJH" });
            let stage_path = store.root().join(stage);
            fs::write(&stage_path, legacy).unwrap();
            drop(store);

            let config = config();
            assert!(matches!(
                FileAgentJournalStore::open_unverified_for_test(
                    directory.agent_root(config.identity.agent),
                    directory.lock(config.identity.agent),
                    config.replicas[0].node,
                ),
                Err(JournalStoreError::Corrupt)
            ));
            assert!(stage_path.exists());
        }
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn reopen_discards_partial_private_object_and_blob_stages() {
        let directory = TestDirectory::new("partial-content-stage");
        let genesis = genesis();
        let mut store = open_file_store(&directory);
        initialize(&mut store, &genesis);
        let heads = store.heads().unwrap().unwrap();
        let entry = first_ordered(&genesis, &heads);
        let object_stage = store.root().join("records/ordered").join(format!(
            "{}.next.partial",
            encode_hex(entry.id().as_bytes())
        ));
        let blob_bytes = b"catalog object after interrupted staging";
        let blob = BlobRef::of_bytes(blob_bytes);
        let blob_stage = store
            .root()
            .join("catalog/blobs")
            .join(format!("{}.next.partial", encode_hex(blob.hash.as_bytes())));
        fs::write(&object_stage, &entry.encode()[..3]).unwrap();
        fs::write(&blob_stage, &blob_bytes[..3]).unwrap();
        drop(store);

        let mut reopened = open_file_store(&directory);
        assert!(!object_stage.exists());
        assert!(!blob_stage.exists());
        assert!(reopened.put(&entry).unwrap());
        assert!(
            reopened
                .put_blob(JournalBlobClass::CatalogArtifact, &blob, blob_bytes)
                .unwrap()
        );
        assert_eq!(reopened.get(entry.id()).unwrap(), Some(entry));
        assert_eq!(
            reopened
                .load_blob(JournalBlobClass::CatalogArtifact, &blob)
                .unwrap(),
            Some(blob_bytes.to_vec())
        );
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn reopen_never_discards_a_recognized_partial_stage() {
        let directory = TestDirectory::new("recognized-partial-stage");
        let genesis = genesis();
        let mut store = open_file_store(&directory);
        initialize(&mut store, &genesis);
        let stage = store.root().join("heads.next");
        fs::write(&stage, b"short write").unwrap();
        drop(store);

        let config = config();
        assert!(matches!(
            FileAgentJournalStore::open(
                directory.agent_root(config.identity.agent),
                directory.lock(config.identity.agent),
                config.replicas[0].node,
            ),
            Err(JournalStoreError::Corrupt)
        ));
        assert!(stage.exists());
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn authority_closure_is_durable_and_reopen_requires_exact_reverification() {
        let directory = TestDirectory::new("authority-reopen");
        let sealed = crate::agent::replay::tests::admitted_genesis(0xb1);
        let mut store = open_file_store_for_sealed(&directory, &sealed);
        initialize_sealed_file_store(&mut store, &sealed);
        let root = store.root().to_path_buf();
        for (_, path) in authority_paths(&root, &sealed) {
            assert!(path.is_file());
            assert!(!path.with_extension("next").exists());
        }
        drop(store);

        assert!(matches!(
            FileAgentJournalStore::open(
                directory.agent_root(sealed.genesis().runtime().agent),
                directory.lock(sealed.genesis().runtime().agent),
                sealed.replica().node,
            ),
            Err(JournalStoreError::Unavailable)
        ));
        let reopened = reopen_file_store_reverified(&directory, &sealed).unwrap();
        assert_eq!(reopened.genesis().unwrap(), Some(sealed.genesis().clone()));
        assert_eq!(reopened.heads().unwrap(), Some(sealed.initial_heads()));
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn authority_reopen_rejects_a_different_valid_seal() {
        let directory = TestDirectory::new("authority-wrong-seal");
        let sealed = crate::agent::replay::tests::admitted_genesis(0xba);
        let alternate = crate::agent::replay::tests::admitted_genesis(0xbb);
        assert_eq!(
            sealed.genesis().runtime().agent,
            alternate.genesis().runtime().agent
        );
        assert_eq!(sealed.replica(), alternate.replica());
        let mut store = open_file_store_for_sealed(&directory, &sealed);
        initialize_sealed_file_store(&mut store, &sealed);
        drop(store);

        assert!(matches!(
            reopen_file_store_reverified(&directory, &alternate),
            Err(JournalStoreError::ScopeMismatch)
        ));
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn authority_partial_private_stages_are_discarded_before_initialization() {
        let directory = TestDirectory::new("authority-partial-stage");
        let sealed = crate::agent::replay::tests::admitted_genesis(0xb2);
        let store = open_file_store_for_sealed(&directory, &sealed);
        let root = store.root().to_path_buf();
        let partials = authority_paths(&root, &sealed)
            .map(|(_, path)| PathBuf::from(format!("{}.next.partial", path.display())));
        for path in &partials {
            fs::write(path, b"short write").unwrap();
        }
        drop(store);

        let mut reopened = open_file_store_for_sealed(&directory, &sealed);
        for path in &partials {
            assert!(!path.exists());
        }
        initialize_sealed_file_store(&mut reopened, &sealed);
        drop(reopened);
        reopen_file_store_reverified(&directory, &sealed).unwrap();
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn authority_reopen_rejects_each_missing_closure_object() {
        for (index, class) in [
            AuthorityStorageClass::RootAnchor,
            AuthorityStorageClass::GenesisEvidence,
            AuthorityStorageClass::GenesisAdmission,
        ]
        .into_iter()
        .enumerate()
        {
            let directory = TestDirectory::new("authority-missing");
            let sealed = crate::agent::replay::tests::admitted_genesis(0xb3 + index as u8);
            let mut store = open_file_store_for_sealed(&directory, &sealed);
            initialize_sealed_file_store(&mut store, &sealed);
            let path = authority_paths(store.root(), &sealed)
                .into_iter()
                .find_map(|(candidate, path)| (candidate == class).then_some(path))
                .unwrap();
            drop(store);
            fs::remove_file(path).unwrap();

            assert!(matches!(
                reopen_file_store_reverified(&directory, &sealed),
                Err(JournalStoreError::MissingObject)
            ));
        }
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn authority_reopen_rejects_each_tampered_closure_object() {
        for (index, class) in [
            AuthorityStorageClass::RootAnchor,
            AuthorityStorageClass::GenesisEvidence,
            AuthorityStorageClass::GenesisAdmission,
        ]
        .into_iter()
        .enumerate()
        {
            let directory = TestDirectory::new("authority-tamper");
            let sealed = crate::agent::replay::tests::admitted_genesis(0xb6 + index as u8);
            let mut store = open_file_store_for_sealed(&directory, &sealed);
            initialize_sealed_file_store(&mut store, &sealed);
            let path = authority_paths(store.root(), &sealed)
                .into_iter()
                .find_map(|(candidate, path)| (candidate == class).then_some(path))
                .unwrap();
            drop(store);
            fs::write(path, b"tampered authority object").unwrap();

            assert!(matches!(
                reopen_file_store_reverified(&directory, &sealed),
                Err(JournalStoreError::Corrupt)
            ));
        }
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn authority_reopen_rejects_legacy_unwrapped_root_admission() {
        let directory = TestDirectory::new("authority-legacy-admission");
        let sealed = crate::agent::replay::tests::admitted_genesis(0xba);
        let mut store = open_file_store_for_sealed(&directory, &sealed);
        initialize_sealed_file_store(&mut store, &sealed);
        let admission_path = authority_paths(store.root(), &sealed)
            .into_iter()
            .find_map(|(class, path)| {
                (class == AuthorityStorageClass::GenesisAdmission).then_some(path)
            })
            .unwrap();
        let AgentGenesisAdmissionRecord::RootBootstrap(root_admission) = sealed.admission_record()
        else {
            panic!("system bootstrap must carry a root admission")
        };
        drop(store);

        // The previous generation persisted this nested record directly. A
        // syntactically valid legacy authority object must not satisfy the
        // v2 journal's outer AGNA identity.
        fs::write(admission_path, root_admission.encode()).unwrap();
        assert!(matches!(
            reopen_file_store_reverified(&directory, &sealed),
            Err(JournalStoreError::Corrupt)
        ));
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn system_authorized_reopen_is_unavailable_until_live_verifier_exists() {
        let directory = TestDirectory::new("authority-system-authorized");
        let admission = phase_one_system_authorized_admission();
        admission.validate().unwrap();
        let mut genesis = genesis();
        genesis.admission = admission.id();
        genesis.validate().unwrap();
        let mut store = open_file_store(&directory);
        initialize(&mut store, &genesis);
        assert!(store.persist_authority(&admission).unwrap());
        drop(store);

        let config = config();
        assert!(matches!(
            FileAgentJournalStore::open(
                directory.agent_root(config.identity.agent),
                directory.lock(config.identity.agent),
                config.replicas[0].node,
            ),
            Err(JournalStoreError::Unavailable)
        ));
    }

    #[test]
    fn stable_lock_prevents_a_competing_writer() {
        let directory = TestDirectory::new("lock");
        let first = open_file_store(&directory);
        let config = config();
        assert!(matches!(
            FileAgentJournalStore::open(
                directory.agent_root(config.identity.agent),
                directory.0.join("alternate.agent-lock"),
                config.replicas[0].node,
            ),
            Err(JournalStoreError::InvalidPath)
        ));
        assert!(matches!(
            FileAgentJournalStore::open(
                directory.agent_root(config.identity.agent),
                directory.lock(config.identity.agent),
                config.replicas[0].node,
            ),
            Err(JournalStoreError::DirectoryInUse)
        ));
        drop(first);
        open_file_store(&directory);
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn overflow_uid_is_trusted_only_when_absent_from_the_inside_uid_map() {
        assert_eq!(uid_is_unmapped_in_id_map(65_534, "1000 0 1\n"), Some(true));
        assert_eq!(
            uid_is_unmapped_in_id_map(65_534, "0 0 4294967295\n"),
            Some(false)
        );
        assert_eq!(
            uid_is_unmapped_in_id_map(65_534, "1000 0 1\n65534 65534 1\n"),
            Some(false)
        );
        assert_eq!(uid_is_unmapped_in_id_map(65_534, ""), None);
        assert_eq!(
            uid_is_unmapped_in_id_map(65_534, "1000 0 1 trailing\n"),
            None
        );
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn direct_file_store_open_supports_a_distinct_authority_parent() {
        let directory = TestDirectory::new("direct-open-split-parents");
        let journal_parent = directory.0.join("journals");
        let authority_parent = directory.0.join("authority");
        fs::create_dir(&journal_parent).unwrap();
        fs::create_dir(&authority_parent).unwrap();

        let config = config();
        let agent = config.identity.agent;
        let encoded_agent = encode_hex(agent.as_bytes());
        let root = journal_parent.join(format!("{encoded_agent}.agent"));
        let lock = authority_parent.join(format!("{encoded_agent}.agent-lock"));
        let store =
            FileAgentJournalStore::open_unverified_for_test(&root, &lock, config.replicas[0].node)
                .unwrap();
        let instance = store.instance_id();
        assert!(root.is_dir());
        assert!(lock.is_file());
        assert!(
            !journal_parent
                .join(format!("{encoded_agent}.agent-lock"))
                .exists()
        );
        drop(store);

        let reopened =
            FileAgentJournalStore::open_unverified_for_test(&root, &lock, config.replicas[0].node)
                .unwrap();
        assert_eq!(reopened.instance_id(), instance);
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn file_store_instance_id_survives_exact_lock_reopen() {
        let directory = TestDirectory::new("instance-id-reopen");
        let config = config();
        let lock = directory.lock(config.identity.agent);
        let first = open_file_store(&directory);
        let instance = first.instance_id();
        let nonce = fs::read(&lock).unwrap();
        assert_eq!(nonce.len(), STABLE_LOCK_NONCE_BYTES);
        assert_ne!(nonce, vec![0; STABLE_LOCK_NONCE_BYTES]);
        drop(first);

        let reopened = open_file_store(&directory);
        assert_eq!(reopened.instance_id(), instance);
        assert_eq!(fs::read(lock).unwrap(), nonce);
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn file_store_instance_id_binds_lock_nonce_and_canonical_path() {
        let first_directory = TestDirectory::new("instance-id-first");
        let config = config();
        let first_lock = first_directory.lock(config.identity.agent);
        let first = open_file_store(&first_directory);
        let first_instance = first.instance_id();
        let first_nonce = fs::read(&first_lock).unwrap();
        drop(first);

        // Replacing the stable lock at the same canonical path creates a new
        // physical store even if the replaceable Agent directory remains.
        fs::remove_file(&first_lock).unwrap();
        fs::write(&first_lock, [0x91; STABLE_LOCK_NONCE_BYTES]).unwrap();
        let replacement = open_file_store(&first_directory);
        assert_ne!(replacement.instance_id(), first_instance);
        drop(replacement);

        // Copying exact nonce bytes to another canonical root must not
        // transplant the original store capability.
        let other_directory = TestDirectory::new("instance-id-other-path");
        fs::write(other_directory.lock(config.identity.agent), first_nonce).unwrap();
        let other = open_file_store(&other_directory);
        assert_ne!(other.instance_id(), first_instance);
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn stable_lock_rejects_malformed_or_zero_nonce() {
        for bytes in [
            vec![0x11],
            vec![0x22; STABLE_LOCK_NONCE_BYTES - 1],
            vec![0x33; STABLE_LOCK_NONCE_BYTES + 1],
            vec![0; STABLE_LOCK_NONCE_BYTES],
        ] {
            let directory = TestDirectory::new("malformed-lock-nonce");
            let config = config();
            fs::write(directory.lock(config.identity.agent), bytes).unwrap();
            assert!(matches!(
                FileAgentJournalStore::open_unverified_for_test(
                    directory.agent_root(config.identity.agent),
                    directory.lock(config.identity.agent),
                    config.replicas[0].node,
                ),
                Err(JournalStoreError::Corrupt)
            ));
        }
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn file_catalog_resolver_reads_exact_content_and_retains_the_stable_lock() {
        let directory = TestDirectory::new("catalog-resolver-lock");
        let mut store = open_file_store(&directory);
        let bytes = b"descriptor-pinned catalog content";
        let reference = BlobRef::of_bytes(bytes);
        store
            .put_blob(JournalBlobClass::CatalogArtifact, &reference, bytes)
            .unwrap();
        let resolver = store.catalog_blob_resolver().unwrap();

        assert_eq!(
            resolver.load_catalog(&reference).unwrap(),
            Some(bytes.to_vec())
        );
        let mut wrong_length = reference.clone();
        wrong_length.len -= 1;
        assert_eq!(
            resolver.load_catalog(&wrong_length),
            Err(JournalStoreError::Corrupt)
        );

        drop(store);
        let config = config();
        assert!(matches!(
            FileAgentJournalStore::open(
                directory.agent_root(config.identity.agent),
                directory.lock(config.identity.agent),
                config.replicas[0].node,
            ),
            Err(JournalStoreError::DirectoryInUse)
        ));
        assert_eq!(
            resolver.load_catalog(&reference).unwrap(),
            Some(bytes.to_vec())
        );
        drop(resolver);
        open_file_store(&directory);
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn file_catalog_resolver_rejects_namespace_slot_replacement() {
        use std::os::unix::fs::symlink;

        let directory = TestDirectory::new("catalog-resolver-namespace");
        let mut store = open_file_store(&directory);
        let bytes = b"catalog bytes must remain pinned";
        let reference = BlobRef::of_bytes(bytes);
        store
            .put_blob(JournalBlobClass::CatalogArtifact, &reference, bytes)
            .unwrap();
        let resolver = store.catalog_blob_resolver().unwrap();
        let catalog = store.root().join("catalog");
        let displaced = store.root().join("catalog.displaced");
        let outside = directory.0.join("outside-catalog-resolver");
        fs::create_dir(&outside).unwrap();
        fs::rename(&catalog, &displaced).unwrap();
        symlink(&outside, &catalog).unwrap();

        assert_eq!(
            resolver.load_catalog(&reference),
            Err(JournalStoreError::Corrupt)
        );
        assert_eq!(fs::read_dir(&outside).unwrap().count(), 0);
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn file_catalog_resolver_rejects_a_newly_writable_pinned_namespace() {
        use std::os::unix::fs::PermissionsExt as _;

        let directory = TestDirectory::new("catalog-resolver-namespace-mode");
        let mut store = open_file_store(&directory);
        let bytes = b"catalog namespace remains private";
        let reference = BlobRef::of_bytes(bytes);
        store
            .put_blob(JournalBlobClass::CatalogArtifact, &reference, bytes)
            .unwrap();
        let resolver = store.catalog_blob_resolver().unwrap();
        let catalog = store.root().join("catalog");
        let mut permissions = fs::metadata(&catalog).unwrap().permissions();
        permissions.set_mode(0o770);
        fs::set_permissions(catalog, permissions).unwrap();

        assert_eq!(
            resolver.load_catalog(&reference),
            Err(JournalStoreError::InvalidPath)
        );
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn file_catalog_resolver_rejects_symlink_nonregular_and_writable_blobs() {
        use std::os::unix::fs::{PermissionsExt as _, symlink};

        enum Mutation {
            Symlink,
            Directory,
            Writable,
        }
        for (label, mutation) in [
            ("symlink", Mutation::Symlink),
            ("directory", Mutation::Directory),
            ("writable", Mutation::Writable),
        ] {
            let directory = TestDirectory::new(label);
            let mut store = open_file_store(&directory);
            let bytes = format!("catalog resolver rejects {label}").into_bytes();
            let reference = BlobRef::of_bytes(&bytes);
            store
                .put_blob(JournalBlobClass::CatalogArtifact, &reference, &bytes)
                .unwrap();
            let resolver = store.catalog_blob_resolver().unwrap();
            let path = store
                .root()
                .join("catalog/blobs")
                .join(encode_hex(reference.hash.as_bytes()));
            match mutation {
                Mutation::Symlink => {
                    let outside = directory.0.join("outside-blob");
                    fs::write(&outside, &bytes).unwrap();
                    fs::remove_file(&path).unwrap();
                    symlink(outside, &path).unwrap();
                }
                Mutation::Directory => {
                    fs::remove_file(&path).unwrap();
                    fs::create_dir(&path).unwrap();
                }
                Mutation::Writable => {
                    let mut permissions = fs::metadata(&path).unwrap().permissions();
                    permissions.set_mode(0o660);
                    fs::set_permissions(&path, permissions).unwrap();
                }
            }
            assert_eq!(
                resolver.load_catalog(&reference),
                Err(JournalStoreError::Corrupt),
                "mutation {label} must fail closed"
            );
        }
    }

    #[test]
    fn legacy_whole_image_blocks_clean_journal_creation() {
        let directory = TestDirectory::new("legacy");
        let config = config();
        let root = directory.agent_root(config.identity.agent);
        fs::write(root.with_extension("agent-image"), b"retired image").unwrap();
        assert!(matches!(
            FileAgentJournalStore::open(
                &root,
                directory.lock(config.identity.agent),
                config.replicas[0].node,
            ),
            Err(JournalStoreError::LegacyGeneration)
        ));
        assert!(!root.exists());
    }

    #[cfg(unix)]
    #[test]
    fn staging_never_follows_a_preseeded_symlink() {
        use std::os::unix::fs::symlink;

        let directory = TestDirectory::new("symlink");
        let genesis = genesis();
        let mut store = open_file_store(&directory);
        initialize(&mut store, &genesis);
        let initial = store.heads().unwrap().unwrap();
        let entry = first_ordered(&genesis, &initial);
        let next = ordered_successor(&initial, &entry);
        let external = directory.0.join("external");
        fs::write(&external, b"must remain unchanged").unwrap();
        symlink(&external, store.root().join("heads.next")).unwrap();
        assert_eq!(
            store.publish_anchor(initial.id(), &entry, &next),
            Err(JournalStoreError::Corrupt)
        );
        assert_eq!(fs::read(external).unwrap(), b"must remain unchanged");
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn live_store_rejects_root_slot_symlink_replacement() {
        use std::os::unix::fs::symlink;

        let directory = TestDirectory::new("root-swap");
        let mut store = open_file_store(&directory);
        let root = store.root().to_path_buf();
        let displaced = directory.0.join("displaced-agent-root");
        let outside = directory.0.join("outside-root-target");
        fs::create_dir(&outside).unwrap();
        fs::rename(&root, &displaced).unwrap();
        symlink(&outside, &root).unwrap();

        let bytes = b"must-not-escape-root";
        let reference = BlobRef::of_bytes(bytes);
        assert_eq!(
            store.put_blob(JournalBlobClass::CatalogArtifact, &reference, bytes),
            Err(JournalStoreError::Corrupt)
        );
        assert_eq!(fs::read_dir(&outside).unwrap().count(), 0);
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn live_store_rejects_internal_directory_symlink_replacement() {
        use std::os::unix::fs::symlink;

        let directory = TestDirectory::new("subdir-swap");
        let mut store = open_file_store(&directory);
        let catalog = store.root().join("catalog");
        let displaced = store.root().join("catalog.displaced");
        let outside = directory.0.join("outside-catalog-target");
        fs::create_dir(&outside).unwrap();
        fs::rename(&catalog, &displaced).unwrap();
        symlink(&outside, &catalog).unwrap();

        let bytes = b"must-not-escape-subdirectory";
        let reference = BlobRef::of_bytes(bytes);
        assert_eq!(
            store.put_blob(JournalBlobClass::CatalogArtifact, &reference, bytes),
            Err(JournalStoreError::Corrupt)
        );
        assert_eq!(fs::read_dir(&outside).unwrap().count(), 0);
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn live_store_rejects_newly_writable_internal_namespace() {
        use std::os::unix::fs::PermissionsExt as _;

        let directory = TestDirectory::new("writable-subdir");
        let mut store = open_file_store(&directory);
        let catalog = store.root().join("catalog");
        let mut permissions = fs::metadata(&catalog).unwrap().permissions();
        permissions.set_mode(0o770);
        fs::set_permissions(&catalog, permissions).unwrap();

        let bytes = b"must-not-enter-writable-namespace";
        let reference = BlobRef::of_bytes(bytes);
        assert_eq!(
            store.put_blob(JournalBlobClass::CatalogArtifact, &reference, bytes),
            Err(JournalStoreError::InvalidPath)
        );
    }

    #[cfg(all(target_os = "linux", feature = "storage"))]
    #[test]
    fn file_authority_slot_supports_distinct_journal_and_authority_parents() {
        let directory = TestDirectory::new("authority-slot-split-parents");
        let journal_parent = directory.0.join("journals");
        let authority_parent = directory.0.join("authority");
        fs::create_dir(&journal_parent).unwrap();
        fs::create_dir(&authority_parent).unwrap();

        let sealed = crate::agent::replay::tests::admitted_genesis(0xe7);
        let agent = sealed.genesis().runtime().agent;
        let encoded_agent = encode_hex(agent.as_bytes());
        let root = journal_parent.join(format!("{encoded_agent}.agent"));
        let lock = authority_parent.join(format!("{encoded_agent}.agent-lock"));
        let canonical = authority_parent.join(system_authority_ledger_file_name(agent));
        let staged = authority_parent.join(sibling_next_name(
            canonical
                .file_name()
                .and_then(|name| name.to_str())
                .unwrap(),
        ));

        let first = FileAgentJournalSlot::acquire(&root, &lock, sealed.replica().node).unwrap();
        assert!(!root.exists());
        assert!(lock.is_file());
        assert!(staged.is_file());
        assert!(!canonical.exists());
        assert!(
            !journal_parent
                .join(format!("{encoded_agent}.agent-lock"))
                .exists()
        );
        assert!(
            !journal_parent
                .join(system_authority_ledger_file_name(agent))
                .exists()
        );

        let first_bound = bind_system_authority_ledger(&first, &sealed);
        let store = initialize_unexposed_system_authority_slot(first, &first_bound, &sealed);
        assert!(root.is_dir());
        assert!(canonical.is_file());
        assert!(!staged.exists());
        assert!(
            !authority_parent
                .join(format!("{encoded_agent}.agent"))
                .exists()
        );

        let resolver = store.catalog_blob_resolver().unwrap();
        drop(store);
        drop(first_bound);
        assert!(matches!(
            FileAgentJournalSlot::acquire(&root, &lock, sealed.replica().node),
            Err(JournalStoreError::DirectoryInUse)
        ));
        drop(resolver);

        let second = FileAgentJournalSlot::acquire(&root, &lock, sealed.replica().node).unwrap();
        let second_bound = bind_system_authority_ledger(&second, &sealed);
        let reopened = second_bound
            .with_startup_root_recovery(|startup| second.open_reverified(&sealed, startup, false))
            .unwrap()
            .unwrap();
        assert_eq!(reopened.root(), root);
    }

    #[cfg(all(target_os = "linux", feature = "storage"))]
    #[test]
    fn pinned_outer_parents_reject_path_replacement_before_slot_writes() {
        for replace_authority in [false, true] {
            let directory = TestDirectory::new(if replace_authority {
                "authority-slot-replaced-authority-parent"
            } else {
                "authority-slot-replaced-journal-parent"
            });
            let journal_parent = directory.0.join("journals");
            let authority_parent = directory.0.join("authority");
            fs::create_dir(&journal_parent).unwrap();
            fs::create_dir(&authority_parent).unwrap();
            let pinned_journal = open_directory_path(&journal_parent).unwrap();
            let pinned_authority = open_directory_path(&authority_parent).unwrap();
            let replaced = if replace_authority {
                &authority_parent
            } else {
                &journal_parent
            };
            let displaced = replaced.with_extension("displaced");
            fs::rename(replaced, &displaced).unwrap();
            fs::create_dir(replaced).unwrap();

            let sealed = crate::agent::replay::tests::admitted_genesis(if replace_authority {
                0xeb
            } else {
                0xea
            });
            let agent = sealed.genesis().runtime().agent;
            let encoded_agent = encode_hex(agent.as_bytes());
            let root = journal_parent.join(format!("{encoded_agent}.agent"));
            let lock = authority_parent.join(format!("{encoded_agent}.agent-lock"));
            assert!(matches!(
                FileAgentJournalSlot::acquire_with_pinned_parents(
                    &root,
                    &lock,
                    sealed.replica().node,
                    &pinned_journal,
                    &pinned_authority,
                ),
                Err(JournalStoreError::Corrupt)
            ));
            assert!(fs::read_dir(&journal_parent).unwrap().next().is_none());
            assert!(fs::read_dir(&authority_parent).unwrap().next().is_none());
        }
    }

    #[cfg(all(target_os = "linux", feature = "storage"))]
    #[test]
    fn file_authority_slot_resumes_the_pinned_stage_crash_before_lock_creation() {
        let directory = TestDirectory::new("authority-slot-fresh-stage");
        let sealed = crate::agent::replay::tests::admitted_genesis(0xd0);
        let agent = sealed.genesis().runtime().agent;
        let root = directory.agent_root(agent);
        let lock = directory.lock(agent);
        let (canonical, staged) = system_authority_ledger_paths(&directory, agent);

        let slot = acquire_system_authority_slot(&directory, &sealed);
        let (fresh_file, fresh_identity) = slot
            .fresh_ledger_stage
            .as_ref()
            .expect("an empty slot must retain its pre-lock O_EXCL witness");
        assert_eq!(FileIdentity::of(fresh_file).unwrap(), *fresh_identity);
        let staged_file = File::open(&staged).unwrap();
        assert_eq!(FileIdentity::of(&staged_file).unwrap(), *fresh_identity);
        assert!(staged.is_file());
        assert!(lock.is_file());
        assert!(!canonical.exists());
        assert!(!root.exists());

        drop(staged_file);
        drop(slot);
        fs::remove_file(&lock).unwrap();
        assert!(staged.is_file());
        assert!(!lock.exists());

        let resumed = acquire_system_authority_slot(&directory, &sealed);
        assert!(resumed.fresh_ledger_stage.is_none());
        let ledger = resumed.open_system_authority_ledger().unwrap();
        assert_eq!(
            ledger.mode(),
            FileSystemAuthorityLedgerOpenMode::ExistingStage
        );
        let owner = open_system_authority_owner_for_mode(&resumed, ledger, &sealed);
        let bound = resumed
            .bind_system_authority_ledger_owner(owner, &sealed)
            .unwrap();
        bound.verify().unwrap();
        assert!(lock.is_file());
        assert!(canonical.is_file());
        assert!(!staged.exists());
        assert_eq!(fs::metadata(canonical).unwrap().nlink(), 1);
    }

    #[cfg(all(target_os = "linux", feature = "storage"))]
    #[test]
    fn file_authority_slot_repairs_an_empty_lock_only_beside_the_staged_witness() {
        let directory = TestDirectory::new("authority-slot-empty-lock-crash");
        let sealed = crate::agent::replay::tests::admitted_genesis(0xdb);
        let agent = sealed.genesis().runtime().agent;
        let lock = directory.lock(agent);
        let (canonical, staged) = system_authority_ledger_paths(&directory, agent);

        let first = acquire_system_authority_slot(&directory, &sealed);
        drop(first);
        File::options()
            .write(true)
            .truncate(true)
            .open(&lock)
            .unwrap()
            .sync_all()
            .unwrap();
        assert_eq!(fs::metadata(&lock).unwrap().len(), 0);
        assert!(staged.is_file());
        assert!(!canonical.exists());

        let resumed = acquire_system_authority_slot(&directory, &sealed);
        let nonce = fs::read(&lock).unwrap();
        assert_eq!(nonce.len(), STABLE_LOCK_NONCE_BYTES);
        assert_ne!(nonce, vec![0; STABLE_LOCK_NONCE_BYTES]);
        let ledger = resumed.open_system_authority_ledger().unwrap();
        assert_eq!(
            ledger.mode(),
            FileSystemAuthorityLedgerOpenMode::ExistingStage
        );
        let owner = open_system_authority_owner_for_mode(&resumed, ledger, &sealed);
        let bound = resumed
            .bind_system_authority_ledger_owner(owner, &sealed)
            .unwrap();
        bound.verify().unwrap();
        assert!(canonical.is_file());
        assert!(!staged.exists());
        assert_eq!(fs::metadata(canonical).unwrap().nlink(), 1);
    }

    #[cfg(all(target_os = "linux", feature = "storage"))]
    #[test]
    fn file_authority_slot_repairs_every_partial_nonce_only_beside_a_pristine_stage() {
        for length in 1..STABLE_LOCK_NONCE_BYTES {
            let directory = TestDirectory::new(&format!("authority-slot-partial-nonce-{length}"));
            let sealed =
                crate::agent::replay::tests::admitted_genesis(0x80_u8.wrapping_add(length as u8));
            let agent = sealed.genesis().runtime().agent;
            let root = directory.agent_root(agent);
            let lock = directory.lock(agent);
            let (canonical, staged) = system_authority_ledger_paths(&directory, agent);
            let first = acquire_system_authority_slot(&directory, &sealed);
            drop(first);

            let prefix = vec![0x5a; length];
            fs::write(&lock, &prefix).unwrap();
            assert_eq!(fs::read(&lock).unwrap(), prefix);
            assert!(staged.is_file());
            assert_eq!(fs::metadata(&staged).unwrap().len(), 0);
            assert!(!canonical.exists());
            assert!(!root.exists());

            let resumed = acquire_system_authority_slot(&directory, &sealed);
            let nonce = fs::read(&lock).unwrap();
            assert_eq!(nonce.len(), STABLE_LOCK_NONCE_BYTES);
            assert_ne!(nonce, vec![0; STABLE_LOCK_NONCE_BYTES]);
            assert_eq!(resumed.stable_lock_nonce, nonce.as_slice());
            assert!(staged.is_file());
            assert!(!canonical.exists());
            assert!(!root.exists());
        }
    }

    #[cfg(all(target_os = "linux", feature = "storage"))]
    #[test]
    fn file_authority_slot_never_repairs_a_partial_nonce_beside_nonempty_stage() {
        for length in [1, STABLE_LOCK_NONCE_BYTES - 1] {
            let directory = TestDirectory::new(&format!("authority-slot-partial-garbage-{length}"));
            let sealed =
                crate::agent::replay::tests::admitted_genesis(0xb0_u8.wrapping_add(length as u8));
            let agent = sealed.genesis().runtime().agent;
            let root = directory.agent_root(agent);
            let lock = directory.lock(agent);
            let (_, staged) = system_authority_ledger_paths(&directory, agent);
            let prefix = vec![0x6b; length];
            let garbage = b"not-an-empty-freshness-witness";
            fs::write(&lock, &prefix).unwrap();
            fs::write(&staged, garbage).unwrap();

            assert!(matches!(
                FileAgentJournalSlot::acquire(&root, &lock, sealed.replica().node),
                Err(JournalStoreError::Corrupt)
            ));
            assert_eq!(fs::read(&lock).unwrap(), prefix);
            assert_eq!(fs::read(&staged).unwrap(), garbage);
            assert!(!root.exists());
        }
    }

    #[cfg(all(target_os = "linux", feature = "storage"))]
    #[test]
    fn file_authority_slot_rejects_garbage_stage_before_creating_or_repairing_lock() {
        for empty_lock in [false, true] {
            let directory = TestDirectory::new(if empty_lock {
                "authority-slot-garbage-stage-empty-lock"
            } else {
                "authority-slot-garbage-stage-no-lock"
            });
            let sealed =
                crate::agent::replay::tests::admitted_genesis(if empty_lock { 0xe9 } else { 0xe8 });
            let agent = sealed.genesis().runtime().agent;
            let root = directory.agent_root(agent);
            let lock = directory.lock(agent);
            let (_, staged) = system_authority_ledger_paths(&directory, agent);
            let garbage = b"not-a-redb-freshness-stage";
            fs::write(&staged, garbage).unwrap();
            if empty_lock {
                fs::write(&lock, b"").unwrap();
            }

            assert!(matches!(
                FileAgentJournalSlot::acquire(&root, &lock, sealed.replica().node),
                Err(JournalStoreError::Corrupt)
            ));
            assert_eq!(fs::read(&staged).unwrap(), garbage);
            if empty_lock {
                assert_eq!(fs::read(&lock).unwrap(), b"");
            } else {
                assert!(!lock.exists(), "garbage stage must not mint a lock");
            }
            assert!(!root.exists());
        }
    }

    #[cfg(all(target_os = "linux", feature = "storage"))]
    #[test]
    fn file_authority_slot_does_not_repair_an_empty_lock_beside_canonical_or_journal_state() {
        let canonical_directory = TestDirectory::new("authority-slot-empty-lock-canonical");
        let canonical_sealed = crate::agent::replay::tests::admitted_genesis(0xdc);
        let canonical_agent = canonical_sealed.genesis().runtime().agent;
        let canonical_root = canonical_directory.agent_root(canonical_agent);
        let canonical_lock = canonical_directory.lock(canonical_agent);
        let (canonical, canonical_stage) =
            system_authority_ledger_paths(&canonical_directory, canonical_agent);
        let canonical_slot = acquire_system_authority_slot(&canonical_directory, &canonical_sealed);
        let canonical_bound = bind_system_authority_ledger(&canonical_slot, &canonical_sealed);
        drop(canonical_bound);
        drop(canonical_slot);
        File::options()
            .write(true)
            .truncate(true)
            .open(&canonical_lock)
            .unwrap()
            .sync_all()
            .unwrap();

        assert!(matches!(
            FileAgentJournalSlot::acquire(
                &canonical_root,
                &canonical_lock,
                canonical_sealed.replica().node,
            ),
            Err(JournalStoreError::Corrupt)
        ));
        assert_eq!(fs::metadata(&canonical_lock).unwrap().len(), 0);
        assert!(canonical.is_file());
        assert!(!canonical_stage.exists());

        let journal_directory = TestDirectory::new("authority-slot-empty-lock-journal");
        let journal_sealed = crate::agent::replay::tests::admitted_genesis(0xdd);
        let journal_agent = journal_sealed.genesis().runtime().agent;
        let journal_root = journal_directory.agent_root(journal_agent);
        let journal_lock = journal_directory.lock(journal_agent);
        let (_, journal_stage) = system_authority_ledger_paths(&journal_directory, journal_agent);
        let journal_slot = acquire_system_authority_slot(&journal_directory, &journal_sealed);
        drop(journal_slot);
        fs::create_dir(&journal_root).unwrap();
        File::options()
            .write(true)
            .truncate(true)
            .open(&journal_lock)
            .unwrap()
            .sync_all()
            .unwrap();

        assert!(matches!(
            FileAgentJournalSlot::acquire(
                &journal_root,
                &journal_lock,
                journal_sealed.replica().node,
            ),
            Err(JournalStoreError::Corrupt)
        ));
        assert_eq!(fs::metadata(&journal_lock).unwrap().len(), 0);
        assert!(journal_stage.is_file());
    }

    #[cfg(all(target_os = "linux", feature = "storage"))]
    #[test]
    fn file_authority_slot_rejects_lock_only_without_minting_freshness() {
        let directory = TestDirectory::new("authority-slot-lock-only");
        let sealed = crate::agent::replay::tests::admitted_genesis(0xd1);
        let agent = sealed.genesis().runtime().agent;
        let (_, staged) = system_authority_ledger_paths(&directory, agent);
        let lock = directory.lock(agent);

        let slot = acquire_system_authority_slot(&directory, &sealed);
        drop(slot);
        fs::remove_file(&staged).unwrap();
        assert!(lock.is_file());

        assert!(matches!(
            FileAgentJournalSlot::acquire(
                directory.agent_root(agent),
                &lock,
                sealed.replica().node,
            ),
            Err(JournalStoreError::Corrupt)
        ));
        assert!(!staged.exists());
    }

    #[cfg(all(target_os = "linux", feature = "storage"))]
    #[test]
    fn file_authority_slot_rejects_a_journal_without_a_canonical_ledger() {
        let directory = TestDirectory::new("authority-slot-journal-without-ledger");
        let sealed = crate::agent::replay::tests::admitted_genesis(0xd2);
        let agent = sealed.genesis().runtime().agent;
        let root = directory.agent_root(agent);
        let lock = directory.lock(agent);
        let (canonical, staged) = system_authority_ledger_paths(&directory, agent);

        let slot = acquire_system_authority_slot(&directory, &sealed);
        drop(slot);
        fs::create_dir(&root).unwrap();
        assert!(root.is_dir());
        assert!(lock.is_file());
        assert!(!canonical.exists());
        assert!(staged.is_file());

        assert!(matches!(
            FileAgentJournalSlot::acquire(&root, &lock, sealed.replica().node),
            Err(JournalStoreError::Corrupt)
        ));
        assert!(staged.is_file());
    }

    #[cfg(all(target_os = "linux", feature = "storage"))]
    #[test]
    fn file_authority_slot_rejects_a_canonical_ledger_without_its_lock() {
        let directory = TestDirectory::new("authority-slot-ledger-without-lock");
        let sealed = crate::agent::replay::tests::admitted_genesis(0xd3);
        let agent = sealed.genesis().runtime().agent;
        let root = directory.agent_root(agent);
        let lock = directory.lock(agent);
        let (canonical, staged) = system_authority_ledger_paths(&directory, agent);

        let slot = acquire_system_authority_slot(&directory, &sealed);
        let bound = bind_system_authority_ledger(&slot, &sealed);
        bound.verify().unwrap();
        drop(bound);
        drop(slot);
        fs::remove_file(&lock).unwrap();
        assert!(canonical.is_file());
        assert!(!staged.exists());
        assert!(!root.exists());

        assert!(matches!(
            FileAgentJournalSlot::acquire(&root, &lock, sealed.replica().node),
            Err(JournalStoreError::Corrupt)
        ));
        assert!(!staged.exists());
    }

    #[cfg(all(target_os = "linux", feature = "storage"))]
    #[test]
    fn file_authority_slot_resumes_an_existing_stage_and_lock() {
        let directory = TestDirectory::new("authority-slot-stage-lock-reopen");
        let sealed = crate::agent::replay::tests::admitted_genesis(0xd4);
        let agent = sealed.genesis().runtime().agent;
        let (canonical, staged) = system_authority_ledger_paths(&directory, agent);

        let first = acquire_system_authority_slot(&directory, &sealed);
        let ledger = first.open_system_authority_ledger().unwrap();
        assert_eq!(ledger.mode(), FileSystemAuthorityLedgerOpenMode::FreshStage);
        drop(ledger);
        drop(first);

        let second = acquire_system_authority_slot(&directory, &sealed);
        assert!(second.fresh_ledger_stage.is_none());
        let ledger = second.open_system_authority_ledger().unwrap();
        assert_eq!(
            ledger.mode(),
            FileSystemAuthorityLedgerOpenMode::ExistingStage
        );
        let owner = open_system_authority_owner_for_mode(&second, ledger, &sealed);
        assert_eq!(owner.owner.journal_store(), second.instance_id());
        let bound = second
            .bind_system_authority_ledger_owner(owner, &sealed)
            .unwrap();
        bound.verify().unwrap();
        assert!(canonical.is_file());
        assert!(!staged.exists());
        assert_eq!(fs::metadata(canonical).unwrap().nlink(), 1);
    }

    #[cfg(all(target_os = "linux", feature = "storage"))]
    #[test]
    fn file_authority_slot_cleans_an_exact_canonical_stage_alias() {
        let directory = TestDirectory::new("authority-slot-exact-stage-alias");
        let sealed = crate::agent::replay::tests::admitted_genesis(0xd5);
        let agent = sealed.genesis().runtime().agent;
        let (canonical, staged) = system_authority_ledger_paths(&directory, agent);

        let first = acquire_system_authority_slot(&directory, &sealed);
        let ledger = first.open_system_authority_ledger().unwrap();
        let owner = open_system_authority_owner_for_mode(&first, ledger, &sealed);
        fs::hard_link(&staged, &canonical).unwrap();
        drop(owner);
        drop(first);

        let second = acquire_system_authority_slot(&directory, &sealed);
        let ledger = second.open_system_authority_ledger().unwrap();
        assert_eq!(
            ledger.mode(),
            FileSystemAuthorityLedgerOpenMode::ExistingCanonical
        );
        assert!(ledger.stage_alias);
        let owner = open_system_authority_owner_for_mode(&second, ledger, &sealed);
        let bound = second
            .bind_system_authority_ledger_owner(owner, &sealed)
            .unwrap();

        bound.verify().unwrap();
        assert!(canonical.is_file());
        assert!(!staged.exists());
        assert_eq!(fs::metadata(canonical).unwrap().nlink(), 1);
    }

    #[cfg(all(target_os = "linux", feature = "storage"))]
    #[test]
    fn file_authority_slot_rejects_distinct_canonical_and_stage_inodes() {
        let directory = TestDirectory::new("authority-slot-distinct-stage");
        let sealed = crate::agent::replay::tests::admitted_genesis(0xd6);
        let agent = sealed.genesis().runtime().agent;
        let (canonical, staged) = system_authority_ledger_paths(&directory, agent);

        let first = acquire_system_authority_slot(&directory, &sealed);
        let ledger = first.open_system_authority_ledger().unwrap();
        drop(ledger);
        drop(first);
        fs::copy(&staged, &canonical).unwrap();
        assert_ne!(
            fs::metadata(&canonical).unwrap().ino(),
            fs::metadata(&staged).unwrap().ino()
        );

        let second = acquire_system_authority_slot(&directory, &sealed);
        assert!(matches!(
            second.open_system_authority_ledger(),
            Err(JournalStoreError::Corrupt)
        ));
        assert!(canonical.is_file());
        assert!(staged.is_file());
    }

    #[cfg(all(target_os = "linux", feature = "storage"))]
    #[test]
    fn file_authority_slot_rejects_external_hard_links_before_database_open() {
        // A staged database must not be initialized through an inode which
        // also has an attacker-controlled sibling name.
        let staged_directory = TestDirectory::new("authority-slot-stage-hard-link");
        let staged_sealed = crate::agent::replay::tests::admitted_genesis(0xeb);
        let staged_agent = staged_sealed.genesis().runtime().agent;
        let staged_slot = acquire_system_authority_slot(&staged_directory, &staged_sealed);
        let (_, staged) = system_authority_ledger_paths(&staged_directory, staged_agent);
        let staged_alias = staged_directory.0.join("external-stage-alias");
        fs::hard_link(&staged, &staged_alias).unwrap();
        let staged_before = fs::read(&staged).unwrap();
        assert!(matches!(
            staged_slot.open_system_authority_ledger(),
            Err(JournalStoreError::Corrupt)
        ));
        assert_eq!(fs::read(&staged).unwrap(), staged_before);
        assert_eq!(fs::read(&staged_alias).unwrap(), staged_before);

        // The stable lock is itself part of the physical store identity and
        // must likewise have exactly one namespace name.
        let lock_directory = TestDirectory::new("authority-slot-lock-hard-link");
        let lock_sealed = crate::agent::replay::tests::admitted_genesis(0xec);
        let lock_agent = lock_sealed.genesis().runtime().agent;
        let lock_slot = acquire_system_authority_slot(&lock_directory, &lock_sealed);
        let lock = lock_directory.lock(lock_agent);
        let lock_alias = lock_directory.0.join("external-lock-alias");
        fs::hard_link(&lock, &lock_alias).unwrap();
        assert!(matches!(
            lock_slot.open_system_authority_ledger(),
            Err(JournalStoreError::Corrupt)
        ));

        // The same alias must be rejected before a later process acquires the
        // slot, not merely by an already-open capability's recheck.
        let prelinked_lock_directory =
            TestDirectory::new("authority-slot-prelinked-lock-hard-link");
        let prelinked_lock_sealed = crate::agent::replay::tests::admitted_genesis(0xef);
        let prelinked_lock_agent = prelinked_lock_sealed.genesis().runtime().agent;
        let prelinked_slot =
            acquire_system_authority_slot(&prelinked_lock_directory, &prelinked_lock_sealed);
        drop(prelinked_slot);
        let prelinked_lock = prelinked_lock_directory.lock(prelinked_lock_agent);
        let prelinked_alias = prelinked_lock_directory.0.join("preexisting-lock-alias");
        fs::hard_link(&prelinked_lock, &prelinked_alias).unwrap();
        let (_, prelinked_stage) =
            system_authority_ledger_paths(&prelinked_lock_directory, prelinked_lock_agent);
        let stage_before = fs::read(&prelinked_stage).unwrap();
        assert!(matches!(
            FileAgentJournalSlot::acquire(
                prelinked_lock_directory.agent_root(prelinked_lock_agent),
                &prelinked_lock,
                prelinked_lock_sealed.replica().node,
            ),
            Err(JournalStoreError::Corrupt)
        ));
        assert_eq!(fs::read(&prelinked_stage).unwrap(), stage_before);

        // A canonical sidecar with any extra name is rejected during slot
        // acquisition, before redb can open it or perform recovery writes.
        let canonical_directory = TestDirectory::new("authority-slot-canonical-hard-link");
        let canonical_sealed = crate::agent::replay::tests::admitted_genesis(0xed);
        let canonical_agent = canonical_sealed.genesis().runtime().agent;
        let first = acquire_system_authority_slot(&canonical_directory, &canonical_sealed);
        let bound = bind_system_authority_ledger(&first, &canonical_sealed);
        drop(bound);
        drop(first);
        let (canonical, _) = system_authority_ledger_paths(&canonical_directory, canonical_agent);
        let canonical_alias = canonical_directory.0.join("external-canonical-alias");
        fs::hard_link(&canonical, &canonical_alias).unwrap();
        assert!(matches!(
            FileAgentJournalSlot::acquire(
                canonical_directory.agent_root(canonical_agent),
                canonical_directory.lock(canonical_agent),
                canonical_sealed.replica().node,
            ),
            Err(JournalStoreError::Corrupt)
        ));

        // Canonical and stage may temporarily be two names for one inode
        // after a no-overwrite publication crash. Exactly those two names are
        // allowed; a third hard link makes the recovery witness ambiguous.
        let crash_alias_directory = TestDirectory::new("authority-slot-crash-alias-third-link");
        let crash_alias_sealed = crate::agent::replay::tests::admitted_genesis(0xf0);
        let crash_alias_agent = crash_alias_sealed.genesis().runtime().agent;
        let crash_alias_slot =
            acquire_system_authority_slot(&crash_alias_directory, &crash_alias_sealed);
        let crash_alias_ledger = crash_alias_slot.open_system_authority_ledger().unwrap();
        let (crash_alias_canonical, crash_alias_stage) =
            system_authority_ledger_paths(&crash_alias_directory, crash_alias_agent);
        fs::hard_link(&crash_alias_stage, &crash_alias_canonical).unwrap();
        let third_alias = crash_alias_directory.0.join("third-ledger-alias");
        fs::hard_link(&crash_alias_stage, &third_alias).unwrap();
        drop(crash_alias_ledger);
        drop(crash_alias_slot);
        let bytes_before = fs::read(&crash_alias_canonical).unwrap();
        assert!(matches!(
            FileAgentJournalSlot::acquire(
                crash_alias_directory.agent_root(crash_alias_agent),
                crash_alias_directory.lock(crash_alias_agent),
                crash_alias_sealed.replica().node,
            ),
            Err(JournalStoreError::Corrupt)
        ));
        assert_eq!(fs::read(&crash_alias_canonical).unwrap(), bytes_before);
        assert_eq!(fs::read(&crash_alias_stage).unwrap(), bytes_before);
        assert_eq!(fs::read(&third_alias).unwrap(), bytes_before);
    }

    #[cfg(all(target_os = "linux", feature = "storage"))]
    #[test]
    fn file_authority_slot_resumes_canonical_ledger_and_lock_before_journal_creation() {
        let directory = TestDirectory::new("authority-slot-ledger-lock-no-journal");
        let sealed = crate::agent::replay::tests::admitted_genesis(0xd7);
        let agent = sealed.genesis().runtime().agent;
        let root = directory.agent_root(agent);
        let (canonical, staged) = system_authority_ledger_paths(&directory, agent);

        let first = acquire_system_authority_slot(&directory, &sealed);
        let bound = bind_system_authority_ledger(&first, &sealed);
        bound.verify().unwrap();
        drop(bound);
        drop(first);
        assert!(canonical.is_file());
        assert!(!staged.exists());
        assert!(!root.exists());

        let second = acquire_system_authority_slot(&directory, &sealed);
        assert!(!second.generation_exists());
        let ledger = second.open_system_authority_ledger().unwrap();
        assert_eq!(
            ledger.mode(),
            FileSystemAuthorityLedgerOpenMode::ExistingCanonical
        );
        let owner = open_system_authority_owner_for_mode(&second, ledger, &sealed);
        let rebound = second
            .bind_system_authority_ledger_owner(owner, &sealed)
            .unwrap();
        rebound.verify().unwrap();
        assert!(!rebound.journal_exposure_is_committed().unwrap());
        assert!(!root.exists());
    }

    #[cfg(all(target_os = "linux", feature = "storage"))]
    #[test]
    fn file_authority_unexposed_bound_owner_gates_ordinary_mutation_and_recovery() {
        let directory = TestDirectory::new("authority-unexposed-gates");
        let sealed = crate::agent::replay::tests::admitted_genesis(0xe1);
        let slot = acquire_system_authority_slot(&directory, &sealed);
        let bound = bind_system_authority_ledger(&slot, &sealed);
        assert!(!bound.journal_exposure_is_committed().unwrap());

        let mutation_entered = std::cell::Cell::new(false);
        assert!(matches!(
            bound.with_root_mutation(|| mutation_entered.set(true)),
            Err(SystemAuthorityLedgerError::JournalExposureRequired)
        ));
        assert!(!mutation_entered.get());

        let recovery_entered = std::cell::Cell::new(false);
        assert!(matches!(
            bound.with_recovery_owner(|_| recovery_entered.set(true)),
            Err(SystemAuthorityLedgerError::JournalExposureRequired)
        ));
        assert!(!recovery_entered.get());

        let startup_entered = std::cell::Cell::new(false);
        bound
            .with_startup_root_recovery(|_| startup_entered.set(true))
            .unwrap();
        assert!(startup_entered.get());
        assert!(!bound.journal_exposure_is_committed().unwrap());
    }

    #[cfg(all(target_os = "linux", feature = "storage"))]
    #[test]
    fn file_authority_startup_capability_is_bound_to_one_physical_slot() {
        let sealed = crate::agent::replay::tests::admitted_genesis(0xee);
        let first_directory = TestDirectory::new("authority-startup-token-first");
        let second_directory = TestDirectory::new("authority-startup-token-second");
        let first = acquire_system_authority_slot(&first_directory, &sealed);
        let second = acquire_system_authority_slot(&second_directory, &sealed);
        let first_bound = bind_system_authority_ledger(&first, &sealed);
        let second_bound = bind_system_authority_ledger(&second, &sealed);
        drop(second_bound);

        let agent = sealed.genesis().runtime().agent;
        let second_root = second_directory.agent_root(agent);
        let (second_ledger, second_stage) = system_authority_ledger_paths(&second_directory, agent);
        let ledger_before = fs::read(&second_ledger).unwrap();
        assert!(!second_root.exists());
        assert!(!second_stage.exists());

        assert!(matches!(
            first_bound.with_startup_root_recovery(|startup| {
                second.open_reverified(&sealed, startup, false)
            }),
            Ok(Err(JournalStoreError::ScopeMismatch))
        ));
        assert!(!second_root.exists());
        assert!(!second_stage.exists());
        assert_eq!(fs::read(&second_ledger).unwrap(), ledger_before);
    }

    #[cfg(all(target_os = "linux", feature = "storage"))]
    #[test]
    fn file_authority_initialized_journal_without_marker_reopens_and_promotes_marker() {
        let directory = TestDirectory::new("authority-initialized-before-marker");
        let sealed = crate::agent::replay::tests::admitted_genesis(0xe2);
        let agent = sealed.genesis().runtime().agent;
        let first = acquire_system_authority_slot(&directory, &sealed);
        let first_bound = bind_system_authority_ledger(&first, &sealed);

        // Model a process death after the filesystem operation completed but
        // before the enclosing redb initialization transaction committed.
        let mut store = first_bound
            .with_startup_root_recovery(|startup| {
                let mut store = first.open_reverified(&sealed, startup, false)?;
                let package_bytes = b"replay-runtime-package";
                store.put_blob(
                    JournalBlobClass::CatalogArtifact,
                    &sealed.genesis().runtime().package,
                    package_bytes,
                )?;
                assert!(store.initialize(&sealed)?);
                Ok::<_, JournalStoreError>(store)
            })
            .unwrap()
            .unwrap();
        assert!(!first_bound.journal_exposure_is_committed().unwrap());
        assert_eq!(store.genesis().unwrap(), Some(sealed.genesis().clone()));
        assert_eq!(store.heads().unwrap(), Some(sealed.initial_heads()));
        drop(store);
        drop(first_bound);

        let second = acquire_system_authority_slot(&directory, &sealed);
        assert!(second.generation_exists());
        let second_bound = bind_system_authority_ledger(&second, &sealed);
        assert!(!second_bound.journal_exposure_is_committed().unwrap());
        store = second_bound
            .with_startup_root_recovery(|startup| second.open_reverified(&sealed, startup, false))
            .unwrap()
            .unwrap();
        second_bound
            .with_unexposed_journal_initialization(sealed.genesis().id(), || {
                assert!(!store.initialize(&sealed)?);
                Ok::<_, JournalStoreError>(())
            })
            .unwrap()
            .unwrap();
        assert!(second_bound.journal_exposure_is_committed().unwrap());
        assert_eq!(store.genesis().unwrap(), Some(sealed.genesis().clone()));
        assert_eq!(store.heads().unwrap(), Some(sealed.initial_heads()));
        assert!(directory.agent_root(agent).is_dir());
    }

    #[cfg(all(target_os = "linux", feature = "storage"))]
    #[test]
    fn file_authority_marker_without_journal_generation_rejects_without_creating_it() {
        let directory = TestDirectory::new("authority-marker-no-journal");
        let sealed = crate::agent::replay::tests::admitted_genesis(0xe3);
        let agent = sealed.genesis().runtime().agent;
        let root = directory.agent_root(agent);
        let first = acquire_system_authority_slot(&directory, &sealed);
        let first_bound = bind_system_authority_ledger(&first, &sealed);
        first_bound
            .with_unexposed_journal_initialization(sealed.genesis().id(), || Ok::<_, ()>(()))
            .unwrap()
            .unwrap();
        assert!(first_bound.journal_exposure_is_committed().unwrap());
        drop(first_bound);
        drop(first);
        assert!(!root.exists());

        let second = acquire_system_authority_slot(&directory, &sealed);
        assert!(!second.generation_exists());
        let second_bound = bind_system_authority_ledger(&second, &sealed);
        assert!(second_bound.journal_exposure_is_committed().unwrap());
        assert!(matches!(
            second_bound.with_startup_root_recovery(|startup| {
                second.open_reverified(&sealed, startup, false)
            }),
            Ok(Err(JournalStoreError::Corrupt))
        ));
        assert!(!root.exists());
    }

    #[cfg(all(target_os = "linux", feature = "storage"))]
    #[test]
    fn file_authority_marked_generation_missing_core_anchor_rejects_before_cleanup() {
        for (index, missing) in ["genesis", "heads"].into_iter().enumerate() {
            let directory = TestDirectory::new("authority-marker-missing-anchor");
            let sealed = crate::agent::replay::tests::admitted_genesis(0xe4 + index as u8);
            let first = acquire_system_authority_slot(&directory, &sealed);
            let first_bound = bind_system_authority_ledger(&first, &sealed);
            let store = initialize_unexposed_system_authority_slot(first, &first_bound, &sealed);
            assert!(first_bound.journal_exposure_is_committed().unwrap());
            let root = store.root().to_path_buf();
            drop(store);
            drop(first_bound);

            fs::remove_file(root.join(missing)).unwrap();
            let private_stage = root.join("heads.next.partial");
            fs::write(&private_stage, b"must survive failed marked preflight").unwrap();
            let second = acquire_system_authority_slot(&directory, &sealed);
            let second_bound = bind_system_authority_ledger(&second, &sealed);
            assert!(second_bound.journal_exposure_is_committed().unwrap());
            assert!(matches!(
                second_bound.with_startup_root_recovery(|startup| {
                    second.open_reverified(&sealed, startup, false)
                }),
                Ok(Err(JournalStoreError::Corrupt))
            ));
            assert!(!root.join(missing).exists());
            assert_eq!(
                fs::read(&private_stage).unwrap(),
                b"must survive failed marked preflight"
            );
        }
    }

    #[cfg(all(target_os = "linux", feature = "storage"))]
    #[test]
    fn file_authority_marked_generation_never_repairs_heads_stage() {
        let directory = TestDirectory::new("authority-marker-heads-stage");
        let sealed = crate::agent::replay::tests::admitted_genesis(0xe6);
        let first = acquire_system_authority_slot(&directory, &sealed);
        let first_bound = bind_system_authority_ledger(&first, &sealed);
        let store = initialize_unexposed_system_authority_slot(first, &first_bound, &sealed);
        let root = store.root().to_path_buf();
        drop(store);
        drop(first_bound);
        fs::copy(root.join("heads"), root.join("heads.next")).unwrap();

        let second = acquire_system_authority_slot(&directory, &sealed);
        let second_bound = bind_system_authority_ledger(&second, &sealed);
        assert!(second_bound.journal_exposure_is_committed().unwrap());
        assert!(matches!(
            second_bound.with_startup_root_recovery(|startup| {
                second.open_reverified(&sealed, startup, false)
            }),
            Ok(Err(JournalStoreError::Corrupt))
        ));
        assert!(root.join("heads.next").is_file());
    }

    #[cfg(all(target_os = "linux", feature = "storage"))]
    #[test]
    fn file_authority_unexposed_foreign_fixed_prefixes_reject_without_any_root_write() {
        for (index, shape) in ["admission-only", "staged-genesis", "genesis-no-heads"]
            .into_iter()
            .enumerate()
        {
            let directory = TestDirectory::new("authority-unexposed-foreign-prefix");
            let sealed = crate::agent::replay::tests::admitted_genesis(0x71 + index as u8);
            let foreign = crate::agent::replay::tests::admitted_genesis(0x81 + index as u8);
            let root =
                initialize_system_authority_slot_without_exposure_marker(&directory, &sealed);
            let admission = fs::read(root.join("genesis-admission")).unwrap();
            let foreign_genesis = foreign.genesis().encode();

            match shape {
                "admission-only" => {
                    retain_root_files(&root, &["genesis-admission"]);
                    fs::write(root.join("genesis-admission"), [0xa5; 32]).unwrap();
                }
                "staged-genesis" => {
                    retain_root_files(&root, &["genesis-admission"]);
                    assert_eq!(fs::read(root.join("genesis-admission")).unwrap(), admission);
                    fs::write(root.join("genesis.next"), &foreign_genesis).unwrap();
                }
                "genesis-no-heads" => {
                    retain_root_files(&root, &["genesis-admission", "genesis"]);
                    fs::write(root.join("genesis"), &foreign_genesis).unwrap();
                }
                _ => unreachable!(),
            }
            fs::write(
                root.join("heads.next.partial"),
                b"must not be cleaned before sealed-prefix admission",
            )
            .unwrap();
            let before = snapshot_file_tree(&root);

            let slot = acquire_system_authority_slot(&directory, &sealed);
            let bound = bind_system_authority_ledger(&slot, &sealed);
            assert!(!bound.journal_exposure_is_committed().unwrap());
            assert!(matches!(
                bound.with_startup_root_recovery(|startup| {
                    slot.open_reverified(&sealed, startup, false)
                }),
                Ok(Err(
                    JournalStoreError::ScopeMismatch | JournalStoreError::Corrupt
                ))
            ));
            assert_eq!(snapshot_file_tree(&root), before, "shape {shape}");
        }
    }

    #[cfg(all(target_os = "linux", feature = "storage"))]
    #[test]
    fn file_authority_unexposed_prefix_rejects_unknown_namespace_before_stage_cleanup() {
        let directory = TestDirectory::new("authority-unexposed-unknown-prefix");
        let sealed = crate::agent::replay::tests::admitted_genesis(0x75);
        let root = initialize_system_authority_slot_without_exposure_marker(&directory, &sealed);
        fs::remove_file(root.join("heads")).unwrap();
        fs::write(root.join("heads.next.partial"), b"retryable private stage").unwrap();
        fs::write(
            root.join("foreign-root-entry"),
            b"must force zero-write quarantine",
        )
        .unwrap();
        let before = snapshot_file_tree(&root);

        let slot = acquire_system_authority_slot(&directory, &sealed);
        let bound = bind_system_authority_ledger(&slot, &sealed);
        assert!(matches!(
            bound.with_startup_root_recovery(|startup| {
                slot.open_reverified(&sealed, startup, false)
            }),
            Ok(Err(JournalStoreError::Corrupt))
        ));
        assert_eq!(snapshot_file_tree(&root), before);
    }

    #[cfg(all(target_os = "linux", feature = "storage"))]
    #[test]
    fn file_authority_fixed_canonicals_with_external_links_fail_closed_before_replay() {
        for (exposed_index, exposed) in [false, true].into_iter().enumerate() {
            for (anchor_index, anchor) in ["genesis-admission", "genesis", "heads"]
                .into_iter()
                .enumerate()
            {
                let directory = TestDirectory::new("authority-fixed-canonical-external-link");
                let sealed = crate::agent::replay::tests::admitted_genesis(
                    0x91 + (exposed_index * 3 + anchor_index) as u8,
                );
                let root = if exposed {
                    let slot = acquire_system_authority_slot(&directory, &sealed);
                    let bound = bind_system_authority_ledger(&slot, &sealed);
                    let store = initialize_unexposed_system_authority_slot(slot, &bound, &sealed);
                    let root = store.root().to_path_buf();
                    drop(store);
                    drop(bound);
                    root
                } else {
                    initialize_system_authority_slot_without_exposure_marker(&directory, &sealed)
                };
                let alias = directory.0.join(format!("external-{anchor}"));
                fs::hard_link(root.join(anchor), &alias).unwrap();
                let before = snapshot_file_tree(&root);
                let alias_bytes = fs::read(&alias).unwrap();

                let slot = acquire_system_authority_slot(&directory, &sealed);
                let bound = bind_system_authority_ledger(&slot, &sealed);
                assert!(matches!(
                    bound.with_startup_root_recovery(|startup| {
                        slot.open_reverified(&sealed, startup, false)
                    }),
                    Ok(Err(JournalStoreError::Corrupt))
                ));
                assert_eq!(snapshot_file_tree(&root), before);
                assert_eq!(fs::read(&alias).unwrap(), alias_bytes);
                assert_eq!(fs::metadata(root.join(anchor)).unwrap().nlink(), 2);
            }
        }
    }

    #[cfg(all(target_os = "linux", feature = "storage"))]
    #[test]
    fn file_authority_impossible_fixed_stage_links_fail_closed_without_cleanup() {
        for (case_index, external_stage_link) in [true, false].into_iter().enumerate() {
            for (anchor_index, anchor) in ["genesis-admission", "genesis", "heads"]
                .into_iter()
                .enumerate()
            {
                let directory = TestDirectory::new("authority-impossible-fixed-stage-link");
                let sealed = crate::agent::replay::tests::admitted_genesis(
                    0xa1 + (case_index * 3 + anchor_index) as u8,
                );
                let root =
                    initialize_system_authority_slot_without_exposure_marker(&directory, &sealed);
                match anchor {
                    "genesis-admission" => retain_root_files(&root, &["genesis-admission"]),
                    "genesis" => retain_root_files(&root, &["genesis-admission", "genesis"]),
                    "heads" => retain_root_files(&root, &["genesis-admission", "genesis", "heads"]),
                    _ => unreachable!(),
                }
                let canonical = root.join(anchor);
                let stage = root.join(format!("{anchor}.next"));
                let external = directory.0.join(format!("external-stage-{anchor}"));
                if external_stage_link {
                    fs::rename(&canonical, &stage).unwrap();
                    fs::hard_link(&stage, &external).unwrap();
                } else {
                    fs::copy(&canonical, &stage).unwrap();
                }
                let before = snapshot_file_tree(&root);

                let slot = acquire_system_authority_slot(&directory, &sealed);
                let bound = bind_system_authority_ledger(&slot, &sealed);
                assert!(matches!(
                    bound.with_startup_root_recovery(|startup| {
                        slot.open_reverified(&sealed, startup, false)
                    }),
                    Ok(Err(JournalStoreError::Corrupt))
                ));
                assert_eq!(snapshot_file_tree(&root), before);
                if external_stage_link {
                    assert!(external.is_file());
                    assert_eq!(fs::metadata(&stage).unwrap().nlink(), 2);
                } else {
                    assert_ne!(
                        fs::metadata(&canonical).unwrap().ino(),
                        fs::metadata(&stage).unwrap().ino()
                    );
                }
            }
        }
    }

    #[cfg(all(target_os = "linux", feature = "storage"))]
    #[test]
    fn file_authority_exact_fixed_publication_aliases_remain_recoverable() {
        for (index, anchor) in ["genesis-admission", "genesis"].into_iter().enumerate() {
            let directory = TestDirectory::new("authority-fixed-publication-alias");
            let sealed = crate::agent::replay::tests::admitted_genesis(0xb1 + index as u8);
            let root =
                initialize_system_authority_slot_without_exposure_marker(&directory, &sealed);
            if anchor == "genesis-admission" {
                fs::remove_file(root.join("genesis")).unwrap();
            }
            fs::remove_file(root.join("heads")).unwrap();
            let stage = root.join(format!("{anchor}.next"));
            fs::hard_link(root.join(anchor), &stage).unwrap();
            assert_eq!(fs::metadata(root.join(anchor)).unwrap().nlink(), 2);

            let slot = acquire_system_authority_slot(&directory, &sealed);
            let bound = bind_system_authority_ledger(&slot, &sealed);
            let store = bound
                .with_startup_root_recovery(|startup| {
                    let mut store = slot.open_reverified(&sealed, startup, false)?;
                    assert!(store.initialize(&sealed)?);
                    Ok::<_, JournalStoreError>(store)
                })
                .unwrap()
                .unwrap();
            assert!(!stage.exists());
            assert_eq!(fs::metadata(root.join(anchor)).unwrap().nlink(), 1);
            assert_eq!(store.genesis().unwrap(), Some(sealed.genesis().clone()));
            assert_eq!(store.heads().unwrap(), Some(sealed.initial_heads()));
        }
    }

    #[cfg(all(target_os = "linux", feature = "storage"))]
    #[test]
    fn file_authority_ledger_capability_rejects_canonical_inode_replacement() {
        let directory = TestDirectory::new("authority-slot-ledger-replacement");
        let sealed = crate::agent::replay::tests::admitted_genesis(0xd8);
        let agent = sealed.genesis().runtime().agent;
        let (canonical, staged) = system_authority_ledger_paths(&directory, agent);

        let slot = acquire_system_authority_slot(&directory, &sealed);
        let bound = bind_system_authority_ledger(&slot, &sealed);
        let displaced = directory.0.join("displaced-system-authority-ledger.redb");
        fs::rename(&canonical, &displaced).unwrap();
        fs::copy(&displaced, &canonical).unwrap();
        assert_ne!(
            fs::metadata(&canonical).unwrap().ino(),
            fs::metadata(&displaced).unwrap().ino()
        );

        assert_eq!(bound.verify(), Err(JournalStoreError::Corrupt));
        let entered = std::cell::Cell::new(false);
        assert!(matches!(
            bound.with_root_mutation(|| entered.set(true)),
            Err(SystemAuthorityLedgerError::CorruptLedger)
        ));
        assert!(!entered.get());
        assert!(!staged.exists());
    }

    #[cfg(all(target_os = "linux", feature = "storage"))]
    #[test]
    fn file_authority_staged_open_rejects_an_unknown_redb_table() {
        use redb::TableHandle as _;

        const UNKNOWN_TABLE: redb::TableDefinition<&[u8], &[u8]> =
            redb::TableDefinition::new("unknown_system_authority_table");

        let directory = TestDirectory::new("authority-slot-unknown-table");
        let sealed = crate::agent::replay::tests::admitted_genesis(0xd9);
        let slot = acquire_system_authority_slot(&directory, &sealed);
        let ledger = slot.open_system_authority_ledger().unwrap();
        let database = ledger.database();
        let transaction = database.begin_write().unwrap();
        {
            let mut table = transaction.open_table(UNKNOWN_TABLE).unwrap();
            table
                .insert(b"foreign".as_slice(), b"row".as_slice())
                .unwrap();
        }
        transaction.commit().unwrap();

        assert!(matches!(
            SystemAuthorityLedgerRouteOwner::open_staged(
                Arc::clone(&database),
                sealed.system_authority_ledger_route().unwrap(),
                slot.instance_id(),
                slot.node(),
            ),
            Err(SystemAuthorityLedgerError::ConfigurationMismatch)
        ));
        let transaction = database.begin_write().unwrap();
        let names = transaction
            .list_tables()
            .unwrap()
            .map(|table| table.name().to_owned())
            .collect::<Vec<_>>();
        drop(transaction);
        assert_eq!(names, vec![UNKNOWN_TABLE.name().to_owned()]);
    }

    #[cfg(all(target_os = "linux", feature = "storage"))]
    #[test]
    fn file_authority_staged_open_rejects_an_unknown_redb_multimap_table() {
        use redb::MultimapTableHandle as _;

        const UNKNOWN_MULTIMAP: redb::MultimapTableDefinition<&[u8], &[u8]> =
            redb::MultimapTableDefinition::new("unknown_system_authority_multimap");

        let directory = TestDirectory::new("authority-slot-unknown-multimap");
        let sealed = crate::agent::replay::tests::admitted_genesis(0xde);
        let slot = acquire_system_authority_slot(&directory, &sealed);
        let ledger = slot.open_system_authority_ledger().unwrap();
        let database = ledger.database();
        let transaction = database.begin_write().unwrap();
        drop(transaction.open_multimap_table(UNKNOWN_MULTIMAP).unwrap());
        transaction.commit().unwrap();

        assert!(matches!(
            SystemAuthorityLedgerRouteOwner::open_staged(
                Arc::clone(&database),
                sealed.system_authority_ledger_route().unwrap(),
                slot.instance_id(),
                slot.node(),
            ),
            Err(SystemAuthorityLedgerError::ConfigurationMismatch)
        ));
        let transaction = database.begin_write().unwrap();
        let names = transaction
            .list_multimap_tables()
            .unwrap()
            .map(|table| table.name().to_owned())
            .collect::<Vec<_>>();
        drop(transaction);
        assert_eq!(names, vec![UNKNOWN_MULTIMAP.name().to_owned()]);
    }

    #[cfg(all(target_os = "linux", feature = "storage"))]
    #[test]
    fn file_authority_staged_open_rejects_and_preserves_a_foreign_route_database() {
        let directory = TestDirectory::new("authority-slot-foreign-route");
        let sealed = crate::agent::replay::tests::admitted_genesis(0xdf);
        let foreign = crate::agent::replay::tests::admitted_genesis(0xe0);
        let slot = acquire_system_authority_slot(&directory, &sealed);
        let ledger = slot.open_system_authority_ledger().unwrap();
        let database = ledger.database();
        let route = sealed.system_authority_ledger_route().unwrap();
        let foreign_route = foreign.system_authority_ledger_route().unwrap();
        assert_ne!(route, foreign_route);
        let owner = SystemAuthorityLedgerRouteOwner::open_staged(
            Arc::clone(&database),
            route,
            slot.instance_id(),
            slot.node(),
        )
        .unwrap();
        drop(owner);

        assert!(matches!(
            SystemAuthorityLedgerRouteOwner::open_staged(
                Arc::clone(&database),
                foreign_route,
                slot.instance_id(),
                slot.node(),
            ),
            Err(SystemAuthorityLedgerError::ConfigurationMismatch)
        ));
        let reopened = SystemAuthorityLedgerRouteOwner::open_staged(
            database,
            route,
            slot.instance_id(),
            slot.node(),
        )
        .unwrap();
        assert_eq!(reopened.route(), route);
        let agent = sealed.genesis().runtime().agent;
        let (canonical, staged) = system_authority_ledger_paths(&directory, agent);
        assert!(staged.is_file());
        assert!(!canonical.exists());
    }

    #[cfg(all(target_os = "linux", feature = "storage"))]
    #[test]
    fn file_authority_owner_open_token_rejects_a_mismatched_slot_agent_unchanged() {
        let directory = TestDirectory::new("authority-slot-owner-open-foreign-agent");
        let sealed = crate::agent::replay::tests::admitted_genesis(0xe3);
        let foreign_agent = AgentId([0xf4; 32]);
        assert_ne!(sealed.genesis().runtime().agent, foreign_agent);
        let slot = FileAgentJournalSlot::acquire(
            directory.agent_root(foreign_agent),
            directory.lock(foreign_agent),
            sealed.replica().node,
        )
        .unwrap();
        let ledger = slot.open_system_authority_ledger().unwrap();
        let (canonical, staged) = system_authority_ledger_paths(&directory, foreign_agent);

        assert!(matches!(
            SystemAuthorityLedgerRouteOwner::open_file(ledger.into_owner_open(), &sealed),
            Err(SystemAuthorityLedgerError::ConfigurationMismatch)
        ));
        assert!(!canonical.exists());
        let database = Database::open(staged).unwrap();
        let transaction = database.begin_write().unwrap();
        assert_eq!(transaction.list_tables().unwrap().count(), 0);
        drop(transaction);
    }

    #[cfg(all(target_os = "linux", feature = "storage"))]
    #[test]
    fn file_authority_canonical_open_mode_never_initializes_an_empty_database() {
        let directory = TestDirectory::new("authority-slot-strict-canonical");
        let sealed = crate::agent::replay::tests::admitted_genesis(0xda);

        let first = acquire_system_authority_slot(&directory, &sealed);
        let mut ledger = first.open_system_authority_ledger().unwrap();
        ledger.finish_owner_open().unwrap();
        drop(ledger);
        drop(first);

        let second = acquire_system_authority_slot(&directory, &sealed);
        let ledger = second.open_system_authority_ledger().unwrap();
        assert_eq!(
            ledger.mode(),
            FileSystemAuthorityLedgerOpenMode::ExistingCanonical
        );
        let agent = sealed.genesis().runtime().agent;
        let (canonical, staged) = system_authority_ledger_paths(&directory, agent);
        assert!(matches!(
            SystemAuthorityLedgerRouteOwner::open_file(ledger.into_owner_open(), &sealed),
            Err(SystemAuthorityLedgerError::ConfigurationMismatch)
        ));
        assert!(!staged.exists());
        let database = Database::open(canonical).unwrap();
        let transaction = database.begin_write().unwrap();
        assert_eq!(transaction.list_tables().unwrap().count(), 0);
        drop(transaction);
    }

    #[test]
    fn reopen_rejects_unknown_root_shape() {
        let directory = TestDirectory::new("shape");
        let store = open_file_store(&directory);
        fs::write(store.root().join("unexpected"), b"not canonical").unwrap();
        drop(store);
        assert!(matches!(
            FileAgentJournalStore::open(
                directory.agent_root(config().identity.agent),
                directory.lock(config().identity.agent),
                config().replicas[0].node,
            ),
            Err(JournalStoreError::Corrupt)
        ));
    }
}

fn clean_absolute_path(path: PathBuf) -> Result<PathBuf, JournalStoreError> {
    let path = if path.is_absolute() {
        path
    } else {
        std::env::current_dir()
            .map_err(|_| JournalStoreError::Unavailable)?
            .join(path)
    };
    if path.components().any(|component| {
        matches!(
            component,
            Component::CurDir | Component::ParentDir | Component::Prefix(_)
        )
    }) {
        return Err(JournalStoreError::InvalidPath);
    }
    Ok(path)
}

fn agent_from_root_path(path: &Path) -> Result<AgentId, JournalStoreError> {
    if path.extension().and_then(|extension| extension.to_str()) != Some("agent") {
        return Err(JournalStoreError::InvalidPath);
    }
    let stem = path
        .file_stem()
        .and_then(|stem| stem.to_str())
        .ok_or(JournalStoreError::InvalidPath)?;
    decode_agent_id(stem).ok_or(JournalStoreError::InvalidPath)
}

fn decode_agent_id(value: &str) -> Option<AgentId> {
    if value.len() != 64 || !value.is_ascii() {
        return None;
    }
    let mut bytes = [0_u8; 32];
    for (index, pair) in value.as_bytes().chunks_exact(2).enumerate() {
        bytes[index] = (decode_nibble(pair[0])? << 4) | decode_nibble(pair[1])?;
    }
    let id = AgentId(bytes);
    (id != AgentId::ZERO).then_some(id)
}

fn decode_nibble(byte: u8) -> Option<u8> {
    match byte {
        b'0'..=b'9' => Some(byte - b'0'),
        b'a'..=b'f' => Some(byte - b'a' + 10),
        _ => None,
    }
}

fn encode_hex(bytes: &[u8; 32]) -> String {
    const HEX: &[u8; 16] = b"0123456789abcdef";
    let mut output = String::with_capacity(64);
    for byte in bytes {
        output.push(HEX[(byte >> 4) as usize] as char);
        output.push(HEX[(byte & 0x0f) as usize] as char);
    }
    output
}

fn sibling_next_name(name: &str) -> String {
    format!("{name}.next")
}

#[cfg(target_os = "linux")]
const PRIVATE_STAGE_SUFFIX: &str = ".next.partial";

#[cfg(target_os = "linux")]
fn private_stage_name(stage: &str) -> Result<String, JournalStoreError> {
    if !stage.ends_with(".next") {
        return Err(JournalStoreError::InvalidPath);
    }
    Ok(format!("{stage}.partial"))
}

#[cfg(target_os = "linux")]
fn is_fixed_private_stage_name(name: &[u8]) -> bool {
    matches!(
        name,
        b"genesis-admission.next.partial"
            | b"genesis.next.partial"
            | b"heads.next.partial"
            | b"gc-intent.next.partial"
    )
}

#[cfg(target_os = "linux")]
fn is_history_fixed_private_stage_name(name: &[u8]) -> bool {
    matches!(
        name,
        b"candidate-intent.next.partial" | b"retirements.next.partial"
    )
}

#[cfg(target_os = "linux")]
fn is_history_candidate_private_stage_name(name: &[u8]) -> bool {
    matches!(
        name,
        b"plan-0.next.partial" | b"plan-1.next.partial" | b"plan-2.next.partial"
    )
}

#[cfg(target_os = "linux")]
fn is_content_private_stage_name(name: &[u8]) -> bool {
    let Some(stem) = name.strip_suffix(PRIVATE_STAGE_SUFFIX.as_bytes()) else {
        return false;
    };
    stem.len() == 64
        && stem
            .iter()
            .all(|byte| byte.is_ascii_digit() || matches!(byte, b'a'..=b'f'))
}

#[cfg(target_os = "linux")]
fn c_name(name: &str) -> Result<CString, JournalStoreError> {
    if name.is_empty() || name == "." || name == ".." || name.as_bytes().contains(&b'/') {
        return Err(JournalStoreError::InvalidPath);
    }
    CString::new(name).map_err(|_| JournalStoreError::InvalidPath)
}

#[cfg(target_os = "linux")]
fn open_directory_path(path: &Path) -> Result<File, JournalStoreError> {
    let name =
        CString::new(path.as_os_str().as_bytes()).map_err(|_| JournalStoreError::InvalidPath)?;
    // SAFETY: `name` is NUL-terminated and the returned descriptor is uniquely
    // owned by the `File` constructed on success.
    let descriptor = unsafe {
        libc::open(
            name.as_ptr(),
            libc::O_RDONLY
                | libc::O_DIRECTORY
                | libc::O_NOFOLLOW
                | libc::O_CLOEXEC
                | libc::O_NONBLOCK,
        )
    };
    if descriptor < 0 {
        return Err(JournalStoreError::Unavailable);
    }
    // SAFETY: successful `open` returned a fresh owned descriptor.
    Ok(unsafe { File::from_raw_fd(descriptor) })
}

#[cfg(target_os = "linux")]
fn open_at(
    directory: &File,
    name: &CStr,
    flags: libc::c_int,
    mode: libc::mode_t,
) -> std::io::Result<File> {
    // SAFETY: both descriptor and C string remain valid for the call; a
    // successful result is a fresh owned descriptor.
    let descriptor = unsafe { libc::openat(directory.as_raw_fd(), name.as_ptr(), flags, mode) };
    if descriptor < 0 {
        Err(std::io::Error::last_os_error())
    } else {
        // SAFETY: successful `openat` returned a fresh owned descriptor.
        Ok(unsafe { File::from_raw_fd(descriptor) })
    }
}

#[cfg(target_os = "linux")]
fn validate_slot_entry_shapes(
    generation: Option<&libc::stat>,
    canonical_ledger: Option<&libc::stat>,
    staged_ledger: Option<&libc::stat>,
    stable_lock: Option<&libc::stat>,
) -> Result<(), JournalStoreError> {
    // SAFETY: `geteuid` has no preconditions or borrowed state.
    let effective_user = unsafe { libc::geteuid() };
    if let Some(status) = generation
        && (status.st_mode & libc::S_IFMT != libc::S_IFDIR
            || status.st_uid != effective_user
            || status.st_mode & 0o022 != 0)
    {
        return Err(JournalStoreError::Corrupt);
    }
    for status in [canonical_ledger, staged_ledger, stable_lock]
        .into_iter()
        .flatten()
    {
        if status.st_mode & libc::S_IFMT != libc::S_IFREG
            || status.st_uid != effective_user
            || status.st_mode & 0o022 != 0
        {
            return Err(JournalStoreError::Corrupt);
        }
    }
    if stable_lock.is_some_and(|status| status.st_nlink != 1) {
        return Err(JournalStoreError::Corrupt);
    }
    match (canonical_ledger, staged_ledger) {
        (Some(canonical), Some(staged))
            if status_identity(canonical) == status_identity(staged) =>
        {
            // The sole multi-link state is the exact crash alias after the
            // canonical ledger link became durable and before `.next` was
            // removed. Any third name makes the inode attacker-controlled.
            if canonical.st_nlink != 2 || staged.st_nlink != 2 {
                return Err(JournalStoreError::Corrupt);
            }
        }
        (Some(canonical), Some(staged)) => {
            if canonical.st_nlink != 1 || staged.st_nlink != 1 {
                return Err(JournalStoreError::Corrupt);
            }
        }
        (Some(canonical), None) if canonical.st_nlink != 1 => {
            return Err(JournalStoreError::Corrupt);
        }
        (None, Some(staged)) if staged.st_nlink != 1 => {
            return Err(JournalStoreError::Corrupt);
        }
        _ => {}
    }
    Ok(())
}

#[cfg(target_os = "linux")]
fn validate_pre_lock_stage_freshness(
    staged_ledger: Option<&libc::stat>,
    stable_lock: Option<&libc::stat>,
) -> Result<(), JournalStoreError> {
    // Before a stable lock contains its complete nonce, the only legitimate
    // authority stage is the exact empty inode durably created as the
    // freshness witness. A non-empty stage may be an initialized redb only
    // after a complete lock serialized that initialization. Reject garbage
    // before creating or repairing lock bytes.
    let incomplete_lock =
        stable_lock.is_none_or(|lock| lock.st_size < STABLE_LOCK_NONCE_BYTES as i64);
    if incomplete_lock && staged_ledger.is_some_and(|stage| stage.st_size != 0)
        || stable_lock.is_some_and(|lock| lock.st_size < STABLE_LOCK_NONCE_BYTES as i64)
            && staged_ledger.is_none()
    {
        return Err(JournalStoreError::Corrupt);
    }
    Ok(())
}

#[cfg(target_os = "linux")]
fn resync_pristine_ledger_stage(
    parent: &File,
    name: &CStr,
    expected: &libc::stat,
) -> Result<(), JournalStoreError> {
    if expected.st_size != 0 || expected.st_nlink != 1 {
        return Err(JournalStoreError::Corrupt);
    }
    let stage = open_owned_regular_at(parent, name)?;
    let identity = status_identity(expected);
    if FileIdentity::of(&stage)? != identity
        || stage
            .metadata()
            .map_err(|_| JournalStoreError::Unavailable)?
            .len()
            != 0
    {
        return Err(JournalStoreError::Corrupt);
    }
    stage
        .sync_all()
        .and_then(|()| parent.sync_all())
        .map_err(|_| JournalStoreError::Unavailable)?;
    verify_regular_entry(parent, name, identity)?;
    require_single_link(&stage)
}

#[cfg(target_os = "linux")]
fn create_empty_exclusive_regular_at(parent: &File, name: &CStr) -> std::io::Result<File> {
    open_at(
        parent,
        name,
        libc::O_RDWR
            | libc::O_CREAT
            | libc::O_EXCL
            | libc::O_NOFOLLOW
            | libc::O_CLOEXEC
            | libc::O_NONBLOCK,
        0o600,
    )
}

#[cfg(target_os = "linux")]
fn open_owned_regular_at(parent: &File, name: &CStr) -> Result<File, JournalStoreError> {
    let file = open_at(
        parent,
        name,
        libc::O_RDWR | libc::O_NOFOLLOW | libc::O_CLOEXEC | libc::O_NONBLOCK,
        0,
    )
    .map_err(|_| JournalStoreError::Corrupt)?;
    validate_owned_regular_file(&file)?;
    Ok(file)
}

#[cfg(all(target_os = "linux", feature = "storage"))]
fn proc_fd_path(file: &File) -> PathBuf {
    PathBuf::from(format!("/proc/self/fd/{}", file.as_raw_fd()))
}

#[cfg(target_os = "linux")]
fn link_file_at_cstr(parent: &File, from: &CStr, to: &CStr) -> std::io::Result<()> {
    // SAFETY: both names are relative, separator-free C strings and the
    // descriptor remains live throughout the call.
    if unsafe {
        libc::linkat(
            parent.as_raw_fd(),
            from.as_ptr(),
            parent.as_raw_fd(),
            to.as_ptr(),
            0,
        )
    } == 0
    {
        Ok(())
    } else {
        Err(std::io::Error::last_os_error())
    }
}

#[cfg(target_os = "linux")]
fn unlink_file_at_cstr(parent: &File, name: &CStr) -> Result<(), JournalStoreError> {
    // SAFETY: descriptor/name are valid and the relative name is not followed.
    if unsafe { libc::unlinkat(parent.as_raw_fd(), name.as_ptr(), 0) } == 0 {
        Ok(())
    } else {
        Err(JournalStoreError::Unavailable)
    }
}

#[cfg(target_os = "linux")]
fn stat_at(directory: &File, name: &CStr) -> std::io::Result<Option<libc::stat>> {
    let mut status = core::mem::MaybeUninit::<libc::stat>::uninit();
    // SAFETY: the descriptor/name are valid and `status` points to writable
    // storage initialized by a successful `fstatat`.
    let result = unsafe {
        libc::fstatat(
            directory.as_raw_fd(),
            name.as_ptr(),
            status.as_mut_ptr(),
            libc::AT_SYMLINK_NOFOLLOW,
        )
    };
    if result == 0 {
        // SAFETY: successful `fstatat` initialized the value.
        Ok(Some(unsafe { status.assume_init() }))
    } else {
        let error = std::io::Error::last_os_error();
        if error.raw_os_error() == Some(libc::ENOENT) {
            Ok(None)
        } else {
            Err(error)
        }
    }
}

#[cfg(target_os = "linux")]
fn status_identity(status: &libc::stat) -> FileIdentity {
    FileIdentity {
        device: status.st_dev,
        inode: status.st_ino,
    }
}

#[cfg(target_os = "linux")]
fn validate_safe_ancestor_directory(directory: &File) -> Result<(), JournalStoreError> {
    let metadata = directory
        .metadata()
        .map_err(|_| JournalStoreError::Unavailable)?;
    // SAFETY: `geteuid` has no preconditions or borrowed state.
    let effective_user = unsafe { libc::geteuid() };
    let trusted_owner = metadata.uid() == 0
        || metadata.uid() == effective_user
        || uid_is_unmapped_overflow(metadata.uid())?;
    let writable = metadata.mode() & 0o022 != 0;
    let protected_sticky = metadata.mode() & libc::S_ISVTX != 0 && trusted_owner;
    if !metadata.file_type().is_dir() || !trusted_owner || writable && !protected_sticky {
        return Err(JournalStoreError::InvalidPath);
    }
    Ok(())
}

#[cfg(target_os = "linux")]
pub(super) fn uid_is_unmapped_overflow(uid: u32) -> Result<bool, JournalStoreError> {
    const MAX_PROC_ID_MAP_BYTES: u64 = 32 * 1024;
    const MAX_PROC_OVERFLOW_UID_BYTES: u64 = 32;

    fn read_bounded(path: &str, maximum: u64) -> Result<String, JournalStoreError> {
        let mut bytes = Vec::new();
        File::open(path)
            .map_err(|_| JournalStoreError::InvalidPath)?
            .take(maximum + 1)
            .read_to_end(&mut bytes)
            .map_err(|_| JournalStoreError::InvalidPath)?;
        if bytes.len() as u64 > maximum {
            return Err(JournalStoreError::InvalidPath);
        }
        String::from_utf8(bytes).map_err(|_| JournalStoreError::InvalidPath)
    }

    let overflow = read_bounded("/proc/sys/kernel/overflowuid", MAX_PROC_OVERFLOW_UID_BYTES)?
        .trim()
        .parse::<u32>()
        .map_err(|_| JournalStoreError::InvalidPath)?;
    if uid != overflow {
        return Ok(false);
    }
    let uid_map = read_bounded("/proc/self/uid_map", MAX_PROC_ID_MAP_BYTES)?;
    uid_is_unmapped_in_id_map(uid, &uid_map).ok_or(JournalStoreError::InvalidPath)
}

#[cfg(target_os = "linux")]
fn uid_is_unmapped_in_id_map(uid: u32, id_map: &str) -> Option<bool> {
    let uid = u64::from(uid);
    let mut saw_range = false;
    let mut mapped = false;
    for line in id_map.lines() {
        let mut fields = line.split_whitespace();
        let inside = fields.next()?.parse::<u64>().ok()?;
        let _outside = fields.next()?.parse::<u64>().ok()?;
        let count = fields.next()?.parse::<u64>().ok()?;
        if count == 0 || fields.next().is_some() {
            return None;
        }
        saw_range = true;
        if uid >= inside && uid - inside < count {
            mapped = true;
        }
    }
    saw_range.then_some(!mapped)
}

#[cfg(target_os = "linux")]
fn validate_owned_directory(directory: &File) -> Result<(), JournalStoreError> {
    let metadata = directory
        .metadata()
        .map_err(|_| JournalStoreError::Unavailable)?;
    // SAFETY: `geteuid` has no preconditions or borrowed state.
    let effective_user = unsafe { libc::geteuid() };
    if !metadata.file_type().is_dir()
        || metadata.uid() != effective_user
        || metadata.mode() & 0o022 != 0
    {
        return Err(JournalStoreError::InvalidPath);
    }
    Ok(())
}

#[cfg(target_os = "linux")]
fn validate_owned_regular_file(file: &File) -> Result<(), JournalStoreError> {
    let metadata = file
        .metadata()
        .map_err(|_| JournalStoreError::Unavailable)?;
    // SAFETY: `geteuid` has no preconditions or borrowed state.
    let effective_user = unsafe { libc::geteuid() };
    if !metadata.file_type().is_file()
        || metadata.uid() != effective_user
        || metadata.mode() & 0o022 != 0
    {
        return Err(JournalStoreError::Corrupt);
    }
    Ok(())
}

#[cfg(target_os = "linux")]
fn require_single_link(file: &File) -> Result<(), JournalStoreError> {
    require_link_count(file, 1)
}

#[cfg(target_os = "linux")]
fn require_link_count(file: &File, expected: u64) -> Result<(), JournalStoreError> {
    if file
        .metadata()
        .map_err(|_| JournalStoreError::Unavailable)?
        .nlink()
        != expected
    {
        return Err(JournalStoreError::Corrupt);
    }
    Ok(())
}

#[cfg(target_os = "linux")]
fn verify_directory_entry(
    parent: &File,
    name: &CStr,
    expected: FileIdentity,
) -> Result<(), JournalStoreError> {
    let status = stat_at(parent, name)
        .map_err(|_| JournalStoreError::Unavailable)?
        .ok_or(JournalStoreError::Corrupt)?;
    if status.st_mode & libc::S_IFMT != libc::S_IFDIR || status_identity(&status) != expected {
        return Err(JournalStoreError::Corrupt);
    }
    Ok(())
}

#[cfg(target_os = "linux")]
fn verify_regular_entry(
    parent: &File,
    name: &CStr,
    expected: FileIdentity,
) -> Result<(), JournalStoreError> {
    let status = stat_at(parent, name)
        .map_err(|_| JournalStoreError::Unavailable)?
        .ok_or(JournalStoreError::Corrupt)?;
    // SAFETY: `geteuid` has no preconditions or borrowed state.
    let effective_user = unsafe { libc::geteuid() };
    if status.st_mode & libc::S_IFMT != libc::S_IFREG
        || status_identity(&status) != expected
        || status.st_uid != effective_user
        || status.st_mode & 0o022 != 0
    {
        return Err(JournalStoreError::Corrupt);
    }
    Ok(())
}

#[cfg(target_os = "linux")]
fn ensure_directory_at(parent: &File, name: &str) -> Result<(), JournalStoreError> {
    let name = c_name(name)?;
    match stat_at(parent, &name).map_err(|_| JournalStoreError::Unavailable)? {
        Some(status) if status.st_mode & libc::S_IFMT == libc::S_IFDIR => {}
        Some(_) => return Err(JournalStoreError::Corrupt),
        None => {
            // SAFETY: descriptor/name are valid and mode grants only the
            // owning process access before the caller applies its umask.
            if unsafe { libc::mkdirat(parent.as_raw_fd(), name.as_ptr(), 0o700) } != 0 {
                let error = std::io::Error::last_os_error();
                if error.raw_os_error() != Some(libc::EEXIST) {
                    return Err(JournalStoreError::Unavailable);
                }
            }
            let status = stat_at(parent, &name)
                .map_err(|_| JournalStoreError::Unavailable)?
                .ok_or(JournalStoreError::Unavailable)?;
            if status.st_mode & libc::S_IFMT != libc::S_IFDIR {
                return Err(JournalStoreError::Corrupt);
            }
        }
    }
    // Re-establish the mkdir durability boundary on every authorized retry.
    // The prior attempt may have created the leaf and then lost the result of
    // this parent sync.
    parent
        .sync_all()
        .map_err(|_| JournalStoreError::Unavailable)
}

#[cfg(target_os = "linux")]
fn open_directory_at(parent: &File, name: &str) -> Result<File, JournalStoreError> {
    open_at(
        parent,
        &c_name(name)?,
        libc::O_RDONLY | libc::O_DIRECTORY | libc::O_NOFOLLOW | libc::O_CLOEXEC | libc::O_NONBLOCK,
        0,
    )
    .map_err(|_| JournalStoreError::Corrupt)
}

#[cfg(target_os = "linux")]
fn open_optional_owned_directory_at(
    parent: &File,
    name: &str,
) -> Result<Option<File>, JournalStoreError> {
    let name_c = c_name(name)?;
    let Some(status) = stat_at(parent, &name_c).map_err(|_| JournalStoreError::Unavailable)? else {
        return Ok(None);
    };
    if status.st_mode & libc::S_IFMT != libc::S_IFDIR {
        return Err(JournalStoreError::Corrupt);
    }
    let directory = open_directory_at(parent, name)?;
    validate_owned_directory(&directory)?;
    let identity = FileIdentity::of(&directory)?;
    if identity != status_identity(&status) {
        return Err(JournalStoreError::Corrupt);
    }
    verify_directory_entry(parent, &name_c, identity)?;
    Ok(Some(directory))
}

/// Validate every structural name which mutable first-initialization recovery
/// can inspect, create beside, or clean. Dynamic content directories remain
/// content-addressed namespaces, but their complete ancestor shape is pinned
/// here before any private-stage unlink or missing-directory creation.
#[cfg(target_os = "linux")]
fn validate_unexposed_initialization_namespace(root: &File) -> Result<(), JournalStoreError> {
    validate_directory_names(
        root,
        &[
            "records",
            "checkpoints",
            "lane-state",
            "artifact-closures",
            "invocation-index",
            "invocation-outcomes",
            SHARED_ORDERED_COMMIT_DIRECTORY,
            HISTORY_DIRECTORY,
            "catalog",
            "authority",
            "genesis-admission",
            "genesis-admission.next",
            "genesis-admission.next.partial",
            "genesis",
            "genesis.next",
            "genesis.next.partial",
            "heads",
            "heads.next",
            "heads.next.partial",
        ],
    )?;

    for name in [
        "checkpoints",
        "artifact-closures",
        "invocation-outcomes",
        SHARED_ORDERED_COMMIT_DIRECTORY,
    ] {
        let _ = open_optional_owned_directory_at(root, name)?;
    }

    if let Some(records) = open_optional_owned_directory_at(root, "records")? {
        let children = [
            "replay-inputs",
            "ordered",
            "local",
            "merge-events",
            "merge-frontiers",
            "merge-seals",
        ];
        validate_directory_names(&records, &children)?;
        for name in children {
            let _ = open_optional_owned_directory_at(&records, name)?;
        }
    }
    if let Some(lane_state) = open_optional_owned_directory_at(root, "lane-state")? {
        let children = ["manifests", "blobs"];
        validate_directory_names(&lane_state, &children)?;
        for name in children {
            let _ = open_optional_owned_directory_at(&lane_state, name)?;
        }
    }
    if let Some(index) = open_optional_owned_directory_at(root, "invocation-index")? {
        let children = ["manifests", "nodes"];
        validate_directory_names(&index, &children)?;
        for name in children {
            let _ = open_optional_owned_directory_at(&index, name)?;
        }
    }
    if let Some(catalog) = open_optional_owned_directory_at(root, "catalog")? {
        validate_directory_names(&catalog, &["blobs"])?;
        let _ = open_optional_owned_directory_at(&catalog, "blobs")?;
    }
    if let Some(authority) = open_optional_owned_directory_at(root, "authority")? {
        let children = [
            "root-anchors",
            "genesis-evidence",
            "genesis-admissions",
            "system-decisions",
            "system-rotations",
            "system-catalog-nodes",
            "system-catalog-records",
            "system-committees",
        ];
        validate_directory_names(&authority, &children)?;
        for name in children {
            let _ = open_optional_owned_directory_at(&authority, name)?;
        }
    }
    if let Some(history) = open_optional_owned_directory_at(root, HISTORY_DIRECTORY)? {
        validate_directory_names(&history, &["nodes", "candidate"])?;
        if let Some(nodes) = open_optional_owned_directory_at(&history, "nodes")? {
            let shards = (0_u16..=255)
                .map(|value| format!("{value:02x}"))
                .collect::<Vec<_>>();
            let names = shards.iter().map(String::as_str).collect::<Vec<_>>();
            validate_directory_names(&nodes, &names)?;
            for name in &shards {
                let _ = open_optional_owned_directory_at(&nodes, name)?;
            }
        }
        if let Some(candidate) = open_optional_owned_directory_at(&history, "candidate")? {
            validate_directory_names(&candidate, &[])?;
        }
    }
    Ok(())
}

/// Verify the only hard-link states produced by fixed-anchor publication.
/// Admission and genesis use stage-to-canonical hard links; heads uses an
/// atomic rename. All three may retain the private-to-stage alias from the
/// earlier crash boundary. Any external/third alias is rejected.
#[cfg(target_os = "linux")]
fn validate_initialization_anchor_links(
    directory: &File,
    canonical: &str,
    hardlink_publication: bool,
) -> Result<(), JournalStoreError> {
    let stage = sibling_next_name(canonical);
    let private = private_stage_name(&stage)?;
    let canonical =
        stat_at(directory, &c_name(canonical)?).map_err(|_| JournalStoreError::Unavailable)?;
    let stage = stat_at(directory, &c_name(&stage)?).map_err(|_| JournalStoreError::Unavailable)?;
    let private =
        stat_at(directory, &c_name(&private)?).map_err(|_| JournalStoreError::Unavailable)?;
    let effective_user = unsafe { libc::geteuid() };
    for status in [canonical.as_ref(), stage.as_ref(), private.as_ref()]
        .into_iter()
        .flatten()
    {
        if status.st_mode & libc::S_IFMT != libc::S_IFREG
            || status.st_uid != effective_user
            || status.st_mode & 0o022 != 0
        {
            return Err(JournalStoreError::Corrupt);
        }
    }

    if let Some(private) = private.as_ref() {
        if let Some(stage) = stage.as_ref()
            && status_identity(private) == status_identity(stage)
        {
            if canonical.is_some() || private.st_nlink != 2 || stage.st_nlink != 2 {
                return Err(JournalStoreError::Corrupt);
            }
            return Ok(());
        }
        if canonical.is_none() && stage.is_none() && private.st_nlink == 1 {
            return Ok(());
        }
        return Err(JournalStoreError::Corrupt);
    }

    match (canonical.as_ref(), stage.as_ref()) {
        (None, None) => Ok(()),
        (Some(canonical), None) if canonical.st_nlink == 1 => Ok(()),
        (None, Some(stage)) if stage.st_nlink == 1 => Ok(()),
        (Some(canonical), Some(stage))
            if hardlink_publication
                && status_identity(canonical) == status_identity(stage)
                && canonical.st_nlink == 2
                && stage.st_nlink == 2 =>
        {
            Ok(())
        }
        _ => Err(JournalStoreError::Corrupt),
    }
}

#[cfg(target_os = "linux")]
const STABLE_LOCK_NONCE_BYTES: usize = 32;

#[cfg(target_os = "linux")]
const LOCAL_STABLE_LOCK_EXPOSED_BYTES: usize = STABLE_LOCK_NONCE_BYTES + 32;

#[cfg(target_os = "linux")]
fn stable_lock_nonce(
    file: &File,
    parent: &File,
) -> Result<[u8; STABLE_LOCK_NONCE_BYTES], JournalStoreError> {
    let length = file
        .metadata()
        .map_err(|_| JournalStoreError::Unavailable)?
        .len();
    let mut nonce = [0_u8; STABLE_LOCK_NONCE_BYTES];
    match length {
        0 => {
            getrandom::getrandom(&mut nonce).map_err(|_| JournalStoreError::Unavailable)?;
            if nonce == [0; STABLE_LOCK_NONCE_BYTES] {
                return Err(JournalStoreError::Unavailable);
            }
            UnixFileExt::write_all_at(file, &nonce, 0)
                .map_err(|_| JournalStoreError::Unavailable)?;
        }
        length if length == STABLE_LOCK_NONCE_BYTES as u64 => {
            UnixFileExt::read_exact_at(file, &mut nonce, 0)
                .map_err(|_| JournalStoreError::Corrupt)?;
            if nonce == [0; STABLE_LOCK_NONCE_BYTES] {
                return Err(JournalStoreError::Corrupt);
            }
        }
        _ => return Err(JournalStoreError::Corrupt),
    }

    // Always re-establish durability, including a retry after a prior open
    // wrote all 32 bytes but failed one of these syncs. Otherwise that retry
    // could bind a ledger capability to a nonce that disappears on crash.
    file.sync_all()
        .and_then(|()| parent.sync_all())
        .map_err(|_| JournalStoreError::Unavailable)?;
    verify_stable_lock_nonce(file, &nonce)?;
    Ok(nonce)
}

#[cfg(target_os = "linux")]
fn verify_stable_lock_nonce(
    file: &File,
    expected: &[u8; STABLE_LOCK_NONCE_BYTES],
) -> Result<(), JournalStoreError> {
    if file
        .metadata()
        .map_err(|_| JournalStoreError::Unavailable)?
        .len()
        != STABLE_LOCK_NONCE_BYTES as u64
    {
        return Err(JournalStoreError::Corrupt);
    }
    let mut nonce = [0_u8; STABLE_LOCK_NONCE_BYTES];
    UnixFileExt::read_exact_at(file, &mut nonce, 0).map_err(|_| JournalStoreError::Corrupt)?;
    if nonce == [0; STABLE_LOCK_NONCE_BYTES] || nonce != *expected {
        return Err(JournalStoreError::Corrupt);
    }
    Ok(())
}

#[cfg(target_os = "linux")]
fn verify_local_stable_lock(
    file: &File,
    expected_nonce: &[u8; STABLE_LOCK_NONCE_BYTES],
    intent: Hash,
) -> Result<bool, JournalStoreError> {
    let length = file
        .metadata()
        .map_err(|_| JournalStoreError::Unavailable)?
        .len();
    if length != STABLE_LOCK_NONCE_BYTES as u64 && length != LOCAL_STABLE_LOCK_EXPOSED_BYTES as u64
    {
        return Err(JournalStoreError::Corrupt);
    }
    let mut nonce = [0_u8; STABLE_LOCK_NONCE_BYTES];
    UnixFileExt::read_exact_at(file, &mut nonce, 0).map_err(|_| JournalStoreError::Corrupt)?;
    if nonce == [0; STABLE_LOCK_NONCE_BYTES] || nonce != *expected_nonce {
        return Err(JournalStoreError::Corrupt);
    }
    if length == STABLE_LOCK_NONCE_BYTES as u64 {
        return Ok(false);
    }
    let mut committed_intent = [0_u8; 32];
    UnixFileExt::read_exact_at(file, &mut committed_intent, STABLE_LOCK_NONCE_BYTES as u64)
        .map_err(|_| JournalStoreError::Corrupt)?;
    if committed_intent != *intent.as_bytes() {
        return Err(JournalStoreError::Corrupt);
    }
    Ok(true)
}

#[cfg(target_os = "linux")]
fn verify_generation_stable_lock(
    file: &File,
    expected_nonce: &[u8; STABLE_LOCK_NONCE_BYTES],
    local_intent: Option<Hash>,
) -> Result<bool, JournalStoreError> {
    match local_intent {
        None => {
            verify_stable_lock_nonce(file, expected_nonce)?;
            Ok(false)
        }
        Some(intent) => verify_local_stable_lock(file, expected_nonce, intent),
    }
}

#[cfg(target_os = "linux")]
fn lock_stable_file(file: &File) -> Result<(), JournalStoreError> {
    validate_owned_regular_file(file).map_err(|_| JournalStoreError::InvalidPath)?;
    FileExt::try_lock_exclusive(file).map_err(|error| {
        if error.kind() == ErrorKind::WouldBlock {
            JournalStoreError::DirectoryInUse
        } else {
            JournalStoreError::Unavailable
        }
    })
}

#[cfg(target_os = "linux")]
fn open_existing_stable_lock_at(
    parent: &File,
    name: &str,
    allow_pristine_nonce_recovery: bool,
) -> Result<(File, [u8; STABLE_LOCK_NONCE_BYTES]), JournalStoreError> {
    let name = c_name(name)?;
    let file = open_at(
        parent,
        &name,
        libc::O_RDWR | libc::O_NOFOLLOW | libc::O_CLOEXEC | libc::O_NONBLOCK,
        0,
    )
    .map_err(|_| JournalStoreError::Corrupt)?;
    lock_stable_file(&file)?;
    let length = file
        .metadata()
        .map_err(|_| JournalStoreError::Unavailable)?
        .len();
    let nonce = match length {
        length if length < STABLE_LOCK_NONCE_BYTES as u64 && allow_pristine_nonce_recovery => {
            // A power loss can leave any prefix of the random nonce. The
            // exact empty, single-link ledger stage proves that no database
            // or generation has yet been initialized, so discarding that
            // unusable prefix and minting a new complete nonce is safe.
            if length != 0 {
                file.set_len(0)
                    .and_then(|()| file.sync_all())
                    .and_then(|()| parent.sync_all())
                    .map_err(|_| JournalStoreError::Unavailable)?;
            }
            stable_lock_nonce(&file, parent)?
        }
        length if length == STABLE_LOCK_NONCE_BYTES as u64 => {
            // Always re-sync a complete nonce before any ledger open. This
            // closes the retry after full-write/file-sync/parent-sync errors.
            stable_lock_nonce(&file, parent)?
        }
        _ => return Err(JournalStoreError::Corrupt),
    };
    verify_stable_lock_nonce(&file, &nonce)?;
    Ok((file, nonce))
}

#[cfg(target_os = "linux")]
fn open_existing_local_stable_lock_at(
    parent: &File,
    name: &str,
    allow_pristine_nonce_recovery: bool,
    generation_exists: bool,
    intent: Hash,
) -> Result<(File, [u8; STABLE_LOCK_NONCE_BYTES], bool), JournalStoreError> {
    let name = c_name(name)?;
    let file = open_at(
        parent,
        &name,
        libc::O_RDWR | libc::O_NOFOLLOW | libc::O_CLOEXEC | libc::O_NONBLOCK,
        0,
    )
    .map_err(|_| JournalStoreError::Corrupt)?;
    lock_stable_file(&file)?;
    let length = file
        .metadata()
        .map_err(|_| JournalStoreError::Unavailable)?
        .len();
    let (nonce, exposed) = match length {
        length if length < STABLE_LOCK_NONCE_BYTES as u64 && allow_pristine_nonce_recovery => {
            if length != 0 {
                file.set_len(0)
                    .and_then(|()| file.sync_all())
                    .and_then(|()| parent.sync_all())
                    .map_err(|_| JournalStoreError::Unavailable)?;
            }
            (stable_lock_nonce(&file, parent)?, false)
        }
        length if length == STABLE_LOCK_NONCE_BYTES as u64 => {
            (stable_lock_nonce(&file, parent)?, false)
        }
        length
            if generation_exists
                && length > STABLE_LOCK_NONCE_BYTES as u64
                && length <= LOCAL_STABLE_LOCK_EXPOSED_BYTES as u64 =>
        {
            let mut nonce = [0_u8; STABLE_LOCK_NONCE_BYTES];
            UnixFileExt::read_exact_at(&file, &mut nonce, 0)
                .map_err(|_| JournalStoreError::Corrupt)?;
            if nonce == [0; STABLE_LOCK_NONCE_BYTES] {
                return Err(JournalStoreError::Corrupt);
            }
            let committed = (length as usize) - STABLE_LOCK_NONCE_BYTES;
            let mut prefix = [0_u8; 32];
            UnixFileExt::read_exact_at(
                &file,
                &mut prefix[..committed],
                STABLE_LOCK_NONCE_BYTES as u64,
            )
            .map_err(|_| JournalStoreError::Corrupt)?;
            if prefix[..committed] != intent.as_bytes()[..committed] {
                return Err(JournalStoreError::Corrupt);
            }
            UnixFileExt::write_all_at(&file, &intent.as_bytes()[committed..], length)
                .and_then(|()| file.sync_all())
                .and_then(|()| parent.sync_all())
                .map_err(|_| JournalStoreError::Unavailable)?;
            (nonce, true)
        }
        _ => return Err(JournalStoreError::Corrupt),
    };
    if verify_local_stable_lock(&file, &nonce, intent)? != exposed {
        return Err(JournalStoreError::Corrupt);
    }
    Ok((file, nonce, exposed))
}

#[cfg(target_os = "linux")]
fn create_stable_lock_at(
    parent: &File,
    name: &str,
) -> Result<(File, [u8; STABLE_LOCK_NONCE_BYTES]), JournalStoreError> {
    let name = c_name(name)?;
    let file = match open_at(
        parent,
        &name,
        libc::O_RDWR
            | libc::O_CREAT
            | libc::O_EXCL
            | libc::O_NOFOLLOW
            | libc::O_CLOEXEC
            | libc::O_NONBLOCK,
        0o600,
    ) {
        Ok(file) => file,
        Err(error) if error.raw_os_error() == Some(libc::EEXIST) => {
            return open_existing_stable_lock_at(
                parent,
                name.to_str().map_err(|_| JournalStoreError::InvalidPath)?,
                false,
            );
        }
        Err(_) => return Err(JournalStoreError::Unavailable),
    };
    lock_stable_file(&file)?;
    let nonce = stable_lock_nonce(&file, parent)?;
    Ok((file, nonce))
}

#[cfg(target_os = "linux")]
fn create_local_stable_lock_at(
    parent: &File,
    name: &str,
    intent: Hash,
) -> Result<(File, [u8; STABLE_LOCK_NONCE_BYTES], bool), JournalStoreError> {
    let name = c_name(name)?;
    let file = match open_at(
        parent,
        &name,
        libc::O_RDWR
            | libc::O_CREAT
            | libc::O_EXCL
            | libc::O_NOFOLLOW
            | libc::O_CLOEXEC
            | libc::O_NONBLOCK,
        0o600,
    ) {
        Ok(file) => file,
        Err(error) if error.raw_os_error() == Some(libc::EEXIST) => {
            return open_existing_local_stable_lock_at(
                parent,
                name.to_str().map_err(|_| JournalStoreError::InvalidPath)?,
                true,
                false,
                intent,
            );
        }
        Err(_) => return Err(JournalStoreError::Unavailable),
    };
    lock_stable_file(&file)?;
    let nonce = stable_lock_nonce(&file, parent)?;
    Ok((file, nonce, false))
}

#[cfg(target_os = "linux")]
fn commit_local_stable_lock_exposure(
    file: &File,
    parent: &File,
    nonce: &[u8; STABLE_LOCK_NONCE_BYTES],
    intent: Hash,
) -> Result<(), JournalStoreError> {
    if verify_local_stable_lock(file, nonce, intent)? {
        return Ok(());
    }
    UnixFileExt::write_all_at(file, intent.as_bytes(), STABLE_LOCK_NONCE_BYTES as u64)
        .and_then(|()| file.sync_all())
        .and_then(|()| parent.sync_all())
        .map_err(|_| JournalStoreError::Unavailable)?;
    if !verify_local_stable_lock(file, nonce, intent)? {
        return Err(JournalStoreError::Corrupt);
    }
    Ok(())
}

#[cfg(all(test, target_os = "linux"))]
fn open_stable_lock_at(
    parent: &File,
    name: &str,
) -> Result<(File, [u8; STABLE_LOCK_NONCE_BYTES]), JournalStoreError> {
    let name = c_name(name)?;
    let file = open_at(
        parent,
        &name,
        libc::O_RDWR | libc::O_CREAT | libc::O_NOFOLLOW | libc::O_CLOEXEC | libc::O_NONBLOCK,
        0o600,
    )
    .map_err(|_| JournalStoreError::Unavailable)?;
    lock_stable_file(&file)?;
    let nonce = stable_lock_nonce(&file, parent)?;
    Ok((file, nonce))
}

#[cfg(target_os = "linux")]
fn reject_legacy_generation_at(parent: &File, agent: AgentId) -> Result<(), JournalStoreError> {
    let name = c_name(&format!("{}.agent-image", encode_hex(agent.as_bytes())))?;
    match stat_at(parent, &name) {
        Ok(None) => Ok(()),
        Ok(Some(_)) => Err(JournalStoreError::LegacyGeneration),
        Err(_) => Err(JournalStoreError::Unavailable),
    }
}

#[cfg(target_os = "linux")]
fn discard_private_stages_at(
    directory: &File,
    is_private_stage: fn(&[u8]) -> bool,
) -> Result<(), JournalStoreError> {
    // `fdopendir` owns its descriptor, so duplicate the pinned capability.
    // Collect names first and unlink only after the directory stream closes.
    // This keeps recovery descriptor-relative and never follows a stale
    // private-stage symlink.
    // SAFETY: `fcntl` receives a valid descriptor and returns a fresh one.
    let duplicate = unsafe { libc::fcntl(directory.as_raw_fd(), libc::F_DUPFD_CLOEXEC, 0) };
    if duplicate < 0 {
        return Err(JournalStoreError::Unavailable);
    }
    // SAFETY: `duplicate` is fresh and ownership passes to the DIR stream.
    let stream = unsafe { libc::fdopendir(duplicate) };
    if stream.is_null() {
        // SAFETY: `fdopendir` failed and did not consume the descriptor.
        unsafe { libc::close(duplicate) };
        return Err(JournalStoreError::Unavailable);
    }
    // `dup` shares the directory cursor with the pinned capability. Always
    // rewind so an earlier scan cannot hide entries from recovery.
    // SAFETY: `stream` is live until `closedir` below.
    unsafe { libc::rewinddir(stream) };
    let mut stale = Vec::new();
    let scan = loop {
        // SAFETY: Linux exposes a thread-local errno pointer.
        unsafe { *libc::__errno_location() = 0 };
        // SAFETY: `stream` remains live until `closedir` below.
        let entry = unsafe { libc::readdir(stream) };
        if entry.is_null() {
            // SAFETY: Linux exposes a thread-local errno pointer.
            let errno = unsafe { *libc::__errno_location() };
            break if errno == 0 {
                Ok(())
            } else {
                Err(JournalStoreError::Unavailable)
            };
        }
        // SAFETY: `d_name` is NUL-terminated for a successful `readdir`.
        let name = unsafe { CStr::from_ptr((*entry).d_name.as_ptr()) }.to_bytes();
        if is_private_stage(name) {
            let Ok(name) = std::str::from_utf8(name) else {
                break Err(JournalStoreError::Corrupt);
            };
            let name = name.to_owned();
            stale.push(name);
        }
    };
    // SAFETY: `stream` is live and `closedir` consumes it and its descriptor.
    let closed = unsafe { libc::closedir(stream) };
    if closed != 0 {
        return Err(JournalStoreError::Unavailable);
    }
    scan?;

    let mut removed = false;
    for name in stale {
        removed |= unlink_file_if_present_at(directory, &name)?;
    }
    if removed {
        directory
            .sync_all()
            .map_err(|_| JournalStoreError::Unavailable)?;
    }
    Ok(())
}

#[cfg(target_os = "linux")]
fn validate_directory_names(directory: &File, allowed: &[&str]) -> Result<(), JournalStoreError> {
    // `fdopendir` owns its descriptor, so duplicate the pinned capability.
    // SAFETY: `fcntl` receives a valid descriptor and returns a fresh one.
    let duplicate = unsafe { libc::fcntl(directory.as_raw_fd(), libc::F_DUPFD_CLOEXEC, 0) };
    if duplicate < 0 {
        return Err(JournalStoreError::Unavailable);
    }
    // SAFETY: `duplicate` is fresh and ownership passes to the DIR stream.
    let stream = unsafe { libc::fdopendir(duplicate) };
    if stream.is_null() {
        // SAFETY: `fdopendir` failed and did not consume the descriptor.
        unsafe { libc::close(duplicate) };
        return Err(JournalStoreError::Unavailable);
    }
    // `dup` shares the directory cursor with the pinned capability. Always
    // rewind so repeated validation still examines the complete namespace.
    // SAFETY: `stream` is live until `closedir` below.
    unsafe { libc::rewinddir(stream) };
    let result = loop {
        // SAFETY: Linux exposes a thread-local errno pointer.
        unsafe { *libc::__errno_location() = 0 };
        // SAFETY: `stream` remains live until `closedir` below.
        let entry = unsafe { libc::readdir(stream) };
        if entry.is_null() {
            // SAFETY: Linux exposes a thread-local errno pointer.
            let errno = unsafe { *libc::__errno_location() };
            break if errno == 0 {
                Ok(())
            } else {
                Err(JournalStoreError::Unavailable)
            };
        }
        // SAFETY: `d_name` is NUL-terminated for a successful `readdir`.
        let name = unsafe { CStr::from_ptr((*entry).d_name.as_ptr()) };
        if name.to_bytes() == b"." || name.to_bytes() == b".." {
            continue;
        }
        let Ok(name) = name.to_str() else {
            break Err(JournalStoreError::Corrupt);
        };
        if !allowed.contains(&name) {
            break Err(JournalStoreError::Corrupt);
        }
    };
    // SAFETY: `stream` is live and `closedir` consumes it and its descriptor.
    let closed = unsafe { libc::closedir(stream) };
    if closed != 0 {
        return Err(JournalStoreError::Unavailable);
    }
    result
}

#[cfg(target_os = "linux")]
fn visit_directory_names_bounded(
    directory: &File,
    maximum: usize,
    mut visit: impl FnMut(&str) -> Result<(), JournalStoreError>,
) -> Result<usize, JournalStoreError> {
    // `fdopendir` consumes its descriptor. Keep the pinned capability intact
    // and stream one borrowed name at a time from a duplicate descriptor.
    // SAFETY: `fcntl` receives a valid descriptor and returns a fresh one.
    let duplicate = unsafe { libc::fcntl(directory.as_raw_fd(), libc::F_DUPFD_CLOEXEC, 0) };
    if duplicate < 0 {
        return Err(JournalStoreError::Unavailable);
    }
    // SAFETY: ownership of `duplicate` passes to the DIR stream.
    let stream = unsafe { libc::fdopendir(duplicate) };
    if stream.is_null() {
        // SAFETY: failed `fdopendir` did not consume the descriptor.
        unsafe { libc::close(duplicate) };
        return Err(JournalStoreError::Unavailable);
    }
    // Duplicated directory descriptors share an offset. Rewind before every
    // explicit scrub so a prior scan cannot hide entries.
    // SAFETY: `stream` remains live until `closedir` below.
    unsafe { libc::rewinddir(stream) };
    let mut visited = 0_usize;
    let result = loop {
        // SAFETY: Linux exposes a thread-local errno pointer.
        unsafe { *libc::__errno_location() = 0 };
        // SAFETY: `stream` remains live until `closedir` below.
        let entry = unsafe { libc::readdir(stream) };
        if entry.is_null() {
            // SAFETY: Linux exposes a thread-local errno pointer.
            let errno = unsafe { *libc::__errno_location() };
            break if errno == 0 {
                Ok(())
            } else {
                Err(JournalStoreError::Unavailable)
            };
        }
        // SAFETY: a successful directory entry has a NUL-terminated name.
        let name = unsafe { CStr::from_ptr((*entry).d_name.as_ptr()) };
        if name.to_bytes() == b"." || name.to_bytes() == b".." {
            continue;
        }
        if visited == maximum {
            break Err(JournalStoreError::LimitExceeded);
        }
        let Ok(name) = name.to_str() else {
            break Err(JournalStoreError::Corrupt);
        };
        visited += 1;
        if let Err(error) = visit(name) {
            break Err(error);
        }
    };
    // SAFETY: `closedir` consumes the live stream and duplicate descriptor.
    let closed = unsafe { libc::closedir(stream) };
    if closed != 0 {
        return Err(JournalStoreError::Unavailable);
    }
    result?;
    Ok(visited)
}

#[cfg(target_os = "linux")]
fn bounded_directory_names(
    directory: &File,
    maximum: usize,
) -> Result<Vec<String>, JournalStoreError> {
    // `fdopendir` owns its descriptor, so duplicate the pinned capability.
    // SAFETY: `fcntl` receives a valid descriptor and returns a fresh one.
    let duplicate = unsafe { libc::fcntl(directory.as_raw_fd(), libc::F_DUPFD_CLOEXEC, 0) };
    if duplicate < 0 {
        return Err(JournalStoreError::Unavailable);
    }
    // SAFETY: `duplicate` is fresh and ownership passes to the DIR stream.
    let stream = unsafe { libc::fdopendir(duplicate) };
    if stream.is_null() {
        // SAFETY: `fdopendir` failed and did not consume the descriptor.
        unsafe { libc::close(duplicate) };
        return Err(JournalStoreError::Unavailable);
    }
    // SAFETY: `stream` is live until `closedir` below.
    unsafe { libc::rewinddir(stream) };
    let mut names = Vec::new();
    let result = loop {
        // SAFETY: Linux exposes a thread-local errno pointer.
        unsafe { *libc::__errno_location() = 0 };
        // SAFETY: `stream` remains live until `closedir` below.
        let entry = unsafe { libc::readdir(stream) };
        if entry.is_null() {
            // SAFETY: Linux exposes a thread-local errno pointer.
            let errno = unsafe { *libc::__errno_location() };
            break if errno == 0 {
                Ok(())
            } else {
                Err(JournalStoreError::Unavailable)
            };
        }
        // SAFETY: `d_name` is NUL-terminated for a successful `readdir`.
        let name = unsafe { CStr::from_ptr((*entry).d_name.as_ptr()) };
        if name.to_bytes() == b"." || name.to_bytes() == b".." {
            continue;
        }
        if names.len() == maximum {
            break Err(JournalStoreError::LimitExceeded);
        }
        let Ok(name) = name.to_str() else {
            break Err(JournalStoreError::Corrupt);
        };
        if names.try_reserve(1).is_err() {
            break Err(JournalStoreError::LimitExceeded);
        }
        names.push(name.to_owned());
    };
    // SAFETY: `stream` is live and `closedir` consumes it and its descriptor.
    let closed = unsafe { libc::closedir(stream) };
    if closed != 0 {
        return Err(JournalStoreError::Unavailable);
    }
    result?;
    Ok(names)
}

#[cfg(target_os = "linux")]
fn read_bounded_regular_at(
    directory: &File,
    name: &str,
    maximum: usize,
) -> Result<Option<Vec<u8>>, JournalStoreError> {
    read_bounded_regular_at_with_work_limit(directory, name, maximum, u64::MAX)
}

#[cfg(target_os = "linux")]
fn read_bounded_regular_at_with_work_limit(
    directory: &File,
    name: &str,
    maximum: usize,
    work_limit: u64,
) -> Result<Option<Vec<u8>>, JournalStoreError> {
    let file = match open_at(
        directory,
        &c_name(name)?,
        libc::O_RDONLY | libc::O_NOFOLLOW | libc::O_CLOEXEC | libc::O_NONBLOCK,
        0,
    ) {
        Ok(file) => file,
        Err(error) if error.raw_os_error() == Some(libc::ENOENT) => return Ok(None),
        Err(_) => return Err(JournalStoreError::Corrupt),
    };
    let metadata = file
        .metadata()
        .map_err(|_| JournalStoreError::Unavailable)?;
    validate_owned_regular_file(&file)?;
    if metadata.len() > maximum as u64 {
        return Err(JournalStoreError::Corrupt);
    }
    if metadata.len() > work_limit {
        return Err(JournalStoreError::LimitExceeded);
    }
    let mut file = file;
    let mut bytes = Vec::with_capacity(metadata.len() as usize);
    let read_limit = (maximum as u64)
        .saturating_add(1)
        .min(work_limit.saturating_add(1));
    Read::by_ref(&mut file)
        .take(read_limit)
        .read_to_end(&mut bytes)
        .map_err(|_| JournalStoreError::Unavailable)?;
    if bytes.len() > maximum {
        return Err(JournalStoreError::Corrupt);
    }
    if bytes.len() as u64 > work_limit {
        return Err(JournalStoreError::LimitExceeded);
    }
    Ok(Some(bytes))
}

/// Read a resolver-visible immutable file while authenticating both the open
/// descriptor and its namespace slot before and after the bounded read.
#[cfg(target_os = "linux")]
fn read_pinned_bounded_regular_at(
    directory: &File,
    name: &str,
    maximum: usize,
) -> Result<Option<Vec<u8>>, JournalStoreError> {
    let name = c_name(name)?;
    let file = match open_at(
        directory,
        &name,
        libc::O_RDONLY | libc::O_NOFOLLOW | libc::O_CLOEXEC | libc::O_NONBLOCK,
        0,
    ) {
        Ok(file) => file,
        Err(error) if error.raw_os_error() == Some(libc::ENOENT) => return Ok(None),
        Err(_) => return Err(JournalStoreError::Corrupt),
    };
    validate_owned_regular_file(&file)?;
    let identity = FileIdentity::of(&file)?;
    verify_regular_entry(directory, &name, identity)?;
    let metadata = file
        .metadata()
        .map_err(|_| JournalStoreError::Unavailable)?;
    if metadata.len() > maximum as u64 {
        return Err(JournalStoreError::Corrupt);
    }

    let mut file = file;
    let mut bytes = Vec::with_capacity(metadata.len() as usize);
    Read::by_ref(&mut file)
        .take((maximum as u64).saturating_add(1))
        .read_to_end(&mut bytes)
        .map_err(|_| JournalStoreError::Unavailable)?;
    if bytes.len() > maximum {
        return Err(JournalStoreError::Corrupt);
    }
    validate_owned_regular_file(&file)?;
    verify_regular_entry(directory, &name, identity)?;
    Ok(Some(bytes))
}

#[cfg(target_os = "linux")]
fn create_synced_stage_at(
    directory: &File,
    name: &str,
    bytes: &[u8],
) -> Result<(), JournalStoreError> {
    // A recognized `.next` name is never populated in place. Recovery may
    // discard this private sibling, so interrupted/short writes cannot become
    // permanent canonical corruption.
    let private = private_stage_name(name)?;
    if unlink_file_if_present_at(directory, &private)? {
        directory
            .sync_all()
            .map_err(|_| JournalStoreError::Unavailable)?;
    }
    let mut file = open_at(
        directory,
        &c_name(&private)?,
        libc::O_WRONLY
            | libc::O_CREAT
            | libc::O_EXCL
            | libc::O_NOFOLLOW
            | libc::O_CLOEXEC
            | libc::O_NONBLOCK,
        0o600,
    )
    .map_err(|_| JournalStoreError::Unavailable)?;
    file.write_all(bytes)
        .and_then(|()| file.sync_all())
        .map_err(|_| JournalStoreError::Unavailable)?;

    // Hard-linking provides an atomic no-replace install within the pinned
    // directory. The source inode is already fully written and durable before
    // the recognized stage can appear.
    link_file_at(directory, &private, name).map_err(|_| JournalStoreError::Unavailable)?;
    directory
        .sync_all()
        .map_err(|_| JournalStoreError::Unavailable)?;
    unlink_file_at(directory, &private)?;
    directory
        .sync_all()
        .map_err(|_| JournalStoreError::Unavailable)
}

#[cfg(target_os = "linux")]
fn sync_regular_file_at(directory: &File, name: &str) -> Result<(), JournalStoreError> {
    let file = open_at(
        directory,
        &c_name(name)?,
        libc::O_RDONLY | libc::O_NOFOLLOW | libc::O_CLOEXEC | libc::O_NONBLOCK,
        0,
    )
    .map_err(|_| JournalStoreError::Corrupt)?;
    validate_owned_regular_file(&file)?;
    file.sync_all().map_err(|_| JournalStoreError::Unavailable)
}

#[cfg(target_os = "linux")]
fn unlink_file_at(directory: &File, name: &str) -> Result<(), JournalStoreError> {
    // SAFETY: descriptor/name are valid and names never contain separators.
    if unsafe { libc::unlinkat(directory.as_raw_fd(), c_name(name)?.as_ptr(), 0) } == 0 {
        Ok(())
    } else {
        Err(JournalStoreError::Unavailable)
    }
}

#[cfg(target_os = "linux")]
fn unlink_file_if_present_at(directory: &File, name: &str) -> Result<bool, JournalStoreError> {
    // SAFETY: descriptor/name are valid, names never contain separators, and
    // `unlinkat` removes a symlink itself rather than following it.
    if unsafe { libc::unlinkat(directory.as_raw_fd(), c_name(name)?.as_ptr(), 0) } == 0 {
        return Ok(true);
    }
    let error = std::io::Error::last_os_error();
    if error.raw_os_error() == Some(libc::ENOENT) {
        Ok(false)
    } else {
        Err(JournalStoreError::Unavailable)
    }
}

#[cfg(target_os = "linux")]
fn rename_file_at(directory: &File, from: &str, to: &str) -> Result<(), JournalStoreError> {
    let from = c_name(from)?;
    let to = c_name(to)?;
    // SAFETY: both names are relative, separator-free, and both descriptors
    // remain valid for the call.
    if unsafe {
        libc::renameat(
            directory.as_raw_fd(),
            from.as_ptr(),
            directory.as_raw_fd(),
            to.as_ptr(),
        )
    } == 0
    {
        Ok(())
    } else {
        Err(JournalStoreError::Unavailable)
    }
}

#[cfg(target_os = "linux")]
fn link_file_at(directory: &File, from: &str, to: &str) -> std::io::Result<()> {
    let from = c_name(from).map_err(|_| std::io::Error::from(ErrorKind::InvalidInput))?;
    let to = c_name(to).map_err(|_| std::io::Error::from(ErrorKind::InvalidInput))?;
    // SAFETY: both names are relative, separator-free, and the descriptor is
    // valid for the duration of the call.
    if unsafe {
        libc::linkat(
            directory.as_raw_fd(),
            from.as_ptr(),
            directory.as_raw_fd(),
            to.as_ptr(),
            0,
        )
    } == 0
    {
        Ok(())
    } else {
        Err(std::io::Error::last_os_error())
    }
}

#[cfg(target_os = "linux")]
fn persist_immutable_at(
    directory: &File,
    name: &str,
    bytes: &[u8],
    maximum: usize,
    mut validate: impl FnMut(&[u8]) -> Result<(), JournalStoreError>,
) -> Result<bool, JournalStoreError> {
    if bytes.len() > maximum {
        return Err(JournalStoreError::LimitExceeded);
    }
    let stage = sibling_next_name(name);
    let existing = read_bounded_regular_at(directory, name, maximum)?;
    if let Some(existing) = &existing {
        validate(existing)?;
        if existing != bytes {
            return Err(JournalStoreError::Corrupt);
        }
    }
    let staged = read_bounded_regular_at(directory, &stage, maximum)?;
    if let Some(staged) = &staged {
        validate(staged)?;
        if staged != bytes {
            return Err(JournalStoreError::Corrupt);
        }
    }
    if existing.is_some() {
        if staged.is_some() {
            unlink_file_at(directory, &stage)?;
            directory
                .sync_all()
                .map_err(|_| JournalStoreError::Unavailable)?;
        }
        return Ok(false);
    }
    if staged.is_none() {
        create_synced_stage_at(directory, &stage, bytes)?;
    } else {
        // Re-establish a recovered staging inode's durability before linking
        // it into the immutable namespace.
        sync_regular_file_at(directory, &stage)?;
    }
    match link_file_at(directory, &stage, name) {
        Ok(()) => {}
        Err(error) if error.kind() == ErrorKind::AlreadyExists => {
            let existing = read_bounded_regular_at(directory, name, maximum)?
                .ok_or(JournalStoreError::Unavailable)?;
            validate(&existing)?;
            if existing != bytes {
                return Err(JournalStoreError::Corrupt);
            }
        }
        Err(_) => return Err(JournalStoreError::Unavailable),
    }
    directory
        .sync_all()
        .map_err(|_| JournalStoreError::Unavailable)?;
    unlink_file_at(directory, &stage)?;
    directory
        .sync_all()
        .map_err(|_| JournalStoreError::Unavailable)?;
    Ok(true)
}

#[cfg(not(target_os = "linux"))]
fn read_bounded_regular_at(
    _directory: &File,
    _name: &str,
    _maximum: usize,
) -> Result<Option<Vec<u8>>, JournalStoreError> {
    Err(JournalStoreError::Unavailable)
}

#[cfg(not(target_os = "linux"))]
fn create_synced_stage_at(
    _directory: &File,
    _name: &str,
    _bytes: &[u8],
) -> Result<(), JournalStoreError> {
    Err(JournalStoreError::Unavailable)
}

#[cfg(not(target_os = "linux"))]
fn sync_regular_file_at(_directory: &File, _name: &str) -> Result<(), JournalStoreError> {
    Err(JournalStoreError::Unavailable)
}

#[cfg(not(target_os = "linux"))]
fn unlink_file_at(_directory: &File, _name: &str) -> Result<(), JournalStoreError> {
    Err(JournalStoreError::Unavailable)
}

#[cfg(not(target_os = "linux"))]
fn rename_file_at(_directory: &File, _from: &str, _to: &str) -> Result<(), JournalStoreError> {
    Err(JournalStoreError::Unavailable)
}

#[cfg(not(target_os = "linux"))]
fn persist_immutable_at(
    _directory: &File,
    _name: &str,
    _bytes: &[u8],
    _maximum: usize,
    _validate: impl FnMut(&[u8]) -> Result<(), JournalStoreError>,
) -> Result<bool, JournalStoreError> {
    Err(JournalStoreError::Unavailable)
}
