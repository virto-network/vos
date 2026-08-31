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
use std::os::unix::fs::MetadataExt as _;
use std::path::{Component, Path, PathBuf};
use std::sync::Arc;

#[cfg(target_os = "linux")]
use fs2::FileExt;

use super::committee::{
    MAX_ROOT_ANCHOR_RECORD_BYTES, MAX_SYSTEM_GENESIS_ADMISSION_BYTES,
    MAX_SYSTEM_GENESIS_EVIDENCE_BYTES, RootAnchorRecord, SystemAgentGenesisAdmissionRecord,
    SystemAgentGenesisEvidence,
};
use super::execution::MAX_RUNTIME_STATE_BYTES;
use super::invocation_index::{
    DEFAULT_INVOCATION_INDEX_NODE_LIMIT, InvocationIndexError, InvocationIndexNode,
    InvocationIndexStore, InvocationOutcomeStore, collect_manifest_reachability,
    validate_manifest_root,
};
use super::journal::{
    AgentJournalGenesis, ArtifactClosure, CanonicalJournalRecord, CheckpointId, CheckpointManifest,
    InvocationIndexId, InvocationIndexManifest, InvocationIndexNodeId, InvocationOutcomeAnchor,
    InvocationOutcomeId, InvocationOutcomeRecord, InvocationOwnershipScope, JournalHeads,
    JournalHeadsId, JournalObjectId, JournalStorageClass, LaneCursor, LaneStateId,
    LaneStateManifest, LocalEntry, LocalEntryId, MAX_ARTIFACT_CLOSURE_BYTES,
    MAX_ARTIFACT_CLOSURE_ENTRIES, MAX_ARTIFACT_CLOSURE_REFERENCED_BYTES,
    MAX_CHECKPOINT_MANIFEST_BYTES, MAX_INVOCATION_INDEX_MANIFEST_BYTES,
    MAX_INVOCATION_INDEX_NODE_BYTES, MAX_INVOCATION_OUTCOME_BYTES, MAX_JOURNAL_RECORD_BYTES,
    MAX_REPLAY_INPUT_BYTES, MAX_REPLAY_SUFFIX_BYTES, MAX_REPLAY_SUFFIX_ENTRIES, MergeEvent,
    MergeEventId, MergeFrontier, MergeFrontierId, MergeSeal, MergeSealId, OrderedBase,
    OrderedEntry, OrderedEntryId, PersistedLane, system_genesis_post_create_state_commitment,
};
use super::replay::{ReplayPublicationAnchor, ReplaySealedGenesis, ReplaySealedPublication};
use super::wire::{RuntimeState, decode_standard_runtime_state};
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
pub trait AgentJournalStore: InvocationOutcomeStore<Error = JournalStoreError> {
    /// Install immutable genesis and its empty head envelope. Exact retries
    /// are idempotent. Implementations may durably retain a validated partial
    /// initialization after an I/O failure; retrying this method completes it.
    fn initialize(&mut self, genesis: &ReplaySealedGenesis) -> Result<bool, JournalStoreError>;

    fn genesis(&self) -> Result<Option<AgentJournalGenesis>, JournalStoreError>;

    fn heads(&self) -> Result<Option<JournalHeads>, JournalStoreError>;

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
    /// Typed closure objects carried by the token are installed by this call;
    /// referenced raw blobs must already be durable through [`Self::put_blob`].
    /// The opaque token can only be minted by exact replay, so callers cannot
    /// ask storage to infer lifecycle, ownership, or checkpoint semantics from
    /// independently assembled records.
    fn publish(
        &mut self,
        publication: &ReplaySealedPublication,
    ) -> Result<JournalPublication, JournalStoreError>;
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

impl CanonicalAuthorityRecord for SystemAgentGenesisAdmissionRecord {
    const STORAGE_CLASS: AuthorityStorageClass = AuthorityStorageClass::GenesisAdmission;
    const DIRECTORY: &'static str = "authority/genesis-admissions";
    const MAXIMUM: usize = MAX_SYSTEM_GENESIS_ADMISSION_BYTES;

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

fn ensure_content_class(class: JournalStorageClass) -> Result<(), JournalStoreError> {
    if matches!(
        class,
        JournalStorageClass::Genesis | JournalStorageClass::Heads
    ) {
        Err(JournalStoreError::InvalidClass)
    } else {
        Ok(())
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
    match R::STORAGE_CLASS {
        JournalStorageClass::OrderedEntry => {
            let entry = decode_anchor::<OrderedEntry, _>(anchor)?;
            let (expected_fence, expected_seal) = if entry.merge_seal.is_some() {
                (
                    OrderedBase {
                        index: entry.index,
                        head: Some(entry.id()),
                    },
                    entry.merge_seal,
                )
            } else {
                (current.merge_fence, current.merge_seal)
            };
            if entry.genesis != current.genesis
                || entry.input.runtime != current.runtime
                || entry.parent != current.ordered_head
                || entry.index
                    != current
                        .ordered_index
                        .checked_add(1)
                        .ok_or(JournalStoreError::LimitExceeded)?
                || entry.merge_frontier != current.merge_frontier
                || next.ordered_head != Some(entry.id())
                || next.ordered_index != entry.index
                || next.merge_frontier != current.merge_frontier
                || next.merge_fence != expected_fence
                || next.merge_seal != expected_seal
                || (entry.merge_seal.is_none()
                    && next.merge_invocations != current.merge_invocations)
                || next.local_invocations != current.local_invocations
                || next.local_head != current.local_head
                || next.local_revision != current.local_revision
                || next.checkpoint != current.checkpoint
            {
                return Err(JournalStoreError::NonCanonical);
            }
        }
        JournalStorageClass::LocalEntry => {
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

struct SealedGenesisShape {
    initial: JournalHeads,
    local_invocations: InvocationIndexManifest,
    lanes: [LaneStateManifest; 4],
}

fn validate_authority_links(
    genesis: &AgentJournalGenesis,
    root: &RootAnchorRecord,
    evidence: &SystemAgentGenesisEvidence,
    admission: SystemAgentGenesisAdmissionRecord,
) -> Result<(), JournalStoreError> {
    let root_id = root.id();
    let evidence_id = evidence.id();
    let admission_id = admission.id();
    decode_authority_record::<RootAnchorRecord>(&root.encode(), *root_id.as_bytes())?;
    decode_authority_record::<SystemAgentGenesisEvidence>(
        &evidence.encode(),
        *evidence_id.as_bytes(),
    )?;
    decode_authority_record::<SystemAgentGenesisAdmissionRecord>(
        &admission.encode(),
        *admission_id.as_bytes(),
    )?;

    let claim = evidence.claim();
    if admission_id != genesis.admission
        || admission.root_anchor() != root_id
        || admission.root_anchor_config_version() != root.config_version()
        || admission.root_anchor_config() != root.config_commitment()
        || admission.evidence() != evidence_id
        || admission.claim() != claim.authority_claim()
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
        | InvocationIndexError::MissingOutcome(_) => JournalStoreError::MissingObject,
        InvocationIndexError::PathLimit
        | InvocationIndexError::NodeLimit
        | InvocationIndexError::Capacity => JournalStoreError::LimitExceeded,
        InvocationIndexError::CorruptManifest
        | InvocationIndexError::CorruptNode(_)
        | InvocationIndexError::CorruptOutcome(_)
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

fn stage_sealed_dependencies<S: AgentJournalStore>(
    store: &mut S,
    publication: &ReplaySealedPublication,
) -> Result<bool, JournalStoreError> {
    validate_sealed_fence_ancestry(store, publication)?;
    let mut created = false;
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
#[derive(Clone, Debug)]
pub struct MemoryAgentJournalStore {
    agent: AgentId,
    node: NodeId,
    genesis_admission: Option<Hash>,
    genesis: Option<Vec<u8>>,
    heads: Option<Vec<u8>>,
    authority: BTreeMap<(AuthorityStorageClass, [u8; 32]), Vec<u8>>,
    objects: BTreeMap<(JournalStorageClass, [u8; 32]), Vec<u8>>,
    // Copy-on-write keeps already-issued catalog resolver snapshots immutable
    // while preserving cheap candidate clones for rollback-safe publication.
    blobs: Arc<BTreeMap<(JournalBlobClass, Hash), Vec<u8>>>,
    gc_intent: Option<GcIntent>,
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
            agent,
            node,
            genesis_admission: None,
            genesis: None,
            heads: None,
            authority: BTreeMap::new(),
            objects: BTreeMap::new(),
            blobs: Arc::new(BTreeMap::new()),
            gc_intent: None,
        })
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

    fn object_bytes<R: CanonicalJournalRecord>(&self, id: R::Id) -> Option<&[u8]> {
        self.objects
            .get(&(R::STORAGE_CLASS, *id.as_bytes()))
            .map(Vec::as_slice)
    }

    fn publish_anchor<R: CanonicalJournalRecord>(
        &mut self,
        expected: JournalHeadsId,
        anchor: &R,
        next: &JournalHeads,
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
        validate_publication_shape(&current, anchor, next)?;

        // Build the candidate in a clone so an in-memory reference has the
        // same all-or-nothing head visibility as the filesystem head swap.
        let mut candidate = self.clone();
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
        let mut candidate = self.clone();
        candidate.put(&empty_frontier)?;
        candidate.put(&ordered_invocations)?;
        candidate.put(&merge_invocations)?;
        candidate.put(&local_invocations)?;
        candidate.genesis_admission = Some(test_admission);
        candidate.genesis = Some(encoded.bytes);
        candidate.heads = Some(encoded_heads.bytes);
        validate_head_targets(&candidate, &initial)?;
        *self = candidate;
        Ok(created)
    }
}

impl AgentJournalStore for MemoryAgentJournalStore {
    fn initialize(&mut self, sealed: &ReplaySealedGenesis) -> Result<bool, JournalStoreError> {
        self.ensure_no_gc_pending()?;
        let shape = validate_sealed_genesis_shape(sealed, self.agent, self.node)?;
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
        {
            return Err(JournalStoreError::Conflict);
        }
        let created = self.genesis.is_none() || self.heads.is_none();
        let mut candidate = self.clone();
        candidate.persist_authority(sealed.root_anchor())?;
        candidate.persist_authority(sealed.admission_evidence())?;
        candidate.persist_authority(&sealed.admission_record())?;
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
        ensure_content_class(R::STORAGE_CLASS)?;
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
        ensure_content_class(R::STORAGE_CLASS)?;
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
        self.ensure_no_gc_pending()?;
        let dependency_created = stage_sealed_dependencies(self, publication)?;
        let expected = publication.expected();
        let next = publication.next();
        let mut result = match publication.anchor() {
            ReplayPublicationAnchor::Ordered(entry) => {
                self.publish_anchor(expected, entry, next)?
            }
            ReplayPublicationAnchor::Local(entry) => self.publish_anchor(expected, entry, next)?,
            ReplayPublicationAnchor::Merge { event, .. } => {
                self.publish_anchor(expected, event, next)?
            }
            ReplayPublicationAnchor::Checkpoint(checkpoint) => {
                self.publish_anchor(expected, checkpoint, next)?
            }
        };
        result.object_created |= dependency_created;
        Ok(result)
    }
}

impl AgentJournalGarbageCollection for MemoryAgentJournalStore {
    fn collect_garbage(
        &mut self,
        expected_heads: JournalHeadsId,
        limits: GcLimits,
    ) -> Result<JournalGc, JournalStoreError> {
        let (intent, mark) = build_gc_mark(self, expected_heads, limits)?;
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
        for key in garbage_objects.iter().take(remaining) {
            if self.objects.remove(key).is_some() {
                objects_removed += 1;
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
        let complete = garbage_objects.len() + garbage_blobs.len() <= limits.max_unlinks_per_run;
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
    external_parent: AbsoluteDirectoryCapability,
    directories: Vec<PinnedDirectory>,
    indexes: BTreeMap<&'static str, usize>,
}

#[cfg(target_os = "linux")]
impl DirectoryCapabilities {
    fn new(
        external_parent: AbsoluteDirectoryCapability,
        root_name: CString,
        root: File,
    ) -> Result<Self, JournalStoreError> {
        validate_owned_directory(&root)?;
        let root_identity = FileIdentity::of(&root)?;
        let mut indexes = BTreeMap::new();
        indexes.insert("", 0);
        Ok(Self {
            external_parent,
            directories: vec![PinnedDirectory {
                file: root,
                parent: None,
                name: root_name,
                identity: root_identity,
            }],
            indexes,
        })
    }

    fn external_parent(&self) -> Result<&File, JournalStoreError> {
        self.external_parent.get()
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
            let external_parent = self.external_parent.get()?;
            verify_directory_entry(external_parent, &directory.name, directory.identity)
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
            external_parent: self.external_parent.try_clone()?,
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
/// `stable_lock_path` must be the deterministic sibling
/// `<full-agent-id>.agent-lock`. Callers cannot select an alternate lock for
/// the same root. The lock therefore remains authoritative if backup/restore
/// replaces the complete Agent directory. Opening acquires it before creating,
/// repairing, or otherwise mutating anything below `root`.
///
/// On Linux, the daemon user is the filesystem trust domain: the lock, Agent
/// root, and every internal directory must be owned by the effective UID and
/// must not be group/other-writable. Absolute ancestors are pinned one
/// component at a time, must be owned by root or the daemon user, and must be
/// non-writable by group/other except for a sticky directory such as `/tmp`.
/// This makes leaf-name publication safe against less-privileged principals;
/// a process running under the daemon's own UID is intentionally inside the
/// same trust boundary.
/// Other operating systems fail closed until an equivalent capability-safe
/// implementation is provided.
pub struct FileAgentJournalStore {
    root: PathBuf,
    agent: AgentId,
    node: NodeId,
    directories: DirectoryCapabilities,
    #[cfg(target_os = "linux")]
    stable_lock_name: CString,
    #[cfg(target_os = "linux")]
    stable_lock_identity: FileIdentity,
    _stable_lock: File,
}

/// Read-only catalog capability detached from the mutable filesystem store.
///
/// On Linux this owns duplicates of the already-open namespace descriptors
/// and of the stable-lock descriptor. Duplicating the latter keeps the same
/// open-file-description lock alive if the writer handle is dropped.
#[cfg(target_os = "linux")]
struct FileCatalogCapability {
    directories: DirectoryCapabilities,
    stable_lock_name: CString,
    stable_lock_identity: FileIdentity,
    stable_lock: File,
}

#[cfg(target_os = "linux")]
impl FileCatalogCapability {
    fn verify(&self) -> Result<(), JournalStoreError> {
        validate_owned_regular_file(&self.stable_lock)?;
        verify_regular_entry(
            self.directories.external_parent()?,
            &self.stable_lock_name,
            self.stable_lock_identity,
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
                stable_lock_name: self.stable_lock_name.clone(),
                stable_lock_identity: self.stable_lock_identity,
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
    pub fn open(
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
    pub(crate) fn open_reverified(
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

    #[cfg(target_os = "linux")]
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
        let expected_lock_path = canonical_root.with_extension("agent-lock");
        if stable_lock_path != expected_lock_path || stable_lock_path.starts_with(&canonical_root) {
            return Err(JournalStoreError::InvalidPath);
        }
        let stable_lock_name = stable_lock_path
            .file_name()
            .and_then(|name| name.to_str())
            .ok_or(JournalStoreError::InvalidPath)?;
        let external_parent = AbsoluteDirectoryCapability::open(&root_parent)?;
        let stable_lock = open_stable_lock_at(external_parent.get()?, stable_lock_name)?;
        let stable_lock_identity = FileIdentity::of(&stable_lock)?;
        let stable_lock_name = c_name(stable_lock_name)?;
        verify_regular_entry(
            external_parent.get()?,
            &stable_lock_name,
            stable_lock_identity,
        )?;

        // Nothing below the replaceable root is touched before ownership of
        // its stable external slot has been won.
        reject_legacy_generation_at(external_parent.get()?, agent)?;
        ensure_directory_at(external_parent.get()?, root_name)?;
        let root_directory = open_directory_at(external_parent.get()?, root_name)?;
        validate_owned_directory(&root_directory)?;
        verify_regular_entry(
            external_parent.get()?,
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
            DirectoryCapabilities::new(external_parent, c_name(root_name)?, root_directory)?;

        let mut store = Self {
            root: canonical_root,
            agent,
            node,
            directories,
            stable_lock_name,
            stable_lock_identity,
            _stable_lock: stable_lock,
        };
        store.validate_recovery_state()?;
        store.ensure_layout()?;
        store.validate_authority_recovery(sealed, allow_unverified_for_test)?;
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
            self.directories.external_parent()?,
            &self.stable_lock_name,
            self.stable_lock_identity,
        )
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
                ("catalog", "", "catalog"),
                ("authority", "", "authority"),
            ] {
                self.directories.add(key, parent, name)?;
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
            validate_directory_names(self.directories.get("catalog")?, &["blobs"])?;
            validate_directory_names(
                self.directories.get("authority")?,
                &["root-anchors", "genesis-evidence", "genesis-admissions"],
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
            ] {
                self.directories.add(key, parent, name)?;
            }
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
                "catalog/blobs",
                "authority/root-anchors",
                "authority/genesis-evidence",
                "authority/genesis-admissions",
            ] {
                discard_private_stages_at(
                    self.directories.get(key)?,
                    is_content_private_stage_name,
                )?;
            }
            for key in [
                "records",
                "lane-state",
                "invocation-index",
                "catalog",
                "authority",
                "",
            ] {
                self.directories.sync(key)?;
            }
            Ok(())
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
            JournalStorageClass::Genesis | JournalStorageClass::Heads => {
                return Err(JournalStoreError::InvalidClass);
            }
        };
        Ok(key)
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
        let name = encode_hex(&expected);
        let staged = sibling_next_name(&name);
        if let Some(bytes) =
            read_bounded_regular_at(self.directory(R::DIRECTORY)?, &staged, R::MAXIMUM)?
        {
            decode_authority_record::<R>(&bytes, expected)?;
        }
        let Some(bytes) =
            read_bounded_regular_at(self.directory(R::DIRECTORY)?, &name, R::MAXIMUM)?
        else {
            return Ok(None);
        };
        decode_authority_record::<R>(&bytes, expected).map(Some)
    }

    fn persist_authority<R: CanonicalAuthorityRecord>(
        &self,
        record: &R,
    ) -> Result<bool, JournalStoreError> {
        self.ensure_no_gc_pending()?;
        let id = record.storage_id();
        let bytes = record.encode();
        decode_authority_record::<R>(&bytes, id)?;
        persist_immutable_at(
            self.directory(R::DIRECTORY)?,
            &encode_hex(&id),
            &bytes,
            R::MAXIMUM,
            |stored| decode_authority_record::<R>(stored, id).map(|_| ()),
        )
    }

    fn load_authority_closure(
        &self,
        genesis: &AgentJournalGenesis,
    ) -> Result<
        (
            RootAnchorRecord,
            SystemAgentGenesisEvidence,
            SystemAgentGenesisAdmissionRecord,
        ),
        JournalStoreError,
    > {
        let admission = self
            .read_authority::<SystemAgentGenesisAdmissionRecord>(*genesis.admission.as_bytes())?
            .ok_or(JournalStoreError::MissingObject)?;
        let evidence = self
            .read_authority::<SystemAgentGenesisEvidence>(*admission.evidence().as_bytes())?
            .ok_or(JournalStoreError::MissingObject)?;
        let root = self
            .read_authority::<RootAnchorRecord>(*admission.root_anchor().as_bytes())?
            .ok_or(JournalStoreError::MissingObject)?;
        validate_authority_links(genesis, &root, &evidence, admission)?;
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
            || sealed.admission_record() != admission
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
        ensure_content_class(R::STORAGE_CLASS)?;
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
        ensure_content_class(R::STORAGE_CLASS)?;
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

    fn publish_inner<R, F>(
        &mut self,
        expected: JournalHeadsId,
        anchor: &R,
        next: &JournalHeads,
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
        validate_publication_shape(&current, anchor, next)?;

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

    fn publish_anchor<R: CanonicalJournalRecord>(
        &mut self,
        expected: JournalHeadsId,
        anchor: &R,
        next: &JournalHeads,
    ) -> Result<JournalPublication, JournalStoreError> {
        self.publish_inner(expected, anchor, next, |_| Ok(()))
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
        if self.read_fixed::<JournalHeads>("", "heads.next")?.is_some() {
            return Err(JournalStoreError::Conflict);
        }
        let (intent, mark) = build_gc_mark(self, expected_heads, limits)?;

        // Pass one is exhaustive and non-mutating. No intent is installed and
        // no garbage is removed unless every namespace entry fits the caller's
        // file/byte bounds and is an owned regular canonical name.
        let scanned = self.scan_gc_namespace(limits)?;
        let garbage = scanned
            .into_iter()
            .filter(|entry| !entry.is_live(&mark))
            .collect::<Vec<_>>();
        let resumed = self.ensure_gc_intent_durable(intent, &mut publication_point)?;

        // Pass two revalidates the exact inode/name observed by preflight
        // immediately before each descriptor-relative unlink.
        let batch = garbage.len().min(limits.max_unlinks_per_run);
        let mut synced = BTreeSet::new();
        let mut objects_removed = 0_usize;
        let mut blobs_removed = 0_usize;
        let mut aliases_removed = 0_usize;
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

        let complete = batch == garbage.len();
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
    ObjectDurable,
    HeadsStaged,
    HeadsDurable,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum GcPoint {
    IntentStaged,
    IntentDurable,
    SweepDurable,
    Complete,
}

impl AgentJournalStore for FileAgentJournalStore {
    fn initialize(&mut self, sealed: &ReplaySealedGenesis) -> Result<bool, JournalStoreError> {
        self.ensure_no_gc_pending()?;
        let shape = validate_sealed_genesis_shape(sealed, self.agent, self.node)?;
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
        self.persist_authority(&sealed.admission_record())?;
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
        self.ensure_no_gc_pending()?;
        let dependency_created = stage_sealed_dependencies(self, publication)?;
        let expected = publication.expected();
        let next = publication.next();
        let mut result = match publication.anchor() {
            ReplayPublicationAnchor::Ordered(entry) => {
                self.publish_anchor(expected, entry, next)?
            }
            ReplayPublicationAnchor::Local(entry) => self.publish_anchor(expected, entry, next)?,
            ReplayPublicationAnchor::Merge { event, .. } => {
                self.publish_anchor(expected, event, next)?
            }
            ReplayPublicationAnchor::Checkpoint(checkpoint) => {
                self.publish_anchor(expected, checkpoint, next)?
            }
        };
        result.object_created |= dependency_created;
        Ok(result)
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

    use super::*;
    use crate::agent::authority::{
        ActorInvocationClaim, ActorInvocationReceipt, AgentAuthorityBinding, AgentAuthorityClaim,
        AgentAuthorityReceipt, ED25519_SIGNATURE_BYTES, ed25519_public_key_wire,
    };
    use crate::agent::committee::SystemAgentGenesisAdmissionId;
    use crate::agent::contract::RuntimePackageContract;
    use crate::agent::execution::{
        ActorExecutionReply, ActorExecutionStatus, ActorInvocation, ActorInvocationAuth,
        ActorObservation,
    };
    use crate::agent::invocation_index::InvocationIndex;
    use crate::agent::journal::{
        CheckpointLane, InvocationDisposition, InvocationOutcomeAnchor, InvocationOutcomeRecord,
        InvocationOwner, InvocationOwnershipKey, InvocationResultState, ReplayInput,
        ReplayOperation, RuntimeBinding,
    };
    use crate::agent::{
        AgentConfig, AgentIdentity, AgentProfile, AgentReplica, LaneSet,
        LifecycleAuthorityAdmission, LifecycleRequest, MethodMode, ReplicaRole,
        RuntimeCapabilities,
    };
    use crate::service::{
        ActorId, CapabilityId, CredentialId, DeploymentId, InvocationId, PrincipalId, ProducerId,
        ProgramId, SpaceId,
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
            admission: SystemAgentGenesisAdmissionId::from_bytes([0xf4; 32]),
            create: create_input(),
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

    fn open_file_store(directory: &TestDirectory) -> FileAgentJournalStore {
        let config = config();
        FileAgentJournalStore::open_unverified_for_test(
            directory.agent_root(config.identity.agent),
            directory.lock(config.identity.agent),
            config.replicas[0].node,
        )
        .unwrap()
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
    fn memory_gc_keeps_live_outcome_anchor_and_tombstone_but_collects_acknowledged_outcome() {
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
        let root_three = {
            let mut index = InvocationIndex::open(&mut store, root_two).unwrap();
            index
                .record(
                    key_two,
                    InvocationOwner {
                        result_state: InvocationResultState::Acknowledged {
                            disposition: InvocationDisposition::Applied,
                        },
                        ..owner_two
                    },
                )
                .unwrap();
            index.id()
        };
        let heads_three = JournalHeads {
            publication_revision: heads_two.publication_revision + 1,
            previous: Some(heads_two.id()),
            ordered_head: Some(entry_three.id()),
            ordered_index: entry_three.index,
            ordered_invocations: root_three,
            ..heads_two
        };
        store
            .publish_anchor(heads_three.previous.unwrap(), &entry_three, &heads_three)
            .unwrap();
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
            index.lookup(key_two).unwrap().unwrap().result_state,
            InvocationResultState::Acknowledged { .. }
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
        assert_eq!(reopened_index.lookup(key).unwrap(), Some(owner));
        assert_eq!(reopened_index.outcome(key).unwrap(), Some(expected_outcome));
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
    let trusted_owner = metadata.uid() == 0 || metadata.uid() == effective_user;
    let writable = metadata.mode() & 0o022 != 0;
    let protected_sticky = metadata.mode() & libc::S_ISVTX != 0
        && (metadata.uid() == 0 || metadata.uid() == effective_user);
    if !metadata.file_type().is_dir() || !trusted_owner || writable && !protected_sticky {
        return Err(JournalStoreError::InvalidPath);
    }
    Ok(())
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
        Some(status) if status.st_mode & libc::S_IFMT == libc::S_IFDIR => Ok(()),
        Some(_) => Err(JournalStoreError::Corrupt),
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
            parent
                .sync_all()
                .map_err(|_| JournalStoreError::Unavailable)
        }
    }
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
fn open_stable_lock_at(parent: &File, name: &str) -> Result<File, JournalStoreError> {
    let name = c_name(name)?;
    let existed = stat_at(parent, &name)
        .map_err(|_| JournalStoreError::Unavailable)?
        .is_some();
    let file = open_at(
        parent,
        &name,
        libc::O_RDWR | libc::O_CREAT | libc::O_NOFOLLOW | libc::O_CLOEXEC | libc::O_NONBLOCK,
        0o600,
    )
    .map_err(|_| JournalStoreError::Unavailable)?;
    validate_owned_regular_file(&file).map_err(|_| JournalStoreError::InvalidPath)?;
    FileExt::try_lock_exclusive(&file).map_err(|error| {
        if error.kind() == ErrorKind::WouldBlock {
            JournalStoreError::DirectoryInUse
        } else {
            JournalStoreError::Unavailable
        }
    })?;
    if !existed {
        file.sync_all()
            .and_then(|()| parent.sync_all())
            .map_err(|_| JournalStoreError::Unavailable)?;
    }
    Ok(file)
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
fn read_bounded_regular_at(
    directory: &File,
    name: &str,
    maximum: usize,
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
    let mut file = file;
    let mut bytes = Vec::with_capacity(metadata.len() as usize);
    Read::by_ref(&mut file)
        .take((maximum as u64).saturating_add(1))
        .read_to_end(&mut bytes)
        .map_err(|_| JournalStoreError::Unavailable)?;
    if bytes.len() > maximum {
        return Err(JournalStoreError::Corrupt);
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
