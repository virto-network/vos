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
    InvocationIndexStore, validate_manifest_root,
};
use super::journal::{
    AgentJournalGenesis, ArtifactClosure, CanonicalJournalRecord, CheckpointId, CheckpointManifest,
    InvocationIndexId, InvocationIndexManifest, InvocationIndexNodeId, InvocationOwnershipScope,
    JournalHeads, JournalHeadsId, JournalObjectId, JournalStorageClass, LaneCursor, LaneStateId,
    LaneStateManifest, LocalEntry, LocalEntryId, MAX_ARTIFACT_CLOSURE_BYTES,
    MAX_ARTIFACT_CLOSURE_ENTRIES, MAX_ARTIFACT_CLOSURE_REFERENCED_BYTES,
    MAX_CHECKPOINT_MANIFEST_BYTES, MAX_INVOCATION_INDEX_MANIFEST_BYTES,
    MAX_INVOCATION_INDEX_NODE_BYTES, MAX_JOURNAL_RECORD_BYTES, MAX_REPLAY_INPUT_BYTES,
    MAX_REPLAY_SUFFIX_BYTES, MAX_REPLAY_SUFFIX_ENTRIES, MergeEvent, MergeEventId, MergeFrontier,
    MergeFrontierId, MergeSeal, MergeSealId, OrderedBase, OrderedEntry, OrderedEntryId,
    PersistedLane, system_genesis_post_create_state_commitment,
};
use super::replay::{ReplayPublicationAnchor, ReplaySealedGenesis, ReplaySealedPublication};
use super::wire::{RuntimeState, decode_standard_runtime_state};
use crate::service::wire::{DecodeError, ServiceWire};
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

/// Typed persistence boundary shared by Local, Raft, and causal adapters.
///
/// There is deliberately no unbounded enumeration operation. Replay starts
/// from authenticated heads or a checkpoint and follows typed parent IDs.
/// Content objects are never removed through this interface: later garbage
/// collection must first prove that a checkpoint covers the retained suffix.
pub trait AgentJournalStore: InvocationIndexStore<Error = JournalStoreError> {
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
                || next.merge_invocations != current.merge_invocations
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
        InvocationIndexError::MissingManifest(_) | InvocationIndexError::MissingNode(_) => {
            JournalStoreError::MissingObject
        }
        InvocationIndexError::PathLimit | InvocationIndexError::NodeLimit => {
            JournalStoreError::LimitExceeded
        }
        InvocationIndexError::CorruptManifest
        | InvocationIndexError::CorruptNode(_)
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
    blobs: BTreeMap<(JournalBlobClass, Hash), Vec<u8>>,
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
            blobs: BTreeMap::new(),
        })
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
        validate_supplied_blob(class, reference, bytes)?;
        let key = (class, reference.hash);
        match self.blobs.get(&key) {
            Some(existing) if existing == bytes => Ok(false),
            Some(_) => Err(JournalStoreError::Corrupt),
            None => {
                self.blobs.insert(key, bytes.to_vec());
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
struct PinnedDirectory {
    file: File,
    parent: Option<usize>,
    name: CString,
    identity: FileIdentity,
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
                "catalog",
                "authority",
                "genesis-admission",
                "genesis-admission.next",
                "genesis",
                "genesis.next",
                "heads",
                "heads.next",
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
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum PublicationPoint {
    ObjectDurable,
    HeadsStaged,
    HeadsDurable,
}

impl AgentJournalStore for FileAgentJournalStore {
    fn initialize(&mut self, sealed: &ReplaySealedGenesis) -> Result<bool, JournalStoreError> {
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
    use crate::agent::execution::{ActorInvocation, ActorInvocationAuth};
    use crate::agent::invocation_index::InvocationIndex;
    use crate::agent::journal::{
        CheckpointLane, InvocationDisposition, InvocationOwner, InvocationOwnershipKey,
        InvocationResultState, ReplayInput, ReplayInputId, ReplayOperation, RuntimeBinding,
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

    trait RawTestInitialize {
        fn initialize_raw(
            &mut self,
            genesis: &AgentJournalGenesis,
        ) -> Result<bool, JournalStoreError>;
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
        let key = InvocationOwnershipKey {
            scope: InvocationOwnershipScope::Ordered,
            invocation: InvocationId([0x61; 32]),
        };
        let owner = InvocationOwner {
            scope: key.scope,
            request_commitment: Hash([0x62; 32]),
            first_input: ReplayInputId([0x63; 32]),
            lane: PersistedLane::Linear,
            node: None,
            disposition: InvocationDisposition::Applied,
            result_state: InvocationResultState::Retained,
        };
        let mut index = InvocationIndex::open(&mut store, heads.ordered_invocations).unwrap();
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
        let reopened = open_file_store(&directory);
        validate_invocation_index(
            &reopened,
            index_id,
            genesis.id(),
            InvocationOwnershipScope::Ordered,
        )
        .unwrap();
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
        b"genesis-admission.next.partial" | b"genesis.next.partial" | b"heads.next.partial"
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
