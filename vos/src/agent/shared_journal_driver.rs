//! Physical Shared-Agent journal application.
//!
//! This is the narrow bridge between a committed per-Agent Raft log and the
//! generic lane journal/replay engine. Raft never publishes a journal record
//! directly: every ordinary slot is first reserved by the generation ledger,
//! artifact commands cross a durable staging boundary, and Ordered commands
//! cross replay's opaque [`PublishedSharedOrdered`] receipt before the Raft
//! application cursor advances.

use std::collections::{BTreeMap, BTreeSet};
use std::fs::{self, File, OpenOptions};
use std::io::{Read, Write};
#[cfg(target_os = "linux")]
use std::os::unix::fs::OpenOptionsExt;
use std::path::{Path, PathBuf};
use std::sync::Arc;

use super::driver::{AgentTrustProvider, SdkManagementArtifacts};
use super::execution::RuntimeBlob;
use super::journal::{
    CanonicalJournalRecord, LocalEntry, MergeEvent, MergeFrontier, OrderedBase, OrderedEntry,
    PersistedLane, ReplayInput, ReplayInputId, ReplayOperation,
};
use super::journal_store::{
    AgentJournalGarbageCollection, AgentJournalStore, CatalogBlobResolver,
    CatalogBlobResolverFactory, GcLimits, JournalBlobClass, JournalGc, JournalStoreError,
    MemoryAgentJournalStore, PortableJournalCheckpoint, PortableJournalLimits,
    ReverifiedRootJournalStore, SharedOrderedCommitRetirementStore, SharedOrderedCommitStore,
    TransitionProofPublicationStore, export_portable_journal_checkpoint, validate_gc_limits,
};
use super::local_journal_driver::{
    AttestedReplayTransitionProvider, LocalMergeAuthenticator, LocalReplayExecutorError,
    StandardLocalReplayExecutor, recent_clean_local_operation, recent_clean_management_operation,
    recent_clean_merge_operation, recent_clean_ordered_operation,
};
use super::replay::{
    CommittedSharedOrdered, MaterializeError, NoPrunedOrderedBases, ReplayExecutor,
    ReplayMaterialization, ReplayPreparation, ReplaySource, SharedReplayPreparation,
    materialize_current, prepare_local, prepare_merge, prepare_shared_checkpoint,
    prepare_shared_ordered, validate_published_shared_checkpoint,
};
use super::shared_commit::{
    OrderedCommitClaim, SharedAgentPortableSnapshotCertificate, SharedAgentPortableSnapshotClaim,
    SharedAgentSnapshotCertificate, SharedAgentSnapshotClaim, SharedCommitError,
    VerifiedSharedAgentPortableSnapshot,
};
use super::shared_raft::{
    ARTIFACT_CHUNK_DATA_BYTES, AgentGenerationRouteKey, AgentRaftApplicationErrorV2,
    AgentRaftApplicationLedgerV2, AgentRaftAuditDisposition, AgentRaftCommand,
    AgentRaftFoundationApplyOutcomeV2, AgentRaftJournalAuditV2, AgentRaftOrderedJournalAnchorV2,
    AgentRaftPendingOrderedV2, ArtifactBatchId, ArtifactBatchManifest, ArtifactChunk,
    CommittedSharedRaftSlot, InstalledAgentRaftSnapshotV2,
};
use super::wire::RuntimeState;
use super::{AgentProfile, ReplicaRole};
use crate::service::wire::ServiceWire;
use crate::service::{BlobRef, Hash, NodeId};

type SharedReplayError = MaterializeError<core::convert::Infallible, LocalReplayExecutorError>;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum SharedArtifactStagerError {
    Unavailable,
    Conflict,
    Corrupt,
    LimitExceeded,
}

/// Durable artifact-batch staging owned by the physical Shared host.
///
/// `load_complete` is non-consuming so an Ordered publication that loses its
/// response can be replayed without reconstructing bytes from an untrusted
/// source. `retire` is cleanup only and happens after both journal publication
/// and atomic Raft cursor advancement.
pub(crate) trait SharedArtifactStager {
    /// Re-audit the complete durable namespace against the exact generation.
    /// Drivers call this before accepting any replay/ledger state on reopen.
    fn audit(&self, generation: AgentGenerationRouteKey) -> Result<(), SharedArtifactStagerError>;

    fn stage(&mut self, chunk: &ArtifactChunk) -> Result<(), SharedArtifactStagerError>;

    /// Return true only when this exact canonical chunk is already durable.
    /// A conflicting manifest or byte body is corruption, never a cache hit.
    fn contains(&self, chunk: &ArtifactChunk) -> Result<bool, SharedArtifactStagerError>;

    fn abort(
        &mut self,
        route: super::shared_raft::AgentRouteKey,
        batch: ArtifactBatchId,
    ) -> Result<(), SharedArtifactStagerError>;

    fn load_complete(
        &self,
        route: super::shared_raft::AgentRouteKey,
        batch: ArtifactBatchId,
    ) -> Result<(ArtifactBatchManifest, Vec<RuntimeBlob>), SharedArtifactStagerError>;

    fn retire(
        &mut self,
        route: super::shared_raft::AgentRouteKey,
        batch: ArtifactBatchId,
    ) -> Result<(), SharedArtifactStagerError>;
}

/// Opaque proof that the configured durable stager returned and the driver
/// content-validated the complete batch for this exact committee route.
/// Fields and construction remain private to this module; replay can inspect
/// but cannot manufacture the capability.
pub(crate) struct ValidatedSharedArtifactBatch {
    route: super::shared_raft::AgentRouteKey,
    batch: ArtifactBatchId,
}

impl ValidatedSharedArtifactBatch {
    fn new(route: super::shared_raft::AgentRouteKey, batch: ArtifactBatchId) -> Self {
        Self { route, batch }
    }

    pub(super) const fn route(&self) -> super::shared_raft::AgentRouteKey {
        self.route
    }

    pub(super) const fn batch(&self) -> ArtifactBatchId {
        self.batch
    }
}

const STAGING_ROUTE_FILE: &str = "generation.route";
const STAGING_MANIFEST_FILE: &str = "manifest";
const STAGING_NEXT_SUFFIX: &str = ".next";
const STAGING_CHUNK_SUFFIX: &str = ".chunk";
const STAGING_FILE_OVERHEAD_BYTES: usize = 1024;

/// Filesystem-backed staging for one exact Shared journal generation.
///
/// The generation binding is an immutable canonical file outside the batch
/// directories. Every manifest and chunk is installed by a create-new staged
/// file followed by rename+directory fsync. Existing bytes are accepted only
/// as an exact retry. Startup scans the complete namespace and rejects unknown
/// entries, symlinks, noncanonical names, and partial staged files rather than
/// treating ambiguous residue as an empty batch.
#[cfg(target_os = "linux")]
pub(crate) struct FileSharedArtifactStager {
    root: PathBuf,
    generation: AgentGenerationRouteKey,
}

#[cfg(target_os = "linux")]
impl FileSharedArtifactStager {
    pub(crate) fn open(
        root: impl Into<PathBuf>,
        generation: AgentGenerationRouteKey,
    ) -> Result<Self, SharedArtifactStagerError> {
        generation
            .validate()
            .map_err(|_| SharedArtifactStagerError::Corrupt)?;
        let root = root.into();
        ensure_plain_directory(&root)?;
        let route_path = root.join(STAGING_ROUTE_FILE);
        install_immutable_file(&route_path, &generation.encode())?;
        let stager = Self { root, generation };
        stager.audit_namespace()?;
        Ok(stager)
    }

    pub(crate) const fn generation(&self) -> AgentGenerationRouteKey {
        self.generation
    }

    fn audit_namespace(&self) -> Result<(), SharedArtifactStagerError> {
        let route = read_regular_bounded(
            &self.root.join(STAGING_ROUTE_FILE),
            super::shared_raft::MAX_AGENT_GENERATION_ROUTE_KEY_BYTES + STAGING_FILE_OVERHEAD_BYTES,
        )?;
        let decoded = AgentGenerationRouteKey::decode(&route)
            .map_err(|_| SharedArtifactStagerError::Corrupt)?;
        if decoded != self.generation || decoded.encode() != route {
            return Err(SharedArtifactStagerError::Conflict);
        }
        for entry in fs::read_dir(&self.root).map_err(|_| SharedArtifactStagerError::Unavailable)? {
            let entry = entry.map_err(|_| SharedArtifactStagerError::Unavailable)?;
            let name = entry
                .file_name()
                .into_string()
                .map_err(|_| SharedArtifactStagerError::Corrupt)?;
            if name == STAGING_ROUTE_FILE {
                require_regular(&entry.path())?;
                continue;
            }
            let batch = decode_batch_directory_name(&name)?;
            require_directory(&entry.path())?;
            self.audit_batch(batch, &entry.path(), false)?;
        }
        Ok(())
    }

    fn batch_path(&self, batch: ArtifactBatchId) -> PathBuf {
        self.root.join(encode_hex(batch.as_bytes()))
    }

    fn manifest(
        &self,
        batch: ArtifactBatchId,
        path: &Path,
    ) -> Result<ArtifactBatchManifest, SharedArtifactStagerError> {
        let bytes = read_regular_bounded(
            &path.join(STAGING_MANIFEST_FILE),
            super::shared_raft::MAX_ARTIFACT_BATCH_MANIFEST_BYTES + STAGING_FILE_OVERHEAD_BYTES,
        )?;
        let manifest = ArtifactBatchManifest::decode(&bytes)
            .map_err(|_| SharedArtifactStagerError::Corrupt)?;
        if manifest.encode() != bytes
            || manifest.id() != batch
            || manifest.route().generation() != self.generation
        {
            return Err(SharedArtifactStagerError::Conflict);
        }
        Ok(manifest)
    }

    fn audit_batch(
        &self,
        batch: ArtifactBatchId,
        path: &Path,
        require_complete: bool,
    ) -> Result<ArtifactBatchManifest, SharedArtifactStagerError> {
        let manifest = self.manifest(batch, path)?;
        let mut expected = BTreeSet::new();
        expected.insert(STAGING_MANIFEST_FILE.to_owned());
        for (artifact_index, reference) in manifest.artifacts().iter().enumerate() {
            let mut offset = 0_u64;
            while offset < reference.len {
                expected.insert(chunk_file_name(artifact_index as u32, offset));
                offset = offset
                    .checked_add(super::shared_raft::ARTIFACT_CHUNK_DATA_BYTES as u64)
                    .ok_or(SharedArtifactStagerError::LimitExceeded)?;
            }
        }
        for entry in fs::read_dir(path).map_err(|_| SharedArtifactStagerError::Unavailable)? {
            let entry = entry.map_err(|_| SharedArtifactStagerError::Unavailable)?;
            let name = entry
                .file_name()
                .into_string()
                .map_err(|_| SharedArtifactStagerError::Corrupt)?;
            if !expected.contains(&name) {
                return Err(SharedArtifactStagerError::Corrupt);
            }
            require_regular(&entry.path())?;
        }
        if require_complete {
            for name in expected {
                require_regular(&path.join(name))?;
            }
        }
        Ok(manifest)
    }

    fn remove_batch(&self, batch: ArtifactBatchId) -> Result<(), SharedArtifactStagerError> {
        let path = self.batch_path(batch);
        match fs::symlink_metadata(&path) {
            Ok(_) => {}
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => return Ok(()),
            Err(_) => return Err(SharedArtifactStagerError::Unavailable),
        }
        require_directory(&path)?;
        self.audit_batch(batch, &path, false)?;
        for entry in fs::read_dir(&path).map_err(|_| SharedArtifactStagerError::Unavailable)? {
            let entry = entry.map_err(|_| SharedArtifactStagerError::Unavailable)?;
            require_regular(&entry.path())?;
            fs::remove_file(entry.path()).map_err(|_| SharedArtifactStagerError::Unavailable)?;
        }
        fs::remove_dir(&path).map_err(|_| SharedArtifactStagerError::Unavailable)?;
        sync_directory(&self.root)
    }
}

#[cfg(target_os = "linux")]
impl SharedArtifactStager for FileSharedArtifactStager {
    fn audit(&self, generation: AgentGenerationRouteKey) -> Result<(), SharedArtifactStagerError> {
        if generation != self.generation {
            return Err(SharedArtifactStagerError::Conflict);
        }
        self.audit_namespace()
    }

    fn stage(&mut self, chunk: &ArtifactChunk) -> Result<(), SharedArtifactStagerError> {
        chunk
            .validate()
            .map_err(|_| SharedArtifactStagerError::Corrupt)?;
        if chunk.manifest().route().generation() != self.generation {
            return Err(SharedArtifactStagerError::Conflict);
        }
        let path = self.batch_path(chunk.batch());
        ensure_plain_directory(&path)?;
        install_immutable_file(
            &path.join(STAGING_MANIFEST_FILE),
            &chunk.manifest().encode(),
        )?;
        let existing = self.manifest(chunk.batch(), &path)?;
        if &existing != chunk.manifest() {
            return Err(SharedArtifactStagerError::Conflict);
        }
        install_immutable_file(
            &path.join(chunk_file_name(chunk.artifact_index(), chunk.offset())),
            chunk.bytes(),
        )?;
        self.audit_batch(chunk.batch(), &path, false)?;
        Ok(())
    }

    fn contains(&self, chunk: &ArtifactChunk) -> Result<bool, SharedArtifactStagerError> {
        chunk
            .validate()
            .map_err(|_| SharedArtifactStagerError::Corrupt)?;
        if chunk.manifest().route().generation() != self.generation {
            return Err(SharedArtifactStagerError::Conflict);
        }
        let path = self.batch_path(chunk.batch());
        match fs::symlink_metadata(&path) {
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => return Ok(false),
            Err(_) => return Err(SharedArtifactStagerError::Unavailable),
            Ok(_) => require_directory(&path)?,
        }
        if self.manifest(chunk.batch(), &path)? != *chunk.manifest() {
            return Err(SharedArtifactStagerError::Conflict);
        }
        let chunk_path = path.join(chunk_file_name(chunk.artifact_index(), chunk.offset()));
        match fs::symlink_metadata(&chunk_path) {
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => Ok(false),
            Err(_) => Err(SharedArtifactStagerError::Unavailable),
            Ok(_) => {
                require_regular(&chunk_path)?;
                let bytes = read_regular_bounded(
                    &chunk_path,
                    super::shared_raft::ARTIFACT_CHUNK_DATA_BYTES + STAGING_FILE_OVERHEAD_BYTES,
                )?;
                if bytes != chunk.bytes() {
                    return Err(SharedArtifactStagerError::Conflict);
                }
                Ok(true)
            }
        }
    }

    fn abort(
        &mut self,
        route: super::shared_raft::AgentRouteKey,
        batch: ArtifactBatchId,
    ) -> Result<(), SharedArtifactStagerError> {
        if route.generation() != self.generation || batch == ArtifactBatchId::ZERO {
            return Err(SharedArtifactStagerError::Conflict);
        }
        self.remove_batch(batch)
    }

    fn load_complete(
        &self,
        route: super::shared_raft::AgentRouteKey,
        batch: ArtifactBatchId,
    ) -> Result<(ArtifactBatchManifest, Vec<RuntimeBlob>), SharedArtifactStagerError> {
        if batch == ArtifactBatchId::ZERO || route.generation() != self.generation {
            return Err(SharedArtifactStagerError::Corrupt);
        }
        let path = self.batch_path(batch);
        require_directory(&path)?;
        let manifest = self.audit_batch(batch, &path, true)?;
        if manifest.route() != route {
            return Err(SharedArtifactStagerError::Conflict);
        }
        let mut blobs = Vec::new();
        blobs
            .try_reserve(manifest.artifacts().len())
            .map_err(|_| SharedArtifactStagerError::LimitExceeded)?;
        for (artifact_index, reference) in manifest.artifacts().iter().enumerate() {
            let capacity = usize::try_from(reference.len)
                .map_err(|_| SharedArtifactStagerError::LimitExceeded)?;
            let mut bytes = Vec::new();
            bytes
                .try_reserve_exact(capacity)
                .map_err(|_| SharedArtifactStagerError::LimitExceeded)?;
            let mut offset = 0_u64;
            while offset < reference.len {
                let chunk = read_regular_bounded(
                    &path.join(chunk_file_name(artifact_index as u32, offset)),
                    super::shared_raft::ARTIFACT_CHUNK_DATA_BYTES + STAGING_FILE_OVERHEAD_BYTES,
                )?;
                let expected = (reference.len - offset)
                    .min(super::shared_raft::ARTIFACT_CHUNK_DATA_BYTES as u64)
                    as usize;
                if chunk.len() != expected {
                    return Err(SharedArtifactStagerError::Corrupt);
                }
                bytes.extend_from_slice(&chunk);
                offset = offset
                    .checked_add(super::shared_raft::ARTIFACT_CHUNK_DATA_BYTES as u64)
                    .ok_or(SharedArtifactStagerError::LimitExceeded)?;
            }
            if bytes.len() != capacity || !reference.matches(&bytes) {
                return Err(SharedArtifactStagerError::Corrupt);
            }
            blobs.push(RuntimeBlob {
                reference: reference.clone(),
                bytes,
            });
        }
        Ok((manifest, blobs))
    }

    fn retire(
        &mut self,
        route: super::shared_raft::AgentRouteKey,
        batch: ArtifactBatchId,
    ) -> Result<(), SharedArtifactStagerError> {
        if route.generation() != self.generation || batch == ArtifactBatchId::ZERO {
            return Err(SharedArtifactStagerError::Conflict);
        }
        let path = self.batch_path(batch);
        if path.exists() {
            let manifest = self.manifest(batch, &path)?;
            if manifest.route() != route {
                return Err(SharedArtifactStagerError::Conflict);
            }
        }
        self.remove_batch(batch)
    }
}

#[cfg(target_os = "linux")]
pub(super) fn install_immutable_file(
    path: &Path,
    bytes: &[u8],
) -> Result<(), SharedArtifactStagerError> {
    match fs::symlink_metadata(path) {
        Ok(_) => {
            let existing = read_regular_bounded(path, bytes.len().saturating_add(1))?;
            if existing != bytes {
                return Err(SharedArtifactStagerError::Conflict);
            }
            let name = path
                .file_name()
                .and_then(|name| name.to_str())
                .ok_or(SharedArtifactStagerError::Corrupt)?;
            let staged = path.with_file_name(format!("{name}{STAGING_NEXT_SUFFIX}"));
            match fs::symlink_metadata(&staged) {
                Ok(_) => {
                    use std::os::unix::fs::MetadataExt as _;

                    let staged_bytes =
                        read_regular_bounded(&staged, bytes.len().saturating_add(1))?;
                    let canonical_meta =
                        fs::metadata(path).map_err(|_| SharedArtifactStagerError::Unavailable)?;
                    let staged_meta = fs::metadata(&staged)
                        .map_err(|_| SharedArtifactStagerError::Unavailable)?;
                    if staged_bytes != bytes
                        || canonical_meta.dev() != staged_meta.dev()
                        || canonical_meta.ino() != staged_meta.ino()
                    {
                        return Err(SharedArtifactStagerError::Conflict);
                    }
                    fs::remove_file(&staged).map_err(|_| SharedArtifactStagerError::Unavailable)?;
                    let parent = path.parent().ok_or(SharedArtifactStagerError::Corrupt)?;
                    sync_directory(parent)?;
                }
                Err(error) if error.kind() == std::io::ErrorKind::NotFound => {}
                Err(_) => return Err(SharedArtifactStagerError::Unavailable),
            }
            return Ok(());
        }
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => {}
        Err(_) => return Err(SharedArtifactStagerError::Unavailable),
    }
    let name = path
        .file_name()
        .and_then(|name| name.to_str())
        .ok_or(SharedArtifactStagerError::Corrupt)?;
    let staged = path.with_file_name(format!("{name}{STAGING_NEXT_SUFFIX}"));
    let mut options = OpenOptions::new();
    options.write(true).create_new(true).mode(0o600);
    match options.open(&staged) {
        Ok(mut file) => {
            file.write_all(bytes)
                .map_err(|_| SharedArtifactStagerError::Unavailable)?;
            file.sync_all()
                .map_err(|_| SharedArtifactStagerError::Unavailable)?;
        }
        Err(error) if error.kind() == std::io::ErrorKind::AlreadyExists => {
            let existing = read_regular_bounded(&staged, bytes.len().saturating_add(1))?;
            if existing != bytes {
                return Err(SharedArtifactStagerError::Conflict);
            }
        }
        Err(_) => return Err(SharedArtifactStagerError::Unavailable),
    }
    // `hard_link` is the portable create-if-absent publication primitive on
    // Linux. Unlike rename it never replaces a concurrently introduced live
    // entry. The generation host owns the directory, but retaining this
    // property also makes namespace attacks fail closed.
    match fs::hard_link(&staged, path) {
        Ok(()) => {}
        Err(error) if error.kind() == std::io::ErrorKind::AlreadyExists => {
            let existing = read_regular_bounded(path, bytes.len().saturating_add(1))?;
            if existing != bytes {
                return Err(SharedArtifactStagerError::Conflict);
            }
        }
        Err(_) => return Err(SharedArtifactStagerError::Unavailable),
    }
    fs::remove_file(&staged).map_err(|_| SharedArtifactStagerError::Unavailable)?;
    let parent = path.parent().ok_or(SharedArtifactStagerError::Corrupt)?;
    sync_directory(parent)
}

#[cfg(target_os = "linux")]
pub(super) fn read_regular_bounded(
    path: &Path,
    maximum: usize,
) -> Result<Vec<u8>, SharedArtifactStagerError> {
    require_regular(path)?;
    let file = OpenOptions::new()
        .read(true)
        .custom_flags(libc::O_NOFOLLOW)
        .open(path)
        .map_err(|_| SharedArtifactStagerError::Unavailable)?;
    let length = file
        .metadata()
        .map_err(|_| SharedArtifactStagerError::Unavailable)?
        .len();
    if length > maximum as u64 {
        return Err(SharedArtifactStagerError::LimitExceeded);
    }
    let mut bytes = Vec::new();
    bytes
        .try_reserve_exact(length as usize)
        .map_err(|_| SharedArtifactStagerError::LimitExceeded)?;
    file.take(maximum.saturating_add(1) as u64)
        .read_to_end(&mut bytes)
        .map_err(|_| SharedArtifactStagerError::Unavailable)?;
    if bytes.len() > maximum {
        return Err(SharedArtifactStagerError::LimitExceeded);
    }
    Ok(bytes)
}

#[cfg(target_os = "linux")]
fn ensure_plain_directory(path: &Path) -> Result<(), SharedArtifactStagerError> {
    match fs::symlink_metadata(path) {
        Ok(_) => require_directory(path),
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => {
            fs::create_dir(path).map_err(|_| SharedArtifactStagerError::Unavailable)?;
            let parent = path.parent().ok_or(SharedArtifactStagerError::Corrupt)?;
            sync_directory(parent)
        }
        Err(_) => Err(SharedArtifactStagerError::Unavailable),
    }
}

#[cfg(target_os = "linux")]
fn require_directory(path: &Path) -> Result<(), SharedArtifactStagerError> {
    let metadata =
        fs::symlink_metadata(path).map_err(|_| SharedArtifactStagerError::Unavailable)?;
    if metadata.file_type().is_dir() && !metadata.file_type().is_symlink() {
        Ok(())
    } else {
        Err(SharedArtifactStagerError::Corrupt)
    }
}

#[cfg(target_os = "linux")]
fn require_regular(path: &Path) -> Result<(), SharedArtifactStagerError> {
    let metadata =
        fs::symlink_metadata(path).map_err(|_| SharedArtifactStagerError::Unavailable)?;
    if metadata.file_type().is_file() && !metadata.file_type().is_symlink() {
        Ok(())
    } else {
        Err(SharedArtifactStagerError::Corrupt)
    }
}

#[cfg(target_os = "linux")]
fn sync_directory(path: &Path) -> Result<(), SharedArtifactStagerError> {
    File::open(path)
        .and_then(|directory| directory.sync_all())
        .map_err(|_| SharedArtifactStagerError::Unavailable)
}

#[cfg(target_os = "linux")]
fn chunk_file_name(artifact_index: u32, offset: u64) -> String {
    format!("{artifact_index:08x}-{offset:016x}{STAGING_CHUNK_SUFFIX}")
}

#[cfg(target_os = "linux")]
fn decode_batch_directory_name(name: &str) -> Result<ArtifactBatchId, SharedArtifactStagerError> {
    if name.len() != 64
        || !name
            .bytes()
            .all(|byte| byte.is_ascii_hexdigit() && !byte.is_ascii_uppercase())
    {
        return Err(SharedArtifactStagerError::Corrupt);
    }
    let mut bytes = [0_u8; 32];
    for (index, byte) in bytes.iter_mut().enumerate() {
        let position = index * 2;
        *byte = u8::from_str_radix(&name[position..position + 2], 16)
            .map_err(|_| SharedArtifactStagerError::Corrupt)?;
    }
    let batch = ArtifactBatchId::from_bytes(bytes);
    if batch == ArtifactBatchId::ZERO || encode_hex(batch.as_bytes()) != name {
        return Err(SharedArtifactStagerError::Corrupt);
    }
    Ok(batch)
}

#[cfg(target_os = "linux")]
fn encode_hex(bytes: &[u8]) -> String {
    let mut output = String::with_capacity(bytes.len() * 2);
    for byte in bytes {
        use core::fmt::Write as _;
        let _ = write!(output, "{byte:02x}");
    }
    output
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum SharedPhysicalApplyOutcome {
    Applied { index: u64 },
    Duplicate { index: u64 },
    Idle,
}

/// Publication state of one canonical Merge object. Content storage is not a
/// substitute for reachability from the authenticated journal head: fetched
/// parents are durably staged before their complete closure is available.
#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) enum SharedMergeObject {
    Missing,
    Staged(Vec<u8>),
    Published(Vec<u8>),
}

/// Deterministic test executor used only to create a fully authenticated
/// Local-head suffix around the snapshot predecessor regression. Production
/// Shared replay always uses `StandardLocalReplayExecutor` above.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) struct SharedSnapshotCompactionOutcome {
    pub(crate) bindings_removed: usize,
    pub(crate) bindings_remaining: usize,
    pub(crate) journal: Option<JournalGc>,
}

#[derive(Debug)]
pub(crate) enum SharedJournalDriverError {
    Store(JournalStoreError),
    Replay(SharedReplayError),
    Ledger(AgentRaftApplicationErrorV2),
    Artifact(SharedArtifactStagerError),
    WrongReplica,
    InvalidProfile,
    InvalidArtifactBatch,
    CrossStoreMismatch,
    Snapshot(SharedCommitError),
    Executor(LocalReplayExecutorError),
}

impl From<JournalStoreError> for SharedJournalDriverError {
    fn from(error: JournalStoreError) -> Self {
        Self::Store(error)
    }
}

impl From<SharedReplayError> for SharedJournalDriverError {
    fn from(error: SharedReplayError) -> Self {
        Self::Replay(error)
    }
}

impl From<AgentRaftApplicationErrorV2> for SharedJournalDriverError {
    fn from(error: AgentRaftApplicationErrorV2) -> Self {
        Self::Ledger(error)
    }
}

impl From<SharedArtifactStagerError> for SharedJournalDriverError {
    fn from(error: SharedArtifactStagerError) -> Self {
        Self::Artifact(error)
    }
}

impl From<SharedCommitError> for SharedJournalDriverError {
    fn from(error: SharedCommitError) -> Self {
        Self::Snapshot(error)
    }
}

impl From<LocalReplayExecutorError> for SharedJournalDriverError {
    fn from(error: LocalReplayExecutorError) -> Self {
        Self::Executor(error)
    }
}

/// Canonical Raft proposal and replay correlation for one clean ordered
/// invocation. No mutable journal state changes while this value is built.
pub(crate) enum PreparedCleanOrdered {
    Retained {
        input: ReplayInputId,
        outcome: crate::agent_sdk::RuntimeOutcome,
    },
    Proposal {
        input: ReplayInputId,
        payload: Vec<u8>,
    },
}

impl PreparedCleanOrdered {
    pub(crate) const fn input(&self) -> ReplayInputId {
        match self {
            Self::Retained { input, .. } | Self::Proposal { input, .. } => *input,
        }
    }

    pub(crate) fn retained(&self) -> Option<&crate::agent_sdk::RuntimeOutcome> {
        match self {
            Self::Retained { outcome, .. } => Some(outcome),
            Self::Proposal { .. } => None,
        }
    }

    pub(crate) fn into_payload(self) -> Option<Vec<u8>> {
        match self {
            Self::Retained { .. } => None,
            Self::Proposal { payload, .. } => Some(payload),
        }
    }
}

/// Exact clean invocation-lifecycle request before its trusted observation
/// slot is fixed by the physical driver. No ResumeWork is accepted here: the
/// yielded selector is only a concurrency token and replay reconstructs the
/// executable resume from durable guest state.
#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) enum CleanInvocationReplayRequest {
    Invoke {
        context: crate::agent_sdk::RuntimeExecutionContext,
        work: crate::agent_sdk::InvocationWork,
        authorization: crate::agent_sdk::InvocationAuthorization,
    },
    Resume {
        context: crate::agent_sdk::RuntimeExecutionContext,
        work: crate::agent_sdk::InvocationWork,
        authorization: crate::agent_sdk::InvocationAuthorization,
        yielded: crate::agent_sdk::YieldedInvocation,
    },
    Acknowledge {
        work: crate::agent_sdk::InvocationWork,
        authorization: crate::agent_sdk::InvocationAuthorization,
    },
}

/// Cursor immediately preceding one canonical actor key. `InspectActors`
/// uses an exclusive cursor, so a one-entry request from this value is a
/// keyed lookup without adding a second directory authority surface.
fn exclusive_actor_predecessor(
    target: crate::agent_sdk::ActorId,
) -> Option<crate::agent_sdk::ActorId> {
    if target == crate::agent_sdk::ActorId::ZERO {
        return None;
    }
    let mut predecessor = target.0;
    for byte in predecessor.iter_mut().rev() {
        if *byte == 0 {
            *byte = u8::MAX;
        } else {
            *byte -= 1;
            let predecessor = crate::agent_sdk::ActorId(predecessor);
            // `InspectActors` rejects an explicit zero cursor. For the
            // smallest valid ActorId, an absent cursor is the exact
            // exclusive predecessor and still yields a one-record lookup.
            return (predecessor != crate::agent_sdk::ActorId::ZERO).then_some(predecessor);
        }
    }
    None
}

impl CleanInvocationReplayRequest {
    pub(crate) const fn work(&self) -> &crate::agent_sdk::InvocationWork {
        match self {
            Self::Invoke { work, .. }
            | Self::Resume { work, .. }
            | Self::Acknowledge { work, .. } => work,
        }
    }

    pub(crate) const fn authorization(&self) -> &crate::agent_sdk::InvocationAuthorization {
        match self {
            Self::Invoke { authorization, .. }
            | Self::Resume { authorization, .. }
            | Self::Acknowledge { authorization, .. } => authorization,
        }
    }

    fn into_operation(self, observed_slot: u64) -> ReplayOperation {
        match self {
            Self::Invoke {
                context,
                work,
                authorization,
            } => ReplayOperation::CleanInvoke {
                context,
                work,
                authorization,
                observed_slot,
            },
            Self::Resume {
                context,
                work,
                authorization,
                yielded,
            } => ReplayOperation::CleanResume {
                context,
                expected_live: None,
                work,
                authorization,
                yielded,
                observed_slot,
            },
            Self::Acknowledge {
                work,
                authorization,
            } => ReplayOperation::CleanAcknowledge {
                context: crate::agent_sdk::RuntimeExecutionContext::Direct,
                expected_live: None,
                work,
                authorization,
            },
        }
    }
}

/// Result of clean management proposal preparation. An unchanged denial is
/// nondurable and allocates no Raft slot. A successful no-op returns an
/// Ordered command unless a bounded durable suffix lookup proves this exact
/// request and receipt were already committed.
#[derive(Debug)]
pub(crate) enum PreparedCleanManagement {
    Denied {
        outcome: crate::agent_sdk::RuntimeOutcome,
        observed_slot: u64,
    },
    Retained {
        outcome: crate::agent_sdk::RuntimeOutcome,
        observed_slot: u64,
    },
    Proposal {
        input: ReplayInputId,
        observed_slot: u64,
        commands: Vec<Vec<u8>>,
    },
}

impl PreparedCleanManagement {
    pub(crate) const fn input(&self) -> Option<ReplayInputId> {
        match self {
            Self::Denied { .. } | Self::Retained { .. } => None,
            Self::Proposal { input, .. } => Some(*input),
        }
    }

    pub(crate) const fn observed_slot(&self) -> u64 {
        match self {
            Self::Denied { observed_slot, .. }
            | Self::Retained { observed_slot, .. }
            | Self::Proposal { observed_slot, .. } => *observed_slot,
        }
    }

    pub(crate) fn denied(&self) -> Option<&crate::agent_sdk::RuntimeOutcome> {
        match self {
            Self::Denied { outcome, .. } => Some(outcome),
            Self::Retained { .. } | Self::Proposal { .. } => None,
        }
    }

    pub(crate) fn retained(&self) -> Option<&crate::agent_sdk::RuntimeOutcome> {
        match self {
            Self::Retained { outcome, .. } => Some(outcome),
            Self::Denied { .. } | Self::Proposal { .. } => None,
        }
    }

    pub(crate) fn into_commands(self) -> Vec<Vec<u8>> {
        match self {
            Self::Denied { .. } | Self::Retained { .. } => Vec::new(),
            Self::Proposal { commands, .. } => commands,
        }
    }
}

/// One independently durable physical Shared replica.
pub(crate) struct SharedJournalAgentDriver<S, A>
where
    S: AgentJournalStore
        + ReplaySource<Error = JournalStoreError>
        + CatalogBlobResolverFactory
        + SharedOrderedCommitStore
        + SharedOrderedCommitRetirementStore
        + AgentJournalGarbageCollection
        + TransitionProofPublicationStore,
    A: SharedArtifactStager,
{
    store: S,
    artifacts: A,
    executor: StandardLocalReplayExecutor<S::Resolver>,
    materialization: ReplayMaterialization,
    ledger: AgentRaftApplicationLedgerV2,
    local_node: NodeId,
    replay_trust: Arc<dyn AgentTrustProvider>,
    replay_merge: Arc<dyn LocalMergeAuthenticator>,
}

impl<S, A> SharedJournalAgentDriver<S, A>
where
    S: AgentJournalStore
        + ReplaySource<Error = JournalStoreError>
        + CatalogBlobResolverFactory
        + SharedOrderedCommitStore
        + SharedOrderedCommitRetirementStore
        + AgentJournalGarbageCollection
        + TransitionProofPublicationStore,
    A: SharedArtifactStager,
{
    pub(crate) fn open(
        store: S,
        artifacts: A,
        ledger: AgentRaftApplicationLedgerV2,
        trust: Arc<dyn AgentTrustProvider>,
        merge: Arc<dyn LocalMergeAuthenticator>,
    ) -> Result<Self, SharedJournalDriverError> {
        Self::open_with_optional_attested_transition_provider(
            store, artifacts, ledger, trust, merge, None,
        )
    }

    /// Open a Shared replica with the producer/journal coordinator installed
    /// before replaying any retained Attested suffix.
    pub(crate) fn open_with_attested_transition_provider(
        store: S,
        artifacts: A,
        ledger: AgentRaftApplicationLedgerV2,
        trust: Arc<dyn AgentTrustProvider>,
        merge: Arc<dyn LocalMergeAuthenticator>,
        provider: Box<dyn AttestedReplayTransitionProvider>,
    ) -> Result<Self, SharedJournalDriverError> {
        Self::open_with_optional_attested_transition_provider(
            store,
            artifacts,
            ledger,
            trust,
            merge,
            Some(provider),
        )
    }

    fn open_with_optional_attested_transition_provider(
        mut store: S,
        artifacts: A,
        ledger: AgentRaftApplicationLedgerV2,
        trust: Arc<dyn AgentTrustProvider>,
        merge: Arc<dyn LocalMergeAuthenticator>,
        provider: Option<Box<dyn AttestedReplayTransitionProvider>>,
    ) -> Result<Self, SharedJournalDriverError> {
        let started = std::time::Instant::now();
        let report_phase = |phase: &'static str| {
            tracing::debug!(
                phase,
                elapsed_ms = started.elapsed().as_millis() as u64,
                "Shared journal driver open phase complete"
            );
        };
        let local_node = merge.node();
        if local_node != ledger.local_node() {
            return Err(SharedJournalDriverError::WrongReplica);
        }
        artifacts.audit(ledger.generation())?;
        report_phase("artifact_audit");
        let committees = ledger.committee_history()?;
        report_phase("committee_history");
        let resolver = store.catalog_blob_resolver()?;
        let mut executor = StandardLocalReplayExecutor::new_shared(
            resolver,
            trust.clone(),
            merge.clone(),
            committees,
        );
        if let Some(provider) = provider {
            executor.replace_attested_transition_provider(provider);
        }
        report_phase("executor_setup");
        let materialization =
            materialize_current(&mut store, &mut executor, &NoPrunedOrderedBases)?;
        report_phase("materialize_current");
        let active = ledger.active_committee()?;
        let route = ledger.generation();
        let (space, agent, shared_profile) = if executor.seeded_clean_descriptor().is_some() {
            let descriptor =
                executor.trusted_current_clean_descriptor(materialization.runtime())?;
            (
                crate::service::SpaceId(descriptor.identity.space.0),
                crate::service::AgentId(descriptor.identity.agent.0),
                descriptor.identity.profile == crate::agent_sdk::AgentProfile::Shared,
            )
        } else {
            let config = super::wire::decode_standard_runtime_state(materialization.state())
                .map_err(|_| SharedJournalDriverError::InvalidProfile)?
                .config
                .ok_or(SharedJournalDriverError::InvalidProfile)?;
            (
                config.identity.space,
                config.identity.agent,
                config.identity.profile == AgentProfile::Shared,
            )
        };
        if !shared_profile
            || active.profile() != AgentProfile::Shared
            || active.validate().is_err()
            || active.space() != space
            || active.agent() != agent
            || route.space() != space
            || route.agent() != agent
            || route.genesis() != materialization.heads().genesis
            || route.admission() != materialization.heads().admission
            || materialization.heads().node != local_node
            || store.instance_id() != ledger.journal_store()
        {
            return Err(SharedJournalDriverError::WrongReplica);
        }
        let audit = ledger.journal_audit()?;
        report_phase("profile_and_ledger_audit");
        if let Some(snapshot) = &audit.snapshot {
            validate_published_shared_checkpoint(&store, &materialization, &snapshot.claim)
                .map_err(|error| {
                    tracing::warn!(
                        ?error,
                        checkpoint_matches = materialization.heads().checkpoint
                            == Some(snapshot.claim.checkpoint()),
                        current_ordered_index = materialization.heads().ordered_index,
                        snapshot_ordered_index = snapshot.claim.ordered().ordered().index,
                        "Shared journal open checkpoint validation failed"
                    );
                    SharedJournalDriverError::CrossStoreMismatch
                })?;
        }
        report_phase("published_checkpoint_validation");
        reconcile_journal_ledger(&store, &materialization, ledger.journal_store(), &audit)
            .map_err(|error| {
                tracing::warn!(?error, "Shared journal open ledger reconciliation failed");
                error
            })?;
        report_phase("reconcile_journal_ledger");
        store.finish_reverified_open()?;
        report_phase("finish_reverified_open");
        Ok(Self {
            store,
            artifacts,
            executor,
            materialization,
            ledger,
            local_node,
            replay_trust: trust,
            replay_merge: merge,
        })
    }

    /// Re-materialize the durable journal using a fresh verifier/result cache
    /// before treating a retained Direct terminal result as lifecycle evidence.
    /// Missing/pruned results and histories requiring an unavailable attested
    /// replay provider fail closed; no new invocation is proposed here.
    pub(crate) fn replay_durable_clean_terminal(
        &mut self,
        request: CleanInvocationReplayRequest,
    ) -> Result<crate::agent_sdk::RuntimeOutcome, SharedJournalDriverError> {
        self.replay_durable_clean_terminal_with_input(request, None)
    }

    pub(crate) fn replay_durable_management_denial(
        &mut self,
        anchor: OrderedBase,
        envelope: &crate::agent_sdk::RuntimeWork,
    ) -> Result<crate::agent_sdk::RuntimeOutcome, SharedJournalDriverError> {
        let input = self
            .management_denial_invocation_after(anchor, envelope)?
            .ok_or(SharedJournalDriverError::CrossStoreMismatch)?;
        let crate::agent_sdk::RuntimeWork::Invoke {
            invocation,
            authorization,
            ..
        } = envelope
        else {
            return Err(SharedJournalDriverError::CrossStoreMismatch);
        };
        self.replay_durable_clean_terminal_with_input(
            CleanInvocationReplayRequest::Invoke {
                context: crate::agent_sdk::RuntimeExecutionContext::Direct,
                work: (**invocation).clone(),
                authorization: (**authorization).clone(),
            },
            Some(input),
        )
    }

    fn replay_durable_clean_terminal_with_input(
        &mut self,
        request: CleanInvocationReplayRequest,
        anchored_input: Option<ReplayInputId>,
    ) -> Result<crate::agent_sdk::RuntimeOutcome, SharedJournalDriverError> {
        let operation = request.into_operation(0);
        let resolver = self.store.catalog_blob_resolver()?;
        let mut executor = StandardLocalReplayExecutor::new_shared(
            resolver,
            self.replay_trust.clone(),
            self.replay_merge.clone(),
            self.ledger.committee_history()?,
        );
        let recovered = materialize_current(&mut self.store, &mut executor, &NoPrunedOrderedBases)?;
        let audit = self.ledger.journal_audit()?;
        if let Some(snapshot) = &audit.snapshot {
            validate_published_shared_checkpoint(&self.store, &recovered, &snapshot.claim)
                .map_err(|_| SharedJournalDriverError::CrossStoreMismatch)?;
        }
        reconcile_journal_ledger(&self.store, &recovered, self.ledger.journal_store(), &audit)?;
        if recovered.heads() != self.materialization.heads()
            || recovered.state() != self.materialization.state()
        {
            return Err(SharedJournalDriverError::CrossStoreMismatch);
        }
        let input = if let Some(input) = anchored_input {
            input
        } else {
            recent_clean_ordered_operation(&self.store, &recovered, &operation)?
                .ok_or(SharedJournalDriverError::CrossStoreMismatch)?
        };
        let outcome = executor
            .clean_ordered_result(input)
            .ok_or(SharedJournalDriverError::CrossStoreMismatch)?;
        if !matches!(outcome, crate::agent_sdk::RuntimeOutcome::Completed(_)) {
            return Err(SharedJournalDriverError::CrossStoreMismatch);
        }
        Ok(outcome)
    }

    pub(crate) fn local_role(&self) -> Result<Option<ReplicaRole>, SharedJournalDriverError> {
        Ok(self
            .ledger
            .active_committee()?
            .member_by_node(self.local_node)
            .map(|member| member.replica().role))
    }

    pub(crate) fn identity(&self) -> Result<super::AgentIdentity, SharedJournalDriverError> {
        if self.executor.seeded_clean_descriptor().is_some() {
            let identity = self
                .executor
                .trusted_current_clean_descriptor(self.materialization.runtime())?
                .identity;
            return Ok(super::AgentIdentity {
                space: crate::service::SpaceId(identity.space.0),
                agent: crate::service::AgentId(identity.agent.0),
                owner: crate::service::PrincipalId(identity.owner.0),
                profile: match identity.profile {
                    crate::agent_sdk::AgentProfile::Local => AgentProfile::Local,
                    crate::agent_sdk::AgentProfile::Shared => AgentProfile::Shared,
                    crate::agent_sdk::AgentProfile::Private => AgentProfile::Private,
                },
                runtime_deployment: crate::service::DeploymentId(identity.runtime_deployment.0),
                runtime_program: crate::service::ProgramId(identity.runtime_program.0),
                runtime_producer: crate::service::ProducerId(identity.runtime_producer.0),
                transition_producer: crate::service::ProducerId(identity.transition_producer.0),
            });
        }
        let state = super::wire::decode_standard_runtime_state(self.materialization.state())
            .map_err(|_| SharedJournalDriverError::InvalidProfile)?;
        Ok(state
            .config
            .ok_or(SharedJournalDriverError::InvalidProfile)?
            .identity)
    }

    /// Exact current clean descriptor reconstructed from the authenticated
    /// runtime binding and admitted package. Supervisor projections must use
    /// this value rather than the immutable genesis descriptor so a runtime
    /// upgrade invalidates every older readiness generation.
    pub(crate) fn clean_descriptor(
        &self,
    ) -> Result<crate::agent_sdk::AgentDescriptor, SharedJournalDriverError> {
        self.executor
            .trusted_current_clean_descriptor(self.materialization.runtime())
            .map_err(Into::into)
    }

    /// Resolve the current actor and every immutable invocation artifact from
    /// the authenticated journal catalog. This is read-only, but it remains
    /// on the physical driver so a policy projection can never provide the
    /// bytes or logical slot used for authority issuance.
    pub(crate) fn physical_invocation_material(
        &self,
        target: crate::agent_sdk::ActorId,
    ) -> Result<super::invocation_preparation::PhysicalInvocationMaterial, SharedJournalDriverError>
    {
        self.physical_material(target, true)
    }

    pub(crate) fn physical_authority_material(
        &self,
        target: crate::agent_sdk::ActorId,
    ) -> Result<super::invocation_preparation::PhysicalInvocationMaterial, SharedJournalDriverError>
    {
        self.physical_material(target, false)
    }

    fn physical_material(
        &self,
        target: crate::agent_sdk::ActorId,
        require_ready: bool,
    ) -> Result<super::invocation_preparation::PhysicalInvocationMaterial, SharedJournalDriverError>
    {
        if target == crate::agent_sdk::ActorId::ZERO {
            return Err(SharedJournalDriverError::CrossStoreMismatch);
        }
        let descriptor = self.clean_descriptor()?;
        if descriptor.validate().is_err()
            || descriptor.identity.profile != crate::agent_sdk::AgentProfile::Shared
        {
            return Err(SharedJournalDriverError::InvalidProfile);
        }
        // The admitted runtime owns its opaque state representation. Obtain
        // directory facts, including immutable install lineage, by executing
        // the canonical read-only ABI against the authenticated current state.
        // `InspectActors` is exclusive-after and the directory is ordered by
        // the actor's canonical bytes. Query from the immediate predecessor
        // with a one-record limit so one invocation never walks the global
        // directory (or lets unrelated actor count become backpressure).
        let after = exclusive_actor_predecessor(target);
        let outcome =
            self.inspect_clean_management(&crate::agent_sdk::ManagementRequest::InspectActors {
                after,
                limit: 1,
            })?;
        let crate::agent_sdk::RuntimeOutcome::Management(Ok(
            crate::agent_sdk::ManagementReply::Actors(page),
        )) = outcome
        else {
            return Err(SharedJournalDriverError::CrossStoreMismatch);
        };
        if page.validate().is_err()
            || page.entries.len() != 1
            || page.entries[0].entry.actor != target
        {
            return Err(SharedJournalDriverError::CrossStoreMismatch);
        }
        let actor = page.entries[0].clone();
        if actor.validate().is_err()
            || require_ready && actor.entry.suspended
            || actor
                .entry
                .validate_for_profile(descriptor.identity.profile)
                .is_err()
        {
            return Err(SharedJournalDriverError::CrossStoreMismatch);
        }

        let resolver = self.store.catalog_blob_resolver()?;
        let legacy_ref = |reference: &crate::agent_sdk::BlobRef| BlobRef {
            hash: Hash(reference.hash.0),
            len: reference.len,
        };
        let load = |reference: &crate::agent_sdk::BlobRef| {
            resolver
                .load_catalog(&legacy_ref(reference))
                .map_err(SharedJournalDriverError::Store)?
                .ok_or(SharedJournalDriverError::CrossStoreMismatch)
        };
        let package_bytes = load(&actor.entry.package)?;
        let package = super::package_admission::admit_actor_package(&package_bytes)
            .map_err(|_| SharedJournalDriverError::CrossStoreMismatch)?;
        let schema_bytes = load(&actor.entry.agent_schema)?;
        let policy_bytes = load(&actor.entry.method_policy)?;
        let installation_data = actor
            .entry
            .installation_data
            .as_ref()
            .map(|reference| {
                load(reference).map(|bytes| crate::agent_sdk::RuntimeBlob {
                    reference: reference.clone(),
                    bytes,
                })
            })
            .transpose()?;
        let parsed_schema = crate::agent_sdk::schema::decode(&schema_bytes)
            .map_err(|_| SharedJournalDriverError::CrossStoreMismatch)?;
        if package.package_ref() != &actor.entry.package
            || package.deployment() != actor.entry.deployment
            || package.program() != actor.entry.program
            || package.manifest().state_lane_schema != actor.entry.agent_schema
            || package.manifest().method_policy != actor.entry.method_policy
            || package.state_lane_schema_bytes() != schema_bytes
            || package.method_policy_bytes() != policy_bytes
            || package
                .envelope()
                .constructor_abi()
                .map_err(|_| SharedJournalDriverError::CrossStoreMismatch)?
                != actor.entry.constructor_abi
            || parsed_schema
                .state_layout_hash()
                .map_err(|_| SharedJournalDriverError::CrossStoreMismatch)?
                != actor.entry.state_layout
            || parsed_schema.lanes() != actor.entry.lanes
            || parsed_schema.requires_installation_data() != actor.entry.installation_data.is_some()
            || installation_data
                .as_ref()
                .map(|blob| crate::agent_sdk::BlobRef::of_bytes(&blob.bytes))
                != actor.entry.installation_data
            || !package
                .requirements()
                .supported_by(descriptor.identity.profile)
            || !descriptor
                .runtime_contract
                .supports(package.manifest().contract)
            || !descriptor.capabilities.satisfies(package.requirements())
        {
            return Err(SharedJournalDriverError::CrossStoreMismatch);
        }
        let program_bytes = package.program_bytes().to_vec();
        let observed_slot = self.executor.current_logical_slot()?;
        let install_request = actor.install_request;
        Ok(super::invocation_preparation::PhysicalInvocationMaterial {
            descriptor,
            actor,
            install_request,
            producer: package.producer(),
            contract: package.manifest().contract,
            requirements: package.requirements(),
            root_provenance: false,
            observed_slot,
            program: crate::agent_sdk::RuntimeBlob {
                reference: crate::agent_sdk::BlobRef::of_bytes(&program_bytes),
                bytes: program_bytes,
            },
            schema: crate::agent_sdk::RuntimeBlob {
                reference: crate::agent_sdk::BlobRef::of_bytes(&schema_bytes),
                bytes: schema_bytes,
            },
            policies: crate::agent_sdk::RuntimeBlob {
                reference: crate::agent_sdk::BlobRef::of_bytes(&policy_bytes),
                bytes: policy_bytes,
            },
            installation_data,
        })
    }

    pub(crate) fn active_route(
        &self,
    ) -> Result<super::shared_raft::AgentRouteKey, SharedJournalDriverError> {
        super::shared_raft::AgentRouteKey::new(
            self.ledger.generation().space(),
            self.ledger.generation().agent(),
            self.ledger.generation().genesis(),
            self.ledger.generation().admission(),
            self.ledger.active_committee()?.id(),
        )
        .map_err(|_| SharedJournalDriverError::WrongReplica)
    }

    pub(crate) fn active_committee(
        &self,
    ) -> Result<super::genesis::AgentReplicaCommittee, SharedJournalDriverError> {
        Ok(self.ledger.active_committee()?)
    }

    pub(crate) fn network_committee_state(
        &self,
    ) -> Result<super::shared_raft::AgentNetworkCommitteeState, SharedJournalDriverError> {
        Ok(self.ledger.network_committee_state()?)
    }

    pub(crate) fn engine_lanes(&self) -> Result<super::LaneSet, SharedJournalDriverError> {
        if self.executor.seeded_clean_descriptor().is_some() {
            return self
                .executor
                .clean_installed_actor_lanes(
                    self.materialization.runtime(),
                    self.materialization.state(),
                )
                .map_err(Into::into);
        }
        let state = super::wire::decode_standard_runtime_state(self.materialization.state())
            .map_err(|_| SharedJournalDriverError::InvalidProfile)?;
        let mut lanes = super::LaneSet::NONE;
        for actor in state.actors {
            lanes = lanes.union(actor.record.entry.lanes);
        }
        Ok(lanes)
    }

    pub(crate) fn merge_roots(&self) -> Result<Vec<[u8; 32]>, SharedJournalDriverError> {
        let frontier = self
            .store
            .get::<super::journal::MergeFrontier>(self.materialization.merge_frontier())?
            .ok_or(SharedJournalDriverError::CrossStoreMismatch)?;
        Ok(frontier
            .events
            .iter()
            .map(|event| *event.as_bytes())
            .collect())
    }

    pub(crate) fn merge_event_bytes(
        &self,
        event: super::journal::MergeEventId,
    ) -> Result<Option<Vec<u8>>, SharedJournalDriverError> {
        Ok(self
            .store
            .get::<MergeEvent>(event)?
            .map(|event| event.encode()))
    }

    pub(crate) fn merge_object(
        &self,
        id: super::journal::MergeEventId,
    ) -> Result<SharedMergeObject, SharedJournalDriverError> {
        let Some(event) = self.store.get::<MergeEvent>(id)? else {
            return Ok(SharedMergeObject::Missing);
        };
        if event.id() != id || event.validate().is_err() {
            return Err(SharedJournalDriverError::CrossStoreMismatch);
        }
        let bytes = event.encode();
        Ok(if self.materialization.contains_merge(id) {
            SharedMergeObject::Published(bytes)
        } else {
            SharedMergeObject::Staged(bytes)
        })
    }

    /// Persist one independently authenticated immutable Merge object without
    /// moving journal heads. This is the crash-safe anti-entropy staging
    /// boundary: full causal replay and publication remain in `import_merge`.
    pub(crate) fn stage_merge(
        &mut self,
        event: &MergeEvent,
    ) -> Result<bool, SharedJournalDriverError> {
        let active = self.ledger.active_committee()?;
        if event.validate().is_err()
            || event.genesis != self.materialization.heads().genesis
            || event.committee != Some(active.id())
            || active.member_by_node(event.author).is_none()
            || !self.executor.verify_merge_event(event)?
        {
            return Err(SharedJournalDriverError::WrongReplica);
        }
        self.store.put(event).map_err(Into::into)
    }

    pub(crate) fn materialization(&self) -> &ReplayMaterialization {
        &self.materialization
    }

    pub(crate) fn latest_clean_management_disposition(
        &self,
    ) -> Result<Option<super::standard::StandardCleanManagementDisposition>, SharedJournalDriverError>
    {
        // The common projection comparator still accepts this legacy-named
        // value type, but its source is host-owned authenticated replay and
        // checkpoint evidence, never a decoded private runtime-state image.
        Ok(self
            .materialization
            .clean_management_evidence()
            .map(
                |evidence| super::standard::StandardCleanManagementDisposition {
                    authority: evidence.authority,
                    request: evidence.request,
                    epoch: evidence.epoch,
                    sequence: evidence.sequence,
                    observed_slot: evidence.observed_slot,
                    result: evidence.result.clone(),
                },
            ))
    }

    /// Return the number of durable Ordered records still required by an
    /// exact projection lifecycle when those records fit the authenticated
    /// composite replay budgets. Recovery first proves a retained positive
    /// Ack, then an exact terminal Invoke, so it reserves zero, one, or two
    /// records rather than pessimistically requiring a fresh pair.
    pub(crate) fn projection_admission_requirement(
        &self,
        work: &crate::agent_sdk::InvocationWork,
        authorization: &crate::agent_sdk::InvocationAuthorization,
        recovering: bool,
    ) -> Result<Option<usize>, SharedJournalDriverError> {
        let (required_entries, required_bytes) =
            self.projection_admission_delta(work, authorization, recovering)?;
        Ok(self
            .materialization
            .has_suffix_headroom(required_entries, required_bytes)
            .then_some(required_entries))
    }

    /// Exact remaining suffix cost of retiring two completed Linear management
    /// invocations. This is a capacity check, not a proposal/GC reservation.
    /// Unlike projection recovery, missing Linear evidence must never trigger
    /// speculative execution at a checkpoint boundary.
    pub(crate) fn management_retirement_admission_requirement(
        &self,
        envelopes: [&crate::agent_sdk::RuntimeWork; 2],
    ) -> Result<Option<usize>, SharedJournalDriverError> {
        self.management_retirement_set_admission_requirement(&envelopes)
    }

    /// Budget all recovered completed invocations together, not independently
    /// against the same remaining suffix. Callers must retain an admission/GC
    /// exclusion over the entire set until durable retirement completes.
    /// This does not authorize incomplete or prepared-but-unaccepted work.
    pub(crate) fn management_retirement_set_admission_requirement(
        &self,
        envelopes: &[&crate::agent_sdk::RuntimeWork],
    ) -> Result<Option<usize>, SharedJournalDriverError> {
        self.management_recovery_admission_requirement(&[], envelopes)
    }

    fn management_retirement_delta(
        &self,
        envelopes: &[&crate::agent_sdk::RuntimeWork],
        mut index: u64,
        mut parent: Option<super::journal::OrderedEntryId>,
    ) -> Result<(usize, usize), SharedJournalDriverError> {
        use crate::agent_sdk::{
            InvocationAuthorization, MethodMode, RuntimeExecutionContext, RuntimeOutcome,
            RuntimeWork,
        };
        // Every member must have its own retained invocation or positive ack
        // in this suffix. A larger set cannot be evidenced by that suffix.
        if envelopes.len() > super::replay::MAX_REPLAY_SUFFIX_ENTRIES {
            return Err(SharedJournalDriverError::CrossStoreMismatch);
        }
        let heads = self.materialization.heads();
        let mut seen = BTreeSet::new();
        let mut entries = 0usize;
        let mut bytes = 0usize;
        for &envelope in envelopes {
            let RuntimeWork::Invoke {
                context,
                state,
                invocation: work,
                authorization,
                observed_slot,
            } = envelope
            else {
                return Err(SharedJournalDriverError::CrossStoreMismatch);
            };
            if *context != RuntimeExecutionContext::Direct
                || *state != crate::agent_sdk::RuntimeState::default()
                || work.mode != MethodMode::Linear
                || !work.validate()
                || **authorization
                    != InvocationAuthorization::PublicPreflight(
                        crate::agent_sdk::PublicPreflight::for_work(work, *observed_slot),
                    )
                || !seen.insert(work.invocation)
            {
                return Err(SharedJournalDriverError::CrossStoreMismatch);
            }
            if self.retained_positive_clean_acknowledgement(work, authorization)? {
                continue;
            }
            let invoke = ReplayOperation::CleanInvoke {
                context: *context,
                work: (**work).clone(),
                authorization: (**authorization).clone(),
                observed_slot: *observed_slot,
            };
            let input =
                recent_clean_ordered_operation(&self.store, &self.materialization, &invoke)?
                    .ok_or(SharedJournalDriverError::CrossStoreMismatch)?;
            if !matches!(
                self.executor.clean_ordered_result(input),
                Some(RuntimeOutcome::Completed(Ok(_)))
            ) {
                return Err(SharedJournalDriverError::CrossStoreMismatch);
            }
            index = index
                .checked_add(1)
                .ok_or(SharedJournalDriverError::CrossStoreMismatch)?;
            let entry = OrderedEntry {
                genesis: heads.genesis,
                index,
                parent,
                merge_frontier: heads.merge_frontier,
                merge_seal: None,
                input: ReplayInput {
                    runtime: heads.runtime.clone(),
                    operation: ReplayOperation::CleanAcknowledge {
                        context: *context,
                        expected_live: None,
                        work: (**work).clone(),
                        authorization: (**authorization).clone(),
                    },
                },
            };
            entry
                .validate()
                .map_err(|_| SharedJournalDriverError::CrossStoreMismatch)?;
            bytes = bytes
                .checked_add(entry.encode().len())
                .ok_or(SharedJournalDriverError::CrossStoreMismatch)?;
            entries += 1;
            parent = Some(entry.id());
        }
        Ok((entries, bytes))
    }

    /// Joint suffix cost for anchored, terminal management invocations and
    /// their acknowledgements. No runtime execution or policy preview occurs.
    /// Anchors must have been durably captured before first dispatch; callers
    /// must exclude competing admission and drain Raft before using the result.
    pub(crate) fn management_pending_admission_requirement(
        &self,
        pending: &[(
            &super::clean_management_intent::ManagementJournalAnchor,
            &crate::agent_sdk::RuntimeWork,
        )],
    ) -> Result<Option<usize>, SharedJournalDriverError> {
        self.management_recovery_admission_requirement(pending, &[])
    }

    /// One prospective Ordered chain for incomplete invocations and completed
    /// results awaiting retirement. Independent per-set checks are insufficient
    /// because both consume the same suffix entry and byte budgets.
    pub(crate) fn management_recovery_admission_requirement(
        &self,
        pending: &[(
            &super::clean_management_intent::ManagementJournalAnchor,
            &crate::agent_sdk::RuntimeWork,
        )],
        retiring: &[&crate::agent_sdk::RuntimeWork],
    ) -> Result<Option<usize>, SharedJournalDriverError> {
        self.management_recovery_admission_with_headroom(pending, retiring, 0, 0)
    }

    /// Reserve a complete fresh two-invocation lifecycle before authorization.
    /// Finalization copies the authorization work, replacing only fixed-size
    /// identities, the origin with anonymous, and the bounded message. Budget
    /// the full message limit in addition to the original message, so no
    /// placeholder acknowledgement is treated as application evidence.
    pub(crate) fn management_initial_admission_requirement(
        &self,
        anchor: &super::clean_management_intent::ManagementJournalAnchor,
        envelope: &crate::agent_sdk::RuntimeWork,
    ) -> Result<Option<usize>, SharedJournalDriverError> {
        let crate::agent_sdk::RuntimeWork::Invoke {
            context,
            invocation,
            authorization,
            observed_slot,
            ..
        } = envelope
        else {
            return Err(SharedJournalDriverError::CrossStoreMismatch);
        };
        let heads = self.materialization.heads();
        let mut future_bytes = 0usize;
        for operation in [
            ReplayOperation::CleanInvoke {
                context: *context,
                work: (**invocation).clone(),
                authorization: (**authorization).clone(),
                observed_slot: *observed_slot,
            },
            ReplayOperation::CleanAcknowledge {
                context: *context,
                expected_live: None,
                work: (**invocation).clone(),
                authorization: (**authorization).clone(),
            },
        ] {
            let entry = OrderedEntry {
                genesis: heads.genesis,
                index: heads
                    .ordered_index
                    .checked_add(1)
                    .ok_or(SharedJournalDriverError::CrossStoreMismatch)?,
                parent: heads.ordered_head,
                merge_frontier: heads.merge_frontier,
                merge_seal: None,
                input: ReplayInput {
                    runtime: heads.runtime.clone(),
                    operation,
                },
            };
            // A currently absent parent may become a 32-byte hash. All other
            // framing uses the same fixed-width encoding as actual admission.
            future_bytes = future_bytes
                .checked_add(entry.encode().len())
                .and_then(|bytes| bytes.checked_add(crate::agent_sdk::MAX_INVOCATION_MESSAGE_BYTES))
                .and_then(|bytes| bytes.checked_add(32))
                .ok_or(SharedJournalDriverError::CrossStoreMismatch)?;
        }
        self.management_recovery_admission_with_headroom(
            &[(anchor, envelope)],
            &[],
            2,
            future_bytes,
        )
    }

    fn management_recovery_admission_with_headroom(
        &self,
        pending: &[(
            &super::clean_management_intent::ManagementJournalAnchor,
            &crate::agent_sdk::RuntimeWork,
        )],
        retiring: &[&crate::agent_sdk::RuntimeWork],
        future_entries: usize,
        future_bytes: usize,
    ) -> Result<Option<usize>, SharedJournalDriverError> {
        use crate::agent_sdk::{RuntimeOutcome, RuntimeWork};
        if pending
            .len()
            .checked_add(retiring.len())
            .is_none_or(|len| len > super::replay::MAX_REPLAY_SUFFIX_ENTRIES)
        {
            return Err(SharedJournalDriverError::CrossStoreMismatch);
        }
        let heads = self.materialization.heads();
        let mut index = heads.ordered_index;
        let mut parent = heads.ordered_head;
        let mut bytes = 0usize;
        let mut entries = 0usize;
        let mut seen = BTreeSet::new();
        for &(anchor, envelope) in pending {
            if anchor.genesis != heads.genesis
                || anchor.admission != heads.admission
                || anchor.runtime != heads.runtime.commitment()
            {
                return Err(SharedJournalDriverError::CrossStoreMismatch);
            }
            let RuntimeWork::Invoke {
                context,
                invocation: work,
                authorization,
                observed_slot,
                ..
            } = envelope
            else {
                return Err(SharedJournalDriverError::CrossStoreMismatch);
            };
            if !seen.insert(work.invocation) {
                return Err(SharedJournalDriverError::CrossStoreMismatch);
            }
            if self.retained_positive_clean_acknowledgement(work, authorization)? {
                let input = self
                    .management_denial_invocation_after(anchor.ordered, envelope)?
                    .ok_or(SharedJournalDriverError::CrossStoreMismatch)?;
                let Some(RuntimeOutcome::Completed(Ok(reply))) =
                    self.executor.clean_ordered_result(input)
                else {
                    return Err(SharedJournalDriverError::CrossStoreMismatch);
                };
                #[cfg(all(feature = "network", target_os = "linux"))]
                let admin_success =
                    super::clean_bootstrap::admin_dispatch::matches_successful_admin_reply(
                        anchor,
                        envelope,
                        &reply.reply,
                    );
                #[cfg(not(all(feature = "network", target_os = "linux")))]
                let admin_success = false;
                if reply.invocation != work.invocation
                    || reply.actor != work.actor
                    || reply.incarnation != work.incarnation
                    || reply.deployment != work.deployment
                    || reply.mode != work.mode
                    || reply.status != crate::agent_sdk::InvocationStatus::Done
                    || (!admin_success
                        && reply.reply
                            != crate::actors::codec::Encode::encode(
                                &crate::actors::value::Value::Bytes(Vec::new()),
                            ))
                {
                    return Err(SharedJournalDriverError::CrossStoreMismatch);
                }
                // A proven denial or exactly bound admin success may remain
                // pending after ACK while terminal evidence is persisted.
                // Other successes still require their separate lifecycle.
                continue;
            }
            let retained = self.management_invocation_after(anchor.ordered, envelope)?;
            let invoke = ReplayOperation::CleanInvoke {
                context: *context,
                work: (**work).clone(),
                authorization: (**authorization).clone(),
                observed_slot: *observed_slot,
            };
            // An anchor newer than a retained invocation cannot be used to
            // budget it as unseen. Later lifecycle steps already fail the
            // anchored walk; completed retirement uses its separate protocol.
            if recent_clean_ordered_operation(&self.store, &self.materialization, &invoke)?
                != retained
            {
                return Err(SharedJournalDriverError::CrossStoreMismatch);
            }
            if retained.is_none()
                && self.retained_positive_clean_acknowledgement(work, authorization)?
            {
                return Err(SharedJournalDriverError::CrossStoreMismatch);
            }
            if let Some(input) = retained {
                if !matches!(
                    self.executor.clean_ordered_result(input),
                    Some(RuntimeOutcome::Completed(Ok(_)))
                ) {
                    return Err(SharedJournalDriverError::CrossStoreMismatch);
                }
            }
            let acknowledgement = ReplayOperation::CleanAcknowledge {
                context: *context,
                expected_live: None,
                work: (**work).clone(),
                authorization: (**authorization).clone(),
            };
            for operation in retained
                .is_none()
                .then_some(invoke)
                .into_iter()
                .chain(core::iter::once(acknowledgement))
            {
                index = index
                    .checked_add(1)
                    .ok_or(SharedJournalDriverError::CrossStoreMismatch)?;
                let entry = OrderedEntry {
                    genesis: heads.genesis,
                    index,
                    parent,
                    merge_frontier: heads.merge_frontier,
                    merge_seal: None,
                    input: ReplayInput {
                        runtime: heads.runtime.clone(),
                        operation,
                    },
                };
                entry
                    .validate()
                    .map_err(|_| SharedJournalDriverError::CrossStoreMismatch)?;
                bytes = bytes
                    .checked_add(entry.encode().len())
                    .ok_or(SharedJournalDriverError::CrossStoreMismatch)?;
                entries += 1;
                parent = Some(entry.id());
            }
        }
        for &envelope in retiring {
            let RuntimeWork::Invoke { invocation, .. } = envelope else {
                return Err(SharedJournalDriverError::CrossStoreMismatch);
            };
            if !seen.insert(invocation.invocation) {
                return Err(SharedJournalDriverError::CrossStoreMismatch);
            }
        }
        let (retirement_entries, retirement_bytes) =
            self.management_retirement_delta(retiring, index, parent)?;
        let entries = entries
            .checked_add(retirement_entries)
            .and_then(|entries| entries.checked_add(future_entries))
            .ok_or(SharedJournalDriverError::CrossStoreMismatch)?;
        let bytes = bytes
            .checked_add(retirement_bytes)
            .and_then(|bytes| bytes.checked_add(future_bytes))
            .ok_or(SharedJournalDriverError::CrossStoreMismatch)?;
        Ok(self
            .materialization
            .has_suffix_headroom(entries, bytes)
            .then_some(entries))
    }

    /// Validate and encode the exact projection lifecycle delta independently
    /// of current suffix capacity. Checkpoint selection needs this count while
    /// the old authenticated suffix is deliberately full; ordinary admission
    /// still calls [`Self::projection_admission_requirement`] and therefore
    /// cannot bypass either replay budget.
    pub(crate) fn projection_admission_records(
        &self,
        work: &crate::agent_sdk::InvocationWork,
        authorization: &crate::agent_sdk::InvocationAuthorization,
        recovering: bool,
    ) -> Result<usize, SharedJournalDriverError> {
        self.projection_admission_delta(work, authorization, recovering)
            .map(|(entries, _)| entries)
    }

    fn projection_admission_delta(
        &self,
        work: &crate::agent_sdk::InvocationWork,
        authorization: &crate::agent_sdk::InvocationAuthorization,
        recovering: bool,
    ) -> Result<(usize, usize), SharedJournalDriverError> {
        if work.mode != crate::agent_sdk::MethodMode::Query || !authorization.matches_work(work) {
            return Err(SharedJournalDriverError::CrossStoreMismatch);
        }
        let crate::agent_sdk::InvocationAuthorization::PublicPreflight(preflight) = authorization
        else {
            return Err(SharedJournalDriverError::CrossStoreMismatch);
        };
        if recovering && self.retained_positive_clean_acknowledgement(work, authorization)? {
            return Ok((0, 0));
        }

        let invoke_operation = ReplayOperation::CleanInvoke {
            context: crate::agent_sdk::RuntimeExecutionContext::Direct,
            work: work.clone(),
            authorization: authorization.clone(),
            observed_slot: preflight.observed_slot,
        };
        let retained_invoke = if recovering {
            self.retained_terminal_projection_input(&invoke_operation)?
        } else {
            None
        };

        let heads = self.materialization.heads();
        let mut entries = Vec::with_capacity(if retained_invoke.is_some() { 1 } else { 2 });
        if retained_invoke.is_none() {
            let invoke = OrderedEntry {
                genesis: heads.genesis,
                index: heads
                    .ordered_index
                    .checked_add(1)
                    .ok_or(SharedJournalDriverError::CrossStoreMismatch)?,
                parent: heads.ordered_head,
                merge_frontier: heads.merge_frontier,
                merge_seal: None,
                input: ReplayInput {
                    runtime: heads.runtime.clone(),
                    operation: invoke_operation,
                },
            };
            invoke
                .validate()
                .map_err(|_| SharedJournalDriverError::CrossStoreMismatch)?;
            entries.push(invoke);
        }
        let (ack_index, ack_parent) = match entries.last() {
            Some(invoke) => (
                invoke
                    .index
                    .checked_add(1)
                    .ok_or(SharedJournalDriverError::CrossStoreMismatch)?,
                Some(invoke.id()),
            ),
            None => (
                heads
                    .ordered_index
                    .checked_add(1)
                    .ok_or(SharedJournalDriverError::CrossStoreMismatch)?,
                heads.ordered_head,
            ),
        };
        let acknowledgement = OrderedEntry {
            genesis: heads.genesis,
            index: ack_index,
            parent: ack_parent,
            merge_frontier: heads.merge_frontier,
            merge_seal: None,
            input: ReplayInput {
                runtime: heads.runtime.clone(),
                operation: ReplayOperation::CleanAcknowledge {
                    context: crate::agent_sdk::RuntimeExecutionContext::Direct,
                    expected_live: None,
                    work: work.clone(),
                    authorization: authorization.clone(),
                },
            },
        };
        acknowledgement
            .validate()
            .map_err(|_| SharedJournalDriverError::CrossStoreMismatch)?;
        entries.push(acknowledgement);
        let required_bytes = entries.iter().try_fold(0usize, |total, entry| {
            total
                .checked_add(entry.encode().len())
                .ok_or(SharedJournalDriverError::CrossStoreMismatch)
        })?;
        let required_entries = entries.len();
        Ok((required_entries, required_bytes))
    }

    fn retained_terminal_projection_input(
        &self,
        operation: &ReplayOperation,
    ) -> Result<Option<(ReplayInputId, crate::agent_sdk::RuntimeOutcome)>, SharedJournalDriverError>
    {
        let retained =
            recent_clean_ordered_operation(&self.store, &self.materialization, operation)?;
        if let Some(input) = retained {
            let outcome = self
                .executor
                .clean_ordered_result(input)
                .ok_or(SharedJournalDriverError::CrossStoreMismatch)?;
            if !matches!(outcome, crate::agent_sdk::RuntimeOutcome::Completed(_)) {
                return Err(SharedJournalDriverError::CrossStoreMismatch);
            }
            return Ok(Some((input, outcome)));
        }
        self.retained_terminal_projection_boundary(operation)
    }

    /// A certified checkpoint may make the exact pending Invoke its replay
    /// boundary. The boundary entry remains content-addressed, while Standard
    /// guest state retains the immutable clean result. Re-execute that exact
    /// read-only work without publication to recover the original outcome;
    /// no replacement Invoke record is appended.
    fn retained_terminal_projection_boundary(
        &self,
        operation: &ReplayOperation,
    ) -> Result<Option<(ReplayInputId, crate::agent_sdk::RuntimeOutcome)>, SharedJournalDriverError>
    {
        let boundary = self.materialization.replay_boundary();
        let Some(id) = boundary.head else {
            return Ok(None);
        };
        let entry = self
            .store
            .get::<OrderedEntry>(id)?
            .ok_or(SharedJournalDriverError::CrossStoreMismatch)?;
        if entry.id() != id
            || entry.index != boundary.index
            || entry.genesis != self.materialization.heads().genesis
        {
            return Err(SharedJournalDriverError::CrossStoreMismatch);
        }
        let (
            ReplayOperation::CleanInvoke {
                context: prior_context,
                work: prior_work,
                authorization: prior_authorization,
                ..
            },
            ReplayOperation::CleanInvoke {
                context,
                work,
                authorization,
                ..
            },
        ) = (&entry.input.operation, operation)
        else {
            return Ok(None);
        };
        if prior_context != context || prior_work != work || prior_authorization != authorization {
            return Ok(None);
        }
        // This fallback is exclusively the read-only projection protocol.
        // Persisted management dispatch also reaches this preparation path;
        // an exact Linear boundary is not authenticated retained-result
        // evidence and must not fall through to speculative execution.
        if work.mode != crate::agent_sdk::MethodMode::Query {
            return Err(SharedJournalDriverError::CrossStoreMismatch);
        }
        let outcome = self
            .executor
            .clean_invocation_terminal_outcome(
                &entry.input.operation,
                self.materialization.state(),
                self.materialization.runtime(),
            )?
            .ok_or(SharedJournalDriverError::CrossStoreMismatch)?;
        Ok(Some((entry.input.id(), outcome)))
    }

    pub(crate) fn retained_terminal_projection_invoke(
        &self,
        work: &crate::agent_sdk::InvocationWork,
        authorization: &crate::agent_sdk::InvocationAuthorization,
    ) -> Result<bool, SharedJournalDriverError> {
        let operation = ReplayOperation::CleanInvoke {
            context: crate::agent_sdk::RuntimeExecutionContext::Direct,
            work: work.clone(),
            authorization: authorization.clone(),
            observed_slot: 0,
        };
        Ok(self
            .retained_terminal_projection_input(&operation)?
            .is_some())
    }

    /// Prove that a fresh exact projection Invoke/Ack pair fits both
    /// authenticated composite replay budgets.
    pub(crate) fn projection_pair_fits(
        &self,
        work: &crate::agent_sdk::InvocationWork,
        authorization: &crate::agent_sdk::InvocationAuthorization,
    ) -> Result<bool, SharedJournalDriverError> {
        Ok(self
            .projection_admission_requirement(work, authorization, false)?
            .is_some())
    }

    /// Read-only proof that the exact pending projection lifecycle already
    /// reached a positive durable acknowledgement. This is used after a
    /// crash between committing Ack and clearing the bootstrap record; it
    /// never appends a replacement Invoke merely to rediscover the result.
    pub(crate) fn retained_positive_clean_acknowledgement(
        &self,
        work: &crate::agent_sdk::InvocationWork,
        authorization: &crate::agent_sdk::InvocationAuthorization,
    ) -> Result<bool, SharedJournalDriverError> {
        let operation = ReplayOperation::CleanAcknowledge {
            context: crate::agent_sdk::RuntimeExecutionContext::Direct,
            expected_live: None,
            work: work.clone(),
            authorization: authorization.clone(),
        };
        let Some(input) =
            recent_clean_ordered_operation(&self.store, &self.materialization, &operation)?
        else {
            return Ok(false);
        };
        match self.executor.clean_ordered_result(input) {
            Some(crate::agent_sdk::RuntimeOutcome::Acknowledged(Ok(acknowledged)))
                if acknowledged.invocation == work.invocation
                    && acknowledged.actor == work.actor
                    && acknowledged.incarnation == work.incarnation
                    && acknowledged.deployment == work.deployment
                    && acknowledged.mode == work.mode
                    && acknowledged.work == work.commitment()
                    && acknowledged.authorization == authorization.commitment() =>
            {
                Ok(true)
            }
            _ => Err(SharedJournalDriverError::CrossStoreMismatch),
        }
    }

    pub(crate) fn journal_position(
        &self,
    ) -> (
        super::journal::AgentJournalGenesisId,
        super::genesis::AgentGenesisAdmissionId,
        u64,
        Option<super::journal::OrderedEntryId>,
        super::journal::MergeFrontierId,
        super::journal::RuntimeBinding,
    ) {
        let heads = self.materialization.heads();
        (
            heads.genesis,
            heads.admission,
            heads.ordered_index,
            heads.ordered_head,
            heads.merge_frontier,
            heads.runtime.clone(),
        )
    }

    /// Read-only evidence for an exact management invocation after a retained
    /// pre-dispatch anchor. Absence is interval-scoped and is not authorization
    /// to dispatch; callers must independently verify and persist that anchor.
    /// This observes applied journal history, not an unapplied Raft tail. The
    /// coordinator must hold admission exclusion and drain a leader barrier
    /// before interpreting it as recovery evidence.
    pub(crate) fn management_invocation_after(
        &self,
        anchor: OrderedBase,
        envelope: &crate::agent_sdk::RuntimeWork,
    ) -> Result<Option<ReplayInputId>, SharedJournalDriverError> {
        self.management_invocation_after_with_denial_ack(anchor, envelope, false)
    }

    pub(crate) fn management_denial_invocation_after(
        &self,
        anchor: OrderedBase,
        envelope: &crate::agent_sdk::RuntimeWork,
    ) -> Result<Option<ReplayInputId>, SharedJournalDriverError> {
        self.management_invocation_after_with_denial_ack(anchor, envelope, true)
    }

    fn management_invocation_after_with_denial_ack(
        &self,
        anchor: OrderedBase,
        envelope: &crate::agent_sdk::RuntimeWork,
        denial: bool,
    ) -> Result<Option<ReplayInputId>, SharedJournalDriverError> {
        use crate::agent_sdk::{
            InvocationAuthorization, MethodMode, RuntimeExecutionContext, RuntimeState, RuntimeWork,
        };
        let RuntimeWork::Invoke {
            context,
            state,
            invocation,
            authorization,
            observed_slot,
        } = envelope
        else {
            return Err(SharedJournalDriverError::CrossStoreMismatch);
        };
        let binding = self.materialization.runtime();
        if *context != RuntimeExecutionContext::Direct
            || *state != RuntimeState::default()
            || invocation.mode != MethodMode::Linear
            || !invocation.validate()
            || invocation.space.0 != binding.space.0
            || invocation.agent.0 != binding.agent.0
            || invocation.runtime_deployment.0 != binding.deployment.0
            || **authorization
                != InvocationAuthorization::PublicPreflight(
                    crate::agent_sdk::PublicPreflight::for_work(invocation, *observed_slot),
                )
        {
            return Err(SharedJournalDriverError::CrossStoreMismatch);
        }
        let operation = ReplayOperation::CleanInvoke {
            context: *context,
            work: (**invocation).clone(),
            authorization: (**authorization).clone(),
            observed_slot: *observed_slot,
        };
        if denial {
            return super::local_journal_driver::clean_denial_operation_after(
                &self.store,
                &self.materialization,
                anchor,
                &operation,
            )
            .map_err(Into::into);
        }
        super::local_journal_driver::clean_ordered_operation_after(
            &self.store,
            &self.materialization,
            anchor,
            &ReplayOperation::CleanInvoke {
                context: *context,
                work: (**invocation).clone(),
                authorization: (**authorization).clone(),
                observed_slot: *observed_slot,
            },
        )
        .map_err(Into::into)
    }

    pub(crate) fn ledger(&self) -> &AgentRaftApplicationLedgerV2 {
        &self.ledger
    }

    fn clean_management_catalog(
        &self,
        descriptor: &crate::agent_sdk::AgentDescriptor,
        request: &crate::agent_sdk::ManagementRequest,
        artifacts: SdkManagementArtifacts<'_>,
    ) -> Result<Vec<RuntimeBlob>, SharedJournalDriverError> {
        if matches!(artifacts, SdkManagementArtifacts::None)
            && matches!(
                request,
                crate::agent_sdk::ManagementRequest::Install(_)
                    | crate::agent_sdk::ManagementRequest::UpgradeActor(_)
                    | crate::agent_sdk::ManagementRequest::UpgradeRuntime(_)
            )
        {
            self.executor
                .validate_clean_management_artifacts(descriptor, request)?;
            return Ok(Vec::new());
        }
        super::driver::validate_sdk_management_artifacts(descriptor, request, artifacts)
            .map_err(|_| SharedJournalDriverError::InvalidArtifactBatch)?;
        let runtime_blob = |bytes: Vec<u8>| RuntimeBlob {
            reference: BlobRef::of_bytes(&bytes),
            bytes,
        };
        let mut catalog = Vec::new();
        match (request, artifacts) {
            (
                crate::agent_sdk::ManagementRequest::Install(install),
                SdkManagementArtifacts::Actor(package),
            ) => {
                catalog.push(runtime_blob(package.exact_bytes().to_vec()));
                catalog.push(runtime_blob(package.state_lane_schema_bytes().to_vec()));
                catalog.push(runtime_blob(package.method_policy_bytes().to_vec()));
                if let Some(data) = &install.installation_data {
                    catalog.push(runtime_blob(data.bytes.clone()));
                }
            }
            (
                crate::agent_sdk::ManagementRequest::UpgradeActor(_),
                SdkManagementArtifacts::Actor(package),
            ) => {
                catalog.push(runtime_blob(package.exact_bytes().to_vec()));
                catalog.push(runtime_blob(package.state_lane_schema_bytes().to_vec()));
                catalog.push(runtime_blob(package.method_policy_bytes().to_vec()));
            }
            (
                crate::agent_sdk::ManagementRequest::UpgradeRuntime(_),
                SdkManagementArtifacts::Runtime(package),
            ) => catalog.push(runtime_blob(package.exact_bytes().to_vec())),
            (_, SdkManagementArtifacts::None) => {}
            _ => return Err(SharedJournalDriverError::InvalidArtifactBatch),
        }
        catalog.sort_by_key(|blob| blob.reference.hash);
        for pair in catalog.windows(2) {
            if pair[0].reference.hash == pair[1].reference.hash && pair[0] != pair[1] {
                return Err(SharedJournalDriverError::InvalidArtifactBatch);
            }
        }
        catalog.dedup();
        Ok(catalog)
    }

    fn stage_current_merge_seal(
        &mut self,
    ) -> Result<super::journal::MergeSealId, SharedJournalDriverError> {
        let heads = self.materialization.heads().clone();
        let merge_state = self.materialization.state().merge.clone();
        let state = BlobRef::of_bytes(&merge_state);
        self.store
            .put_blob(JournalBlobClass::LaneState, &state, &merge_state)?;
        let manifest = super::journal::LaneStateManifest {
            genesis: heads.genesis,
            runtime: heads.runtime.clone(),
            lane: PersistedLane::Merge,
            cursor: super::journal::LaneCursor::Merge {
                frontier: heads.merge_frontier,
            },
            state,
        };
        self.store.put(&manifest)?;
        let seal = super::journal::MergeSeal {
            genesis: heads.genesis,
            frontier: heads.merge_frontier,
            ordered_base: OrderedBase {
                index: heads.ordered_index,
                head: heads.ordered_head,
            },
            merge_state: manifest.id(),
        };
        self.store.put(&seal)?;
        Ok(seal.id())
    }

    /// Prepare the exact command sequence for one clean SDK management
    /// mutation. Artifact bytes are content-admitted first, but become journal
    /// catalog truth only when their chunk commands commit and apply. Only an
    /// exact request/receipt found in the bounded durable Ordered suffix may
    /// return its replay-derived result without another Raft slot.
    pub(crate) fn prepare_clean_management(
        &mut self,
        request: crate::agent_sdk::ManagementRequest,
        authority: crate::agent_sdk::authority::AuthorityReceipt,
        artifacts: SdkManagementArtifacts<'_>,
    ) -> Result<PreparedCleanManagement, SharedJournalDriverError> {
        if matches!(
            request,
            crate::agent_sdk::ManagementRequest::Create(_)
                | crate::agent_sdk::ManagementRequest::InspectActors { .. }
                | crate::agent_sdk::ManagementRequest::InspectResources
                | crate::agent_sdk::ManagementRequest::ChangeReplicas { .. }
                | crate::agent_sdk::ManagementRequest::PrivateControl { .. }
        ) {
            return Err(SharedJournalDriverError::CrossStoreMismatch);
        }
        let runtime = self.materialization.runtime().clone();
        let descriptor = self.executor.trusted_current_clean_descriptor(&runtime)?;
        let catalog = self.clean_management_catalog(&descriptor, &request, artifacts)?;
        if let Some((input, observed_slot)) = recent_clean_management_operation(
            &self.store,
            &self.materialization,
            &request,
            &authority,
        )? {
            let outcome = self
                .executor
                .clean_management_result(input)
                .ok_or(SharedJournalDriverError::CrossStoreMismatch)?;
            return Ok(PreparedCleanManagement::Retained {
                outcome,
                observed_slot,
            });
        }
        let observed_slot = self.executor.current_logical_slot()?;
        let input = ReplayInput {
            runtime: runtime.clone(),
            operation: ReplayOperation::CleanManage {
                request: request.clone(),
                authority: authority.clone(),
                observed_slot,
            },
        };
        input
            .validate()
            .map_err(|_| SharedJournalDriverError::CrossStoreMismatch)?;
        let preview = self.executor.preview_clean_management(
            &runtime,
            self.materialization.state(),
            &request,
            &authority,
            observed_slot,
            false,
        )?;
        let preview_state = RuntimeState {
            control: preview.state.control,
            linear: preview.state.linear,
            merge: preview.state.merge,
            local: preview.state.local,
        };
        if preview_state == *self.materialization.state()
            && matches!(
                &preview.outcome,
                crate::agent_sdk::RuntimeOutcome::Management(Err(_))
            )
        {
            return Ok(PreparedCleanManagement::Denied {
                outcome: preview.outcome,
                observed_slot,
            });
        }
        let input_id = input.id();
        let route = self.active_route()?;
        let mut commands = Vec::new();
        let artifact_batch = if catalog.is_empty() {
            None
        } else {
            let manifest = ArtifactBatchManifest::new(
                route,
                catalog.iter().map(|blob| blob.reference.clone()).collect(),
            )
            .map_err(|_| SharedJournalDriverError::InvalidArtifactBatch)?;
            let batch = manifest.id();
            for (artifact_index, blob) in catalog.iter().enumerate() {
                for (chunk_index, bytes) in blob.bytes.chunks(ARTIFACT_CHUNK_DATA_BYTES).enumerate()
                {
                    let offset = chunk_index
                        .checked_mul(ARTIFACT_CHUNK_DATA_BYTES)
                        .and_then(|offset| u64::try_from(offset).ok())
                        .ok_or(SharedJournalDriverError::InvalidArtifactBatch)?;
                    let chunk = ArtifactChunk::new(
                        manifest.clone(),
                        u32::try_from(artifact_index)
                            .map_err(|_| SharedJournalDriverError::InvalidArtifactBatch)?,
                        offset,
                        bytes.to_vec(),
                    )
                    .map_err(|_| SharedJournalDriverError::InvalidArtifactBatch)?;
                    if !self.artifacts.contains(&chunk)? {
                        commands.push(AgentRaftCommand::ArtifactChunk(chunk).encode());
                    }
                }
            }
            Some(batch)
        };
        let merge_seal = self.stage_current_merge_seal()?;
        let heads = self.materialization.heads();
        let entry = OrderedEntry {
            genesis: heads.genesis,
            index: heads
                .ordered_index
                .checked_add(1)
                .ok_or(SharedJournalDriverError::CrossStoreMismatch)?,
            parent: heads.ordered_head,
            merge_frontier: heads.merge_frontier,
            merge_seal: Some(merge_seal),
            input,
        };
        let ordered = AgentRaftCommand::Ordered {
            route,
            artifact_batch,
            entry,
        };
        ordered
            .validate()
            .map_err(|_| SharedJournalDriverError::CrossStoreMismatch)?;
        commands.push(ordered.encode());
        Ok(PreparedCleanManagement::Proposal {
            input: input_id,
            observed_slot,
            commands,
        })
    }

    pub(crate) fn inspect_clean_management(
        &self,
        request: &crate::agent_sdk::ManagementRequest,
    ) -> Result<crate::agent_sdk::RuntimeOutcome, SharedJournalDriverError> {
        self.executor
            .inspect_clean_management(
                self.materialization.runtime(),
                self.materialization.state(),
                request,
            )
            .map_err(Into::into)
    }

    pub(crate) fn clean_state_commitment(
        &self,
    ) -> Result<crate::agent_sdk::Hash, SharedJournalDriverError> {
        super::journal::system_genesis_post_create_state_commitment(self.materialization.state())
            .map(|commitment| crate::agent_sdk::Hash(commitment.0))
            .map_err(|_| SharedJournalDriverError::CrossStoreMismatch)
    }

    fn clean_operation_input(
        &self,
        request: CleanInvocationReplayRequest,
    ) -> Result<ReplayInput, SharedJournalDriverError> {
        let observed_slot = self.executor.current_logical_slot()?;
        self.clean_operation_input_at(request, observed_slot)
    }

    fn clean_operation_input_at(
        &self,
        request: CleanInvocationReplayRequest,
        observed_slot: u64,
    ) -> Result<ReplayInput, SharedJournalDriverError> {
        let heads = self.materialization.heads();
        let input = ReplayInput {
            runtime: heads.runtime.clone(),
            operation: request.into_operation(observed_slot),
        };
        input
            .validate()
            .map_err(|_| SharedJournalDriverError::CrossStoreMismatch)?;
        self.executor.verify_clean_operation_input(
            &input.operation,
            self.materialization.state(),
            &input.runtime,
        )?;
        Ok(input)
    }

    /// Construct the exact clean ordered command which a live Raft worker
    /// may propose. Authority and complete SDK work are verified before the
    /// proposal bytes exist; replay repeats verification before publication.
    pub(crate) fn prepare_clean_ordered(
        &self,
        work: crate::agent_sdk::InvocationWork,
        authorization: crate::agent_sdk::InvocationAuthorization,
    ) -> Result<PreparedCleanOrdered, SharedJournalDriverError> {
        self.prepare_clean_ordered_operation(CleanInvocationReplayRequest::Invoke {
            context: crate::agent_sdk::RuntimeExecutionContext::Direct,
            work,
            authorization,
        })
    }

    pub(crate) fn prepare_clean_ordered_operation(
        &self,
        request: CleanInvocationReplayRequest,
    ) -> Result<PreparedCleanOrdered, SharedJournalDriverError> {
        self.prepare_clean_ordered_operation_with_policy(request, false, None)
    }

    /// Locally generated bootstrap work receives its unsigned preflight at
    /// journal admission. A retry recovers the original acceptance from the
    /// authenticated journal; it never refreshes a retained authorization.
    pub(crate) fn prepare_bootstrap_invocation(
        &self,
        request: CleanInvocationReplayRequest,
    ) -> Result<PreparedCleanOrdered, SharedJournalDriverError> {
        use crate::agent_sdk::{InvocationAuthorization, PublicPreflight, RuntimeExecutionContext};
        let CleanInvocationReplayRequest::Invoke {
            context: RuntimeExecutionContext::Direct,
            work,
            authorization: InvocationAuthorization::PublicPreflight(preflight),
        } = request
        else {
            return Err(SharedJournalDriverError::CrossStoreMismatch);
        };
        if !preflight.matches_work(&work) || work.mode != crate::agent_sdk::MethodMode::Linear {
            return Err(SharedJournalDriverError::CrossStoreMismatch);
        }
        let mut cursor = self.materialization.heads().ordered_head;
        let mut retained = None;
        // Bootstrap contains only a handful of operations. Fail closed if its
        // history unexpectedly grows beyond the normal retained-result bound.
        for _ in 0..1_024 {
            let Some(id) = cursor else { break };
            if self.materialization.replay_boundary().head == Some(id) {
                break;
            }
            let entry = self
                .store
                .get::<OrderedEntry>(id)?
                .ok_or(SharedJournalDriverError::CrossStoreMismatch)?;
            if entry.id() != id || entry.genesis != self.materialization.heads().genesis {
                return Err(SharedJournalDriverError::CrossStoreMismatch);
            }
            if let ReplayOperation::CleanInvoke {
                context,
                work: previous,
                authorization,
                ..
            } = &entry.input.operation
                && previous.invocation == work.invocation
            {
                if *context != RuntimeExecutionContext::Direct
                    || previous != &work
                    || !matches!(authorization, InvocationAuthorization::PublicPreflight(value) if value.matches_work(&work))
                {
                    return Err(SharedJournalDriverError::CrossStoreMismatch);
                }
                retained = Some(authorization.clone());
                break;
            }
            cursor = entry.parent;
        }
        let authorization = match retained {
            Some(authorization) => authorization,
            None => {
                if cursor.is_some() && cursor != self.materialization.replay_boundary().head {
                    return Err(SharedJournalDriverError::CrossStoreMismatch);
                }
                InvocationAuthorization::PublicPreflight(PublicPreflight::for_work(
                    &work,
                    self.executor.current_logical_slot()?,
                ))
            }
        };
        let InvocationAuthorization::PublicPreflight(preflight) = &authorization else {
            unreachable!()
        };
        let observed_slot = preflight.observed_slot;
        self.prepare_clean_ordered_operation_with_policy(
            CleanInvocationReplayRequest::Invoke {
                context: RuntimeExecutionContext::Direct,
                work,
                authorization,
            },
            false,
            Some(observed_slot),
        )
    }

    pub(crate) fn prepare_terminal_clean_ordered_operation(
        &self,
        request: CleanInvocationReplayRequest,
    ) -> Result<PreparedCleanOrdered, SharedJournalDriverError> {
        self.prepare_clean_ordered_operation_with_policy(request, true, None)
    }

    /// Internal management work whose complete preflight envelope is already
    /// durable in its lifecycle intent. The intent's observation is immutable;
    /// neither dispatch latency nor reopening may turn it into a new admission.
    /// This is not an ingress API or a projection-pair capacity reservation.
    pub(crate) fn prepare_persisted_management_invocation(
        &self,
        request: CleanInvocationReplayRequest,
    ) -> Result<PreparedCleanOrdered, SharedJournalDriverError> {
        let CleanInvocationReplayRequest::Invoke {
            context: crate::agent_sdk::RuntimeExecutionContext::Direct,
            work,
            authorization: crate::agent_sdk::InvocationAuthorization::PublicPreflight(preflight),
        } = &request
        else {
            return Err(SharedJournalDriverError::CrossStoreMismatch);
        };
        if work.mode != crate::agent_sdk::MethodMode::Linear
            || !preflight.matches_work(work)
            || preflight.observed_slot > self.executor.current_logical_slot()?
        {
            return Err(SharedJournalDriverError::CrossStoreMismatch);
        }
        let observed_slot = preflight.observed_slot;
        self.prepare_clean_ordered_operation_with_policy(request, true, Some(observed_slot))
    }

    /// Prepare only the exact persisted system-authority projection work
    /// protected by a projection-pair admission. Its PublicPreflight slot was
    /// sampled before the pending bootstrap record became durable, so recovery
    /// must reuse that accepted slot rather than resampling the trust clock.
    pub(crate) fn prepare_reserved_projection_operation(
        &self,
        request: CleanInvocationReplayRequest,
        terminal_only: bool,
    ) -> Result<PreparedCleanOrdered, SharedJournalDriverError> {
        let work = request.work();
        let crate::agent_sdk::InvocationAuthorization::PublicPreflight(preflight) =
            request.authorization()
        else {
            return Err(SharedJournalDriverError::CrossStoreMismatch);
        };
        let accepted_observed_slot = preflight.observed_slot;
        if work.mode != crate::agent_sdk::MethodMode::Query
            || !request
                .authorization()
                .matches_invoke(work, accepted_observed_slot)
        {
            return Err(SharedJournalDriverError::CrossStoreMismatch);
        }
        self.prepare_clean_ordered_operation_with_policy(
            request,
            terminal_only,
            Some(accepted_observed_slot),
        )
    }

    fn prepare_clean_ordered_operation_with_policy(
        &self,
        request: CleanInvocationReplayRequest,
        terminal_only: bool,
        accepted_observed_slot: Option<u64>,
    ) -> Result<PreparedCleanOrdered, SharedJournalDriverError> {
        // Retry identity excludes the trusted observation slot. The real slot
        // is sampled exactly once below only when a new operation is built.
        let operation = request.clone().into_operation(0);
        if let Some(input) =
            recent_clean_ordered_operation(&self.store, &self.materialization, &operation)?
        {
            let outcome = self
                .executor
                .clean_ordered_result(input)
                .ok_or(SharedJournalDriverError::CrossStoreMismatch)?;
            if terminal_only && !matches!(outcome, crate::agent_sdk::RuntimeOutcome::Completed(_)) {
                return Err(SharedJournalDriverError::CrossStoreMismatch);
            }
            return Ok(PreparedCleanOrdered::Retained { input, outcome });
        }
        if accepted_observed_slot.is_some()
            && terminal_only
            && let Some((input, outcome)) =
                self.retained_terminal_projection_boundary(&operation)?
        {
            return Ok(PreparedCleanOrdered::Retained { input, outcome });
        }
        let input = match accepted_observed_slot {
            Some(observed_slot) => self.clean_operation_input_at(request, observed_slot)?,
            None => self.clean_operation_input(request)?,
        };
        if !matches!(
            input.persisted_lane(),
            PersistedLane::Control | PersistedLane::Linear
        ) {
            return Err(SharedJournalDriverError::CrossStoreMismatch);
        }
        if terminal_only
            && !self.executor.clean_invocation_is_terminal(
                &input.operation,
                self.materialization.state(),
                &input.runtime,
            )?
        {
            return Err(SharedJournalDriverError::CrossStoreMismatch);
        }
        let heads = self.materialization.heads();
        let entry = OrderedEntry {
            genesis: heads.genesis,
            index: heads
                .ordered_index
                .checked_add(1)
                .ok_or(SharedJournalDriverError::CrossStoreMismatch)?,
            parent: heads.ordered_head,
            merge_frontier: heads.merge_frontier,
            merge_seal: None,
            input,
        };
        entry
            .validate()
            .map_err(|_| SharedJournalDriverError::CrossStoreMismatch)?;
        let input = entry.input.id();
        let payload = AgentRaftCommand::Ordered {
            route: self.active_route()?,
            artifact_batch: None,
            entry,
        }
        .encode();
        AgentRaftCommand::decode(&payload)
            .map_err(|_| SharedJournalDriverError::CrossStoreMismatch)?;
        Ok(PreparedCleanOrdered::Proposal { input, payload })
    }

    /// Publish one clean Local-lane invocation on this exact physical
    /// replica. This never enters Raft; a routed request mutates only the
    /// receiving replica's Local lane.
    pub(crate) fn apply_clean_local(
        &mut self,
        work: crate::agent_sdk::InvocationWork,
        authorization: crate::agent_sdk::InvocationAuthorization,
    ) -> Result<crate::agent_sdk::RuntimeOutcome, SharedJournalDriverError> {
        self.apply_clean_local_operation(CleanInvocationReplayRequest::Invoke {
            context: crate::agent_sdk::RuntimeExecutionContext::Direct,
            work,
            authorization,
        })
    }

    pub(crate) fn apply_clean_local_operation(
        &mut self,
        request: CleanInvocationReplayRequest,
    ) -> Result<crate::agent_sdk::RuntimeOutcome, SharedJournalDriverError> {
        let retry = request.clone().into_operation(0);
        if let Some(input) =
            recent_clean_local_operation(&self.store, &self.materialization, &retry)?
        {
            return self
                .executor
                .clean_ordered_result(input)
                .ok_or(SharedJournalDriverError::CrossStoreMismatch);
        }
        let input = self.clean_operation_input(request)?;
        if input.persisted_lane() != PersistedLane::Local {
            return Err(SharedJournalDriverError::CrossStoreMismatch);
        }
        let input_id = input.id();
        let heads = self.materialization.heads();
        let entry = LocalEntry {
            genesis: heads.genesis,
            node: heads.node,
            revision: heads
                .local_revision
                .checked_add(1)
                .ok_or(SharedJournalDriverError::CrossStoreMismatch)?,
            parent: heads.local_head,
            ordered_base: OrderedBase {
                index: heads.ordered_index,
                head: heads.ordered_head,
            },
            merge_frontier: heads.merge_frontier,
            input,
        };
        match prepare_local(
            &mut self.store,
            &mut self.executor,
            &self.materialization,
            &entry,
        )? {
            ReplayPreparation::Ready(prepared) => {
                let (_, successor, _) = prepared.publish()?;
                self.materialization = successor;
            }
            ReplayPreparation::AlreadyCommitted(_) => {
                return Err(SharedJournalDriverError::CrossStoreMismatch);
            }
        }
        self.executor
            .take_clean_invocation_result(input_id)
            .ok_or(SharedJournalDriverError::CrossStoreMismatch)
    }

    /// Publish one locally authored clean Merge invocation. The full active
    /// committee authenticates membership, while the local replica key signs
    /// the canonical event and replay verifies it again.
    pub(crate) fn apply_clean_merge(
        &mut self,
        work: crate::agent_sdk::InvocationWork,
        authorization: crate::agent_sdk::InvocationAuthorization,
    ) -> Result<crate::agent_sdk::RuntimeOutcome, SharedJournalDriverError> {
        self.apply_clean_merge_operation(CleanInvocationReplayRequest::Invoke {
            context: crate::agent_sdk::RuntimeExecutionContext::Direct,
            work,
            authorization,
        })
    }

    pub(crate) fn apply_clean_merge_operation(
        &mut self,
        request: CleanInvocationReplayRequest,
    ) -> Result<crate::agent_sdk::RuntimeOutcome, SharedJournalDriverError> {
        let retry = request.clone().into_operation(0);
        if let Some(input) =
            recent_clean_merge_operation(&self.store, &self.materialization, &retry)?
        {
            return self
                .executor
                .clean_ordered_result(input)
                .ok_or(SharedJournalDriverError::CrossStoreMismatch);
        }
        let input = self.clean_operation_input(request)?;
        if input.persisted_lane() != PersistedLane::Merge {
            return Err(SharedJournalDriverError::CrossStoreMismatch);
        }
        let input_id = input.id();
        let heads = self.materialization.heads();
        let frontier = self
            .store
            .get::<MergeFrontier>(heads.merge_frontier)?
            .ok_or(SharedJournalDriverError::CrossStoreMismatch)?;
        if frontier.id() != heads.merge_frontier || frontier.genesis != heads.genesis {
            return Err(SharedJournalDriverError::CrossStoreMismatch);
        }
        let mut maximum = 0_u64;
        for parent in &frontier.events {
            let event = self
                .store
                .get::<MergeEvent>(*parent)?
                .ok_or(SharedJournalDriverError::CrossStoreMismatch)?;
            if event.id() != *parent || event.genesis != heads.genesis {
                return Err(SharedJournalDriverError::CrossStoreMismatch);
            }
            maximum = maximum.max(event.causal_height);
        }
        let causal_height = maximum
            .checked_add(1)
            .ok_or(SharedJournalDriverError::CrossStoreMismatch)?;
        let mut event = MergeEvent {
            genesis: heads.genesis,
            author: self.local_node,
            committee: Some(self.ledger.active_committee()?.id()),
            ordered_base: OrderedBase {
                index: heads.ordered_index,
                head: heads.ordered_head,
            },
            causal_height,
            parents: frontier.events,
            input,
            signature: Vec::new(),
        };
        self.executor.sign_shared_merge_event(&mut event)?;
        match prepare_merge(
            &mut self.store,
            &mut self.executor,
            &NoPrunedOrderedBases,
            &self.materialization,
            &event,
        )? {
            ReplayPreparation::Ready(prepared) => {
                let (_, successor, _) = prepared.publish()?;
                self.materialization = successor;
            }
            ReplayPreparation::AlreadyCommitted(_) => {
                return Err(SharedJournalDriverError::CrossStoreMismatch);
            }
        }
        self.executor
            .take_clean_invocation_result(input_id)
            .ok_or(SharedJournalDriverError::CrossStoreMismatch)
    }

    #[cfg(all(test, feature = "network"))]
    pub(crate) fn publish_merge_for_test(
        &mut self,
        operation: ReplayOperation,
    ) -> Result<super::journal::MergeEventId, SharedJournalDriverError> {
        let heads = self.materialization.heads();
        let input = ReplayInput {
            runtime: heads.runtime.clone(),
            operation,
        };
        input
            .validate()
            .map_err(|_| SharedJournalDriverError::CrossStoreMismatch)?;
        if input.persisted_lane() != PersistedLane::Merge {
            return Err(SharedJournalDriverError::CrossStoreMismatch);
        }
        let frontier = self
            .store
            .get::<MergeFrontier>(heads.merge_frontier)?
            .ok_or(SharedJournalDriverError::CrossStoreMismatch)?;
        if frontier.id() != heads.merge_frontier || frontier.genesis != heads.genesis {
            return Err(SharedJournalDriverError::CrossStoreMismatch);
        }
        let mut maximum = 0_u64;
        for parent in &frontier.events {
            let event = self
                .store
                .get::<MergeEvent>(*parent)?
                .ok_or(SharedJournalDriverError::CrossStoreMismatch)?;
            if event.id() != *parent || event.genesis != heads.genesis {
                return Err(SharedJournalDriverError::CrossStoreMismatch);
            }
            maximum = maximum.max(event.causal_height);
        }
        let mut event = MergeEvent {
            genesis: heads.genesis,
            author: self.local_node,
            committee: Some(self.ledger.active_committee()?.id()),
            ordered_base: OrderedBase {
                index: heads.ordered_index,
                head: heads.ordered_head,
            },
            causal_height: maximum
                .checked_add(1)
                .ok_or(SharedJournalDriverError::CrossStoreMismatch)?,
            parents: frontier.events,
            input,
            signature: Vec::new(),
        };
        self.executor.sign_shared_merge_event(&mut event)?;
        let id = event.id();
        match prepare_merge(
            &mut self.store,
            &mut self.executor,
            &NoPrunedOrderedBases,
            &self.materialization,
            &event,
        )? {
            ReplayPreparation::Ready(prepared) => {
                let (_, successor, _) = prepared.publish()?;
                self.materialization = successor;
            }
            ReplayPreparation::AlreadyCommitted(_) => {
                return Err(SharedJournalDriverError::CrossStoreMismatch);
            }
        }
        Ok(id)
    }

    pub(crate) fn take_clean_ordered_result(
        &mut self,
        input: ReplayInputId,
    ) -> Result<crate::agent_sdk::RuntimeOutcome, SharedJournalDriverError> {
        self.try_take_clean_ordered_result(input)?
            .ok_or(SharedJournalDriverError::CrossStoreMismatch)
    }

    /// Poll the bounded synchronous response handoff. Absence is not journal
    /// corruption: the relevant committed entry can be on another apply
    /// thread, or the caller may already have consumed its response. Exact
    /// management retries use the separate bounded replay-derived cache.
    pub(crate) fn try_take_clean_ordered_result(
        &mut self,
        input: ReplayInputId,
    ) -> Result<Option<crate::agent_sdk::RuntimeOutcome>, SharedJournalDriverError> {
        Ok(self.executor.take_clean_invocation_result(input))
    }

    /// Build one real seal-only Ordered command from the currently
    /// materialized filesystem journal, then append its canonical bytes to
    /// the physical Raft log. Test-only because production log admission is
    /// owned by the not-yet-attached Agent transport coordinator.
    #[cfg(test)]
    pub(crate) fn append_ordered_for_test(
        &mut self,
        term: u64,
        operation: super::journal::ReplayOperation,
    ) -> Result<u64, SharedJournalDriverError> {
        let heads = self.materialization.heads().clone();
        let merge_state = self.materialization.state().merge.clone();
        let state = BlobRef::of_bytes(&merge_state);
        self.store
            .put_blob(JournalBlobClass::LaneState, &state, &merge_state)?;
        let manifest = super::journal::LaneStateManifest {
            genesis: heads.genesis,
            runtime: heads.runtime.clone(),
            lane: super::journal::PersistedLane::Merge,
            cursor: super::journal::LaneCursor::Merge {
                frontier: heads.merge_frontier,
            },
            state,
        };
        self.store.put(&manifest)?;
        let seal = super::journal::MergeSeal {
            genesis: heads.genesis,
            frontier: heads.merge_frontier,
            ordered_base: super::journal::OrderedBase {
                index: heads.ordered_index,
                head: heads.ordered_head,
            },
            merge_state: manifest.id(),
        };
        self.store.put(&seal)?;
        let entry = super::journal::OrderedEntry {
            genesis: heads.genesis,
            index: heads
                .ordered_index
                .checked_add(1)
                .ok_or(SharedJournalDriverError::CrossStoreMismatch)?,
            parent: heads.ordered_head,
            merge_frontier: heads.merge_frontier,
            merge_seal: Some(seal.id()),
            input: super::journal::ReplayInput {
                runtime: heads.runtime,
                operation,
            },
        };
        let command = AgentRaftCommand::Ordered {
            route: self.active_route()?,
            artifact_batch: None,
            entry,
        };
        self.ledger
            .append_committed_for_test(
                term,
                &vos_raft::EntryKind::Data {
                    payload: command.encode(),
                },
            )
            .map_err(SharedJournalDriverError::from)
    }

    pub(crate) fn capacity(&self) -> Result<(u64, u64, bool), SharedJournalDriverError> {
        self.ledger.capacity().map_err(Into::into)
    }

    fn snapshot_boundary_claim(&self) -> Result<OrderedCommitClaim, SharedJournalDriverError> {
        let heads = self.materialization.heads();
        let entry = heads.ordered_head.ok_or(SharedJournalDriverError::Ledger(
            AgentRaftApplicationErrorV2::SnapshotBoundaryRequired,
        ))?;
        let matches_heads = |claim: &OrderedCommitClaim| {
            claim.ordered().head == Some(entry)
                && claim.ordered().index == heads.ordered_index
                && claim.genesis() == heads.genesis
                && claim.admission() == heads.admission
                && claim.runtime() == &heads.runtime
        };
        // Prefer the current verified snapshot when no new logical Ordered
        // transition followed it. Its physical foundation may already be a
        // later leader no-op, and using an older still-retained binding would
        // make the next no-op-only compaction appear to skip its base.
        if let Some(installed) = self.ledger.current_snapshot()?
            && matches_heads(installed.claim.ordered())
        {
            return Ok(installed.claim.ordered().clone());
        }
        let binding = self
            .store
            .shared_ordered_commit(entry)?
            .ok_or(SharedJournalDriverError::CrossStoreMismatch)?;
        let claim = binding.claim();
        if !matches_heads(claim) {
            return Err(SharedJournalDriverError::CrossStoreMismatch);
        }
        Ok(claim.clone())
    }

    fn prepare_snapshot_candidate(
        &mut self,
    ) -> Result<
        (
            super::replay::PreparedSharedCheckpoint,
            SharedAgentSnapshotClaim,
        ),
        SharedJournalDriverError,
    > {
        let ordered = self.snapshot_boundary_claim()?;
        let context = self.ledger.snapshot_context(&ordered)?;
        let plan = prepare_shared_checkpoint(&mut self.store, &self.materialization)
            .map_err(|_| SharedJournalDriverError::CrossStoreMismatch)?;
        let (control, linear, merge, local) = plan
            .lane_roots()
            .ok_or(SharedJournalDriverError::CrossStoreMismatch)?;
        let next = plan.next_heads();
        let claim = SharedAgentSnapshotClaim::new(
            context.ordered,
            context.active_committee,
            context.authority_epoch,
            Hash(*self.store.instance_id().as_bytes()),
            context.boundary_payload_commitment,
            context.ordered_successor,
            plan.predecessor_heads(),
            next.id(),
            plan.checkpoint().manifest().id(),
            next.node,
            control,
            linear,
            merge,
            local,
            next.ordered_invocations,
            next.merge_invocations,
            next.local_invocations,
            plan.checkpoint().manifest().artifacts,
            context.retired_audit_root,
            context.committee_evidence_root,
            context.previous_snapshot,
        )?;
        plan.validate_claim(&claim)?;
        Ok((plan, claim))
    }

    /// Return the exact unsigned checkpoint claim. This may stage immutable
    /// proof-compaction objects, but no lane blob, journal head, audit row, or
    /// Raft scalar is changed until a voter-majority certificate is returned.
    pub(crate) fn snapshot_candidate(
        &mut self,
    ) -> Result<SharedAgentSnapshotClaim, SharedJournalDriverError> {
        self.prepare_snapshot_candidate().map(|(_, claim)| claim)
    }

    /// Publish and install one exact Agent-specific snapshot. The journal CAS
    /// precedes the atomic Raft/audit retirement; restart recognizes the
    /// journal-first intermediate state and accepts only the same certificate.
    pub(crate) fn install_snapshot(
        &mut self,
        certificate: &SharedAgentSnapshotCertificate,
    ) -> Result<InstalledAgentRaftSnapshotV2, SharedJournalDriverError> {
        if let Some(installed) = self.ledger.current_snapshot()? {
            if installed.certificate_commitment == certificate.commitment() {
                if installed.claim != *certificate.claim() {
                    return Err(SharedJournalDriverError::CrossStoreMismatch);
                }
                validate_published_shared_checkpoint(
                    &self.store,
                    &self.materialization,
                    certificate.claim(),
                )
                .map_err(|_| SharedJournalDriverError::CrossStoreMismatch)?;
                return self
                    .ledger
                    .install_snapshot(certificate, None)
                    .map_err(Into::into);
            }
            // Let the ledger's authenticated snapshot cursor reject lower or
            // equal divergent certificates before preparing or publishing
            // any journal checkpoint material.
            if certificate.claim().raft_index() <= installed.claim.raft_index() {
                return self
                    .ledger
                    .install_snapshot(certificate, None)
                    .map_err(Into::into);
            }
        }

        let logical_ordered = self.snapshot_boundary_claim()?;
        let verified = if self.materialization.heads_id() == certificate.claim().journal_heads() {
            let context = self.ledger.snapshot_context(&logical_ordered)?;
            validate_published_shared_checkpoint(
                &self.store,
                &self.materialization,
                certificate.claim(),
            )
            .map_err(|_| SharedJournalDriverError::CrossStoreMismatch)?;
            let claim = certificate.claim();
            if claim.ordered() != &context.ordered
                || claim.active_committee() != &context.active_committee
                || claim.authority_epoch() != context.authority_epoch
                || claim.journal_store().0 != *self.store.instance_id().as_bytes()
                || claim.boundary_payload_commitment() != context.boundary_payload_commitment
                || claim.ordered_successor() != context.ordered_successor
                || claim.retired_audit_root() != context.retired_audit_root
                || claim.committee_evidence_root() != context.committee_evidence_root
                || claim.previous_snapshot() != context.previous_snapshot
            {
                return Err(SharedJournalDriverError::CrossStoreMismatch);
            }
            certificate.verify(&context.active_committee, claim)?
        } else {
            let (plan, expected) = self.prepare_snapshot_candidate()?;
            let active = expected.active_committee().clone();
            let verified = certificate.verify(&active, &expected)?;
            let successor = plan.publish_shared(&mut self.store, &verified)?;
            self.materialization = successor;
            verified
        };
        if verified.claim() != certificate.claim() {
            return Err(SharedJournalDriverError::CrossStoreMismatch);
        }
        self.ledger
            .install_snapshot(certificate, Some(&logical_ordered))
            .map_err(Into::into)
    }

    pub(crate) fn current_snapshot(
        &self,
    ) -> Result<Option<InstalledAgentRaftSnapshotV2>, SharedJournalDriverError> {
        self.ledger.current_snapshot().map_err(Into::into)
    }

    pub(crate) fn compact_snapshot(
        &mut self,
        maximum_binding_unlinks: usize,
        gc_limits: GcLimits,
    ) -> Result<SharedSnapshotCompactionOutcome, SharedJournalDriverError> {
        if maximum_binding_unlinks == 0 {
            return Err(JournalStoreError::LimitExceeded.into());
        }
        // Validate every caller-selected budget before retiring authority
        // bindings. A rejected pass must leave both namespaces untouched.
        validate_gc_limits(gc_limits)?;
        let snapshot = self
            .ledger
            .current_snapshot()?
            .ok_or(SharedJournalDriverError::Ledger(
                AgentRaftApplicationErrorV2::SnapshotBoundaryRequired,
            ))?;
        validate_published_shared_checkpoint(&self.store, &self.materialization, &snapshot.claim)
            .map_err(|_| SharedJournalDriverError::CrossStoreMismatch)?;
        let bindings = self
            .store
            .retire_shared_ordered_commits(&snapshot, maximum_binding_unlinks)?;
        let journal = if bindings.remaining == 0 {
            Some(
                self.store
                    .collect_garbage(self.materialization.heads_id(), gc_limits)?,
            )
        } else {
            None
        };
        Ok(SharedSnapshotCompactionOutcome {
            bindings_removed: bindings.removed,
            bindings_remaining: bindings.remaining,
            journal,
        })
    }

    /// Apply one authenticated causal event without crossing Raft. Replay
    /// enforces the exact Merge lane, author signature, parent closure, and
    /// ordered-base dependency before the journal head moves.
    pub(crate) fn import_merge(
        &mut self,
        event: &MergeEvent,
    ) -> Result<SharedPhysicalApplyOutcome, SharedJournalDriverError> {
        let active = self.ledger.active_committee()?;
        if event.committee != Some(active.id()) || active.member_by_node(event.author).is_none() {
            return Err(SharedJournalDriverError::WrongReplica);
        }
        let index = self.materialization.heads().ordered_index;
        match prepare_merge(
            &mut self.store,
            &mut self.executor,
            &NoPrunedOrderedBases,
            &self.materialization,
            event,
        )? {
            ReplayPreparation::Ready(prepared) => {
                let (_, successor, _) = prepared.publish()?;
                self.materialization = successor;
                Ok(SharedPhysicalApplyOutcome::Applied { index })
            }
            ReplayPreparation::AlreadyCommitted(_) => {
                Ok(SharedPhysicalApplyOutcome::Duplicate { index })
            }
        }
    }

    #[cfg(test)]
    pub(crate) fn stage_next_ordered_before_heads_for_test(
        &mut self,
        include_anchor: bool,
    ) -> Result<(), SharedJournalDriverError> {
        let Some(CommittedSharedRaftSlot::Command(command)) = self.ledger.next_committed_slot()?
        else {
            panic!("fixture requires an Ordered command");
        };
        let reserved = self.ledger.reserve_command_application(&command)?;
        let committee = self.ledger.active_committee()?;
        let committed = CommittedSharedOrdered::from_reserved_raft_application(
            reserved,
            &committee,
            None,
        )
        .expect("valid fixture reservation");
        match prepare_shared_ordered(
            &mut self.store,
            &mut self.executor,
            &NoPrunedOrderedBases,
            &self.materialization,
            committed,
        )? {
            SharedReplayPreparation::Ready(prepared) => {
                prepared.stage_binding_before_heads_for_test(include_anchor)?;
                Ok(())
            }
            SharedReplayPreparation::AlreadyCommitted { .. } => panic!("fixture already published"),
        }
    }

    #[cfg(test)]
    pub(crate) fn assert_staged_binding_requires_exact_reservation_for_test(&self) {
        for mutation in 0..7 {
            let mut audit = self.ledger.journal_audit().unwrap();
            if mutation == 0 {
                audit.pending_ordered = None;
            } else {
                let pending = audit.pending_ordered.as_mut().unwrap();
                match mutation {
                    1 => pending.ordered_index += 1,
                    2 => pending.ordered_parent = Some(pending.entry),
                    3 => pending.index += 1,
                    4 => pending.term += 1,
                    5 => pending.command_commitment = Hash::ZERO,
                    6 => pending.entry = super::journal::OrderedEntryId([0xa5; 32]),
                    _ => unreachable!(),
                }
            }
            assert!(
                matches!(
                    reconcile_journal_ledger(
                        &self.store,
                        &self.materialization,
                        self.ledger.journal_store(),
                        &audit,
                    ),
                    Err(SharedJournalDriverError::CrossStoreMismatch)
                ),
                "accepted altered pending reservation {mutation}"
            );
        }
    }

    /// Drain exactly one committed physical Raft slot through its typed
    /// storage/replay boundary.
    pub(crate) fn apply_next(
        &mut self,
    ) -> Result<SharedPhysicalApplyOutcome, SharedJournalDriverError> {
        let Some(slot) = self.ledger.next_committed_slot()? else {
            return Ok(SharedPhysicalApplyOutcome::Idle);
        };
        let index = slot.index();
        let outcome = match &slot {
            CommittedSharedRaftSlot::LeaderNoop(_) | CommittedSharedRaftSlot::Configuration(_) => {
                let outcome = match self.ledger.apply_foundation_slot(&slot)? {
                    AgentRaftFoundationApplyOutcomeV2::Applied(_) => {
                        SharedPhysicalApplyOutcome::Applied { index }
                    }
                    AgentRaftFoundationApplyOutcomeV2::Duplicate(_) => {
                        SharedPhysicalApplyOutcome::Duplicate { index }
                    }
                };
                self.executor
                    .replace_shared_committees(self.ledger.committee_history()?);
                outcome
            }
            CommittedSharedRaftSlot::Command(command)
                if matches!(
                    command.entry().command(),
                    AgentRaftCommand::PrepareCommitteeChange(_)
                ) =>
            {
                let outcome = match self.ledger.apply_foundation_slot(&slot)? {
                    AgentRaftFoundationApplyOutcomeV2::Applied(_) => {
                        SharedPhysicalApplyOutcome::Applied { index }
                    }
                    AgentRaftFoundationApplyOutcomeV2::Duplicate(_) => {
                        SharedPhysicalApplyOutcome::Duplicate { index }
                    }
                };
                self.executor
                    .replace_shared_committees(self.ledger.committee_history()?);
                outcome
            }
            CommittedSharedRaftSlot::Command(command) => {
                let reserved = self.ledger.reserve_command_application(command)?;
                match command.entry().command() {
                    AgentRaftCommand::ArtifactChunk(chunk) => {
                        self.artifacts.stage(chunk)?;
                        let completion = self.ledger.complete_artifact_command(
                            &reserved,
                            AgentRaftAuditDisposition::ArtifactChunkStored {
                                batch: chunk.batch(),
                                artifact: chunk.artifact().hash,
                                offset: chunk.offset(),
                                chunk: chunk.commitment(),
                            },
                        )?;
                        command_outcome(completion, index)
                    }
                    AgentRaftCommand::ArtifactAbort { route, batch } => {
                        self.artifacts.abort(*route, *batch)?;
                        let completion = self.ledger.complete_artifact_command(
                            &reserved,
                            AgentRaftAuditDisposition::ArtifactBatchAborted { batch: *batch },
                        )?;
                        command_outcome(completion, index)
                    }
                    AgentRaftCommand::Ordered {
                        route,
                        artifact_batch,
                        entry,
                    } => {
                        let expected_clean_artifacts =
                            clean_management_artifact_references(&entry.input.operation);
                        if let Some(expected) = &expected_clean_artifacts {
                            if expected.is_empty() && artifact_batch.is_some() {
                                return Err(SharedJournalDriverError::InvalidArtifactBatch);
                            }
                            if !expected.is_empty() && artifact_batch.is_none() {
                                for reference in expected {
                                    let bytes = self
                                        .store
                                        .load_blob(JournalBlobClass::CatalogArtifact, reference)?
                                        .ok_or(SharedJournalDriverError::InvalidArtifactBatch)?;
                                    if BlobRef::of_bytes(&bytes) != *reference {
                                        return Err(SharedJournalDriverError::InvalidArtifactBatch);
                                    }
                                }
                            }
                        }
                        let validated_batch = if let Some(batch) = artifact_batch {
                            let (manifest, blobs) = self.artifacts.load_complete(*route, *batch)?;
                            validate_complete_batch(*route, *batch, &manifest, &blobs)?;
                            if expected_clean_artifacts
                                .as_ref()
                                .is_some_and(|expected| manifest.artifacts() != expected)
                            {
                                return Err(SharedJournalDriverError::InvalidArtifactBatch);
                            }
                            for blob in blobs {
                                self.store.put_blob(
                                    JournalBlobClass::CatalogArtifact,
                                    &blob.reference,
                                    &blob.bytes,
                                )?;
                            }
                            self.executor
                                .replace_resolver(self.store.catalog_blob_resolver()?);
                            Some(ValidatedSharedArtifactBatch::new(*route, *batch))
                        } else {
                            None
                        };
                        let committee = self.ledger.active_committee()?;
                        let committed = CommittedSharedOrdered::from_reserved_raft_application(
                            reserved,
                            &committee,
                            validated_batch,
                        )
                        .map_err(|error| {
                            SharedJournalDriverError::Replay(
                                error
                                    .map_source(|never| match never {})
                                    .map_executor(|never| match never {}),
                            )
                        })?;
                        let published = match prepare_shared_ordered(
                            &mut self.store,
                            &mut self.executor,
                            &NoPrunedOrderedBases,
                            &self.materialization,
                            committed,
                        )? {
                            SharedReplayPreparation::Ready(prepared) => {
                                let (_, successor, _, publication) = prepared.publish_shared()?;
                                self.materialization = successor;
                                publication
                            }
                            SharedReplayPreparation::AlreadyCommitted { publication, .. } => {
                                publication
                            }
                        };
                        let completion = self.ledger.anchor_applied_ordered(published)?;
                        if let Some(batch) = artifact_batch {
                            self.artifacts.retire(*route, *batch)?;
                        }
                        command_outcome(completion, index)
                    }
                    AgentRaftCommand::PrepareCommitteeChange(_) => unreachable!(),
                }
            }
        };
        Ok(outcome)
    }
}

#[cfg(target_os = "linux")]
impl
    SharedJournalAgentDriver<super::journal_store::FileAgentJournalStore, FileSharedArtifactStager>
{
    pub(crate) fn portable_checkpoint(
        &self,
        limits: PortableJournalLimits,
    ) -> Result<PortableJournalCheckpoint, SharedJournalDriverError> {
        export_portable_journal_checkpoint(&self.store, limits).map_err(Into::into)
    }

    pub(crate) fn portable_snapshot_candidate(
        &self,
        genesis_intent: Hash,
        root_pins: Hash,
        limits: PortableJournalLimits,
    ) -> Result<
        (PortableJournalCheckpoint, SharedAgentPortableSnapshotClaim),
        SharedJournalDriverError,
    > {
        let installed = self
            .ledger
            .current_snapshot()?
            .ok_or(SharedJournalDriverError::Ledger(
                AgentRaftApplicationErrorV2::SnapshotBoundaryRequired,
            ))?;
        validate_published_shared_checkpoint(&self.store, &self.materialization, &installed.claim)
            .map_err(|_| SharedJournalDriverError::CrossStoreMismatch)?;
        let image = self.portable_checkpoint(limits)?;
        if image.heads().id() != installed.claim.journal_heads() {
            return Err(SharedJournalDriverError::CrossStoreMismatch);
        }
        let physical = installed.claim;
        let claim = SharedAgentPortableSnapshotClaim::new(
            genesis_intent,
            root_pins,
            physical.ordered().clone(),
            physical.active_committee().clone(),
            physical.authority_epoch(),
            physical.ordered_successor(),
            physical.checkpoint_predecessor(),
            physical.journal_heads(),
            physical.checkpoint(),
            physical.local_node(),
            physical.control(),
            physical.linear(),
            physical.merge(),
            physical.local(),
            physical.ordered_invocations(),
            physical.merge_invocations(),
            physical.local_invocations(),
            physical.artifacts(),
            image.commitment(),
        )?;
        validate_portable_materialization(&self.store, &self.materialization, &claim)?;
        Ok((image, claim))
    }

    pub(crate) fn restore_portable_checkpoint(
        &mut self,
        image: &PortableJournalCheckpoint,
        maximum_index_nodes: usize,
        certificate: &SharedAgentPortableSnapshotCertificate,
        verified: &VerifiedSharedAgentPortableSnapshot,
    ) -> Result<(), SharedJournalDriverError> {
        if verified.claim() != certificate.claim()
            || verified.certificate_commitment() != certificate.commitment()
            || image.commitment() != certificate.claim().journal_image()
            || image.heads().id() != certificate.claim().journal_heads()
        {
            return Err(SharedJournalDriverError::CrossStoreMismatch);
        }
        self.store
            .install_portable_checkpoint(image, maximum_index_nodes)?;
        self.materialization =
            materialize_current(&mut self.store, &mut self.executor, &NoPrunedOrderedBases)?;
        validate_portable_materialization(&self.store, &self.materialization, certificate.claim())?;
        let installed = self
            .ledger
            .restore_portable_snapshot(certificate, verified)?;
        validate_published_shared_checkpoint(&self.store, &self.materialization, &installed.claim)
            .map_err(|_| SharedJournalDriverError::CrossStoreMismatch)?;
        let audit = self.ledger.journal_audit()?;
        reconcile_journal_ledger(
            &self.store,
            &self.materialization,
            self.ledger.journal_store(),
            &audit,
        )
    }

    #[cfg(test)]
    pub(crate) fn stage_portable_checkpoint_for_test(
        &mut self,
        image: &PortableJournalCheckpoint,
        maximum_index_nodes: usize,
    ) -> Result<(), SharedJournalDriverError> {
        self.store
            .stage_portable_checkpoint_for_test(image, maximum_index_nodes)?;
        Ok(())
    }

    #[cfg(test)]
    pub(crate) fn journal_store_instance_for_test(
        &self,
    ) -> super::shared_raft::JournalStoreInstanceId {
        self.store.instance_id()
    }

    pub(crate) fn create_shared_unexposed<T: super::replay::ReplaySealedOrdinaryGenesis>(
        mut store: super::journal_store::FileAgentJournalStore,
        artifacts: FileSharedArtifactStager,
        ledger: AgentRaftApplicationLedgerV2,
        sealed: &T,
        catalog: &[RuntimeBlob],
        trust: Arc<dyn AgentTrustProvider>,
        merge: Arc<dyn LocalMergeAuthenticator>,
    ) -> Result<Self, SharedJournalDriverError> {
        for blob in catalog {
            store.put_blob(
                JournalBlobClass::CatalogArtifact,
                &blob.reference,
                &blob.bytes,
            )?;
        }
        store.initialize_shared(sealed)?;
        store.sync_unexposed_generation()?;
        Self::open(store, artifacts, ledger, trust, merge)
    }

    pub(crate) fn open_shared_unexposed(
        store: super::journal_store::FileAgentJournalStore,
        artifacts: FileSharedArtifactStager,
        ledger: AgentRaftApplicationLedgerV2,
        trust: Arc<dyn AgentTrustProvider>,
        merge: Arc<dyn LocalMergeAuthenticator>,
    ) -> Result<Self, SharedJournalDriverError> {
        Self::open(store, artifacts, ledger, trust, merge)
    }

    pub(crate) fn commit_exposure<T: super::replay::ReplaySealedOrdinaryGenesis>(
        &mut self,
        sealed: &T,
        intent: crate::service::Hash,
    ) -> Result<(), SharedJournalDriverError> {
        self.store.commit_shared_exposure(sealed, intent)?;
        Ok(())
    }
}

fn command_outcome(
    outcome: super::shared_raft::AgentRaftCommandApplyOutcomeV2,
    index: u64,
) -> SharedPhysicalApplyOutcome {
    match outcome {
        super::shared_raft::AgentRaftCommandApplyOutcomeV2::Applied(_) => {
            SharedPhysicalApplyOutcome::Applied { index }
        }
        super::shared_raft::AgentRaftCommandApplyOutcomeV2::Duplicate(_) => {
            SharedPhysicalApplyOutcome::Duplicate { index }
        }
    }
}

/// Reconstruct a portable image in an independent in-memory journal before
/// any destination namespace is created. This repeats package trust and exact
/// replay over the same typed store API used on restart.
pub(crate) fn preflight_portable_checkpoint<T: super::replay::ReplaySealedOrdinaryGenesis>(
    sealed: &T,
    catalog: &[RuntimeBlob],
    image: &PortableJournalCheckpoint,
    claim: &super::shared_commit::SharedAgentPortableSnapshotClaim,
    maximum_index_nodes: usize,
    trust: Arc<dyn AgentTrustProvider>,
    merge: Arc<dyn LocalMergeAuthenticator>,
    committee: super::genesis::AgentReplicaCommittee,
) -> Result<ReplayMaterialization, SharedJournalDriverError> {
    if image.commitment() != claim.journal_image() || image.heads().id() != claim.journal_heads() {
        return Err(SharedJournalDriverError::CrossStoreMismatch);
    }
    let mut store = MemoryAgentJournalStore::new(sealed.genesis().runtime().agent, merge.node())?;
    for blob in catalog {
        store.put_blob(
            JournalBlobClass::CatalogArtifact,
            &blob.reference,
            &blob.bytes,
        )?;
    }
    store.initialize_shared(sealed)?;
    store.install_portable_checkpoint(image, maximum_index_nodes)?;
    let resolver = store.catalog_blob_resolver()?;
    let mut executor =
        StandardLocalReplayExecutor::new_shared(resolver, trust, merge, vec![committee]);
    let materialization = materialize_current(&mut store, &mut executor, &NoPrunedOrderedBases)?;
    validate_portable_materialization(&store, &materialization, claim)?;
    Ok(materialization)
}

fn validate_portable_materialization<S>(
    store: &S,
    materialization: &ReplayMaterialization,
    claim: &super::shared_commit::SharedAgentPortableSnapshotClaim,
) -> Result<(), SharedJournalDriverError>
where
    S: AgentJournalStore + ReplaySource<Error = JournalStoreError>,
{
    let commitment = claim.commitment();
    let validation_claim = SharedAgentSnapshotClaim::new(
        claim.ordered().clone(),
        claim.active_committee().clone(),
        claim.authority_epoch(),
        Hash::digest(
            b"vos/agent/shared/portable-validation/store/v1",
            &[&commitment.0],
        ),
        Hash::digest(
            b"vos/agent/shared/portable-validation/foundation/v1",
            &[&commitment.0],
        ),
        claim.ordered_successor(),
        claim.checkpoint_predecessor(),
        claim.journal_heads(),
        claim.checkpoint(),
        claim.local_node(),
        claim.control(),
        claim.linear(),
        claim.merge(),
        claim.local(),
        claim.ordered_invocations(),
        claim.merge_invocations(),
        claim.local_invocations(),
        claim.artifacts(),
        Hash::digest(
            b"vos/agent/shared/portable-validation/retired/v1",
            &[&commitment.0],
        ),
        Hash::digest(
            b"vos/agent/shared/portable-validation/committee/v1",
            &[&commitment.0],
        ),
        None,
    )?;
    validate_published_shared_checkpoint(store, materialization, &validation_claim)
        .map_err(|_| SharedJournalDriverError::CrossStoreMismatch)
}

fn clean_management_artifact_references(operation: &ReplayOperation) -> Option<Vec<BlobRef>> {
    let ReplayOperation::CleanManage { request, .. } = operation else {
        return None;
    };
    let clean = |reference: &crate::agent_sdk::BlobRef| BlobRef {
        hash: Hash(reference.hash.0),
        len: reference.len,
    };
    let mut artifacts = match request {
        crate::agent_sdk::ManagementRequest::Install(install) => {
            let mut artifacts = vec![
                clean(&install.package),
                clean(&install.agent_schema),
                clean(&install.method_policy),
            ];
            if let Some(data) = &install.installation_data {
                artifacts.push(clean(&data.reference));
            }
            artifacts
        }
        crate::agent_sdk::ManagementRequest::UpgradeActor(upgrade) => vec![
            clean(&upgrade.package),
            clean(&upgrade.agent_schema),
            clean(&upgrade.method_policy),
        ],
        crate::agent_sdk::ManagementRequest::UpgradeRuntime(upgrade) => {
            vec![clean(&upgrade.package)]
        }
        crate::agent_sdk::ManagementRequest::Create(_)
        | crate::agent_sdk::ManagementRequest::InspectActors { .. }
        | crate::agent_sdk::ManagementRequest::InspectResources
        | crate::agent_sdk::ManagementRequest::Suspend { .. }
        | crate::agent_sdk::ManagementRequest::Resume { .. }
        | crate::agent_sdk::ManagementRequest::RemoveLeaf { .. }
        | crate::agent_sdk::ManagementRequest::ChangeReplicas { .. }
        | crate::agent_sdk::ManagementRequest::PrivateControl { .. } => Vec::new(),
    };
    artifacts.sort_by_key(|artifact| artifact.hash);
    artifacts.dedup();
    Some(artifacts)
}

fn validate_complete_batch(
    route: super::shared_raft::AgentRouteKey,
    batch: ArtifactBatchId,
    manifest: &ArtifactBatchManifest,
    blobs: &[RuntimeBlob],
) -> Result<(), SharedJournalDriverError> {
    manifest
        .validate()
        .map_err(|_| SharedJournalDriverError::InvalidArtifactBatch)?;
    if manifest.route() != route
        || manifest.id() != batch
        || blobs.len() != manifest.artifacts().len()
    {
        return Err(SharedJournalDriverError::InvalidArtifactBatch);
    }
    for (blob, reference) in blobs.iter().zip(manifest.artifacts()) {
        if &blob.reference != reference
            || !reference.matches(&blob.bytes)
            || reference != &BlobRef::of_bytes(&blob.bytes)
        {
            return Err(SharedJournalDriverError::InvalidArtifactBatch);
        }
    }
    Ok(())
}

fn reconcile_journal_ledger<S: AgentJournalStore + SharedOrderedCommitStore>(
    store: &S,
    materialization: &ReplayMaterialization,
    journal_store: super::shared_raft::JournalStoreInstanceId,
    audit: &AgentRaftJournalAuditV2,
) -> Result<(), SharedJournalDriverError> {
    let heads = materialization.heads();
    let snapshot_base = audit
        .snapshot
        .as_ref()
        .map(|snapshot| snapshot.claim.ordered().ordered());
    tracing::debug!(
        ordered_index = heads.ordered_index,
        snapshot_index = snapshot_base.map_or(0, |base| base.index),
        anchors = audit.ordered.len(),
        pending = audit.pending_ordered.is_some(),
        "Reconciling Shared journal ordered bindings"
    );
    let mut chain = BTreeMap::new();
    let mut next = heads.ordered_head;
    let mut expected_index = heads.ordered_index;
    while expected_index > snapshot_base.map_or(0, |base| base.index) {
        let entry_id = next.ok_or(SharedJournalDriverError::CrossStoreMismatch)?;
        if chain.len() == super::shared_raft::MAX_AGENT_RAFT_ORDERED_EVIDENCE_ENTRIES {
            return Err(SharedJournalDriverError::CrossStoreMismatch);
        }
        let entry = store
            .get::<super::journal::OrderedEntry>(entry_id)?
            .ok_or(SharedJournalDriverError::CrossStoreMismatch)?;
        if entry.id() != entry_id
            || entry.genesis != heads.genesis
            || entry.index != expected_index
            || chain.insert(entry_id, entry.clone()).is_some()
        {
            return Err(SharedJournalDriverError::CrossStoreMismatch);
        }
        next = entry.parent;
        expected_index = expected_index
            .checked_sub(1)
            .ok_or(SharedJournalDriverError::CrossStoreMismatch)?;
    }
    let expected_parent = snapshot_base.and_then(|base| base.head);
    if expected_index != snapshot_base.map_or(0, |base| base.index)
        || next != expected_parent
        || chain.len()
            != heads
                .ordered_index
                .saturating_sub(snapshot_base.map_or(0, |base| base.index)) as usize
    {
        return Err(SharedJournalDriverError::CrossStoreMismatch);
    }

    let mut expected_bindings = BTreeSet::new();
    tracing::debug!(entries = chain.len(), "Shared reconciliation chain validated");
    for anchor in &audit.ordered {
        validate_ordered_anchor(store, &chain, journal_store, anchor).map_err(|error| {
            tracing::warn!(
                ?error,
                entry = ?anchor.entry,
                raft_index = anchor.index,
                in_chain = chain.contains_key(&anchor.entry),
                "Shared reconciliation ordered anchor failed"
            );
            error
        })?;
        if !expected_bindings.insert(anchor.entry) {
            return Err(SharedJournalDriverError::CrossStoreMismatch);
        }
    }
    tracing::debug!("Shared reconciliation ordered anchors validated");
    if let Some(pending) = &audit.pending_ordered {
        match store.shared_ordered_commit(pending.entry)? {
            Some(binding) => {
                validate_pending_binding(heads, &chain, journal_store, pending, &binding)
                    .map_err(|error| {
                        tracing::warn!(
                            ?error,
                            entry = ?pending.entry,
                            raft_index = pending.index,
                            in_chain = chain.contains_key(&pending.entry),
                            "Shared reconciliation pending binding failed"
                        );
                        error
                    })?;
                if !expected_bindings.insert(pending.entry) {
                    return Err(SharedJournalDriverError::CrossStoreMismatch);
                }
            }
            None if chain.contains_key(&pending.entry) => {
                tracing::warn!("Shared reconciliation pending chain entry has no binding");
                return Err(SharedJournalDriverError::CrossStoreMismatch);
            }
            None => {}
        }
    }
    tracing::debug!("Shared reconciliation pending binding validated");
    let actual = store.shared_ordered_commit_ids()?;
    for entry in &actual {
        if expected_bindings.contains(entry) {
            continue;
        }
        let snapshot = audit
            .snapshot
            .as_ref()
            .ok_or(SharedJournalDriverError::CrossStoreMismatch)?;
        let binding = store
            .shared_ordered_commit(*entry)?
            .ok_or(SharedJournalDriverError::CrossStoreMismatch)?;
        let claim = binding.claim();
        if binding.journal_store() != journal_store
            || claim.space() != snapshot.claim.ordered().space()
            || claim.agent() != snapshot.claim.ordered().agent()
            || claim.genesis() != snapshot.claim.ordered().genesis()
            || claim.admission() != snapshot.claim.ordered().admission()
            || claim.raft_index() > snapshot.claim.raft_index()
            || claim.ordered().index > snapshot.claim.ordered().ordered().index
            || claim.ordered().head != Some(*entry)
        {
            tracing::warn!(
                entry = ?entry,
                same_store = binding.journal_store() == journal_store,
                same_space = claim.space() == snapshot.claim.ordered().space(),
                same_agent = claim.agent() == snapshot.claim.ordered().agent(),
                same_genesis = claim.genesis() == snapshot.claim.ordered().genesis(),
                same_admission = claim.admission() == snapshot.claim.ordered().admission(),
                same_head = claim.ordered().head == Some(*entry),
                binding_raft_index = claim.raft_index(),
                snapshot_raft_index = snapshot.claim.raft_index(),
                binding_ordered_index = claim.ordered().index,
                snapshot_ordered_index = snapshot.claim.ordered().ordered().index,
                "Shared reconciliation extra binding is outside snapshot prefix"
            );
            return Err(SharedJournalDriverError::CrossStoreMismatch);
        }
    }
    if expected_bindings
        .iter()
        .any(|entry| !actual.contains(entry))
        || chain.keys().any(|entry| !expected_bindings.contains(entry))
    {
        tracing::warn!(
            missing_expected = expected_bindings.iter().filter(|entry| !actual.contains(entry)).count(),
            missing_chain = chain.keys().filter(|entry| !expected_bindings.contains(entry)).count(),
            "Shared reconciliation binding coverage failed"
        );
        return Err(SharedJournalDriverError::CrossStoreMismatch);
    }
    Ok(())
}

fn validate_ordered_anchor<S: AgentJournalStore + SharedOrderedCommitStore>(
    store: &S,
    chain: &BTreeMap<super::journal::OrderedEntryId, super::journal::OrderedEntry>,
    journal_store: super::shared_raft::JournalStoreInstanceId,
    anchor: &AgentRaftOrderedJournalAnchorV2,
) -> Result<(), SharedJournalDriverError> {
    let entry = chain
        .get(&anchor.entry)
        .ok_or(SharedJournalDriverError::CrossStoreMismatch)?;
    let binding = store
        .shared_ordered_commit(anchor.entry)?
        .ok_or(SharedJournalDriverError::CrossStoreMismatch)?;
    let claim = binding.claim();
    if entry.id() != anchor.entry
        || binding.journal_store() != journal_store
        || binding.entry() != anchor.entry
        || binding.raft_payload_commitment() != anchor.command_commitment
        || binding.successor() != anchor.successor
        || claim.commitment() != anchor.claim
        || claim.raft_index() != anchor.index
        || claim.raft_term() != anchor.term
        || claim.ordered().head != Some(anchor.entry)
        || claim.ordered().index != entry.index
        || claim.space() != anchor.route.space()
        || claim.agent() != anchor.route.agent()
        || claim.genesis() != anchor.route.genesis()
        || claim.admission() != anchor.route.admission()
        || claim.committee() != anchor.route.committee()
    {
        tracing::warn!(
            same_entry = entry.id() == anchor.entry && binding.entry() == anchor.entry,
            same_store = binding.journal_store() == journal_store,
            same_payload = binding.raft_payload_commitment() == anchor.command_commitment,
            same_successor = binding.successor() == anchor.successor,
            same_claim = claim.commitment() == anchor.claim,
            same_raft_index = claim.raft_index() == anchor.index,
            same_term = claim.raft_term() == anchor.term,
            same_head = claim.ordered().head == Some(anchor.entry),
            same_ordered_index = claim.ordered().index == entry.index,
            same_space = claim.space() == anchor.route.space(),
            same_agent = claim.agent() == anchor.route.agent(),
            same_genesis = claim.genesis() == anchor.route.genesis(),
            same_admission = claim.admission() == anchor.route.admission(),
            same_committee = claim.committee() == anchor.route.committee(),
            "Shared reconciliation ordered anchor fields differ"
        );
        return Err(SharedJournalDriverError::CrossStoreMismatch);
    }
    Ok(())
}

fn validate_pending_binding(
    heads: &super::journal::JournalHeads,
    chain: &BTreeMap<super::journal::OrderedEntryId, super::journal::OrderedEntry>,
    journal_store: super::shared_raft::JournalStoreInstanceId,
    pending: &AgentRaftPendingOrderedV2,
    binding: &super::journal_store::SharedOrderedCommitBinding,
) -> Result<(), SharedJournalDriverError> {
    match chain.get(&pending.entry) {
        Some(entry)
            if entry.index == pending.ordered_index
                && entry.parent == pending.ordered_parent => {}
        // Shared dependencies are durable before the head CAS, possibly even
        // before the entry file. Only the exact reserved next Ordered command
        // may account for such a binding. It remains pending, not applied;
        // normal replay must reconstruct and publish the exact binding later.
        None
            if heads.ordered_index.checked_add(1) == Some(pending.ordered_index)
                && heads.ordered_head == pending.ordered_parent => {}
        _ => return Err(SharedJournalDriverError::CrossStoreMismatch),
    }
    let claim = binding.claim();
    if binding.journal_store() != journal_store
        || binding.entry() != pending.entry
        || binding.raft_payload_commitment() != pending.command_commitment
        || binding.successor() == super::journal::JournalHeadsId::ZERO
        || claim.raft_index() != pending.index
        || claim.raft_term() != pending.term
        || claim.ordered().head != Some(pending.entry)
        || claim.ordered().index != pending.ordered_index
        || claim.space() != pending.route.space()
        || claim.agent() != pending.route.agent()
        || claim.genesis() != pending.route.genesis()
        || claim.admission() != pending.route.admission()
        || claim.committee() != pending.route.committee()
    {
        return Err(SharedJournalDriverError::CrossStoreMismatch);
    }
    Ok(())
}

#[cfg(test)]
mod keyed_actor_cursor_tests {
    use super::exclusive_actor_predecessor;

    #[test]
    fn actor_predecessor_is_exact_across_borrows_and_refuses_zero() {
        use crate::agent_sdk::ActorId;

        assert_eq!(exclusive_actor_predecessor(ActorId::ZERO), None);
        let mut minimum = [0_u8; 32];
        minimum[31] = 1;
        assert_eq!(exclusive_actor_predecessor(ActorId(minimum)), None);
        let mut target = [0_u8; 32];
        target[30] = 1;
        let mut predecessor = [0_u8; 32];
        predecessor[31] = u8::MAX;
        assert_eq!(
            exclusive_actor_predecessor(ActorId(target)),
            Some(ActorId(predecessor))
        );
        assert_eq!(
            exclusive_actor_predecessor(ActorId([u8::MAX; 32])),
            Some(ActorId({
                let mut bytes = [u8::MAX; 32];
                bytes[31] -= 1;
                bytes
            }))
        );
    }
}
