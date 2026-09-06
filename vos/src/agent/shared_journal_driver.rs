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

use super::driver::AgentTrustProvider;
use super::execution::RuntimeBlob;
use super::journal::{
    CanonicalJournalRecord, LocalEntry, MergeEvent, MergeFrontier, OrderedBase, OrderedEntry,
    PersistedLane, ReplayInput, ReplayInputId, ReplayOperation,
};
use super::journal_store::{
    AgentJournalGarbageCollection, AgentJournalStore, CatalogBlobResolverFactory, GcLimits,
    JournalBlobClass, JournalGc, JournalStoreError, ReverifiedRootJournalStore,
    SharedOrderedCommitRetirementStore, SharedOrderedCommitStore, validate_gc_limits,
};
use super::local_journal_driver::{
    LocalMergeAuthenticator, LocalReplayExecutorError, StandardLocalReplayExecutor,
};
use super::replay::{
    CommittedSharedOrdered, MaterializeError, NoPrunedOrderedBases, ReplayExecutor,
    ReplayMaterialization, ReplayPreparation, ReplaySource, SharedReplayPreparation,
    materialize_current, prepare_local, prepare_merge, prepare_shared_checkpoint,
    prepare_shared_ordered, validate_published_shared_checkpoint,
};
use super::shared_commit::{
    OrderedCommitClaim, SharedAgentSnapshotCertificate, SharedAgentSnapshotClaim, SharedCommitError,
};
use super::shared_raft::{
    AgentGenerationRouteKey, AgentRaftApplicationErrorV2, AgentRaftApplicationLedgerV2,
    AgentRaftAuditDisposition, AgentRaftCommand, AgentRaftFoundationApplyOutcomeV2,
    AgentRaftJournalAuditV2, AgentRaftOrderedJournalAnchorV2, AgentRaftPendingOrderedV2,
    ArtifactBatchId, ArtifactBatchManifest, ArtifactChunk, CommittedSharedRaftSlot,
    InstalledAgentRaftSnapshotV2,
};
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
#[cfg(test)]
struct RejectedInvocationTestExecutor;

#[cfg(test)]
impl super::replay::ReplayExecutor for RejectedInvocationTestExecutor {
    type Error = core::convert::Infallible;

    fn verify_merge_event(&mut self, _event: &MergeEvent) -> Result<bool, Self::Error> {
        Ok(true)
    }

    fn authenticate(
        &mut self,
        input: &super::journal::ReplayInput,
        _before: &super::wire::RuntimeState,
        _position: super::replay::ReplayPosition,
    ) -> Result<(), Self::Error> {
        assert!(input.validate().is_ok());
        Ok(())
    }

    fn execute(
        &mut self,
        input: &super::journal::ReplayInput,
        before: &super::wire::RuntimeState,
        _position: super::replay::ReplayPosition,
    ) -> Result<super::replay::ReplayTransition, Self::Error> {
        let super::journal::ReplayOperation::Invoke {
            invocation,
            observed_slot,
            ..
        } = &input.operation
        else {
            panic!("the acknowledgement short-circuits before test execution")
        };
        let decoded = super::wire::decode_standard_runtime_state(before).unwrap();
        let mut runtime = super::standard::StandardAgentRuntime::restore(decoded).unwrap();
        runtime
            .commit_exact_outcome_clock(invocation, *observed_slot)
            .unwrap();
        Ok(super::replay::ReplayTransition {
            state: super::wire::encode_standard_runtime_state(&runtime.snapshot()),
            disposition: super::replay::ReplayDisposition::Rejected,
            result: Some(Err(super::execution::ActorExecutionError::NotFound)),
            next_runtime: input.runtime.clone(),
            products: super::replay::ReplayProducts::default(),
        })
    }
}

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
pub(crate) struct PreparedCleanOrdered {
    input: ReplayInputId,
    payload: Vec<u8>,
}

impl PreparedCleanOrdered {
    pub(crate) const fn input(&self) -> ReplayInputId {
        self.input
    }

    pub(crate) fn into_payload(self) -> Vec<u8> {
        self.payload
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
        + AgentJournalGarbageCollection,
    A: SharedArtifactStager,
{
    store: S,
    artifacts: A,
    executor: StandardLocalReplayExecutor<S::Resolver>,
    materialization: ReplayMaterialization,
    ledger: AgentRaftApplicationLedgerV2,
    local_node: NodeId,
}

impl<S, A> SharedJournalAgentDriver<S, A>
where
    S: AgentJournalStore
        + ReplaySource<Error = JournalStoreError>
        + CatalogBlobResolverFactory
        + SharedOrderedCommitStore
        + SharedOrderedCommitRetirementStore
        + AgentJournalGarbageCollection,
    A: SharedArtifactStager,
{
    pub(crate) fn open(
        mut store: S,
        artifacts: A,
        ledger: AgentRaftApplicationLedgerV2,
        trust: Arc<dyn AgentTrustProvider>,
        merge: Arc<dyn LocalMergeAuthenticator>,
    ) -> Result<Self, SharedJournalDriverError> {
        let local_node = merge.node();
        if local_node != ledger.local_node() {
            return Err(SharedJournalDriverError::WrongReplica);
        }
        artifacts.audit(ledger.generation())?;
        let committees = ledger.committee_history()?;
        let resolver = store.catalog_blob_resolver()?;
        let mut executor =
            StandardLocalReplayExecutor::new_shared(resolver, trust, merge, committees);
        let materialization =
            materialize_current(&mut store, &mut executor, &NoPrunedOrderedBases)?;
        let config = super::wire::decode_standard_runtime_state(materialization.state())
            .map_err(|_| SharedJournalDriverError::InvalidProfile)?
            .config
            .ok_or(SharedJournalDriverError::InvalidProfile)?;
        let active = ledger.active_committee()?;
        let route = ledger.generation();
        if config.identity.profile != AgentProfile::Shared
            || active.profile() != AgentProfile::Shared
            || active.validate().is_err()
            || active.space() != config.identity.space
            || active.agent() != config.identity.agent
            || route.space() != config.identity.space
            || route.agent() != config.identity.agent
            || route.genesis() != materialization.heads().genesis
            || route.admission() != materialization.heads().admission
            || materialization.heads().node != local_node
            || store.instance_id() != ledger.journal_store()
        {
            return Err(SharedJournalDriverError::WrongReplica);
        }
        let audit = ledger.journal_audit()?;
        if let Some(snapshot) = &audit.snapshot {
            validate_published_shared_checkpoint(&store, &materialization, &snapshot.claim)
                .map_err(|_| SharedJournalDriverError::CrossStoreMismatch)?;
        }
        reconcile_journal_ledger(&store, &materialization, ledger.journal_store(), &audit)?;
        store.finish_reverified_open()?;
        Ok(Self {
            store,
            artifacts,
            executor,
            materialization,
            ledger,
            local_node,
        })
    }

    pub(crate) fn local_role(&self) -> Result<Option<ReplicaRole>, SharedJournalDriverError> {
        Ok(self
            .ledger
            .active_committee()?
            .member_by_node(self.local_node)
            .map(|member| member.replica().role))
    }

    pub(crate) fn identity(&self) -> Result<super::AgentIdentity, SharedJournalDriverError> {
        let state = super::wire::decode_standard_runtime_state(self.materialization.state())
            .map_err(|_| SharedJournalDriverError::InvalidProfile)?;
        Ok(state
            .config
            .ok_or(SharedJournalDriverError::InvalidProfile)?
            .identity)
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

    pub(crate) fn ledger(&self) -> &AgentRaftApplicationLedgerV2 {
        &self.ledger
    }

    fn clean_invocation_input(
        &self,
        work: crate::agent_sdk::InvocationWork,
        authorization: crate::agent_sdk::InvocationAuthorization,
    ) -> Result<ReplayInput, SharedJournalDriverError> {
        let heads = self.materialization.heads();
        let observed_slot = self.executor.current_logical_slot()?;
        let input = ReplayInput {
            runtime: heads.runtime.clone(),
            operation: ReplayOperation::CleanInvoke {
                work,
                authorization,
                observed_slot,
            },
        };
        input
            .validate()
            .map_err(|_| SharedJournalDriverError::CrossStoreMismatch)?;
        let ReplayOperation::CleanInvoke {
            work,
            authorization,
            observed_slot,
        } = &input.operation
        else {
            unreachable!()
        };
        self.executor.verify_clean_invocation_input(
            work,
            authorization,
            *observed_slot,
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
        let input = self.clean_invocation_input(work, authorization)?;
        if !matches!(
            input.persisted_lane(),
            PersistedLane::Control | PersistedLane::Linear
        ) {
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
        Ok(PreparedCleanOrdered { input, payload })
    }

    /// Publish one clean Local-lane invocation on this exact physical
    /// replica. This never enters Raft; a routed request mutates only the
    /// receiving replica's Local lane.
    pub(crate) fn apply_clean_local(
        &mut self,
        work: crate::agent_sdk::InvocationWork,
        authorization: crate::agent_sdk::InvocationAuthorization,
    ) -> Result<crate::agent_sdk::RuntimeOutcome, SharedJournalDriverError> {
        let input = self.clean_invocation_input(work, authorization)?;
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
        let input = self.clean_invocation_input(work, authorization)?;
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
    /// thread, or its ephemeral response may have been lost across restart.
    /// In either case an exact retry is recovered by the guest-owned result in
    /// canonical runtime state.
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

    /// Publish a rejected Local invocation and its acknowledgement through
    /// the generic replay/store boundary. This is test-only scaffolding for
    /// proving that snapshot recovery binds the actual post-Ordered head.
    #[cfg(test)]
    pub(crate) fn append_acknowledged_local_for_test(
        &mut self,
        invocation: super::journal::ReplayOperation,
        acknowledgement: super::journal::ReplayOperation,
    ) -> Result<(), SharedJournalDriverError> {
        let mut executor = RejectedInvocationTestExecutor;
        for operation in [invocation, acknowledgement] {
            let heads = self.materialization.heads().clone();
            let entry = super::journal::LocalEntry {
                genesis: heads.genesis,
                node: heads.node,
                revision: heads
                    .local_revision
                    .checked_add(1)
                    .ok_or(SharedJournalDriverError::CrossStoreMismatch)?,
                parent: heads.local_head,
                ordered_base: super::journal::OrderedBase {
                    index: heads.ordered_index,
                    head: heads.ordered_head,
                },
                merge_frontier: heads.merge_frontier,
                input: super::journal::ReplayInput {
                    runtime: heads.runtime,
                    operation,
                },
            };
            let prepared = prepare_local(
                &mut self.store,
                &mut executor,
                &self.materialization,
                &entry,
            )
            .map_err(|_| SharedJournalDriverError::CrossStoreMismatch)?;
            let ReplayPreparation::Ready(prepared) = prepared else {
                return Err(SharedJournalDriverError::CrossStoreMismatch);
            };
            let (_, successor, _) = prepared.publish()?;
            self.materialization = successor;
        }
        Ok(())
    }

    pub(crate) fn capacity(&self) -> Result<(u64, u64, bool), SharedJournalDriverError> {
        let audit = self.ledger.journal_audit()?;
        Ok((
            audit.applied_slots,
            audit.remaining_slots,
            audit.reservation_pending,
        ))
    }

    fn snapshot_boundary_claim(&self) -> Result<OrderedCommitClaim, SharedJournalDriverError> {
        let heads = self.materialization.heads();
        let entry = heads.ordered_head.ok_or(SharedJournalDriverError::Ledger(
            AgentRaftApplicationErrorV2::SnapshotBoundaryRequired,
        ))?;
        let binding = self
            .store
            .shared_ordered_commit(entry)?
            .ok_or(SharedJournalDriverError::CrossStoreMismatch)?;
        let claim = binding.claim();
        if claim.ordered().head != Some(entry)
            || claim.ordered().index != heads.ordered_index
            || claim.genesis() != heads.genesis
            || claim.admission() != heads.admission
            || claim.runtime() != &heads.runtime
        {
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
            ordered,
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

    /// Return the exact unsigned checkpoint claim. This is a read-only
    /// operation: no lane blob, journal head, audit row, or Raft scalar is
    /// changed until a voter-majority certificate is returned.
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
                    .install_snapshot(certificate)
                    .map_err(Into::into);
            }
            // Let the ledger's authenticated snapshot cursor reject lower or
            // equal divergent certificates before preparing or publishing
            // any journal checkpoint material.
            if certificate.claim().raft_index() <= installed.claim.raft_index() {
                return self
                    .ledger
                    .install_snapshot(certificate)
                    .map_err(Into::into);
            }
        }

        let verified = if self.materialization.heads_id() == certificate.claim().journal_heads() {
            let ordered = self.snapshot_boundary_claim()?;
            let context = self.ledger.snapshot_context(&ordered)?;
            validate_published_shared_checkpoint(
                &self.store,
                &self.materialization,
                certificate.claim(),
            )
            .map_err(|_| SharedJournalDriverError::CrossStoreMismatch)?;
            let claim = certificate.claim();
            if claim.ordered() != &ordered
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
            .install_snapshot(certificate)
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
                        ..
                    } => {
                        let validated_batch = if let Some(batch) = artifact_batch {
                            let (manifest, blobs) = self.artifacts.load_complete(*route, *batch)?;
                            validate_complete_batch(*route, *batch, &manifest, &blobs)?;
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
    pub(crate) fn create_shared_unexposed(
        mut store: super::journal_store::FileAgentJournalStore,
        artifacts: FileSharedArtifactStager,
        ledger: AgentRaftApplicationLedgerV2,
        sealed: &super::replay::ReplaySealedSharedGenesis,
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

    pub(crate) fn commit_exposure(
        &mut self,
        sealed: &super::replay::ReplaySealedSharedGenesis,
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
    for anchor in &audit.ordered {
        validate_ordered_anchor(store, &chain, journal_store, anchor)?;
        if !expected_bindings.insert(anchor.entry) {
            return Err(SharedJournalDriverError::CrossStoreMismatch);
        }
    }
    if let Some(pending) = &audit.pending_ordered {
        match store.shared_ordered_commit(pending.entry)? {
            Some(binding) => {
                validate_pending_binding(store, &chain, journal_store, pending, &binding)?;
                if !expected_bindings.insert(pending.entry) {
                    return Err(SharedJournalDriverError::CrossStoreMismatch);
                }
            }
            None if chain.contains_key(&pending.entry) => {
                return Err(SharedJournalDriverError::CrossStoreMismatch);
            }
            None => {}
        }
    }
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
            return Err(SharedJournalDriverError::CrossStoreMismatch);
        }
    }
    if expected_bindings
        .iter()
        .any(|entry| !actual.contains(entry))
        || chain.keys().any(|entry| !expected_bindings.contains(entry))
    {
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
        return Err(SharedJournalDriverError::CrossStoreMismatch);
    }
    Ok(())
}

fn validate_pending_binding<S: AgentJournalStore + SharedOrderedCommitStore>(
    _store: &S,
    chain: &BTreeMap<super::journal::OrderedEntryId, super::journal::OrderedEntry>,
    journal_store: super::shared_raft::JournalStoreInstanceId,
    pending: &AgentRaftPendingOrderedV2,
    binding: &super::journal_store::SharedOrderedCommitBinding,
) -> Result<(), SharedJournalDriverError> {
    let entry = chain
        .get(&pending.entry)
        .ok_or(SharedJournalDriverError::CrossStoreMismatch)?;
    let claim = binding.claim();
    if binding.journal_store() != journal_store
        || binding.entry() != pending.entry
        || binding.raft_payload_commitment() != pending.command_commitment
        || binding.successor() == super::journal::JournalHeadsId::ZERO
        || claim.raft_index() != pending.index
        || claim.raft_term() != pending.term
        || claim.ordered().head != Some(pending.entry)
        || claim.ordered().index != entry.index
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
