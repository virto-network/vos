//! Verified offline backup and recoverable restore for one complete space.
//!
//! The archive is a directory rather than an opaque tarball so operators can
//! inspect and copy it with ordinary tools. `manifest.json` binds every byte
//! under `data/` (redb files, v2 images, proof/private-input/record side
//! stores, node identity and local policy) and `blobs/` (the content-addressed
//! program cache). Restore verifies the complete archive before touching the
//! destination and renames replaced state aside instead of deleting it.

use std::collections::BTreeSet;
use std::fs;
use std::io::Read;
use std::path::{Component, Path, PathBuf};

use serde::{Deserialize, Serialize};

use crate::blob_store::{self, BlobHash};
use crate::commands::space::{endpoint, space_lock::SpaceDataLock};
use crate::spaces_index::{self, SpaceEntry};

const MANIFEST_FILE: &str = "manifest.json";
const ARCHIVE_FORMAT: &str = "VOSB1";
const ARCHIVE_VERSION: u32 = 1;
const MAX_MANIFEST_BYTES: u64 = 16 * 1024 * 1024;
const MAX_ARCHIVE_FILES: usize = 100_000;
const NODE_KEY_WIRE: &str = "data/node.key";

#[derive(Debug, Clone, Serialize, Deserialize)]
struct BackupManifest {
    format: String,
    version: u32,
    space: SpaceEntry,
    files: Vec<BackupFile>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
struct BackupFile {
    /// Slash-separated path rooted at `data/` or `blobs/`.
    path: String,
    bytes: u64,
    blake2b_256: String,
    /// Unix permission bits. `None` on non-Unix producers.
    mode: Option<u32>,
}

struct PartialDirectory {
    path: PathBuf,
    armed: bool,
}

impl PartialDirectory {
    fn new(path: PathBuf) -> Self {
        Self { path, armed: true }
    }

    fn disarm(&mut self) {
        self.armed = false;
    }
}

impl Drop for PartialDirectory {
    fn drop(&mut self) {
        if self.armed {
            let _ = fs::remove_dir_all(&self.path);
        }
    }
}

pub fn run_backup(query: &str, output: &Path) -> anyhow::Result<()> {
    let index = spaces_index::load()?;
    let initial = spaces_index::find(&index, query)?;
    let space_id = initial
        .id_bytes()
        .ok_or_else(|| anyhow::anyhow!("space id in index is not 32 bytes of hex"))?;
    let _lock = SpaceDataLock::shared(&space_id)?;
    // Index replacement uses the same space lock, but it may have completed
    // between our first lookup and acquisition. Resolve again under the lock
    // so a name reuse cannot make us archive a retired directory.
    let index = spaces_index::load()?;
    let entry = spaces_index::find(&index, query)?.clone();
    if entry.id_bytes() != Some(space_id) {
        anyhow::bail!("space index changed while backup was acquiring its lock; retry");
    }
    let data_dir = PathBuf::from(&entry.data_dir);
    refuse_live_daemon(&data_dir)?;
    let digest = create_archive(&entry, output, &blob_store::cache_dir())?;
    println!(
        "backed up '{}' to {} (manifest {})",
        entry.name,
        output.display(),
        digest,
    );
    Ok(())
}

pub fn run_restore(
    archive: &Path,
    data_dir: Option<&Path>,
    replace: bool,
    name: Option<&str>,
) -> anyhow::Result<()> {
    // Verify once before selecting a lock/destination. `restore_archive`
    // verifies again while copying, so corruption between these phases still
    // fails before activation.
    let manifest = verify_archive(archive)?;
    let expected_manifest = hash_file(&archive.join(MANIFEST_FILE))?;
    let space_id = manifest
        .space
        .id_bytes()
        .ok_or_else(|| anyhow::anyhow!("backup manifest space id is not 32 bytes of hex"))?;
    let _lock = SpaceDataLock::exclusive(&space_id)?;
    let destination = data_dir
        .map(PathBuf::from)
        .unwrap_or_else(|| crate::paths::space_dir(&space_id));
    let destination = spaces_index::normalize_data_directory(&destination)?;
    refuse_live_daemon(&destination)?;
    let replaced = restore_archive(
        archive,
        &destination,
        &blob_store::cache_dir(),
        &crate::paths::spaces_index_path(),
        Some(expected_manifest),
        replace,
        name,
    )?;
    println!(
        "restored '{}' to {}",
        name.unwrap_or(&manifest.space.name),
        destination.display(),
    );
    if let Some(replaced) = replaced {
        println!("previous state retained at {}", replaced.display());
    }
    Ok(())
}

fn refuse_live_daemon(data_dir: &Path) -> anyhow::Result<()> {
    if let Some(endpoint) = endpoint::read(data_dir)?
        && endpoint::is_alive(&endpoint)
    {
        anyhow::bail!(
            "space daemon pid {} is still running; stop it before backup or restore",
            endpoint.pid,
        );
    }
    Ok(())
}

fn create_archive(entry: &SpaceEntry, output: &Path, cache_dir: &Path) -> anyhow::Result<String> {
    if path_entry_exists(output)? {
        anyhow::bail!("backup destination already exists: {}", output.display());
    }
    if !entry.pending_recipe.is_empty() {
        anyhow::bail!(
            "space still references the external pending recipe {}; complete its first `space up` before backup",
            entry.pending_recipe,
        );
    }
    let data_dir = PathBuf::from(&entry.data_dir);
    let data_metadata = fs::symlink_metadata(&data_dir).map_err(|error| {
        anyhow::anyhow!(
            "inspect space data directory {}: {error}",
            data_dir.display()
        )
    })?;
    if data_metadata.file_type().is_symlink() || !data_metadata.is_dir() {
        anyhow::bail!(
            "space data directory must be a real directory, not a symlink: {}",
            data_dir.display()
        );
    }
    reject_nested_output(output, &data_dir, cache_dir)?;
    let parent = usable_parent(output);
    fs::create_dir_all(parent)
        .map_err(|error| anyhow::anyhow!("create {}: {error}", parent.display()))?;
    let stage = temporary_sibling(output, "backup-partial")?;
    fs::create_dir(&stage)
        .map_err(|error| anyhow::anyhow!("create {}: {error}", stage.display()))?;
    set_directory_private(&stage)?;
    let mut partial = PartialDirectory::new(stage.clone());

    let mut files = Vec::new();
    copy_tree_into_archive(&data_dir, &stage, "data", true, &mut files)?;
    copy_cache_into_archive(cache_dir, &stage, &mut files)?;
    files.sort_by(|left, right| left.path.cmp(&right.path));
    let registry_path = format!("blobs/{}", entry.registry_hash);
    if !files.iter().any(|file| file.path == registry_path) {
        anyhow::bail!(
            "registry blob {} is absent from the content-addressed cache; backup would not be self-contained",
            entry.registry_hash,
        );
    }

    let manifest = BackupManifest {
        format: ARCHIVE_FORMAT.into(),
        version: ARCHIVE_VERSION,
        space: entry.clone(),
        files,
    };
    let bytes = serde_json::to_vec_pretty(&manifest)
        .map_err(|error| anyhow::anyhow!("encode backup manifest: {error}"))?;
    fs::write(stage.join(MANIFEST_FILE), &bytes)
        .map_err(|error| anyhow::anyhow!("write backup manifest: {error}"))?;
    fs::File::open(stage.join(MANIFEST_FILE))?.sync_all()?;
    sync_tree_directories(&stage)?;
    verify_archive(&stage)?;
    fs::rename(&stage, output).map_err(|error| {
        anyhow::anyhow!(
            "activate backup {} -> {}: {error}",
            stage.display(),
            output.display(),
        )
    })?;
    sync_directory(parent)?;
    partial.disarm();
    Ok(hex::encode(vos::crypto::blake2b_hash::<32>(
        b"vosx/space-backup-manifest/v1",
        &[&bytes],
    )))
}

fn reject_nested_output(output: &Path, data_dir: &Path, cache_dir: &Path) -> anyhow::Result<()> {
    let data = fs::canonicalize(data_dir)
        .map_err(|error| anyhow::anyhow!("resolve {}: {error}", data_dir.display()))?;
    let cache = fs::canonicalize(cache_dir).ok();
    let parent = usable_parent(output);
    fs::create_dir_all(parent)
        .map_err(|error| anyhow::anyhow!("create {}: {error}", parent.display()))?;
    let parent = fs::canonicalize(parent)
        .map_err(|error| anyhow::anyhow!("resolve {}: {error}", parent.display()))?;
    let candidate = parent.join(
        output
            .file_name()
            .ok_or_else(|| anyhow::anyhow!("backup destination needs a final path component"))?,
    );
    if candidate.starts_with(&data)
        || cache
            .as_ref()
            .is_some_and(|cache| candidate.starts_with(cache))
    {
        anyhow::bail!("backup destination must be outside the space data and blob-cache trees");
    }
    Ok(())
}

fn copy_tree_into_archive(
    source_root: &Path,
    archive_root: &Path,
    prefix: &str,
    skip_endpoint: bool,
    files: &mut Vec<BackupFile>,
) -> anyhow::Result<()> {
    let mut pending = vec![PathBuf::new()];
    while let Some(relative) = pending.pop() {
        let directory = source_root.join(&relative);
        let mut entries = fs::read_dir(&directory)
            .map_err(|error| anyhow::anyhow!("read {}: {error}", directory.display()))?
            .collect::<Result<Vec<_>, _>>()
            .map_err(|error| anyhow::anyhow!("read {}: {error}", directory.display()))?;
        entries.sort_by_key(|entry| entry.file_name());
        for entry in entries.into_iter().rev() {
            let child_relative = relative.join(entry.file_name());
            if skip_endpoint && child_relative == Path::new(".endpoint") {
                continue;
            }
            let metadata = fs::symlink_metadata(entry.path())
                .map_err(|error| anyhow::anyhow!("inspect {}: {error}", entry.path().display()))?;
            if metadata.file_type().is_symlink() {
                anyhow::bail!(
                    "backup refuses symlink {} (archive paths must be self-contained)",
                    entry.path().display(),
                );
            }
            if metadata.is_dir() {
                pending.push(child_relative);
            } else if metadata.is_file() {
                let wire = wire_path(prefix, &child_relative)?;
                copy_one_file(&entry.path(), archive_root, &wire, files, false)?;
            } else {
                anyhow::bail!("backup refuses special file {}", entry.path().display());
            }
        }
    }
    Ok(())
}

fn copy_cache_into_archive(
    cache_dir: &Path,
    archive_root: &Path,
    files: &mut Vec<BackupFile>,
) -> anyhow::Result<()> {
    let cache_metadata = fs::symlink_metadata(cache_dir)
        .map_err(|error| anyhow::anyhow!("inspect blob cache {}: {error}", cache_dir.display()))?;
    if cache_metadata.file_type().is_symlink() || !cache_metadata.is_dir() {
        anyhow::bail!(
            "blob cache must be a real directory, not a symlink: {}",
            cache_dir.display(),
        );
    }
    let entries = match fs::read_dir(cache_dir) {
        Ok(entries) => entries,
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => {
            anyhow::bail!("blob cache does not exist: {}", cache_dir.display())
        }
        Err(error) => return Err(anyhow::anyhow!("read {}: {error}", cache_dir.display())),
    };
    let mut entries = entries
        .collect::<Result<Vec<_>, _>>()
        .map_err(|error| anyhow::anyhow!("read {}: {error}", cache_dir.display()))?;
    entries.sort_by_key(|entry| entry.file_name());
    for entry in entries {
        let name = entry.file_name();
        let Some(name) = name.to_str() else { continue };
        if name.len() != 64 || !name.bytes().all(|byte| byte.is_ascii_hexdigit()) {
            continue;
        }
        let hash = BlobHash::from_hex(name)
            .map_err(|_| anyhow::anyhow!("invalid canonical blob-cache name {name}"))?;
        let metadata = fs::symlink_metadata(entry.path())?;
        if metadata.file_type().is_symlink() || !metadata.is_file() {
            anyhow::bail!("canonical blob-cache entry {name} is not a regular file");
        }
        let actual = BlobHash(hash_file(&entry.path())?);
        if actual != hash {
            anyhow::bail!("corrupt blob cache entry {name}: computed {actual}");
        }
        // Cache objects are immutable and content-addressed. Prefer an
        // independent copy-on-write clone on Linux so an ordinary local
        // backup does not immediately duplicate large PVM artifacts. This is
        // deliberately not a hard link: later corruption of the live cache
        // must not mutate the archived inode too. Unsupported/cross-filesystem
        // destinations transparently fall back to a byte copy.
        copy_one_file(
            &entry.path(),
            archive_root,
            &format!("blobs/{name}"),
            files,
            true,
        )?;
    }
    Ok(())
}

fn copy_one_file(
    source: &Path,
    archive_root: &Path,
    wire: &str,
    files: &mut Vec<BackupFile>,
    allow_reflink: bool,
) -> anyhow::Result<()> {
    let destination = wire_to_path(archive_root, wire)?;
    if let Some(parent) = destination.parent() {
        fs::create_dir_all(parent)
            .map_err(|error| anyhow::anyhow!("create {}: {error}", parent.display()))?;
    }
    let cloned = allow_reflink && try_reflink(source, &destination)?;
    if !cloned {
        fs::copy(source, &destination).map_err(|error| {
            anyhow::anyhow!(
                "copy {} -> {}: {error}",
                source.display(),
                destination.display(),
            )
        })?;
    }
    let metadata = fs::metadata(&destination)?;
    let mode = file_mode(source)?;
    set_file_mode(&destination, mode)?;
    fs::File::open(&destination)?.sync_all()?;
    files.push(BackupFile {
        path: wire.into(),
        bytes: metadata.len(),
        blake2b_256: hex::encode(hash_file(&destination)?),
        mode,
    });
    Ok(())
}

#[cfg(target_os = "linux")]
fn try_reflink(source: &Path, destination: &Path) -> anyhow::Result<bool> {
    use std::os::fd::AsRawFd;

    // Linux FICLONE creates a distinct copy-on-write inode. Failure is an
    // expected capability/filesystem result, not a backup error; remove the
    // empty target and let the caller perform a conventional copy.
    const FICLONE: libc::c_ulong = 0x4004_9409;
    let source = fs::File::open(source)?;
    let destination_file = fs::OpenOptions::new()
        .write(true)
        .create_new(true)
        .open(destination)?;
    // SAFETY: both descriptors remain open for the ioctl, FICLONE consumes
    // no userspace pointer, and the kernel validates descriptor suitability.
    let cloned =
        unsafe { libc::ioctl(destination_file.as_raw_fd(), FICLONE, source.as_raw_fd()) == 0 };
    drop(destination_file);
    if !cloned {
        fs::remove_file(destination)?;
    }
    Ok(cloned)
}

#[cfg(not(target_os = "linux"))]
fn try_reflink(_source: &Path, _destination: &Path) -> anyhow::Result<bool> {
    Ok(false)
}

fn verify_archive(archive: &Path) -> anyhow::Result<BackupManifest> {
    let archive_metadata = fs::symlink_metadata(archive)
        .map_err(|error| anyhow::anyhow!("inspect backup root {}: {error}", archive.display()))?;
    if archive_metadata.file_type().is_symlink() || !archive_metadata.is_dir() {
        anyhow::bail!("backup root must be a real directory");
    }
    let manifest_path = archive.join(MANIFEST_FILE);
    let manifest_metadata = fs::symlink_metadata(&manifest_path)
        .map_err(|error| anyhow::anyhow!("inspect {}: {error}", manifest_path.display()))?;
    if !manifest_metadata.is_file()
        || manifest_metadata.file_type().is_symlink()
        || manifest_metadata.len() > MAX_MANIFEST_BYTES
    {
        anyhow::bail!("backup manifest is not a bounded regular file");
    }
    let bytes = fs::read(&manifest_path)
        .map_err(|error| anyhow::anyhow!("read {}: {error}", manifest_path.display()))?;
    let manifest: BackupManifest = serde_json::from_slice(&bytes)
        .map_err(|error| anyhow::anyhow!("decode {}: {error}", manifest_path.display()))?;
    if manifest.format != ARCHIVE_FORMAT || manifest.version != ARCHIVE_VERSION {
        anyhow::bail!(
            "unsupported backup format {} version {}",
            manifest.format,
            manifest.version,
        );
    }
    if manifest.files.len() > MAX_ARCHIVE_FILES {
        anyhow::bail!("backup manifest contains too many files");
    }
    manifest
        .space
        .id_bytes()
        .ok_or_else(|| anyhow::anyhow!("backup manifest contains an invalid space id"))?;
    let registry_hash = BlobHash::from_hex(&manifest.space.registry_hash)
        .map_err(|_| anyhow::anyhow!("backup manifest contains an invalid registry blob hash"))?;
    if registry_hash.to_hex() != manifest.space.registry_hash {
        anyhow::bail!("backup manifest registry blob hash is not canonical lowercase hex");
    }
    let mut previous: Option<&str> = None;
    let mut expected = BTreeSet::new();
    for file in &manifest.files {
        if file.mode.is_some_and(|mode| mode > 0o7777) {
            anyhow::bail!("backup entry has invalid Unix mode: {}", file.path);
        }
        if previous.is_some_and(|previous| previous >= file.path.as_str()) {
            anyhow::bail!("backup manifest file paths must be strictly sorted");
        }
        previous = Some(&file.path);
        let path = wire_to_path(archive, &file.path)?;
        let metadata = fs::symlink_metadata(&path)
            .map_err(|error| anyhow::anyhow!("inspect {}: {error}", path.display()))?;
        if !metadata.is_file() || metadata.file_type().is_symlink() {
            anyhow::bail!("backup entry is not a regular file: {}", file.path);
        }
        let actual_hash = hex::encode(hash_file(&path)?);
        if metadata.len() != file.bytes || actual_hash != file.blake2b_256 {
            anyhow::bail!("backup integrity mismatch: {}", file.path);
        }
        if let Some(blob_hash) = file.path.strip_prefix("blobs/")
            && (blob_hash.len() != 64 || blob_hash.contains('/') || actual_hash != blob_hash)
        {
            anyhow::bail!("backup blob path is not its content address: {}", file.path);
        }
        expected.insert(file.path.clone());
    }
    let actual = archive_file_set(archive)?;
    if actual != expected {
        anyhow::bail!("backup contains files absent from its integrity manifest");
    }
    let registry_db = registry_db_wire();
    let registry_blob = format!("blobs/{}", manifest.space.registry_hash);
    for required in [NODE_KEY_WIRE, registry_db.as_str(), registry_blob.as_str()] {
        if !expected.contains(required) {
            anyhow::bail!("backup is structurally incomplete: missing {required}");
        }
        if fs::metadata(wire_to_path(archive, required)?)?.len() == 0 {
            anyhow::bail!("backup is structurally incomplete: {required} is empty");
        }
    }
    Ok(manifest)
}

fn archive_file_set(archive: &Path) -> anyhow::Result<BTreeSet<String>> {
    let mut root_names = fs::read_dir(archive)?
        .collect::<Result<Vec<_>, _>>()?
        .into_iter()
        .map(|entry| entry.file_name())
        .collect::<Vec<_>>();
    root_names.sort();
    for name in &root_names {
        if name != MANIFEST_FILE && name != "data" && name != "blobs" {
            anyhow::bail!(
                "backup contains an unexpected root entry {}",
                name.to_string_lossy(),
            );
        }
    }
    let mut files = Vec::new();
    for prefix in ["data", "blobs"] {
        let root = archive.join(prefix);
        let metadata = fs::symlink_metadata(&root).map_err(|error| {
            anyhow::anyhow!("backup is missing required {prefix}/ directory: {error}")
        })?;
        if metadata.file_type().is_symlink() || !metadata.is_dir() {
            anyhow::bail!("backup {prefix}/ root must be a real directory");
        }
        collect_wire_files(&root, prefix, &mut files)?;
    }
    Ok(files.into_iter().collect())
}

fn registry_db_wire() -> String {
    format!(
        "data/agents/{:08x}.redb",
        vos::abi::service::ServiceId::REGISTRY.0,
    )
}

fn collect_wire_files(root: &Path, prefix: &str, files: &mut Vec<String>) -> anyhow::Result<()> {
    let mut pending = vec![PathBuf::new()];
    while let Some(relative) = pending.pop() {
        let directory = root.join(&relative);
        for entry in fs::read_dir(&directory)
            .map_err(|error| anyhow::anyhow!("read {}: {error}", directory.display()))?
        {
            let entry = entry?;
            let child = relative.join(entry.file_name());
            let metadata = fs::symlink_metadata(entry.path())?;
            if metadata.file_type().is_symlink() || (!metadata.is_dir() && !metadata.is_file()) {
                anyhow::bail!(
                    "backup contains unsupported file {}",
                    entry.path().display()
                );
            }
            if metadata.is_dir() {
                pending.push(child);
            } else {
                files.push(wire_path(prefix, &child)?);
            }
        }
    }
    Ok(())
}

fn restore_archive(
    archive: &Path,
    destination: &Path,
    cache_dir: &Path,
    index_path: &Path,
    expected_manifest: Option<[u8; 32]>,
    replace: bool,
    name: Option<&str>,
) -> anyhow::Result<Option<PathBuf>> {
    let destination = spaces_index::normalize_data_directory(destination)?;
    let manifest = verify_archive(archive)?;
    if let Some(expected) = expected_manifest
        && hash_file(&archive.join(MANIFEST_FILE))? != expected
    {
        anyhow::bail!("backup manifest changed while restore was acquiring its lock");
    }
    reject_restore_overlap(archive, &destination)?;
    let mut restored_entry = manifest.space.clone();
    if let Some(name) = name {
        if name.is_empty() {
            anyhow::bail!("restored space name cannot be empty");
        }
        restored_entry.name = name.into();
    }
    restored_entry.data_dir = destination.to_string_lossy().into_owned();
    // Different space locks intentionally permit independent backups, but
    // index activation is one global read-modify-write transaction. Hold a
    // stable sibling lock through the reload, destination ownership checks,
    // directory activation, and atomic index replacement.
    let mut index = spaces_index::LockedSpacesIndex::acquire_from(index_path)?;
    index.validate_upsert(&restored_entry)?;

    let destination_exists = path_entry_exists(&destination)?;
    if destination_exists && fs::symlink_metadata(&destination)?.file_type().is_symlink() {
        anyhow::bail!("restore destination must not be a symlink");
    }
    if destination_exists && !replace {
        anyhow::bail!(
            "restore destination exists: {}; pass --replace to retain it and activate the backup",
            destination.display(),
        );
    }
    let parent = usable_parent(&destination);
    fs::create_dir_all(parent)
        .map_err(|error| anyhow::anyhow!("create {}: {error}", parent.display()))?;
    let stage = temporary_sibling(&destination, "restore-partial")?;
    fs::create_dir(&stage)
        .map_err(|error| anyhow::anyhow!("create {}: {error}", stage.display()))?;
    set_directory_private(&stage)?;
    let mut partial = PartialDirectory::new(stage.clone());

    for file in &manifest.files {
        let source = wire_to_path(archive, &file.path)?;
        if let Some(relative) = file.path.strip_prefix("data/") {
            let target = wire_to_path(&stage, relative)?;
            copy_verified_file(&source, &target, file)?;
        } else if file.path.strip_prefix("blobs/").is_some() {
            // Installed below through the explicit cache root. Keeping this
            // loop focused on data files avoids tests or embedded callers
            // ever mutating the process-global XDG cache by surprise.
        } else {
            anyhow::bail!("backup path has no supported root: {}", file.path);
        }
    }

    restore_blobs_to_cache(archive, &manifest, cache_dir)?;
    sync_tree_directories(&stage)?;

    let replaced = if destination_exists {
        let replaced = temporary_sibling(&destination, "restore-replaced")?;
        fs::rename(&destination, &replaced).map_err(|error| {
            anyhow::anyhow!(
                "retain existing state {} -> {}: {error}",
                destination.display(),
                replaced.display(),
            )
        })?;
        Some(replaced)
    } else {
        None
    };
    if let Err(error) = fs::rename(&stage, &destination) {
        if let Some(replaced) = &replaced {
            if let Err(rollback) = fs::rename(replaced, &destination) {
                return Err(anyhow::anyhow!(
                    "activate restored state {} -> {}: {error}; restoring retained state {} also failed: {rollback}",
                    stage.display(),
                    destination.display(),
                    replaced.display(),
                ));
            }
        }
        return Err(anyhow::anyhow!(
            "activate restored state {} -> {}: {error}",
            stage.display(),
            destination.display(),
        ));
    }
    if let Err(error) = sync_directory(parent) {
        return Err(rollback_error(
            error,
            &destination,
            &stage,
            replaced.as_deref(),
        ));
    }
    partial.disarm();

    spaces_index::upsert(&mut index, restored_entry);
    if let Err(error) = index.save() {
        return Err(rollback_error(
            error.into(),
            &destination,
            &stage,
            replaced.as_deref(),
        ));
    }
    Ok(replaced)
}

fn restore_blobs_to_cache(
    archive: &Path,
    manifest: &BackupManifest,
    cache_dir: &Path,
) -> anyhow::Result<()> {
    fs::create_dir_all(cache_dir)?;
    for file in &manifest.files {
        let Some(hash_hex) = file.path.strip_prefix("blobs/") else {
            continue;
        };
        let source = wire_to_path(archive, &file.path)?;
        let actual = BlobHash(hash_file(&source)?);
        if actual.to_hex() != hash_hex {
            anyhow::bail!("backup blob {hash_hex} has content address {actual}");
        }
        let target = cache_dir.join(hash_hex);
        if target.exists() {
            if BlobHash(hash_file(&target)?) != actual {
                anyhow::bail!("restore cache already contains corrupt blob {hash_hex}");
            }
        } else {
            let temporary = temporary_sibling(&target, "cache-partial")?;
            fs::copy(&source, &temporary)?;
            if BlobHash(hash_file(&temporary)?) != actual {
                let _ = fs::remove_file(&temporary);
                anyhow::bail!("backup blob {hash_hex} changed during restore");
            }
            match fs::rename(&temporary, &target) {
                Ok(()) => {}
                Err(error) if target.exists() => {
                    let _ = fs::remove_file(&temporary);
                    if BlobHash(hash_file(&target)?) != actual {
                        return Err(error.into());
                    }
                }
                Err(error) => {
                    let _ = fs::remove_file(&temporary);
                    return Err(error.into());
                }
            }
            fs::File::open(&target)?.sync_all()?;
        }
    }
    sync_directory(cache_dir)?;
    Ok(())
}

fn rollback_restore(
    destination: &Path,
    stage: &Path,
    replaced: Option<&Path>,
) -> anyhow::Result<()> {
    fs::rename(destination, stage).map_err(|error| {
        anyhow::anyhow!(
            "move failed restore {} aside to {}: {error}",
            destination.display(),
            stage.display(),
        )
    })?;
    if let Some(replaced) = replaced {
        fs::rename(replaced, destination).map_err(|error| {
            anyhow::anyhow!(
                "restore retained state {} -> {}: {error}",
                replaced.display(),
                destination.display(),
            )
        })?;
    }
    fs::remove_dir_all(stage)
        .map_err(|error| anyhow::anyhow!("remove failed restore {}: {error}", stage.display()))?;
    sync_directory(usable_parent(destination))?;
    Ok(())
}

fn rollback_error(
    original: anyhow::Error,
    destination: &Path,
    stage: &Path,
    replaced: Option<&Path>,
) -> anyhow::Error {
    match rollback_restore(destination, stage, replaced) {
        Ok(()) => original,
        Err(rollback) => anyhow::anyhow!(
            "restore failed: {original:#}; rollback also failed: {rollback:#}; inspect {} and {} before retrying",
            destination.display(),
            stage.display(),
        ),
    }
}

fn copy_verified_file(source: &Path, destination: &Path, file: &BackupFile) -> anyhow::Result<()> {
    let metadata = fs::metadata(source)?;
    if metadata.len() != file.bytes || hex::encode(hash_file(source)?) != file.blake2b_256 {
        anyhow::bail!("backup changed during restore: {}", file.path);
    }
    if let Some(parent) = destination
        .parent()
        .filter(|parent| !parent.as_os_str().is_empty())
    {
        fs::create_dir_all(parent)?;
    }
    fs::copy(source, destination)?;
    if fs::metadata(destination)?.len() != file.bytes
        || hex::encode(hash_file(destination)?) != file.blake2b_256
    {
        anyhow::bail!("backup changed while copying: {}", file.path);
    }
    set_file_mode(destination, file.mode)?;
    fs::File::open(destination)?.sync_all()?;
    Ok(())
}

fn reject_restore_overlap(archive: &Path, destination: &Path) -> anyhow::Result<()> {
    let archive = fs::canonicalize(archive)
        .map_err(|error| anyhow::anyhow!("resolve {}: {error}", archive.display()))?;
    let parent = usable_parent(destination);
    fs::create_dir_all(parent)?;
    let parent = fs::canonicalize(parent)?;
    let candidate = parent.join(
        destination
            .file_name()
            .ok_or_else(|| anyhow::anyhow!("restore destination needs a final path component"))?,
    );
    if candidate.starts_with(&archive) || archive.starts_with(&candidate) {
        anyhow::bail!("restore destination and backup directory must not overlap");
    }
    Ok(())
}

fn hash_file(path: &Path) -> anyhow::Result<[u8; 32]> {
    let mut file = fs::File::open(path)?;
    let mut state = blake2b_simd::Params::new().hash_length(32).to_state();
    let mut buffer = [0u8; 64 * 1024];
    loop {
        let read = file.read(&mut buffer)?;
        if read == 0 {
            break;
        }
        state.update(&buffer[..read]);
    }
    Ok(state
        .finalize()
        .as_bytes()
        .try_into()
        .expect("32-byte digest"))
}

fn sync_tree_directories(root: &Path) -> anyhow::Result<()> {
    #[cfg(unix)]
    {
        let mut directories = vec![root.to_path_buf()];
        let mut cursor = 0;
        while cursor < directories.len() {
            for entry in fs::read_dir(&directories[cursor])? {
                let entry = entry?;
                if entry.file_type()?.is_dir() {
                    directories.push(entry.path());
                }
            }
            cursor += 1;
        }
        // Children before parents ensures directory entries reach stable
        // storage before the top-level activation rename is synced by its
        // parent filesystem transaction.
        for directory in directories.into_iter().rev() {
            fs::File::open(directory)?.sync_all()?;
        }
    }
    Ok(())
}

fn sync_directory(path: &Path) -> anyhow::Result<()> {
    #[cfg(unix)]
    fs::File::open(path)?.sync_all()?;
    Ok(())
}

fn temporary_sibling(path: &Path, label: &str) -> anyhow::Result<PathBuf> {
    let mut nonce = [0u8; 8];
    getrandom::getrandom(&mut nonce)
        .map_err(|error| anyhow::anyhow!("OS entropy for temporary path: {error}"))?;
    let file = path
        .file_name()
        .ok_or_else(|| anyhow::anyhow!("path needs a final component: {}", path.display()))?
        .to_string_lossy();
    Ok(path.with_file_name(format!(
        ".{file}.{label}.{}.{}",
        std::process::id(),
        hex::encode(nonce),
    )))
}

fn path_entry_exists(path: &Path) -> anyhow::Result<bool> {
    match fs::symlink_metadata(path) {
        Ok(_) => Ok(true),
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => Ok(false),
        Err(error) => Err(error.into()),
    }
}

fn usable_parent(path: &Path) -> &Path {
    path.parent()
        .filter(|parent| !parent.as_os_str().is_empty())
        .unwrap_or_else(|| Path::new("."))
}

fn wire_path(prefix: &str, relative: &Path) -> anyhow::Result<String> {
    let mut segments = vec![prefix.to_string()];
    for component in relative.components() {
        let Component::Normal(segment) = component else {
            anyhow::bail!("non-canonical archive source path: {}", relative.display());
        };
        let segment = segment
            .to_str()
            .ok_or_else(|| anyhow::anyhow!("backup paths must be valid UTF-8"))?;
        if segment.is_empty() || segment.contains('/') || segment.contains('\\') {
            anyhow::bail!("non-canonical archive path component");
        }
        segments.push(segment.into());
    }
    Ok(segments.join("/"))
}

fn wire_to_path(root: &Path, wire: &str) -> anyhow::Result<PathBuf> {
    if wire.is_empty() || wire.starts_with('/') || wire.ends_with('/') || wire.contains('\\') {
        anyhow::bail!("non-canonical backup path {wire:?}");
    }
    let mut path = root.to_path_buf();
    for segment in wire.split('/') {
        if segment.is_empty() || segment == "." || segment == ".." {
            anyhow::bail!("non-canonical backup path {wire:?}");
        }
        path.push(segment);
    }
    Ok(path)
}

#[cfg(unix)]
fn file_mode(path: &Path) -> anyhow::Result<Option<u32>> {
    use std::os::unix::fs::PermissionsExt;
    Ok(Some(fs::metadata(path)?.permissions().mode() & 0o7777))
}

#[cfg(not(unix))]
fn file_mode(_path: &Path) -> anyhow::Result<Option<u32>> {
    Ok(None)
}

#[cfg(unix)]
fn set_file_mode(path: &Path, mode: Option<u32>) -> anyhow::Result<()> {
    use std::os::unix::fs::PermissionsExt;
    if let Some(mode) = mode {
        fs::set_permissions(path, fs::Permissions::from_mode(mode))?;
    }
    Ok(())
}

#[cfg(unix)]
fn set_directory_private(path: &Path) -> anyhow::Result<()> {
    use std::os::unix::fs::PermissionsExt;
    fs::set_permissions(path, fs::Permissions::from_mode(0o700))?;
    Ok(())
}

#[cfg(not(unix))]
fn set_directory_private(_path: &Path) -> anyhow::Result<()> {
    Ok(())
}

#[cfg(not(unix))]
fn set_file_mode(_path: &Path, _mode: Option<u32>) -> anyhow::Result<()> {
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    struct TempDir(PathBuf);

    impl TempDir {
        fn new(label: &str) -> Self {
            let path = std::env::temp_dir().join(format!(
                "vosx-backup-test-{label}-{}-{}",
                std::process::id(),
                std::time::SystemTime::now()
                    .duration_since(std::time::UNIX_EPOCH)
                    .unwrap()
                    .as_nanos(),
            ));
            fs::create_dir_all(&path).unwrap();
            Self(path)
        }
    }

    impl Drop for TempDir {
        fn drop(&mut self) {
            if !std::thread::panicking() {
                let _ = fs::remove_dir_all(&self.0);
            }
        }
    }

    fn fixture(root: &Path) -> (SpaceEntry, PathBuf, PathBuf) {
        let data = root.join("source");
        let cache = root.join("cache");
        fs::create_dir_all(data.join("agents")).unwrap();
        fs::create_dir_all(data.join("v2-services/root.image.proofs")).unwrap();
        fs::create_dir_all(data.join("v2-services/root.image.records")).unwrap();
        fs::create_dir_all(&cache).unwrap();
        fs::write(data.join("node.key"), b"secret-node-key").unwrap();
        fs::write(
            data.join(
                registry_db_wire()
                    .strip_prefix("data/")
                    .expect("registry DB lives below data"),
            ),
            b"registry-redb",
        )
        .unwrap();
        fs::write(
            data.join("v2-services/root.image"),
            b"committed-service-image",
        )
        .unwrap();
        fs::write(
            data.join("v2-services/root.image.proofs/proof"),
            b"proof-side-cas",
        )
        .unwrap();
        fs::write(
            data.join("v2-services/root.image.records/record"),
            b"producer-private-record",
        )
        .unwrap();
        fs::write(data.join(".endpoint"), b"ephemeral").unwrap();
        let blob = b"signed-v2-package";
        let hash = BlobHash::of(blob);
        fs::write(cache.join(hash.to_hex()), blob).unwrap();
        let entry = SpaceEntry {
            id: hex::encode([0x72; 32]),
            name: "backup-fixture".into(),
            created_at: "2026-08-21T00:00:00Z".into(),
            data_dir: data.to_string_lossy().into_owned(),
            registry_hash: hash.to_hex(),
            bootnodes: Vec::new(),
            hyperspace: String::new(),
            pending_recipe: String::new(),
        };
        (entry, data, cache)
    }

    #[test]
    fn archive_roundtrip_covers_private_side_stores_and_cache() {
        let temp = TempDir::new("roundtrip");
        let (entry, _data, cache) = fixture(&temp.0);
        let archive = temp.0.join("backup");
        create_archive(&entry, &archive, &cache).unwrap();
        let manifest = verify_archive(&archive).unwrap();
        assert!(
            manifest
                .files
                .iter()
                .any(|file| file.path.ends_with("root.image.proofs/proof"))
        );
        assert!(
            manifest
                .files
                .iter()
                .any(|file| file.path.ends_with("root.image.records/record"))
        );
        assert!(
            !manifest
                .files
                .iter()
                .any(|file| file.path == "data/.endpoint")
        );

        let destination = temp.0.join("restored");
        let restored_cache = temp.0.join("restored-cache");
        let index = temp.0.join("spaces.toml");
        restore_archive(
            &archive,
            &destination,
            &restored_cache,
            &index,
            None,
            false,
            Some("restored-name"),
        )
        .unwrap();
        assert_eq!(
            fs::read(destination.join("node.key")).unwrap(),
            b"secret-node-key"
        );
        assert_eq!(
            fs::read(destination.join("v2-services/root.image.records/record")).unwrap(),
            b"producer-private-record",
        );
        let restored_index = spaces_index::load_from(&index).unwrap();
        assert_eq!(restored_index.spaces[0].name, "restored-name");
        assert_eq!(
            restored_index.spaces[0].data_dir,
            destination.to_string_lossy()
        );
        assert_eq!(fs::read_dir(restored_cache).unwrap().count(), 1);
    }

    #[test]
    fn restore_rejects_tampering_before_touching_destination() {
        let temp = TempDir::new("tamper");
        let (entry, _data, cache) = fixture(&temp.0);
        let archive = temp.0.join("backup");
        create_archive(&entry, &archive, &cache).unwrap();
        fs::write(archive.join("data/node.key"), b"tampered").unwrap();
        let destination = temp.0.join("restored");
        let error = restore_archive(
            &archive,
            &destination,
            &temp.0.join("restored-cache"),
            &temp.0.join("spaces.toml"),
            None,
            false,
            None,
        )
        .unwrap_err();
        assert!(error.to_string().contains("integrity mismatch"));
        assert!(!destination.exists());
    }

    #[test]
    fn archived_cache_inode_is_independent_from_the_live_cache() {
        let temp = TempDir::new("cache-independence");
        let (entry, _data, cache) = fixture(&temp.0);
        let archive = temp.0.join("backup");
        create_archive(&entry, &archive, &cache).unwrap();
        let hash = entry.registry_hash;
        let archived = archive.join("blobs").join(&hash);
        let original = fs::read(&archived).unwrap();

        // A hard-linked optimization would mutate the archive here. The
        // copy/reflink contract keeps backup bytes stable even if the live
        // cache is damaged after backup activation.
        fs::write(cache.join(&hash), vec![0xA5; original.len()]).unwrap();
        assert_eq!(fs::read(archived).unwrap(), original);
        verify_archive(&archive).unwrap();
    }

    #[test]
    fn restore_rejects_traversal_and_preserves_replaced_state() {
        let temp = TempDir::new("replace");
        let (entry, _data, cache) = fixture(&temp.0);
        let archive = temp.0.join("backup");
        create_archive(&entry, &archive, &cache).unwrap();
        let mut manifest = verify_archive(&archive).unwrap();
        manifest.files[0].path = "data/../escape".into();
        fs::write(
            archive.join(MANIFEST_FILE),
            serde_json::to_vec_pretty(&manifest).unwrap(),
        )
        .unwrap();
        assert!(verify_archive(&archive).is_err());

        // Rebuild a clean archive and prove replacement is rename-aside, not
        // overwrite/delete.
        fs::remove_dir_all(&archive).unwrap();
        create_archive(&entry, &archive, &cache).unwrap();
        let destination = temp.0.join("restored");
        fs::create_dir(&destination).unwrap();
        fs::write(destination.join("old"), b"recover me").unwrap();
        let replaced = restore_archive(
            &archive,
            &destination,
            &temp.0.join("restored-cache"),
            &temp.0.join("spaces.toml"),
            None,
            true,
            None,
        )
        .unwrap()
        .unwrap();
        assert_eq!(fs::read(replaced.join("old")).unwrap(), b"recover me");
        assert_eq!(
            fs::read(destination.join("node.key")).unwrap(),
            b"secret-node-key"
        );
    }

    #[test]
    fn restore_refuses_a_directory_owned_by_another_indexed_space() {
        let temp = TempDir::new("owned-destination");
        let (entry, _data, cache) = fixture(&temp.0);
        let archive = temp.0.join("backup");
        create_archive(&entry, &archive, &cache).unwrap();

        let destination = temp.0.join("other-space");
        fs::create_dir(&destination).unwrap();
        fs::write(destination.join("owner"), b"keep me").unwrap();
        let index_path = temp.0.join("spaces.toml");
        let other = SpaceEntry {
            id: hex::encode([0x73; 32]),
            name: "other".into(),
            created_at: "2026-08-21T00:00:00Z".into(),
            data_dir: destination.to_string_lossy().into_owned(),
            registry_hash: entry.registry_hash.clone(),
            bootnodes: Vec::new(),
            hyperspace: String::new(),
            pending_recipe: String::new(),
        };
        spaces_index::save_to(
            &spaces_index::SpacesIndex {
                spaces: vec![other.clone()],
            },
            &index_path,
        )
        .unwrap();

        let error = restore_archive(
            &archive,
            &destination,
            &temp.0.join("restored-cache"),
            &index_path,
            None,
            true,
            None,
        )
        .unwrap_err();
        assert!(error.to_string().contains("overlaps indexed space"));
        assert_eq!(fs::read(destination.join("owner")).unwrap(), b"keep me");
        let index = spaces_index::load_from(&index_path).unwrap();
        assert_eq!(index.spaces.len(), 1);
        assert_eq!(index.spaces[0].id, other.id);
    }

    #[test]
    fn restore_refuses_ancestor_and_descendant_of_an_indexed_data_directory() {
        let temp = TempDir::new("nested-destination");
        let (entry, _data, cache) = fixture(&temp.0);
        let archive = temp.0.join("backup");
        create_archive(&entry, &archive, &cache).unwrap();

        let owned_parent = temp.0.join("owned-parent");
        let owned = owned_parent.join("owned-space");
        fs::create_dir_all(&owned).unwrap();
        fs::write(owned.join("owner"), b"keep me").unwrap();
        let index_path = temp.0.join("spaces.toml");
        let other = SpaceEntry {
            id: hex::encode([0x75; 32]),
            name: "other-nested".into(),
            created_at: "2026-08-21T00:00:00Z".into(),
            data_dir: owned.to_string_lossy().into_owned(),
            registry_hash: entry.registry_hash.clone(),
            bootnodes: Vec::new(),
            hyperspace: String::new(),
            pending_recipe: String::new(),
        };
        spaces_index::save_to(
            &spaces_index::SpacesIndex {
                spaces: vec![other],
            },
            &index_path,
        )
        .unwrap();

        for destination in [owned.join("nested-a"), owned_parent.clone()] {
            let error = restore_archive(
                &archive,
                &destination,
                &temp.0.join("restored-cache"),
                &index_path,
                None,
                true,
                None,
            )
            .unwrap_err();
            assert!(error.to_string().contains("overlaps indexed space"));
        }
        assert_eq!(fs::read(owned.join("owner")).unwrap(), b"keep me");
    }

    #[test]
    fn concurrent_restores_preserve_both_index_entries() {
        let temp = TempDir::new("concurrent-index");
        let (first, _first_data, first_cache) = fixture(&temp.0.join("first"));
        let (mut second, _second_data, second_cache) = fixture(&temp.0.join("second"));
        second.id = hex::encode([0x74; 32]);
        second.name = "second-backup".into();
        let first_archive = temp.0.join("first-backup");
        let second_archive = temp.0.join("second-backup");
        create_archive(&first, &first_archive, &first_cache).unwrap();
        create_archive(&second, &second_archive, &second_cache).unwrap();

        let index = temp.0.join("spaces.toml");
        let first_destination = temp.0.join("first-restored");
        let second_destination = temp.0.join("second-restored");
        let first_cache = temp.0.join("first-restored-cache");
        let second_cache = temp.0.join("second-restored-cache");
        let first_index = index.clone();
        let second_index = index.clone();
        let first_join = std::thread::spawn(move || {
            restore_archive(
                &first_archive,
                &first_destination,
                &first_cache,
                &first_index,
                None,
                false,
                None,
            )
        });
        let second_join = std::thread::spawn(move || {
            restore_archive(
                &second_archive,
                &second_destination,
                &second_cache,
                &second_index,
                None,
                false,
                None,
            )
        });
        first_join.join().unwrap().unwrap();
        second_join.join().unwrap().unwrap();

        let index = spaces_index::load_from(&index).unwrap();
        assert_eq!(index.spaces.len(), 2);
        assert!(index.spaces.iter().any(|entry| entry.id == first.id));
        assert!(index.spaces.iter().any(|entry| entry.id == second.id));
    }

    #[test]
    fn structurally_incomplete_archive_is_rejected() {
        let temp = TempDir::new("incomplete");
        let (entry, _data, _cache) = fixture(&temp.0);
        let archive = temp.0.join("backup");
        fs::create_dir_all(archive.join("data")).unwrap();
        fs::create_dir_all(archive.join("blobs")).unwrap();
        fs::write(
            archive.join(MANIFEST_FILE),
            serde_json::to_vec_pretty(&BackupManifest {
                format: ARCHIVE_FORMAT.into(),
                version: ARCHIVE_VERSION,
                space: entry,
                files: Vec::new(),
            })
            .unwrap(),
        )
        .unwrap();
        let error = verify_archive(&archive).unwrap_err();
        assert!(error.to_string().contains("structurally incomplete"));
    }

    #[cfg(unix)]
    #[test]
    fn archive_data_and_blob_roots_must_not_be_symlinks() {
        use std::os::unix::fs::symlink;

        for prefix in ["data", "blobs"] {
            let temp = TempDir::new(&format!("root-symlink-{prefix}"));
            let (entry, _data, cache) = fixture(&temp.0);
            let archive = temp.0.join("backup");
            create_archive(&entry, &archive, &cache).unwrap();
            let root = archive.join(prefix);
            let external = temp.0.join(format!("external-{prefix}"));
            fs::rename(&root, &external).unwrap();
            symlink(&external, &root).unwrap();
            let error = verify_archive(&archive).unwrap_err();
            assert!(error.to_string().contains("must be a real directory"));
        }
    }

    #[test]
    fn bare_relative_backup_and_restore_paths_have_a_real_parent() {
        let temp = TempDir::new("relative-parent");
        let (_entry, data, cache) = fixture(&temp.0);
        assert_eq!(usable_parent(Path::new("backup-dir")), Path::new("."));
        reject_nested_output(Path::new("backup-dir"), &data, &cache).unwrap();
        reject_restore_overlap(&temp.0, Path::new("restored-dir")).unwrap();
    }
}
