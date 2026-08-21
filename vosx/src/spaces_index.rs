//! `~/.config/vosx/spaces.toml` — the user's known-spaces index.
//!
//! One entry per space the user has created or joined. Read by
//! `space list`, written by `space new` / `space up <token>`. Lives in
//! `$XDG_CONFIG_HOME` so it follows the user across machines that
//! sync configs (it's metadata, not data — the per-space agent
//! redbs in `data_root()` are the substantive state).

use serde::{Deserialize, Serialize};
use std::fs::{self, File, OpenOptions};
use std::io::{self, Write};
use std::ops::{Deref, DerefMut};
use std::path::{Path, PathBuf};

use fs2::FileExt;

use crate::paths::{space_id_hex, spaces_index_path};

#[derive(Serialize, Deserialize, Debug, Clone, Default)]
pub struct SpacesIndex {
    #[serde(default, rename = "space")]
    pub spaces: Vec<SpaceEntry>,
}

#[derive(Serialize, Deserialize, Debug, Clone)]
pub struct SpaceEntry {
    /// 64-character hex-encoded space_id.
    pub id: String,
    /// User-given short name for the space.
    pub name: String,
    /// ISO-8601 timestamp of when this entry was first added.
    pub created_at: String,
    /// Where this entry's per-space data lives. Defaults to
    /// `data_root()/<id>` but may be overridden by `--data-dir`.
    #[serde(default)]
    pub data_dir: String,
    /// Hex-encoded blake2b-256 hash of the space-registry actor
    /// blob. Resolved at `space new` time and looked up in the
    /// blob cache on subsequent `space up`. Empty until the
    /// space has been initialized.
    #[serde(default)]
    pub registry_hash: String,
    /// libp2p multiaddrs to dial on `space up`. Set by `space up
    /// <token>` (join-if-needed, from the token's bootnodes); `space
    /// new` leaves it empty.
    #[serde(default)]
    pub bootnodes: Vec<String>,
    /// Hyperspace (federation) name this space belongs to, if any.
    /// Persisted at the first recipe apply that declares `hyperspace =
    /// "…"` so a later bare `space up` re-attaches the space to the
    /// federation instead of silently detaching it. Empty when the space
    /// is not a hyperspace member.
    #[serde(default)]
    pub hyperspace: String,
    /// An absolute recipe-TOML path awaiting a one-shot genesis apply.
    /// Set by `space up <recipe>` / `space new --recipe`; consumed on
    /// the next boot (agents → registry, node-local → local.toml) and
    /// cleared. Empty = nothing pending. The alias reads entries written
    /// before the recipe-vocabulary rename.
    #[serde(default, alias = "pending_manifest")]
    pub pending_recipe: String,
}

/// Cross-process serialization for read-modify-write changes to one spaces
/// index. The lock uses a stable sibling inode because the index itself may be
/// replaced atomically while the guard is held.
pub(crate) struct ExclusiveIndexLock {
    _file: File,
}

impl ExclusiveIndexLock {
    pub(crate) fn acquire(path: &Path) -> Result<Self, IndexError> {
        let lock_path = index_lock_path(path)?;
        if let Some(parent) = usable_parent(&lock_path) {
            fs::create_dir_all(parent)?;
        }
        let file = OpenOptions::new()
            .read(true)
            .write(true)
            .create(true)
            .truncate(false)
            .open(&lock_path)?;
        FileExt::lock_exclusive(&file)?;
        Ok(Self { _file: file })
    }
}

/// The only runtime read-modify-write boundary for `spaces.toml`.
///
/// Holding the guard across both load and atomic save prevents a concurrent
/// creator, invite join, recipe update, restore, or forget from replacing a
/// newer index with a stale snapshot.
pub(crate) struct LockedSpacesIndex {
    _lock: ExclusiveIndexLock,
    path: PathBuf,
    index: SpacesIndex,
}

impl LockedSpacesIndex {
    pub(crate) fn acquire() -> Result<Self, IndexError> {
        Self::acquire_from(&spaces_index_path())
    }

    pub(crate) fn acquire_from(path: &Path) -> Result<Self, IndexError> {
        let lock = ExclusiveIndexLock::acquire(path)?;
        let index = load_from(path)?;
        Ok(Self {
            _lock: lock,
            path: path.to_path_buf(),
            index,
        })
    }

    pub(crate) fn validate_upsert(&self, candidate: &SpaceEntry) -> Result<(), IndexError> {
        validate_upsert(&self.index, candidate)
    }

    pub(crate) fn save(self) -> Result<(), IndexError> {
        validate_data_directories(&self.index)?;
        save_to_atomically(&self.index, &self.path)
    }
}

impl Deref for LockedSpacesIndex {
    type Target = SpacesIndex;

    fn deref(&self) -> &Self::Target {
        &self.index
    }
}

impl DerefMut for LockedSpacesIndex {
    fn deref_mut(&mut self) -> &mut Self::Target {
        &mut self.index
    }
}

fn index_lock_path(path: &Path) -> Result<PathBuf, IndexError> {
    let file_name = path.file_name().ok_or_else(|| {
        IndexError::Io(io::Error::new(
            io::ErrorKind::InvalidInput,
            "spaces index path needs a final component",
        ))
    })?;
    Ok(path.with_file_name(format!(".{}.lock", file_name.to_string_lossy())))
}

fn usable_parent(path: &Path) -> Option<&Path> {
    path.parent()
        .filter(|parent| !parent.as_os_str().is_empty())
}

impl SpaceEntry {
    /// Decode the hex id back to bytes — used by `space up`
    /// to re-derive the per-space replication id and verify
    /// genesis.
    pub fn id_bytes(&self) -> Option<[u8; 32]> {
        let v = hex::decode(&self.id).ok()?;
        if v.len() != 32 {
            return None;
        }
        let mut out = [0u8; 32];
        out.copy_from_slice(&v);
        Some(out)
    }
}

#[derive(Debug)]
pub enum IndexError {
    Io(io::Error),
    Decode(toml::de::Error),
    Encode(toml::ser::Error),
    NotFound(String),
    Conflict(String),
}

impl core::fmt::Display for IndexError {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        match self {
            IndexError::Io(e) => write!(f, "spaces index i/o: {e}"),
            IndexError::Decode(e) => write!(f, "spaces index decode: {e}"),
            IndexError::Encode(e) => write!(f, "spaces index encode: {e}"),
            IndexError::NotFound(s) => write!(f, "no space matching '{s}' in index"),
            IndexError::Conflict(s) => write!(f, "spaces index conflict: {s}"),
        }
    }
}

fn validate_upsert(index: &SpacesIndex, candidate: &SpaceEntry) -> Result<(), IndexError> {
    for existing in &index.spaces {
        if existing.id == candidate.id {
            if !paths_equal(
                Path::new(&existing.data_dir),
                Path::new(&candidate.data_dir),
            )? {
                return Err(IndexError::Conflict(format!(
                    "space {} is already indexed at {}; restore or update it there",
                    candidate.id, existing.data_dir,
                )));
            }
            continue;
        }
        if existing.name == candidate.name {
            return Err(IndexError::Conflict(format!(
                "another indexed space already uses name '{}'",
                candidate.name,
            )));
        }
        if paths_overlap(
            Path::new(&existing.data_dir),
            Path::new(&candidate.data_dir),
        )? {
            return Err(IndexError::Conflict(format!(
                "data directory {} overlaps indexed space '{}' ({}) at {}",
                candidate.data_dir, existing.name, existing.id, existing.data_dir,
            )));
        }
    }
    Ok(())
}

fn validate_data_directories(index: &SpacesIndex) -> Result<(), IndexError> {
    for (position, left) in index.spaces.iter().enumerate() {
        for right in &index.spaces[position + 1..] {
            if paths_overlap(Path::new(&left.data_dir), Path::new(&right.data_dir))? {
                return Err(IndexError::Conflict(format!(
                    "data directories for '{}' ({}) and '{}' ({}) overlap",
                    left.name, left.data_dir, right.name, right.data_dir,
                )));
            }
        }
    }
    Ok(())
}

fn paths_equal(left: &Path, right: &Path) -> Result<bool, IndexError> {
    Ok(normalized_absolute(left)? == normalized_absolute(right)?)
}

fn paths_overlap(left: &Path, right: &Path) -> Result<bool, IndexError> {
    let left = normalized_absolute(left)?;
    let right = normalized_absolute(right)?;
    Ok(left.starts_with(&right) || right.starts_with(&left))
}

fn normalized_absolute(path: &Path) -> Result<PathBuf, IndexError> {
    if path.as_os_str().is_empty() {
        return Err(IndexError::Conflict(
            "space data directory cannot be empty".into(),
        ));
    }
    let absolute = lexical_absolute(path)?;
    let mut existing = absolute.as_path();
    let mut suffix = Vec::new();
    loop {
        match fs::symlink_metadata(existing) {
            Ok(_) => break,
            Err(error) if error.kind() == io::ErrorKind::NotFound => {
                let file_name = existing.file_name().ok_or_else(|| {
                    IndexError::Conflict(format!(
                        "data directory has no existing ancestor: {}",
                        path.display(),
                    ))
                })?;
                suffix.push(file_name.to_os_string());
                existing = existing.parent().ok_or_else(|| {
                    IndexError::Conflict(format!(
                        "data directory has no existing ancestor: {}",
                        path.display(),
                    ))
                })?;
            }
            Err(error) => return Err(IndexError::Io(error)),
        }
    }
    let mut normalized = fs::canonicalize(existing)?;
    for component in suffix.into_iter().rev() {
        normalized.push(component);
    }
    Ok(normalized)
}

fn lexical_absolute(path: &Path) -> Result<PathBuf, IndexError> {
    let absolute = if path.is_absolute() {
        path.to_path_buf()
    } else {
        std::env::current_dir()?.join(path)
    };
    let mut normalized = PathBuf::new();
    for component in absolute.components() {
        match component {
            std::path::Component::CurDir => {}
            std::path::Component::ParentDir => {
                normalized.pop();
            }
            std::path::Component::Prefix(_)
            | std::path::Component::RootDir
            | std::path::Component::Normal(_) => normalized.push(component.as_os_str()),
        }
    }
    Ok(normalized)
}

impl std::error::Error for IndexError {}

impl From<io::Error> for IndexError {
    fn from(e: io::Error) -> Self {
        IndexError::Io(e)
    }
}

/// Read the index. Missing file → empty index; malformed file
/// errors loudly so the user can fix it.
pub fn load() -> Result<SpacesIndex, IndexError> {
    load_from(&spaces_index_path())
}

pub fn load_from(path: &Path) -> Result<SpacesIndex, IndexError> {
    let bytes = match fs::read(path) {
        Ok(b) => b,
        Err(e) if e.kind() == io::ErrorKind::NotFound => return Ok(SpacesIndex::default()),
        Err(e) => return Err(IndexError::Io(e)),
    };
    let s = String::from_utf8_lossy(&bytes);
    toml::from_str(&s).map_err(IndexError::Decode)
}

/// Test-only raw writer for constructing fixtures. Runtime mutations must use
/// [`LockedSpacesIndex`] so a stale read can never overwrite another writer.
#[cfg(test)]
pub fn save_to(index: &SpacesIndex, path: &Path) -> Result<(), IndexError> {
    if let Some(parent) = path.parent() {
        fs::create_dir_all(parent)?;
    }
    let body = toml::to_string_pretty(index).map_err(IndexError::Encode)?;
    fs::write(path, body).map_err(IndexError::Io)
}

fn save_to_atomically(index: &SpacesIndex, path: &Path) -> Result<(), IndexError> {
    if let Some(parent) = usable_parent(path) {
        fs::create_dir_all(parent)?;
    }
    let body = toml::to_string_pretty(index).map_err(IndexError::Encode)?;
    let file_name = path.file_name().ok_or_else(|| {
        IndexError::Io(io::Error::new(
            io::ErrorKind::InvalidInput,
            "spaces index path needs a final component",
        ))
    })?;
    let mut nonce = [0u8; 8];
    getrandom::getrandom(&mut nonce)
        .map_err(|error| IndexError::Io(io::Error::other(error.to_string())))?;
    let temporary = path.with_file_name(format!(
        ".{}.partial.{}.{}",
        file_name.to_string_lossy(),
        std::process::id(),
        hex::encode(nonce),
    ));
    let mut file = OpenOptions::new()
        .write(true)
        .create_new(true)
        .open(&temporary)?;
    if let Err(error) = file
        .write_all(body.as_bytes())
        .and_then(|()| file.sync_all())
    {
        let _ = fs::remove_file(&temporary);
        return Err(IndexError::Io(error));
    }
    drop(file);
    if let Err(error) = fs::rename(&temporary, path) {
        let _ = fs::remove_file(&temporary);
        return Err(IndexError::Io(error));
    }
    // The file is durable before activation. Directory fsync is best-effort:
    // once rename succeeds, reporting failure could make a caller repeat an
    // already-committed index mutation.
    #[cfg(unix)]
    if let Some(parent) = usable_parent(path)
        && let Ok(directory) = File::open(parent)
    {
        let _ = directory.sync_all();
    }
    Ok(())
}

/// Append a new entry, replacing any existing one with the same
/// `id`.
pub fn upsert(index: &mut SpacesIndex, entry: SpaceEntry) {
    if let Some(slot) = index.spaces.iter_mut().find(|e| e.id == entry.id) {
        *slot = entry;
    } else {
        index.spaces.push(entry);
    }
}

/// Look up by id (full hex) or by name (case-sensitive). Errors
/// if no match or if multiple names collide.
pub fn find<'a>(index: &'a SpacesIndex, query: &str) -> Result<&'a SpaceEntry, IndexError> {
    if let Some(by_id) = index.spaces.iter().find(|e| e.id == query) {
        return Ok(by_id);
    }
    let by_name: Vec<&SpaceEntry> = index.spaces.iter().filter(|e| e.name == query).collect();
    match by_name.len() {
        0 => Err(IndexError::NotFound(query.to_string())),
        1 => Ok(by_name[0]),
        _ => Err(IndexError::NotFound(format!(
            "{query} (matches {} spaces — disambiguate by id)",
            by_name.len()
        ))),
    }
}

/// Construct a fresh entry with a default `data_dir` derived
/// from the space_id. Persistent listen prefs aren't on the
/// entry — they live in `<data_dir>/local.toml` (per-node
/// override, see `subscriptions::LocalConfig`).
pub fn entry_for(id_bytes: &[u8; 32], name: &str) -> SpaceEntry {
    let id = space_id_hex(id_bytes);
    let data_dir = crate::paths::space_dir(id_bytes)
        .to_string_lossy()
        .to_string();
    SpaceEntry {
        id,
        name: name.to_string(),
        created_at: now_iso8601(),
        data_dir,
        registry_hash: String::new(),
        bootnodes: Vec::new(),
        hyperspace: String::new(),
        pending_recipe: String::new(),
    }
}

/// `yyyy-mm-ddThh:mm:ssZ` UTC — bit-identical to the previous
/// handrolled impl, just delegated to the `time` crate so the
/// civil-date math doesn't live in vosx.
fn now_iso8601() -> String {
    const FORMAT: &[time::format_description::FormatItem<'_>] =
        time::macros::format_description!("[year]-[month]-[day]T[hour]:[minute]:[second]Z");
    time::OffsetDateTime::now_utc()
        .format(FORMAT)
        .unwrap_or_else(|_| "1970-01-01T00:00:00Z".to_string())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn tmp_path(label: &str) -> std::path::PathBuf {
        std::env::temp_dir().join(format!(
            "vosx-spaces-test-{label}-{}-{}",
            std::process::id(),
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_nanos(),
        ))
    }

    #[test]
    fn load_missing_file_returns_empty() {
        let p = tmp_path("missing");
        let idx = load_from(&p).unwrap();
        assert!(idx.spaces.is_empty());
    }

    #[test]
    fn save_then_load_roundtrips() {
        let p = tmp_path("rt");
        let mut idx = SpacesIndex::default();
        upsert(
            &mut idx,
            SpaceEntry {
                id: "ab".repeat(32),
                name: "demo".into(),
                created_at: "2026-05-07T00:00:00Z".into(),
                data_dir: "/tmp/data".into(),
                registry_hash: String::new(),
                bootnodes: Vec::new(),
                hyperspace: "bank-federation".into(),
                pending_recipe: String::new(),
            },
        );
        save_to(&idx, &p).unwrap();
        let back = load_from(&p).unwrap();
        assert_eq!(back.spaces.len(), 1);
        assert_eq!(back.spaces[0].name, "demo");
        // Hyperspace membership survives the index round-trip so a bare
        // `space up` re-attaches to the federation.
        assert_eq!(back.spaces[0].hyperspace, "bank-federation");
        let _ = std::fs::remove_file(&p);
    }

    #[test]
    fn missing_hyperspace_field_defaults_empty() {
        // A pre-hyperspace spaces.toml (no `hyperspace` key) must still
        // load — the field is `#[serde(default)]` — with membership
        // treated as "not a hyperspace member".
        let p = tmp_path("nohs");
        std::fs::write(
            &p,
            "[[space]]\nid = \"aa\"\nname = \"old\"\ncreated_at = \"\"\n",
        )
        .unwrap();
        let idx = load_from(&p).unwrap();
        assert_eq!(idx.spaces.len(), 1);
        assert!(idx.spaces[0].hyperspace.is_empty());
        let _ = std::fs::remove_file(&p);
    }

    #[test]
    fn upsert_replaces_by_id() {
        let mut idx = SpacesIndex::default();
        let id = "cd".repeat(32);
        upsert(
            &mut idx,
            SpaceEntry {
                id: id.clone(),
                name: "v1".into(),
                created_at: "x".into(),
                data_dir: "".into(),
                registry_hash: String::new(),
                bootnodes: Vec::new(),
                hyperspace: String::new(),
                pending_recipe: String::new(),
            },
        );
        upsert(
            &mut idx,
            SpaceEntry {
                id: id.clone(),
                name: "v2".into(),
                created_at: "y".into(),
                data_dir: "".into(),
                registry_hash: String::new(),
                bootnodes: Vec::new(),
                hyperspace: String::new(),
                pending_recipe: String::new(),
            },
        );
        assert_eq!(idx.spaces.len(), 1);
        assert_eq!(idx.spaces[0].name, "v2");
    }

    #[test]
    fn locked_writers_reload_after_the_previous_atomic_save() {
        let path = tmp_path("locked-writers");
        let mut first = LockedSpacesIndex::acquire_from(&path).unwrap();
        let first_entry = SpaceEntry {
            id: "11".repeat(32),
            name: "first".into(),
            created_at: "2026-08-21T00:00:00Z".into(),
            data_dir: "/tmp/first".into(),
            registry_hash: String::new(),
            bootnodes: Vec::new(),
            hyperspace: String::new(),
            pending_recipe: String::new(),
        };
        upsert(&mut first, first_entry.clone());

        let second_path = path.clone();
        let (started_tx, started_rx) = std::sync::mpsc::channel();
        let second = std::thread::spawn(move || {
            started_tx.send(()).unwrap();
            let mut index = LockedSpacesIndex::acquire_from(&second_path).unwrap();
            assert!(index.spaces.iter().any(|entry| entry.id == first_entry.id));
            upsert(
                &mut index,
                SpaceEntry {
                    id: "22".repeat(32),
                    name: "second".into(),
                    created_at: "2026-08-21T00:00:00Z".into(),
                    data_dir: "/tmp/second".into(),
                    registry_hash: String::new(),
                    bootnodes: Vec::new(),
                    hyperspace: String::new(),
                    pending_recipe: String::new(),
                },
            );
            index.save().unwrap();
        });
        started_rx.recv().unwrap();
        first.save().unwrap();
        second.join().unwrap();

        let saved = load_from(&path).unwrap();
        assert_eq!(saved.spaces.len(), 2);
        let _ = fs::remove_file(index_lock_path(&path).unwrap());
        let _ = fs::remove_file(path);
    }

    #[test]
    fn find_by_id_or_name() {
        let mut idx = SpacesIndex::default();
        let id_a = "aa".repeat(32);
        upsert(
            &mut idx,
            SpaceEntry {
                id: id_a.clone(),
                name: "alpha".into(),
                created_at: "".into(),
                data_dir: "".into(),
                registry_hash: String::new(),
                bootnodes: Vec::new(),
                hyperspace: String::new(),
                pending_recipe: String::new(),
            },
        );
        assert_eq!(find(&idx, &id_a).unwrap().name, "alpha");
        assert_eq!(find(&idx, "alpha").unwrap().id, id_a);
        assert!(matches!(find(&idx, "nope"), Err(IndexError::NotFound(_))));
    }

    #[test]
    fn now_iso8601_is_well_formed() {
        let s = now_iso8601();
        assert_eq!(s.len(), 20, "expected yyyy-mm-ddThh:mm:ssZ, got {s}");
        assert_eq!(s.chars().nth(4), Some('-'));
        assert_eq!(s.chars().nth(10), Some('T'));
        assert_eq!(s.chars().last(), Some('Z'));
    }

    #[test]
    fn entry_for_uses_default_data_dir() {
        let id = [0xCDu8; 32];
        let entry = entry_for(&id, "demo");
        assert!(entry.data_dir.contains(&space_id_hex(&id)));
    }
}
