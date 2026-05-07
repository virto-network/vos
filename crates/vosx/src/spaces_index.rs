//! `~/.config/vosx/spaces.toml` — the user's known-spaces index.
//!
//! One entry per space the user has created or joined. Read by
//! `space list`, written by `space new` / `space join`. Lives in
//! `$XDG_CONFIG_HOME` so it follows the user across machines that
//! sync configs (it's metadata, not data — the per-space agent
//! redbs in `data_root()` are the substantive state).

use serde::{Deserialize, Serialize};
use std::fs;
use std::io;
use std::path::Path;

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
    /// libp2p multiaddrs the local node listens on for this space.
    /// Empty when the space is local-only.
    #[serde(default)]
    pub listen: Vec<String>,
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
    /// libp2p multiaddrs to dial on `space up`. Set by
    /// `space join`; `space new` leaves it empty.
    #[serde(default)]
    pub bootnodes: Vec<String>,
}

impl SpaceEntry {
    /// Decode the hex id back to bytes. Used by Phase 1b/1c to
    /// re-derive the per-space data dir for `space up` / `space
    /// join`.
    #[allow(dead_code)]
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
}

impl core::fmt::Display for IndexError {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        match self {
            IndexError::Io(e) => write!(f, "spaces index i/o: {e}"),
            IndexError::Decode(e) => write!(f, "spaces index decode: {e}"),
            IndexError::Encode(e) => write!(f, "spaces index encode: {e}"),
            IndexError::NotFound(s) => write!(f, "no space matching '{s}' in index"),
        }
    }
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

/// Write the index, creating parent directories as needed.
pub fn save(index: &SpacesIndex) -> Result<(), IndexError> {
    save_to(index, &spaces_index_path())
}

pub fn save_to(index: &SpacesIndex, path: &Path) -> Result<(), IndexError> {
    if let Some(parent) = path.parent() {
        fs::create_dir_all(parent)?;
    }
    let body = toml::to_string_pretty(index).map_err(IndexError::Encode)?;
    fs::write(path, body).map_err(IndexError::Io)
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
/// from the space_id.
pub fn entry_for(id_bytes: &[u8; 32], name: &str, listen: Vec<String>) -> SpaceEntry {
    let id = space_id_hex(id_bytes);
    let data_dir = crate::paths::space_dir(id_bytes)
        .to_string_lossy()
        .to_string();
    SpaceEntry {
        id,
        name: name.to_string(),
        created_at: now_iso8601(),
        listen,
        data_dir,
        registry_hash: String::new(),
        bootnodes: Vec::new(),
    }
}

fn now_iso8601() -> String {
    let now = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0);
    // Truly tiny formatter — yyyy-mm-ddThh:mm:ssZ in UTC.
    // Avoids pulling chrono just for one field.
    let secs = now;
    let days = secs / 86_400;
    let secs_of_day = secs % 86_400;
    let h = secs_of_day / 3600;
    let m = (secs_of_day % 3600) / 60;
    let s = secs_of_day % 60;
    let (y, mo, d) = days_to_ymd(days as i64);
    format!("{y:04}-{mo:02}-{d:02}T{h:02}:{m:02}:{s:02}Z")
}

/// Civil-date conversion (proleptic Gregorian) — same as the
/// algorithm in `time` v0.3 minus the dependency. Days since
/// 1970-01-01 → (y, mo, d).
fn days_to_ymd(days_since_epoch: i64) -> (i64, u32, u32) {
    // Convert epoch days to days-since-0000-03-01.
    let days = days_since_epoch + 719_468;
    let era = days.div_euclid(146_097);
    let doe = days.rem_euclid(146_097) as u64;
    let yoe = (doe - doe / 1460 + doe / 36524 - doe / 146_096) / 365;
    let y = yoe as i64 + era * 400;
    let doy = doe - (365 * yoe + yoe / 4 - yoe / 100);
    let mp = (5 * doy + 2) / 153;
    let d = (doy - (153 * mp + 2) / 5 + 1) as u32;
    let m = if mp < 10 { mp + 3 } else { mp - 9 } as u32;
    let y = if m <= 2 { y + 1 } else { y };
    (y, m, d)
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
                listen: vec!["/ip4/127.0.0.1/tcp/4811".into()],
                data_dir: "/tmp/data".into(),
                registry_hash: String::new(),
                bootnodes: Vec::new(),
            },
        );
        save_to(&idx, &p).unwrap();
        let back = load_from(&p).unwrap();
        assert_eq!(back.spaces.len(), 1);
        assert_eq!(back.spaces[0].name, "demo");
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
                listen: vec![],
                data_dir: "".into(),
                registry_hash: String::new(),
                bootnodes: Vec::new(),
            },
        );
        upsert(
            &mut idx,
            SpaceEntry {
                id: id.clone(),
                name: "v2".into(),
                created_at: "y".into(),
                listen: vec![],
                data_dir: "".into(),
                registry_hash: String::new(),
                bootnodes: Vec::new(),
            },
        );
        assert_eq!(idx.spaces.len(), 1);
        assert_eq!(idx.spaces[0].name, "v2");
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
                listen: vec![],
                data_dir: "".into(),
                registry_hash: String::new(),
                bootnodes: Vec::new(),
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
        let entry = entry_for(&id, "demo", vec![]);
        assert!(entry.data_dir.contains(&space_id_hex(&id)));
    }

}
