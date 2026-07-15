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
    /// Hyperspace (federation) name this space belongs to, if any.
    /// Persisted at the first recipe apply that declares `hyperspace =
    /// "…"` so a later bare `space up` re-attaches the space to the
    /// federation instead of silently detaching it. Empty when the space
    /// is not a hyperspace member.
    #[serde(default)]
    pub hyperspace: String,
    /// A `vos1…` invite token awaiting redemption. Set by `space up
    /// <token>` (join-if-needed) and consumed by the redeem loop in the
    /// boot tick: each pass re-parses it and invokes the bootnode's
    /// `redeem_invite`, clearing it on success. Empty = nothing pending.
    #[serde(default)]
    pub pending_token: String,
    /// An absolute recipe-TOML path awaiting a one-shot genesis apply.
    /// Set by `space up <recipe>` / `space new --manifest`; consumed on
    /// the next boot (agents → registry, node-local → local.toml) and
    /// cleared. Empty = nothing pending.
    #[serde(default)]
    pub pending_manifest: String,
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
        pending_token: String::new(),
        pending_manifest: String::new(),
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
                pending_token: String::new(),
                pending_manifest: String::new(),
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
                pending_token: String::new(),
                pending_manifest: String::new(),
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
                pending_token: String::new(),
                pending_manifest: String::new(),
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
                data_dir: "".into(),
                registry_hash: String::new(),
                bootnodes: Vec::new(),
                hyperspace: String::new(),
                pending_token: String::new(),
                pending_manifest: String::new(),
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
