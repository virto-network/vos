// Phase 1 will exercise every public symbol; until then the
// module is loaded but unused.
#![allow(dead_code)]

//! Standard filesystem layout for `vosx` state.
//!
//! ```text
//! ~/.local/share/vosx/<space_id>/    # per-space state
//!   node.key                          # libp2p keypair (per-space)
//!   agents/{svc_id:08x}.redb         # per-agent CRDT/Raft databases
//!   trash/{instance_name}/           # uninstalled-but-recoverable agent state
//!   local.toml                        # user overrides (subscriptions, listen addr)
//!
//! ~/.config/vosx/spaces.toml          # known-spaces index
//! ~/.cache/vosx/blobs/{hex_hash}     # cross-space blob cache (see blob_store)
//! ```
//!
//! All path helpers are pure — they don't create directories.
//! Callers create what they need.

use std::path::PathBuf;

/// Hex-format a 32-byte space id for use as a path segment.
pub fn space_id_hex(id: &[u8; 32]) -> String {
    hex::encode(id)
}

/// Base data directory: `$XDG_DATA_HOME/vosx` or
/// `~/.local/share/vosx`.
pub fn data_root() -> PathBuf {
    let base = std::env::var_os("XDG_DATA_HOME")
        .map(PathBuf::from)
        .or_else(|| std::env::var_os("HOME").map(|h| PathBuf::from(h).join(".local").join("share")))
        .unwrap_or_else(|| PathBuf::from(".local").join("share"));
    base.join("vosx")
}

/// Per-space data directory.
pub fn space_dir(space_id: &[u8; 32]) -> PathBuf {
    data_root().join(space_id_hex(space_id))
}

/// Per-space libp2p keypair file. Identities are per-space by
/// default — different keypair per space prevents cross-space
/// linkability of the same node.
pub fn node_key_path(space_id: &[u8; 32]) -> PathBuf {
    space_dir(space_id).join("node.key")
}

/// Per-space agents subdirectory (one redb per agent).
pub fn agents_dir(space_id: &[u8; 32]) -> PathBuf {
    space_dir(space_id).join("agents")
}

/// Path for a specific agent's redb database. `svc_id` is the
/// 32-bit ServiceId.
pub fn agent_db_path(space_id: &[u8; 32], svc_id: u32) -> PathBuf {
    agents_dir(space_id).join(format!("{svc_id:08x}.redb"))
}

/// Trash subdirectory — `space uninstall` moves an agent's
/// data here instead of deleting, so `--undo` can recover.
pub fn trash_dir(space_id: &[u8; 32]) -> PathBuf {
    space_dir(space_id).join("trash")
}

/// User-local override file: subscriptions, listen addr, etc.
pub fn local_config_path(space_id: &[u8; 32]) -> PathBuf {
    space_dir(space_id).join("local.toml")
}

/// Config directory: `$XDG_CONFIG_HOME/vosx` or `~/.config/vosx`.
pub fn config_root() -> PathBuf {
    let base = std::env::var_os("XDG_CONFIG_HOME")
        .map(PathBuf::from)
        .or_else(|| std::env::var_os("HOME").map(|h| PathBuf::from(h).join(".config")))
        .unwrap_or_else(|| PathBuf::from(".config"));
    base.join("vosx")
}

/// Known-spaces index: TOML file listing every space the user
/// has interacted with — fed by `space new` / `space join`,
/// read by `space list`.
pub fn spaces_index_path() -> PathBuf {
    config_root().join("spaces.toml")
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn space_id_hex_is_64_chars() {
        let id = [0xABu8; 32];
        let s = space_id_hex(&id);
        assert_eq!(s.len(), 64);
        assert_eq!(s, "ab".repeat(32));
    }

    #[test]
    fn paths_compose_under_space_dir() {
        let id = [0u8; 32];
        let space = space_dir(&id);
        assert!(node_key_path(&id).starts_with(&space));
        assert!(agents_dir(&id).starts_with(&space));
        assert!(agent_db_path(&id, 0xC0DE).starts_with(&space));
        assert!(trash_dir(&id).starts_with(&space));
        assert!(local_config_path(&id).starts_with(&space));
    }

    #[test]
    fn agent_db_filename_uses_padded_hex() {
        let id = [0u8; 32];
        let p = agent_db_path(&id, 0x1234);
        let name = p.file_name().unwrap().to_str().unwrap();
        assert_eq!(name, "00001234.redb");
    }

    #[test]
    fn data_and_config_roots_diverge() {
        // Data ≠ config; we don't want them collapsing to the
        // same directory when XDG vars are unset.
        assert_ne!(data_root(), config_root());
    }
}
