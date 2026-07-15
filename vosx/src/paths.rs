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

/// Resolve `$<env_var>/vosx` if the env var is set, else
/// `$HOME/<home_relative>/vosx`, else fall back to a relative
/// path. Used by the XDG-style `data_root` / `config_root` /
/// `cache_root` helpers below.
fn xdg_root(env_var: &str, home_relative: &[&str]) -> PathBuf {
    let from_home = || {
        std::env::var_os("HOME").map(|h| {
            home_relative
                .iter()
                .fold(PathBuf::from(h), |p, s| p.join(s))
        })
    };
    let base = std::env::var_os(env_var)
        .map(PathBuf::from)
        .or_else(from_home)
        .unwrap_or_else(|| home_relative.iter().fold(PathBuf::new(), |p, s| p.join(s)));
    base.join("vosx")
}

/// Base data directory: `$XDG_DATA_HOME/vosx` or
/// `~/.local/share/vosx`.
pub fn data_root() -> PathBuf {
    xdg_root("XDG_DATA_HOME", &[".local", "share"])
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
    xdg_root("XDG_CONFIG_HOME", &[".config"])
}

/// Cache directory: `$XDG_CACHE_HOME/vosx` or `~/.cache/vosx`.
/// The blob store extends this further with `/blobs`.
pub fn cache_root() -> PathBuf {
    xdg_root("XDG_CACHE_HOME", &[".cache"])
}

/// Blob cache: `cache_root()/blobs`. Cross-space — two spaces
/// installing the same program share storage.
pub fn blob_cache_dir() -> PathBuf {
    cache_root().join("blobs")
}

/// Known-spaces index: TOML file listing every space the user
/// has interacted with — fed by `space new` / `space up <token>`,
/// read by `space list`.
pub fn spaces_index_path() -> PathBuf {
    config_root().join("spaces.toml")
}

/// Operator's persistent libp2p keypair, shared across every
/// `vosx` client invocation from this shell user. Used by
/// Sprint 2's daemon-auth path: the daemon recognises the same
/// PeerId across calls and consults its `members` allow-list.
/// Persistence is per-config-home; an operator with multiple
/// machines / containers gets multiple identities.
pub fn client_identity_path() -> PathBuf {
    config_root().join("identity.key")
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
