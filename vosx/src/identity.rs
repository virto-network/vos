//! Operator identity for `vosx` client invocations.
//!
//! The daemon needs a stable caller identity to consult its membership policy.
//!
//! Layout:
//!
//! ```text
//! $XDG_CONFIG_HOME/vosx/identity.key   # libp2p protobuf-encoded ed25519
//! ```
//!
//! Single key per `$XDG_CONFIG_HOME` — an operator's interactive
//! shell, scripts, and CI worker share an identity if they share
//! the config home. Containers / per-persona setups override
//! `XDG_CONFIG_HOME` for separation.
//!
//! The authorization check trusts the PeerId, and the registry is the source
//! of truth for what that PeerId may do.

use std::path::Path;

use libp2p::identity::{KeyType, Keypair};

use crate::paths;

const MAX_IDENTITY_KEY_BYTES: u64 = 4 * 1024;

/// Administrative retries must never create an ambient replacement identity.
pub fn load_existing() -> anyhow::Result<Keypair> {
    let path = paths::client_identity_path();
    let bytes = crate::secure_file::read_owner_only_optional(&path, MAX_IDENTITY_KEY_BYTES)?
        .ok_or_else(|| {
            anyhow::anyhow!("operator identity is missing; refusing to create a replacement")
        })?;
    decode_canonical_ed25519(&path, &bytes)
}

/// Load the operator's persistent client keypair, creating it
/// on first use. Idempotent — every `vosx` command can call
/// this freely.
pub fn load_or_create() -> anyhow::Result<Keypair> {
    let path = paths::client_identity_path();
    load_or_create_at(&path)
}

/// Variant that takes an explicit path. Test-only entry point
/// — production callers go through `load_or_create()` to honour
/// the XDG layout.
pub fn load_or_create_at(path: &Path) -> anyhow::Result<Keypair> {
    if let Some(parent) = path.parent() {
        std::fs::create_dir_all(parent)
            .map_err(|e| anyhow::anyhow!("create {} for identity: {e}", parent.display()))?;
    }
    match crate::secure_file::read_owner_only_optional(path, MAX_IDENTITY_KEY_BYTES)? {
        Some(bytes) => decode_canonical_ed25519(path, &bytes),
        None => create_at(path),
    }
}

fn decode_canonical_ed25519(path: &Path, bytes: &[u8]) -> anyhow::Result<Keypair> {
    let keypair = Keypair::from_protobuf_encoding(bytes)
        .map_err(|e| anyhow::anyhow!("decode identity at {}: {e}", path.display()))?;
    if keypair.key_type() != KeyType::Ed25519 {
        anyhow::bail!("identity at {} must be Ed25519", path.display());
    }
    let canonical = keypair
        .to_protobuf_encoding()
        .map_err(|e| anyhow::anyhow!("canonicalize identity at {}: {e}", path.display()))?;
    if canonical != bytes {
        anyhow::bail!("identity at {} is not canonically encoded", path.display());
    }
    Ok(keypair)
}

/// Always-create variant. Existing paths are rejected; the typical entry
/// point is [`load_or_create`].
fn create_at(path: &Path) -> anyhow::Result<Keypair> {
    let kp = Keypair::generate_ed25519();
    let bytes = kp
        .to_protobuf_encoding()
        .map_err(|e| anyhow::anyhow!("encode identity: {e}"))?;
    // The key file is a long-lived secret — write 0600 on unix
    // so a shared $HOME can't leak it across users. On platforms
    // without unix perms (windows) we fall through to the OS
    // default ACL.
    write_owner_only(path, &bytes)?;
    tracing::info!(path = %path.display(), "created persistent client identity");
    Ok(kp)
}

#[cfg(unix)]
fn write_owner_only(path: &Path, bytes: &[u8]) -> anyhow::Result<()> {
    use std::os::unix::fs::OpenOptionsExt;
    let mut f = std::fs::OpenOptions::new()
        .write(true)
        .create_new(true)
        .mode(0o600)
        .open(path)
        .map_err(|e| anyhow::anyhow!("create {}: {e}", path.display()))?;
    use std::io::Write;
    f.write_all(bytes)
        .map_err(|e| anyhow::anyhow!("write {}: {e}", path.display()))?;
    Ok(())
}

#[cfg(not(unix))]
fn write_owner_only(path: &Path, bytes: &[u8]) -> anyhow::Result<()> {
    std::fs::write(path, bytes).map_err(|e| anyhow::anyhow!("write {}: {e}", path.display()))
}

/// Convenience: format the PeerId for the operator's persistent
/// identity. Surfaced in error messages and `vosx space members`
/// listings.
#[allow(dead_code)]
pub fn peer_id_string() -> anyhow::Result<String> {
    Ok(libp2p::PeerId::from(load_or_create()?.public()).to_string())
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::path::PathBuf;

    struct TempPath(PathBuf);
    impl TempPath {
        fn new(label: &str) -> Self {
            let mut p = std::env::temp_dir();
            let nanos = std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap_or_default()
                .as_nanos();
            p.push(format!(
                "vosx-identity-{}-{}-{}",
                std::process::id(),
                label,
                nanos,
            ));
            TempPath(p)
        }
    }
    impl Drop for TempPath {
        fn drop(&mut self) {
            // Best-effort cleanup is intentionally scoped to this test's
            // scratch directory, never its shared parent.
            let _ = std::fs::remove_dir_all(&self.0);
        }
    }

    #[test]
    fn load_or_create_round_trips() {
        let tmp = TempPath::new("roundtrip");
        let path = tmp.0.join("identity.key");
        let first = load_or_create_at(&path).expect("create");
        let second = load_or_create_at(&path).expect("load");
        // PeerId is the stable handle; the keypair itself
        // doesn't expose Eq.
        let p1 = libp2p::PeerId::from(first.public());
        let p2 = libp2p::PeerId::from(second.public());
        assert_eq!(p1, p2, "second load must yield the same PeerId");
    }

    #[test]
    fn create_writes_owner_only_on_unix() {
        let tmp = TempPath::new("perms");
        let path = tmp.0.join("identity.key");
        let _ = load_or_create_at(&path).expect("create");
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            let meta = std::fs::metadata(&path).expect("stat");
            let mode = meta.permissions().mode() & 0o777;
            assert_eq!(mode, 0o600, "identity must be owner-only readable");
        }
    }

    #[test]
    fn corrupt_file_surfaces_clear_error() {
        let tmp = TempPath::new("corrupt");
        std::fs::create_dir_all(&tmp.0).unwrap();
        let path = tmp.0.join("identity.key");
        std::fs::write(&path, b"not a protobuf").unwrap();
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt as _;
            std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o600)).unwrap();
        }
        let err = load_or_create_at(&path).expect_err("corrupt file should error");
        let msg = format!("{err}");
        assert!(
            msg.contains("decode identity"),
            "error should mention decode, got: {msg}"
        );
    }

    #[cfg(unix)]
    #[test]
    fn existing_identity_with_shared_permissions_is_rejected() {
        use std::os::unix::fs::PermissionsExt as _;

        let tmp = TempPath::new("shared-permissions");
        let path = tmp.0.join("identity.key");
        let _ = load_or_create_at(&path).expect("create");
        std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o640)).unwrap();
        let error = load_or_create_at(&path).expect_err("shared secret must fail closed");
        assert!(error.to_string().contains("permissions must be owner-only"));
    }
}
