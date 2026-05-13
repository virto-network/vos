//! Operator identity for `vosx` client invocations.
//!
//! Sprint 2 prerequisite: the daemon needs a stable caller
//! identity to consult its `members` ACL table against. Without
//! persistence every `vosx` invocation generated a fresh
//! ephemeral keypair (see `commands/space/client.rs`), so the
//! daemon couldn't tell two calls from the same operator apart.
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
//! Per-space identities (a.k.a. "multi-persona") are sketched in
//! `project_identity_devices.md` and stay out of Sprint 2's
//! scope; the auth check trusts the PeerId, and the registry's
//! `members` table is the source of truth for what that PeerId
//! is allowed to do.

use std::path::Path;

use libp2p::identity::Keypair;

use crate::paths;

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
    match std::fs::read(path) {
        Ok(bytes) => Keypair::from_protobuf_encoding(&bytes)
            .map_err(|e| anyhow::anyhow!("decode identity at {}: {e}", path.display())),
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => create_at(path),
        Err(e) => Err(anyhow::anyhow!("read {}: {e}", path.display())),
    }
}

/// Always-create variant. Overwrites any existing file at
/// `path` — use sparingly; the typical entry point is
/// [`load_or_create`].
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
#[allow(dead_code)] // wired in the Sprint 2 `space members` CLI commit.
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
            // Best-effort cleanup of the per-test scratch dir. The
            // earlier version removed `.parent()` which is /tmp —
            // collateral damage across tests in the same suite.
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
        let err = load_or_create_at(&path).expect_err("corrupt file should error");
        let msg = format!("{err}");
        assert!(
            msg.contains("decode identity"),
            "error should mention decode, got: {msg}"
        );
    }
}
