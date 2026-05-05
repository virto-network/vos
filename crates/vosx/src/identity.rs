//! libp2p identity loading for vosx.
//!
//! Resolves a `[node].identity` manifest field (or a CLI override)
//! into a `libp2p::identity::Keypair`. Lives in vosx — not vos —
//! because parsing the operator-supplied identity spec is a CLI
//! concern; the PVM-actor runtime never reads it directly.

use std::path::{Path, PathBuf};

use libp2p::identity;
use tracing::info;

/// Resolve the manifest's `[node].identity` field into a libp2p
/// keypair.
///
/// - `None` or `Some("auto")` — derive (or load) a keypair stored
///   at `{data_dir}/node.key`. Persisted across runs so the
///   node's PeerId is stable.
/// - `Some(path)` — load the keypair from that file (protobuf
///   encoding produced by `Keypair::to_protobuf_encoding`).
pub fn load_or_generate_identity(
    spec: Option<&str>,
    data_dir: Option<&Path>,
) -> Result<identity::Keypair, String> {
    match spec {
        Some("auto") | None => {
            let dir = data_dir.unwrap_or(Path::new("."));
            let key_path: PathBuf = dir.join("node.key");
            if key_path.exists() {
                let bytes = std::fs::read(&key_path)
                    .map_err(|e| format!("read {}: {e}", key_path.display()))?;
                identity::Keypair::from_protobuf_encoding(&bytes)
                    .map_err(|e| format!("decode {}: {e}", key_path.display()))
            } else {
                let kp = identity::Keypair::generate_ed25519();
                let bytes = kp
                    .to_protobuf_encoding()
                    .map_err(|e| format!("encode keypair: {e}"))?;
                if !dir.exists() {
                    std::fs::create_dir_all(dir)
                        .map_err(|e| format!("mkdir {}: {e}", dir.display()))?;
                }
                std::fs::write(&key_path, &bytes)
                    .map_err(|e| format!("write {}: {e}", key_path.display()))?;
                info!(path = %key_path.display(), "vosx: generated new node identity");
                Ok(kp)
            }
        }
        Some(path) => {
            let bytes = std::fs::read(path).map_err(|e| format!("read {path}: {e}"))?;
            identity::Keypair::from_protobuf_encoding(&bytes)
                .map_err(|e| format!("decode {path}: {e}"))
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use libp2p::PeerId;

    #[test]
    fn identity_auto_persists_across_calls() {
        let dir = std::env::temp_dir().join(format!(
            "vosx_id_{}_{}",
            std::process::id(),
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_nanos(),
        ));
        std::fs::create_dir_all(&dir).unwrap();

        let k1 = load_or_generate_identity(Some("auto"), Some(&dir)).unwrap();
        let k2 = load_or_generate_identity(Some("auto"), Some(&dir)).unwrap();
        assert_eq!(
            PeerId::from(k1.public()),
            PeerId::from(k2.public()),
            "auto-identity should be stable across loads",
        );

        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn identity_explicit_path_loads_existing_key() {
        let dir = std::env::temp_dir().join(format!(
            "vosx_id_explicit_{}_{}",
            std::process::id(),
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_nanos(),
        ));
        std::fs::create_dir_all(&dir).unwrap();
        let path = dir.join("custom.key");

        // Generate a key, save it manually, then load.
        let kp = identity::Keypair::generate_ed25519();
        let bytes = kp.to_protobuf_encoding().unwrap();
        std::fs::write(&path, &bytes).unwrap();

        let loaded = load_or_generate_identity(Some(path.to_str().unwrap()), None).unwrap();
        assert_eq!(PeerId::from(kp.public()), PeerId::from(loaded.public()));

        let _ = std::fs::remove_dir_all(&dir);
    }
}
