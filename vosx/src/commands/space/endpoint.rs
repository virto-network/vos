//! Per-space "where the daemon is" descriptor.
//!
//! `space up` writes its libp2p multiaddrs + peer-id to
//! `<data_dir>/.endpoint` once the swarm has bound a listen
//! address. Client commands (`publish`, `install`, …) read the
//! file to discover where to dial. The file is deleted on
//! graceful shutdown; if it sticks around after a crash the
//! kernel-released libp2p port still gives the next client a
//! "connection refused" rather than silent corruption.

use std::path::Path;

use serde::{Deserialize, Serialize};

const ENDPOINT_FILE: &str = ".endpoint";

#[derive(Serialize, Deserialize, Debug, Clone)]
pub struct Endpoint {
    /// Daemon's libp2p PeerId, multibase-encoded.
    pub peer_id: String,
    /// Multiaddrs the daemon is listening on. Local-only
    /// spaces typically have a single `/ip4/127.0.0.1/tcp/N`.
    pub multiaddrs: Vec<String>,
    /// Daemon's 16-bit node_prefix — used by clients to
    /// construct the registry ServiceId without re-deriving
    /// from peer_id.
    pub prefix: u16,
    /// PID of the running daemon. Used to spot stale endpoint
    /// files after an ungraceful crash.
    pub pid: u32,
    /// Effective `intra_caps` this daemon loaded for each service
    /// extension, recorded at reconcile time so operators can
    /// inspect them via `space describe` / `space caps` without
    /// scraping the boot log. These are *per-daemon* host policy
    /// (not replicated registry state), which is why they ride the
    /// local endpoint descriptor rather than the registry.
    /// `#[serde(default)]` keeps older `.endpoint` files (and
    /// manifest-less daemons) readable.
    #[serde(default)]
    pub extensions: Vec<ExtensionCaps>,
}

/// One service extension's effective relay capabilities, as the
/// canonical `"actor:role"` tokens (`*` for either wildcard). An
/// empty `caps` means the extension relays every outbound call as
/// `Caller::Unauthenticated` — it has no relay authority.
#[derive(Serialize, Deserialize, Debug, Clone)]
pub struct ExtensionCaps {
    pub name: String,
    pub caps: Vec<String>,
}

pub fn path(data_dir: &Path) -> std::path::PathBuf {
    data_dir.join(ENDPOINT_FILE)
}

pub fn write(data_dir: &Path, endpoint: &Endpoint) -> anyhow::Result<()> {
    let p = path(data_dir);
    let body =
        toml::to_string_pretty(endpoint).map_err(|e| anyhow::anyhow!("encode endpoint: {e}"))?;
    std::fs::write(&p, body).map_err(|e| anyhow::anyhow!("write {}: {e}", p.display()))?;
    Ok(())
}

pub fn read(data_dir: &Path) -> anyhow::Result<Option<Endpoint>> {
    let p = path(data_dir);
    let bytes = match std::fs::read(&p) {
        Ok(b) => b,
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => return Ok(None),
        Err(e) => return Err(anyhow::anyhow!("read {}: {e}", p.display())),
    };
    let s = String::from_utf8_lossy(&bytes);
    let ep: Endpoint =
        toml::from_str(&s).map_err(|e| anyhow::anyhow!("decode {}: {e}", p.display()))?;
    Ok(Some(ep))
}

pub fn delete(data_dir: &Path) {
    let _ = std::fs::remove_file(path(data_dir));
}

/// Quick liveness check: is the recorded PID still alive?
/// Stale endpoint files (left by a crashed daemon) report
/// `false` here so clients can tell the user "no daemon
/// running" instead of timing out on a dead connection.
pub fn is_alive(endpoint: &Endpoint) -> bool {
    // POSIX `kill -0` — sends signal 0, which only checks
    // permissions / existence without actually delivering.
    unsafe { libc::kill(endpoint.pid as libc::pid_t, 0) == 0 }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn roundtrips_with_extension_caps() {
        let ep = Endpoint {
            peer_id: "12D3KooW".into(),
            multiaddrs: vec!["/ip4/127.0.0.1/tcp/4001".into()],
            prefix: 0x00a3,
            pid: 4242,
            extensions: vec![
                ExtensionCaps {
                    name: "dev".into(),
                    caps: vec!["space-registry:admin".into()],
                },
                ExtensionCaps {
                    name: "gateway".into(),
                    caps: vec![], // deny-all relay
                },
            ],
        };
        let s = toml::to_string_pretty(&ep).unwrap();
        let back: Endpoint = toml::from_str(&s).unwrap();
        assert_eq!(back.extensions.len(), 2);
        assert_eq!(back.extensions[0].name, "dev");
        assert_eq!(back.extensions[0].caps, vec!["space-registry:admin"]);
        assert!(back.extensions[1].caps.is_empty());
    }

    #[test]
    fn legacy_endpoint_without_extensions_still_parses() {
        // A `.endpoint` written by a daemon predating the caps field
        // must still load — `#[serde(default)]` fills an empty list so
        // upgrading the binary doesn't strand running spaces.
        let legacy = r#"
            peer_id = "12D3KooW"
            multiaddrs = ["/ip4/127.0.0.1/tcp/4001"]
            prefix = 7
            pid = 99
        "#;
        let ep: Endpoint = toml::from_str(legacy).unwrap();
        assert!(ep.extensions.is_empty());
        assert_eq!(ep.prefix, 7);
    }
}
