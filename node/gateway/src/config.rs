//! The gateway's TOML file: its key, its HTTP listener and public TLS, the
//! limits per address, the nodes behind it, and its SSH port.

use std::net::SocketAddr;
use std::path::{Path, PathBuf};

use serde::Deserialize;

use crate::limits::PerAddress;
use crate::upstream::Address;

/// A node behind the gateway, as the file names it.
#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Node {
    /// Its key, in hex.
    pub key: String,
    /// `unix:/path` or `quic://host:port`.
    pub address: String,
}

/// How HTTP serves TLS.
#[derive(Clone, Copy, Debug, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "lowercase")]
pub enum Tls {
    /// A certificate for the gateway's own key, which clients pin.
    Key,
    /// A certificate chain and its key from PEM files, `tls_chain` and
    /// `tls_key`.
    Files,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Config {
    /// The gateway's key's seed file, in hex: made if missing. The nodes
    /// list its public key in `gateways`; its own-key HTTPS presents it.
    pub key: PathBuf,
    /// Where HTTP listens. Without TLS, a loopback address only.
    pub http: SocketAddr,
    pub tls: Option<Tls>,
    /// The names an own-key certificate gives.
    #[serde(default)]
    pub tls_names: Vec<String>,
    pub tls_chain: Option<PathBuf>,
    pub tls_key: Option<PathBuf>,
    /// The most HTTP connections at once, from every address.
    pub connections: Option<usize>,
    pub per_address_connections: Option<usize>,
    pub per_address_rate: Option<u32>,
    pub per_address_burst: Option<u32>,
    /// The nodes behind the gateway.
    pub nodes: Vec<Node>,
    /// Where the SSH port listens, for s4's screens and the `vos-api`
    /// subsystem: none by default.
    pub ssh: Option<SocketAddr>,
    /// The SSH host key, made if missing.
    pub ssh_host_key: Option<PathBuf>,
    /// The s4 app's client key's seed file, made if missing: an ordinary
    /// client key, apart from the gateway's.
    pub app_key: Option<PathBuf>,
}

impl Config {
    pub fn read(path: &Path) -> Result<Self, String> {
        let text = std::fs::read_to_string(path).map_err(|e| format!("{}: {e}", path.display()))?;
        toml::from_str(&text).map_err(|e| format!("{}: {e}", path.display()))
    }

    /// The limits per address, the defaults where the file names none.
    pub fn per_address(&self) -> PerAddress {
        let defaults = PerAddress::default();
        PerAddress {
            connections: self.per_address_connections.unwrap_or(defaults.connections),
            rate: self.per_address_rate.unwrap_or(defaults.rate),
            burst: self.per_address_burst.unwrap_or(defaults.burst),
        }
    }

    /// The nodes, each its key and address.
    pub fn upstreams(&self) -> Result<Vec<([u8; 32], Address)>, String> {
        self.nodes
            .iter()
            .map(|node| Ok((hex32(&node.key)?, Address::parse(&node.address)?)))
            .collect()
    }

    /// HTTP's TLS, for the gateway whose seed is `secret`.
    pub fn http_tls(
        &self,
        secret: &[u8; 32],
    ) -> Result<Option<std::sync::Arc<rustls::ServerConfig>>, String> {
        use vos_http::tls::{IngressTls, server_config};
        let tls = match self.tls {
            None if self.http.ip().is_loopback() => return Ok(None),
            None => {
                return Err(format!(
                    "{}: plain HTTP serves loopback addresses only; give the gateway TLS",
                    self.http
                ));
            }
            Some(Tls::Key) => IngressTls::NodeKey {
                names: self.tls_names.clone(),
            },
            Some(Tls::Files) => IngressTls::Files {
                chain: self
                    .tls_chain
                    .clone()
                    .ok_or("tls = \"files\" needs tls_chain")?,
                key: self
                    .tls_key
                    .clone()
                    .ok_or("tls = \"files\" needs tls_key")?,
            },
        };
        server_config(&tls, secret).map(Some)
    }
}

/// 32 bytes from 64 hex digits.
pub fn hex32(text: &str) -> Result<[u8; 32], String> {
    let bytes = hex::decode(text.trim()).map_err(|error| format!("{text}: {error}"))?;
    bytes
        .try_into()
        .map_err(|_| format!("{text}: not 32 bytes"))
}

/// The seed in the file at `path`, in hex; made at random, readable by its
/// owner only, if there is none.
pub fn seed(path: &Path) -> Result<[u8; 32], String> {
    match std::fs::read_to_string(path) {
        Ok(text) => hex32(&text),
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => {
            use std::io::Write;
            use std::os::unix::fs::OpenOptionsExt;
            let mut seed = [0u8; 32];
            getrandom::getrandom(&mut seed).map_err(|error| error.to_string())?;
            let mut file = std::fs::OpenOptions::new()
                .write(true)
                .create_new(true)
                .mode(0o600)
                .open(path)
                .map_err(|e| format!("{}: {e}", path.display()))?;
            file.write_all(hex::encode(seed).as_bytes())
                .and_then(|()| file.sync_all())
                .map_err(|e| format!("{}: {e}", path.display()))?;
            Ok(seed)
        }
        Err(error) => Err(format!("{}: {error}", path.display())),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_file_names_its_nodes_and_limits() {
        let config: Config = toml::from_str(&format!(
            "key = \"gateway.key\"\nhttp = \"127.0.0.1:8080\"\nper_address_rate = 5\n\
             [[nodes]]\nkey = \"{}\"\naddress = \"unix:/run/vos/api.sock\"\n",
            "ab".repeat(32)
        ))
        .unwrap();
        assert_eq!(
            config.upstreams().unwrap(),
            vec![([0xab; 32], Address::Socket("/run/vos/api.sock".into()))]
        );
        assert_eq!(config.per_address().rate, 5);
        assert_eq!(config.per_address().burst, PerAddress::default().burst);
        assert!(config.http_tls(&[1; 32]).unwrap().is_none());
        let open: Config =
            toml::from_str("key = \"k\"\nhttp = \"0.0.0.0:80\"\nnodes = []\n").unwrap();
        assert!(open.http_tls(&[1; 32]).is_err(), "plain HTTP off loopback");
        assert!(
            toml::from_str::<Config>("key = \"k\"\nhttp = \"0.0.0.0:80\"\nnodes = []\nother = 1\n")
                .is_err()
        );
    }

    #[test]
    fn a_seed_is_made_once() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("gateway.key");
        let made = seed(&path).unwrap();
        assert_eq!(seed(&path).unwrap(), made);
        use std::os::unix::fs::PermissionsExt;
        let mode = std::fs::metadata(&path).unwrap().permissions().mode();
        assert_eq!(mode & 0o777, 0o600);
    }
}
