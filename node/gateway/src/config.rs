//! The gateway's TOML file: its key, its HTTP listener and public TLS, the
//! limits per address, the nodes behind it, its SSH port, and its onion
//! service.

use std::net::SocketAddr;
use std::path::{Path, PathBuf};

use serde::Deserialize;

use crate::caps::PerPort;
use crate::circuits::PerCircuit;
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
    /// The space file of the nodes' space: each of its nodes must be among
    /// `nodes`, as a home's gateways list every node (`light-node.md`
    /// §3.3), or the gateway does not start.
    pub space: Option<PathBuf>,
    /// Where the SSH port listens, for s4's screens and the `vos-api`
    /// subsystem: none by default.
    pub ssh: Option<SocketAddr>,
    /// The SSH host key, made if missing.
    pub ssh_host_key: Option<PathBuf>,
    /// The s4 app's client key's seed file, made if missing: an ordinary
    /// client key, apart from the gateway's.
    pub app_key: Option<PathBuf>,
    /// The demo's agent and its actors, whose screens the SSH port serves.
    #[cfg(feature = "ssh")]
    pub demo: Option<crate::demo::Demo>,
    /// The onion service: the same HTTP and, with an SSH port, SSH, and
    /// nothing else.
    pub onion: Option<Onion>,
}

/// The onion service (`light-node.md` §6.1, §6.6): arti in process (the
/// `tor` feature), or a C tor beside the gateway forwarding to loopback
/// listeners; and what its circuits and calls may take.
#[derive(Clone, Debug, Default, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Onion {
    /// arti's state directory, whose keystore holds the onion's key once
    /// the gateway inserted it.
    pub state: Option<PathBuf>,
    /// arti's directory cache.
    pub cache: Option<PathBuf>,
    /// The onion's key's seed file, in hex, made if missing: its address
    /// is the key's.
    pub key: Option<PathBuf>,
    /// arti's service-side proof of work, which a release has not yet
    /// declared ready: the `tor-pow` feature, off by default.
    #[serde(default)]
    pub pow: bool,
    /// Introduction points, 3 by default.
    pub intro_points: Option<u8>,
    /// The introductions a second the introduction points pass on, and
    /// their burst, for them to enforce; the consensus's by default.
    pub intro_rate: Option<u32>,
    pub intro_burst: Option<u32>,
    /// A C tor beside the gateway in place of arti: the loopback listeners
    /// its `HiddenServicePort 22` and `80` forward to, with
    /// `HiddenServiceExportCircuitID haproxy`.
    pub sidecar_ssh: Option<SocketAddr>,
    pub sidecar_http: Option<SocketAddr>,
    /// Streams open at once on one circuit.
    pub circuit_streams: Option<usize>,
    /// Circuits held at once.
    pub circuits: Option<usize>,
    /// HTTP connections and SSH channels at once from one circuit, and its
    /// requests a second with a burst.
    pub circuit_connections: Option<usize>,
    pub circuit_rate: Option<u32>,
    pub circuit_burst: Option<u32>,
    /// Proven calls in flight through the onion, and from one connection.
    pub proven: Option<usize>,
    pub proven_per_connection: Option<usize>,
    /// An agent's calls a second from one circuit, and their burst.
    pub agent_rate: Option<u32>,
    pub agent_burst: Option<u32>,
}

/// What one circuit may take by default, as an address would: fewer
/// connections and requests than an address, since a client opens
/// circuits at will.
pub const PER_CIRCUIT: PerAddress = PerAddress {
    connections: 4,
    rate: 20,
    burst: 40,
};

impl Onion {
    /// Whether a C tor serves it, not arti.
    pub fn sidecar(&self) -> bool {
        self.sidecar_ssh.is_some() || self.sidecar_http.is_some()
    }

    pub fn per_circuit(&self) -> PerCircuit {
        let defaults = PerCircuit::default();
        PerCircuit {
            streams: self.circuit_streams.unwrap_or(defaults.streams),
            circuits: self.circuits.unwrap_or(defaults.circuits),
        }
    }

    /// The limits each circuit counts as an address.
    pub fn limits(&self) -> PerAddress {
        PerAddress {
            connections: self.circuit_connections.unwrap_or(PER_CIRCUIT.connections),
            rate: self.circuit_rate.unwrap_or(PER_CIRCUIT.rate),
            burst: self.circuit_burst.unwrap_or(PER_CIRCUIT.burst),
        }
    }

    pub fn caps(&self) -> PerPort {
        let defaults = PerPort::default();
        PerPort {
            proven: self.proven.unwrap_or(defaults.proven),
            proven_per_connection: self
                .proven_per_connection
                .unwrap_or(defaults.proven_per_connection),
            agent_rate: self.agent_rate.unwrap_or(defaults.agent_rate),
            agent_burst: self.agent_burst.unwrap_or(defaults.agent_burst),
        }
    }
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

    /// Refused: a space file naming a node the gateway does not list, and
    /// an onion both arti's and a C tor's.
    pub fn check(&self) -> Result<(), String> {
        if let Some(space) = &self.space {
            let listed: Vec<[u8; 32]> = self.upstreams()?.into_iter().map(|(key, _)| key).collect();
            let text = std::fs::read_to_string(space)
                .map_err(|error| format!("{}: {error}", space.display()))?;
            for key in space_keys(&text).map_err(|error| format!("{}: {error}", space.display()))? {
                if !listed.contains(&key) {
                    return Err(format!(
                        "{}: node {} is not among the gateway's nodes: list every node of the space",
                        space.display(),
                        hex::encode(key)
                    ));
                }
            }
        }
        if let Some(onion) = &self.onion
            && onion.sidecar()
            && (onion.state.is_some() || onion.cache.is_some() || onion.key.is_some() || onion.pow)
        {
            return Err("an onion is arti's (state, cache, key, pow) or a C tor's (sidecar_ssh, sidecar_http), not both".into());
        }
        Ok(())
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

/// The node keys a space file names: one node a line, its key the second
/// of four fields; a `#` starts a comment.
pub fn space_keys(text: &str) -> Result<Vec<[u8; 32]>, String> {
    text.lines()
        .enumerate()
        .filter_map(|(line, content)| {
            let content = content.split('#').next().unwrap_or_default().trim();
            (!content.is_empty()).then_some((line, content))
        })
        .map(|(line, content)| {
            let fields: Vec<&str> = content.split_whitespace().collect();
            let [_, key, _, _] = fields[..] else {
                return Err(format!(
                    "line {}: four fields: number, key, peer address, contact",
                    line + 1
                ));
            };
            hex32(key).map_err(|error| format!("line {}: {error}", line + 1))
        })
        .collect()
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
    fn every_node_of_the_space_is_listed_or_the_gateway_does_not_start() {
        let dir = tempfile::tempdir().unwrap();
        let space = dir.path().join("space");
        std::fs::write(
            &space,
            format!(
                "# number key peer contact\n1 {} 10.0.0.1:7800 https://g\n2 {} 10.0.0.2:7800 https://g # two\n",
                "ab".repeat(32),
                "cd".repeat(32)
            ),
        )
        .unwrap();
        let node = |key: u8| {
            format!(
                "[[nodes]]\nkey = \"{}\"\naddress = \"unix:/n{key}\"\n",
                hex::encode([key; 32])
            )
        };
        let config = |nodes: &str| -> Config {
            toml::from_str(&format!(
                "key = \"k\"\nhttp = \"127.0.0.1:80\"\nspace = \"{}\"\n{nodes}",
                space.display()
            ))
            .unwrap()
        };
        assert!(config(&node(0xab)).check().is_err(), "node 2 unlisted");
        assert!(config(&(node(0xab) + &node(0xcd))).check().is_ok());
        assert!(space_keys("1 ab 10.0.0.1:1 c\n").is_err());
        let onion = |text: &str| -> Config {
            toml::from_str(&format!(
                "key = \"k\"\nhttp = \"127.0.0.1:80\"\nnodes = []\n[onion]\n{text}"
            ))
            .unwrap()
        };
        assert!(
            onion("sidecar_ssh = \"127.0.0.1:2222\"\nkey = \"o\"\n")
                .check()
                .is_err()
        );
        let sidecar = onion("sidecar_http = \"127.0.0.1:8081\"\ncircuit_rate = 5\n");
        assert!(sidecar.check().is_ok());
        let served = sidecar.onion.unwrap();
        assert!(served.sidecar());
        assert_eq!(served.limits().rate, 5);
        assert_eq!(served.limits().connections, PER_CIRCUIT.connections);
        assert_eq!(served.caps(), PerPort::default());
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
