//! Networking layer — peer transport over libp2p.
//!
//! Cycle 1 of the kunekt networking work: establishes the pipe and
//! nothing more. The [`Network`] runs the libp2p swarm on its own
//! tokio thread, independent of [`VosNode`](crate::node::VosNode);
//! subsequent cycles wire envelope routing, cross-node invoke, and
//! CRDT sync through it.
//!
//! # Cycle 1 scope
//!
//! - TCP / Noise / yamux transport.
//! - Identify + ping for keepalive and peer info exchange.
//! - mDNS for LAN peer discovery (zero-config two-process testing).
//! - `Identity::auto` derives an Ed25519 keypair and persists it
//!   to `{data_dir}/node.key`; explicit `path` strings load the
//!   keypair from that file.
//!
//! # Out of scope (later cycles)
//!
//! - Wire format for actor envelopes and InvokeRequest /
//!   InvokeReply frames over libp2p streams.
//! - Cross-node routing in [`VosNode::route`](crate::node::VosNode).
//! - CRDT gossip / sync via libp2p pubsub.
//! - Hyperspace-driven peer discovery.

#![cfg(feature = "network")]

use std::path::{Path, PathBuf};
use std::thread::{self, JoinHandle};
use std::time::Duration;

use libp2p::futures::StreamExt;
use libp2p::swarm::{NetworkBehaviour, SwarmEvent};
use libp2p::{identify, identity, mdns, noise, ping, tcp, yamux, Multiaddr, PeerId, Swarm};
use tokio::sync::mpsc as async_mpsc;
use tracing::{debug, error, info, warn};

/// Combined libp2p behaviour for the cycle-1 pipe.
#[derive(NetworkBehaviour)]
struct VosBehaviour {
    mdns: mdns::tokio::Behaviour,
    ping: ping::Behaviour,
    identify: identify::Behaviour,
}

/// Handle to the running network thread. Drop or call
/// [`shutdown`](Self::shutdown) to wind it down.
pub struct Network {
    peer_id: PeerId,
    cmd_tx: async_mpsc::UnboundedSender<NetworkCmd>,
    join: Option<JoinHandle<()>>,
}

/// Configuration for the libp2p layer.
pub struct NetworkConfig {
    /// libp2p keypair. Use [`load_or_generate_identity`] to derive
    /// one from the manifest's `[node].identity` field.
    pub keypair: identity::Keypair,
    /// Multiaddrs the node listens on. Empty = no inbound
    /// connections (the node is dial-only).
    pub listen: Vec<Multiaddr>,
    /// Multiaddrs to dial at startup. Useful when not relying on
    /// mDNS / hyperspace discovery.
    pub bootstrap: Vec<Multiaddr>,
}

enum NetworkCmd {
    Connect(Multiaddr),
    Shutdown,
}

impl Network {
    /// Spin up the libp2p swarm on a dedicated thread.
    pub fn start(config: NetworkConfig) -> Self {
        let peer_id = PeerId::from(config.keypair.public());
        let (cmd_tx, cmd_rx) = async_mpsc::unbounded_channel();

        let join = thread::spawn(move || {
            let rt = match tokio::runtime::Builder::new_current_thread()
                .enable_all()
                .build()
            {
                Ok(rt) => rt,
                Err(e) => {
                    error!(error = %e, "network: failed to build tokio runtime");
                    return;
                }
            };
            rt.block_on(network_main(config, cmd_rx));
        });

        Self {
            peer_id,
            cmd_tx,
            join: Some(join),
        }
    }

    /// The local libp2p peer ID.
    pub fn peer_id(&self) -> PeerId {
        self.peer_id
    }

    /// Dial a peer at the given multiaddr.
    pub fn connect(&self, addr: Multiaddr) {
        let _ = self.cmd_tx.send(NetworkCmd::Connect(addr));
    }

    /// Signal the network thread to stop. The actual exit happens
    /// on the next swarm-event tick (≤ 50 ms typical).
    pub fn shutdown(&self) {
        let _ = self.cmd_tx.send(NetworkCmd::Shutdown);
    }

    /// Wait for the network thread to exit.
    pub fn join(mut self) {
        self.shutdown();
        if let Some(j) = self.join.take() {
            let _ = j.join();
        }
    }
}

impl Drop for Network {
    fn drop(&mut self) {
        // Best-effort shutdown if the user didn't call .join().
        let _ = self.cmd_tx.send(NetworkCmd::Shutdown);
    }
}

async fn network_main(
    config: NetworkConfig,
    mut cmd_rx: async_mpsc::UnboundedReceiver<NetworkCmd>,
) {
    let local_peer_id = PeerId::from(config.keypair.public());
    info!(peer_id = %local_peer_id, "network: starting");

    let mut swarm = match build_swarm(config.keypair.clone()) {
        Ok(s) => s,
        Err(e) => {
            error!(error = %e, "network: failed to build swarm");
            return;
        }
    };

    for addr in &config.listen {
        match swarm.listen_on(addr.clone()) {
            Ok(_) => info!(%addr, "network: requesting listen"),
            Err(e) => error!(%addr, error = %e, "network: listen failed"),
        }
    }

    for addr in &config.bootstrap {
        match swarm.dial(addr.clone()) {
            Ok(_) => info!(%addr, "network: dialing bootstrap"),
            Err(e) => warn!(%addr, error = %e, "network: dial failed"),
        }
    }

    loop {
        tokio::select! {
            event = swarm.select_next_some() => {
                handle_swarm_event(&mut swarm, event);
            }
            cmd = cmd_rx.recv() => {
                match cmd {
                    Some(NetworkCmd::Connect(addr)) => {
                        match swarm.dial(addr.clone()) {
                            Ok(_) => info!(%addr, "network: dialing peer"),
                            Err(e) => warn!(%addr, error = %e, "network: dial failed"),
                        }
                    }
                    Some(NetworkCmd::Shutdown) | None => {
                        info!("network: shutting down");
                        break;
                    }
                }
            }
        }
    }
}

fn build_swarm(
    keypair: identity::Keypair,
) -> Result<Swarm<VosBehaviour>, Box<dyn std::error::Error + Send + Sync>> {
    let local_peer_id = PeerId::from(keypair.public());
    let swarm = libp2p::SwarmBuilder::with_existing_identity(keypair)
        .with_tokio()
        .with_tcp(
            tcp::Config::default(),
            noise::Config::new,
            yamux::Config::default,
        )?
        .with_behaviour(|key| {
            let mdns_cfg = mdns::Config::default();
            let mdns = mdns::tokio::Behaviour::new(mdns_cfg, local_peer_id)
                .map_err::<Box<dyn std::error::Error + Send + Sync>, _>(|e| Box::new(e))?;
            let ping = ping::Behaviour::default();
            let identify = identify::Behaviour::new(identify::Config::new(
                "/vos/0.1.0".into(),
                key.public(),
            ));
            Ok::<_, Box<dyn std::error::Error + Send + Sync>>(VosBehaviour { mdns, ping, identify })
        })?
        .with_swarm_config(|c| c.with_idle_connection_timeout(Duration::from_secs(60)))
        .build();
    Ok(swarm)
}

fn handle_swarm_event(swarm: &mut Swarm<VosBehaviour>, event: SwarmEvent<VosBehaviourEvent>) {
    match event {
        SwarmEvent::NewListenAddr { address, .. } => {
            info!(%address, "network: listening on");
        }
        SwarmEvent::ConnectionEstablished { peer_id, endpoint, .. } => {
            info!(%peer_id, ?endpoint, "network: peer connected");
        }
        SwarmEvent::ConnectionClosed { peer_id, cause, .. } => {
            info!(%peer_id, ?cause, "network: peer disconnected");
        }
        SwarmEvent::OutgoingConnectionError { peer_id, error, .. } => {
            warn!(?peer_id, error = %error, "network: outgoing connection failed");
        }
        SwarmEvent::Behaviour(VosBehaviourEvent::Mdns(mdns::Event::Discovered(peers))) => {
            for (peer_id, addr) in peers {
                info!(%peer_id, %addr, "network: mDNS discovered peer; dialing");
                let _ = swarm.dial(addr);
            }
        }
        SwarmEvent::Behaviour(VosBehaviourEvent::Mdns(mdns::Event::Expired(peers))) => {
            for (peer_id, _addr) in peers {
                debug!(%peer_id, "network: mDNS peer expired");
            }
        }
        SwarmEvent::Behaviour(VosBehaviourEvent::Identify(identify::Event::Received { peer_id, info, .. })) => {
            debug!(%peer_id, agent = %info.agent_version, "network: identify received");
        }
        _ => {}
    }
}

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
                info!(path = %key_path.display(), "network: generated new node identity");
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

    #[test]
    fn identity_auto_persists_across_calls() {
        let dir = std::env::temp_dir().join(format!(
            "vos_net_id_{}_{}",
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
            "vos_net_explicit_{}_{}",
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
