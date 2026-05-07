//! Tiny libp2p client peer that dials a running `space up`
//! daemon and remote-invokes its registry.
//!
//! Replaces the old `TransientRegistry::boot` pattern: rather
//! than two processes opening the same redb (which redb forbids
//! and which racing made unsafe), the daemon owns the redb and
//! every other `space *` command is a one-shot client that
//! sends a single libp2p invoke and exits.
//!
//! Use `DaemonClient::connect(query)` to get a handle, then
//! `client.registry()` for the macro-generated typed `Ref`
//! pointed at the daemon's `(daemon_prefix, REGISTRY)`. Same
//! call shape as `TransientRegistry`; only the wire path
//! differs (libp2p invoke instead of in-process dispatch).

use std::str::FromStr;
use std::time::{Duration, Instant};

use space_registry::SpaceRegistryRef;
use vos::abi::service::ServiceId;
use vos::node::VosNode;

use crate::commands::space::endpoint;
use crate::spaces_index::{self, SpaceEntry};

const CONNECT_TIMEOUT: Duration = Duration::from_secs(5);

pub struct DaemonClient {
    node: VosNode,
    /// Cached so command handlers can access the entry the
    /// query resolved to (e.g. for printing the space name).
    pub entry: SpaceEntry,
    daemon_prefix: u16,
}

impl DaemonClient {
    /// Resolve `query` to a space, read its endpoint file, and
    /// dial the running daemon. Errors fast if no daemon is
    /// running or the dial fails.
    pub fn connect(query: &str) -> anyhow::Result<Self> {
        let index = spaces_index::load()?;
        let entry = spaces_index::find(&index, query)?.clone();
        let data_dir = std::path::PathBuf::from(&entry.data_dir);

        let ep = endpoint::read(&data_dir)?
            .ok_or_else(|| anyhow::anyhow!(
                "no daemon running for space '{}'. Start it with `vosx space up {}`.",
                entry.name,
                entry.name,
            ))?;
        if !endpoint::is_alive(&ep) {
            anyhow::bail!(
                "stale endpoint file (pid {} not running). \
                 Delete {} and start `vosx space up {}`.",
                ep.pid,
                endpoint::path(&data_dir).display(),
                entry.name,
            );
        }

        let bootstrap_str = ep
            .multiaddrs
            .first()
            .ok_or_else(|| anyhow::anyhow!("daemon endpoint advertises no multiaddrs"))?;
        let bootstrap: libp2p::Multiaddr = libp2p::Multiaddr::from_str(bootstrap_str)
            .map_err(|e| anyhow::anyhow!("bad daemon multiaddr '{bootstrap_str}': {e}"))?;

        let keypair = libp2p::identity::Keypair::generate_ed25519();
        let peer_id = libp2p::PeerId::from(keypair.public());
        let local_prefix = vos::network::derive_node_prefix(&peer_id);

        let net = vos::network::Network::start(vos::network::NetworkConfig {
            keypair,
            local_prefix,
            listen: vec![],
            bootstrap: vec![bootstrap],
        });

        let mut node = VosNode::with_prefix(local_prefix);
        node.attach_network(net);

        // Wait for the prefix routing table to know about the daemon.
        let net_arc = node.network().expect("network was just attached");
        let deadline = Instant::now() + CONNECT_TIMEOUT;
        while Instant::now() < deadline {
            if net_arc.peer_for_prefix(ep.prefix).is_some() {
                break;
            }
            std::thread::sleep(Duration::from_millis(25));
        }
        if net_arc.peer_for_prefix(ep.prefix).is_none() {
            node.shutdown();
            let _ = node.collect();
            anyhow::bail!(
                "couldn't reach daemon (prefix {:#06x}) at {} within {:?}",
                ep.prefix, bootstrap_str, CONNECT_TIMEOUT,
            );
        }

        Ok(Self {
            node,
            entry,
            daemon_prefix: ep.prefix,
        })
    }

    /// Macro-generated typed `Ref` pointed at the daemon's
    /// registry. Use as `vos::block_on(client.registry().publish(&mut &*client.node(), ...))`.
    pub fn registry(&self) -> SpaceRegistryRef {
        SpaceRegistryRef::at(ServiceId::new(
            self.daemon_prefix,
            ServiceId::REGISTRY.local_id(),
        ))
    }

    pub fn node(&self) -> &VosNode {
        &self.node
    }

    /// Tear down the libp2p peer. Always call before exiting
    /// so background threads drain cleanly.
    pub fn shutdown(self) -> anyhow::Result<()> {
        self.node.shutdown();
        let _ = self.node.collect();
        Ok(())
    }
}
