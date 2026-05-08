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

use crate::commands::space::common::instance_service_id;
use crate::commands::space::endpoint;
use crate::spaces_index::{self, SpaceEntry};

const CONNECT_TIMEOUT: Duration = Duration::from_secs(5);
const INVOKE_TIMEOUT: Duration = Duration::from_secs(10);

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
        SpaceRegistryRef::at(self.registry_id())
    }

    /// The daemon's registry `ServiceId` — `(daemon_prefix, 0)`.
    pub fn registry_id(&self) -> ServiceId {
        ServiceId::new(self.daemon_prefix, ServiceId::REGISTRY.local_id())
    }

    pub fn node(&self) -> &VosNode {
        &self.node
    }

    /// Resolve a user-supplied target string to a daemon-side
    /// `ServiceId`. Three forms supported:
    ///
    /// - `"registry"` — the well-known per-space registry.
    /// - `"<instance_name>"` — looks the agent up in the daemon's
    ///   registry, then derives its per-node ServiceId via
    ///   `derive_instance_svc_id` (the same function `space up`
    ///   uses to register installed agents, so the derived id
    ///   matches the actual registration).
    /// - `"0xHEX"` / 8-hex-chars — bare 32-bit ServiceId. The
    ///   prefix half is honored as-is, letting power users
    ///   target a specific node in a multi-node setup.
    pub fn resolve_target(&self, target: &str) -> anyhow::Result<ServiceId> {
        if target == "registry" {
            return Ok(self.registry_id());
        }
        if let Some(hex) = target.strip_prefix("0x") {
            let raw = u32::from_str_radix(hex, 16)
                .map_err(|e| anyhow::anyhow!("invalid 0x ServiceId '{target}': {e}"))?;
            return Ok(ServiceId(raw));
        }
        // Otherwise an installed-agent instance name. Ask the
        // daemon's registry whether such an agent exists; if
        // yes, derive the daemon-local svc_id from the name +
        // daemon prefix.
        let reg = self.registry();
        let agent = vos::block_on(reg.agent(&mut &self.node, target.to_string()))
            .map_err(|e| anyhow::anyhow!("registry.agent('{target}'): {e}"))?
            .ok_or_else(|| anyhow::anyhow!(
                "no agent named '{target}' is installed in this space \
                 (use `vosx space agents <space>` to list)",
            ))?;
        // Sanity-check the lookup: the agent's name on the
        // wire should match what we asked for. If a malicious
        // bootnode ever returned a different agent we'd want
        // to know.
        debug_assert_eq!(agent.instance_name, target);
        Ok(instance_service_id(target, self.daemon_prefix))
    }

    /// Generic invoke — send `msg` to `target` on the daemon
    /// and return the decoded reply `Value`. Foundation under
    /// every `space *` command that talks to the registry, and
    /// the engine for `space call` against arbitrary agents.
    pub fn invoke_dyn(
        &self,
        target: ServiceId,
        msg: &vos::value::Msg,
    ) -> anyhow::Result<vos::value::Value> {
        use vos::Encode;
        let encoded = msg.encode();
        let mut payload = Vec::with_capacity(1 + encoded.len());
        payload.push(vos::value::TAG_DYNAMIC);
        payload.extend_from_slice(&encoded);

        let reply = self.node.invoke_with_timeout(target, payload, INVOKE_TIMEOUT)
            .ok_or_else(|| anyhow::anyhow!(
                "daemon at {target} didn't reply within {:?} (target unreachable or timed out)",
                INVOKE_TIMEOUT,
            ))?;
        if reply.is_empty() {
            return Ok(vos::value::Value::Unit);
        }
        Ok(vos::Decode::decode(&reply))
    }

    /// Tear down the libp2p peer. Always call before exiting
    /// so background threads drain cleanly.
    pub fn shutdown(self) -> anyhow::Result<()> {
        self.node.shutdown();
        let _ = self.node.collect();
        Ok(())
    }
}
