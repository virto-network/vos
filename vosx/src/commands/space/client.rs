//! Bounded one-shot client for a running local Space daemon.
//!
//! The retained client supports daemon liveness and the explicit `zk`
//! namespace's native-extension calls. It contains no catalog, membership, or
//! legacy service-management wrappers.

use std::str::FromStr;
use std::time::{Duration, Instant};

use vos::abi::service::ServiceId;
use vos::node::VosNode;
use vos::registry::{ProgramRow, RegistryRef};

use super::{common::instance_service_id, endpoint};
use crate::spaces_index;

const CONNECT_TIMEOUT: Duration = Duration::from_secs(5);
const INVOKE_TIMEOUT: Duration = Duration::from_secs(60);

pub struct DaemonClient {
    node: VosNode,
    endpoint: endpoint::Endpoint,
    daemon_prefix: u16,
}

fn require_daemon_registry_handshake(
    result: Result<vos::registry::RegistryProtocol, vos::actors::client::ClientError>,
) -> anyhow::Result<()> {
    result
        .map(|_| ())
        .map_err(|error| anyhow::anyhow!("daemon registry protocol handshake failed: {error}"))
}

impl DaemonClient {
    pub fn connect(query: &str) -> anyhow::Result<Self> {
        let index = spaces_index::load()?;
        let entry = spaces_index::find(&index, query)?.clone();
        let data_dir = std::path::PathBuf::from(&entry.data_dir);
        let endpoint = endpoint::read(&data_dir)?.ok_or_else(|| {
            anyhow::anyhow!(
                "no daemon running for space '{}'; start it with `vosx space up {}`",
                entry.name,
                entry.name,
            )
        })?;
        if !endpoint::is_alive(&endpoint) {
            super::endpoint::delete(&data_dir);
            anyhow::bail!(
                "no daemon running for space '{}' (removed stale endpoint from pid {})",
                entry.name,
                endpoint.pid,
            );
        }

        let bootstrap_text = endpoint
            .multiaddrs
            .first()
            .ok_or_else(|| anyhow::anyhow!("daemon endpoint advertises no addresses"))?;
        let bootstrap = libp2p::Multiaddr::from_str(bootstrap_text).map_err(|error| {
            anyhow::anyhow!("invalid daemon address '{bootstrap_text}': {error}")
        })?;
        let keypair = crate::identity::load_or_create()?;
        let local_prefix =
            vos::network::derive_node_prefix(&libp2p::PeerId::from(keypair.public()));
        let network = vos::network::Network::start(vos::network::NetworkConfig {
            keypair,
            local_prefix,
            listen: Vec::new(),
            bootstrap: vec![bootstrap],
            auto_dial_mdns: false,
        });
        let mut node = VosNode::with_prefix(local_prefix);
        node.attach_network(network);

        let network = node.network().expect("network was attached");
        let deadline = Instant::now() + CONNECT_TIMEOUT;
        while Instant::now() < deadline && network.peer_for_prefix(endpoint.prefix).is_none() {
            std::thread::sleep(Duration::from_millis(25));
        }
        if network.peer_for_prefix(endpoint.prefix).is_none() {
            node.shutdown();
            let _ = node.collect();
            anyhow::bail!(
                "could not reach daemon prefix {:#06x} within {:?}",
                endpoint.prefix,
                CONNECT_TIMEOUT,
            );
        }

        let client = Self {
            node,
            daemon_prefix: endpoint.prefix,
            endpoint,
        };
        if let Err(error) = require_daemon_registry_handshake(vos::block_on(
            client.registry().protocol(&mut &client.node),
        )) {
            let _ = client.shutdown();
            return Err(error);
        }
        Ok(client)
    }

    pub fn with_connect<T>(
        query: &str,
        operation: impl FnOnce(&Self) -> anyhow::Result<T>,
    ) -> anyhow::Result<T> {
        struct Guard(Option<DaemonClient>);
        impl Drop for Guard {
            fn drop(&mut self) {
                if let Some(client) = self.0.take() {
                    let _ = client.shutdown();
                }
            }
        }
        let guard = Guard(Some(Self::connect(query)?));
        operation(guard.0.as_ref().expect("guard contains client"))
    }

    fn registry(&self) -> RegistryRef {
        RegistryRef::at(ServiceId::new(
            self.daemon_prefix,
            ServiceId::REGISTRY.local_id(),
        ))
    }

    /// Resolve only the registry and extensions the daemon explicitly
    /// published in its endpoint. Registry catalog rows are not executable CLI
    /// targets after the clean cutover.
    pub fn resolve_target(&self, target: &str) -> anyhow::Result<ServiceId> {
        if target == "registry" {
            return Ok(self.registry().id());
        }
        super::common::parse_instance_name(target)?;
        if self
            .endpoint
            .extensions
            .iter()
            .any(|extension| extension.name == target)
        {
            return Ok(instance_service_id(target, self.daemon_prefix));
        }
        anyhow::bail!("no local extension named '{target}' is loaded")
    }

    pub fn invoke_dyn(
        &self,
        target: ServiceId,
        message: &vos::value::Msg,
    ) -> anyhow::Result<vos::value::Value> {
        self.invoke_dyn_with_timeout(target, message, INVOKE_TIMEOUT)
    }

    pub fn invoke_dyn_with_timeout(
        &self,
        target: ServiceId,
        message: &vos::value::Msg,
        timeout: Duration,
    ) -> anyhow::Result<vos::value::Value> {
        use vos::Encode as _;

        let encoded = message.encode();
        let mut payload = Vec::with_capacity(encoded.len() + 1);
        payload.push(vos::value::TAG_DYNAMIC);
        payload.extend_from_slice(&encoded);
        let reply = self
            .node
            .invoke_with_timeout(target, payload, timeout)
            .ok_or_else(|| {
                anyhow::anyhow!("daemon target {target} did not reply within {timeout:?}")
            })?;
        if reply.is_empty() {
            return Ok(vos::value::Value::Unit);
        }
        Ok(vos::Decode::decode(&reply))
    }

    /// Lightweight registry round-trip used by `space info`.
    pub fn programs(&self) -> anyhow::Result<Vec<ProgramRow>> {
        vos::block_on(self.registry().programs_all(&mut &self.node))
            .map_err(|error| anyhow::anyhow!("registry liveness probe failed: {error}"))
    }

    pub fn shutdown(self) -> anyhow::Result<()> {
        self.node.shutdown();
        let _ = self.node.collect();
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn daemon_registry_handshake_is_fail_closed() {
        let error =
            require_daemon_registry_handshake(Err(vos::actors::client::ClientError::Unreachable))
                .expect_err("unreachable daemon must fail");
        assert!(error.to_string().contains("protocol handshake failed"));
    }
}
