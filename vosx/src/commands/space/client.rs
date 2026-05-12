//! Tiny libp2p client peer that dials a running `space up`
//! daemon and remote-invokes its registry.
//!
//! Replaces the old `TransientRegistry::boot` pattern: rather
//! than two processes opening the same redb (which redb forbids
//! and which racing made unsafe), the daemon owns the redb and
//! every other `space *` command is a one-shot client that
//! sends a single libp2p invoke and exits.
//!
//! Use `DaemonClient::with_connect(query, |c| …)` for the common
//! "connect, do one thing, shut down" shape — shutdown runs
//! on both the success and error paths. The typed wrappers
//! (`programs`, `agents`, `publish`, …) hide the
//! `vos::block_on(reg.X(&mut &node))` boilerplate.

use std::str::FromStr;
use std::time::{Duration, Instant};

use space_registry::{AgentRow, MemberRow, ProgramRow, SpaceRegistryRef};
use vos::abi::service::ServiceId;
use vos::node::VosNode;

use crate::commands::space::common::instance_service_id;
use crate::commands::space::endpoint;
use crate::spaces_index::{self, SpaceEntry};

const CONNECT_TIMEOUT: Duration = Duration::from_secs(5);
const INVOKE_TIMEOUT_DEFAULT: Duration = Duration::from_secs(10);

/// Resolve the per-invoke timeout, honouring an env override.
/// `VOSX_INVOKE_TIMEOUT_MS` lets the e2e suite shorten the wait
/// when it intentionally talks to a handler that doesn't reply
/// (extension dispatch before Phase 5 wires the `stop`/`status`
/// handlers). Production callers never set it, so the default
/// stays at 10s.
fn invoke_timeout() -> Duration {
    std::env::var("VOSX_INVOKE_TIMEOUT_MS")
        .ok()
        .and_then(|s| s.parse::<u64>().ok())
        .map(Duration::from_millis)
        .unwrap_or(INVOKE_TIMEOUT_DEFAULT)
}

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

        let ep = endpoint::read(&data_dir)?.ok_or_else(|| {
            anyhow::anyhow!(
                "no daemon running for space '{}'. Start it with `vosx space up {}`.",
                entry.name,
                entry.name,
            )
        })?;
        if !endpoint::is_alive(&ep) {
            // Daemon crashed without cleaning up. Remove the stale
            // file so the next `space up` doesn't trip over it, and
            // report no-daemon-running so the user just retries.
            tracing::info!(
                pid = ep.pid,
                path = %endpoint::path(&data_dir).display(),
                "removing stale endpoint file (pid not running)",
            );
            endpoint::delete(&data_dir);
            anyhow::bail!(
                "no daemon running for space '{}' (cleaned up stale endpoint from pid {}). \
                 Start it with `vosx space up {}`.",
                entry.name,
                ep.pid,
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
            // One-shot client peer: only the known daemon
            // bootstrap address matters. Skipping mDNS auto-dial
            // avoids spurious "outgoing connection failed" logs
            // when unrelated libp2p apps are on the LAN.
            auto_dial_mdns: false,
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
                ep.prefix,
                bootstrap_str,
                CONNECT_TIMEOUT,
            );
        }

        Ok(Self {
            node,
            entry,
            daemon_prefix: ep.prefix,
        })
    }

    /// Connect, run `f`, shut down — even on error or panic.
    /// The common shape of every client subcommand: a single
    /// registry round-trip wrapped in a connect/shutdown pair.
    ///
    /// Shutdown runs inside an RAII guard's `Drop`, so a panic
    /// inside `f` still tears down the libp2p peer cleanly
    /// rather than leaking the network thread.
    pub fn with_connect<T, F>(query: &str, f: F) -> anyhow::Result<T>
    where
        F: FnOnce(&Self) -> anyhow::Result<T>,
    {
        struct Guard(Option<DaemonClient>);
        impl Drop for Guard {
            fn drop(&mut self) {
                if let Some(c) = self.0.take() {
                    let _ = c.shutdown();
                }
            }
        }
        let guard = Guard(Some(Self::connect(query)?));
        let client = guard
            .0
            .as_ref()
            .expect("guard always holds Some after connect");
        f(client)
    }

    /// Macro-generated typed `Ref` pointed at the daemon's
    /// registry. Internal — every typed wrapper goes through
    /// here.
    fn registry(&self) -> SpaceRegistryRef {
        SpaceRegistryRef::at(self.registry_id())
    }

    /// The daemon's registry `ServiceId` — `(daemon_prefix, 0)`.
    fn registry_id(&self) -> ServiceId {
        ServiceId::new(self.daemon_prefix, ServiceId::REGISTRY.local_id())
    }

    /// Resolve a user-supplied target string to a daemon-side
    /// `ServiceId`. Four forms supported, in lookup order:
    ///
    /// - `"registry"` — the well-known per-space registry.
    /// - `"0xHEX"` / 8-hex-chars — bare 32-bit ServiceId. The
    ///   prefix half is honored as-is, letting power users
    ///   target a specific node in a multi-node setup.
    /// - `"<instance_name>"` of an installed PVM agent — looks
    ///   the agent up in the daemon's registry, then derives
    ///   its per-node ServiceId via `instance_service_id` (the
    ///   same function `space up` uses to register installed
    ///   agents, so the derived id matches the actual registration).
    /// - `"<instance_name>"` of a manifest-installed extension —
    ///   the reconciler now installs extensions at the same
    ///   deterministic `instance_service_id(name, prefix)` shape,
    ///   so the fallback path simply confirms the name exists in
    ///   `extension_metas` (via `meta_for_instance`) and returns
    ///   the same derivation. The two namespaces share an id
    ///   formula but the registry guarantees their names are
    ///   distinct (agent-first lookup in `meta_for_instance`).
    pub fn resolve_target(&self, target: &str) -> anyhow::Result<ServiceId> {
        if target == "registry" {
            return Ok(self.registry_id());
        }
        if let Some(hex) = target.strip_prefix("0x") {
            let raw = u32::from_str_radix(hex, 16)
                .map_err(|e| anyhow::anyhow!("invalid 0x ServiceId '{target}': {e}"))?;
            return Ok(ServiceId(raw));
        }
        if let Some(agent) = self.agent(target)? {
            debug_assert_eq!(agent.instance_name, target);
            return Ok(instance_service_id(target, self.daemon_prefix));
        }
        // Not an installed agent — try the extension fallback.
        // `meta_for_instance` returns non-empty bytes for any
        // name with a registered schema, including extensions.
        let meta_blob = self.meta_for_instance(target)?;
        if !meta_blob.is_empty() {
            return Ok(instance_service_id(target, self.daemon_prefix));
        }
        anyhow::bail!(
            "no agent or extension named '{target}' is installed in this space \
             (use `vosx space agents <space>` to list installed agents)",
        )
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

        let timeout = invoke_timeout();
        let reply = self
            .node
            .invoke_with_timeout(target, payload, timeout)
            .ok_or_else(|| {
                anyhow::anyhow!(
                    "daemon at {target} didn't reply within {timeout:?} (target unreachable or timed out)",
                )
            })?;
        if reply.is_empty() {
            return Ok(vos::value::Value::Unit);
        }
        Ok(vos::Decode::decode(&reply))
    }

    /// Tear down the libp2p peer. Always call before exiting
    /// so background threads drain cleanly. Most callers go
    /// through `with_connect`, which calls this for them.
    pub fn shutdown(self) -> anyhow::Result<()> {
        self.node.shutdown();
        let _ = self.node.collect();
        Ok(())
    }

    // ── Typed registry wrappers ──────────────────────────────
    //
    // Each is a one-line wrapper around
    // `vos::block_on(reg.X(&mut &self.node, ...))` that converts
    // the registry's error type into `anyhow` with a recognisable
    // prefix. Per-command status decoding stays at the call site.

    pub fn programs(&self) -> anyhow::Result<Vec<ProgramRow>> {
        vos::block_on(self.registry().programs(&mut &self.node))
            .map_err(|e| anyhow::anyhow!("registry.programs(): {e}"))
    }

    pub fn program(&self, name: &str, version: &str) -> anyhow::Result<Option<ProgramRow>> {
        vos::block_on(self.registry().program(
            &mut &self.node,
            name.to_string(),
            version.to_string(),
        ))
        .map_err(|e| anyhow::anyhow!("registry.program('{name}:{version}'): {e}"))
    }

    pub fn agents(&self) -> anyhow::Result<Vec<AgentRow>> {
        vos::block_on(self.registry().agents(&mut &self.node))
            .map_err(|e| anyhow::anyhow!("registry.agents(): {e}"))
    }

    pub fn agent(&self, instance_name: &str) -> anyhow::Result<Option<AgentRow>> {
        vos::block_on(
            self.registry()
                .agent(&mut &self.node, instance_name.to_string()),
        )
        .map_err(|e| anyhow::anyhow!("registry.agent('{instance_name}'): {e}"))
    }

    /// Fetch the raw `.vos_meta` blob the registry has on file
    /// for the agent's program. Empty when no meta is
    /// registered (older binaries) — callers treat that as
    /// "schema unknown".
    pub fn meta_for_instance(&self, instance_name: &str) -> anyhow::Result<Vec<u8>> {
        vos::block_on(
            self.registry()
                .meta_for_instance(&mut &self.node, instance_name.to_string()),
        )
        .map_err(|e| anyhow::anyhow!("registry.meta_for_instance('{instance_name}'): {e}"))
    }

    pub fn members(&self) -> anyhow::Result<Vec<MemberRow>> {
        vos::block_on(self.registry().members(&mut &self.node))
            .map_err(|e| anyhow::anyhow!("registry.members(): {e}"))
    }

    pub fn publish(&self, name: String, version: String, hash: Vec<u8>) -> anyhow::Result<u8> {
        vos::block_on(
            self.registry()
                .publish(&mut &self.node, name, version, hash),
        )
        .map_err(|e| anyhow::anyhow!("registry.publish(): {e}"))
    }

    pub fn unpublish(&self, name: String, version: String) -> anyhow::Result<u8> {
        vos::block_on(self.registry().unpublish(&mut &self.node, name, version))
            .map_err(|e| anyhow::anyhow!("registry.unpublish(): {e}"))
    }

    #[allow(clippy::too_many_arguments)]
    pub fn install(
        &self,
        instance_name: String,
        program_name: String,
        program_version: String,
        program_hash: Vec<u8>,
        replication_id: Vec<u8>,
        consistency: u8,
        install_args: Vec<u8>,
        install_payloads: Vec<u8>,
    ) -> anyhow::Result<u8> {
        vos::block_on(self.registry().install(
            &mut &self.node,
            instance_name,
            program_name,
            program_version,
            program_hash,
            replication_id,
            consistency,
            install_args,
            install_payloads,
        ))
        .map_err(|e| anyhow::anyhow!("registry.install(): {e}"))
    }

    pub fn upgrade(
        &self,
        instance_name: String,
        program_name: String,
        program_version: String,
        program_hash: Vec<u8>,
    ) -> anyhow::Result<u8> {
        vos::block_on(self.registry().upgrade(
            &mut &self.node,
            instance_name,
            program_name,
            program_version,
            program_hash,
        ))
        .map_err(|e| anyhow::anyhow!("registry.upgrade(): {e}"))
    }

    pub fn uninstall(&self, instance_name: String) -> anyhow::Result<u8> {
        vos::block_on(self.registry().uninstall(&mut &self.node, instance_name))
            .map_err(|e| anyhow::anyhow!("registry.uninstall(): {e}"))
    }

    pub fn add_node(&self, prefix: u32, peer_id: Vec<u8>, role: u8) -> anyhow::Result<u8> {
        vos::block_on(
            self.registry()
                .add_node(&mut &self.node, prefix, peer_id, role),
        )
        .map_err(|e| anyhow::anyhow!("registry.add_node(): {e}"))
    }

    pub fn remove_node(&self, prefix: u32) -> anyhow::Result<u8> {
        vos::block_on(self.registry().remove_node(&mut &self.node, prefix))
            .map_err(|e| anyhow::anyhow!("registry.remove_node(): {e}"))
    }

    pub fn add_identity(
        &self,
        public_key: Vec<u8>,
        proof_kind: u8,
        proof_data: Vec<u8>,
    ) -> anyhow::Result<u8> {
        vos::block_on(self.registry().add_identity(
            &mut &self.node,
            public_key,
            proof_kind,
            proof_data,
        ))
        .map_err(|e| anyhow::anyhow!("registry.add_identity(): {e}"))
    }

    pub fn remove_identity(&self, public_key: Vec<u8>) -> anyhow::Result<u8> {
        vos::block_on(self.registry().remove_identity(&mut &self.node, public_key))
            .map_err(|e| anyhow::anyhow!("registry.remove_identity(): {e}"))
    }
}
