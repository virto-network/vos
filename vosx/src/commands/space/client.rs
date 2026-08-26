//! Tiny libp2p client peer that dials a running `space up`
//! daemon and remote-invokes its registry.
//!
//! The daemon owns the registry database. Every other `space *` command is a
//! one-shot client that sends one libp2p request and exits.
//!
//! Use `DaemonClient::with_connect(query, |c| …)` for the common
//! "connect, do one thing, shut down" shape — shutdown runs
//! on both the success and error paths. The typed wrappers
//! (`programs`, `agents`, `publish`, …) hide the
//! `vos::block_on(reg.X(&mut &node))` boilerplate.

use std::str::FromStr;
use std::sync::Mutex;
use std::time::{Duration, Instant};

use vos::abi::service::ServiceId;
use vos::node::VosNode;
use vos::registry::{AgentRow, MemberRow, ProgramRow, RegistryRef, Status};

use crate::commands::space::common::instance_service_id;
use crate::commands::space::endpoint;
use crate::commands::space::op_sign::op_auth;
use crate::spaces_index::{self, SpaceEntry};

const CONNECT_TIMEOUT: Duration = Duration::from_secs(5);
// The default Raft configuration alone permits an invocation to spend 35
// seconds authenticating, staging private input, crossing a read barrier, and
// committing genesis/admission/apply. Keep the CLI outside that legitimate
// operation budget so it never reports failure while the service can still
// commit the request.
const INVOKE_TIMEOUT_DEFAULT: Duration = Duration::from_secs(60);
/// A role-authorized service call may wait for a Raft authority read barrier and
/// decision commit before the Local target executes. Match the libp2p
/// request-response budget unless the operator supplied an explicit override.
const ROLE_AUTHORIZED_INVOKE_TIMEOUT_DEFAULT: Duration = Duration::from_secs(300);

/// Resolve the per-invoke timeout, honouring an env override.
/// `VOSX_INVOKE_TIMEOUT_MS` lets the e2e suite shorten the wait
/// when it intentionally talks to a handler that doesn't reply
/// (extension dispatch before `stop`/`status` handlers are
/// wired). Production callers never set it, so the default
/// stays at 60s.
fn invoke_timeout() -> Duration {
    std::env::var("VOSX_INVOKE_TIMEOUT_MS")
        .ok()
        .and_then(|s| s.parse::<u64>().ok())
        .map(Duration::from_millis)
        .unwrap_or(INVOKE_TIMEOUT_DEFAULT)
}

fn invoke_timeout_for_policy(policy: Option<&vos::service::MethodPolicy>) -> Duration {
    let configured = invoke_timeout();
    if std::env::var_os("VOSX_INVOKE_TIMEOUT_MS").is_some() {
        return configured;
    }
    if policy.is_some_and(|policy| {
        !policy.public && policy.space_role.is_some() && policy.actor_role.is_none()
    }) {
        ROLE_AUTHORIZED_INVOKE_TIMEOUT_DEFAULT
    } else {
        configured
    }
}

pub struct DaemonClient {
    node: VosNode,
    /// The operator's libp2p identity key — signs the `auth`
    /// blob on every gated registry mutation. The same key drives the
    /// libp2p dial below, so the daemon sees a `Caller::Peer` whose
    /// role it can check AND a signature its registry actor verifies.
    signer: libp2p::identity::Keypair,
    /// Cached so command handlers can access the entry the
    /// query resolved to (e.g. for printing the space name).
    pub entry: SpaceEntry,
    /// The endpoint descriptor read at connect time. Retained so
    /// handlers can read daemon-published diagnostics (e.g. each
    /// extension's effective `intra_caps`) without re-reading the
    /// file.
    pub endpoint: endpoint::Endpoint,
    daemon_prefix: u16,
    /// Service actor identities and signed method policies learned while resolving
    /// an installed package name. Registry and extension targets use their explicit
    /// control-plane wire instead.
    service_targets: Mutex<std::collections::HashMap<u32, ServiceTarget>>,
}

#[derive(Clone)]
struct ServiceTarget {
    actor: vos::service::ActorId,
    methods: std::collections::HashMap<String, vos::service::MethodPolicy>,
}

fn encode_service_invocation(
    target: &ServiceTarget,
    invocation: vos::service::InvocationId,
    msg: &vos::value::Msg,
    arguments: Vec<u8>,
) -> anyhow::Result<Vec<u8>> {
    use vos::service::ServiceWire;

    let policy = target
        .methods
        .get(&msg.name)
        .ok_or_else(|| anyhow::anyhow!("service package has no method named '{}'", msg.name))?;
    if policy.attested {
        anyhow::bail!(
            "attested method '{}' requires the proof-producing transport path, which space call does not attach yet",
            msg.name,
        );
    }
    if !policy.public && (policy.space_role.is_none() || policy.actor_role.is_some()) {
        anyhow::bail!(
            "actor-local or mixed-role method '{}' requires a bound-handle credential, which space call does not accept yet",
            msg.name,
        );
    }
    Ok(vos::service::RootTreeInvocation {
        invocation,
        target: target.actor,
        method: msg.name.clone(),
        arguments,
        proof_requested: false,
    }
    .encode())
}

fn is_reserved_host_operation(method: &str) -> bool {
    matches!(method, "__stop" | "__describe")
}

fn decode_exact_service_package(
    bytes: &[u8],
    label: &str,
) -> anyhow::Result<vos::service::VosPackage> {
    use vos::service::ServiceWire;

    let package = vos::service::VosPackage::decode(bytes)
        .map_err(|error| anyhow::anyhow!("decode {label} signed service package: {error}"))?;
    package
        .validate()
        .map_err(|error| anyhow::anyhow!("validate {label} signed service package: {error}"))?;
    if package.encode() != bytes {
        anyhow::bail!("{label} signed service package is not canonical");
    }
    Ok(package)
}

fn role_grant_mutation(
    space: vos::service::SpaceId,
    peer_id: &[u8],
    role: u8,
    epoch: u64,
) -> anyhow::Result<vos::service::RoleAuthorityMutation> {
    let role = vos::SpaceRole::from_u8(role)
        .ok_or_else(|| anyhow::anyhow!("role {role} is not a canonical service space role"))?;
    Ok(vos::service::RoleAuthorityMutation::Grant {
        space,
        holder: vos::service::Origin::Member(vos::service::SubjectId::of_authenticated_peer(
            peer_id,
        )),
        role,
        epoch,
    })
}

fn role_revoke_mutation(
    space: vos::service::SpaceId,
    peer_id: &[u8],
    epoch: u64,
) -> vos::service::RoleAuthorityMutation {
    vos::service::RoleAuthorityMutation::Revoke {
        space,
        holder: vos::service::Origin::Member(vos::service::SubjectId::of_authenticated_peer(
            peer_id,
        )),
        epoch,
    }
}

impl DaemonClient {
    fn daemon_peer_id(&self) -> anyhow::Result<libp2p::PeerId> {
        libp2p::PeerId::from_str(&self.endpoint.peer_id)
            .map_err(|error| anyhow::anyhow!("invalid daemon PeerId in endpoint: {error}"))
    }

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

        // Load the operator's persistent libp2p identity from
        // $XDG_CONFIG_HOME/vosx/identity.key (auto-create on first
        // call). The daemon recognises the same PeerId across
        // invocations and consults its members ACL table.
        let keypair = crate::identity::load_or_create()?;
        let peer_id = libp2p::PeerId::from(keypair.public());
        let local_prefix = vos::network::derive_node_prefix(&peer_id);
        // Retain the key for signing registry mutations; the clone
        // below is consumed by the libp2p stack.
        let signer = keypair.clone();

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
            signer,
            entry,
            daemon_prefix: ep.prefix,
            endpoint: ep,
            service_targets: Mutex::new(std::collections::HashMap::new()),
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

    /// Dynamic-dispatch registry client pointed at the daemon's
    /// registry. Internal — every typed wrapper goes through here.
    fn registry(&self) -> RegistryRef {
        RegistryRef::at(self.registry_id())
    }

    /// The daemon's registry `ServiceId` — `(daemon_prefix, 0)`.
    fn registry_id(&self) -> ServiceId {
        ServiceId::new(self.daemon_prefix, ServiceId::REGISTRY.local_id())
    }

    /// The connected daemon's 16-bit node prefix. Stable per
    /// node (derived from its libp2p `PeerId`), useful as a
    /// per-identity discriminator — e.g. when minting a default
    /// branch name like `ai/<prefix>/suggested` so two nodes
    /// suggesting changes to the same project never collide on
    /// the branch ref.
    pub fn daemon_prefix(&self) -> u16 {
        self.daemon_prefix
    }

    /// Resolve a user-supplied target string to a daemon-side
    /// `ServiceId`. Three forms are supported, in lookup order:
    ///
    /// - `"registry"` — the well-known per-space registry.
    /// - `"<instance_name>"` of an installed PVM agent — looks
    ///   the agent up in the daemon's registry, then derives
    ///   its per-node ServiceId via `instance_service_id` (the
    ///   same function `space up` uses to register installed
    ///   agents, so the derived id matches the actual registration).
    /// - `"<instance_name>"` of a recipe-installed extension —
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
        if let Some(agent) = self.agent(target)? {
            debug_assert_eq!(agent.instance_name, target);
            let route = instance_service_id(target, self.daemon_prefix);
            self.remember_service_target(route, &agent)?;
            return Ok(route);
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
        let timeout = self
            .service_targets
            .lock()
            .ok()
            .and_then(|targets| targets.get(&target.0).cloned())
            .and_then(|target| target.methods.get(&msg.name).cloned());
        self.invoke_dyn_with_timeout(target, msg, invoke_timeout_for_policy(timeout.as_ref()))
    }

    /// Like [`Self::invoke_dyn`] but with an explicit per-call timeout, for the
    /// rare handler that legitimately runs far past the 10s default — e.g.
    /// `vosx zk pin`'s `measure_catalog`, a minutes-long trace + prove. The
    /// extension runs on its own thread, so a long wait here doesn't stall the
    /// node's other services.
    pub fn invoke_dyn_with_timeout(
        &self,
        target: ServiceId,
        msg: &vos::value::Msg,
        timeout: Duration,
    ) -> anyhow::Result<vos::value::Value> {
        let reply = self.invoke_dyn_bytes_with_timeout(target, msg, timeout)?;
        if reply.is_empty() {
            return Ok(vos::value::Value::Unit);
        }
        Ok(vos::Decode::decode(&reply))
    }

    /// Like [`Self::invoke_dyn`] but returns the RAW reply bytes (empty when
    /// the reply is empty), with an explicit per-call timeout. Callers that
    /// need to distinguish the daemon's 5-byte forbidden-refusal envelope from
    /// a normal reply use this — [`Self::invoke_dyn`] decodes blindly and would
    /// mis-handle a refusal.
    pub fn invoke_dyn_bytes_with_timeout(
        &self,
        target: ServiceId,
        msg: &vos::value::Msg,
        timeout: Duration,
    ) -> anyhow::Result<Vec<u8>> {
        use vos::Encode;
        let encoded = msg.encode();
        let mut payload = Vec::with_capacity(1 + encoded.len());
        payload.push(vos::value::TAG_DYNAMIC);
        payload.extend_from_slice(&encoded);

        let service_target = self
            .service_targets
            .lock()
            .map_err(|_| anyhow::anyhow!("service target cache is unavailable"))?
            .get(&target.0)
            .cloned();
        let is_service_invocation =
            service_target.is_some() && !is_reserved_host_operation(&msg.name);
        let payload = if let Some(service_target) =
            service_target.filter(|_| !is_reserved_host_operation(&msg.name))
        {
            let mut nonce = [0; 32];
            getrandom::getrandom(&mut nonce)
                .map_err(|error| anyhow::anyhow!("mint service invocation ID: {error}"))?;
            encode_service_invocation(
                &service_target,
                vos::service::InvocationId::derive(b"vosx/daemon-invocation/service", &nonce),
                msg,
                payload,
            )?
        } else {
            payload
        };

        let reply = self
            .node
            .invoke_with_timeout(target, payload, timeout)
            .ok_or_else(|| {
                anyhow::anyhow!(
                    "daemon at {target} didn't reply within {timeout:?} (target unreachable or timed out)",
                )
            })?;
        if is_service_invocation && reply.is_empty() {
            anyhow::bail!("service target at {target} refused the invocation or is not attached");
        }
        Ok(reply)
    }

    fn remember_service_target(&self, route: ServiceId, agent: &AgentRow) -> anyhow::Result<()> {
        let service_target = self.service_target_for_agent(agent)?;
        self.service_targets
            .lock()
            .map_err(|_| anyhow::anyhow!("service target cache is unavailable"))?
            .insert(route.0, service_target);
        Ok(())
    }

    fn service_target_for_agent(&self, agent: &AgentRow) -> anyhow::Result<ServiceTarget> {
        use vos::service::ServiceWire;

        let hash = crate::blob_store::BlobHash(agent.program_hash);
        let Some(exact_package) = crate::blob_store::cache_get(&hash)? else {
            anyhow::bail!(
                "installed package for '{}' is missing from the local content store",
                agent.instance_name
            );
        };
        if exact_package.get(..4) != Some(b"VOSP") {
            anyhow::bail!(
                "installed catalog entry '{}' does not contain a signed service package",
                agent.instance_name
            );
        }
        let package = vos::service::VosPackage::decode(&exact_package)
            .map_err(|error| anyhow::anyhow!("decode installed service package: {error}"))?;
        package
            .validate()
            .map_err(|error| anyhow::anyhow!("validate installed service package: {error}"))?;
        if package.encode() != exact_package {
            anyhow::bail!("installed service package wire is not canonical");
        }
        let policies = vos::service::PackageRolePolicies::decode(&package.role_policies)
            .map_err(|error| anyhow::anyhow!("decode installed service policies: {error}"))?;
        let space = vos::service::SpaceId(
            self.entry
                .id_bytes()
                .ok_or_else(|| anyhow::anyhow!("space ID is not canonical hex"))?,
        );
        let service = crate::commands::space::common::service_root_service_id(
            space,
            &agent.instance_name,
            agent.replication_id,
        );
        Ok(ServiceTarget {
            actor: crate::commands::space::common::service_root_actor_id(
                service,
                &agent.instance_name,
            ),
            methods: policies
                .methods
                .into_iter()
                .map(|policy| (policy.method.clone(), policy))
                .collect(),
        })
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
        vos::block_on(self.registry().programs_all(&mut &self.node))
            .map_err(|e| anyhow::anyhow!("registry.programs(): {e}"))
    }

    pub fn program(&self, name: &str) -> anyhow::Result<Option<ProgramRow>> {
        vos::block_on(self.registry().program(&mut &self.node, name.to_string()))
            .map_err(|e| anyhow::anyhow!("registry.program('{name}'): {e}"))
    }

    pub fn agents(&self) -> anyhow::Result<Vec<AgentRow>> {
        vos::block_on(self.registry().agents_all(&mut &self.node))
            .map_err(|e| anyhow::anyhow!("registry.agents(): {e}"))
    }

    pub fn agent(&self, instance_name: &str) -> anyhow::Result<Option<AgentRow>> {
        vos::block_on(
            self.registry()
                .agent(&mut &self.node, instance_name.to_string()),
        )
        .map_err(|e| anyhow::anyhow!("registry.agent('{instance_name}'): {e}"))
    }

    /// Ask the connected daemon for its view of a Raft group
    /// (identified by `replication_id`) via a `RaftStatusReq` frame —
    /// role, term, leader hint, and member prefixes. Errors if the
    /// daemon peer isn't reachable or doesn't answer in time; a
    /// `present = false` reply (daemon isn't running that group) is
    /// returned as-is for the caller to report.
    pub fn raft_status(
        &self,
        replication_id: [u8; 32],
    ) -> anyhow::Result<vos::network::RaftStatusReply> {
        let net = self
            .node
            .network()
            .ok_or_else(|| anyhow::anyhow!("client has no network attached"))?;
        // The endpoint records the full identity we dialled. Never resolve
        // this management request through the collision-prone prefix map.
        let peer = self.daemon_peer_id()?;
        net.send_raft_status_req(peer, replication_id)
            .recv_timeout(invoke_timeout())
            .map_err(|_| anyhow::anyhow!("no raft-status reply from daemon within timeout"))
    }

    /// Drive one idempotent production voter replacement through the daemon.
    /// A follower proxies to its exact authenticated leader while preserving
    /// this client's Noise-authenticated operator identity.
    pub fn replace_raft_voter(
        &self,
        replication_id: [u8; 32],
        old: &MemberRow,
        replacement: &MemberRow,
        operation_epoch: u64,
    ) -> anyhow::Result<vos::network::RaftReplaceVoterResult> {
        let net = self
            .node
            .network()
            .ok_or_else(|| anyhow::anyhow!("client has no network attached"))?;
        let daemon = self.daemon_peer_id()?;
        let operator = libp2p::PeerId::from(self.signer.public());
        let signed = vos::registry::raft_voter_replacement_signed_bytes(
            &replication_id,
            old.prefix,
            &old.key,
            replacement.prefix,
            &replacement.key,
            operation_epoch,
        );
        let operator_signature: [u8; vos::registry::OP_SIG_LEN] = self
            .signer
            .sign(&signed)
            .map_err(|error| anyhow::anyhow!("sign Raft voter replacement: {error}"))?
            .try_into()
            .map_err(|_| anyhow::anyhow!("operator produced a non-Ed25519 signature"))?;
        net.send_raft_replace_voter_req(
            daemon,
            replication_id,
            old.prefix,
            old.key.clone(),
            replacement.prefix,
            replacement.key.clone(),
            operator.to_bytes(),
            operation_epoch,
            operator_signature,
        )
        .recv_timeout(Duration::from_secs(60))
        .map_err(|_| anyhow::anyhow!("no Raft voter-replacement reply within 60 seconds"))
    }

    /// Fetch the raw `.vos_meta` blob the registry has on file
    /// for the agent's program. Empty means no schema is registered.
    pub fn meta_for_instance(&self, instance_name: &str) -> anyhow::Result<Vec<u8>> {
        vos::block_on(
            self.registry()
                .meta_for_instance(&mut &self.node, instance_name.to_string()),
        )
        .map_err(|e| anyhow::anyhow!("registry.meta_for_instance('{instance_name}'): {e}"))
    }

    pub fn members(&self) -> anyhow::Result<Vec<MemberRow>> {
        // The registry pages the roster (nodes then identities);
        // `members_all` drains every page into one Vec.
        vos::block_on(self.registry().members_all(&mut &self.node))
            .map_err(|e| anyhow::anyhow!("registry.members(): {e}"))
    }

    // The catalog mutators (publish/unpublish/install/uninstall/upgrade)
    // pass an empty `auth`: the daemon signs them on relay with the
    // operator key it loaded at boot, so the signature is the operator's
    // regardless of whether the CLI or a keyless PVM agent drove the op.
    // See `space_registry`'s signed-registry-ops note.
    pub fn publish(&self, name: String, hash: Vec<u8>, crdt: bool) -> anyhow::Result<Status> {
        vos::block_on(
            self.registry()
                .publish(&mut &self.node, name, hash, crdt, Vec::new()),
        )
        .map_err(|e| anyhow::anyhow!("registry.publish(): {e}"))
    }

    /// Forward a program's `.vos_meta` schema blob to the registry,
    /// keyed by its program hash, so `meta_for_instance` (and thus
    /// schema-aware dynamic dispatch) resolves for agents installed off
    /// this program. Mirrors what the recipe reconciler does; empty
    /// `auth` is signed on relay by the daemon's operator key.
    pub fn register_meta(
        &self,
        program_hash: Vec<u8>,
        meta_blob: Vec<u8>,
    ) -> anyhow::Result<Status> {
        vos::block_on(self.registry().register_meta(
            &mut &self.node,
            program_hash,
            meta_blob,
            Vec::new(),
        ))
        .map_err(|e| anyhow::anyhow!("registry.register_meta(): {e}"))
    }

    pub fn unpublish(&self, name: String) -> anyhow::Result<Status> {
        vos::block_on(self.registry().unpublish(&mut &self.node, name, Vec::new()))
            .map_err(|e| anyhow::anyhow!("registry.unpublish(): {e}"))
    }

    #[allow(clippy::too_many_arguments)]
    pub fn install(
        &self,
        instance_name: String,
        program_name: String,
        program_hash: Vec<u8>,
        replication_id: Vec<u8>,
        consistency: u8,
        network_reachable: bool,
        sync_role: vos::registry::SyncFloor,
    ) -> anyhow::Result<Status> {
        vos::block_on(self.registry().install(
            &mut &self.node,
            instance_name,
            program_name,
            program_hash,
            replication_id,
            consistency,
            network_reachable,
            sync_role,
            Vec::new(),
        ))
        .map_err(|e| anyhow::anyhow!("registry.install(): {e}"))
    }

    pub fn upgrade(
        &self,
        instance_name: String,
        program_name: String,
        program_hash: Vec<u8>,
    ) -> anyhow::Result<Status> {
        use vos::service::ServiceWire as _;

        // Compare-and-swap base: read the instance's live program hash so
        // the registry rejects this upgrade if the instance has moved on
        // (a replayed or superseded upgrade cannot roll the package back).
        let installed = vos::block_on(
            self.registry()
                .agent(&mut &self.node, instance_name.clone()),
        )
        .map_err(|e| anyhow::anyhow!("registry.agent(): {e}"))?
        .ok_or_else(|| anyhow::anyhow!("upgrade: instance '{instance_name}' is not installed"))?;
        let from_hash = installed.program_hash;
        let to_hash: [u8; 32] = program_hash
            .as_slice()
            .try_into()
            .map_err(|_| anyhow::anyhow!("upgrade: target program hash must be 32 bytes"))?;
        let from_artifact = crate::blob_store::cache_get(&crate::blob_store::BlobHash(from_hash))?
            .ok_or_else(|| {
                anyhow::anyhow!(
                    "upgrade: current program {} is absent from the local cache; refusing to mutate the catalog without classifying its runtime ABI",
                    hex::encode(from_hash),
                )
            })?;
        let to_artifact = crate::blob_store::cache_get(&crate::blob_store::BlobHash(to_hash))?
            .ok_or_else(|| {
                anyhow::anyhow!(
                    "upgrade: target program {} is absent from the local cache; refusing to mutate the catalog without classifying its runtime ABI",
                    hex::encode(to_hash),
                )
            })?;
        let from = from_artifact.get(..4) == Some(b"VOSP");
        let to = to_artifact.get(..4) == Some(b"VOSP");
        let terminal_catalog_retry = from_hash == to_hash;
        if from != to {
            anyhow::bail!("upgrade cannot change the package format");
        }
        if from {
            let from_package = decode_exact_service_package(&from_artifact, "installed")?;
            let to_package = decode_exact_service_package(&to_artifact, "replacement")?;
            if instance_name == vos::service::ROLE_AUTHORITY_INSTANCE_ {
                let root_peer_id = vos::block_on(self.registry().root(&mut &self.node))
                    .map_err(|error| anyhow::anyhow!("registry.root(): {error}"))?;
                let consistency = super::common::consistency_from_u8(installed.consistency)
                    .ok_or_else(|| anyhow::anyhow!("space-authority has unknown consistency"))?;
                super::up::validate_role_authority_deployment(
                    &from_package,
                    &root_peer_id,
                    consistency,
                )?;
                super::up::validate_role_authority_deployment(
                    &to_package,
                    &root_peer_id,
                    consistency,
                )?;
            }
            let target = self.resolve_target(&instance_name)?;
            let actor = self
                .service_targets
                .lock()
                .map_err(|_| anyhow::anyhow!("service target cache is unavailable"))?
                .get(&target.0)
                .map(|target| target.actor)
                .ok_or_else(|| anyhow::anyhow!("installed root is not a signed service target"))?;
            let request = vos::service::RootTreeUpgradeRequest {
                expected_deployment: from_package.deployment_id(),
                expected_program: from_package.manifest.actor_program,
                replacement: to_package.clone(),
            };
            let mut nonce = [0; 32];
            getrandom::getrandom(&mut nonce)
                .map_err(|error| anyhow::anyhow!("mint service upgrade invocation ID: {error}"))?;
            let ingress = vos::service::RootTreeInvocation {
                invocation: vos::service::InvocationId::derive(
                    b"vosx/root-upgrade/service",
                    &nonce,
                ),
                target: actor,
                method: vos::service::ROOT_UPGRADE_METHOD_.into(),
                arguments: vos::service::ServiceWire::encode(&request),
                proof_requested: false,
            };
            let reply = self
                .node
                .invoke_with_timeout(
                    target,
                    vos::service::ServiceWire::encode(&ingress),
                    Duration::from_secs(120),
                )
                .ok_or_else(|| {
                    anyhow::anyhow!(
                        "service root upgrade was refused or its durable disposition could not be recovered"
                    )
                })?;
            let result = vos::service::AccumulationResult::decode(&reply)
                .map_err(|error| anyhow::anyhow!("decode service root upgrade result: {error}"))?;
            match result {
                vos::service::AccumulationResult::ActorUpgraded {
                    actor: committed_actor,
                    previous_deployment,
                    previous_program,
                    deployment,
                    program,
                    duplicate,
                    ..
                } if committed_actor == actor
                    && deployment == to_package.deployment_id()
                    && program == to_package.manifest.actor_program
                    && ((!terminal_catalog_retry
                        && previous_deployment == from_package.deployment_id()
                        && previous_program == from_package.manifest.actor_program)
                        || (terminal_catalog_retry && duplicate)) => {}
                vos::service::AccumulationResult::Rejected(rejection) => {
                    anyhow::bail!("guest rejected service root upgrade: {rejection:?}")
                }
                _ => anyhow::bail!("service root returned a mismatched upgrade result"),
            }
        }
        if terminal_catalog_retry {
            return Ok(Status::Ok);
        }
        vos::block_on(self.registry().upgrade(
            &mut &self.node,
            instance_name,
            program_name,
            program_hash,
            from_hash.to_vec(),
            Vec::new(),
        ))
        .map_err(|e| anyhow::anyhow!("registry.upgrade(): {e}"))
    }

    pub fn uninstall(&self, instance_name: String) -> anyhow::Result<Status> {
        vos::block_on(
            self.registry()
                .uninstall(&mut &self.node, instance_name, Vec::new()),
        )
        .map_err(|e| anyhow::anyhow!("registry.uninstall(): {e}"))
    }

    pub fn add_node(&self, prefix: u32, peer_id: Vec<u8>, role: u8) -> anyhow::Result<Status> {
        let auth = op_auth(
            &self.signer,
            "add_node",
            &[&prefix.to_le_bytes(), &peer_id, &[role]],
        )?;
        vos::block_on(
            self.registry()
                .add_node(&mut &self.node, prefix, peer_id, role, auth),
        )
        .map_err(|e| anyhow::anyhow!("registry.add_node(): {e}"))
    }

    pub fn remove_node(&self, prefix: u32) -> anyhow::Result<Status> {
        let auth = op_auth(&self.signer, "remove_node", &[&prefix.to_le_bytes()])?;
        vos::block_on(self.registry().remove_node(&mut &self.node, prefix, auth))
            .map_err(|e| anyhow::anyhow!("registry.remove_node(): {e}"))
    }

    pub fn add_identity(
        &self,
        public_key: Vec<u8>,
        proof_kind: u8,
        proof_data: Vec<u8>,
    ) -> anyhow::Result<Status> {
        let auth = op_auth(
            &self.signer,
            "add_identity",
            &[&public_key, &[proof_kind], &proof_data],
        )?;
        vos::block_on(self.registry().add_identity(
            &mut &self.node,
            public_key,
            proof_kind,
            proof_data,
            auth,
        ))
        .map_err(|e| anyhow::anyhow!("registry.add_identity(): {e}"))
    }

    pub fn remove_identity(&self, public_key: Vec<u8>) -> anyhow::Result<Status> {
        let auth = op_auth(&self.signer, "remove_identity", &[&public_key])?;
        vos::block_on(
            self.registry()
                .remove_identity(&mut &self.node, public_key, auth),
        )
        .map_err(|e| anyhow::anyhow!("registry.remove_identity(): {e}"))
    }

    // ── Auth grants ────────────────────────────────────

    pub fn grant_role(&self, peer_id: Vec<u8>, role: u8) -> anyhow::Result<Status> {
        let authority = self
            .role_authority_id()?
            .ok_or_else(|| anyhow::anyhow!("the space role authority is not installed"))?;
        self.require_service_role_authority_root()?;
        // Read the peer's current freshness epoch and sign `epoch + 1`
        // so the grant strictly post-dates any prior revoke — a replayed
        // stale-epoch grant can never resurrect a revoked role.
        let epoch = self.peer_epoch(peer_id.clone())? + 1;
        let auth = op_auth(
            &self.signer,
            "grant_role",
            &[&peer_id, &[role], &epoch.to_le_bytes(), &authority],
        )?;
        let status = vos::block_on(self.registry().grant_role(
            &mut &self.node,
            peer_id.clone(),
            role,
            epoch,
            authority.to_vec(),
            auth,
        ))
        .map_err(|e| anyhow::anyhow!("registry.grant_role(): {e}"))?;
        if status == Status::Ok {
            let mutation = role_grant_mutation(self.service_space_id()?, &peer_id, role, epoch)?;
            self.commit_service_role_mutation(&mutation).map_err(|error| {
                anyhow::anyhow!(
                    "registry grant committed at epoch {epoch}, but service authority did not: {error}; retry the same grant"
                )
            })?;
        }
        Ok(status)
    }

    pub fn revoke_role(&self, peer_id: Vec<u8>) -> anyhow::Result<Status> {
        let authority = self
            .role_authority_id()?
            .ok_or_else(|| anyhow::anyhow!("the space role authority is not installed"))?;
        self.require_service_role_authority_root()?;
        let epoch = self.peer_epoch(peer_id.clone())? + 1;
        let auth = op_auth(
            &self.signer,
            "revoke_role",
            &[&peer_id, &epoch.to_le_bytes(), &authority],
        )?;
        let status = vos::block_on(self.registry().revoke_role(
            &mut &self.node,
            peer_id.clone(),
            epoch,
            authority.to_vec(),
            auth,
        ))
        .map_err(|e| anyhow::anyhow!("registry.revoke_role(): {e}"))?;
        if status == Status::Ok {
            let mutation = role_revoke_mutation(self.service_space_id()?, &peer_id, epoch);
            self.commit_service_role_mutation(&mutation).map_err(|error| {
                anyhow::anyhow!(
                    "registry revoke committed at epoch {epoch}, but service authority did not: {error}; retry the same revoke"
                )
            })?;
        }
        Ok(status)
    }

    pub fn role_authority_id(&self) -> anyhow::Result<Option<[u8; 32]>> {
        let marker = vos::block_on(self.registry().role_authority(&mut &self.node))
            .map_err(|error| anyhow::anyhow!("registry.role_authority(): {error}"))?;
        if marker.is_empty() {
            return Ok(None);
        }
        let marker: [u8; 32] = marker
            .try_into()
            .map_err(|_| anyhow::anyhow!("registry role-authority marker is corrupt"))?;
        if marker == [0; 32] {
            anyhow::bail!("registry role-authority marker is zero");
        }
        Ok(Some(marker))
    }

    fn require_service_role_authority_root(&self) -> anyhow::Result<()> {
        let root = vos::block_on(self.registry().root(&mut &self.node))
            .map_err(|error| anyhow::anyhow!("registry.root(): {error}"))?;
        let signer = libp2p::PeerId::from(self.signer.public()).to_bytes();
        if root.is_empty() || signer != root {
            anyhow::bail!(
                "service role mutations must be signed by this space's immutable root identity"
            );
        }
        Ok(())
    }

    fn service_space_id(&self) -> anyhow::Result<vos::service::SpaceId> {
        self.entry
            .id_bytes()
            .map(vos::service::SpaceId)
            .ok_or_else(|| anyhow::anyhow!("space ID is not canonical hex"))
    }

    fn commit_service_role_mutation(
        &self,
        mutation: &vos::service::RoleAuthorityMutation,
    ) -> anyhow::Result<()> {
        use vos::service::ServiceWire;

        let mutation_bytes = mutation.encode();
        let signature = self
            .signer
            .sign(&mutation_bytes)
            .map_err(|error| anyhow::anyhow!("sign service role mutation: {error}"))?;
        if signature.len() != vos::registry::OP_SIG_LEN {
            anyhow::bail!("service role authority requires an Ed25519 root identity");
        }
        let target = self.resolve_target(vos::service::ROLE_AUTHORITY_INSTANCE_)?;
        if !self.service_targets.lock().unwrap().contains_key(&target.0) {
            anyhow::bail!("canonical space-authority package is unavailable to the CLI");
        }
        let reply = self.invoke_dyn(
            target,
            &vos::value::Msg::new(vos::service::ROLE_AUTHORITY_MUTATION_METHOD_)
                .with("mutation", mutation_bytes)
                .with("signature", signature),
        )?;
        if reply.as_bool() != Some(true) {
            anyhow::bail!("space-authority rejected the signed mutation");
        }
        Ok(())
    }

    /// Current freshness epoch for `peer_id` — read before signing a
    /// `grant_role`/`revoke_role`.
    fn peer_epoch(&self, peer_id: Vec<u8>) -> anyhow::Result<u64> {
        vos::block_on(self.registry().peer_epoch(&mut &self.node, peer_id))
            .map_err(|e| anyhow::anyhow!("registry.peer_epoch(): {e}"))
    }

    #[allow(dead_code)] // exposed for tooling; CLI consumers use `space role list`.
    pub fn peer_role(&self, peer_id: Vec<u8>) -> anyhow::Result<u8> {
        vos::block_on(self.registry().peer_role(&mut &self.node, peer_id))
            .map_err(|e| anyhow::anyhow!("registry.peer_role(): {e}"))
    }

    pub fn auth_grants(&self) -> anyhow::Result<Vec<vos::registry::AuthGrantRow>> {
        // The registry pages this list; drain every page into one Vec so
        // callers keep the whole-catalog view. The cursor is the last
        // scanned peer id; an empty `next` ends the walk.
        let mut out = Vec::new();
        let mut after: Vec<u8> = Vec::new();
        loop {
            let page = vos::block_on(self.registry().auth_grants(&mut &self.node, after, 0))
                .map_err(|e| anyhow::anyhow!("registry.auth_grants(): {e}"))?;
            out.extend(page.grants);
            if page.next.is_empty() {
                break;
            }
            after = page.next;
        }
        Ok(out)
    }

    // ── Invites ─────────────────────────────────────────────────

    /// Drain every page of the invites table into one Vec. The cursor is
    /// the last scanned `token_pub`; an empty `next` ends the walk (same
    /// shape as `auth_grants`).
    pub fn invites(&self) -> anyhow::Result<Vec<vos::registry::InviteRow>> {
        let mut out = Vec::new();
        let mut after: Vec<u8> = Vec::new();
        loop {
            let page = vos::block_on(self.registry().invites(&mut &self.node, after, 0))
                .map_err(|e| anyhow::anyhow!("registry.invites(): {e}"))?;
            out.extend(page.invites);
            if page.next.is_empty() {
                break;
            }
            after = page.next;
        }
        Ok(out)
    }

    /// Flip an invite's `revoked` flag (grow-only, idempotent). The
    /// canonical is just `("revoke_invite", [token_pub])` — no epoch,
    /// unlike grant/revoke_role.
    pub fn revoke_invite(&self, token_pub: Vec<u8>) -> anyhow::Result<Status> {
        self.role_authority_id()?
            .ok_or_else(|| anyhow::anyhow!("the space role authority is unavailable"))?;
        let token: [u8; 32] = token_pub
            .as_slice()
            .try_into()
            .map_err(|_| anyhow::anyhow!("invite token public key is not 32 bytes"))?;
        self.commit_service_invite_revocation(token)?;
        let auth = op_auth(&self.signer, "revoke_invite", &[&token_pub])?;
        vos::block_on(
            self.registry()
                .revoke_invite(&mut &self.node, token_pub, auth),
        )
        .map_err(|e| anyhow::anyhow!("registry.revoke_invite(): {e}"))
    }

    fn commit_service_invite_revocation(&self, token_pub: [u8; 32]) -> anyhow::Result<()> {
        use vos::service::ServiceWire;

        let revocation = vos::service::RoleAuthorityInviteRevocation {
            space: self.service_space_id()?,
            token_pub,
            admin_peer_id: libp2p::PeerId::from(self.signer.public()).to_bytes(),
        };
        let signature = self
            .signer
            .sign(&revocation.encode())
            .map_err(|error| anyhow::anyhow!("sign service invite revocation: {error}"))?;
        if signature.len() != vos::registry::OP_SIG_LEN {
            anyhow::bail!("service role authority requires an Ed25519 admin identity");
        }
        let target = self.resolve_target(vos::service::ROLE_AUTHORITY_INSTANCE_)?;
        if !self.service_targets.lock().unwrap().contains_key(&target.0) {
            anyhow::bail!("canonical space-authority package is unavailable to the CLI");
        }
        let reply = self.invoke_dyn(
            target,
            &vos::value::Msg::new(vos::service::ROLE_AUTHORITY_INVITE_REVOKE_METHOD_)
                .with("revocation", revocation.encode())
                .with("signature", signature),
        )?;
        if reply.as_bool() != Some(true) {
            anyhow::bail!("space-authority rejected the signed invite revocation");
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use vos::service::ServiceWire;

    fn target(method: &str, public: bool, attested: bool) -> ServiceTarget {
        let policy = vos::service::MethodPolicy {
            method: method.to_string(),
            schema: vos::service::Hash([1; 32]),
            policy: vos::service::Hash([2; 32]),
            public,
            attested,
            space_role: None,
            actor_role: None,
        };
        ServiceTarget {
            actor: vos::service::ActorId([0x41; 32]),
            methods: [(method.to_string(), policy)].into_iter().collect(),
        }
    }

    #[test]
    fn service_ingress_preserves_typed_identity_and_actor_message() {
        let target = target("increment", true, false);
        let invocation = vos::service::InvocationId([0x17; 32]);
        let msg = vos::value::Msg::new("increment").with("by", 3u64);
        let mut arguments = vec![vos::value::TAG_DYNAMIC];
        arguments.extend_from_slice(&vos::Encode::encode(&msg));

        let encoded =
            encode_service_invocation(&target, invocation, &msg, arguments.clone()).unwrap();
        let decoded = vos::service::RootTreeInvocation::decode(&encoded).unwrap();

        assert_eq!(decoded.invocation, invocation);
        assert_eq!(decoded.target, target.actor);
        assert_eq!(decoded.method, "increment");
        assert_eq!(decoded.arguments, arguments);
        assert!(!decoded.proof_requested);
    }

    #[test]
    fn daemon_ingress_admits_space_roles_but_refuses_unwired_authorization_paths() {
        let invocation = vos::service::InvocationId([0x18; 32]);
        let msg = vos::value::Msg::new("claim");
        let arguments = vec![vos::value::TAG_DYNAMIC, 1];

        let attested = encode_service_invocation(
            &target("claim", true, true),
            invocation,
            &msg,
            arguments.clone(),
        )
        .unwrap_err()
        .to_string();
        assert!(attested.contains("proof-producing transport"));

        let mut space_role = target("claim", false, false);
        space_role.methods.get_mut("claim").unwrap().space_role =
            Some(vos::SpaceRole::Member.as_u8());
        assert!(
            encode_service_invocation(&space_role, invocation, &msg, arguments.clone(),).is_ok(),
            "the daemon obtains an invocation-scoped assertion from the installed authority",
        );
        assert_eq!(
            invoke_timeout_for_policy(space_role.methods.get("claim")),
            ROLE_AUTHORIZED_INVOKE_TIMEOUT_DEFAULT,
        );

        let mut actor_role = target("claim", false, false);
        actor_role.methods.get_mut("claim").unwrap().actor_role = Some(1);
        let protected = encode_service_invocation(&actor_role, invocation, &msg, arguments)
            .unwrap_err()
            .to_string();
        assert!(protected.contains("bound-handle credential"));
    }

    #[test]
    fn default_invoke_timeout_covers_the_default_raft_operation_budget() {
        assert!(INVOKE_TIMEOUT_DEFAULT >= Duration::from_secs(35));
    }

    #[test]
    fn reserved_lifecycle_operations_bypass_actor_package_dispatch() {
        assert!(is_reserved_host_operation("__stop"));
        assert!(is_reserved_host_operation("__describe"));
        assert!(!is_reserved_host_operation("stop"));
        assert!(!is_reserved_host_operation("value"));
    }

    #[test]
    fn root_upgrade_control_method_is_outside_the_actor_namespace() {
        assert!(vos::service::ROOT_UPGRADE_METHOD_.starts_with('\0'));
        assert!(!is_reserved_host_operation(
            vos::service::ROOT_UPGRADE_METHOD_
        ));
    }

    #[test]
    fn registry_peer_roles_map_to_exact_authority_mutations() {
        let space = vos::service::SpaceId([0x51; 32]);
        let peer = b"authenticated peer";
        let grant =
            role_grant_mutation(space, peer, vos::registry::AUTH_ROLE_DEVELOPER, 7).unwrap();
        assert_eq!(
            grant,
            vos::service::RoleAuthorityMutation::Grant {
                space,
                holder: vos::service::Origin::Member(
                    vos::service::SubjectId::of_authenticated_peer(peer)
                ),
                role: vos::SpaceRole::Developer,
                epoch: 7,
            }
        );
        assert_eq!(
            vos::service::RoleAuthorityMutation::decode(&grant.encode()).unwrap(),
            grant
        );
        assert_eq!(
            role_revoke_mutation(space, peer, 8),
            vos::service::RoleAuthorityMutation::Revoke {
                space,
                holder: vos::service::Origin::Member(
                    vos::service::SubjectId::of_authenticated_peer(peer)
                ),
                epoch: 8,
            }
        );
        assert!(role_grant_mutation(space, peer, 255, 9).is_err());
    }
}
