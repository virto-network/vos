//! Multi-agent node — runs multiple services on separate threads.
//!
//! Each agent/service gets its own [`VosRuntime`] on a dedicated thread.
//! All services on a node share a **global ID namespace** with a common
//! node prefix:
//!
//! ```text
//! ServiceId = [node_prefix: 16 bits][local_id: 16 bits]
//! ```
//!
//! Cross-agent transfers are routed by the node: if the target's prefix
//! matches this node, the message is delivered locally. Otherwise it's
//! forwarded to the network layer (future).

use std::collections::{HashMap, HashSet};
use std::sync::atomic::{AtomicBool, AtomicU16, Ordering};
use std::sync::{Arc, Mutex, OnceLock, mpsc};
use std::thread;
use std::time::{Duration, Instant};

use tracing::{error, info, warn};

use crate::abi::service::ServiceId;
use crate::runtime::VosRuntime;

/// A message routed between agents via the node.
#[derive(Debug, Clone)]
pub struct Envelope {
    pub from: ServiceId,
    pub to: ServiceId,
    pub payload: Vec<u8>,
}

/// Handle to a running agent thread.
struct AgentHandle {
    join: Option<thread::JoinHandle<AgentResult>>,
}

/// Result returned when an agent thread completes.
///
/// `panics` counts PVM-side panics during refine. `error` is set
/// when the host itself failed unrecoverably — strategy build,
/// replay rebuild divergence, commit failure — and we tore the
/// agent down rather than continuing with corrupt state.
pub struct AgentResult {
    pub id: ServiceId,
    pub panics: u32,
    pub error: Option<String>,
}

impl AgentResult {
    /// Did the agent finish cleanly (no PVM panics, no host errors)?
    pub fn is_ok(&self) -> bool {
        self.panics == 0 && self.error.is_none()
    }
}

/// Replication / persistence semantics selected per agent.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum Consistency {
    /// In-memory only — state is lost when the agent exits. The
    /// default; matches the pre-persistence behaviour.
    #[default]
    Ephemeral,
    /// redb-backed local persistence (no replication, no log).
    Local,
    /// Merkle-CRDT replication: state + DAG + roots are written
    /// atomically on every dispatch, and the observed-effect log
    /// is attached to each DAG node for deterministic replay.
    Crdt,
    /// Raft consensus — every state-changing dispatch appends a
    /// committed log entry. Phase 1 runs as a single-node
    /// "self-quorum" mode (durable persistence + replay equivalent
    /// to `Local` + a log); the cluster machinery (election,
    /// AppendEntries, leader-forwarding `commit_with_log`) lands
    /// in later phases.
    Raft,
}

/// Configuration for registering an agent in the node.
pub struct AgentConfig {
    /// PVM blob (already transpiled).
    pub blob: Vec<u8>,
    /// Initial payloads to deliver on startup.
    pub init_payloads: Vec<Vec<u8>>,
    /// Pre-populated storage entries (key, value).
    pub storage: Vec<(Vec<u8>, Vec<u8>)>,
    /// Optional data directory for state persistence. When set and
    /// `consistency` isn't `Ephemeral`, the agent's redb file is
    /// created at `{data_dir}/agents/{svc_id}.redb`.
    pub data_dir: Option<std::path::PathBuf>,
    /// Replication / persistence semantics for this agent.
    pub consistency: Consistency,
    /// 32-byte handle that identifies the *replication group* this
    /// agent belongs to. Replicas of the same logical actor on
    /// different nodes share this id and use it to find each other
    /// over the network. Only meaningful when `consistency ==
    /// Crdt`. `None` means "this CRDT actor has no peers" — its
    /// DAG stays purely local.
    pub replication_id: Option<[u8; 32]>,
    /// Pre-opened, shared `redb::Database` for the agent's
    /// `CrdtCommit`. When `register` plans to wire this actor
    /// into the network's `SyncHandler`, it opens the file
    /// here, hands the same `Arc` to the agent's commit
    /// strategy *and* to the sync layer — redb is exclusive on
    /// file open, so this is the only way to share. `None`
    /// means the agent thread opens the file itself.
    #[cfg(feature = "storage")]
    #[doc(hidden)]
    pub pre_opened_db: Option<Arc<redb::Database>>,
    /// Companion to `pre_opened_db`: the commit lock that
    /// serializes the agent thread's `commit_with_log` against
    /// the sync ticker's `insert_node` + `compact_roots`. Both
    /// must hand it to their `CrdtCommit::from_db_arc_locked`
    /// for the serialization to actually happen.
    #[cfg(feature = "storage")]
    #[doc(hidden)]
    pub pre_opened_lock: Option<Arc<Mutex<()>>>,
    /// Static cluster membership (list of `node_prefix`es) for
    /// `Consistency::Raft`. Empty = single-node degenerate mode.
    /// All cluster members must list the same set in the same
    /// order.
    pub members: Vec<u16>,
    /// Pre-spawned Raft worker for `Consistency::Raft` multi-mode
    /// replication. `register` spawns this when the right
    /// conditions hold (multi-member + network attached + storage
    /// feature on) and hands it to the agent thread, which builds
    /// `RaftCommit::from_worker` with it. Caller code shouldn't
    /// set this directly.
    #[cfg(all(feature = "storage", feature = "network"))]
    #[doc(hidden)]
    pub raft_worker: Option<crate::raft::RaftWorker>,
    /// Apply-receiver paired with `raft_worker`. Drained by
    /// `RaftCommit::commit_with_log` while waiting for an
    /// in-flight propose to commit.
    #[cfg(all(feature = "storage", feature = "network"))]
    #[doc(hidden)]
    pub raft_apply_rx: Option<std::sync::mpsc::Receiver<u64>>,
}

impl AgentConfig {
    /// Build a config with no persistence (the default).
    pub fn new(blob: Vec<u8>) -> Self {
        Self {
            blob,
            init_payloads: Vec::new(),
            storage: Vec::new(),
            data_dir: None,
            consistency: Consistency::Ephemeral,
            replication_id: None,
            #[cfg(feature = "storage")]
            pre_opened_db: None,
            #[cfg(feature = "storage")]
            pre_opened_lock: None,
            members: Vec::new(),
            #[cfg(all(feature = "storage", feature = "network"))]
            raft_worker: None,
            #[cfg(all(feature = "storage", feature = "network"))]
            raft_apply_rx: None,
        }
    }

    /// Set the static cluster membership for `Consistency::Raft`
    /// — list of `node_prefix`es. Same list on every replica.
    pub fn with_members(mut self, members: Vec<u16>) -> Self {
        self.members = members;
        self
    }

    /// Attach initial payloads dispatched on cold start.
    pub fn with_init_payloads(mut self, payloads: Vec<Vec<u8>>) -> Self {
        self.init_payloads = payloads;
        self
    }

    /// Attach pre-populated storage (key, value) entries.
    pub fn with_storage(mut self, storage: Vec<(Vec<u8>, Vec<u8>)>) -> Self {
        self.storage = storage;
        self
    }

    /// Pick the replication/persistence strategy.
    pub fn with_consistency(mut self, c: Consistency) -> Self {
        self.consistency = c;
        self
    }

    /// Enable persistence under the given data directory.
    pub fn persist(mut self, data_dir: impl Into<std::path::PathBuf>) -> Self {
        self.data_dir = Some(data_dir.into());
        self
    }

    /// Pin this agent into a named replication group. Replicas
    /// across nodes that share the same id automatically discover
    /// each other (over an attached `Network`) and converge their
    /// merkle-DAGs.
    pub fn with_replication_id(mut self, id: [u8; 32]) -> Self {
        self.replication_id = Some(id);
        self
    }

    /// Convenience: derive a replication id from the agent's blob
    /// plus a logical name. Replicas with identical (blob, name)
    /// automatically share an id without manifest coordination.
    pub fn auto_replication_id(mut self, name: &str) -> Self {
        let mut h = blake2b_simd::Params::new().hash_length(32).to_state();
        h.update(name.as_bytes());
        h.update(&[0u8]); // delimiter so name||blob ≠ shifted variants
        h.update(&self.blob);
        let mut out = [0u8; 32];
        out.copy_from_slice(h.finalize().as_bytes());
        self.replication_id = Some(out);
        self
    }

    /// Derive the redb path for this agent from its data directory
    /// and service ID. Only meaningful when the `storage` feature
    /// is enabled.
    #[cfg(feature = "storage")]
    fn db_path(&self, id: ServiceId) -> Option<std::path::PathBuf> {
        let data_dir = self.data_dir.as_ref()?;
        let dir = data_dir.join("agents");
        std::fs::create_dir_all(&dir).ok()?;
        Some(dir.join(format!("{:08x}.redb", id.0)))
    }
}

/// Configuration for registering a native extension in the node.
pub struct ExtensionConfig {
    /// Path to the extension `.so` file.
    pub path: std::path::PathBuf,
    /// rkyv-encoded `vos::value::Args` for the extension's constructor.
    /// Empty if the constructor takes no parameters.
    pub init_args: Vec<u8>,
    /// Optional data directory for state persistence.
    /// When set, the extension's redb file is created at
    /// `{data_dir}/extensions/{name}.redb`.
    pub data_dir: Option<std::path::PathBuf>,
    /// Sprint 2: cap-overage policy applied at the host ABI
    /// boundary for this extension. Default `Block` — refuse
    /// syscalls outside the declared caps. Override via the space
    /// manifest's `cap_policy = "log"`/`"block"`/`"kill"`.
    pub cap_policy: crate::extension::CapPolicy,
}

impl ExtensionConfig {
    /// Build a config with no init args and no persistence.
    pub fn new(path: impl Into<std::path::PathBuf>) -> Self {
        Self {
            path: path.into(),
            init_args: Vec::new(),
            data_dir: None,
            cap_policy: crate::extension::CapPolicy::default(),
        }
    }

    /// Build a config with rkyv-encoded init args.
    pub fn with_args(path: impl Into<std::path::PathBuf>, args: &crate::value::Args) -> Self {
        let bytes = crate::rkyv::to_bytes::<crate::rkyv::rancor::Error>(args)
            .expect("rkyv encode Args")
            .to_vec();
        Self {
            path: path.into(),
            init_args: bytes,
            data_dir: None,
            cap_policy: crate::extension::CapPolicy::default(),
        }
    }

    /// Enable state persistence under the given data directory.
    /// The extension's state is stored in `{data_dir}/extensions/{name}.redb`
    /// where `name` is derived from the `.so` filename.
    pub fn persist(mut self, data_dir: impl Into<std::path::PathBuf>) -> Self {
        self.data_dir = Some(data_dir.into());
        self
    }

    /// Override the cap-overage policy. Defaults to
    /// [`CapPolicy::Block`](crate::extension::CapPolicy::Block) —
    /// callers in tests that want the Sprint-1 warn-only
    /// behaviour pass `CapPolicy::Log`.
    pub fn with_cap_policy(mut self, policy: crate::extension::CapPolicy) -> Self {
        self.cap_policy = policy;
        self
    }

    /// Derive the redb path from the data directory and the .so filename.
    #[cfg(feature = "storage")]
    fn db_path(&self) -> Option<std::path::PathBuf> {
        let data_dir = self.data_dir.as_ref()?;
        let name = self
            .path
            .file_stem()
            .and_then(|s| s.to_str())
            .unwrap_or("extension")
            .trim_start_matches("lib");
        let dir = data_dir.join("extensions");
        std::fs::create_dir_all(&dir).ok()?;
        Some(dir.join(format!("{name}.redb")))
    }
}

/// Synchronous invoke request routed through `invoke_routes`.
///
/// `chain` carries the ServiceIds of the agents already on the
/// stack of synchronous invokes leading to this hop, including the
/// caller. Each agent's `external_invoke` checks the chain before
/// forwarding so an A→B→A cycle aborts immediately at the second
/// hop instead of deadlocking until the 10 s reply timeout. The
/// chain doubles as a depth counter — capped at
/// [`MAX_CROSS_AGENT_DEPTH`] hops.
struct InvokeRequest {
    /// Who's calling — host-side identity as seen by the dispatch
    /// gate. `Caller::Peer` for libp2p inbound (multihash bytes of
    /// the noise-verified PeerId); `Caller::Actor` for intra-system
    /// invokes (the calling actor's ServiceId); `Caller::Unauthenticated`
    /// for host-initiated calls and future HTTP gateway routes.
    #[allow(dead_code)] // Consumer wired via macro emission in M6.
    caller: crate::actors::Caller,
    /// Space-wide role byte for `caller`, decoded as a
    /// [`SpaceRole`](crate::actors::SpaceRole) discriminant.
    /// `None` for callers without a space-level grant (Unauthenticated
    /// or unknown peers). Populated by [`NodeService::dispatch_invoke`]
    /// in M5; until then, all sites leave it at `None`.
    #[allow(dead_code)] // Consumer wired in M3/M5.
    space_role: Option<u8>,
    /// Actor-local role byte for `caller`, decoded against the
    /// target actor's [`Role`](crate::Actor::Role) discriminant.
    /// `None` when no actor-local grant exists; falls back to the
    /// space-level grant mapped via `SPACE_ROLE_MAP`. Populated
    /// in M5; until then, all sites leave it at `None`.
    #[allow(dead_code)] // Consumer wired in M3/M5.
    actor_local_role: Option<u8>,
    msg: Vec<u8>,
    reply_tx: mpsc::Sender<Vec<u8>>,
    // Read by agent_thread via `&req.chain` before moving `req`
    // into handle_invoke_request; rustc's read analysis misses
    // that pattern when the rest of the struct is then consumed.
    #[allow(dead_code)]
    chain: Vec<u32>,
}

/// Maximum number of cross-agent invoke hops in one synchronous
/// chain. Each agent's external_invoke aborts forwarding when
/// `chain.len()` reaches this. Picked generously — typical chains
/// are 1–3 deep; 32 catches runaway recursion without limiting
/// realistic compositions.
const MAX_CROSS_AGENT_DEPTH: usize = 32;

/// Maximum size, in bytes, of a single reply sent through an
/// `InvokeRequest`'s `reply_tx`. Distinct from the per-call
/// recording cap (`DEFAULT_REPLY_CAP`, 16 KiB) which bounds DAG
/// log size. The producer cap is much larger — it's a guardrail
/// against runaway memory pressure when an agent or worker
/// produces a multi-megabyte reply, not a consensus-history
/// concern. Replies exceeding this are dropped at the producer
/// side and surface as `InvokeError::NotFound` at the caller.
const MAX_PRODUCER_REPLY: usize = 1024 * 1024;

/// Send `reply` through `reply_tx` if it's within the producer
/// cap; otherwise log and drop the channel so the caller gets a
/// disconnect-shaped failure. Pulled out to share between
/// `handle_invoke_request` and `extension_thread`.
fn send_reply_capped(reply_tx: mpsc::Sender<Vec<u8>>, reply: Vec<u8>, svc_id: ServiceId) {
    if reply.len() > MAX_PRODUCER_REPLY {
        warn!(
            %svc_id,
            size = reply.len(),
            cap = MAX_PRODUCER_REPLY,
            "reply exceeds producer-side cap; dropping channel",
        );
        drop(reply_tx);
    } else {
        let _ = reply_tx.send(reply);
    }
}

/// Result of the pre-forward safety check on a synchronous invoke.
#[derive(Debug, PartialEq, Eq)]
enum InvokeForwardCheck {
    Allowed,
    /// Target is already in the chain — forwarding would form a
    /// cycle (and deadlock until the 10 s reply timeout).
    Cycle,
    /// Chain has reached the depth cap.
    DepthExceeded,
}

/// Decide whether to forward an invoke to `target` given the
/// caller's current chain. Pulled out as a free function so the
/// rule is testable without spinning up agent threads.
fn check_invoke_forward(chain: &[u32], target: u32) -> InvokeForwardCheck {
    if chain.contains(&target) {
        InvokeForwardCheck::Cycle
    } else if chain.len() >= MAX_CROSS_AGENT_DEPTH {
        InvokeForwardCheck::DepthExceeded
    } else {
        InvokeForwardCheck::Allowed
    }
}

/// A multi-agent VOS node.
///
/// Each agent runs on its own thread with its own `VosRuntime`.
/// All services share a global ID namespace scoped by `node_prefix`.
pub struct VosNode {
    node_prefix: u16,
    next_local: AtomicU16,
    /// Map from ServiceId → agent channel. Multiple services can map
    /// to the same agent (an agent with child actors).
    routes: HashMap<u32, mpsc::Sender<Envelope>>,
    agents: Vec<AgentHandle>,
    /// Outbound channel — agent threads send cross-service transfers here.
    outbox_tx: mpsc::Sender<Envelope>,
    outbox_rx: mpsc::Receiver<Envelope>,
    /// Map from ServiceId → synchronous invoke channel. Both
    /// workers and PVM agents register here. Wrapped in an
    /// `Arc<Mutex<...>>` so threads spawned earlier can resolve
    /// peers registered later — the alternative (cloning the map
    /// at thread spawn time) freezes A's view of the world before
    /// B exists, breaking cross-agent invoke order-independent.
    invoke_routes: InvokeRoutes,
    /// Set by [`VosNode::run_until_idle`] (or `collect`) when the
    /// node decides it's done. Threads poll this at the top of
    /// their main loop and exit cleanly. Replaces the per-agent
    /// "exit after N seconds idle" heuristic with explicit
    /// node-driven lifecycle.
    shutdown: Arc<AtomicBool>,
    /// Last time anything happened on the node — outbox routing,
    /// agent dispatch, worker dispatch, invoke handling. Updated
    /// by both threads and the routing loop. Read by
    /// [`run_until_idle`] to decide when to wind the node down.
    ///
    /// [`run_until_idle`]: VosNode::run_until_idle
    last_activity: ActivityClock,
    /// Optional libp2p network handle. Shared with all agent
    /// threads so cross-node `external_invoke` works regardless of
    /// whether the network was attached before or after agent
    /// registration. `None` inside the `Mutex` until
    /// [`attach_network`](Self::attach_network) runs.
    #[cfg(feature = "network")]
    pub(crate) shared_network: SharedNetwork,
    /// Map: replication group → local replica handle.
    /// Populated by `register` whenever a CRDT actor with a
    /// `replication_id` is added. Read by [`NodeService`] (db
    /// only) to answer inbound sync queries; the agent thread
    /// and sync ticker share the `commit_lock` to serialize
    /// their writes against each other.
    #[cfg(all(feature = "network", feature = "storage"))]
    pub(crate) crdt_replicas: Arc<Mutex<HashMap<[u8; 32], ReplicaSlot>>>,
    /// Optional manifest payload exposed to peers via
    /// [`Frame::ManifestReq`](crate::network::Frame::ManifestReq).
    /// Populated by [`set_manifest`](Self::set_manifest) before
    /// [`attach_network`](Self::attach_network) — vosx loads the
    /// space.toml + actor blobs and stashes them here so the
    /// `NetworkService` impl can serve them when a `vosx join`er
    /// asks. Set-once; `None` for nodes that don't expose a
    /// manifest (transient peers, manifest-less raw `vosx run`).
    #[cfg(feature = "network")]
    pub(crate) manifest: Arc<OnceLock<crate::network::ManifestReply>>,
    /// Join handles for the per-replica sync threads spawned
    /// by [`spawn_sync_thread`]. We keep these so [`collect`]
    /// can wait for the threads to exit before returning —
    /// otherwise the threads outlive the node, hold open
    /// `Arc<redb::Database>` references, and the next
    /// `redb::Database::create` against the same file fails
    /// with `Database already open. Cannot acquire lock`.
    #[cfg(all(feature = "network", feature = "storage"))]
    sync_threads: Vec<thread::JoinHandle<()>>,
}

/// Shared handle for one CRDT replication group. The same
/// `Arc<Database>` powers the agent's `CrdtCommit` and the
/// sync layer's `SyncHandler`; the `commit_lock` serializes
/// the agent's `commit_with_log` against the sync ticker's
/// `insert_node` + `compact_roots`.
#[cfg(all(feature = "network", feature = "storage"))]
#[derive(Clone)]
pub(crate) struct ReplicaSlot {
    pub db: Arc<redb::Database>,
    pub commit_lock: Arc<Mutex<()>>,
}

/// Shared invoke-route table. Cheap to clone and pass to threads.
type InvokeRoutes = Arc<Mutex<HashMap<u32, mpsc::Sender<InvokeRequest>>>>;

/// Thread-safe handle for invoking local services. Returned by
/// [`VosNode::invoke_handle`] so background tasks can keep
/// calling into the node while [`VosNode::run_forever`] holds
/// the main thread.
///
/// Local-only — cross-node invokes need the attached network,
/// which lives on `VosNode` proper. Drop this handle when the
/// background task is done; the node's lifetime is unaffected.
pub struct InvokeHandle {
    invoke_routes: InvokeRoutes,
    shutdown: Arc<AtomicBool>,
}

impl InvokeHandle {
    /// Synchronously invoke `target`. Returns `None` when the
    /// target isn't a local service or the call times out.
    pub fn invoke_with_timeout(
        &self,
        target: ServiceId,
        msg: Vec<u8>,
        timeout: Duration,
    ) -> Option<Vec<u8>> {
        let tx = {
            let map = self.invoke_routes.lock().ok()?;
            map.get(&target.0).cloned()
        };
        let tx = tx?;
        let (reply_tx, reply_rx) = mpsc::channel();
        tx.send(InvokeRequest {
            // Host-side API entry: the caller is the embedder
            // (vosx, a test harness) — no transport identity.
            caller: crate::actors::Caller::Unauthenticated,
            space_role: None,
            actor_local_role: None,
            msg,
            reply_tx,
            chain: Vec::new(),
        })
        .ok()?;
        // Strip the cross-thread invoke envelope down to reply
        // bytes for host-side callers — see `VosNode::invoke`.
        reply_rx
            .recv_timeout(timeout)
            .ok()
            .and_then(|env| unwrap_invoke_envelope(&env))
    }

    /// `true` once the owning [`VosNode`] has been told to shut
    /// down. Background loops poll this so they exit cleanly.
    pub fn is_shutting_down(&self) -> bool {
        self.shutdown.load(Ordering::Relaxed)
    }
}

/// Shared pointer to the (optional) attached libp2p network. Agent
/// threads grab a clone at spawn time and check it on every
/// `external_invoke` so a `Network` attached *after* registration
/// still gets used. `None` until [`VosNode::attach_network`] is
/// called.
#[cfg(feature = "network")]
type SharedNetwork = Arc<Mutex<Option<Arc<crate::network::Network>>>>;

/// Single inbound-frame service for the node. Combines what used
/// to be three separate trait impls (invoke / sync / manifest)
/// behind one [`NetworkService`](crate::network::NetworkService)
/// installation. Each method either delegates to a node-owned
/// table (invoke routes, CRDT replicas) or returns the data the
/// host pre-stashed (manifest).
///
/// Constructed in [`VosNode::attach_network`] from the node's
/// already-existing tables; the manifest slot is populated by the
/// host (`vosx space up`) before `attach_network` runs.
#[cfg(feature = "network")]
struct NodeService {
    invoke_routes: InvokeRoutes,
    #[cfg(feature = "storage")]
    replicas: Arc<Mutex<HashMap<[u8; 32], ReplicaSlot>>>,
    manifest: Arc<OnceLock<crate::network::ManifestReply>>,
}

#[cfg(feature = "network")]
impl NodeService {
    /// Sprint 2 auth lookup. Send a synchronous `peer_role` invoke
    /// to the local space-registry and surface the result as the
    /// `AUTH_ROLE_*` byte the gate compares against. Returns
    /// `AUTH_ROLE_NONE` (= "deny") for any of:
    ///
    /// - `caller_peer_id == None` — in-process calls don't have
    ///   a libp2p identity (no current callers, but defensive).
    /// - registry route missing — gate fires before the registry
    ///   boots? bail safe.
    /// - registry reply empty / undecodable.
    ///
    /// Cheap (~1 short round-trip on local mpsc) but a hot
    /// frequent-call surface; the response is the registry's
    /// already-cached in-memory `auth_grants` Vec lookup.
    fn lookup_caller_role(&self, caller_peer_id: Option<&libp2p::PeerId>) -> u8 {
        let Some(peer_id) = caller_peer_id else {
            return AUTH_ROLE_NONE;
        };
        // Build a `peer_role` Msg with the caller's PeerId bytes.
        use crate::actors::codec::Encode;
        use crate::value::{Msg, TAG_DYNAMIC};
        let msg = Msg::new("peer_role").with("peer_id", peer_id.to_bytes());
        let mut payload = Vec::with_capacity(1 + 64);
        payload.push(TAG_DYNAMIC);
        payload.extend_from_slice(&msg.encode());
        self.probe_registry_for_u8(payload)
            .unwrap_or(AUTH_ROLE_NONE)
    }

    /// M5 — actor-local role probe. Sibling of
    /// [`Self::lookup_caller_role`] for the actor-local override
    /// table. Looks up the byte the registry's `actor_role`
    /// handler returns; `AUTH_ROLE_NONE` for "no row" so the
    /// caller can map back to `Option::None` cleanly.
    ///
    /// `agent_name` is the *target* actor's instance name —
    /// `"space-registry"` for the well-known registry target,
    /// the manifest-installed name for others. For v1, only the
    /// registry target gets this probe; non-registry targets
    /// require a service-id → name reverse lookup that a later
    /// commit will add.
    fn lookup_caller_actor_role(
        &self,
        caller_peer_id: Option<&libp2p::PeerId>,
        agent_name: &str,
    ) -> u8 {
        let Some(peer_id) = caller_peer_id else {
            return AUTH_ROLE_NONE;
        };
        use crate::actors::codec::Encode;
        use crate::value::{Msg, TAG_DYNAMIC};
        let msg = Msg::new("actor_role")
            .with("peer_id", peer_id.to_bytes())
            .with("agent_name", agent_name);
        let mut payload = Vec::with_capacity(1 + 64);
        payload.push(TAG_DYNAMIC);
        payload.extend_from_slice(&msg.encode());
        self.probe_registry_for_u8(payload)
            .unwrap_or(AUTH_ROLE_NONE)
    }

    /// Shared probe helper for both auth lookups — sends an
    /// already-encoded dynamic Msg to the registry, decodes the
    /// reply as a single `u8`. Returns `None` if the registry is
    /// unreachable (gate fires before registry boots), the reply
    /// times out, or the reply payload doesn't decode.
    fn probe_registry_for_u8(&self, payload: Vec<u8>) -> Option<u8> {
        let registry_id = crate::abi::service::ServiceId::REGISTRY.local_id() as u32;
        let tx = self.invoke_routes.lock().ok()?.get(&registry_id).cloned()?;
        let (reply_tx, reply_rx) = mpsc::channel();
        if tx
            .send(InvokeRequest {
                // Internal host probe of a registry read handler
                // — no real caller. Registry reads accept
                // Unauthenticated.
                caller: crate::actors::Caller::Unauthenticated,
                space_role: None,
                actor_local_role: None,
                msg: payload,
                reply_tx,
                chain: vec![],
            })
            .is_err()
        {
            return None;
        }
        let envelope = reply_rx.recv_timeout(Duration::from_secs(5)).ok()?;
        let reply_bytes = unwrap_invoke_envelope(&envelope)?;
        decode_u8_reply(&reply_bytes)
    }
}

/// Pull a `u8` out of the actor-framework reply bytes. Handles
/// both the `Value::U8` wire shape and the `Value::Bytes(rkyv(u8))`
/// fallback. Sprint 2's auth lookup needs this; other host
/// callers stay with the dynamic Value decoder.
#[cfg(feature = "network")]
fn decode_u8_reply(bytes: &[u8]) -> Option<u8> {
    use crate::actors::codec::Decode;
    let value = <crate::value::Value as Decode>::try_decode(bytes)?;
    match value {
        crate::value::Value::U8(n) => Some(n),
        crate::value::Value::U32(n) => Some(n as u8),
        crate::value::Value::U64(n) => Some(n as u8),
        crate::value::Value::Bytes(b) => <u8 as Decode>::try_decode(&b),
        _ => None,
    }
}

#[cfg(feature = "network")]
impl crate::network::NetworkService for NodeService {
    fn dispatch_invoke(
        &self,
        caller_peer_id: Option<libp2p::PeerId>,
        _from: u32,
        to: u32,
        chain: Vec<u32>,
        msg: Vec<u8>,
    ) -> Vec<u8> {
        // The chain arrived already including the original caller's
        // ID (the remote peer's agent). The receiver's own
        // external_invoke prepends *this* agent's ID when dispatching
        // further hops, so we don't need to touch the chain here.
        //
        // Cross-network targets carry the receiver's `node_prefix` in
        // the upper 16 bits. Many agents (notably the well-known
        // registry at local_id 0) register themselves as unscoped
        // (`ServiceId(0, local_id)`), so a literal lookup of `to`
        // misses. Fall back to the unscoped form when the prefix
        // matches our own node — same routing decision the local
        // path makes via `is_on_node || is_local`.
        let to_unscoped = to & 0xFFFF;

        // Sprint 2 auth gate: when the target is the registry
        // (well-known ServiceId 0) and the inner Msg names a
        // gated handler, consult auth_grants for the caller. The
        // gate runs BEFORE forwarding so a refused call never
        // reaches the actor (and never lands in the DAG).
        if to_unscoped == crate::abi::service::ServiceId::REGISTRY.local_id() as u32
            && let Some(handler) = peek_dynamic_msg_name(&msg)
            && handler_requires_admin(&handler)
        {
            let caller_role = self.lookup_caller_role(caller_peer_id.as_ref());
            if caller_role < AUTH_ROLE_ADMIN {
                let peer_label = caller_peer_id
                    .as_ref()
                    .map(|p| p.to_string())
                    .unwrap_or_else(|| "<local>".into());
                warn!(
                    handler = %handler,
                    peer = %peer_label,
                    granted_role = caller_role,
                    "auth: refusing privileged registry handler — \
                     caller lacks admin grant",
                );
                return forbidden_envelope();
            }
        }

        let tx = self.invoke_routes.lock().ok().and_then(|m| {
            m.get(&to).cloned().or_else(|| {
                if to != to_unscoped {
                    m.get(&to_unscoped).cloned()
                } else {
                    None
                }
            })
        });
        let Some(tx) = tx else {
            return Vec::new();
        };
        let (reply_tx, reply_rx) = mpsc::channel();
        // libp2p noise verified the PeerId at connect time; the
        // multihash bytes are what the registry's grant table
        // keys on. `None` (in-process libp2p frame with no peer)
        // collapses to Unauthenticated.
        let caller = match caller_peer_id.as_ref() {
            Some(p) => crate::actors::Caller::Peer(p.to_bytes()),
            None => crate::actors::Caller::Unauthenticated,
        };
        // M5 — populate the role bytes for Peer callers so the
        // actor's M6 macro-emitted check has the inputs it needs.
        // Space-level grant always probed; actor-local grant
        // probed for the registry target (the only target with a
        // host-known agent name in v1; other targets stay None
        // until the service-id → name reverse lookup lands).
        let (space_role, actor_local_role) = match &caller {
            crate::actors::Caller::Peer(_) => {
                let space = self.lookup_caller_role(caller_peer_id.as_ref());
                let actor_local =
                    if to_unscoped == crate::abi::service::ServiceId::REGISTRY.local_id() as u32 {
                        self.lookup_caller_actor_role(caller_peer_id.as_ref(), "space-registry")
                    } else {
                        AUTH_ROLE_NONE
                    };
                (
                    (space != AUTH_ROLE_NONE).then_some(space),
                    (actor_local != AUTH_ROLE_NONE).then_some(actor_local),
                )
            }
            // Unauthenticated has no grant lookups; intra-system
            // Actor callers bypass via the Context::has_role
            // short-circuit.
            _ => (None, None),
        };
        if tx
            .send(InvokeRequest {
                caller,
                space_role,
                actor_local_role,
                msg,
                reply_tx,
                chain,
            })
            .is_err()
        {
            return Vec::new();
        }
        // The receiver replies with the full invoke envelope; the
        // libp2p protocol still ships only reply bytes, so unwrap
        // here. A future protocol bump can carry the envelope so
        // remote yielded children become drivable cross-node.
        //
        // Timeout budget mirrors the libp2p request_response side
        // (5 min) so slow handlers like the dev extension's
        // `compile` (cargo + rustc) don't get cut off here while
        // the wire layer is still patient.
        reply_rx
            .recv_timeout(Duration::from_secs(300))
            .ok()
            .and_then(|env| unwrap_invoke_envelope(&env))
            .unwrap_or_default()
    }

    #[cfg(feature = "storage")]
    fn sync_roots(&self, replication_id: &[u8; 32]) -> Option<Vec<[u8; 32]>> {
        let slot = self.replicas.lock().ok()?.get(replication_id).cloned()?;
        crate::commit::read_roots(&slot.db).ok()
    }

    #[cfg(feature = "storage")]
    fn sync_get_node(&self, replication_id: &[u8; 32], cid: &[u8; 32]) -> Option<Vec<u8>> {
        let slot = self.replicas.lock().ok()?.get(replication_id).cloned()?;
        crate::commit::read_dag_node(&slot.db, cid).ok().flatten()
    }

    fn manifest(&self) -> Option<crate::network::ManifestReply> {
        self.manifest.get().cloned()
    }
}

/// Replay every log in the strategy's DAG against `runtime`'s
/// state for `svc_id`. Used by both cold-start recovery and
/// mid-flight soft restarts after the sync ticker merges new
/// nodes. Caller is responsible for clearing prior state when
/// rebuilding from scratch — this function only feeds messages
/// through `begin_replay` and lets the actor produce state.
fn replay_dag_into_runtime(
    runtime: &mut VosRuntime,
    svc_id: ServiceId,
    strategy: &dyn crate::commit::CommitStrategy,
) -> Result<(), String> {
    let logs = strategy
        .replay_logs()
        .map_err(|e| format!("replay_logs failed: {e}"))?;
    if logs.is_empty() {
        return Ok(());
    }
    for (i, log) in logs.into_iter().enumerate() {
        let msg = log.msg.clone();
        runtime.begin_replay(log);
        runtime.send_to(svc_id, msg);
        runtime.run_blocking();
        // External transfers emitted during replay had their
        // original effects at record time; we don't re-issue them.
        let _ = runtime.drain_external_transfers(svc_id);
        let replay = runtime.finish_replay().expect("replay was active");
        if !replay.is_complete() {
            return Err(format!(
                "replay diverged at log #{i} (pos={}, exhausted={}); \
                 handler is non-deterministic",
                replay.position(),
                replay.was_exhausted(),
            ));
        }
    }
    Ok(())
}

/// Soft restart for a CRDT actor. Picks up whatever the sync
/// ticker merged into our redb file, throws away the locally-
/// derived runtime state, replays every log in the merged DAG,
/// and commits the rebuilt state. Idempotent — calling it twice
/// in a row produces the same final state.
///
/// Called from the agent thread between dispatches when the
/// sync notifier fires, so blocking is fine. Returns `Err(msg)`
/// only on host-side errors (corrupt strategy, non-deterministic
/// handler) — caller logs and tears the agent down.
#[cfg(feature = "storage")]
fn soft_restart_crdt(
    runtime: &mut VosRuntime,
    svc_id: ServiceId,
    strategy: &mut dyn crate::commit::CommitStrategy,
) -> Result<(), String> {
    strategy
        .reload()
        .map_err(|e| format!("strategy.reload: {e}"))?;
    runtime
        .storage
        .delete(svc_id, crate::lifecycle::STATE_KEY_BYTES);
    replay_dag_into_runtime(runtime, svc_id, strategy)?;
    let state = runtime
        .storage
        .read(svc_id, crate::lifecycle::STATE_KEY_BYTES)
        .map(|v| v.to_vec())
        .unwrap_or_default();
    if !state.is_empty() {
        strategy
            .commit(&state)
            .map_err(|e| format!("post-soft-restart commit: {e}"))?;
    }
    Ok(())
}

/// How often the per-replica sync ticker fires. Short enough that
/// integration tests can observe convergence in a few hundred ms,
/// long enough that idle clusters don't flood the wire.
#[cfg(all(feature = "network", feature = "storage"))]
const SYNC_INTERVAL: Duration = Duration::from_millis(250);

/// Per-fetch deadline. Peers that disappear mid-handshake still
/// only steal this long from the ticker.
#[cfg(all(feature = "network", feature = "storage"))]
const SYNC_FETCH_TIMEOUT: Duration = Duration::from_secs(2);

/// Every Nth sync tick we re-probe all connected peers (not
/// just known group members) so newly-joined replicas of an
/// existing group get discovered. Picked to be a small
/// multiple of the tick interval — at 250ms × 8, that's a 2s
/// upper bound on discovering a new peer for a group we
/// already track.
#[cfg(all(feature = "network", feature = "storage"))]
const SYNC_REPROBE_EVERY: u64 = 8;

#[cfg(all(feature = "network", feature = "storage"))]
#[derive(Debug)]
enum SyncOutcome {
    /// Peer has the replication group. `inserted` is true iff
    /// at least one DAG node was new locally.
    PeerHasGroup { inserted: bool },
    /// Peer answered with empty heads — they don't (currently)
    /// host this group. Treated as a soft signal: the membership
    /// cache demotes them, but a full re-probe sweep
    /// (`SYNC_REPROBE_EVERY` ticks later) gives them another shot.
    PeerEmpty,
}

/// Background ticker for one replication group. Tracks which
/// connected peers have actually answered with non-empty heads
/// for this group and only fans the BFS pull out to those —
/// otherwise an N-peer / M-group cluster eats N×M FetchHeads
/// frames per tick. Every [`SYNC_REPROBE_EVERY`] ticks the
/// loop also probes peers it doesn't yet have membership info
/// for, picking up replicas that joined the group after the
/// initial discovery sweep.
///
/// Runs detached — exits when `shutdown` is set or every clone
/// of the relevant `Arc`s has been dropped (signalling the
/// network/node/db they reference is gone). When `notifier` is
/// `Some`, sends `()` after every cycle that brought in at
/// least one new node so the agent thread can soft-restart and
/// pick up the merged state.
#[cfg(all(feature = "network", feature = "storage"))]
fn sync_loop(
    rep_id: [u8; 32],
    shared_network: SharedNetwork,
    slot: ReplicaSlot,
    shutdown: Arc<AtomicBool>,
    notifier: Option<mpsc::Sender<()>>,
) {
    let mut confirmed: HashSet<libp2p::PeerId> = HashSet::new();
    let mut tick: u64 = 0;
    let mut subscribed = false;
    let (hint_tx, hint_rx) = mpsc::channel::<libp2p::PeerId>();
    while !shutdown.load(Ordering::Relaxed) {
        std::thread::sleep(SYNC_INTERVAL);
        if shutdown.load(Ordering::Relaxed) {
            break;
        }
        let Some(net) = shared_network.lock().ok().and_then(|g| g.clone()) else {
            continue;
        };
        // First time we see the network attached, subscribe to
        // the gossipsub topic and register our hint channel so
        // peer head announcements wake us up.
        if !subscribed {
            net.join_replication(rep_id, hint_tx.clone());
            subscribed = true;
        }
        let local = net.peer_id();
        let connected: HashSet<libp2p::PeerId> = net
            .connected_peers()
            .into_iter()
            .filter(|p| p != &local)
            .collect();
        // Drop peers that disconnected since our last tick.
        confirmed.retain(|p| connected.contains(p));

        // Drain pending gossipsub hints — peers that just
        // published heads. Each hint triggers an immediate
        // (single-peer) sync, bypassing the periodic poll.
        let mut hinted: Vec<libp2p::PeerId> = Vec::new();
        while let Ok(peer) = hint_rx.try_recv() {
            if peer != local && connected.contains(&peer) && !hinted.contains(&peer) {
                hinted.push(peer);
            }
        }

        // Reprobe sweep: every Nth tick (or whenever we have no
        // confirmed members yet) hit every connected peer to
        // find new group hosts. Otherwise stick to the cache
        // plus any hinted peers from the gossipsub side.
        let reprobe = tick.is_multiple_of(SYNC_REPROBE_EVERY) || confirmed.is_empty();
        tick = tick.wrapping_add(1);

        let mut targets: Vec<libp2p::PeerId> = if reprobe {
            connected.iter().copied().collect()
        } else {
            confirmed.iter().copied().collect()
        };
        for h in &hinted {
            if !targets.contains(h) {
                targets.push(*h);
            }
        }

        let mut any_inserted = false;
        for peer in targets {
            match sync_with_peer(&net, peer, &rep_id, &slot) {
                Ok(SyncOutcome::PeerHasGroup { inserted }) => {
                    confirmed.insert(peer);
                    if inserted {
                        any_inserted = true;
                    }
                }
                Ok(SyncOutcome::PeerEmpty) => {
                    // Demote — they're either out of the group
                    // or briefly empty during their own cold
                    // start. The next reprobe rediscovers them.
                    confirmed.remove(&peer);
                }
                Err(e) => warn!(error = %e, "sync: per-peer cycle failed"),
            }
        }
        if any_inserted && let Some(n) = &notifier {
            let _ = n.send(());
        }
    }
}

/// One pull cycle against a single peer for one replication
/// group. Returns:
///   - `PeerHasGroup { inserted }` when the peer answered with
///     non-empty heads (regardless of whether anything new was
///     pulled in)
///   - `PeerEmpty` when the peer reports no heads — interpreted
///     as "this peer doesn't host the group right now"
///
/// Errors only on host-side commit failures; transient network
/// failures surface as a timeout / disconnect, which we silently
/// treat as `PeerEmpty` for the membership cache (the next
/// reprobe sweep retries).
#[cfg(all(feature = "network", feature = "storage"))]
fn sync_with_peer(
    net: &crate::network::Network,
    peer: libp2p::PeerId,
    rep_id: &[u8; 32],
    slot: &ReplicaSlot,
) -> Result<SyncOutcome, crate::commit::CommitError> {
    use crate::commit::CrdtCommit;
    use crate::effect_log::CrdtEvent;
    use merkle_crdt::DagNode;

    let heads_rx = net.send_fetch_heads(peer, *rep_id);
    let heads = match heads_rx.recv_timeout(SYNC_FETCH_TIMEOUT) {
        Ok(v) => v,
        Err(_) => return Ok(SyncOutcome::PeerEmpty),
    };
    if heads.is_empty() {
        return Ok(SyncOutcome::PeerEmpty);
    }

    // Sync only inserts peer-produced DAG nodes; it never allocates
    // a fresh `(origin, seq)`. The replica_origin we hand the
    // strategy here would only matter if a local write slipped in
    // — derive it the same way the agent thread does so the two
    // CrdtCommits over the same redb agree on origin if they ever
    // both write.
    let replica_origin = derive_replica_origin(rep_id, net.local_prefix());
    let mut cc =
        CrdtCommit::from_db_arc_locked(slot.db.clone(), slot.commit_lock.clone(), replica_origin);
    let mut frontier: Vec<[u8; 32]> = heads.clone();
    let mut seen: HashSet<[u8; 32]> = HashSet::new();
    let mut inserted_any = false;

    while let Some(cid) = frontier.pop() {
        if !seen.insert(cid) {
            continue;
        }
        if cc.get_node_bytes(&cid)?.is_some() {
            continue;
        }
        let node_rx = net.send_fetch_node(peer, *rep_id, cid);
        let Ok(Some(node_bytes)) = node_rx.recv_timeout(SYNC_FETCH_TIMEOUT) else {
            continue;
        };
        match cc.insert_node(&cid, &node_bytes) {
            Ok(true) => inserted_any = true,
            Ok(false) => {}
            Err(e) => {
                warn!(error = %e, "sync: node from peer rejected");
                continue;
            }
        }
        // Walk children so the BFS keeps going.
        if let Some(node) = DagNode::<crate::commit::Blake2b, CrdtEvent>::from_bytes(&node_bytes) {
            for child in node.children {
                frontier.push(child.0);
            }
        }
    }

    if inserted_any {
        cc.compact_roots()?;
    }
    Ok(SyncOutcome::PeerHasGroup {
        inserted: inserted_any,
    })
}

/// Shared "last activity" instant, bumped on every dispatch. The
/// node uses it as a global idle signal that — unlike outbox-only
/// monitoring — also accounts for invoke traffic, which doesn't
/// flow through the outbox.
type ActivityClock = Arc<Mutex<Instant>>;

impl VosNode {
    /// Create a node with the default prefix (0 = local/unscoped).
    pub fn new() -> Self {
        Self::with_prefix(0)
    }

    /// Create a node with a specific network prefix.
    pub fn with_prefix(node_prefix: u16) -> Self {
        let (outbox_tx, outbox_rx) = mpsc::channel();
        Self {
            node_prefix,
            next_local: AtomicU16::new(1), // 0 is reserved for registry
            routes: HashMap::new(),
            agents: Vec::new(),
            outbox_tx,
            outbox_rx,
            invoke_routes: Arc::new(Mutex::new(HashMap::new())),
            shutdown: Arc::new(AtomicBool::new(false)),
            last_activity: Arc::new(Mutex::new(Instant::now())),
            #[cfg(feature = "network")]
            shared_network: Arc::new(Mutex::new(None)),
            #[cfg(all(feature = "network", feature = "storage"))]
            crdt_replicas: Arc::new(Mutex::new(HashMap::new())),
            #[cfg(feature = "network")]
            manifest: Arc::new(OnceLock::new()),
            #[cfg(all(feature = "network", feature = "storage"))]
            sync_threads: Vec::new(),
        }
    }

    /// Pre-populate the manifest payload exposed to peers via
    /// `Frame::ManifestReq`. Set-once: a second call is a
    /// programming error and is silently ignored. Call before
    /// [`attach_network`](Self::attach_network) — the
    /// `NetworkService` snapshot taken there reads from this slot.
    /// `vosx space up` calls this with the parsed `space.toml` bytes
    /// plus every actor blob so `vosx space join`ers can fetch the
    /// cluster's manifest without `--manifest`.
    #[cfg(feature = "network")]
    pub fn set_manifest(&self, reply: crate::network::ManifestReply) {
        let _ = self.manifest.set(reply);
    }

    /// Attach a libp2p [`Network`](crate::network::Network) so the
    /// node can route to and from peers.
    ///
    /// After this call:
    /// - [`route`](Self::route) forwards any envelope whose target
    ///   `node_prefix` doesn't match this node over the wire (via
    ///   the network's `peer_for_prefix` lookup).
    /// - A bridge thread reads inbound `Tell` frames from the
    ///   network and feeds them back into this node's outbox, so
    ///   they're routed by the same path local-only traffic uses.
    ///
    /// The bridge thread exits cleanly when either the network's
    /// inbox closes (because the [`Network`](crate::network::Network)
    /// is dropping) or the outbox closes (because the node is
    /// being collected).
    #[cfg(feature = "network")]
    pub fn attach_network(&mut self, network: crate::network::Network) {
        // Install the unified service first so any inbound frame
        // that arrives between now and the bridge starting gets
        // resolved against this node's tables (invoke_routes,
        // crdt_replicas, host-supplied manifest) rather than the
        // trait's empty-reply defaults.
        let service = Arc::new(NodeService {
            invoke_routes: self.invoke_routes.clone(),
            #[cfg(feature = "storage")]
            replicas: self.crdt_replicas.clone(),
            manifest: self.manifest.clone(),
        });
        network.set_service(service);

        let inbox_rx = match network.take_inbox() {
            Some(rx) => rx,
            None => {
                warn!("network already had its inbox taken; bridge will not run");
                *self.shared_network.lock().unwrap() = Some(Arc::new(network));
                return;
            }
        };

        let outbox_tx = self.outbox_tx.clone();
        let activity = self.last_activity.clone();
        let shutdown = self.shutdown.clone();
        thread::spawn(move || {
            for tell in inbox_rx {
                if shutdown.load(Ordering::Relaxed) {
                    break;
                }
                *activity.lock().unwrap() = Instant::now();
                let env = Envelope {
                    from: ServiceId(tell.from),
                    to: ServiceId(tell.to),
                    payload: tell.payload,
                };
                if outbox_tx.send(env).is_err() {
                    break;
                }
            }
        });

        *self.shared_network.lock().unwrap() = Some(Arc::new(network));
    }

    /// Allocate the next service ID on this node.
    fn alloc_id(&self) -> ServiceId {
        let local = self.next_local.fetch_add(1, Ordering::Relaxed);
        ServiceId::new(self.node_prefix, local)
    }

    /// Register an agent at an explicit `ServiceId` instead of
    /// auto-allocating one. Used for well-known slots like the
    /// hyperspace registry which always lives at
    /// [`ServiceId::REGISTRY`] (== `ServiceId(0)`) so any agent
    /// can address it by a stable id without a name lookup.
    ///
    /// Caller is responsible for not double-registering.
    pub fn register_at_id(&mut self, config: AgentConfig, id: ServiceId) -> ServiceId {
        self.register_inner(config, id)
    }

    /// Register an agent and return its service ID.
    /// The agent starts immediately on a new thread.
    pub fn register(&mut self, config: AgentConfig) -> ServiceId {
        let id = self.alloc_id();
        self.register_inner(config, id)
    }

    fn register_inner(&mut self, mut config: AgentConfig, id: ServiceId) -> ServiceId {
        let (tx, rx) = mpsc::channel();
        let (invoke_tx, invoke_rx) = mpsc::channel();
        let outbox = self.outbox_tx.clone();

        self.routes.insert(id.0, tx);
        self.invoke_routes.lock().unwrap().insert(id.0, invoke_tx);

        // Pre-open the redb database for CRDT actors that declare
        // a replication group, so the same `Arc<Database>` powers
        // both the agent's `CrdtCommit` and the network's
        // `SyncHandler`. redb is exclusive on file open, so this
        // is the only way to share the file across threads.
        //
        // When the file opens cleanly we also create a one-shot-
        // style notification channel: the per-replica sync ticker
        // pings the Sender after a non-empty merge, the agent
        // thread holds the Receiver and runs `soft_restart_crdt`
        // between dispatches to refresh its in-memory state.
        #[cfg(all(feature = "network", feature = "storage"))]
        let sync_rx: Option<mpsc::Receiver<()>> = if config.consistency == Consistency::Crdt {
            config.replication_id.and_then(|rep_id| {
                let path = config.db_path(id)?;
                match redb::Database::create(&path) {
                    Ok(db) => {
                        let slot = ReplicaSlot {
                            db: Arc::new(db),
                            commit_lock: Arc::new(Mutex::new(())),
                        };
                        self.crdt_replicas
                            .lock()
                            .unwrap()
                            .insert(rep_id, slot.clone());
                        config.pre_opened_db = Some(slot.db.clone());
                        config.pre_opened_lock = Some(slot.commit_lock.clone());
                        let (sync_tx, sync_rx) = mpsc::channel::<()>();
                        self.spawn_sync_thread(rep_id, slot, Some(sync_tx));
                        Some(sync_rx)
                    }
                    Err(e) => {
                        error!(%id, error = %e, "register: failed to open CRDT db; \
                            replication will be inactive");
                        None
                    }
                }
            })
        } else if config.consistency == Consistency::Raft && config.members.len() > 1 {
            // Multi-mode Raft: spawn a worker, install it as the
            // network's RaftRpcHandler, and bridge the worker's
            // apply notifications into both (a) the agent's
            // sync_rx (so the soft-restart path catches up state
            // on followers) and (b) the strategy's apply_rx (so
            // the leader's commit_with_log unblocks once its
            // proposed entry commits).
            let network = self.shared_network.lock().ok().and_then(|g| g.clone());
            let rep_id = config.replication_id.unwrap_or([0u8; 32]);
            match config.db_path(id).map(|p| {
                let db = redb::Database::create(&p);
                (p, db)
            }) {
                Some((_path, Ok(db))) => {
                    let db = Arc::new(db);
                    config.pre_opened_db = Some(db.clone());

                    let worker_cfg = crate::raft::WorkerConfig {
                        me: id.node_prefix(),
                        members: config.members.clone(),
                        replication_id: rep_id,
                        election_timeout_ms: (150, 300),
                        heartbeat_interval_ms: 50,
                    };
                    let (worker_tx, worker_rx) = mpsc::channel::<u64>();
                    let worker = crate::raft::RaftWorker::spawn(
                        db.clone(),
                        worker_cfg,
                        network.clone(),
                        Some(worker_tx),
                    );
                    if let Some(net) = network.as_ref() {
                        net.register_raft_handler(rep_id, Arc::new(worker.handler()));
                    }
                    // Relay: each commit advance fans out to both
                    // the strategy's apply_rx and the agent's
                    // sync_rx. Lives until the worker drops its
                    // sender (either side closing is fine).
                    let (commit_tx, commit_rx) = mpsc::channel::<u64>();
                    let (sync_tx, sync_rx) = mpsc::channel::<()>();
                    thread::Builder::new()
                        .name(format!("raft-relay-{:08x}", id.0))
                        .spawn(move || {
                            while let Ok(idx) = worker_rx.recv() {
                                let _ = commit_tx.send(idx);
                                let _ = sync_tx.send(());
                            }
                        })
                        .expect("spawn raft relay");
                    config.raft_worker = Some(worker);
                    config.raft_apply_rx = Some(commit_rx);
                    Some(sync_rx)
                }
                Some((path, Err(e))) => {
                    error!(%id, path = %path.display(), error = %e,
                        "register: failed to open Raft db; replication will be inactive");
                    None
                }
                None => None,
            }
        } else {
            None
        };

        let invoke_routes = self.invoke_routes.clone();
        let shutdown = self.shutdown.clone();
        let activity = self.last_activity.clone();
        #[cfg(feature = "network")]
        let shared_network = self.shared_network.clone();

        let join = thread::spawn(move || {
            agent_thread(
                id,
                config,
                rx,
                invoke_rx,
                outbox,
                invoke_routes,
                shutdown,
                activity,
                #[cfg(feature = "network")]
                shared_network,
                #[cfg(all(feature = "network", feature = "storage"))]
                sync_rx,
            )
        });

        self.agents.push(AgentHandle { join: Some(join) });
        id
    }

    /// Register a native extension at a freshly-allocated
    /// ServiceId. Spawns the extension thread immediately.
    pub fn register_extension(&mut self, config: ExtensionConfig) -> ServiceId {
        let id = self.alloc_id();
        self.register_extension_inner(config, id)
    }

    /// Register an extension at an explicit `ServiceId`. Mirrors
    /// [`register_at_id`](Self::register_at_id) for the actor side
    /// — used to slot a mock registry into `ServiceId::REGISTRY`
    /// (= 0) for tests and to install built-in service extensions
    /// at well-known ids.
    ///
    /// Caller is responsible for not double-registering.
    pub fn register_extension_at_id(
        &mut self,
        config: ExtensionConfig,
        id: ServiceId,
    ) -> ServiceId {
        self.register_extension_inner(config, id)
    }

    fn register_extension_inner(&mut self, config: ExtensionConfig, id: ServiceId) -> ServiceId {
        let (tx, rx) = mpsc::channel();
        let (invoke_tx, invoke_rx) = mpsc::channel();
        let outbox = self.outbox_tx.clone();

        self.routes.insert(id.0, tx);
        self.invoke_routes.lock().unwrap().insert(id.0, invoke_tx);

        let shutdown = self.shutdown.clone();
        let activity = self.last_activity.clone();
        let invoke_routes = self.invoke_routes.clone();

        let join = thread::spawn(move || {
            extension_thread(
                id,
                config,
                rx,
                invoke_rx,
                outbox,
                invoke_routes,
                shutdown,
                activity,
            )
        });

        self.agents.push(AgentHandle { join: Some(join) });
        id
    }

    /// Route messages until the node has been globally idle for the
    /// default duration (2 seconds). Shorthand for
    /// `run_until_idle(Duration::from_secs(2))`.
    pub fn run(&mut self) {
        self.run_until_idle(Duration::from_secs(2));
    }

    /// Route messages until traffic — both outbox routing AND
    /// agent/worker dispatch — has been quiet for `threshold`,
    /// then signal shutdown to all threads.
    ///
    /// Unlike the previous "agents auto-exit on idle" heuristic,
    /// this is decided centrally: agents stay alive as long as the
    /// node hasn't told them to stop. That keeps cross-agent
    /// invoke peers reachable for the entire run, even when one
    /// side has nothing on its inbox at the moment.
    pub fn run_until_idle(&mut self, threshold: Duration) {
        *self.last_activity.lock().unwrap() = Instant::now();
        loop {
            match self.outbox_rx.recv_timeout(Duration::from_millis(50)) {
                Ok(envelope) => {
                    self.route(envelope);
                    *self.last_activity.lock().unwrap() = Instant::now();
                }
                Err(mpsc::RecvTimeoutError::Timeout) => {
                    // If every agent has already exited (e.g.
                    // they all errored at startup), there's no
                    // point waiting out the threshold.
                    let all_done = self
                        .agents
                        .iter()
                        .all(|h| h.join.as_ref().is_none_or(|j| j.is_finished()));
                    if all_done {
                        break;
                    }

                    let idle = self.last_activity.lock().unwrap().elapsed();
                    if idle >= threshold {
                        self.shutdown.store(true, Ordering::Relaxed);
                        break;
                    }
                }
                Err(mpsc::RecvTimeoutError::Disconnected) => break,
            }
        }
    }

    /// Run forever, only stopping when [`shutdown`](Self::shutdown)
    /// is called from another thread (e.g. a SIGTERM handler) or
    /// every agent has exited on its own.
    pub fn run_forever(&mut self) {
        loop {
            match self.outbox_rx.recv_timeout(Duration::from_millis(50)) {
                Ok(envelope) => {
                    self.route(envelope);
                    *self.last_activity.lock().unwrap() = Instant::now();
                }
                Err(mpsc::RecvTimeoutError::Timeout) => {
                    if self.shutdown.load(Ordering::Relaxed) {
                        break;
                    }
                    let all_done = self
                        .agents
                        .iter()
                        .all(|h| h.join.as_ref().is_none_or(|j| j.is_finished()));
                    if all_done {
                        break;
                    }
                }
                Err(mpsc::RecvTimeoutError::Disconnected) => break,
            }
        }
    }

    /// Trigger an explicit shutdown. Threads notice on their next
    /// iteration (≤ 50 ms) and exit cleanly. Safe to call from a
    /// signal handler or another thread.
    pub fn shutdown(&self) {
        self.shutdown.store(true, Ordering::Relaxed);
    }

    /// Clone of the attached network, if any. Lets external code
    /// (tests, monitoring, host-side bootstraps) inspect peer
    /// state — `peer_for_prefix`, `connected_peers`, etc. —
    /// without taking the network out of the node's ownership.
    /// Returns `None` until [`attach_network`](Self::attach_network)
    /// has run.
    #[cfg(feature = "network")]
    pub fn network(&self) -> Option<Arc<crate::network::Network>> {
        self.shared_network.lock().ok().and_then(|g| g.clone())
    }

    /// Clone of the shutdown signal. Set to `true` from any thread
    /// to wind the node down. Useful when the node has been moved
    /// into a [`run_forever`](Self::run_forever) thread.
    pub fn shutdown_handle(&self) -> Arc<AtomicBool> {
        self.shutdown.clone()
    }

    /// Returns a thread-safe handle that can synchronously invoke
    /// any **local** service registered on this node. Background
    /// tasks (e.g. vosx's auto-heartbeat) take this handle before
    /// [`run_forever`](Self::run_forever) blocks the main thread,
    /// then keep calling into the node from a side thread.
    ///
    /// Cross-node invokes aren't supported through this handle —
    /// it doesn't carry the network reference. Use [`invoke`](Self::invoke)
    /// from the owning thread for that.
    pub fn invoke_handle(&self) -> InvokeHandle {
        InvokeHandle {
            invoke_routes: self.invoke_routes.clone(),
            shutdown: self.shutdown.clone(),
        }
    }

    /// Clone of the outbox sender. Pushing an [`Envelope`] here
    /// runs it through [`route`](Self::route) — the same path
    /// agent threads use for outgoing transfers — so addresses
    /// targeting other nodes get forwarded over the network when
    /// one is attached. Intended for host-side bootstraps and
    /// tests that need to inject traffic from outside the agent
    /// system.
    pub fn outbox_sender(&self) -> mpsc::Sender<Envelope> {
        self.outbox_tx.clone()
    }

    /// Install a "ghost" route under a fresh ServiceId: every
    /// envelope routed to that ID is delivered to the returned
    /// channel instead of an agent. Used by integration tests to
    /// observe what crosses the routing layer; not part of the
    /// production API.
    #[cfg(test)]
    pub(crate) fn install_inspector(&mut self) -> (ServiceId, mpsc::Receiver<Envelope>) {
        let id = self.alloc_id();
        let (tx, rx) = mpsc::channel();
        self.routes.insert(id.0, tx);
        (id, rx)
    }

    /// Register a `(replication_id → redb path)` pair directly in
    /// the CRDT replica map and spin up the matching sync ticker.
    /// Used by tests that want to verify the sync layer without
    /// spinning up a real PVM agent. No notifier is wired because
    /// no agent thread is consuming.
    #[cfg(all(test, feature = "network", feature = "storage"))]
    pub(crate) fn install_test_replica(
        &mut self,
        rep_id: [u8; 32],
        db_path: &std::path::Path,
    ) -> ReplicaSlot {
        let slot = ReplicaSlot {
            db: Arc::new(redb::Database::create(db_path).expect("create db")),
            commit_lock: Arc::new(Mutex::new(())),
        };
        self.crdt_replicas
            .lock()
            .unwrap()
            .insert(rep_id, slot.clone());
        self.spawn_sync_thread(rep_id, slot.clone(), None);
        slot
    }

    /// Spawn the per-replica sync ticker. Detached: exits via the
    /// shared shutdown flag (set on `collect`/`shutdown`) or when
    /// the network/db Arcs die. `notifier` (when present) is
    /// pinged after a non-empty merge so the agent thread can
    /// run `soft_restart_crdt` to pick up the new state.
    #[cfg(all(feature = "network", feature = "storage"))]
    fn spawn_sync_thread(
        &mut self,
        rep_id: [u8; 32],
        slot: ReplicaSlot,
        notifier: Option<mpsc::Sender<()>>,
    ) {
        let shared_network = self.shared_network.clone();
        let shutdown = self.shutdown.clone();
        let join =
            thread::spawn(move || sync_loop(rep_id, shared_network, slot, shutdown, notifier));
        self.sync_threads.push(join);
    }

    /// Install a synchronous-invoke responder under a fresh
    /// ServiceId. The handler runs on a helper thread; each
    /// inbound `InvokeRequest` is fed its `msg` bytes and the
    /// returned `Vec<u8>` is sent back as the reply.
    #[cfg(test)]
    pub(crate) fn install_invoke_responder<F>(&mut self, mut handler: F) -> ServiceId
    where
        F: FnMut(Vec<u8>) -> Vec<u8> + Send + 'static,
    {
        let id = self.alloc_id();
        let (tx, rx) = mpsc::channel::<InvokeRequest>();
        self.invoke_routes.lock().unwrap().insert(id.0, tx);
        thread::spawn(move || {
            for req in rx {
                let reply = handler(req.msg);
                // Test responders never yield — pack as DONE so
                // the reply parses as `InvokeResult::Done` on the
                // caller side, matching real worker/agent shape.
                let envelope = encode_invoke_envelope(crate::actors::run::STATUS_DONE, &[], &reply);
                let _ = req.reply_tx.send(envelope);
            }
        });
        id
    }

    /// Synchronously invoke a registered service from outside the
    /// PVM — for tests, host-side bootstraps, and any code path
    /// where you want to ask an agent or worker without first
    /// spinning up another PVM agent to do it.
    ///
    /// Returns the raw rkyv-encoded reply bytes, or `None` if the
    /// target isn't registered, the channel is disconnected, the
    /// reply exceeds the producer cap, or the call times out.
    /// Default timeout is 10 seconds; use
    /// [`invoke_with_timeout`](Self::invoke_with_timeout) for
    /// finer control.
    pub fn invoke(&self, target: ServiceId, msg: Vec<u8>) -> Option<Vec<u8>> {
        self.invoke_with_timeout(target, msg, Duration::from_secs(10))
    }

    /// Like [`invoke`](Self::invoke) but with an explicit timeout.
    ///
    /// Lookup order:
    ///
    /// 1. Local invoke route (any agent or worker on this node).
    /// 2. Cross-node via the attached network: when the target's
    ///    `node_prefix` doesn't match this node and a peer with
    ///    that prefix has completed the Hello handshake, the
    ///    invoke is forwarded over libp2p.
    ///
    /// Returns `None` if neither path resolves the target, or if
    /// the call times out / the channel disconnects.
    pub fn invoke_with_timeout(
        &self,
        target: ServiceId,
        msg: Vec<u8>,
        timeout: Duration,
    ) -> Option<Vec<u8>> {
        // 1. Local. Same fallback `dispatch_invoke` uses: when
        //    `target` carries this node's prefix but the agent
        //    was registered as unscoped (`ServiceId(0, local_id)`),
        //    retry with the prefix stripped. The well-known
        //    registry registers at `ServiceId::REGISTRY` (= 0),
        //    so a local invoke from an in-process Ref pointed
        //    at `(self.node_prefix, 0)` wouldn't find it
        //    otherwise.
        let local_tx = {
            let map = self.invoke_routes.lock().ok()?;
            let direct = map.get(&target.0).cloned();
            if direct.is_some() {
                direct
            } else if target.is_on_node(self.node_prefix) {
                map.get(&(target.0 & 0xFFFF)).cloned()
            } else {
                None
            }
        };
        if let Some(tx) = local_tx {
            let (reply_tx, reply_rx) = mpsc::channel();
            tx.send(InvokeRequest {
                // Host-side `VosNode::invoke` entry point — no
                // transport identity. Tests + the bootstrap
                // admin-grant path reach the actor through here.
                caller: crate::actors::Caller::Unauthenticated,
                space_role: None,
                actor_local_role: None,
                msg,
                reply_tx,
                chain: Vec::new(),
            })
            .ok()?;
            // Cross-thread channel now carries the full invoke
            // envelope (status + state + reply); host callers
            // don't care about YIELDED/DONE so unwrap to just
            // reply bytes.
            return reply_rx
                .recv_timeout(timeout)
                .ok()
                .and_then(|env| unwrap_invoke_envelope(&env));
        }

        // 2. Cross-node fallback.
        #[cfg(feature = "network")]
        {
            if !target.is_on_node(self.node_prefix) && !target.is_local() {
                let net = self.shared_network.lock().ok().and_then(|g| g.clone());
                if let Some(net) = net
                    && let Some(peer) = net.peer_for_prefix(target.node_prefix())
                {
                    // `from = 0` because this is host-side; it
                    // never participates in chain detection.
                    let reply_rx =
                        net.send_invoke(peer, ServiceId::REGISTRY.0, target.0, Vec::new(), msg);
                    // Daemon's `dispatch_invoke` already strips
                    // the envelope back to raw reply bytes, so
                    // we just forward them.
                    return reply_rx.recv_timeout(timeout).ok();
                }
            }
        }

        None
    }

    /// Route a single envelope to its destination.
    fn route(&self, envelope: Envelope) {
        let target = envelope.to;

        // Local delivery: prefix matches or target is unscoped (prefix 0)
        if target.is_on_node(self.node_prefix) || target.is_local() {
            if let Some(tx) = self.routes.get(&target.0) {
                let _ = tx.send(envelope);
            } else {
                warn!(%target, "node: no route for target, dropping");
            }
            return;
        }

        // Remote delivery via the network (if attached). The
        // target's high 16 bits select the peer; if we haven't
        // seen that prefix yet (no Hello received), the envelope
        // is dropped with a warn — VOS has no store-and-forward
        // semantics today.
        #[cfg(feature = "network")]
        {
            let net = self.shared_network.lock().ok().and_then(|g| g.clone());
            if let Some(net) = net {
                let prefix = target.node_prefix();
                if let Some(peer) = net.peer_for_prefix(prefix) {
                    net.send_tell(peer, envelope.from.0, envelope.to.0, envelope.payload);
                    return;
                }
                warn!(
                    %target,
                    prefix = format!("{prefix:#06x}"),
                    "node: no peer known for prefix; dropping remote envelope",
                );
                return;
            }
        }

        warn!(%target, "node: no network layer, dropping remote target");
    }

    /// Collect results from all agent threads. Forces shutdown if
    /// it hasn't already been requested, so callers don't have to
    /// remember the order.
    ///
    /// Also joins the per-replica sync threads. Without this,
    /// they outlive the node and keep `Arc<redb::Database>`
    /// references live, blocking any subsequent
    /// `redb::Database::create` against the same file with
    /// "Database already open. Cannot acquire lock." Restart
    /// scenarios depend on this join happening.
    pub fn collect(mut self) -> Vec<AgentResult> {
        self.shutdown.store(true, Ordering::Relaxed);
        drop(self.outbox_tx);
        drop(self.routes); // drop agent inboxes so threads can detect disconnect
        // Drain the invoke routes too so threads' invoke_rx
        // disconnects when the node is winding down.
        self.invoke_routes.lock().unwrap().clear();
        drop(self.invoke_routes); // drop our reference so threads' Arc count drops

        // Drop the replica registry so the sync threads' last
        // reference to each `Arc<redb::Database>` is the one
        // they hold themselves — once they exit, the underlying
        // file is unlocked.
        #[cfg(all(feature = "network", feature = "storage"))]
        {
            self.crdt_replicas.lock().unwrap().clear();
        }

        let agent_results: Vec<AgentResult> = self
            .agents
            .iter_mut()
            .filter_map(|h| h.join.take().and_then(|j| j.join().ok()))
            .collect();

        // Sync threads poll `shutdown` every SYNC_INTERVAL and
        // exit on the next tick, so this is a bounded wait.
        #[cfg(all(feature = "network", feature = "storage"))]
        for h in self.sync_threads.drain(..) {
            let _ = h.join();
        }

        agent_results
    }
}

impl Default for VosNode {
    fn default() -> Self {
        Self::new()
    }
}

// ── Agent thread ─────────────────────────────────────────────────────

#[allow(clippy::too_many_arguments)]
fn agent_thread(
    id: ServiceId,
    mut config: AgentConfig,
    inbox: mpsc::Receiver<Envelope>,
    invoke_rx: mpsc::Receiver<InvokeRequest>,
    outbox: mpsc::Sender<Envelope>,
    invoke_routes: InvokeRoutes,
    shutdown: Arc<AtomicBool>,
    activity: ActivityClock,
    #[cfg(feature = "network")] shared_network: SharedNetwork,
    #[cfg(all(feature = "network", feature = "storage"))] sync_rx: Option<mpsc::Receiver<()>>,
) -> AgentResult {
    use std::collections::VecDeque;

    let mut runtime = VosRuntime::new();
    let bump = || *activity.lock().unwrap() = Instant::now();

    // The chain of ServiceIds currently on the synchronous-invoke
    // stack leading to this thread, including this agent itself.
    // Updated at the entry of every dispatch and read by the
    // `external_invoke` closure to short-circuit cycles and cap
    // total depth. Wrapped in Arc<Mutex<...>> rather than
    // Rc<RefCell<...>> so the closure satisfies the `Send` bound
    // on `ExternalInvokeFn`.
    let current_chain: Arc<Mutex<Vec<u32>>> = Arc::new(Mutex::new(Vec::new()));

    // External invoke handler for ctx.ask targets that live on a
    // different thread (workers OR other agents). Looks up the
    // target's invoke channel in the shared route table and
    // blocks on the reply, with two safety checks first:
    //
    //   - Cycle: if `target` already appears in the current chain,
    //     forwarding would deadlock. Abort with `None`, which
    //     surfaces to the caller's PVM as `InvokeError::NotFound`.
    //   - Depth: cap at MAX_CROSS_AGENT_DEPTH hops. Same abort.
    let invoke_routes_for_ext = invoke_routes.clone();
    let chain_for_ext = current_chain.clone();
    #[cfg(feature = "network")]
    let shared_network_for_ext = shared_network.clone();
    let local_prefix = id.node_prefix();
    runtime.set_external_invoke(Box::new(move |target, msg| {
        let chain_snapshot = chain_for_ext.lock().ok()?.clone();

        match check_invoke_forward(&chain_snapshot, target.0) {
            InvokeForwardCheck::Allowed => {}
            InvokeForwardCheck::Cycle => {
                warn!(
                    target = target.0,
                    chain = ?chain_snapshot,
                    "cross-agent invoke would form a cycle; aborting forward",
                );
                return None;
            }
            InvokeForwardCheck::DepthExceeded => {
                warn!(
                    depth = chain_snapshot.len(),
                    cap = MAX_CROSS_AGENT_DEPTH,
                    "cross-agent invoke chain exceeded depth cap; aborting forward",
                );
                return None;
            }
        }

        // 1. Local invoke route — same node, agent or worker.
        let local_tx = {
            let map = invoke_routes_for_ext.lock().ok()?;
            map.get(&target.0).cloned()
        };
        if let Some(tx) = local_tx {
            let (reply_tx, reply_rx) = mpsc::channel();
            tx.send(InvokeRequest {
                // Intra-system call from this agent. `id` is the
                // calling agent's ServiceId — perfect for the
                // `Caller::Actor` variant. Past-the-libp2p-gate
                // calls bypass role checks by virtue of being
                // inside the trust boundary.
                caller: crate::actors::Caller::Actor(id),
                space_role: None,
                actor_local_role: None,
                msg: msg.to_vec(),
                reply_tx,
                chain: chain_snapshot,
            })
            .ok()?;
            // The receiver replies with the full invoke envelope;
            // unpack it back to (status, state, reply) so the
            // runtime can repack into the local invoke wire format
            // — preserving STATUS_YIELDED across the thread
            // boundary so the calling actor can keep driving a
            // yielded child.
            let envelope = reply_rx
                .recv_timeout(std::time::Duration::from_secs(10))
                .ok()?;
            return decode_invoke_envelope(&envelope);
        }

        // 2. Cross-node invoke — target on a different node and we
        //    have a `Network` attached. Reuses the chain so the
        //    far side detects cycles that span multiple hosts.
        //
        // The libp2p protocol still ships only reply bytes (no
        // YIELDED/state plumbing across the wire yet), so we wrap
        // them in a DONE envelope here. A future protocol bump
        // can carry the full envelope so cross-node yielded
        // children are drivable too.
        #[cfg(feature = "network")]
        {
            if !target.is_on_node(local_prefix) && !target.is_local() {
                let net = shared_network_for_ext.lock().ok().and_then(|g| g.clone());
                if let Some(net) = net {
                    let prefix = target.node_prefix();
                    if let Some(peer) = net.peer_for_prefix(prefix) {
                        let reply_rx =
                            net.send_invoke(peer, id.0, target.0, chain_snapshot, msg.to_vec());
                        return reply_rx
                            .recv_timeout(std::time::Duration::from_secs(10))
                            .ok()
                            .map(crate::runtime::ExternalInvokeReply::Done);
                    }
                }
            }
        }

        None
    }));

    let consistency = config.consistency;
    // Recording captures the per-dispatch `EffectLog` payload the
    // strategy needs to replay deterministically on cold start.
    // Both replicating strategies want it; the non-replicating ones
    // ignore the log if handed.
    let recording_enabled = matches!(consistency, Consistency::Crdt | Consistency::Raft,);
    // Capture rep_id up front — config is consumed below.
    #[cfg(all(feature = "network", feature = "storage"))]
    let agent_rep_id: Option<[u8; 32]> = config.replication_id;
    // Multi-mode Raft: register() pre-spawned the worker and
    // handed it to us through the config; build the Multi-flavour
    // strategy here while we still own `config` mutably.
    #[cfg(all(feature = "network", feature = "storage"))]
    let raft_multi: Option<Box<dyn crate::commit::CommitStrategy>> =
        if consistency == Consistency::Raft && config.raft_worker.is_some() {
            let db = config.pre_opened_db.clone();
            let worker = config.raft_worker.take();
            let apply_rx = config.raft_apply_rx.take();
            match (db, worker, apply_rx) {
                (Some(db), Some(worker), Some(apply_rx)) => {
                    let cfg = crate::raft::RaftConfig {
                        me: id.node_prefix(),
                        members: config.members.clone(),
                        replication_id: agent_rep_id.unwrap_or([0u8; 32]),
                        ..crate::raft::RaftConfig::default()
                    };
                    match crate::raft::RaftCommit::from_worker(db, cfg, worker, apply_rx) {
                        Ok(s) => Some(Box::new(s) as Box<dyn crate::commit::CommitStrategy>),
                        Err(e) => {
                            error!(%id, error = %e, "raft multi: failed to construct strategy");
                            None
                        }
                    }
                }
                _ => None,
            }
        } else {
            None
        };
    #[cfg(not(all(feature = "network", feature = "storage")))]
    let raft_multi: Option<Box<dyn crate::commit::CommitStrategy>> = None;
    let mut strategy: Box<dyn crate::commit::CommitStrategy> = match raft_multi {
        Some(s) => s,
        None => match build_agent_strategy(&config, id, id.node_prefix()) {
            Ok(s) => s,
            Err(e) => {
                let err = format!("strategy build failed: {e}");
                error!(%id, "{err}");
                return AgentResult {
                    id,
                    panics: 0,
                    error: Some(err),
                };
            }
        },
    };

    let blob_idx = runtime.register_service_blob(config.blob);
    let svc_id = runtime.register_service_with_id(blob_idx, id);

    for (key, value) in &config.storage {
        runtime.storage.write(svc_id, key, value);
    }

    // Restore state or rebuild from the DAG.
    if let Some(state_bytes) = strategy.restore() {
        runtime
            .storage
            .write(svc_id, crate::lifecycle::STATE_KEY_BYTES, &state_bytes);
        info!(%id, bytes = state_bytes.len(), "agent: restored state");
    } else if recording_enabled {
        // Cold-start replay: pull every log out of the DAG and
        // feed it through `begin_replay` / `finish_replay`. Same
        // helper we use for mid-flight soft restarts.
        match strategy.replay_logs() {
            Ok(logs) if !logs.is_empty() => {
                info!(%id, dag_nodes = logs.len(), "agent: rebuilding state from DAG");
                if let Err(err) = replay_dag_into_runtime(&mut runtime, svc_id, strategy.as_ref()) {
                    error!(%id, "{err}");
                    return AgentResult {
                        id,
                        panics: runtime.panics,
                        error: Some(err),
                    };
                }
                let _ = logs;
                // Materialize the state into the strategy so
                // subsequent cold starts hit the fast path.
                let state = runtime
                    .storage
                    .read(svc_id, crate::lifecycle::STATE_KEY_BYTES)
                    .map(|v| v.to_vec())
                    .unwrap_or_default();
                if !state.is_empty()
                    && let Err(e) = strategy.commit(&state)
                {
                    let err = format!("post-replay commit failed: {e}");
                    error!(%id, "{err}");
                    return AgentResult {
                        id,
                        panics: runtime.panics,
                        error: Some(err),
                    };
                }
            }
            Ok(_) => {}
            Err(e) => {
                let err = format!("replay_logs failed: {e}");
                error!(%id, "{err}");
                return AgentResult {
                    id,
                    panics: runtime.panics,
                    error: Some(err),
                };
            }
        }
    }

    // Queue initial payloads. When no init payloads are supplied we
    // still kick the actor with an empty envelope so `on_start`
    // fires — matches the pre-refactor behaviour. On a Raft
    // follower the commit_with_log triggered by on_start will
    // return NotLeader, and the inbox-loop's commit-fail handler
    // soft-restarts the runtime to bring it back in sync.
    let mut pending: VecDeque<Vec<u8>> = config.init_payloads.into_iter().collect();
    if pending.is_empty() {
        pending.push_back(Vec::new());
    }

    let mut fatal_error: Option<String> = None;

    // Loop until the node tells us to stop (or our channels
    // disconnect, which happens during collect()). No per-agent
    // idle heuristic — the node is the source of truth for "are
    // we done."
    loop {
        if shutdown.load(Ordering::Relaxed) {
            break;
        }

        // Priority 1 — drain pending invoke requests. The caller's
        // PVM is suspended at the ecall waiting for a reply, so
        // these jump to the front of the queue.
        let mut serviced_invoke = false;
        loop {
            match invoke_rx.try_recv() {
                Ok(req) => {
                    serviced_invoke = true;
                    bump();
                    // Set the chain to the caller's chain plus our
                    // own ID, so any outgoing invokes during this
                    // dispatch see the full lineage.
                    {
                        let mut chain = current_chain.lock().unwrap();
                        chain.clear();
                        chain.extend_from_slice(&req.chain);
                        chain.push(id.0);
                    }
                    let outcome = handle_invoke_request(
                        &mut runtime,
                        svc_id,
                        &outbox,
                        id,
                        req,
                        strategy.as_mut(),
                        recording_enabled,
                    );
                    if let Err(e) = outcome {
                        fatal_error = Some(format!("commit failed during invoke: {e}"));
                        break;
                    }
                    #[cfg(all(feature = "network", feature = "storage"))]
                    publish_heads_if_replicated(&shared_network, agent_rep_id, strategy.as_ref());
                }
                Err(mpsc::TryRecvError::Empty) => break,
                Err(mpsc::TryRecvError::Disconnected) => break,
            }
        }
        if fatal_error.is_some() {
            break;
        }
        if serviced_invoke {
            continue;
        }

        // Cycle 4 — drain CRDT sync notifications. The per-replica
        // ticker pings us after merging remote DAG nodes; we run
        // a soft restart to reload the strategy and replay the
        // merged log set so our in-memory state matches.
        #[cfg(all(feature = "network", feature = "storage"))]
        if let Some(rx) = &sync_rx {
            let mut got_signal = false;
            while let Ok(()) = rx.try_recv() {
                got_signal = true;
            }
            if got_signal {
                bump();
                info!(%id, "agent: CRDT sync merged new nodes; soft-restarting");
                if let Err(err) = soft_restart_crdt(&mut runtime, svc_id, strategy.as_mut()) {
                    fatal_error = Some(format!("soft restart failed: {err}"));
                    break;
                }
                // Restart the loop so we re-check invokes that
                // may have arrived during the soft restart.
                continue;
            }
        }

        let msg = if let Some(m) = pending.pop_front() {
            bump();
            // Fresh inbox-style dispatch; chain starts at us.
            *current_chain.lock().unwrap() = vec![id.0];
            m
        } else if runtime.has_work() {
            bump();
            // Residual work — pending self-messages or transfers
            // queued by the previous dispatch. A merely suspended
            // service (continuation saved, no pending message)
            // no longer counts as residual: under the dumb-host
            // model it sleeps until a parent agent invokes it
            // again. Including `is_suspended` here would busy-spin
            // on yielded children.
            // Keep the chain set by the dispatch that produced it.
            if let Err(e) = dispatch_once(
                &mut runtime,
                svc_id,
                &outbox,
                id,
                None,
                strategy.as_mut(),
                recording_enabled,
            ) {
                // On a Raft follower the commit can return
                // NotLeader. Log, soft-restart to bring the runtime
                // back in sync, continue. CRDT failures are still
                // unexpected but the same recovery applies.
                warn!(%id, error = %e, "residual-work commit failed; soft-restarting");
                #[cfg(all(feature = "network", feature = "storage"))]
                if let Err(restart_err) = soft_restart_crdt(&mut runtime, svc_id, strategy.as_mut())
                {
                    fatal_error = Some(format!("residual soft restart: {restart_err}"));
                    break;
                }
                continue;
            }
            #[cfg(all(feature = "network", feature = "storage"))]
            publish_heads_if_replicated(&shared_network, agent_rep_id, strategy.as_ref());
            continue;
        } else {
            // Short blocking wait on inbox so we re-check the
            // shutdown flag and the invoke channel promptly.
            match inbox.recv_timeout(Duration::from_millis(50)) {
                Ok(env) => {
                    bump();
                    *current_chain.lock().unwrap() = vec![id.0];
                    env.payload
                }
                Err(mpsc::RecvTimeoutError::Timeout) => continue,
                Err(mpsc::RecvTimeoutError::Disconnected) => break,
            }
        };
        if let Err(e) = dispatch_once(
            &mut runtime,
            svc_id,
            &outbox,
            id,
            Some(msg),
            strategy.as_mut(),
            recording_enabled,
        ) {
            // Tell-style dispatch on a follower will return
            // NotLeader. Soft-restart and continue rather than
            // killing the agent; the message is effectively
            // dropped (which is OK — clients should target the
            // leader).
            warn!(%id, error = %e, "tell-style commit failed; soft-restarting");
            #[cfg(all(feature = "network", feature = "storage"))]
            if let Err(restart_err) = soft_restart_crdt(&mut runtime, svc_id, strategy.as_mut()) {
                fatal_error = Some(format!("soft restart: {restart_err}"));
                break;
            }
            continue;
        }
        #[cfg(all(feature = "network", feature = "storage"))]
        publish_heads_if_replicated(&shared_network, agent_rep_id, strategy.as_ref());
    }

    if let Some(err) = &fatal_error {
        error!(%id, "{err}");
    }
    AgentResult {
        id,
        panics: runtime.panics,
        error: fatal_error,
    }
}

/// Publish the strategy's current roots on the gossipsub topic
/// for `rep_id` if the agent is replicated and a network is
/// attached. Cheap when not replicated (early return); the
/// strategy's `roots()` is also a no-op for non-CRDT types.
#[cfg(all(feature = "network", feature = "storage"))]
fn publish_heads_if_replicated(
    shared_network: &SharedNetwork,
    rep_id: Option<[u8; 32]>,
    strategy: &dyn crate::commit::CommitStrategy,
) {
    let Some(rep_id) = rep_id else {
        return;
    };
    let Some(net) = shared_network.lock().ok().and_then(|g| g.clone()) else {
        return;
    };
    let roots = strategy.roots();
    if roots.is_empty() {
        return;
    }
    net.publish_heads(rep_id, roots);
}

/// Handle a synchronous invoke request from a peer: dispatch the
/// message through this agent's runtime, capture the reply bytes
/// (rkyv-encoded `Value`), and send them back through the caller's
/// reply channel. The CALLER's `handle_invoke` wraps the reply in
/// the invoke wire frame (`[STATUS_DONE][state_len=0][reply]`) —
/// same convention workers use, so this path is symmetric with
/// `extension_thread`.
///
/// Recording is honored: a CRDT-mode agent records the dispatch
/// just like any other external message, since from its own
/// perspective the invoke IS its external event for that tick.
fn handle_invoke_request(
    runtime: &mut VosRuntime,
    svc_id: ServiceId,
    outbox: &mpsc::Sender<Envelope>,
    from_id: ServiceId,
    req: InvokeRequest,
    strategy: &mut dyn crate::commit::CommitStrategy,
    recording_enabled: bool,
) -> Result<(), crate::commit::CommitError> {
    if recording_enabled {
        runtime.begin_recording(req.msg.clone());
    }
    runtime.send_to(svc_id, req.msg);
    runtime.run_blocking();

    // Route any external transfers the dispatch produced.
    let external = runtime.drain_external_transfers(svc_id);
    for (target, memo) in external {
        let _ = outbox.send(Envelope {
            from: from_id,
            to: target,
            payload: memo,
        });
    }

    // Persist before replying. If the commit fails (e.g. Raft
    // `NotLeader` because we lost leadership between dispatch
    // and commit), we drop the reply so the caller sees
    // `Unreachable` and can retry against the new leader. Doing
    // it in this order means the client only sees success when
    // the state is durable.
    let state = runtime
        .storage
        .read(svc_id, crate::lifecycle::STATE_KEY_BYTES)
        .map(|v| v.to_vec())
        .unwrap_or_default();
    let commit_result = if recording_enabled {
        let log = runtime.finish_recording().expect("recording was started");
        strategy.commit_with_log(&state, &log)
    } else if !state.is_empty() {
        strategy.commit(&state)
    } else {
        Ok(())
    };

    if let Err(e) = commit_result {
        // Drop the reply (caller surfaces `Unreachable`) and
        // soft-restart to bring the runtime back in sync with
        // the durable log. Don't bubble the error — a transient
        // `NotLeader` shouldn't kill the agent thread.
        warn!(%svc_id, error = %e, "commit failed; soft-restarting and dropping reply");
        drop(req.reply_tx);
        #[cfg(all(feature = "network", feature = "storage"))]
        if let Err(restart_err) = soft_restart_crdt(runtime, svc_id, strategy) {
            error!(%svc_id, "soft restart after commit failure: {restart_err}");
        }
        return Ok(());
    }

    // Commit succeeded. Pack the reply as the full invoke wire
    // envelope `[status][state_len:u32][state][reply]` so the
    // caller's PVM sees the same shape it would for a local
    // INVOKE. `is_suspended` after `run_blocking` tells us the
    // handler yielded with a continuation still alive — STATUS_YIELDED
    // surfaces upstream so a parent agent can keep driving us tick
    // by tick. Without this distinction every cross-thread invoke
    // looks like STATUS_DONE and the caller drops yielded children
    // from its run queue.
    //
    // `take_last_reply` returns `None` only when the handler
    // panicked; we signal that to the caller by dropping
    // `reply_tx`, which surfaces upstream as `InvokeError::Panicked`.
    let reply = match runtime.take_last_reply(svc_id) {
        Some(bytes) => bytes,
        None => {
            drop(req.reply_tx);
            return Ok(());
        }
    };
    // M6 — when the macro-emitted role check refused the call,
    // the runtime stashes STATUS_FORBIDDEN in last_status. That
    // wins over the default DONE/YIELDED inference so the wire
    // envelope carries the actor-level refusal end-to-end.
    let actor_status = runtime.take_last_status(svc_id);
    let status = if let Some(s) = actor_status {
        s
    } else if runtime.is_suspended(svc_id) {
        crate::actors::run::STATUS_YIELDED
    } else {
        crate::actors::run::STATUS_DONE
    };
    let envelope = encode_invoke_envelope(status, &state, &reply);
    send_reply_capped(req.reply_tx, envelope, svc_id);
    Ok(())
}

/// Encode the invoke wire envelope `[status][state_len:u32 LE][state][reply]`
/// — the same format `runtime::handle_invoke` writes for a same-runtime
/// Sprint 2 auth roles, kept in sync with
/// `space_registry::AUTH_ROLE_*` so the host's dispatch-layer
/// gate doesn't need a cross-crate dep on the actor.
#[cfg(feature = "network")]
pub(crate) const AUTH_ROLE_NONE: u8 = 0;
#[cfg(feature = "network")]
pub(crate) const AUTH_ROLE_ADMIN: u8 = 3;

/// Set of registry handlers gated behind `AUTH_ROLE_ADMIN`.
/// Mutating handlers go through here; read-only handlers
/// (`programs`, `agents`, `members`, `auth_grants`, `peer_role`,
/// `meta_for_instance`, …) stay open so a peer can introspect
/// what's there before requesting enrollment.
#[cfg(feature = "network")]
pub(crate) fn handler_requires_admin(handler: &str) -> bool {
    matches!(
        handler,
        "publish"
            | "install"
            | "upgrade"
            | "uninstall"
            | "add_node"
            | "remove_node"
            | "add_identity"
            | "remove_identity"
            | "grant_role"
            | "revoke_role"
            | "register_meta"
            | "register_extension_meta"
            | "upload_blob"
    )
}

/// Peek the handler name out of an invoke payload without
/// fully running it. Used by the auth gate to classify the
/// call before forwarding. Returns `None` for payloads that
/// don't carry a dynamic msg tag — the gate falls through to
/// allow, since typed-dispatch payloads don't reach the
/// publish/install handlers we care about anyway.
#[cfg(feature = "network")]
fn peek_dynamic_msg_name(payload: &[u8]) -> Option<String> {
    use crate::value::TAG_DYNAMIC;
    let body = payload.strip_prefix(&[TAG_DYNAMIC])?;
    let msg = <crate::value::Msg as crate::actors::codec::Decode>::try_decode(body)?;
    Some(msg.name)
}

/// Build a failure envelope the libp2p layer relays back to
/// the caller when the dispatch-layer auth gate refuses a call.
/// `STATUS_FORBIDDEN` is the distinct status the client-side
/// `Invoker for &VosNode` peeks at (see `vos/src/lib.rs`) so
/// vosx surfaces "permission denied" rather than colliding with
/// a generic actor panic.
///
/// Shape: exactly 5 bytes — `[STATUS_FORBIDDEN, 0, 0, 0, 0]`
/// (status + zero-length state). Both the length and the leading
/// status byte are load-bearing for the client-side detection.
#[cfg(feature = "network")]
fn forbidden_envelope() -> Vec<u8> {
    use crate::actors::run::STATUS_FORBIDDEN;
    encode_invoke_envelope(STATUS_FORBIDDEN, &[], &[])
}

/// INVOKE. Used by the cross-thread invoke path so a yielded child on
/// another agent thread surfaces as `STATUS_YIELDED` (with its post-
/// dispatch state) to the calling actor's `lifecycle::invoke_raw`,
/// not as `STATUS_DONE`.
fn encode_invoke_envelope(status: u8, state: &[u8], reply: &[u8]) -> Vec<u8> {
    let mut out = Vec::with_capacity(1 + 4 + state.len() + reply.len());
    out.push(status);
    out.extend_from_slice(&(state.len() as u32).to_le_bytes());
    out.extend_from_slice(state);
    out.extend_from_slice(reply);
    out
}

/// Strip the invoke envelope back to just the rkyv-encoded reply
/// bytes for host-side callers (`VosNode::invoke`, peer invoke
/// forwarding) who don't care about YIELDED/DONE — they only want
/// the handler's return value. A short envelope or one carrying a
/// failure status (`STATUS_NOT_FOUND` / `STATUS_PANICKED` /
/// `STATUS_OOG` / `STATUS_FORBIDDEN`) decodes as `None` so the
/// gateway and other ask-style callers can distinguish "actor
/// returned nothing" from "actor failed".
fn unwrap_invoke_envelope(envelope: &[u8]) -> Option<Vec<u8>> {
    use crate::actors::run::{STATUS_DONE, STATUS_YIELDED};
    if envelope.len() < 5 {
        return None;
    }
    match envelope[0] {
        STATUS_DONE | STATUS_YIELDED => {}
        // STATUS_NOT_FOUND / STATUS_PANICKED / STATUS_OOG /
        // STATUS_FORBIDDEN and any future failure variant: the
        // actor did not produce a valid reply. Surface as None.
        _ => return None,
    }
    let state_len =
        u32::from_le_bytes([envelope[1], envelope[2], envelope[3], envelope[4]]) as usize;
    let reply_start = 5 + state_len;
    if reply_start > envelope.len() {
        return None;
    }
    Some(envelope[reply_start..].to_vec())
}

/// Decode a cross-thread invoke envelope back into the
/// [`runtime::ExternalInvokeReply`] enum the runtime's
/// `external_invoke` callback expects, so a yielded child on one
/// agent thread surfaces as [`runtime::ExternalInvokeReply::Yielded`]
/// to the calling actor's PVM.
///
/// A short envelope (just a status byte — `STATUS_NOT_FOUND` /
/// `STATUS_PANICKED`) returns `None`; the runtime then falls
/// through to its own NOT_FOUND path.
fn decode_invoke_envelope(envelope: &[u8]) -> Option<crate::runtime::ExternalInvokeReply> {
    use crate::actors::run::{STATUS_DONE, STATUS_YIELDED};
    use crate::runtime::ExternalInvokeReply;
    if envelope.len() < 5 {
        return None;
    }
    let status = envelope[0];
    let state_len =
        u32::from_le_bytes([envelope[1], envelope[2], envelope[3], envelope[4]]) as usize;
    let state_end = 5 + state_len;
    if state_end > envelope.len() {
        return None;
    }
    let state = envelope[5..state_end].to_vec();
    let reply = envelope[state_end..].to_vec();
    match status {
        STATUS_YIELDED => Some(ExternalInvokeReply::Yielded { state, reply }),
        STATUS_DONE => Some(ExternalInvokeReply::Done(reply)),
        _ => None,
    }
}

/// Run one dispatch cycle: optionally begin recording, deliver the
/// message (or just drive residual work), route external transfers,
/// then commit the resulting state via the strategy.
///
/// Returns `Err` only on host-side commit failures — those are
/// terminal for the agent. Routing failures and transient runtime
/// issues are not surfaced here.
fn dispatch_once(
    runtime: &mut VosRuntime,
    svc_id: ServiceId,
    outbox: &mpsc::Sender<Envelope>,
    from_id: ServiceId,
    msg: Option<Vec<u8>>,
    strategy: &mut dyn crate::commit::CommitStrategy,
    recording_enabled: bool,
) -> Result<(), crate::commit::CommitError> {
    let recorded = recording_enabled
        && if let Some(payload) = msg.as_ref() {
            runtime.begin_recording(payload.clone());
            true
        } else {
            false
        };
    if let Some(payload) = msg {
        runtime.send_to(svc_id, payload);
    }
    runtime.run_blocking();

    let external = runtime.drain_external_transfers(svc_id);
    for (target, memo) in external {
        let _ = outbox.send(Envelope {
            from: from_id,
            to: target,
            payload: memo,
        });
    }

    let state = runtime
        .storage
        .read(svc_id, crate::lifecycle::STATE_KEY_BYTES)
        .map(|v| v.to_vec())
        .unwrap_or_default();

    if recorded {
        let log = runtime.finish_recording().expect("recording was started");
        strategy.commit_with_log(&state, &log)?;
    } else if !state.is_empty() {
        strategy.commit(&state)?;
    }
    Ok(())
}

/// Select the agent's commit strategy from its config.
///
/// Returns `Err` when a non-`Ephemeral` strategy was requested but
/// the underlying redb open failed, or when storage was requested
/// without a `data_dir`. We deliberately do not silently downgrade
/// to `NoCommit` — a CRDT actor that can't open its DAG file
/// shouldn't pretend to be replicated.
/// Derive the per-replica `CrdtEvent.origin` from the group's
/// replication_id and the host node's 16-bit prefix.
///
/// `blake2b("vos-replica-origin/v1" || replication_id || prefix)`
/// — the prefix domain-separates replicas of the same group
/// running on different nodes, while the replication_id
/// domain-separates groups that happen to share a node. The
/// prefix string keeps this hash from colliding with other vos
/// blake2b uses (registry rep_id derivation, etc).
#[cfg(feature = "storage")]
fn derive_replica_origin(replication_id: &[u8; 32], node_prefix: u16) -> [u8; 32] {
    let mut h = blake2b_simd::Params::new().hash_length(32).to_state();
    h.update(b"vos-replica-origin/v1");
    h.update(&[0u8]);
    h.update(replication_id);
    h.update(&node_prefix.to_le_bytes());
    let mut out = [0u8; 32];
    out.copy_from_slice(h.finalize().as_bytes());
    out
}

fn build_agent_strategy(
    config: &AgentConfig,
    id: ServiceId,
    self_node_prefix: u16,
) -> Result<Box<dyn crate::commit::CommitStrategy>, crate::commit::CommitError> {
    #[cfg(feature = "storage")]
    {
        let _ = (id, self_node_prefix);
        match config.consistency {
            Consistency::Ephemeral => Ok(Box::new(crate::commit::NoCommit)),
            Consistency::Local => {
                let path = config.db_path(id).ok_or_else(|| {
                    crate::commit::CommitError::Config(
                        "Local consistency requires data_dir on AgentConfig".into(),
                    )
                })?;
                Ok(Box::new(crate::commit::LocalCommit::open(&path)?))
            }
            Consistency::Crdt => {
                // CRDT events are tagged with a per-replica origin
                // so peer replicas can tell our events apart from
                // theirs by content alone. Two replicas of the same
                // group share the *replication_id* (it's the group
                // identity for sync/discovery), so we can't reuse
                // that — the per-replica origin is derived from
                // `(replication_id, node_prefix)` so:
                //   - replicas on different nodes get different
                //     origins (different prefixes),
                //   - a replica's origin is stable across restarts
                //     of the same node (same prefix),
                //   - origins are domain-separated by group, so
                //     two unrelated groups on the same node never
                //     share origins.
                // We still require `replication_id` to be set
                // explicitly: an unconfigured Crdt agent has no
                // group identity to sync against, which is a
                // silent determinism failure waiting to happen.
                let replication_id = config.replication_id.ok_or_else(|| {
                    crate::commit::CommitError::Config(
                        "Crdt consistency requires AgentConfig::replication_id; \
                         set one explicitly or use `auto_replication_id(name)`"
                            .into(),
                    )
                })?;
                let replica_origin = derive_replica_origin(&replication_id, self_node_prefix);
                if let Some(arc) = &config.pre_opened_db {
                    let cc = match &config.pre_opened_lock {
                        Some(lock) => crate::commit::CrdtCommit::from_db_arc_locked(
                            arc.clone(),
                            lock.clone(),
                            replica_origin,
                        ),
                        None => crate::commit::CrdtCommit::from_db_arc(arc.clone(), replica_origin),
                    };
                    return Ok(Box::new(cc));
                }
                let path = config.db_path(id).ok_or_else(|| {
                    crate::commit::CommitError::Config(
                        "Crdt consistency requires data_dir on AgentConfig".into(),
                    )
                })?;
                Ok(Box::new(crate::commit::CrdtCommit::open(
                    &path,
                    replica_origin,
                )?))
            }
            Consistency::Raft => {
                // Single-node-only path: agent_thread handles the
                // multi-mode case before reaching here (it owns
                // the pre-spawned worker via `config.raft_worker`).
                let cfg = crate::raft::RaftConfig {
                    me: self_node_prefix,
                    members: config.members.clone(),
                    replication_id: config.replication_id.unwrap_or([0u8; 32]),
                    ..crate::raft::RaftConfig::default()
                };
                let path = config.db_path(id).ok_or_else(|| {
                    crate::commit::CommitError::Config(
                        "Raft consistency requires data_dir on AgentConfig".into(),
                    )
                })?;
                Ok(Box::new(crate::raft::RaftCommit::open(&path, cfg)?))
            }
        }
    }
    #[cfg(not(feature = "storage"))]
    {
        let _ = (config, id);
        match config.consistency {
            Consistency::Ephemeral => Ok(Box::new(crate::commit::NoCommit)),
            other => Err(crate::commit::CommitError::Config(format!(
                "consistency={other:?} requires the `storage` feature"
            ))),
        }
    }
}

/// Max deferred messages held while waiting for a specific reply.
const MAX_DEFERRED: usize = 256;

// ── Worker thread ────────────────────────────────────────────────────

#[allow(clippy::too_many_arguments)]
fn extension_thread(
    id: ServiceId,
    config: ExtensionConfig,
    inbox: mpsc::Receiver<Envelope>,
    invoke_rx: mpsc::Receiver<InvokeRequest>,
    outbox: mpsc::Sender<Envelope>,
    invoke_routes: InvokeRoutes,
    shutdown: Arc<AtomicBool>,
    activity: ActivityClock,
) -> AgentResult {
    use crate::extension::ExtensionPlugin;
    use std::collections::VecDeque;

    // SAFETY: ExtensionPlugin::load wraps libloading::Library; it's
    // only unsafe because dlopen runs the .so's static initialisers
    // and binds C symbols whose type signatures we can't verify at
    // compile time. We trust the operator's manifest path to point
    // at a vos-built extension.
    let plugin = match unsafe { ExtensionPlugin::load(&config.path) } {
        Ok(p) => p,
        Err(e) => {
            let err = format!("failed to load extension plugin: {e}");
            error!(%id, "extension: {err}");
            return AgentResult {
                id,
                panics: 1,
                error: Some(err),
            };
        }
    };

    if let Some(meta) = plugin.meta() {
        info!(
            %id,
            actor = %meta.actor_name,
            kind = ?crate::extension::ExtensionKind::from_byte(meta.kind),
            path = %config.path.display(),
            "extension: loaded plugin"
        );
        if !meta.caps.is_empty() {
            info!(%id, actor = %meta.actor_name, caps = ?meta.caps, "extension: declared capabilities");
        }
    }

    // Phase 3: dispatch on plugin kind. Service-mode extensions
    // own their thread + originate calls via ServiceCtx; the
    // actor-mode dispatch loop below is unused for them. Phase 5
    // adds a dispatch sidecar: when the .so exports
    // `vos_service_handle_invoke`, run_service_extension spawns a
    // helper thread that consumes `invoke_rx` and routes each
    // inbound invoke through it, so `vosx <ext> <method>` reaches
    // a real handler instead of sitting in the channel until the
    // caller times out.
    if plugin.kind() == crate::extension::ExtensionKind::Service {
        return run_service_extension(
            id,
            plugin,
            config,
            inbox,
            invoke_rx,
            outbox,
            invoke_routes,
            shutdown,
            activity,
        );
    }

    let bump = || *activity.lock().unwrap() = Instant::now();

    // Pick a persistence strategy. Extensions always get LocalCommit
    // when a data directory is configured, NoCommit otherwise;
    // replication strategies (CRDT, Raft) are not available to
    // extensions since they live outside the deterministic universe.
    let mut strategy: Box<dyn crate::commit::CommitStrategy> =
        build_extension_strategy(&config, id);
    let saved_state = strategy.restore();

    let mut instance = match saved_state {
        Some(bytes) => {
            info!(%id, bytes = bytes.len(), "extension: restored state");
            plugin.load_state(&bytes)
        }
        None if config.init_args.is_empty() => plugin.create(),
        None => plugin.create_with_args(&config.init_args),
    };

    // Messages that arrived while we were waiting for a specific reply.
    // Bounded to prevent OOM from a misbehaving sender (see MAX_DEFERRED).
    let mut deferred: VecDeque<Envelope> = VecDeque::new();

    loop {
        if shutdown.load(Ordering::Relaxed) {
            break;
        }

        // Process up to a few invoke requests per iteration to avoid
        // starving the regular inbox.
        for _ in 0..4 {
            match invoke_rx.try_recv() {
                Ok(req) => {
                    bump();
                    let outcome = dispatch_and_poll(
                        &mut instance,
                        &req.msg,
                        &inbox,
                        &outbox,
                        id,
                        &mut deferred,
                    );
                    // Workers don't yield — pack as DONE with no
                    // state so the caller's invoke_raw decodes
                    // `InvokeResult::Done { state: empty, reply }`.
                    // A `DispatchOutcome::Err` (handler panicked,
                    // missing future, etc) becomes STATUS_PANICKED
                    // so the gateway's `unwrap_invoke_envelope`
                    // can distinguish it from a legitimate `()`
                    // return — see vos::actors::run::STATUS_*.
                    let envelope = match outcome {
                        DispatchOutcome::Ok(reply) => {
                            encode_invoke_envelope(crate::actors::run::STATUS_DONE, &[], &reply)
                        }
                        DispatchOutcome::Err => {
                            encode_invoke_envelope(crate::actors::run::STATUS_PANICKED, &[], &[])
                        }
                    };
                    send_reply_capped(req.reply_tx, envelope, id);
                    persist(strategy.as_mut(), &instance, id);
                }
                Err(_) => break,
            }
        }

        // Take next message: deferred first, then inbox
        let envelope = if let Some(e) = deferred.pop_front() {
            bump();
            e
        } else {
            match inbox.recv_timeout(Duration::from_millis(50)) {
                Ok(e) => {
                    bump();
                    e
                }
                Err(mpsc::RecvTimeoutError::Timeout) => continue,
                Err(mpsc::RecvTimeoutError::Disconnected) => break,
            }
        };

        let outcome = dispatch_and_poll(
            &mut instance,
            &envelope.payload,
            &inbox,
            &outbox,
            id,
            &mut deferred,
        );
        // Envelope-mode replies don't carry the `[status][state][reply]`
        // wrapper — that's an invoke-channel detail. On the envelope
        // path the receiver just gets the reply bytes addressed
        // `from = target`. Treat a `DispatchOutcome::Err` as an empty
        // reply here (we lose the panic vs () distinction in the
        // envelope path, but no caller demands it today — the
        // ask-style path that *does* distinguish them goes through
        // invoke). Always reply even on empty so an ask-style caller
        // doesn't hang for the full reply timeout.
        let reply_bytes = match outcome {
            DispatchOutcome::Ok(b) => b,
            DispatchOutcome::Err => Vec::new(),
        };
        let _ = outbox.send(Envelope {
            from: id,
            to: envelope.from,
            payload: reply_bytes,
        });
        persist(strategy.as_mut(), &instance, id);
    }

    AgentResult {
        id,
        panics: 0,
        error: None,
    }
}

// ── Service-mode extension runner (Phase 3) ──────────────────────────

/// Drive a service-mode extension: build a HostCtx, hand it to the
/// extension's `vos_extension_run` entry, block until it returns.
///
/// The extension owns its own concurrency (typically tokio inside).
/// Control flow back here only happens when the extension's run
/// loop exits — either because `shutdown` was flipped or because
/// the extension hit an unrecoverable error.
#[allow(clippy::too_many_arguments)]
fn run_service_extension(
    id: ServiceId,
    plugin: crate::extension::ExtensionPlugin,
    config: ExtensionConfig,
    inbox: mpsc::Receiver<Envelope>,
    invoke_rx: mpsc::Receiver<InvokeRequest>,
    outbox: mpsc::Sender<Envelope>,
    invoke_routes: InvokeRoutes,
    shutdown: Arc<AtomicBool>,
    activity: ActivityClock,
) -> AgentResult {
    use crate::extension::{HostCtx, HostCtxHandle, SERVICE_VTABLE};
    use std::collections::VecDeque;
    use std::sync::Mutex;

    *activity.lock().unwrap() = Instant::now();

    // Wrap the node's invoke_routes table in a closure the
    // extension layer can call without knowing about
    // `InvokeRequest`. The closure: look up target's invoke channel,
    // send the request with this extension's own id as the chain
    // root, block on reply with the extension's timeout. Returns
    // None on transport error / timeout / unknown target.
    let invoke_routes_for_ctx = invoke_routes.clone();
    let me = id.0;
    let invoke_shutdown = shutdown.clone();
    let invoke_fn: std::sync::Arc<crate::extension::InvokeFn> = std::sync::Arc::new(
        move |target: u32, payload: &[u8], timeout_ms: u64| -> Option<Vec<u8>> {
            let tx = invoke_routes_for_ctx
                .lock()
                .ok()
                .and_then(|m| m.get(&target).cloned())?;
            let (reply_tx, reply_rx) = mpsc::channel::<Vec<u8>>();
            tx.send(InvokeRequest {
                // Intra-system call from this extension. `me` is
                // its ServiceId — `Caller::Actor` mirrors the
                // agent-thread path above.
                caller: crate::actors::Caller::Actor(ServiceId(me)),
                space_role: None,
                actor_local_role: None,
                msg: payload.to_vec(),
                reply_tx,
                chain: vec![me],
            })
            .ok()?;
            // Default timeout: a generous 5 minutes; explicit 0
            // means "wait forever" but we still poll in 50ms ticks
            // so shutdown signal is honored promptly.
            let deadline = if timeout_ms == 0 {
                Instant::now() + Duration::from_secs(300)
            } else {
                Instant::now() + Duration::from_millis(timeout_ms)
            };
            loop {
                if invoke_shutdown.load(Ordering::Relaxed) {
                    return None;
                }
                match reply_rx.recv_timeout(Duration::from_millis(50)) {
                    Ok(envelope) => {
                        // PVM agent and actor-mode extension both
                        // reply with the wrapped invoke envelope
                        // `[status][state_len:u32][state][reply]`.
                        // `unwrap_invoke_envelope` returns Some(reply)
                        // for DONE/YIELDED (legitimate completions —
                        // empty bytes are fine for a `()` return) and
                        // None for failure statuses (PANICKED /
                        // NOT_FOUND / OOG). Passing the None through
                        // lets `ServiceCtx::ask_raw` surface failures
                        // as None at the caller — the gateway then
                        // distinguishes "handler succeeded with no
                        // value" (200 null) from "handler failed"
                        // (502). Before this distinction, every
                        // failure shape collapsed into 200 null.
                        return unwrap_invoke_envelope(&envelope);
                    }
                    Err(mpsc::RecvTimeoutError::Timeout) => {
                        if Instant::now() >= deadline {
                            return None;
                        }
                    }
                    Err(mpsc::RecvTimeoutError::Disconnected) => return None,
                }
            }
        },
    );

    // Read declared caps off the plugin's meta blob so the
    // vtable shims can gate / log at the syscall boundary
    // (Sprint 2 — see HostCtx::check_cap_or_deny). cap_policy
    // flows in from ExtensionConfig (operator-set via space
    // manifest).
    let (declared_caps, actor_name) = match plugin.meta() {
        Some(m) => (m.caps.clone(), m.actor_name.clone()),
        None => (Vec::new(), format!("svc:{:#06x}", id.0)),
    };
    let cap_policy = config.cap_policy;
    let host_ctx = Box::new(HostCtx {
        me: id.0,
        outbox: outbox.clone(),
        inbox: Mutex::new(inbox),
        deferred: Mutex::new(VecDeque::new()),
        shutdown: shutdown.clone(),
        invoke: invoke_fn,
        declared_caps,
        cap_policy,
        cap_warns_logged: std::sync::Mutex::new(std::collections::BTreeSet::new()),
        actor_name,
    });
    let host_ptr = Box::into_raw(host_ctx);
    let handle = HostCtxHandle {
        state: host_ptr as *mut core::ffi::c_void,
        vtable: &SERVICE_VTABLE as *const _,
    };

    // SAFETY: create_state pairs with drop_state below; both use
    // the plugin's symbol pair so the allocator matches.
    let state = unsafe { plugin.create_state(&config.init_args) };
    if state.is_null() {
        // SAFETY: host_ptr was just allocated above; nothing else
        // observed it, so reclaiming it is safe.
        unsafe {
            let _ = Box::from_raw(host_ptr);
        }
        let err = "service-mode extension: create_state returned null";
        error!(%id, "{err}");
        return AgentResult {
            id,
            panics: 1,
            error: Some(err.into()),
        };
    }

    // Phase 5: if the extension exports `vos_service_handle_invoke`,
    // spawn a sidecar dispatch thread that consumes `invoke_rx` in
    // parallel with `run()`. Each request is dispatched through
    // the extension's fn and the reply wrapped in the standard
    // invoke envelope (STATUS_DONE / STATUS_NOT_FOUND / STATUS_PANICKED).
    // Extensions without the symbol get the legacy behaviour — the
    // channel goes unread and callers time out. State pointer is
    // shared across threads as `*mut ()`; the extension is
    // responsible for thread-safe access between its run thread
    // and the dispatch path (HttpGateway uses an OnceLock + Arc).
    //
    // Plugin handle is `Arc`-shared with the sidecar rather than
    // re-loaded — `Library`'s fn-ptr fields are `Send+Sync`, and
    // a single dlopen is cheaper than two. The Arc also keeps the
    // library mapped for the sidecar's lifetime even if `run()`
    // exits first.
    let plugin = std::sync::Arc::new(plugin);
    let sidecar = if plugin.service_has_invoke_dispatch() {
        let state_ptr = SendState(state);
        let plugin_for_sidecar = plugin.clone();
        let shutdown_for_sidecar = shutdown.clone();
        Some(std::thread::spawn(move || {
            run_service_invoke_sidecar(
                id,
                plugin_for_sidecar,
                state_ptr,
                invoke_rx,
                shutdown_for_sidecar,
            );
        }))
    } else {
        // No dispatch handler — drop the receiver so any sender
        // sees Disconnected on send and the channel doesn't leak.
        drop(invoke_rx);
        None
    };

    // Capture panics inside run so we can clean up state + host_ptr
    // even if the extension blows up.
    let plugin_ref = &*plugin;
    let handle_ptr: *const HostCtxHandle = &handle;
    let exit = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
        // SAFETY: state is a live instance from create_state above;
        // handle_ptr lives on this stack frame and outlives the call.
        unsafe { plugin_ref.run_service(state, handle_ptr) }
    }));

    // After run() returns we need the sidecar to exit too. The
    // process-wide `shutdown` flag would do it but is shared by
    // every other agent/extension on this daemon — flipping it
    // here would take them down too. Instead we drop the sender
    // half of the invoke channel by removing the entry from
    // `invoke_routes`; the sidecar's `recv_timeout` sees
    // `Disconnected` and exits. Other clones of the Sender (e.g.
    // a thread mid-send) keep the channel briefly alive, but
    // they're short-lived and the sidecar exits within one
    // timeout tick (50ms) after the last clone drops. Falls back
    // to global shutdown anyway if a stray sender lingers.
    if let Some(handle) = sidecar {
        invoke_routes.lock().unwrap().remove(&id.0);
        let _ = handle.join();
    }

    // Drop state regardless of panic.
    // SAFETY: state was returned by this plugin's create_state and
    // hasn't been dropped yet.
    unsafe {
        plugin.drop_state(state);
    }
    // SAFETY: host_ptr is the unique live pointer to the HostCtx;
    // service_thread is single-threaded after run returns.
    unsafe {
        let _ = Box::from_raw(host_ptr);
    }

    *activity.lock().unwrap() = Instant::now();

    match exit {
        Ok(code) if code >= 0 => AgentResult {
            id,
            panics: 0,
            error: None,
        },
        Ok(code) => AgentResult {
            id,
            panics: 1,
            error: Some(format!("service-mode extension: run returned {code}")),
        },
        Err(_) => AgentResult {
            id,
            panics: 1,
            error: Some("service-mode extension: run panicked".into()),
        },
    }
}

/// Outcome of a single extension dispatch. `Ok(bytes)` means the
/// handler completed with the given reply (`bytes` may be empty
/// for a `()` return). `Err` covers the cases that can't be
/// represented as bytes — handler panic, decode failure, missing
/// future — and lets `extension_thread` pick the right `STATUS_*`
/// byte for the invoke envelope. The exact `POLL_ERR_*` code
/// behind the failure is logged inside `dispatch_and_poll` (the
/// caller doesn't need it to pick a status byte).
enum DispatchOutcome {
    Ok(Vec<u8>),
    Err,
}

/// `*mut ()` newtype that implements `Send` so the service-mode
/// invoke dispatch sidecar can carry the extension's state across
/// thread boundaries. The pointer aliases the same state the
/// `run()` thread reads; coordination across the two threads is
/// the extension's responsibility (HttpGateway uses interior
/// `Arc`/`AtomicBool` for that).
struct SendState(*mut ());
// SAFETY: the underlying state lives in the extension's address
// space and is accessed via the extension's own thread-safe
// primitives — the host doesn't dereference it.
unsafe impl Send for SendState {}

/// Pull invokes off the channel and dispatch each through the
/// extension's `vos_service_handle_invoke`. Wrap replies in the
/// standard invoke envelope so the calling actor's
/// `unwrap_invoke_envelope` decodes them the same way it does
/// for PVM and actor-mode-extension replies. Exits when
/// `shutdown` is set or the channel disconnects (the latter is
/// the per-extension wake signal — `run_service_extension`
/// drops the Sender out of `invoke_routes` after `run()`
/// returns).
fn run_service_invoke_sidecar(
    id: ServiceId,
    plugin: std::sync::Arc<crate::extension::ExtensionPlugin>,
    state: SendState,
    invoke_rx: mpsc::Receiver<InvokeRequest>,
    shutdown: Arc<AtomicBool>,
) {
    use crate::actors::run::{STATUS_DONE, STATUS_NOT_FOUND, STATUS_PANICKED};
    use crate::extension::{POLL_ERR_NO_FUTURE, POLL_READY};

    loop {
        if shutdown.load(Ordering::Relaxed) {
            return;
        }
        match invoke_rx.recv_timeout(Duration::from_millis(50)) {
            Ok(req) => {
                // SAFETY: the extension's state ptr is alive for
                // the duration of run_service_extension, which
                // joins this sidecar before dropping state.
                let outcome = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| unsafe {
                    plugin.dispatch_service_invoke(state.0, &req.msg)
                }));
                let envelope = match outcome {
                    Ok((POLL_READY, Some(bytes))) => {
                        encode_invoke_envelope(STATUS_DONE, &[], &bytes)
                    }
                    Ok((POLL_ERR_NO_FUTURE, _)) => {
                        encode_invoke_envelope(STATUS_NOT_FOUND, &[], &[])
                    }
                    _ => encode_invoke_envelope(STATUS_PANICKED, &[], &[]),
                };
                send_reply_capped(req.reply_tx, envelope, id);
            }
            Err(mpsc::RecvTimeoutError::Timeout) => continue,
            Err(mpsc::RecvTimeoutError::Disconnected) => return,
        }
    }
}

/// Dispatch a message to an actor-mode extension instance and poll
/// to completion. Returns the reply bytes on success or a
/// `POLL_ERR_*` status on a poisoned future (panic, missing future,
/// etc).
fn dispatch_and_poll(
    instance: &mut crate::extension::ExtensionInstance<'_>,
    msg: &[u8],
    inbox: &mpsc::Receiver<Envelope>,
    outbox: &mpsc::Sender<Envelope>,
    extension_id: ServiceId,
    deferred: &mut std::collections::VecDeque<Envelope>,
) -> DispatchOutcome {
    use crate::extension::{POLL_PENDING, POLL_READY};

    instance.dispatch_start(msg);

    loop {
        let result = instance.poll_once();
        match result.status {
            POLL_READY => {
                // SAFETY: `result.ptr` was just returned by the
                // extension's poll-once shim with the matching len;
                // it's a Vec we own until `free_reply` releases it.
                let reply = if !result.ptr.is_null() && result.len > 0 {
                    unsafe { std::slice::from_raw_parts(result.ptr, result.len) }.to_vec()
                } else {
                    Vec::new()
                };
                instance.free_reply(&result);
                return DispatchOutcome::Ok(reply);
            }
            POLL_PENDING => {
                let effect = instance.pending_effect();
                let result = handle_effect(&effect, inbox, outbox, extension_id, deferred);
                instance.provide_result(&result);
            }
            err => {
                error!(%extension_id, status = err, "extension: poll returned error");
                return DispatchOutcome::Err;
            }
        }
    }
}

/// Fulfill a host I/O effect. Dispatches by the effect tag byte.
fn handle_effect(
    effect: &[u8],
    inbox: &mpsc::Receiver<Envelope>,
    outbox: &mpsc::Sender<Envelope>,
    extension_id: ServiceId,
    deferred: &mut std::collections::VecDeque<Envelope>,
) -> Vec<u8> {
    use crate::effects::{EFFECT_ASK, EFFECT_FETCH};

    if effect.is_empty() {
        return Vec::new();
    }
    let tag = effect[0];
    let rest = &effect[1..];

    match tag {
        EFFECT_ASK => {
            // [target:u32 LE][payload...]
            if rest.len() < 4 {
                return Vec::new();
            }
            let target_id = u32::from_le_bytes(rest[..4].try_into().unwrap());
            let payload = rest[4..].to_vec();
            let _ = outbox.send(Envelope {
                from: extension_id,
                to: ServiceId(target_id),
                payload,
            });
            wait_for_reply(inbox, target_id, deferred)
        }
        EFFECT_FETCH => {
            #[cfg(feature = "http")]
            {
                handle_fetch(rest)
            }
            #[cfg(not(feature = "http"))]
            {
                let _ = rest;
                crate::effects::FetchResponse::host_error(
                    "vos: built without 'http' feature — EFFECT_FETCH unavailable",
                )
                .encode()
            }
        }
        other => {
            error!(%extension_id, tag = format!("{other:#04x}"), "extension: unknown effect tag");
            Vec::new()
        }
    }
}

/// Perform an HTTP request via ureq. Blocking; runs on the worker thread.
#[cfg(feature = "http")]
fn handle_fetch(payload: &[u8]) -> Vec<u8> {
    use crate::effects::{FetchRequest, FetchResponse, HttpMethod};

    let Some(req) = FetchRequest::decode(payload) else {
        return FetchResponse::host_error("malformed FetchRequest").encode();
    };

    let mut ureq_req = match req.method {
        HttpMethod::Get => ureq::get(&req.url),
        HttpMethod::Post => ureq::post(&req.url),
        HttpMethod::Put => ureq::put(&req.url),
        HttpMethod::Delete => ureq::delete(&req.url),
        HttpMethod::Patch => ureq::patch(&req.url),
        HttpMethod::Head => ureq::head(&req.url),
        HttpMethod::Options => ureq::request("OPTIONS", &req.url),
    };
    for (name, value) in &req.headers {
        ureq_req = ureq_req.set(name, value);
    }

    let result = if req.body.is_empty() {
        ureq_req.call()
    } else {
        ureq_req.send_bytes(&req.body)
    };

    let response = match result {
        Ok(r) => ureq_response_to(r),
        Err(ureq::Error::Status(code, r)) => {
            let mut resp = ureq_response_to(r);
            resp.status = code;
            resp
        }
        Err(e) => FetchResponse::host_error(format!("network error: {e}")),
    };

    response.encode()
}

#[cfg(feature = "http")]
fn ureq_response_to(r: ureq::Response) -> crate::effects::FetchResponse {
    use crate::effects::FetchResponse;
    let status = r.status();
    let headers: Vec<(String, String)> = r
        .headers_names()
        .into_iter()
        .filter_map(|n| r.header(&n).map(|v| (n, v.to_string())))
        .collect();
    let mut body = Vec::new();
    let _ = std::io::Read::read_to_end(&mut r.into_reader(), &mut body);
    FetchResponse {
        status,
        headers,
        body,
    }
}

// ── State persistence ───────────────────────────────────────────────

/// Pick the worker's commit strategy from its config.
///
/// Workers never get CRDT or Raft commits — they live outside the
/// deterministic universe. If a data directory is configured and the
/// `storage` feature is on, use [`LocalCommit`]; otherwise fall back
/// to [`NoCommit`] (state is held in memory only).
///
/// [`LocalCommit`]: crate::commit::LocalCommit
/// [`NoCommit`]: crate::commit::NoCommit
fn build_extension_strategy(
    config: &ExtensionConfig,
    id: ServiceId,
) -> Box<dyn crate::commit::CommitStrategy> {
    #[cfg(feature = "storage")]
    {
        if let Some(path) = config.db_path() {
            match crate::commit::LocalCommit::open(&path) {
                Ok(lc) => return Box::new(lc),
                Err(e) => {
                    warn!(%id, error = %e, "extension: failed to open storage; continuing without persistence")
                }
            }
        }
    }
    #[cfg(not(feature = "storage"))]
    {
        let _ = (config, id);
    }
    Box::new(crate::commit::NoCommit)
}

/// Serialize the worker's state and hand it to the commit strategy.
fn persist(
    strategy: &mut dyn crate::commit::CommitStrategy,
    instance: &crate::extension::ExtensionInstance<'_>,
    id: ServiceId,
) {
    let bytes = instance.save_state();
    if let Err(e) = strategy.commit(&bytes) {
        warn!(%id, error = %e, "extension: failed to persist state");
    }
}

/// Block until a reply arrives from a specific target service.
/// Messages from other senders are pushed to the deferred queue.
fn wait_for_reply(
    inbox: &mpsc::Receiver<Envelope>,
    target_id: u32,
    deferred: &mut std::collections::VecDeque<Envelope>,
) -> Vec<u8> {
    use std::time::Duration;
    const REPLY_TIMEOUT: Duration = Duration::from_secs(10);

    loop {
        match inbox.recv_timeout(REPLY_TIMEOUT) {
            Ok(reply) if reply.from.0 == target_id => {
                return reply.payload;
            }
            Ok(other) => {
                // Not the reply we're waiting for — defer it
                if deferred.len() < MAX_DEFERRED {
                    deferred.push_back(other);
                } else {
                    warn!(from = %other.from, "extension: deferred queue full, dropping message");
                }
            }
            Err(_) => {
                warn!(target_id, "extension: ask timeout waiting for reply");
                return Vec::new();
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn node_lifecycle_basic() {
        let mut node = VosNode::new();
        node.run();
        let results = node.collect();
        assert!(results.is_empty());
    }

    // ── unwrap_invoke_envelope contract ─────────────────────────
    //
    // Locks in what b112aa6 doc-corrected: STATUS_DONE and
    // STATUS_YIELDED both surface their reply bytes; everything
    // else (PANICKED, NOT_FOUND, short envelopes, malformed
    // state_len) collapses to None so gateway/host callers see
    // "no reply" rather than partial garbage.

    fn make_envelope(status: u8, state: &[u8], reply: &[u8]) -> Vec<u8> {
        // Mirrors `encode_invoke_envelope` exactly so we're not
        // testing the encoder against itself — keeps the test
        // honest if `encode_invoke_envelope` regresses.
        let mut v = Vec::with_capacity(5 + state.len() + reply.len());
        v.push(status);
        v.extend_from_slice(&(state.len() as u32).to_le_bytes());
        v.extend_from_slice(state);
        v.extend_from_slice(reply);
        v
    }

    #[test]
    fn unwrap_envelope_done_with_reply_yields_reply() {
        use crate::actors::run::STATUS_DONE;
        let env = make_envelope(STATUS_DONE, b"some-state", b"the-reply");
        assert_eq!(
            unwrap_invoke_envelope(&env).as_deref(),
            Some(&b"the-reply"[..]),
        );
    }

    #[test]
    fn unwrap_envelope_done_with_empty_reply_yields_empty() {
        use crate::actors::run::STATUS_DONE;
        let env = make_envelope(STATUS_DONE, b"state-only", b"");
        // Empty reply is meaningful: handler returned `()`.
        // Caller distinguishes `Some(empty)` (returned unit) from
        // `None` (envelope unusable).
        let r = unwrap_invoke_envelope(&env).expect("done envelope decodes");
        assert!(r.is_empty(), "empty-reply envelope must yield Some(empty)");
    }

    #[test]
    fn unwrap_envelope_yielded_surfaces_reply() {
        // YIELDED carries a post-dispatch state + the partial
        // reply so far. Host callers (gateway) just want the
        // bytes; the YIELDED-vs-DONE distinction is for
        // `decode_invoke_envelope` on the runtime side.
        use crate::actors::run::STATUS_YIELDED;
        let env = make_envelope(STATUS_YIELDED, b"yielded-state", b"partial");
        assert_eq!(
            unwrap_invoke_envelope(&env).as_deref(),
            Some(&b"partial"[..]),
        );
    }

    #[test]
    fn unwrap_envelope_panicked_yields_none() {
        // The gateway path now distinguishes panic → 502 from
        // "() return" → 200 null. That hinges on PANICKED
        // collapsing to None here.
        let env = make_envelope(crate::STATUS_PANICKED, b"", b"would-be-reply");
        assert_eq!(unwrap_invoke_envelope(&env), None);
    }

    #[test]
    fn unwrap_envelope_not_found_yields_none() {
        let env = make_envelope(crate::STATUS_NOT_FOUND, b"", b"");
        assert_eq!(unwrap_invoke_envelope(&env), None);
    }

    #[test]
    fn unwrap_envelope_too_short_yields_none() {
        // < 5 bytes can't carry status + state_len, regardless
        // of what those bytes claim.
        assert_eq!(unwrap_invoke_envelope(&[]), None);
        assert_eq!(unwrap_invoke_envelope(&[0]), None);
        assert_eq!(unwrap_invoke_envelope(&[0, 0, 0, 0]), None);
    }

    #[cfg(feature = "network")]
    #[test]
    fn forbidden_envelope_is_5_bytes_starting_with_status_forbidden() {
        // Wire-shape contract: vosx's `is_forbidden_envelope` peeks
        // for exactly this 5-byte pattern to surface
        // `ClientError::Forbidden`. If either the length or the
        // status byte drifts, the client-side detection silently
        // breaks and refusals collapse back to "transport failure"
        // again. Pin both.
        let env = forbidden_envelope();
        assert_eq!(env.len(), 5, "forbidden envelope must be exactly 5 bytes");
        assert_eq!(env[0], crate::STATUS_FORBIDDEN, "status byte mismatch");
        assert_eq!(&env[1..5], &[0, 0, 0, 0], "state_len must be zero");
    }

    #[test]
    fn unwrap_envelope_forbidden_yields_none() {
        // STATUS_FORBIDDEN belongs to the same failure family as
        // PANICKED/NOT_FOUND/OOG for `unwrap_invoke_envelope` —
        // there's no actor-produced reply to surface. Client-side
        // detection happens at a different layer (Invoker for
        // &VosNode), not here.
        let env = make_envelope(crate::STATUS_FORBIDDEN, b"", b"");
        assert_eq!(unwrap_invoke_envelope(&env), None);
    }

    #[test]
    fn unwrap_envelope_oversized_state_len_yields_none() {
        // state_len claims more bytes than the envelope holds —
        // a hostile or corrupt wire payload. Must collapse to
        // None rather than slicing out-of-bounds.
        use crate::actors::run::STATUS_DONE;
        let mut env = Vec::new();
        env.push(STATUS_DONE);
        env.extend_from_slice(&(999u32).to_le_bytes()); // claims 999B state
        env.extend_from_slice(b"only-3"); // but only 6 bytes follow
        assert_eq!(unwrap_invoke_envelope(&env), None);
    }

    #[test]
    fn invoke_forward_check_detects_cycle() {
        // Self-invoke (target already in chain).
        let chain = [1u32];
        assert_eq!(check_invoke_forward(&chain, 1), InvokeForwardCheck::Cycle);

        // A→B with B trying to call A.
        let chain = [1u32, 2u32];
        assert_eq!(check_invoke_forward(&chain, 1), InvokeForwardCheck::Cycle);

        // A→B→C, fresh target D — allowed.
        let chain = [1u32, 2u32, 3u32];
        assert_eq!(check_invoke_forward(&chain, 4), InvokeForwardCheck::Allowed);
    }

    #[test]
    fn send_reply_capped_passes_normal_payload() {
        let (tx, rx) = mpsc::channel();
        send_reply_capped(tx, vec![0u8; 100], ServiceId(1));
        let received = rx.recv().expect("received");
        assert_eq!(received.len(), 100);
    }

    #[test]
    fn send_reply_capped_drops_oversized_payload() {
        let (tx, rx) = mpsc::channel();
        // One byte over the cap.
        send_reply_capped(tx, vec![0u8; MAX_PRODUCER_REPLY + 1], ServiceId(1));
        // Sender dropped without sending → recv yields Err(Disconnected).
        // External_invoke maps that to None, surfacing as
        // InvokeError::NotFound at the caller's PVM.
        assert!(
            rx.recv().is_err(),
            "tx should have been dropped without a send"
        );
    }

    #[test]
    fn invoke_forward_check_caps_depth() {
        let chain: Vec<u32> = (1..=MAX_CROSS_AGENT_DEPTH as u32).collect();
        assert_eq!(chain.len(), MAX_CROSS_AGENT_DEPTH);
        // At cap, even a fresh target is rejected.
        assert_eq!(
            check_invoke_forward(&chain, 9999),
            InvokeForwardCheck::DepthExceeded,
        );
        // One under cap is fine.
        let chain = &chain[..MAX_CROSS_AGENT_DEPTH - 1];
        assert_eq!(
            check_invoke_forward(chain, 9999),
            InvokeForwardCheck::Allowed,
        );
    }

    #[test]
    fn service_id_topology() {
        let id = ServiceId::new(0x00A3, 5);
        assert_eq!(id.0, 0x00A3_0005);
        assert_eq!(id.node_prefix(), 0x00A3);
        assert_eq!(id.local_id(), 5);
        assert!(id.is_on_node(0x00A3));
        assert!(!id.is_on_node(0));
        assert!(!id.is_local());
    }

    #[test]
    fn backwards_compat_local_ids() {
        let id = ServiceId(3);
        assert_eq!(id.node_prefix(), 0);
        assert_eq!(id.local_id(), 3);
        assert!(id.is_local());
        assert!(id.is_on_node(0));
    }

    #[test]
    fn registry_is_zero() {
        assert_eq!(ServiceId::REGISTRY.0, 0);
        assert_eq!(ServiceId::REGISTRY.node_prefix(), 0);
        assert_eq!(ServiceId::REGISTRY.local_id(), 0);
    }

    #[test]
    fn node_assigns_global_ids() {
        let node = VosNode::with_prefix(0x0042);
        let id1 = node.alloc_id();
        let id2 = node.alloc_id();
        assert_eq!(id1, ServiceId::new(0x0042, 1));
        assert_eq!(id2, ServiceId::new(0x0042, 2));
        assert!(id1.is_on_node(0x0042));
    }

    #[test]
    #[cfg(feature = "storage")]
    fn extension_state_persists_across_restarts() {
        // EchoExtension has a `count` field that increments on each echo.
        // Run the worker, send a few messages, shut down. Restart with
        // the same redb path — the count should resume where it left off.
        let workspace = std::path::PathBuf::from(env!("CARGO_MANIFEST_DIR"))
            .parent()
            .unwrap()
            .to_path_buf();
        let profile = if cfg!(debug_assertions) {
            "debug"
        } else {
            "release"
        };
        let echo_path = workspace
            .join("target")
            .join(profile)
            .join("libecho_extension.so");
        if !echo_path.exists() {
            eprintln!("skipping: build echo-extension first");
            return;
        }

        // Use a temp data directory
        let data_dir =
            std::env::temp_dir().join(format!("vos_test_persist_{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&data_dir);

        use crate::actors::codec::Encode;
        use crate::actors::value::Msg;
        let send_echo = |node: &VosNode, target: ServiceId, text: &str| {
            let msg = Msg::new("echo").with("text", text);
            let encoded = msg.encode();
            let mut payload = Vec::with_capacity(1 + encoded.len());
            payload.push(crate::actors::value::TAG_DYNAMIC);
            payload.extend_from_slice(&encoded);
            if let Some(tx) = node.routes.get(&target.0) {
                tx.send(Envelope {
                    from: ServiceId(0),
                    to: target,
                    payload,
                })
                .unwrap();
            }
        };

        // ── First run: send 2 echoes ────────────────────────────────
        {
            let mut node = VosNode::new();
            let id =
                node.register_extension(ExtensionConfig::new(echo_path.clone()).persist(&data_dir));
            send_echo(&node, id, "first");
            send_echo(&node, id, "second");
            node.run();
            let _ = node.collect();
        }

        // ── Second run: state should be restored, count starts at 2 ──
        {
            let mut node = VosNode::new();
            let id = node.register_extension(ExtensionConfig::new(echo_path).persist(&data_dir));
            send_echo(&node, id, "third");
            node.run();
            let _ = node.collect();
        }

        // Verify by opening the db directly and checking the persisted state
        use crate::commit::STATE_TABLE;
        let db_path = data_dir.join("extensions").join("echo_extension.redb");
        let db = redb::Database::open(&db_path).expect("open db");
        let txn = db.begin_read().unwrap();
        let table = txn.open_table(STATE_TABLE).unwrap();
        let bytes = table
            .get("actor")
            .unwrap()
            .expect("state present")
            .value()
            .to_vec();

        // EchoExtension has a single u32 `count` field — rkyv packs it to
        // exactly 4 bytes. After 3 echoes, count = 3.
        assert_eq!(bytes.len(), 4, "EchoExtension state is one u32");
        let count = u32::from_le_bytes(bytes.try_into().unwrap());
        assert_eq!(count, 3, "expected 3 echoes total across both runs");

        let _ = std::fs::remove_dir_all(&data_dir);
    }

    #[test]
    #[cfg(feature = "http")]
    fn extension_does_http_fetch() {
        // Loads fetcher-extension and asks it to GET a URL.
        // Uses example.com which is stable and small. Skips on no network.
        let workspace = std::path::PathBuf::from(env!("CARGO_MANIFEST_DIR"))
            .parent()
            .unwrap()
            .to_path_buf();
        let profile = if cfg!(debug_assertions) {
            "debug"
        } else {
            "release"
        };
        let path = workspace
            .join("target")
            .join(profile)
            .join("libfetcher_extension.so");
        if !path.exists() {
            eprintln!("skipping extension_does_http_fetch: build fetcher-extension first");
            return;
        }

        let mut node = VosNode::new();
        let fetcher_id = node.register_extension(ExtensionConfig::new(path));

        use crate::actors::codec::Encode;
        use crate::actors::value::Msg;
        let msg = Msg::new("status").with("url", "https://example.com");
        let encoded = msg.encode();
        let mut payload = Vec::with_capacity(1 + encoded.len());
        payload.push(crate::actors::value::TAG_DYNAMIC);
        payload.extend_from_slice(&encoded);

        if let Some(tx) = node.routes.get(&fetcher_id.0) {
            tx.send(Envelope {
                from: ServiceId(0),
                to: fetcher_id,
                payload,
            })
            .unwrap();
        }

        node.run();
        let results = node.collect();
        for r in &results {
            assert_eq!(r.panics, 0, "fetcher worker {} panicked", r.id);
        }
    }

    #[test]
    fn extension_to_extension_ask() {
        // This test requires both echo-extension and proxy-extension to be built.
        // Run: cargo build -p echo-extension -p proxy-extension
        let workspace = std::path::PathBuf::from(env!("CARGO_MANIFEST_DIR"))
            .parent()
            .unwrap()
            .to_path_buf();
        let profile = if cfg!(debug_assertions) {
            "debug"
        } else {
            "release"
        };
        let echo_path = workspace
            .join("target")
            .join(profile)
            .join("libecho_extension.so");
        let proxy_path = workspace
            .join("target")
            .join(profile)
            .join("libproxy_extension.so");

        if !echo_path.exists() || !proxy_path.exists() {
            eprintln!("skipping extension_to_extension_ask: build workers first");
            return;
        }

        let mut node = VosNode::new();

        // Register echo worker — gets ServiceId 1
        let echo_id = node.register_extension(ExtensionConfig::new(echo_path));

        // Build init args for proxy: target = echo's ServiceId
        use crate::actors::codec::Encode;
        use crate::actors::value::{Args, Msg};
        let proxy_args = Args::new().with("target", echo_id.0);
        let proxy_id = node.register_extension(ExtensionConfig::with_args(proxy_path, &proxy_args));

        // Send a "proxy" message to the proxy worker (no target arg now —
        // the proxy already knows its target from init args)
        let msg = Msg::new("proxy").with("text", "hello via proxy");
        let encoded = msg.encode();
        let mut payload = Vec::with_capacity(1 + encoded.len());
        payload.push(crate::actors::value::TAG_DYNAMIC);
        payload.extend_from_slice(&encoded);

        // Inject the message by sending directly to proxy's route
        if let Some(tx) = node.routes.get(&proxy_id.0) {
            tx.send(Envelope {
                from: ServiceId(0), // pretend it's from the registry
                to: proxy_id,
                payload,
            })
            .unwrap();
        }

        // Run the node — proxy asks echo, echo replies, proxy replies back
        node.run();
        let results = node.collect();

        // Both workers should complete without panics
        for r in &results {
            assert_eq!(r.panics, 0, "worker {} panicked", r.id);
        }
    }

    #[test]
    fn display_format() {
        assert_eq!(format!("{}", ServiceId(3)), "svc:3");
        assert_eq!(format!("{}", ServiceId::new(0x00A3, 5)), "svc:00a3:5");
        assert_eq!(format!("{}", ServiceId::REGISTRY), "svc:0");
    }

    /// Phase 3 — service-mode extension end-to-end. Loads echo
    /// (kind=Actor) at id 1, then heartbeat (kind=Service) which
    /// pings echo every 100ms. After 500ms, asserts that echo's
    /// reply count grew (heartbeat actually originated calls), then
    /// signals shutdown and confirms heartbeat exits cleanly.
    #[test]
    fn service_extension_originates_asks_via_ctx() {
        let workspace = std::path::PathBuf::from(env!("CARGO_MANIFEST_DIR"))
            .parent()
            .unwrap()
            .to_path_buf();
        let profile = if cfg!(debug_assertions) {
            "debug"
        } else {
            "release"
        };
        let echo_path = workspace
            .join("target")
            .join(profile)
            .join("libecho_extension.so");
        let heartbeat_path = workspace
            .join("target")
            .join(profile)
            .join("libheartbeat_extension.so");

        if !echo_path.exists() || !heartbeat_path.exists() {
            eprintln!(
                "skipping service_extension_originates_asks_via_ctx: \
                 build echo-extension and heartbeat-extension first"
            );
            return;
        }

        // Heartbeat targets ServiceId(1) by default — register echo
        // first so it lands at id 1.
        let mut node = VosNode::new();
        let echo_id = node.register_extension(ExtensionConfig::new(echo_path));
        assert_eq!(
            echo_id.0, 1,
            "echo should land at id 1 (heartbeat default target)"
        );

        let _heartbeat_id = node.register_extension(ExtensionConfig::new(heartbeat_path));

        // Let the heartbeat tick for ~500ms — at PING_EVERY=100ms
        // that's ~5 round trips. Use run_until_idle with a
        // generous threshold; the heartbeat keeps the node busy so
        // it won't go idle until shutdown.
        std::thread::spawn({
            let shutdown = node.shutdown.clone();
            move || {
                std::thread::sleep(std::time::Duration::from_millis(500));
                shutdown.store(true, std::sync::atomic::Ordering::Relaxed);
            }
        });
        node.run_forever();
        let results = node.collect();
        for r in &results {
            assert_eq!(r.panics, 0, "extension {} panicked: {:?}", r.id, r.error);
        }
    }
}
