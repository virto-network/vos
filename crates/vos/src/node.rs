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
use std::sync::{mpsc, Arc, Mutex};
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
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Consistency {
    /// In-memory only — state is lost when the agent exits. The
    /// default; matches the pre-persistence behaviour.
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

impl Default for Consistency {
    fn default() -> Self {
        Self::Ephemeral
    }
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
    /// + a logical name. Replicas with identical (blob, name)
    /// automatically share an id without manifest coordination.
    pub fn auto_replication_id(mut self, name: &str) -> Self {
        let mut h = blake2b_simd::Params::new()
            .hash_length(32)
            .to_state();
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

/// Configuration for registering a native worker in the node.
pub struct WorkerConfig {
    /// Path to the worker `.so` file.
    pub path: std::path::PathBuf,
    /// rkyv-encoded `vos::value::Args` for the worker's constructor.
    /// Empty if the constructor takes no parameters.
    pub init_args: Vec<u8>,
    /// Optional data directory for state persistence.
    /// When set, the worker's redb file is created at
    /// `{data_dir}/workers/{name}.redb`.
    pub data_dir: Option<std::path::PathBuf>,
}

impl WorkerConfig {
    /// Build a config with no init args and no persistence.
    pub fn new(path: impl Into<std::path::PathBuf>) -> Self {
        Self { path: path.into(), init_args: Vec::new(), data_dir: None }
    }

    /// Build a config with rkyv-encoded init args.
    pub fn with_args(path: impl Into<std::path::PathBuf>, args: &crate::value::Args) -> Self {
        let bytes = crate::rkyv::to_bytes::<crate::rkyv::rancor::Error>(args)
            .expect("rkyv encode Args")
            .to_vec();
        Self { path: path.into(), init_args: bytes, data_dir: None }
    }

    /// Enable state persistence under the given data directory.
    /// The worker's state is stored in `{data_dir}/workers/{name}.redb`
    /// where `name` is derived from the `.so` filename.
    pub fn persist(mut self, data_dir: impl Into<std::path::PathBuf>) -> Self {
        self.data_dir = Some(data_dir.into());
        self
    }

    /// Derive the redb path from the data directory and the .so filename.
    #[cfg(feature = "storage")]
    fn db_path(&self) -> Option<std::path::PathBuf> {
        let data_dir = self.data_dir.as_ref()?;
        let name = self.path.file_stem()
            .and_then(|s| s.to_str())
            .unwrap_or("worker")
            .trim_start_matches("lib");
        let dir = data_dir.join("workers");
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
/// `handle_invoke_request` and `worker_thread`.
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
    /// `replication_id` is added. Read by [`NodeSyncHandler`]
    /// (db only) to answer inbound sync queries; the agent
    /// thread and sync ticker share the `commit_lock` to
    /// serialize their writes against each other.
    #[cfg(all(feature = "network", feature = "storage"))]
    pub(crate) crdt_replicas: Arc<Mutex<HashMap<[u8; 32], ReplicaSlot>>>,
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
        tx.send(InvokeRequest { msg, reply_tx, chain: Vec::new() }).ok()?;
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

/// `InvokeHandler` impl that routes inbound cross-node invokes
/// into this node's local invoke-route table. The network thread
/// runs `dispatch` on a `tokio::task::spawn_blocking`, so blocking
/// on the std `mpsc` reply channel here is fine.
#[cfg(feature = "network")]
struct LocalInvokeHandler {
    invoke_routes: InvokeRoutes,
}

/// `SyncHandler` impl backed by the node's `crdt_replicas` map.
/// Looks up the shared `Arc<Database>` for the replication group
/// and reads roots / DAG nodes directly through the public
/// `commit::read_roots` / `commit::read_dag_node` helpers. Reads
/// are pure redb read txns — they don't need the commit lock.
#[cfg(all(feature = "network", feature = "storage"))]
struct NodeSyncHandler {
    replicas: Arc<Mutex<HashMap<[u8; 32], ReplicaSlot>>>,
}

#[cfg(all(feature = "network", feature = "storage"))]
impl crate::network::SyncHandler for NodeSyncHandler {
    fn roots(&self, replication_id: &[u8; 32]) -> Option<Vec<[u8; 32]>> {
        let slot = self.replicas.lock().ok()?.get(replication_id).cloned()?;
        crate::commit::read_roots(&slot.db).ok()
    }
    fn get_node(&self, replication_id: &[u8; 32], cid: &[u8; 32]) -> Option<Vec<u8>> {
        let slot = self.replicas.lock().ok()?.get(replication_id).cloned()?;
        crate::commit::read_dag_node(&slot.db, cid).ok().flatten()
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
        let replay = runtime
            .finish_replay()
            .expect("replay was active");
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
            net.subscribe_rep(rep_id);
            net.register_hint_sender(rep_id, hint_tx.clone());
            subscribed = true;
        }
        let local = net.peer_id();
        let connected: HashSet<libp2p::PeerId> =
            net.connected_peers().into_iter().filter(|p| p != &local).collect();
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
        let reprobe = tick % SYNC_REPROBE_EVERY == 0 || confirmed.is_empty();
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
        if any_inserted {
            if let Some(n) = &notifier {
                let _ = n.send(());
            }
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
    use crate::effect_log::EffectLog;
    use merkle_crdt::DagNode;

    let heads_rx = net.send_fetch_heads(peer, *rep_id);
    let heads = match heads_rx.recv_timeout(SYNC_FETCH_TIMEOUT) {
        Ok(v) => v,
        Err(_) => return Ok(SyncOutcome::PeerEmpty),
    };
    if heads.is_empty() {
        return Ok(SyncOutcome::PeerEmpty);
    }

    let mut cc = CrdtCommit::from_db_arc_locked(slot.db.clone(), slot.commit_lock.clone());
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
        if let Some(node) = DagNode::<crate::commit::Blake2b, EffectLog>::from_bytes(&node_bytes) {
            for child in node.children {
                frontier.push(child.0);
            }
        }
    }

    if inserted_any {
        cc.compact_roots()?;
    }
    Ok(SyncOutcome::PeerHasGroup { inserted: inserted_any })
}

#[cfg(feature = "network")]
impl crate::network::InvokeHandler for LocalInvokeHandler {
    fn dispatch(&self, _from: u32, to: u32, chain: Vec<u32>, msg: Vec<u8>) -> Vec<u8> {
        // The chain arrived already including the original caller's
        // ID (the remote peer's agent). The receiver's own
        // external_invoke prepends *this* agent's ID when dispatching
        // further hops, so we don't need to touch the chain here.
        let tx = self
            .invoke_routes
            .lock()
            .ok()
            .and_then(|m| m.get(&to).cloned());
        let Some(tx) = tx else {
            return Vec::new();
        };
        let (reply_tx, reply_rx) = mpsc::channel();
        if tx
            .send(InvokeRequest {
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
        reply_rx
            .recv_timeout(Duration::from_secs(10))
            .ok()
            .and_then(|env| unwrap_invoke_envelope(&env))
            .unwrap_or_default()
    }
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
            #[cfg(all(feature = "network", feature = "storage"))]
            sync_threads: Vec::new(),
        }
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
        // Install the dispatcher first so any inbound InvokeRequest
        // that arrives between now and the bridge starting gets
        // resolved against this node's invoke_routes rather than
        // the empty-reply default.
        let dispatcher = Arc::new(LocalInvokeHandler {
            invoke_routes: self.invoke_routes.clone(),
        });
        network.set_invoke_handler(dispatcher);

        // Same story for the sync provider — answers inbound
        // FetchHeads/FetchNode against the local CRDT replicas
        // already opened by `register`.
        #[cfg(feature = "storage")]
        {
            let sync_provider = Arc::new(NodeSyncHandler {
                replicas: self.crdt_replicas.clone(),
            });
            network.set_sync_handler(sync_provider);
        }

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
        } else if config.consistency == Consistency::Raft
            && config.members.len() > 1
        {
            // Multi-mode Raft: spawn a worker, install it as the
            // network's RaftRpcHandler, and bridge the worker's
            // apply notifications into both (a) the agent's
            // sync_rx (so the soft-restart path catches up state
            // on followers) and (b) the strategy's apply_rx (so
            // the leader's commit_with_log unblocks once its
            // proposed entry commits).
            let network = self.shared_network.lock().ok().and_then(|g| g.clone());
            let rep_id = config.replication_id.unwrap_or([0u8; 32]);
            match config.db_path(id).map(|p| (p, redb::Database::create(&config.db_path(id).unwrap()))) {
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
                id, config, rx, invoke_rx, outbox, invoke_routes, shutdown, activity,
                #[cfg(feature = "network")] shared_network,
                #[cfg(all(feature = "network", feature = "storage"))] sync_rx,
            )
        });

        self.agents.push(AgentHandle { join: Some(join) });
        id
    }

    /// Register a native worker and return its service ID.
    /// The worker starts immediately on a new thread.
    pub fn register_worker(&mut self, config: WorkerConfig) -> ServiceId {
        let id = self.alloc_id();
        let (tx, rx) = mpsc::channel();
        let (invoke_tx, invoke_rx) = mpsc::channel();
        let outbox = self.outbox_tx.clone();

        self.routes.insert(id.0, tx);
        self.invoke_routes.lock().unwrap().insert(id.0, invoke_tx);

        let shutdown = self.shutdown.clone();
        let activity = self.last_activity.clone();

        let join = thread::spawn(move || {
            worker_thread(id, config, rx, invoke_rx, outbox, shutdown, activity)
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
                    let all_done = self.agents.iter().all(|h| {
                        h.join.as_ref().map_or(true, |j| j.is_finished())
                    });
                    if all_done { break; }

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
                    let all_done = self.agents.iter().all(|h| {
                        h.join.as_ref().map_or(true, |j| j.is_finished())
                    });
                    if all_done { break; }
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
        let join = thread::spawn(move || sync_loop(rep_id, shared_network, slot, shutdown, notifier));
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
                let envelope = encode_invoke_envelope(
                    crate::actors::run::STATUS_DONE, &[], &reply,
                );
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
        // 1. Local
        let local_tx = {
            let map = self.invoke_routes.lock().ok()?;
            map.get(&target.0).cloned()
        };
        if let Some(tx) = local_tx {
            let (reply_tx, reply_rx) = mpsc::channel();
            tx.send(InvokeRequest {
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
                if let Some(net) = net {
                    if let Some(peer) = net.peer_for_prefix(target.node_prefix()) {
                        // `from = 0` because this is host-side; it
                        // never participates in chain detection.
                        let reply_rx = net.send_invoke(
                            peer,
                            ServiceId::REGISTRY.0,
                            target.0,
                            Vec::new(),
                            msg,
                        );
                        return reply_rx.recv_timeout(timeout).ok();
                    }
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
        // is dropped with a warn — kunekt has no store-and-forward
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
    #[cfg(all(feature = "network", feature = "storage"))]
    sync_rx: Option<mpsc::Receiver<()>>,
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
                let net = shared_network_for_ext
                    .lock()
                    .ok()
                    .and_then(|g| g.clone());
                if let Some(net) = net {
                    let prefix = target.node_prefix();
                    if let Some(peer) = net.peer_for_prefix(prefix) {
                        let reply_rx = net.send_invoke(
                            peer,
                            id.0,
                            target.0,
                            chain_snapshot,
                            msg.to_vec(),
                        );
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
    let recording_enabled = matches!(
        consistency,
        Consistency::Crdt | Consistency::Raft,
    );
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
                return AgentResult { id, panics: 0, error: Some(err) };
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
                if !state.is_empty() {
                    if let Err(e) = strategy.commit(&state) {
                        let err = format!("post-replay commit failed: {e}");
                        error!(%id, "{err}");
                        return AgentResult {
                            id,
                            panics: runtime.panics,
                            error: Some(err),
                        };
                    }
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
        if shutdown.load(Ordering::Relaxed) { break; }

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
                        &mut runtime, svc_id, &outbox, id, req,
                        strategy.as_mut(), recording_enabled,
                    );
                    if let Err(e) = outcome {
                        fatal_error = Some(format!("commit failed during invoke: {e}"));
                        break;
                    }
                    #[cfg(all(feature = "network", feature = "storage"))]
                    publish_heads_if_replicated(
                        &shared_network, agent_rep_id, strategy.as_ref(),
                    );
                }
                Err(mpsc::TryRecvError::Empty) => break,
                Err(mpsc::TryRecvError::Disconnected) => break,
            }
        }
        if fatal_error.is_some() { break; }
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
            if let Err(e) = dispatch_once(&mut runtime, svc_id, &outbox, id, None,
                strategy.as_mut(), recording_enabled) {
                // On a Raft follower the commit can return
                // NotLeader. Log, soft-restart to bring the runtime
                // back in sync, continue. CRDT failures are still
                // unexpected but the same recovery applies.
                warn!(%id, error = %e, "residual-work commit failed; soft-restarting");
                #[cfg(all(feature = "network", feature = "storage"))]
                if let Err(restart_err) = soft_restart_crdt(&mut runtime, svc_id, strategy.as_mut()) {
                    fatal_error = Some(format!("residual soft restart: {restart_err}"));
                    break;
                }
                continue;
            }
            #[cfg(all(feature = "network", feature = "storage"))]
            publish_heads_if_replicated(
                &shared_network, agent_rep_id, strategy.as_ref(),
            );
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
        if let Err(e) = dispatch_once(&mut runtime, svc_id, &outbox, id, Some(msg),
            strategy.as_mut(), recording_enabled) {
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
        publish_heads_if_replicated(
            &shared_network, agent_rep_id, strategy.as_ref(),
        );
    }

    if let Some(err) = &fatal_error {
        error!(%id, "{err}");
    }
    AgentResult { id, panics: runtime.panics, error: fatal_error }
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
    let Some(rep_id) = rep_id else { return; };
    let Some(net) = shared_network.lock().ok().and_then(|g| g.clone()) else { return; };
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
/// `worker_thread`.
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
        None => { drop(req.reply_tx); return Ok(()); }
    };
    let status = if runtime.is_suspended(svc_id) {
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
/// the handler's return value. A short envelope (just a status byte
/// from `STATUS_NOT_FOUND` / `STATUS_PANICKED`) decodes as `None`.
fn unwrap_invoke_envelope(envelope: &[u8]) -> Option<Vec<u8>> {
    if envelope.len() < 5 { return None; }
    let state_len = u32::from_le_bytes([
        envelope[1], envelope[2], envelope[3], envelope[4],
    ]) as usize;
    let reply_start = 5 + state_len;
    if reply_start > envelope.len() { return None; }
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
    if envelope.len() < 5 { return None; }
    let status = envelope[0];
    let state_len = u32::from_le_bytes([
        envelope[1], envelope[2], envelope[3], envelope[4],
    ]) as usize;
    let state_end = 5 + state_len;
    if state_end > envelope.len() { return None; }
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
    let recorded = msg.is_some() && recording_enabled;
    if recorded {
        runtime.begin_recording(msg.as_ref().unwrap().clone());
    }
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
                if let Some(arc) = &config.pre_opened_db {
                    let cc = match &config.pre_opened_lock {
                        Some(lock) => crate::commit::CrdtCommit::from_db_arc_locked(
                            arc.clone(),
                            lock.clone(),
                        ),
                        None => crate::commit::CrdtCommit::from_db_arc(arc.clone()),
                    };
                    return Ok(Box::new(cc));
                }
                let path = config.db_path(id).ok_or_else(|| {
                    crate::commit::CommitError::Config(
                        "Crdt consistency requires data_dir on AgentConfig".into(),
                    )
                })?;
                Ok(Box::new(crate::commit::CrdtCommit::open(&path)?))
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

fn worker_thread(
    id: ServiceId,
    config: WorkerConfig,
    inbox: mpsc::Receiver<Envelope>,
    invoke_rx: mpsc::Receiver<InvokeRequest>,
    outbox: mpsc::Sender<Envelope>,
    shutdown: Arc<AtomicBool>,
    activity: ActivityClock,
) -> AgentResult {
    use crate::worker::WorkerPlugin;
    use std::collections::VecDeque;

    let bump = || *activity.lock().unwrap() = Instant::now();

    let plugin = match unsafe { WorkerPlugin::load(&config.path) } {
        Ok(p) => p,
        Err(e) => {
            let err = format!("failed to load worker plugin: {e}");
            error!(%id, "worker: {err}");
            return AgentResult { id, panics: 1, error: Some(err) };
        }
    };

    if let Some(meta) = plugin.meta() {
        info!(%id, actor = %meta.actor_name, path = %config.path.display(), "worker: loaded plugin");
    }

    // Pick a persistence strategy. Workers always get LocalCommit
    // when a data directory is configured, NoCommit otherwise;
    // replication strategies (CRDT, Raft) are not available to
    // workers since they live outside the deterministic universe.
    let mut strategy: Box<dyn crate::commit::CommitStrategy> =
        build_worker_strategy(&config, id);
    let saved_state = strategy.restore();

    let mut instance = match saved_state {
        Some(bytes) => {
            info!(%id, bytes = bytes.len(), "worker: restored state");
            plugin.load_state(&bytes)
        }
        None if config.init_args.is_empty() => plugin.create(),
        None => plugin.create_with_args(&config.init_args),
    };

    // Messages that arrived while we were waiting for a specific reply.
    // Bounded to prevent OOM from a misbehaving sender (see MAX_DEFERRED).
    let mut deferred: VecDeque<Envelope> = VecDeque::new();

    loop {
        if shutdown.load(Ordering::Relaxed) { break; }

        // Process up to a few invoke requests per iteration to avoid
        // starving the regular inbox.
        for _ in 0..4 {
            match invoke_rx.try_recv() {
                Ok(req) => {
                    bump();
                    let reply = dispatch_and_poll(&mut instance, &req.msg, &inbox, &outbox, id, &mut deferred);
                    // Workers don't yield — pack as DONE with no
                    // state so the caller's invoke_raw decodes
                    // `InvokeResult::Done { state: empty, reply }`.
                    let envelope = encode_invoke_envelope(
                        crate::actors::run::STATUS_DONE, &[], &reply,
                    );
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
                Ok(e) => { bump(); e }
                Err(mpsc::RecvTimeoutError::Timeout) => continue,
                Err(mpsc::RecvTimeoutError::Disconnected) => break,
            }
        };

        let reply = dispatch_and_poll(
            &mut instance, &envelope.payload,
            &inbox, &outbox, id, &mut deferred,
        );
        if !reply.is_empty() {
            let _ = outbox.send(Envelope {
                from: id,
                to: envelope.from,
                payload: reply,
            });
        }
        persist(strategy.as_mut(), &instance, id);
    }

    AgentResult { id, panics: 0, error: None }
}

/// Dispatch a message to a worker instance and poll to completion.
/// Returns the reply bytes (rkyv-encoded Value).
fn dispatch_and_poll(
    instance: &mut crate::worker::WorkerInstance<'_>,
    msg: &[u8],
    inbox: &mpsc::Receiver<Envelope>,
    outbox: &mpsc::Sender<Envelope>,
    worker_id: ServiceId,
    deferred: &mut std::collections::VecDeque<Envelope>,
) -> Vec<u8> {
    use crate::worker::{POLL_READY, POLL_PENDING};

    instance.dispatch_start(msg);

    loop {
        let result = instance.poll_once();
        match result.status {
            POLL_READY => {
                let reply = if !result.ptr.is_null() && result.len > 0 {
                    unsafe {
                        std::slice::from_raw_parts(result.ptr, result.len)
                    }.to_vec()
                } else {
                    Vec::new()
                };
                instance.free_reply(&result);
                return reply;
            }
            POLL_PENDING => {
                let effect = instance.pending_effect();
                let result = handle_effect(&effect, inbox, outbox, worker_id, deferred);
                instance.provide_result(&result);
            }
            _ => {
                error!(%worker_id, status = result.status, "worker: poll returned error");
                return Vec::new();
            }
        }
    }
}

/// Fulfill a host I/O effect. Dispatches by the effect tag byte.
fn handle_effect(
    effect: &[u8],
    inbox: &mpsc::Receiver<Envelope>,
    outbox: &mpsc::Sender<Envelope>,
    worker_id: ServiceId,
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
            if rest.len() < 4 { return Vec::new(); }
            let target_id = u32::from_le_bytes(rest[..4].try_into().unwrap());
            let payload = rest[4..].to_vec();
            let _ = outbox.send(Envelope {
                from: worker_id,
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
                    "vos: built without 'http' feature — EFFECT_FETCH unavailable"
                ).encode()
            }
        }
        other => {
            error!(%worker_id, tag = format!("{other:#04x}"), "worker: unknown effect tag");
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
    FetchResponse { status, headers, body }
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
fn build_worker_strategy(
    config: &WorkerConfig,
    id: ServiceId,
) -> Box<dyn crate::commit::CommitStrategy> {
    #[cfg(feature = "storage")]
    {
        if let Some(path) = config.db_path() {
            match crate::commit::LocalCommit::open(&path) {
                Ok(lc) => return Box::new(lc),
                Err(e) => warn!(%id, error = %e, "worker: failed to open storage; continuing without persistence"),
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
    instance: &crate::worker::WorkerInstance<'_>,
    id: ServiceId,
) {
    let bytes = instance.save_state();
    if let Err(e) = strategy.commit(&bytes) {
        warn!(%id, error = %e, "worker: failed to persist state");
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
                    warn!(from = %other.from, "worker: deferred queue full, dropping message");
                }
            }
            Err(_) => {
                warn!(target_id, "worker: ask timeout waiting for reply");
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
        assert!(rx.recv().is_err(), "tx should have been dropped without a send");
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
    fn worker_state_persists_across_restarts() {
        // EchoWorker has a `count` field that increments on each echo.
        // Run the worker, send a few messages, shut down. Restart with
        // the same redb path — the count should resume where it left off.
        let workspace = std::path::PathBuf::from(env!("CARGO_MANIFEST_DIR"))
            .parent().unwrap().parent().unwrap().to_path_buf();
        let profile = if cfg!(debug_assertions) { "debug" } else { "release" };
        let echo_path = workspace.join("target").join(profile).join("libecho_worker.so");
        if !echo_path.exists() {
            eprintln!("skipping: build echo-worker first");
            return;
        }

        // Use a temp data directory
        let data_dir = std::env::temp_dir().join(format!(
            "vos_test_persist_{}",
            std::process::id()
        ));
        let _ = std::fs::remove_dir_all(&data_dir);

        use crate::actors::value::Msg;
        use crate::actors::codec::Encode;
        let send_echo = |node: &VosNode, target: ServiceId, text: &str| {
            let msg = Msg::new("echo").with("text", text);
            let encoded = msg.encode();
            let mut payload = Vec::with_capacity(1 + encoded.len());
            payload.push(crate::actors::value::TAG_DYNAMIC);
            payload.extend_from_slice(&encoded);
            if let Some(tx) = node.routes.get(&target.0) {
                tx.send(Envelope { from: ServiceId(0), to: target, payload }).unwrap();
            }
        };

        // ── First run: send 2 echoes ────────────────────────────────
        {
            let mut node = VosNode::new();
            let id = node.register_worker(
                WorkerConfig::new(echo_path.clone()).persist(&data_dir)
            );
            send_echo(&node, id, "first");
            send_echo(&node, id, "second");
            node.run();
            let _ = node.collect();
        }

        // ── Second run: state should be restored, count starts at 2 ──
        {
            let mut node = VosNode::new();
            let id = node.register_worker(
                WorkerConfig::new(echo_path).persist(&data_dir)
            );
            send_echo(&node, id, "third");
            node.run();
            let _ = node.collect();
        }

        // Verify by opening the db directly and checking the persisted state
        use crate::commit::STATE_TABLE;
        let db_path = data_dir.join("workers").join("echo_worker.redb");
        let db = redb::Database::open(&db_path).expect("open db");
        let txn = db.begin_read().unwrap();
        let table = txn.open_table(STATE_TABLE).unwrap();
        let bytes = table.get("actor").unwrap().expect("state present").value().to_vec();

        // EchoWorker has a single u32 `count` field — rkyv packs it to
        // exactly 4 bytes. After 3 echoes, count = 3.
        assert_eq!(bytes.len(), 4, "EchoWorker state is one u32");
        let count = u32::from_le_bytes(bytes.try_into().unwrap());
        assert_eq!(count, 3, "expected 3 echoes total across both runs");

        let _ = std::fs::remove_dir_all(&data_dir);
    }

    #[test]
    #[cfg(feature = "http")]
    fn worker_does_http_fetch() {
        // Loads fetcher-worker and asks it to GET a URL.
        // Uses example.com which is stable and small. Skips on no network.
        let workspace = std::path::PathBuf::from(env!("CARGO_MANIFEST_DIR"))
            .parent().unwrap().parent().unwrap().to_path_buf();
        let profile = if cfg!(debug_assertions) { "debug" } else { "release" };
        let path = workspace.join("target").join(profile).join("libfetcher_worker.so");
        if !path.exists() {
            eprintln!("skipping worker_does_http_fetch: build fetcher-worker first");
            return;
        }

        let mut node = VosNode::new();
        let fetcher_id = node.register_worker(WorkerConfig::new(path));

        use crate::actors::value::Msg;
        use crate::actors::codec::Encode;
        let msg = Msg::new("status").with("url", "https://example.com");
        let encoded = msg.encode();
        let mut payload = Vec::with_capacity(1 + encoded.len());
        payload.push(crate::actors::value::TAG_DYNAMIC);
        payload.extend_from_slice(&encoded);

        if let Some(tx) = node.routes.get(&fetcher_id.0) {
            tx.send(Envelope { from: ServiceId(0), to: fetcher_id, payload }).unwrap();
        }

        node.run();
        let results = node.collect();
        for r in &results {
            assert_eq!(r.panics, 0, "fetcher worker {} panicked", r.id);
        }
    }

    #[test]
    fn worker_to_worker_ask() {
        // This test requires both echo-worker and proxy-worker to be built.
        // Run: cargo build -p echo-worker -p proxy-worker
        let workspace = std::path::PathBuf::from(env!("CARGO_MANIFEST_DIR"))
            .parent().unwrap().parent().unwrap().to_path_buf();
        let profile = if cfg!(debug_assertions) { "debug" } else { "release" };
        let echo_path = workspace.join("target").join(profile).join("libecho_worker.so");
        let proxy_path = workspace.join("target").join(profile).join("libproxy_worker.so");

        if !echo_path.exists() || !proxy_path.exists() {
            eprintln!("skipping worker_to_worker_ask: build workers first");
            return;
        }

        let mut node = VosNode::new();

        // Register echo worker — gets ServiceId 1
        let echo_id = node.register_worker(WorkerConfig::new(echo_path));

        // Build init args for proxy: target = echo's ServiceId
        use crate::actors::value::{Args, Msg};
        use crate::actors::codec::Encode;
        let proxy_args = Args::new().with("target", echo_id.0);
        let proxy_id = node.register_worker(
            WorkerConfig::with_args(proxy_path, &proxy_args),
        );

        // Send a "proxy" message to the proxy worker (no target arg now —
        // the proxy already knows its target from init args)
        let msg = Msg::new("proxy")
            .with("text", "hello via proxy");
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
            }).unwrap();
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
}
