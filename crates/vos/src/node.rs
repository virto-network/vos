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

use std::collections::HashMap;
use std::sync::atomic::{AtomicU16, Ordering};
use std::sync::mpsc;
use std::thread;

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
        }
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

    /// Derive the redb path for this agent from its data directory
    /// and service ID.
    #[allow(dead_code)] // only read when the `storage` feature is on
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

/// Synchronous invoke request to a worker.
struct InvokeRequest {
    msg: Vec<u8>,
    reply_tx: mpsc::Sender<Vec<u8>>,
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
    /// Map from worker ServiceId → synchronous invoke channel.
    /// Used by PVM agents' external_invoke handlers to dispatch
    /// directly to workers.
    worker_invoke: HashMap<u32, mpsc::Sender<InvokeRequest>>,
}

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
            worker_invoke: HashMap::new(),
        }
    }

    /// Allocate the next service ID on this node.
    fn alloc_id(&self) -> ServiceId {
        let local = self.next_local.fetch_add(1, Ordering::Relaxed);
        ServiceId::new(self.node_prefix, local)
    }

    /// Register an agent and return its service ID.
    /// The agent starts immediately on a new thread.
    pub fn register(&mut self, config: AgentConfig) -> ServiceId {
        let id = self.alloc_id();
        let (tx, rx) = mpsc::channel();
        let outbox = self.outbox_tx.clone();

        // Route this service ID to this agent's inbox
        self.routes.insert(id.0, tx.clone());

        // Clone worker invoke channels so the PVM agent can call workers
        let worker_invoke = self.worker_invoke.clone();

        let join = thread::spawn(move || {
            agent_thread(id, config, rx, outbox, worker_invoke)
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
        self.worker_invoke.insert(id.0, invoke_tx);

        let join = thread::spawn(move || {
            worker_thread(id, config, rx, invoke_rx, outbox)
        });

        self.agents.push(AgentHandle { join: Some(join) });
        id
    }

    /// Route messages until all agents are idle or finished.
    pub fn run(&mut self) {
        loop {
            match self.outbox_rx.recv_timeout(std::time::Duration::from_millis(100)) {
                Ok(envelope) => self.route(envelope),
                Err(mpsc::RecvTimeoutError::Timeout) => {
                    let all_done = self.agents.iter().all(|h| {
                        h.join.as_ref().map_or(true, |j| j.is_finished())
                    });
                    if all_done { break; }
                }
                Err(mpsc::RecvTimeoutError::Disconnected) => break,
            }
        }
    }

    /// Route a single envelope to its destination.
    fn route(&self, envelope: Envelope) {
        let target = envelope.to;

        // Local delivery: prefix matches or target is unscoped (prefix 0)
        if target.is_on_node(self.node_prefix) || target.is_local() {
            if let Some(tx) = self.routes.get(&target.0) {
                let _ = tx.send(envelope);
            } else {
                eprintln!("node: no route for {target}, dropping");
            }
        } else {
            // Future: forward to network layer
            eprintln!("node: no network layer, dropping remote target {target}");
        }
    }

    /// Collect results from all agent threads.
    pub fn collect(mut self) -> Vec<AgentResult> {
        drop(self.outbox_tx);
        drop(self.routes); // drop agent inboxes so threads can detect disconnect
        drop(self.worker_invoke); // drop invoke channels so worker threads can detect disconnect
        self.agents.iter_mut()
            .filter_map(|h| h.join.take().and_then(|j| j.join().ok()))
            .collect()
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
    config: AgentConfig,
    inbox: mpsc::Receiver<Envelope>,
    outbox: mpsc::Sender<Envelope>,
    worker_invoke: HashMap<u32, mpsc::Sender<InvokeRequest>>,
) -> AgentResult {
    use std::collections::VecDeque;
    use std::time::Duration;

    let mut runtime = VosRuntime::new();

    // Set up external invoke handler for PVM → worker calls.
    // When a PVM actor calls ctx.ask() on a worker ServiceId, this
    // handler dispatches synchronously via the invoke channel.
    if !worker_invoke.is_empty() {
        runtime.set_external_invoke(Box::new(move |target, msg| {
            let tx = worker_invoke.get(&target.0)?;
            let (reply_tx, reply_rx) = mpsc::channel();
            tx.send(InvokeRequest {
                msg: msg.to_vec(),
                reply_tx,
            }).ok()?;
            reply_rx.recv_timeout(std::time::Duration::from_secs(10)).ok()
        }));
    }

    let consistency = config.consistency;
    let recording_enabled = consistency == Consistency::Crdt;
    let mut strategy: Box<dyn crate::commit::CommitStrategy> =
        match build_agent_strategy(&config, id) {
            Ok(s) => s,
            Err(e) => {
                let err = format!("strategy build failed: {e}");
                eprintln!("agent {id}: {err}");
                return AgentResult { id, panics: 0, error: Some(err) };
            }
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
        eprintln!("agent {id}: restored {} bytes of state", state_bytes.len());
    } else if recording_enabled {
        match strategy.replay_logs() {
            Ok(logs) if !logs.is_empty() => {
                eprintln!("agent {id}: rebuilding state from {} DAG nodes", logs.len());
                for (i, log) in logs.into_iter().enumerate() {
                    let msg = log.msg.clone();
                    runtime.begin_replay(log);
                    runtime.send_to(svc_id, msg);
                    runtime.run_blocking();
                    // Drop any external transfers emitted during
                    // replay — those had their original effects at
                    // record time; we are not re-issuing them.
                    let _ = runtime.drain_external_transfers(svc_id);
                    let replay = runtime.finish_replay()
                        .expect("replay was active");
                    if !replay.is_complete() {
                        let err = format!(
                            "replay diverged at log #{i} (pos={}, exhausted={}); \
                             handler is non-deterministic",
                            replay.position(),
                            replay.was_exhausted(),
                        );
                        eprintln!("agent {id}: {err}");
                        return AgentResult {
                            id,
                            panics: runtime.panics,
                            error: Some(err),
                        };
                    }
                }
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
                        eprintln!("agent {id}: {err}");
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
                eprintln!("agent {id}: {err}");
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
    // fires — matches the pre-refactor behaviour.
    let mut pending: VecDeque<Vec<u8>> = config.init_payloads.into_iter().collect();
    if pending.is_empty() {
        pending.push_back(Vec::new());
    }

    let mut handled_any = false;
    let mut fatal_error: Option<String> = None;

    loop {
        // Prefer the local queue, otherwise wait on the inbox.
        let msg = if let Some(m) = pending.pop_front() {
            m
        } else if runtime.has_work() || runtime.is_suspended(svc_id) {
            // Residual work (self-messages, suspended continuation)
            // — drive the runtime and loop, no new external event.
            if let Err(e) = dispatch_once(&mut runtime, svc_id, &outbox, id, None,
                strategy.as_mut(), recording_enabled) {
                fatal_error = Some(format!("commit failed during residual work: {e}"));
                break;
            }
            continue;
        } else {
            match inbox.recv_timeout(Duration::from_millis(200)) {
                Ok(env) => env.payload,
                Err(mpsc::RecvTimeoutError::Timeout) => {
                    if handled_any { break; }
                    continue;
                }
                Err(mpsc::RecvTimeoutError::Disconnected) => break,
            }
        };
        handled_any = true;
        if let Err(e) = dispatch_once(&mut runtime, svc_id, &outbox, id, Some(msg),
            strategy.as_mut(), recording_enabled) {
            fatal_error = Some(format!("commit failed: {e}"));
            break;
        }
    }

    if let Some(err) = &fatal_error {
        eprintln!("agent {id}: {err}");
    }
    AgentResult { id, panics: runtime.panics, error: fatal_error }
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
) -> Result<Box<dyn crate::commit::CommitStrategy>, crate::commit::CommitError> {
    #[cfg(feature = "storage")]
    {
        let _ = id;
        match config.consistency {
            Consistency::Ephemeral => Ok(Box::new(crate::commit::NoCommit)),
            Consistency::Local => {
                let path = config.db_path(id).ok_or_else(|| {
                    crate::commit::CommitError::Backend(
                        "Local consistency requires data_dir on AgentConfig".into(),
                    )
                })?;
                Ok(Box::new(crate::commit::LocalCommit::open(&path)?))
            }
            Consistency::Crdt => {
                let path = config.db_path(id).ok_or_else(|| {
                    crate::commit::CommitError::Backend(
                        "Crdt consistency requires data_dir on AgentConfig".into(),
                    )
                })?;
                Ok(Box::new(crate::commit::CrdtCommit::open(&path)?))
            }
        }
    }
    #[cfg(not(feature = "storage"))]
    {
        let _ = (config, id);
        match config.consistency {
            Consistency::Ephemeral => Ok(Box::new(crate::commit::NoCommit)),
            other => Err(crate::commit::CommitError::Backend(format!(
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
) -> AgentResult {
    use crate::worker::WorkerPlugin;
    use std::collections::VecDeque;
    use std::time::Duration;

    let plugin = match unsafe { WorkerPlugin::load(&config.path) } {
        Ok(p) => p,
        Err(e) => {
            let err = format!("failed to load worker plugin: {e}");
            eprintln!("worker {id}: {err}");
            return AgentResult { id, panics: 1, error: Some(err) };
        }
    };

    if let Some(meta) = plugin.meta() {
        eprintln!("worker {id}: loaded '{}' from {}", meta.actor_name, config.path.display());
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
            eprintln!("worker {id}: restored {} bytes of state", bytes.len());
            plugin.load_state(&bytes)
        }
        None if config.init_args.is_empty() => plugin.create(),
        None => plugin.create_with_args(&config.init_args),
    };

    // Messages that arrived while we were waiting for a specific reply.
    // Bounded to prevent OOM from a misbehaving sender (see MAX_DEFERRED).
    let mut deferred: VecDeque<Envelope> = VecDeque::new();
    let mut handled_any = false;

    loop {
        // Process up to a few invoke requests per iteration to avoid
        // starving the regular inbox.
        for _ in 0..4 {
            match invoke_rx.try_recv() {
                Ok(req) => {
                    handled_any = true;
                    let reply = dispatch_and_poll(&mut instance, &req.msg, &inbox, &outbox, id, &mut deferred);
                    let _ = req.reply_tx.send(reply);
                    persist(strategy.as_mut(), &instance, id);
                }
                Err(_) => break,
            }
        }

        // Take next message: deferred first, then inbox
        let envelope = if let Some(e) = deferred.pop_front() {
            e
        } else {
            match inbox.recv_timeout(Duration::from_millis(200)) {
                Ok(e) => e,
                Err(mpsc::RecvTimeoutError::Timeout) => {
                    // Exit if we've handled at least one message and
                    // there's nothing left. Otherwise keep waiting for
                    // the first message.
                    if handled_any { break; }
                    continue;
                }
                Err(mpsc::RecvTimeoutError::Disconnected) => break,
            }
        };
        handled_any = true;

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
                eprintln!("worker {worker_id}: poll error {}", result.status);
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
            eprintln!("worker {worker_id}: unknown effect tag 0x{other:02x}");
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
                Err(e) => eprintln!("worker {id}: failed to open storage: {e}"),
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
        eprintln!("worker {id}: failed to persist state: {e}");
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
                    eprintln!("worker: deferred queue full, dropping message from {}", other.from);
                }
            }
            Err(_) => {
                eprintln!("worker: ask timeout waiting for reply from svc:{target_id}");
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
