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
pub struct AgentResult {
    pub id: ServiceId,
    pub panics: u32,
}

/// Configuration for registering an agent in the node.
pub struct AgentConfig {
    /// PVM blob (already transpiled).
    pub blob: Vec<u8>,
    /// Initial payloads to deliver on startup.
    pub init_payloads: Vec<Vec<u8>>,
    /// Pre-populated storage entries (key, value).
    pub storage: Vec<(Vec<u8>, Vec<u8>)>,
}

/// Configuration for registering a native worker in the node.
pub struct WorkerConfig {
    /// Path to the worker `.so` file.
    pub path: std::path::PathBuf,
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

    let blob_idx = runtime.register_service_blob(config.blob);
    let svc_id = runtime.register_service_with_id(blob_idx, id);

    for (key, value) in &config.storage {
        runtime.storage.write(svc_id, key, value);
    }

    if config.init_payloads.is_empty() {
        runtime.send_to(svc_id, Vec::new());
    } else {
        for payload in config.init_payloads {
            runtime.send_to(svc_id, payload);
        }
    }

    loop {
        runtime.run_blocking();

        // Route outbound cross-service transfers through the node
        let external = runtime.drain_external_transfers(svc_id);
        let mut sent_any = false;
        for (target, memo) in external {
            sent_any = true;
            let _ = outbox.send(Envelope {
                from: id,
                to: target,
                payload: memo,
            });
        }

        // Drain inbox
        let mut received = false;
        while let Ok(envelope) = inbox.try_recv() {
            runtime.send_to(svc_id, envelope.payload);
            received = true;
        }

        if received { continue; }

        if sent_any {
            if let Ok(envelope) = inbox.recv_timeout(std::time::Duration::from_millis(50)) {
                runtime.send_to(svc_id, envelope.payload);
                continue;
            }
        }

        if !runtime.has_work() && !runtime.is_suspended(svc_id) {
            break;
        }

        match inbox.recv_timeout(std::time::Duration::from_millis(200)) {
            Ok(envelope) => {
                runtime.send_to(svc_id, envelope.payload);
            }
            Err(_) => break,
        }
    }

    AgentResult { id, panics: runtime.panics }
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
            eprintln!("worker {id}: failed to load: {e}");
            return AgentResult { id, panics: 1 };
        }
    };

    if let Some(meta) = plugin.meta() {
        eprintln!("worker {id}: loaded '{}' from {}", meta.actor_name, config.path.display());
    }

    let mut instance = plugin.create();
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
    }

    AgentResult { id, panics: 0 }
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
                if effect.len() >= 4 {
                    let target_id = u32::from_le_bytes(
                        effect[..4].try_into().unwrap()
                    );
                    let payload = effect[4..].to_vec();

                    let _ = outbox.send(Envelope {
                        from: worker_id,
                        to: ServiceId(target_id),
                        payload,
                    });

                    let reply = wait_for_reply(inbox, target_id, deferred);
                    instance.provide_result(&reply);
                } else {
                    instance.provide_result(&[]);
                }
            }
            _ => {
                eprintln!("worker {worker_id}: poll error {}", result.status);
                return Vec::new();
            }
        }
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
        let echo_id = node.register_worker(WorkerConfig { path: echo_path });
        // Register proxy worker — gets ServiceId 2
        let proxy_id = node.register_worker(WorkerConfig { path: proxy_path });

        // Send a "proxy" message to the proxy worker, telling it to ask the echo worker
        // Message format: TAG_DYNAMIC + rkyv-encoded Msg
        use crate::actors::value::Msg;
        use crate::actors::codec::Encode;
        let msg = Msg::new("proxy")
            .with("target", echo_id.0)
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
