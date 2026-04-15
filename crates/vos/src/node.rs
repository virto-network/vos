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

        let join = thread::spawn(move || {
            agent_thread(id, config, rx, outbox)
        });

        self.agents.push(AgentHandle { join: Some(join) });
        id
    }

    /// Register a native worker and return its service ID.
    /// The worker starts immediately on a new thread.
    pub fn register_worker(&mut self, config: WorkerConfig) -> ServiceId {
        let id = self.alloc_id();
        let (tx, rx) = mpsc::channel();
        let outbox = self.outbox_tx.clone();

        self.routes.insert(id.0, tx);

        let join = thread::spawn(move || {
            worker_thread(id, config, rx, outbox)
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
) -> AgentResult {
    let mut runtime = VosRuntime::new();

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

// ── Worker thread ────────────────────────────────────────────────────

fn worker_thread(
    id: ServiceId,
    config: WorkerConfig,
    inbox: mpsc::Receiver<Envelope>,
    outbox: mpsc::Sender<Envelope>,
) -> AgentResult {
    use crate::worker::{WorkerPlugin, POLL_READY, POLL_PENDING};

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

    loop {
        // Wait for a message
        let envelope = match inbox.recv_timeout(std::time::Duration::from_millis(200)) {
            Ok(e) => e,
            Err(mpsc::RecvTimeoutError::Timeout) => continue,
            Err(mpsc::RecvTimeoutError::Disconnected) => break,
        };

        // Start dispatch
        instance.dispatch_start(&envelope.payload);

        // Poll loop with host I/O fulfillment
        loop {
            let result = instance.poll_once();
            match result.status {
                POLL_READY => {
                    // If there's a reply, send it back to the caller
                    if !result.ptr.is_null() && result.len > 0 {
                        let reply_bytes = unsafe {
                            std::slice::from_raw_parts(result.ptr, result.len)
                        }.to_vec();
                        instance.free_reply(&result);

                        // Send reply as a transfer back to the sender
                        let _ = outbox.send(Envelope {
                            from: id,
                            to: envelope.from,
                            payload: reply_bytes,
                        });
                    } else {
                        instance.free_reply(&result);
                    }
                    break;
                }
                POLL_PENDING => {
                    // Read pending host effect
                    let effect = instance.pending_effect();
                    if effect.len() >= 4 {
                        // Protocol: [target:u32 LE][payload...]
                        // This is an ask/tell to another service
                        let target_id = u32::from_le_bytes(
                            effect[..4].try_into().unwrap()
                        );
                        let payload = effect[4..].to_vec();

                        // Route via outbox and wait for reply
                        // For now: send and provide empty result
                        // TODO: implement request-reply correlation
                        let _ = outbox.send(Envelope {
                            from: id,
                            to: ServiceId(target_id),
                            payload,
                        });
                        // Provide empty result to unblock the handler
                        instance.provide_result(&[]);
                    } else {
                        // Unknown effect, provide empty result
                        instance.provide_result(&[]);
                    }
                }
                _ => {
                    eprintln!("worker {id}: poll error {}", result.status);
                    break;
                }
            }
        }

        // Drain any additional queued messages
        while let Ok(next) = inbox.try_recv() {
            instance.dispatch_start(&next.payload);
            // Simple poll to completion for queued messages
            loop {
                let r = instance.poll_once();
                if r.status != POLL_PENDING {
                    instance.free_reply(&r);
                    break;
                }
                instance.provide_result(&[]);
            }
        }
    }

    AgentResult { id, panics: 0 }
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
    fn display_format() {
        assert_eq!(format!("{}", ServiceId(3)), "svc:3");
        assert_eq!(format!("{}", ServiceId::new(0x00A3, 5)), "svc:00a3:5");
        assert_eq!(format!("{}", ServiceId::REGISTRY), "svc:0");
    }
}
