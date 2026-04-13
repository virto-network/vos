//! Multi-agent node — runs multiple services on separate threads.
//!
//! Each agent/service gets its own [`VosRuntime`] on a dedicated thread.
//! Cross-agent communication uses channels that map to JAM's
//! cross-service transfers: when service A transfers to service B, the
//! message is routed through the node's mailbox system to B's runtime.
//!
//! This is preparation for Kunekt's consensus layer where nodes sync
//! state via merkle-CRDTs instead of blockchain consensus.

use std::collections::HashMap;
use std::string::String;
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
    /// Send work items to this agent's runtime.
    tx: mpsc::Sender<Envelope>,
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

/// Pre-populated package registry for bootstrapping.
/// Agents can resolve packages by name+version from this.
#[derive(Default)]
pub struct HostRegistry {
    packages: HashMap<(String, String), Vec<u8>>,
}

impl HostRegistry {
    pub fn new() -> Self {
        Self::default()
    }

    /// Register a code blob under a name and version.
    pub fn publish(&mut self, name: &str, version: &str, blob: Vec<u8>) {
        self.packages.insert((name.to_string(), version.to_string()), blob);
    }

    /// Look up a code blob by name and version.
    pub fn resolve(&self, name: &str, version: &str) -> Option<&Vec<u8>> {
        self.packages.get(&(name.to_string(), version.to_string()))
    }
}

/// A multi-agent VOS node.
///
/// Each agent runs on its own thread with its own `VosRuntime`.
/// Cross-agent transfers are routed through a shared channel.
pub struct VosNode {
    agents: HashMap<u32, AgentHandle>,
    /// Outbound channel — agents send cross-service transfers here.
    outbox_tx: mpsc::Sender<Envelope>,
    /// The node reads from this to route messages.
    outbox_rx: mpsc::Receiver<Envelope>,
    next_id: u32,
    /// Host-side package registry for bootstrapping.
    pub registry: HostRegistry,
}

impl VosNode {
    pub fn new() -> Self {
        let (outbox_tx, outbox_rx) = mpsc::channel();
        Self {
            agents: HashMap::new(),
            outbox_tx,
            outbox_rx,
            next_id: 1,
            registry: HostRegistry::new(),
        }
    }

    /// Register an agent and return its service ID.
    /// The agent is not started until [`run`] is called.
    pub fn register(&mut self, config: AgentConfig) -> ServiceId {
        let id = self.next_id;
        self.next_id += 1;

        let (tx, rx) = mpsc::channel();
        let outbox = self.outbox_tx.clone();
        let svc_id = ServiceId(id);

        let join = thread::spawn(move || {
            agent_thread(svc_id, config, rx, outbox)
        });

        self.agents.insert(id, AgentHandle {
            tx,
            join: Some(join),
        });

        svc_id
    }

    /// Run the node: deliver initial payloads, then route cross-agent
    /// messages until all agents are idle or finished.
    pub fn run(&mut self) {
        // Route messages until no more activity.
        // Use a timeout-based approach: if no message arrives within
        // a short window and all agents are done, stop.
        loop {
            match self.outbox_rx.recv_timeout(std::time::Duration::from_millis(100)) {
                Ok(envelope) => {
                    if let Some(handle) = self.agents.get(&envelope.to.0) {
                        let _ = handle.tx.send(envelope);
                    }
                }
                Err(mpsc::RecvTimeoutError::Timeout) => {
                    // Check if all agent threads have finished
                    let all_done = self.agents.values().all(|h| {
                        h.join.as_ref().map_or(true, |j| j.is_finished())
                    });
                    if all_done {
                        break;
                    }
                }
                Err(mpsc::RecvTimeoutError::Disconnected) => break,
            }
        }
    }

    /// Collect results from all agent threads.
    pub fn collect(mut self) -> Vec<AgentResult> {
        // Drop senders so agent threads can detect disconnect
        drop(self.outbox_tx);
        self.agents.values_mut()
            .filter_map(|h| {
                h.join.take().and_then(|j| j.join().ok())
            })
            .collect()
    }
}

impl Default for VosNode {
    fn default() -> Self {
        Self::new()
    }
}

/// The main loop for one agent's thread.
fn agent_thread(
    id: ServiceId,
    config: AgentConfig,
    inbox: mpsc::Receiver<Envelope>,
    outbox: mpsc::Sender<Envelope>,
) -> AgentResult {
    let mut runtime = VosRuntime::new();

    let blob_idx = runtime.register_service_blob(config.blob);
    let svc_id = runtime.register_service(blob_idx);

    // Write pre-populated storage
    for (key, value) in &config.storage {
        runtime.storage.write(svc_id, key, value);
    }

    // Deliver initial payloads
    if config.init_payloads.is_empty() {
        runtime.send_to(svc_id, Vec::new());
    } else {
        for payload in config.init_payloads {
            runtime.send_to(svc_id, payload);
        }
    }

    loop {
        // Run until no more internal work
        runtime.run_blocking();

        // Drain cross-service transfers from the runtime and route
        // them through the node's outbox.
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

        // Check for incoming messages (non-blocking)
        let mut received = false;
        while let Ok(envelope) = inbox.try_recv() {
            runtime.send_to(svc_id, envelope.payload);
            received = true;
        }

        if received {
            continue; // Process new messages
        }

        if sent_any {
            // Wait briefly for responses
            match inbox.recv_timeout(std::time::Duration::from_millis(50)) {
                Ok(envelope) => {
                    runtime.send_to(svc_id, envelope.payload);
                    continue;
                }
                Err(_) => {}
            }
        }

        // No more work — check if suspended or done
        if !runtime.has_work() && !runtime.is_suspended(svc_id) {
            break;
        }

        // Brief wait for new messages before declaring done
        match inbox.recv_timeout(std::time::Duration::from_millis(200)) {
            Ok(envelope) => {
                runtime.send_to(svc_id, envelope.payload);
            }
            Err(_) => break,
        }
    }

    AgentResult {
        id,
        panics: runtime.panics,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn node_lifecycle_basic() {
        // Verify the node can be created and run with no agents.
        let mut node = VosNode::new();
        node.run();
        let results = node.collect();
        assert!(results.is_empty());
    }
}
