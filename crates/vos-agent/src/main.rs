//! VOS Agent — scheduler that drives child services via invoke().
//!
//! The agent owns the service table and scheduling loop. When a message
//! is routed to a child, the agent invokes it synchronously, running it
//! to its next `.await` point. Yielded services are re-invoked on the
//! next tick. This is the only place scheduling policy lives — fork
//! this crate to customize prioritization, time-slicing, etc.
//!
//! ## Messages
//!
//! - `RegisterBlob(blob)` → stores blob, returns code hash
//! - `SpawnService(code_hash)` → creates new child service
//! - `Route(target, payload)` → invoke child, drive to next yield
//! - `Tick` → continue processing yielded services
//! - `Status` → report agent state

use vos::actors::context::ServiceId;
use vos::registry::{ServiceTable, ServiceState};
use vos::{agent, messages, service_code_hash, STATUS_YIELDED};

/// Max child services the agent can manage.
const MAX_SERVICES: usize = 32;

/// Max invoke iterations per tick (time-slice budget).
const MAX_ROUNDS_PER_TICK: usize = 16;

/// Simple hash for blob identification.
fn hash_blob(data: &[u8]) -> [u8; 32] {
    let mut h = [0u8; 32];
    for (i, &byte) in data.iter().enumerate() {
        h[i % 32] ^= byte.wrapping_add(i as u8);
    }
    h
}

#[derive(Debug)]
enum AgentError {
    InvalidCodeHash { expected: usize, got: usize },
    RegistryFull,
    ServiceNotFound(u32),
}

#[agent(error = AgentError)]
struct Agent {
    blob_count: u32,
    /// Persistent service metadata — survives across invocations.
    services: ServiceTable<MAX_SERVICES>,
    /// Queue of (service_id, last_message) for yielded services awaiting re-invocation.
    run_queue: Vec<(u32, Vec<u8>)>,
}

#[messages]
impl Agent {
    fn new() -> Self {
        println!("agent: initialized");
        Agent {
            blob_count: 0,
            services: ServiceTable::new(),
            run_queue: Vec::new(),
        }
    }

    /// Register a code blob. Stores it as a preimage keyed by hash.
    #[msg]
    async fn register_blob(&mut self, blob: Vec<u8>, ctx: &mut Context<Self>) {
        let hash = hash_blob(&blob);
        ctx.store(&hash, &blob);
        self.blob_count += 1;
        println!(
            "agent: registered blob #{} ({} bytes)",
            self.blob_count,
            blob.len()
        );
    }

    /// Spawn a new child service from a previously registered code hash.
    #[msg]
    async fn spawn_service(&mut self, code_hash: Vec<u8>, ctx: &mut Context<Self>) -> Result<()> {
        if code_hash.len() != 32 {
            return Err(AgentError::InvalidCodeHash {
                expected: 32,
                got: code_hash.len(),
            });
        }
        let mut hash = [0u8; 32];
        hash.copy_from_slice(&code_hash);
        let id = self.services.register(hash).ok_or(AgentError::RegistryFull)?;
        ctx.spawn(hash);
        self.services.update_state(id, ServiceState::Running);
        println!(
            "agent: spawned service {} (id={})",
            self.services.alive_count(),
            id.0
        );
        Ok(())
    }

    /// Route a message to a child service. The agent invokes the child
    /// synchronously, driving it to its next yield point. If the child
    /// yields, it's queued for re-invocation on the next tick.
    #[msg]
    async fn route(
        &mut self,
        target: u32,
        payload: Vec<u8>,
        ctx: &mut Context<Self>,
    ) -> Result<()> {
        let svc_id = ServiceId(target);
        if self.services.get(svc_id).is_none() {
            return Err(AgentError::ServiceNotFound(target));
        }

        let status = Self::invoke_child(target, &payload);
        if status == STATUS_YIELDED {
            self.run_queue.push((target, payload));
            self.services.update_state(svc_id, ServiceState::Suspended);
        }

        self.maybe_schedule_tick(ctx);
        println!("agent: routed message to service {}", target);
        Ok(())
    }

    /// Process the run queue: re-invoke yielded services with their
    /// last message. Time-sliced to MAX_ROUNDS_PER_TICK iterations.
    #[msg]
    async fn tick(&mut self, ctx: &mut Context<Self>) {
        let queue: Vec<_> = self.run_queue.drain(..).collect();
        let mut rounds = 0;

        for (svc_id, msg) in queue {
            let status = Self::invoke_child(svc_id, &msg);
            if status == STATUS_YIELDED {
                self.run_queue.push((svc_id, msg));
            } else {
                self.services.update_state(ServiceId(svc_id), ServiceState::Running);
            }

            rounds += 1;
            if rounds >= MAX_ROUNDS_PER_TICK {
                break;
            }
        }

        self.maybe_schedule_tick(ctx);
    }

    /// Report agent status.
    #[msg]
    async fn report_status(&self, _ctx: &mut Context<Self>) {
        println!(
            "agent: {} blob(s), {} service(s) alive, {} in run queue",
            self.blob_count,
            self.services.alive_count(),
            self.run_queue.len(),
        );
    }

    // --- Internal helpers (not messages) ---

    /// Invoke a child service synchronously. Returns the exit status byte.
    fn invoke_child(svc_id: u32, payload: &[u8]) -> u8 {
        let hash = service_code_hash(svc_id);
        let mut output = [0u8; 64];
        let n = vos::hostcalls::invoke(&hash, payload, 0, &mut output);
        if n > 0 { output[0] } else { 0 }
    }

    /// If the run queue has pending work, send ourselves a Tick message
    /// so the runtime re-invokes us next round.
    fn maybe_schedule_tick(&self, ctx: &mut Context<Self>) {
        if !self.run_queue.is_empty() {
            let tick_msg = AgentMsg::Tick(Tick);
            ctx.tell(ctx.id(), &tick_msg.to_bytes());
        }
    }
}
