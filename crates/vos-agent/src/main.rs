//! VOS Agent — supervisor actor that schedules child services.
//!
//! The agent is a regular VOS actor compiled to RISC-V, running as PVM-in-PVM
//! inside vosx. It owns the service registry and scheduler: blob registration,
//! service spawning, message routing, and cooperative tick-based execution.
//!
//! ## Messages
//!
//! - `RegisterBlob(blob)` → stores blob, returns code hash
//! - `SpawnService(code_hash)` → creates new child service
//! - `Route(target, payload)` → queues message for target, ticks scheduler
//! - `Tick` → advance all child services one step
//! - `Status` → report agent state

use vos::actors::context::ServiceId;
use vos::registry::{ServiceRegistry, ServiceState};
use vos::{agent, messages};

/// Max child services the agent can manage.
const MAX_SERVICES: usize = 32;
/// Mailbox capacity per child service.
const MAILBOX_CAP: usize = 16;

/// A pending message for a child service.
#[derive(Default)]
struct RawMsg {
    data: Vec<u8>,
}

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
    /// Transient per-invocation state — not persisted, rebuilt each invocation.
    #[rkyv(with = vos::rkyv::with::Skip)]
    services: ServiceRegistry<RawMsg, MAX_SERVICES, MAILBOX_CAP>,
}

#[messages]
impl Agent {
    fn new() -> Self {
        println!("agent: initialized");
        Agent {
            blob_count: 0,
            services: ServiceRegistry::new(),
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
    /// Registers it in the local service registry and tells the host to
    /// create the PVM instance.
    #[msg]
    async fn spawn_service(&mut self, code_hash: Vec<u8>, ctx: &mut Context<Self>) -> Result<()> {
        if code_hash.len() != 32 {
            return Err(AgentError::InvalidCodeHash {
                expected: 32,
                got: code_hash.len(),
            });
        }
        let id = self.services.register().ok_or(AgentError::RegistryFull)?;
        let mut hash = [0u8; 32];
        hash.copy_from_slice(&code_hash);
        ctx.spawn(hash);
        println!(
            "agent: spawned service {} (id={})",
            self.services.alive_count(),
            id.0
        );
        Ok(())
    }

    /// Route a message to a child service's local mailbox, then tick.
    #[msg]
    async fn route(
        &mut self,
        target: u32,
        payload: Vec<u8>,
        ctx: &mut Context<Self>,
    ) -> Result<()> {
        let id = ServiceId(target);
        let msg = RawMsg { data: payload };
        self.services
            .send(id, msg)
            .map_err(|_| AgentError::ServiceNotFound(target))?;
        println!("agent: queued message for service {}", target);
        self.tick_services(ctx);
        Ok(())
    }

    /// Advance all child services that have pending work.
    #[msg]
    async fn tick(&mut self, ctx: &mut Context<Self>) {
        self.tick_services(ctx);
    }

    /// Report agent status.
    #[msg]
    async fn report_status(&self, _ctx: &mut Context<Self>) {
        println!(
            "agent: {} blob(s), {} service(s) alive",
            self.blob_count,
            self.services.alive_count()
        );
    }
}

impl Agent {
    /// Tick all services: drain mailboxes and send pending messages
    /// to the host for PVM execution.
    fn tick_services(&mut self, ctx: &mut vos::Context<Agent>) {
        use vos::registry::Status;
        self.services.tick(|id, state, msg| match (state, msg) {
            (_, Some(raw)) => {
                ctx.send(id, &raw.data);
                println!(
                    "agent: delivering {} bytes to service {}",
                    raw.data.len(),
                    id.0
                );
                Status::Pending
            }
            (ServiceState::Suspended, None) => Status::Pending,
            _ => Status::Ready,
        });
    }
}
