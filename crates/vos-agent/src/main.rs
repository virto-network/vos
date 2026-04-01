//! VOS Agent — generic message router for child services.
//!
//! The agent is a regular VOS actor compiled to RISC-V, running as PVM-in-PVM
//! inside vosx. It owns the service table and routes messages to child services.
//!
//! ## Messages
//!
//! - `RegisterBlob(blob)` → stores blob, returns code hash
//! - `SpawnService(code_hash)` → creates new child service
//! - `Route(target, payload)` → queues message for target
//! - `Status` → report agent state

use vos::actors::context::ServiceId;
use vos::registry::{ServiceTable, ServiceState};
use vos::{agent, messages};

/// Max child services the agent can manage.
const MAX_SERVICES: usize = 32;

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
}

#[messages]
impl Agent {
    fn new() -> Self {
        println!("agent: initialized");
        Agent {
            blob_count: 0,
            services: ServiceTable::new(),
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

    /// Generic routing — agent doesn't interpret the payload.
    /// Queues a transfer to the target service.
    #[msg]
    async fn route(
        &mut self,
        target: u32,
        payload: Vec<u8>,
        ctx: &mut Context<Self>,
    ) -> Result<()> {
        let id = ServiceId(target);
        if self.services.get(id).is_none() {
            return Err(AgentError::ServiceNotFound(target));
        }
        ctx.tell(id, &payload);
        println!("agent: routed message to service {}", target);
        Ok(())
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
