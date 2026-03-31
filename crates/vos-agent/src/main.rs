//! VOS Agent — supervisor actor that schedules child services.
//!
//! The agent is a regular VOS actor compiled to RISC-V, running as PVM-in-PVM
//! inside vosx. It owns the service table and drives child services via the
//! YIELD-loop convergence pattern:
//!
//! 1. Process incoming messages (register_blob, spawn, route)
//! 2. Queue transfers to child services
//! 3. YIELD → host runs children, generates receipts
//! 4. FETCH receipts → update service states
//! 5. Route cross-service messages if any → loop back to YIELD
//! 6. Persist state and halt when converged
//!
//! ## Messages
//!
//! - `RegisterBlob(blob)` → stores blob, returns code hash
//! - `SpawnService(code_hash)` → creates new child service
//! - `Route(target, payload)` → queues message for target
//! - `Tick` → advance all child services one step
//! - `Status` → report agent state

use vos::actors::context::ServiceId;
use vos::registry::{ServiceTable, ServiceState};
use vos::{agent, messages};

/// Max child services the agent can manage.
const MAX_SERVICES: usize = 32;

/// Receipt size: 4 bytes service_id + 1 byte status.
const RECEIPT_SIZE: usize = 5;

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

    /// Route a message to a child service. Queues a transfer and triggers
    /// the YIELD-loop to flush it, run the child, and process receipts.
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
        ctx.send(id, &payload);
        println!("agent: queued message for service {}", target);
        // Flush effects so the YIELD-loop can process the transfer
        ctx.flush_effects();
        self.process_receipts();
        Ok(())
    }

    /// Advance: flush any pending transfers and process receipts.
    #[msg]
    async fn tick(&mut self, ctx: &mut Context<Self>) {
        ctx.flush_effects();
        self.process_receipts();
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
    /// YIELD-loop: yield to host, fetch receipts, update service states.
    /// Repeats until no more receipts (convergence).
    fn process_receipts(&mut self) {
        #[cfg(feature = "guest")]
        {
            use vos_abi::guest::ecall;
            use vos_abi::hostcall;

            let mut buf = [0u8; 4096];

            loop {
                // YIELD: tell host to process our queued transfers
                ecall::ecall0(hostcall::YIELD);

                // FETCH: get receipts from host
                let n = ecall::ecall2(
                    hostcall::FETCH,
                    buf.as_mut_ptr() as u64,
                    buf.len() as u64,
                );
                if n == 0 || n as usize > buf.len() {
                    break; // No receipts → converged
                }

                let receipt_data = &buf[..n as usize];
                // Parse 5-byte receipt chunks: [service_id: u32 LE, status: u8]
                for chunk in receipt_data.chunks_exact(RECEIPT_SIZE) {
                    let svc_id = u32::from_le_bytes([chunk[0], chunk[1], chunk[2], chunk[3]]);
                    let status = chunk[4];
                    let state = match status {
                        0 => ServiceState::Running,   // Halt → completed successfully
                        1 => ServiceState::Stopped,    // Panic
                        2 => ServiceState::Suspended,  // Out of gas
                        _ => ServiceState::Stopped,    // Page fault / other error
                    };
                    self.services.update_state(ServiceId(svc_id), state);
                    println!("agent: receipt svc={} status={}", svc_id, status);
                }
            }
        }
    }
}
