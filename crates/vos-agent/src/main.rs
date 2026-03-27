//! VOS Agent — supervisor actor managing service registry and blob storage.
//!
//! The agent is a regular VOS actor compiled to RISC-V and transpiled to PVM,
//! running as PVM-in-PVM inside vosx. It manages the lifecycle of child
//! services: blob registration, service spawning, and message routing.
//!
//! ## Messages
//!
//! - `RegisterBlob(blob)` → stores blob in registry, returns code hash
//! - `SpawnService(code_hash)` → creates new service from registered blob
//! - `Route(target, payload)` → forwards payload to target service

use vos::{actor, messages};

/// Simple hash for blob identification.
/// Returns first 32 bytes of a basic xor-rotate hash.
fn hash_blob(data: &[u8]) -> [u8; 32] {
    let mut h = [0u8; 32];
    for (i, &byte) in data.iter().enumerate() {
        h[i % 32] ^= byte.wrapping_add(i as u8);
    }
    h
}

#[actor]
struct Agent {
    /// Number of registered blobs.
    blob_count: u32,
    /// Number of spawned services.
    service_count: u32,
}

#[messages]
impl Agent {
    fn new() -> Self {
        println!("agent: initialized");
        Agent {
            blob_count: 0,
            service_count: 0,
        }
    }

    /// Register a code blob. Stores it as a preimage and returns the hash.
    #[msg]
    async fn register_blob(&mut self, blob: Vec<u8>, ctx: &mut Context<Self>) {
        let hash = hash_blob(&blob);
        // Store blob keyed by hash so it can be retrieved for spawning
        ctx.store(&hash, &blob);
        self.blob_count += 1;
        println!("agent: registered blob #{} ({} bytes)", self.blob_count, blob.len());
    }

    /// Spawn a new service from a previously registered code hash.
    #[msg]
    async fn spawn_service(&mut self, code_hash: Vec<u8>, ctx: &mut Context<Self>) {
        if code_hash.len() == 32 {
            let mut hash = [0u8; 32];
            hash.copy_from_slice(&code_hash);
            ctx.spawn(hash);
            self.service_count += 1;
            println!("agent: spawned service #{}", self.service_count);
        } else {
            println!("agent: invalid code hash length");
        }
    }

    /// Route a payload to a target service.
    #[msg]
    async fn route(&mut self, target: u32, payload: Vec<u8>, ctx: &mut Context<Self>) {
        println!("agent: routing {} bytes to service {}", payload.len(), target);
        ctx.send(
            vos::actors::context::ServiceId(target),
            &payload,
        );
    }

    /// Report agent status.
    #[msg]
    async fn status(&self, _ctx: &mut Context<Self>) {
        println!(
            "agent: {} blob(s), {} service(s)",
            self.blob_count, self.service_count
        );
    }
}
