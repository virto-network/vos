//! Supervisor / VOS Agent — manages service registry and blob storage.
//!
//! The agent is a regular VOS actor compiled to RISC-V and transpiled to PVM,
//! running as PVM-in-PVM inside vosx. See `examples/vos-agent/` for the
//! implementation.
//!
//! ## Messages
//!
//! - `RegisterBlob(blob)` → stores blob in registry, returns code hash
//! - `SpawnService(code_hash)` → creates new service from registered blob
//! - `Route(target, payload)` → forwards payload to target service
//! - `Status` → reports agent status
//!
//! ## Integration with vosx
//!
//! When cross-compilation is set up, vosx loads the pre-built agent blob as
//! service 0. The agent manages child services: blob registration, spawning,
//! and message routing.
//!
//! ```ignore
//! use vos::{Actor, messages};
//!
//! #[derive(Actor)]
//! struct Agent {
//!     blob_count: u32,
//!     service_count: u32,
//! }
//!
//! #[messages]
//! impl Agent {
//!     fn new() -> Self { ... }
//!     #[msg] async fn register_blob(&mut self, blob: Vec<u8>, ctx: &mut Context<Self>) { ... }
//!     #[msg] async fn spawn_service(&mut self, code_hash: Vec<u8>, ctx: &mut Context<Self>) { ... }
//!     #[msg] async fn route(&mut self, target: u32, payload: Vec<u8>, ctx: &mut Context<Self>) { ... }
//!     #[msg] async fn status(&self, _ctx: &mut Context<Self>) { ... }
//! }
//! ```
