//! Supervisor actor — manages service registry and blob storage.
//!
//! The supervisor is a regular VOS actor that would be compiled to RISC-V
//! and transpiled to PVM, running as PVM-in-PVM. For now, vosx uses the
//! VosRuntime directly, but this source defines the supervisor's message
//! interface for when it becomes a cross-compiled actor.
//!
//! ## Messages
//!
//! - `RegisterBlob(blob)` → stores blob, returns code hash
//! - `SpawnService(code_hash)` → creates new service from blob
//! - `Route(target, payload)` → forwards payload to target service
//!
//! ## Future: cross-compiled supervisor
//!
//! ```ignore
//! use vos_actors::{Actor, messages};
//!
//! #[derive(Actor)]
//! #[derive(rkyv::Archive, rkyv::Serialize, rkyv::Deserialize)]
//! pub struct Supervisor {
//!     services: BTreeMap<ServiceId, ServiceState>,
//!     blob_registry: BTreeMap<[u8; 32], Vec<u8>>,
//! }
//!
//! #[messages]
//! impl Supervisor {
//!     fn new() -> Self { ... }
//!     #[msg] async fn register_blob(&mut self, blob: Vec<u8>, ctx: &mut Context<Self>) -> [u8; 32] { ... }
//!     #[msg] async fn spawn_service(&mut self, code_hash: [u8; 32], ctx: &mut Context<Self>) -> u32 { ... }
//!     #[msg] async fn route(&mut self, target: u32, payload: Vec<u8>, ctx: &mut Context<Self>) { ... }
//! }
//! ```
//!
//! When cross-compilation is set up, this will be built as a RISC-V binary,
//! transpiled to PVM, and embedded in vosx. The VosRuntime will load it as
//! service 0 (the supervisor service).
