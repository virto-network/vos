//! Minimal actor framework for VOS. JAR-aligned lifecycle:
//! fresh PVM per invocation, state via storage, transfer-based messaging.
//!
//! Actors appear as long-running structs with methods. The framework
//! hides the fresh-PVM-per-invocation model: each invocation deserializes
//! state from storage, runs handlers, serializes state back, and halts.
//!
//! ## Cooperative primitives
//!
//! - `ctx.tell(target, payload)` — fire-and-forget message (queues transfer)
//! - `ctx.ask(target, payload)` — synchronous query (suspends until result)
//! - `ctx.yield_now()` — checkpoint state, self-schedule, halt
//! - `ctx.sleep(n)` — checkpoint state, sleep N ticks, halt

mod actor;
pub mod codec;
pub mod init;
pub mod lifecycle;
pub mod metadata;
pub mod run;
pub mod value;

pub use actor::{Actor, Message};
pub use codec::{Encode, Decode};
pub mod context;
pub use context::Context;
pub use run::{Yield, Ask, RunResult, try_poll, service_code_hash, STATUS_DONE, STATUS_YIELDED, STATUS_PANICKED, STATUS_NOT_FOUND, STATUS_OOG};
pub use value::InvokeError;
#[cfg(feature = "service")]
pub use run::{run_accumulate, run_refine_service, run_accumulate_service};
#[cfg(feature = "pvm")]
pub use run::run_refine;

/// Unified entry point — resolves to `run_accumulate` (service) or `run_refine` (guest).
/// The macro generates calls to this so downstream crates don't need feature cfgs.
#[cfg(feature = "service")]
pub fn run_entry<A: Actor>() { run::run_accumulate::<A>() }
#[cfg(all(feature = "pvm", not(feature = "service")))]
pub fn run_entry<A: Actor>() { run::run_refine::<A>() }

/// JAM refine entry (PC=0). On services, runs the pure refine body and
/// halts with a `RefinePayload`. On invoked actors (no `service` feature),
/// falls through to the existing `run_refine`.
#[cfg(feature = "service")]
pub fn run_refine_entry<A: Actor>() { run::run_refine_service::<A>() }
#[cfg(all(feature = "pvm", not(feature = "service")))]
pub fn run_refine_entry<A: Actor>() { run::run_refine::<A>() }

/// JAM accumulate entry (PC=5). Services replay refine effects via
/// real hostcalls. Not meaningful for invoked actors.
#[cfg(feature = "service")]
pub fn run_accumulate_entry<A: Actor>() { run::run_accumulate_service::<A>() }
#[cfg(all(feature = "pvm", not(feature = "service")))]
pub fn run_accumulate_entry<A: Actor>() { /* no-op for invoked actors */ }

// --- Guest I/O macros and panic handler ---

#[cfg(feature = "pvm")]
mod guest_io;

#[cfg(feature = "pvm")]
mod guest_panic;
