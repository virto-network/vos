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
pub mod metadata;
mod run;

pub use actor::{Actor, Message};
pub mod context;
pub use context::{Context, PendingAsk};
pub use run::{Yield, RunResult, try_poll, service_code_hash, STATUS_DONE, STATUS_YIELDED};
#[cfg(feature = "service")]
pub use run::main_loop;
#[cfg(feature = "pvm")]
pub use run::refine_loop;

/// Unified entry point — resolves to `main_loop` (service) or `refine_loop` (guest).
/// The macro always generates calls to this so the same code works with either feature.
#[cfg(feature = "service")]
pub use run::main_loop as entry_loop;
#[cfg(all(feature = "pvm", not(feature = "service")))]
pub use run::refine_loop as entry_loop;

// --- Guest I/O macros and panic handler ---

#[cfg(feature = "pvm")]
mod guest_io;

#[cfg(feature = "pvm")]
mod guest_panic;
