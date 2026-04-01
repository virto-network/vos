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
pub use run::{Yield, RunResult, try_poll};
#[cfg(feature = "guest")]
pub use run::main_loop;

// --- Guest I/O macros and panic handler ---

#[cfg(feature = "guest")]
mod guest_io;

#[cfg(feature = "guest")]
mod guest_panic;
