//! Minimal actor framework for VOS. JAR-aligned lifecycle:
//! fresh PVM per invocation, state via storage, transfer-based messaging.
//!
//! Actors appear as long-running structs with methods. The framework
//! hides the fresh-PVM-per-invocation model: each invocation deserializes
//! state from storage, runs handlers, serializes state back, and halts.

mod actor;
mod executor;
mod mailbox;
pub mod metadata;
mod run;

pub use actor::{Actor, Message};
pub mod context;
pub use context::Context;
pub use executor::{Executor, Progress};
pub use mailbox::Mailbox;
pub use run::{Yield, block_on};
#[cfg(feature = "guest")]
pub use run::main_loop;

// --- Guest I/O macros and panic handler ---

#[cfg(feature = "guest")]
mod guest_io;

#[cfg(feature = "guest")]
mod guest_panic;
