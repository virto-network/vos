//! # vos-actors
//!
//! Minimal `no_std` actor framework for VOS. JAR-aligned lifecycle:
//! fresh PVM per invocation, state via storage, transfer-based messaging.
//!
//! Actors appear as long-running structs with methods. The framework
//! hides the fresh-PVM-per-invocation model: each invocation deserializes
//! state from storage, runs handlers, serializes state back, and halts.

#![no_std]
#![allow(async_fn_in_trait)]

extern crate alloc;

pub use rkyv;

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

#[cfg(feature = "vos-actors-macros")]
pub use vos_actors_macros::{Actor, messages};

// --- Guest I/O macros and panic handler ---

#[cfg(feature = "guest")]
mod guest_io;

#[cfg(feature = "guest")]
mod guest_panic;

/// Re-export for use by generated print!/println! macros.
#[cfg(feature = "guest")]
#[doc(hidden)]
pub mod __io {
    pub use vos_abi::guest::hostcalls::debug_write;
}
