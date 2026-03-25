//! # pvx-actors
//!
//! Minimal `no_std`/`no_alloc` actor framework for cooperative async PVM programs.
//!
//! Each PVM program is an actor. The host runs multiple programs cooperatively
//! in a single-threaded environment by calling [`poll`] which drives all actors
//! forward at their await/yield points.
//!
//! ## Design
//!
//! - **1 PVM program = 1 actor**: each actor is an async state machine
//! - **Cooperative scheduling**: actors yield at `.await` points, the host
//!   calls `poll` to drive progress
//! - **No allocator required**: messages flow through fixed-capacity channels
//! - **No runtime**: the host *is* the runtime via the `poll` function

#![no_std]
// Single-threaded PVM execution — no Send bounds needed on async trait futures.
#![allow(async_fn_in_trait)]

extern crate alloc;

pub use rkyv;

mod actor;
mod context;
mod executor;
mod mailbox;
mod run;

pub use actor::{Actor, Message};
pub use context::{ActorId, Context};
pub use executor::{Executor, Progress};
pub use mailbox::Mailbox;
pub use run::{Yield, block_on};

#[cfg(feature = "pvx-actors-macros")]
pub use pvx_actors_macros::{Actor, messages};
