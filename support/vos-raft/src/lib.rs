//! # vos-raft
//!
//! Raft consensus as a protocol core without I/O, on `core + alloc`.
//!
//! ## Concepts
//!
//! - [`core::Core`]: one replica of one group as a state machine. The host
//!   feeds it events (messages, proposals, ticks, write completions) and
//!   carries out the actions it returns (ordered writes, messages, loads,
//!   commit notifications, answers). It reads no clock and does no I/O, so
//!   one host can drive thousands of groups.
//! - [`Message`]: the one-way protocol messages between replicas.
//! - [`sim`]: groups of cores over a simulated network and stores, checked
//!   for Raft's safety properties under faults.
//!
//! ## A group of one
//!
//! ```
//! use vos_raft::core::{Action, Core, Recovered};
//! use vos_raft::{Config, Role};
//!
//! // A lone member campaigns at its first tick, and leads once its term
//! // and vote are durable.
//! let mut core = Core::new(Config::new(1u16, vec![1]), Recovered::default(), 0, 7);
//! core.tick(0);
//! for action in core.take_actions() {
//!     if let Action::Write(write) = action {
//!         // The host writes it to its store, then reports it.
//!         core.durable(write.seq);
//!         core.entries_durable(write.seq);
//!     }
//! }
//! assert_eq!(core.role(), Role::Leader);
//! ```
//!
//! `tests/core.rs` drives the core write by write.

#![no_std]

extern crate alloc;

pub mod config;
pub mod core;
pub mod log_entry;
mod log_view;
pub mod message;
pub mod meta;
pub mod pair;
mod random;
pub mod role;
pub mod sim;

pub use crate::core::ActiveConfigRecord;
pub use config::{Config, NodeId};
pub use log_entry::{EntryKind, LogEntry};
pub use message::{AppendResult, Message};
pub use meta::Meta;
pub use role::Role;
