//! # vos-raft
//!
//! Raft consensus as a protocol core without I/O, plus a driver that runs
//! one replica of it.
//!
//! ## Concepts
//!
//! - [`core::Core`]: one replica of one group as a state machine. The host
//!   feeds it events (messages, proposals, ticks, write completions) and
//!   carries out the actions it returns (ordered writes, messages, loads,
//!   commit notifications, answers). It reads no clock and does no I/O, so
//!   one host can drive thousands of groups. `no_std + alloc`.
//! - [`Message`]: the one-way protocol messages between replicas.
//! - [`Worker`] / [`WorkerHandle`] (std): a driver for one replica, with a
//!   [`Storage`], a [`Transport`], a [`Clock`] and an [`ApplySink`]; it
//!   also streams snapshots, which the core leaves to its host.
//!
//! ## Std-feature quickstart
//!
//! ```
//! use std::sync::Arc;
//! use vos_raft::{Config, Envelope, MemStorage, Transport, Worker};
//!
//! struct NoopT;
//! impl Transport<u16> for NoopT {
//!     fn send(&self, _from: u16, _to: u16, _envelope: Envelope<u16>) {}
//! }
//! // A one-member group elects itself.
//! let mut cfg = Config::new(0xAAAA, vec![0xAAAA], [0xC0; 32]);
//! cfg.election_timeout_ms = (10, 30);
//! let worker = Worker::spawn(MemStorage::<u16>::new(), Arc::new(NoopT), cfg, None);
//! worker.shutdown();
//! ```

#![cfg_attr(not(feature = "std"), no_std)]

extern crate alloc;

pub mod clock;
pub mod config;
pub mod core;
pub mod log_entry;
mod log_view;
pub mod message;
pub mod meta;
pub mod role;
pub mod rpc;
#[cfg(feature = "std")]
pub mod sim;
pub mod storage;
pub mod transport;

#[cfg(test)]
pub(crate) mod testutil;

#[cfg(feature = "std")]
pub mod worker;

#[cfg(feature = "tokio")]
pub use clock::TokioClock;
pub use clock::{ApplySink, Clock, Rng};
#[cfg(feature = "std")]
pub use clock::{StdClock, StdRng};
pub use config::{Config, NodeId};
pub use log_entry::{EntryKind, LogEntry};
pub use message::{AppendResult, Message};
pub use meta::Meta;
pub use role::Role;
pub use rpc::{InstallSnapshotReq, InstallSnapshotResp};
pub use storage::{ActiveConfigRecord, MemStorage, Storage, WriteBatch};
pub use transport::{Envelope, Transport};

#[cfg(feature = "std")]
pub use worker::{
    ChangeMembershipError, ProposeError, RaftMsg, ReadIndexError, Worker, WorkerHandle,
    WorkerSnapshot,
};
