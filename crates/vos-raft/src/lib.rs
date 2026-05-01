//! # vos-raft
//!
//! Transport- and storage-agnostic Raft consensus core, designed
//! to live alongside any transport (libp2p, tarpc, raw TCP, an
//! embedded radio) and any persistence layer (redb, sled, an MCU
//! flash log, an in-memory hash map for tests). The crate
//! compiles `no_std + alloc` so it can ship to microcontrollers.
//!
//! ## Concepts
//!
//! - [`Storage<N>`] — the durable log + meta + snapshot row.
//!   Async by default; the in-crate [`MemStorage`] is fine for
//!   tests, vos ships a redb impl, embedded users plug in
//!   their own flash-backed impl.
//! - [`Transport<N>`] — outbound RPCs. Async by default; the
//!   worker calls `send_append`, `send_vote`, `send_install`
//!   from a single task using `FuturesUnordered`.
//! - [`Clock`] + [`Rng`] — runtime abstractions for the
//!   election timer + jitter. [`StdClock`] / [`StdRng`] ship
//!   with the `std` feature; embedded users provide their own.
//! - [`ApplySink`] — receives `commit_index` advances. `()` is
//!   a valid no-op sink for hosts that don't need notifications.
//! - [`Worker`] / [`WorkerHandle`] (std-only) — a thread-spawning
//!   convenience that drives the worker future on a dedicated
//!   thread. Embedded hosts skip this and call
//!   [`worker::run_worker`] directly on their own executor.
//!
//! ## Std-feature quickstart
//!
//! ```
//! use std::sync::Arc;
//! use vos_raft::{Config, MemStorage, Worker};
//!
//! # struct NoopT;
//! # #[derive(Debug)] struct E;
//! # impl core::fmt::Display for E { fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result { write!(f, "x") } }
//! # impl std::error::Error for E {}
//! # impl vos_raft::Transport<u16> for NoopT {
//! #     type Error = E;
//! #     async fn send_append(&self, _: u16, _: vos_raft::AppendEntriesReq<u16>) -> Result<vos_raft::AppendEntriesResp, E> { Err(E) }
//! #     async fn send_vote(&self, _: u16, _: vos_raft::RequestVoteReq<u16>) -> Result<vos_raft::RequestVoteResp, E> { Err(E) }
//! #     async fn send_install(&self, _: u16, _: vos_raft::InstallSnapshotReq<u16>) -> Result<vos_raft::InstallSnapshotResp, E> { Err(E) }
//! # }
//! // Solo-cluster smoke test — single member self-elects to
//! // Leader on its first election timer.
//! let storage = MemStorage::<u16>::new();
//! let transport = Arc::new(NoopT);
//! let mut cfg = Config::new(0xAAAA, vec![0xAAAA], [0xC0; 32]);
//! cfg.election_timeout_ms = (10, 30);
//!
//! let worker = Worker::spawn(storage, transport, cfg, None);
//! // ... `worker.handler()` for proposals, RPC dispatch, etc.
//! worker.shutdown();
//! ```
//!
//! ## Embedded usage (no_std)
//!
//! With `default-features = false` the [`Worker`] / [`Worker::spawn`]
//! convenience is gone. Embedded hosts implement [`Storage`],
//! [`Transport`], [`Clock`], [`Rng`], and [`ApplySink`] against
//! their own primitives (Embassy timers, SPI flash, etc.) and
//! drive the worker future themselves:
//!
//! ```ignore
//! // On Embassy or any other no_std executor:
//! let (inbox_tx, inbox_rx) = my_channel::unbounded();
//! let role = alloc::sync::Arc::new(core::sync::atomic::AtomicU8::new(0));
//! vos_raft::worker::run_worker(
//!     storage, transport, cfg, inbox_rx, apply_sink,
//!     clock, rng, role,
//! ).await;
//! ```

#![cfg_attr(not(feature = "std"), no_std)]

extern crate alloc;

pub mod clock;
pub mod config;
pub mod log_entry;
pub mod meta;
pub mod role;
pub mod rpc;
pub mod storage;
pub mod transport;

#[cfg(test)]
pub(crate) mod testutil;

#[cfg(feature = "std")]
pub mod worker;

pub use clock::{ApplySink, Clock, Rng};
#[cfg(feature = "std")]
pub use clock::{StdClock, StdRng};
#[cfg(feature = "tokio")]
pub use clock::TokioClock;
pub use config::{Config, NodeId};
pub use log_entry::LogEntry;
pub use meta::Meta;
pub use role::Role;
pub use rpc::{
    AppendEntriesReq, AppendEntriesResp, InstallSnapshotReq, InstallSnapshotResp,
    PreVoteReq, PreVoteResp, RequestVoteReq, RequestVoteResp,
};
pub use storage::{MemStorage, Storage, WriteBatch};
pub use transport::Transport;

#[cfg(feature = "std")]
pub use worker::{ProposeError, RaftMsg, Worker, WorkerHandle, WorkerSnapshot};
