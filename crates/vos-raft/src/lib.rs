//! # vos-raft
//!
//! Transport- and storage-agnostic Raft consensus core, designed
//! to live alongside any transport (libp2p, tarpc, raw TCP, an
//! embedded radio) and any persistence layer (redb, sled, an MCU
//! flash log, an in-memory hash map for tests). The crate
//! compiles `no_std + alloc` so it can ship to microcontrollers.
//!
//! ## Status
//!
//! This is the v1 carve-out from `vos`. Phase 1 of the extraction
//! is "pure data types only" — the Raft log entry shape, the
//! RPC request/response structs, the role enum, and the
//! configuration. The state-machine worker, the storage trait,
//! the transport trait, and the async loop arrive in subsequent
//! commits.
//!
//! The types here are byte-for-byte interchangeable with the
//! ones the `vos` crate used to define inline; the parent crate
//! re-exports them through `vos::raft::*` for now so existing
//! call sites keep compiling.

#![cfg_attr(not(feature = "std"), no_std)]

extern crate alloc;

pub mod config;
pub mod log_entry;
pub mod role;
pub mod rpc;

pub use config::Config;
pub use log_entry::LogEntry;
pub use role::Role;
pub use rpc::{
    AppendEntriesReq, AppendEntriesResp, InstallSnapshotReq, InstallSnapshotResp,
    RequestVoteReq, RequestVoteResp,
};
