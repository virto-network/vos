//! # pvm-executor
//!
//! Cooperative async executor for PVM actor programs.
//!
//! The executor manages child actor programs, routing messages between
//! them and handling their syscalls. It can run in two modes:
//!
//! - **As a PVM program itself**: the host calls `poll()`, the executor
//!   drives child actors. This enables nested PVM execution.
//! - **As a std host process**: for development, testing, and running
//!   actors outside PVM.
//!
//! ## Architecture
//!
//! ```text
//! ┌──────────────────────────────────┐
//! │  Host / outer PVM                │
//! │  calls executor.poll()           │
//! ├──────────────────────────────────┤
//! │  pvm-executor                    │
//! │  ┌───────────────────────────┐   │
//! │  │ Scheduler (round-robin)   │   │
//! │  ├───────────────────────────┤   │
//! │  │ Syscall handler           │   │
//! │  │  - message routing        │   │
//! │  │  - virtual fd table       │   │
//! │  │  - logging                │   │
//! │  ├───────────────────────────┤   │
//! │  │ Actor registry            │   │
//! │  │  [Actor 1] [Actor 2] ...  │   │
//! │  └───────────────────────────┘   │
//! └──────────────────────────────────┘
//! ```

#![cfg_attr(not(feature = "std"), no_std)]
#![allow(async_fn_in_trait)]

pub mod registry;
pub mod scheduler;
pub mod syscall_handler;
pub mod vfs;

#[cfg(feature = "std")]
pub mod manifest;
#[cfg(feature = "std")]
pub mod pvm_driver;

pub use syscall_handler::MemoryAccess;
