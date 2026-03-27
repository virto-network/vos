//! # vos
//!
//! VOS runtime — JAR-aligned PVM executor for VOS actors.
//!
//! The runtime manages service lifecycles using the JAR execution model:
//! fresh PVM per invocation, state via storage hostcalls, transfer-based messaging.
//!
//! ## Architecture
//!
//! ```text
//! ┌──────────────────────────────────┐
//! │  vosx (native host)              │
//! ├──────────────────────────────────┤
//! │  VosRuntime                      │
//! │  ┌───────────────────────────┐   │
//! │  │ Hostcall handler          │   │
//! │  │  - per-service KV storage │   │
//! │  │  - preimage store         │   │
//! │  │  - transfer routing       │   │
//! │  ├───────────────────────────┤   │
//! │  │ Service registry          │   │
//! │  │  [Svc 1] [Svc 2] ...     │   │
//! │  └───────────────────────────┘   │
//! └──────────────────────────────────┘
//! ```

#![cfg_attr(not(feature = "std"), no_std)]
#![allow(async_fn_in_trait)]

extern crate alloc;

pub use rkyv;

// --- Actor framework (always available, no_std compatible) ---

pub mod actors;

// Re-export core actor types at crate root for `use vos::*`
pub use actors::{Actor, Message, Context, Executor, Progress, Mailbox, Yield, block_on, metadata};
#[cfg(feature = "macros")]
pub use vos_macros::{actor, actor as document, actor as agent, actor as skill, messages};
#[cfg(feature = "guest")]
pub use actors::main_loop;

// --- Shared data structures (no_std compatible) ---

pub mod registry;

// --- Runtime infrastructure (host-only) ---

pub mod scheduler;
pub mod hostcall_handler;

#[cfg(feature = "std")]
pub mod manifest;
#[cfg(feature = "std")]
pub mod pvm_driver;
#[cfg(feature = "std")]
pub mod runtime;

pub use hostcall_handler::MemoryAccess;

/// Re-export for use by generated print!/println! macros.
#[cfg(feature = "guest")]
#[doc(hidden)]
pub mod __io {
    pub use vos_abi::guest::hostcalls::debug_write;
}
