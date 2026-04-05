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
pub use actors::{Actor, Message, Context, PendingAsk, Yield, RunResult, try_poll, metadata};
pub use actors::{Encode, Decode};
pub use actors::{service_code_hash, STATUS_DONE, STATUS_YIELDED};
pub use actors::lifecycle;
#[cfg(feature = "macros")]
pub use vos_macros::{actor, actor as document, actor as agent, actor as skill, messages};
#[cfg(feature = "service")]
pub use actors::run_accumulate;
#[cfg(feature = "pvm")]
pub use actors::run_refine;
#[cfg(feature = "pvm")]
pub use actors::run_entry;

/// Re-export guest hostcalls for direct use by actors (e.g. agent calling invoke).
#[cfg(feature = "pvm")]
pub mod hostcalls {
    pub use vos_abi::pvm::hostcalls::*;
}

// --- Runtime infrastructure (host-only) ---

#[cfg(feature = "std")]
pub mod runtime;

/// Re-export for use by generated print!/println! macros.
#[cfg(feature = "pvm")]
#[doc(hidden)]
pub mod __io {
    pub use vos_abi::pvm::hostcalls::debug_write;
}
