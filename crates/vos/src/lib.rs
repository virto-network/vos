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

// --- ABI (hostcall IDs, error codes, ecall wrappers) ---

pub mod abi;

// --- Actor framework (always available, no_std compatible) ---

pub mod actors;
pub mod refine_payload;
pub mod registry;

pub mod worker;

#[cfg(feature = "std")]
pub mod data_layer;
#[cfg(feature = "std")]
pub mod pvm_image;

// Re-export core actor types at crate root for `use vos::*`
pub use actors::{Actor, Message, Context, Yield, Ask, RunResult, try_poll, run_blocking, metadata};
pub use actors::{Encode, Decode};
pub use actors::{service_code_hash, STATUS_DONE, STATUS_YIELDED, STATUS_PANICKED, STATUS_NOT_FOUND, STATUS_OOG};
pub use actors::InvokeError;
pub use actors::init;
pub use actors::lifecycle;
pub use actors::value;
#[cfg(feature = "macros")]
pub use vos_macros::{actor, actor as document, actor as agent, actor as skill, messages};
#[cfg(feature = "pvm")]
pub use actors::run_refine;
#[cfg(feature = "pvm")]
pub use actors::{run_refine_entry, run_accumulate_entry};

/// Re-export guest hostcalls for direct use by actors (e.g. agent calling invoke).
#[cfg(feature = "pvm")]
pub mod hostcalls {
    pub use crate::abi::pvm::hostcalls::*;
}

// --- Runtime infrastructure (host-only) ---

#[cfg(feature = "std")]
pub mod operand;

#[cfg(feature = "std")]
pub mod runtime;

#[cfg(feature = "std")]
pub mod node;

/// Re-export for use by generated print!/println! macros.
#[cfg(feature = "pvm")]
#[doc(hidden)]
pub mod __io {
    pub use crate::abi::pvm::hostcalls::debug_write;
}

/// Re-export for use by generated worker entry points.
#[doc(hidden)]
pub mod __worker {
    pub use crate::actors::run::noop_waker;
}
