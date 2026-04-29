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

pub mod effects;
pub mod effect_log;
pub mod worker;

// ── WASM bootstrap (allocator + panic handler) ───────────────────────
//
// no_std cdylib WASM modules need a global allocator and a panic
// handler. With the `wasm-bootstrap` feature enabled, vos provides
// both, so the actor crate only needs `#![no_std]` plus its actor
// definitions — no manual allocator/panic plumbing.
//
// Both items are crate-unique; if you need a custom allocator or
// panic behaviour, omit this feature and provide them yourself.

#[cfg(all(target_arch = "wasm32", feature = "wasm-bootstrap"))]
#[global_allocator]
static __VOS_ALLOC: dlmalloc::GlobalDlmalloc = dlmalloc::GlobalDlmalloc;

#[cfg(all(target_arch = "wasm32", feature = "wasm-bootstrap"))]
#[panic_handler]
fn __vos_panic(_info: &core::panic::PanicInfo) -> ! {
    core::arch::wasm32::unreachable()
}

#[cfg(feature = "std")]
pub mod data_layer;
#[cfg(feature = "std")]
pub mod pvm_image;

// Re-export core actor types at crate root for `use vos::*`
pub use actors::{Actor, Message, Context, WorkerActor, WorkerCtx, Yield, Ask, RunResult, try_poll, run_blocking, metadata};
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

/// Materialize the PVM entry points (`_start`, `accumulate`)
/// and the `.vos_meta` static for an actor type.
///
/// `#[messages]` no longer emits these itself — putting them in
/// the lib would cause duplicate-symbol link errors when one
/// actor crate depends on another's lib. Instead, the bin's
/// `main.rs` invokes this macro once:
///
/// ```ignore
/// vos::pvm_main!(crate::Foo);
/// ```
///
/// All emitted items are gated on `cfg(target_arch = "riscv64")`,
/// so a host build of the same `main.rs` is just `fn main() {}`.
#[macro_export]
macro_rules! pvm_main {
    ($actor:ty) => {
        #[cfg(target_arch = "riscv64")]
        #[unsafe(no_mangle)]
        pub extern "C" fn _start() {
            $crate::run_refine_entry::<$actor>();
        }

        #[cfg(target_arch = "riscv64")]
        #[unsafe(no_mangle)]
        pub extern "C" fn accumulate() {
            $crate::run_accumulate_entry::<$actor>();
        }

        #[cfg(target_arch = "riscv64")]
        #[used]
        static _KEEP_ACCUMULATE: unsafe extern "C" fn() = accumulate;

        // Meta encoding lives here so the `.vos_meta` static
        // sits in the bin's translation unit — same reason as
        // `_start`. The const is recomputed from the actor's
        // `Message::META` rather than referenced from the lib.
        #[cfg(target_arch = "riscv64")]
        const __VOS_PVM_MAIN_META: ([u8; 4096], usize) = $crate::metadata::encode::<4096>(
            &<<$actor as $crate::Actor>::Message>::META
        );

        #[cfg(target_arch = "riscv64")]
        #[unsafe(link_section = ".vos_meta")]
        #[used]
        static _VOS_META: [u8; __VOS_PVM_MAIN_META.1] = {
            let (src, len) = __VOS_PVM_MAIN_META;
            let mut out = [0u8; __VOS_PVM_MAIN_META.1];
            let mut i = 0;
            while i < len { out[i] = src[i]; i += 1; }
            out
        };
    };
}

// --- Runtime infrastructure (host-only) ---

#[cfg(feature = "std")]
pub mod operand;

#[cfg(feature = "std")]
pub mod runtime;

#[cfg(feature = "std")]
pub mod node;

#[cfg(feature = "std")]
pub mod commit;

#[cfg(feature = "network")]
pub mod network;

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
