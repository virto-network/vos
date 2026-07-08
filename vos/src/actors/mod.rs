//! Minimal actor framework for VOS. JAR-aligned lifecycle:
//! fresh PVM per invocation, state via storage, transfer-based messaging.
//!
//! Actors appear as long-running structs with methods. The framework
//! hides the fresh-PVM-per-invocation model: each invocation deserializes
//! state from storage, runs handlers, serializes state back, and halts.
//!
//! ## Cooperative primitives
//!
//! - `ctx.tell(target, payload)` — fire-and-forget message (queues transfer)
//! - `ctx.ask(target, payload)` — synchronous query (suspends until result)
//! - `ctx.yield_now()` — commit state, self-schedule, halt
//! - `ctx.sleep(n)` — commit state, sleep N ticks, halt

mod actor;
pub mod auth;
pub mod client;
pub mod codec;
pub mod init;
pub mod lifecycle;
pub mod metadata;
pub mod run;
pub mod value;

/// Cooperative multi-task executor for native extensions. Only compiled in an
/// extension build.
#[cfg(feature = "extension")]
pub mod exec;

pub use actor::{Actor, Message};
pub use auth::{
    Caller, Forbidden, IntraCap, IntraCapParseError, NO_ROLES_MAP, NoRoles, RoleByte, SpaceRole,
    SpaceRoleMap, cap_for,
};
pub use codec::{Decode, Encode};
pub mod context;
pub use context::{Context, Extension, ExtensionCtx};
#[cfg(feature = "extension")]
pub use exec::{ExecIo, TaskFut, TaskState, TaskTable, task_waker};
#[cfg(feature = "pvm")]
pub use run::run_refine;
pub use run::{
    Ask, HostIo, RunResult, STATUS_DONE, STATUS_FORBIDDEN, STATUS_NOT_FOUND, STATUS_OOG,
    STATUS_PANICKED, STATUS_YIELDED, Yield, noop_waker, run_blocking, service_code_hash, try_poll,
};
#[cfg(feature = "service")]
pub use run::run_refine_service;
pub use value::InvokeError;

/// JAM refine entry (PC=0). Always uses the service lifecycle so
/// actors can run both standalone (`vosx run actor.elf -s`) and as
/// invoked children. State is read from storage on cold start; FETCH
/// items are treated as messages.
#[cfg(feature = "service")]
pub fn run_refine_entry<A: Actor>() {
    run::run_refine_service::<A>()
}
#[cfg(all(feature = "pvm", not(feature = "service")))]
pub fn run_refine_entry<A: Actor>() {
    run::run_refine::<A>()
}

// --- Guest panic handler ---
//
// Guest-only #[panic_handler]. Include only when we're a no_std
// guest build — when both `pvm` and `std` are enabled (which
// happens to vos itself when an actor crate is dev-deped from
// host code), std already provides `panic_impl` and a second one
// here is a duplicate-lang-item error.
#[cfg(all(feature = "pvm", not(feature = "std")))]
mod guest_panic;

// Guest-side stdout shims (`print!`/`println!`/`eprint!`/`eprintln!`)
// backed by the DEBUG_WRITE hostcall. The macros are `#[macro_export]`
// so they're exposed at the vos crate root regardless; the prelude
// re-exports them under `pvm` so a single `use vos::prelude::*;`
// covers both `log::info!` and `println!` for actor source files.
#[cfg(feature = "pvm")]
mod guest_io;
