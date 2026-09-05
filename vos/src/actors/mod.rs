//! Minimal actor framework for VOS. PVM-aligned lifecycle:
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
//! - `ctx.yield_now()` — commit state, self-schedule, halt (alias: `ctx.sleep`)

mod actor;
pub mod auth;
pub mod client;
pub mod codec;
pub mod init;
pub mod lifecycle;
pub mod metadata;
pub mod run;
pub mod storage;
pub mod tasks;
pub mod value;

/// Cooperative multi-task executor for native extensions. Only compiled in an
/// extension build.
#[cfg(feature = "extension")]
pub mod exec;

pub use actor::{Actor, Message};
pub use auth::{
    Caller, Forbidden, IngressAccessGrant, IngressAccessStatus, IntraCap, IntraCapParseError,
    MAX_MEMBER_CREDENTIAL_HISTORY, MAX_MEMBER_CREDENTIALS, MAX_MEMBER_ROLES, MAX_ROLE_CAPABILITIES,
    MAX_SPACE_ROLES, NO_ROLES_MAP, NoRoles, RoleByte, SpaceMemberRoles, SpaceRole,
    SpaceRoleDefinition, SpaceRoleMap, cap_for, capability, default_space_roles,
    ingress_credential_id, ssh_credential_id,
};
pub use client::{
    ActorHandle, ActorReference, CallError, ClientError, ExtensionHandle, ExtensionReference,
};
pub use codec::{Decode, Encode};
pub mod context;
pub use context::{Context, DeviceSignature, Extension, ExtensionCtx};
#[cfg(feature = "extension")]
pub use exec::{ExecIo, TaskFut, TaskState, TaskTable, task_waker};
#[cfg(feature = "pvm")]
pub use run::run_refine;
pub use run::{
    Ask, HostIo, InvokeStatus, RunResult, STATUS_DONE, STATUS_FORBIDDEN, STATUS_NOT_FOUND,
    STATUS_OOG, STATUS_PANICKED, STATUS_TOO_BIG, STATUS_YIELDED, Yield, noop_waker, run_blocking,
    service_code_hash, try_poll,
};
#[cfg(feature = "service")]
pub use run::{run_refine_service, run_task_service};
pub use value::InvokeError;

/// service platform refine entry (PC=0). Always uses the service lifecycle so
/// actors can run both standalone (`vosx run actor.elf -s`) and as
/// invoked children. State is read from storage on cold start; FETCH
/// items are treated as messages.
#[cfg(feature = "service")]
pub fn run_refine_entry<A: Actor>() {
    run::run_refine_service::<A>()
}
/// Nested PVM actor entry selected by the service CALL marker.
#[cfg(feature = "service")]
pub fn run_nested_actor_entry<A: Actor>(input_address: u64, input_len: u64, capacity: u64) -> ! {
    run::run_nested_actor_service::<A>(input_address, input_len, capacity)
}
#[cfg(all(feature = "pvm", not(feature = "service")))]
pub fn run_refine_entry<A: Actor>(args_address: u64, args_len: u64) {
    run::run_refine::<A>(args_address, args_len)
}

/// Canonical actor entry. Transitional service guests retain their nested
/// marker, while standard agent actors have one kernel-free refine entry.
#[cfg(feature = "service")]
pub fn run_actor_entry<A: Actor>(a0: u64, a1: u64, a2: u64, a3: u64) {
    if a3 == crate::service::NESTED_ACTOR_CALL_MAGIC {
        run_nested_actor_entry::<A>(a0, a1, a2)
    } else {
        run_refine_entry::<A>()
    }
}

#[cfg(all(feature = "pvm", not(feature = "service")))]
pub fn run_actor_entry<A: Actor>(a0: u64, a1: u64, _a2: u64, _a3: u64) {
    run_refine_entry::<A>(a0, a1)
}

/// service platform refine entry (PC=0) for **Task** blobs: input is the
/// witness-delivered `(state, msg)` at `witness_ptr` instead of
/// READ/FETCH — see [`run::run_task_service`]. Emitted as `_start` by
/// `#[actor(task)]`.
#[cfg(feature = "service")]
pub fn run_task_entry<A: Actor>(witness_ptr: *const u8, witness_cap: usize) {
    run::run_task_service::<A>(witness_ptr, witness_cap)
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
