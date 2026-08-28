//! # vos
//!
//! Actor SDK and host runtime for signed VOS applications.
//!
//! Each installed package runs behind the generic service guest. The service
//! authenticates work, invokes the actor, and commits its state and effects
//! through Local, Raft, or CRDT ordering.
//!
//! ## Architecture
//!
//! ```text
//! Client → node → root service → actor tree → durable state
//! ```

#![cfg_attr(not(feature = "std"), no_std)]
#![allow(async_fn_in_trait)]

extern crate alloc;

pub use rkyv;

/// Re-export of the [`log`](https://docs.rs/log/0.4) facade. The
/// per-target `Log` impl is auto-installed by the entry point for
/// each build flavor (PVM `_start`, `vos_extension_create`,
/// `vos_wasm_create`), so user code only needs to call
/// `log::info!(...)` etc. — no manual subscriber setup.
pub use ::log;

/// Common imports for actor crates. `use vos::prelude::*;` brings
/// in:
/// - `actor` and `messages` proc-macro attributes,
/// - the `log` module (so `log::info!(...)` works without a
///   per-call-site path),
/// - `Msg` for raw `ctx.ask` payloads (most users prefer typed
///   `{Actor}Ref`, but agent-style actors that route dynamic
///   messages still hand-build `Msg` values),
/// - the `lifecycle` module (`lifecycle::invoke` etc. for agents
///   that drive sub-actors directly via the INVOKE hostcall).
///
/// Each actor lib.rs typically only needs this single line.
pub mod prelude {
    pub use crate::crdt;
    pub use crate::lifecycle;
    pub use crate::value::Msg;
    pub use crate::{Decode, Encode};
    // Available for explicit actor helper methods and manual Actor impls.
    pub use crate::Context;
    pub use crate::{ActorId, CallError, CallId, CapabilityId, InvocationId, Origin, SpaceRole};
    pub use crate::{Attestation, AttestationError, Verified};
    #[cfg(feature = "macros")]
    pub use crate::{actor, messages};
    // Guest-side stdout shims backed by DEBUG_WRITE. Available at
    // crate root via `#[macro_export]` on pvm builds; re-exporting
    // them through the prelude lets a single glob cover both
    // `log::info!` and `println!`.
    #[cfg(feature = "pvm")]
    pub use crate::{eprint, eprintln, print, println};
    pub use ::log;
}

/// Backing for the print!/println! macros declared in
/// `actors::guest_io`. Hidden — user code goes through the macros.
#[cfg(feature = "pvm")]
#[doc(hidden)]
pub mod __io {
    pub use crate::abi::pvm::hostcalls::debug_write;
}

// --- ABI (hostcall IDs, error codes, ecall wrappers) ---

pub mod abi;
pub mod attestation;
pub mod crypto;
/// Canonical service contracts and the local conformance harness.
///
/// Service packages and persisted stores use this contract exclusively.
pub mod service;

/// ZK actor-I/O ABI: bind a PVM execution proof to a `(public, return)` tuple
/// (TAGLESS — program identity lives in the proof's program commitment,
/// not the hash).  `compute_io_hash` is always available (guest + host);
/// the guest-side `bind_io` is `pvm`-gated.  Proof verification (STARK
/// validity ∧ io-binding) is composed in the `prover` host extension.
pub mod zk;

// --- Actor framework (always available, no_std compatible) ---

pub mod actors;
/// Convergent, PVM-safe field types for `#[actor(crdt)]` state.
pub mod crdt;
pub mod jobs;
// Space-registry protocol — wire rows, status/role consts, and the
// consensus-critical canonical signing-byte encodings. Always available
// (no_std) so the space-registry actor's service/wasm builds can
// `pub use` them back; the daemon's sign-on-relay path is std-gated
// inside the module.
pub mod provable;
pub mod refine_payload;
pub mod registry;
pub mod task_abi;

pub mod effect_log;
pub mod effects;
pub mod extension;
// Auto-installed `log::Log` impl for PVM builds. Worker- and
// wasm-side log impls live in the user crate (emitted by the
// `__vos_emit_*_glue!` decl macros) because they need std /
// host imports that don't fit into vos's no_std-friendly
// feature shape. The `run_refine_service` call site is itself
// `cfg(feature = "service")` which implies `pvm`, so a no-pvm
// build never references this module.
#[cfg(feature = "pvm")]
pub(crate) mod log_impl;

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
pub use actors::InvokeError;
pub use actors::init;
pub use actors::lifecycle;
#[cfg(feature = "pvm")]
pub use actors::run_refine;
pub use actors::storage;
pub use actors::value;
pub use actors::{
    Actor, ActorHandle, ActorReference, Ask, CallError, Caller, ClientError, Context,
    DeviceSignature, Extension, ExtensionCtx, ExtensionHandle, ExtensionReference, Forbidden,
    IngressAccessGrant, IngressAccessStatus, IntraCap, IntraCapParseError,
    MAX_MEMBER_CREDENTIAL_HISTORY, MAX_MEMBER_CREDENTIALS, MAX_MEMBER_ROLES,
    MAX_ROLE_CAPABILITIES, MAX_SPACE_ROLES, Message, NO_ROLES_MAP, NoRoles, RoleByte, RunResult,
    SpaceMemberRoles, SpaceRole, SpaceRoleDefinition, SpaceRoleMap, Yield, capability,
    default_space_roles, ingress_credential_id, metadata, run_blocking, ssh_credential_id,
    try_poll,
};
pub use actors::{Decode, Encode};
pub use actors::{
    InvokeStatus, STATUS_DONE, STATUS_FORBIDDEN, STATUS_NOT_FOUND, STATUS_OOG, STATUS_PANICKED,
    STATUS_TOO_BIG, STATUS_YIELDED, service_code_hash,
};
pub use attestation::{
    Attestation, AttestationError, AttestationPreparation, AttestationProofBackend,
    AttestationProofHost, AttestationProofProducer, AttestationProofRequest,
    AttestationProofVerifier, AttestationReplayGuard, AttestationReplayKey, AttestationReplayStore,
    AttestationSource, AttestationSourceResolver, AttestationStatement, AttestedMethod,
    ProducedAttestationProof, ProofVerifier, ReceiptVerifier, StateCommitment, VerificationContext,
    Verified, VerifyAttestationBuilder, VerifyAttestationFrom, verify_once,
};
pub use service::{
    ActorId, CallId, CapabilityId, InvocationId, Origin, ProducerId, ProgramId, RoleId, SubjectId,
};
// Per-task future machinery for native extensions: the scheduler lives
// host-side (see node.rs). Re-exported at the crate root so the
// `__vos_emit_worker_glue!` macro can name `$crate::TaskTable` / `$crate::TaskState`
// / `$crate::TaskFut` / `$crate::task_waker` from the user crate.
#[cfg(feature = "extension")]
pub use actors::exec::{TaskFut, TaskState, TaskTable, task_waker};
#[cfg(feature = "pvm")]
pub use actors::run_refine_entry;
#[cfg(feature = "service")]
pub use actors::{run_nested_actor_entry, run_task_entry};
#[cfg(feature = "macros")]
pub use vos_macros::{actor, messages};

/// The agent model: parent-managed children — `Tasks` tables of
/// `Child::{Task, Peer}` records, spawned and driven from handlers.
pub mod agent {
    pub use crate::actors::tasks::{Child, TaskId, TaskRecord, TaskStatus, Tasks};
}

/// Re-export guest hostcalls for direct use by actors (e.g. agent calling invoke).
#[cfg(feature = "pvm")]
pub mod hostcalls {
    pub use crate::abi::pvm::hostcalls::*;
}

// --- Runtime infrastructure (host-only) ---

#[cfg(feature = "std")]
pub mod runtime;

#[cfg(feature = "std")]
pub mod node;

#[cfg(feature = "http-ingress")]
pub mod ingress;
#[cfg(feature = "ssh-ingress")]
pub mod ssh_ingress;

/// Drive a future to completion on the current thread.
///
/// Single-poll loop with a no-op waker — sufficient because the
/// futures returned by [`Invoker`](crate::actors::client::Invoker)
/// impls used from host code (notably `&VosNode`) are always
/// `Ready` on the first poll. Use this to call typed `{Actor}Ref`
/// methods from host code without pulling a real async runtime:
///
/// ```ignore
/// let id = vos::block_on(reg.resolve(&mut &node, name))?;
/// ```
#[cfg(feature = "std")]
pub fn block_on<F: core::future::Future>(fut: F) -> F::Output {
    use core::pin::pin;
    use core::task::{Context, Poll};
    let waker = crate::actors::run::noop_waker();
    let mut cx = Context::from_waker(&waker);
    let mut fut = pin!(fut);
    loop {
        if let Poll::Ready(v) = fut.as_mut().poll(&mut cx) {
            return v;
        }
    }
}

#[cfg(feature = "std")]
mod host_invoker {
    use crate::Decode;
    use crate::actors::client::{AttestationInvoker, ClientError, Invoker};
    use crate::actors::value::Value;
    use crate::node::VosNode;
    use alloc::vec::Vec;
    use core::future::Future;

    // VosNode actor invocation is synchronous and takes `&self`, so the natural
    // call site is `&node`. The trait wants `&mut self`, hence
    // `&mut &node` at the call site — clunky but compiles cleanly,
    // and a tiny price for keeping a single trait shape across both
    // PVM and host invokers.
    impl Invoker for &VosNode {
        fn invoke_actor(
            &mut self,
            target: crate::service::ActorId,
            payload: Vec<u8>,
        ) -> impl Future<Output = Result<Value, ClientError>> + '_ {
            let outcome = VosNode::invoke_actor(self, target, payload);
            async move {
                match outcome {
                    Ok(bytes) if bytes.is_empty() => Ok(Value::Unit),
                    Ok(bytes) => Ok(<Value as Decode>::decode(&bytes)),
                    Err(error) => Err(error),
                }
            }
        }
    }

    impl AttestationInvoker for &VosNode {
        fn invoke_actor_attested(
            &mut self,
            target: crate::service::ActorId,
            payload: Vec<u8>,
        ) -> impl Future<
            Output = Result<crate::actors::client::AttestedInvocationResult, ClientError>,
        > + '_ {
            let outcome = VosNode::invoke_actor_attested(self, target, payload);
            core::future::ready(outcome)
        }
    }
}

#[cfg(feature = "std")]
pub mod commit;

#[cfg(feature = "storage")]
pub mod raft;

#[cfg(feature = "network")]
pub mod network;

/// Re-export for use by generated worker entry points.
#[doc(hidden)]
pub mod __extension {
    pub use crate::actors::run::noop_waker;
}

/// Re-export of `alloc` for use by the `#[messages]` macro — actor
/// crates don't need to declare `extern crate alloc` themselves to
/// access `Box::pin`.
#[doc(hidden)]
pub mod __alloc {
    pub use alloc::boxed;
}

// ── Role-glue decl macros ────────────────────────────────────────────
//
// These three macros are called unconditionally by the
// `#[messages]` proc-macro to emit worker / WASM / host-side
// glue. The cfg gating is *here*, evaluated against `vos`'s own
// features — which check-cfg knows about — so the user crate
// never sees a `cfg(feature = ...)` referencing `vos`'s feature
// names. That keeps actor crates free of `[lints.rust.unexpected_cfgs]`
// allowlists.
//
// When the gating feature is off, each macro expands to nothing.

/// Emit the native worker plugin (`vos_extension_*` extern fns).
/// Active when `vos` is built with the `worker` feature; otherwise
/// expands to nothing.
#[cfg(feature = "extension")]
#[macro_export]
#[doc(hidden)]
macro_rules! __vos_emit_worker_glue {
    ($actor_name:path, $enum_name:path) => {
        // Unconditional bits — these are no-symbol items (a trait
        // impl and a use) so they don't conflict across cross-actor
        // lib deps. They need to be visible whenever the worker
        // feature is active so handler bodies can call `ctx.fetch`
        // / `ctx.fs_read` / etc. through the `ExtensionCtx` extension
        // methods, without the user having to remember to import
        // the trait themselves.
        impl $crate::Extension for $actor_name {}

        #[allow(unused_imports)]
        use $crate::ExtensionCtx as _;

        // The extern-fn bits are bin-gated. `vos_extension_create` /
        // `vos_extension_dispatch` / etc. are exported symbols the
        // host's libloading lookup needs; emitting them in a
        // dependency rlib would duplicate them in the dependent
        // worker's link. Top-of-graph builds keep `bin` on; cross-
        // actor lib deps disable default features so this block
        // expands to nothing.
        //
        // SAFETY contract with the host (see also vos/src/extension.rs):
        // - The `state: *mut ()` opaque handle is whatever `vos_extension_create`
        //   returned (a `Box::into_raw(WorkerState)`). The host stores
        //   it and passes it back unchanged on every later call.
        //   `vos_extension_destroy` consumes it. No mutable aliasing —
        //   the host calls these in sequence on one thread per extension.
        // - `(msg_ptr, msg_len)`, `(args_ptr, args_len)`, etc., are
        //   borrowed slices owned by the caller for the duration of
        //   the call. We read them, never store the pointer.
        // - The `(state_ptr, state_len, state_cap)` returned from the v2
        //   snapshot function is a `Vec` raw-parts triple the host must hand
        //   back unchanged to `vos_extension_free` so we can drop it.
        // - The `_VOS_WORKER_META` byte slice is a `'static` array;
        //   the host promises not to mutate through the pointer.
        #[cfg(feature = "bin")]
        mod __vos_worker {
            use super::*;
            use core::future::Future;
            use core::pin::Pin;

            // The scheduler now lives HOST-SIDE (smol). The `.so`
            // keeps only the per-task future slab.
            //
            // `tasks` is declared FIRST so field-order drop frees the in-flight
            // futures before `actor` even if `tasks.clear()` is ever skipped (a
            // future captures `*mut actor`; dropping it never polls, so the
            // pointer is only released, not dereferenced).
            //
            // `actor` is BOXED so it lives in its OWN heap allocation, disjoint
            // from `WorkerState` and from each boxed `TaskState`. Soundness
            // invariant: `vos_extension_task_poll` takes a brief
            // `&mut WorkerState` to find a task slot, but the handler future
            // reaches the actor through a raw `*mut` captured at task-build time
            // — pointing into the actor's separate allocation, so the brief
            // `&mut WorkerState` cannot alias it under any borrow model.
            struct WorkerState {
                tasks: $crate::TaskTable,
                actor: Box<$actor_name>,
            }

            static _VOS_WORKER_META: [u8; _VOS_META_ENCODED.1] = {
                let (src, len) = _VOS_META_ENCODED;
                let mut out = [0u8; _VOS_META_ENCODED.1];
                let mut i = 0;
                while i < len {
                    out[i] = src[i];
                    i += 1;
                }
                out
            };

            #[unsafe(no_mangle)]
            pub extern "C" fn vos_extension_meta(out_ptr: *mut *const u8, out_len: *mut usize) {
                unsafe {
                    *out_ptr = _VOS_WORKER_META.as_ptr();
                    *out_len = _VOS_WORKER_META.len();
                }
            }

            // Stderr-backed `log::Log` impl. Lives in the user crate
            // because the worker target is a host cdylib where std is
            // always available regardless of vos's feature flags.
            // `set_logger` returns Err on duplicate install — we
            // ignore so a host that prefers `tracing-log`,
            // `env_logger`, etc. can install its subscriber before
            // the first dispatch and win (first-installer wins).
            // `log` is reached through `$crate::log` (vos's
            // re-export) so user crates don't need to list it as a
            // direct dep.
            struct __VosWorkerLogger;
            impl $crate::log::Log for __VosWorkerLogger {
                fn enabled(&self, _: &$crate::log::Metadata<'_>) -> bool {
                    true
                }
                fn log(&self, record: &$crate::log::Record<'_>) {
                    use std::io::Write as _;
                    let _ = writeln!(
                        std::io::stderr(),
                        "[{} {}] {}",
                        record.level(),
                        record.target(),
                        record.args(),
                    );
                }
                fn flush(&self) {
                    use std::io::Write as _;
                    let _ = std::io::stderr().flush();
                }
            }
            static __VOS_WORKER_LOGGER: __VosWorkerLogger = __VosWorkerLogger;

            #[unsafe(no_mangle)]
            pub extern "C" fn vos_extension_create(
                args_ptr: *const u8,
                args_len: usize,
            ) -> *mut () {
                // Install the worker logger on first create.
                // Idempotent — subsequent calls are no-ops.
                let _ = $crate::log::set_logger(&__VOS_WORKER_LOGGER);
                $crate::log::set_max_level($crate::log::LevelFilter::Trace);

                use $crate::Actor as _;
                let mut actor = if args_ptr.is_null() || args_len == 0 {
                    <$actor_name as $crate::Actor>::create()
                } else {
                    let args_bytes = unsafe { core::slice::from_raw_parts(args_ptr, args_len) };
                    <$actor_name>::__vos_create_with_args(args_bytes)
                };
                // Run on_start on a throwaway ctx, exactly as before (its
                // effects / host-IO are unsupported at on_start time, so the
                // discarded ctx preserves behaviour).
                let mut tmp =
                    $crate::Context::<$actor_name>::new($crate::actors::context::ServiceId(0));
                if let Err(error) = $crate::run_blocking(actor.on_start(&mut tmp)) {
                    $crate::log::error!("extension on_start failed: {:?}", error);
                    return core::ptr::null_mut();
                }
                let state = Box::new(WorkerState {
                    tasks: $crate::TaskTable::new(),
                    actor: Box::new(actor),
                });
                Box::into_raw(state) as *mut ()
            }

            // `task_new` builds a handler future and slots
            // it (returning a non-zero handle), `task_poll` injects the host's
            // fulfilment of the previous PENDING and polls the future once,
            // `task_drop` frees the slot, `take_spawned` drains spawned children
            // (reserved). The scheduler runs host-side.

            #[unsafe(no_mangle)]
            pub extern "C" fn vos_extension_task_new_v2(
                state: *mut (),
                msg_ptr: *const u8,
                msg_len: usize,
                context_ptr: *const u8,
                context_len: usize,
            ) -> u64 {
                if state.is_null() || msg_ptr.is_null() || context_ptr.is_null() {
                    return 0;
                }
                let ws = unsafe { &mut *(state as *mut WorkerState) };
                let raw = unsafe { core::slice::from_raw_parts(msg_ptr, msg_len) };
                let context_raw = unsafe { core::slice::from_raw_parts(context_ptr, context_len) };
                let Some(task_context) =
                    $crate::extension::ExtensionInvocationContext::decode(context_raw)
                else {
                    return 0;
                };

                if raw.first() != Some(&$crate::value::TAG_DYNAMIC) {
                    return 0;
                }
                let Some(dynamic) = <$crate::value::Msg as $crate::Decode>::try_decode(&raw[1..])
                else {
                    return 0;
                };
                let msg = match <$enum_name as $crate::value::FromDynamic>::from_dynamic(&dynamic) {
                    Some(m) => m,
                    // Unknown method → no future built; return 0 so the host
                    // maps it to an error (the POLL_ERR_NO_FUTURE behaviour).
                    None => return 0,
                };

                // Raw pointer into the actor's OWN heap allocation (Box<actor>),
                // disjoint from WorkerState — so the brief &mut WorkerState a
                // later task_poll takes to find the task slot cannot alias this
                // pointer (soundness invariant; see the WorkerState comment).
                let actor_ptr = &mut *ws.actor as *mut $actor_name;
                // Per-task Context, moved into the future (no raw ptr into it
                // outlives the task; host I/O flows through the TaskState the
                // waker hands ExecIo). Output = the reply bytes, so the
                // (non-generic) per-task machinery never touches this Context.
                let future: Pin<Box<dyn Future<Output = Vec<u8>>>> = Box::pin(async move {
                    let mut ctx = task_context.into_actor_context::<$actor_name>();
                    // SAFETY: extensions are driven N=1 by the host (one root task
                    // at a time, to completion), so this is the only live &mut to
                    // the actor.
                    let actor = unsafe { &mut *actor_ptr };
                    let _stop = msg.deliver(actor, &mut ctx).await;
                    ctx.take_reply_bytes()
                });
                ws.tasks.install(future)
            }

            #[unsafe(no_mangle)]
            pub extern "C" fn vos_extension_task_poll(
                state: *mut (),
                handle: u64,
                result_ptr: *const u8,
                result_len: usize,
            ) -> $crate::extension::TaskPoll {
                // Find the task's stable pointer, then DROP the WorkerState
                // borrow before polling — see the across-poll discipline below.
                let ts_ptr: *mut $crate::TaskState = {
                    let ws = unsafe { &mut *(state as *mut WorkerState) };
                    ws.tasks.ptr(handle)
                };
                if ts_ptr.is_null() {
                    // 0 / out-of-range / already-dropped handle.
                    return $crate::extension::TaskPoll::panic();
                }
                // Inject the host's fulfilment of the previous PENDING (empty on
                // the first poll). Copied immediately; the borrowed result_ptr is
                // never retained past this call.
                let result = if result_ptr.is_null() || result_len == 0 {
                    Vec::new()
                } else {
                    unsafe { core::slice::from_raw_parts(result_ptr, result_len) }.to_vec()
                };
                // SAFETY / ACROSS-POLL ALIASING DISCIPLINE (load-bearing):
                //  * `ts_ptr` points at a live, BOXED TaskState (stable address);
                //  * the WorkerState borrow above is already dropped, and we hold
                //    NO &/&mut to WorkerState, the TaskTable, or the Box across
                //    the bare `fut.poll` below;
                //  * the future is TAKEN OUT of the slot (`take_fut`) so no &mut
                //    to it is alive across the poll either;
                //  * during the poll, ExecIo reconstructs the SOLE &mut TaskState
                //    from the waker (this ts_ptr); the handler reconstructs the
                //    actor from the ptr captured in its future — `&mut *actor_ptr`
                //    for an extension task (N=1, exclusive; task_new path) but a
                //    SHARED `&*actor_ptr` for a transport conn task (N>1 concurrent
                //    conn_new tasks, NEVER &mut — promoting it would alias). Either
                //    way TaskState, the actor box, and WorkerState are three
                //    disjoint allocations; single-threaded → no aliasing under any
                //    borrow model.
                unsafe { (*ts_ptr).set_result(result) };
                loop {
                    let mut fut = match unsafe { (*ts_ptr).take_fut() } {
                        Some(f) => f,
                        // Future already consumed (buggy double-poll) — surface
                        // as PANIC rather than UB.
                        None => return $crate::extension::TaskPoll::panic(),
                    };
                    let waker = $crate::task_waker(ts_ptr as *const ());
                    let mut cx = core::task::Context::from_waker(&waker);
                    // Per-task catch_unwind keeps a handler panic from unwinding
                    // through this extern "C" boundary (which would abort the
                    // host) and isolates it to this one task. Lives here in the
                    // glue because the user crate has std (vos itself is no_std in
                    // an extension build).
                    let polled = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
                        fut.as_mut().poll(&mut cx)
                    }));
                    match polled {
                        Ok(core::task::Poll::Ready(reply)) => {
                            // Future done — moved its reply into the stable `out`
                            // slot; `fut` is NOT put back (dropped here).
                            let (ptr, len) = unsafe { (*ts_ptr).finish_ready(reply) };
                            return $crate::extension::TaskPoll::ready(ptr, len);
                        }
                        Ok(core::task::Poll::Pending) => {
                            match unsafe { (*ts_ptr).step_pending(fut) } {
                                Some((ptr, len)) => {
                                    return $crate::extension::TaskPoll::pending(ptr, len);
                                }
                                // Pending with no host-I/O request filed = a bare
                                // cooperative yield; re-poll without the host.
                                None => continue,
                            }
                        }
                        Err(_panic) => return $crate::extension::TaskPoll::panic(),
                    }
                }
            }

            #[unsafe(no_mangle)]
            pub extern "C" fn vos_extension_task_drop(state: *mut (), handle: u64) {
                let ws = unsafe { &mut *(state as *mut WorkerState) };
                ws.tasks.drop_task(handle);
            }

            #[unsafe(no_mangle)]
            pub extern "C" fn vos_extension_take_spawned(state: *mut ()) -> u64 {
                let ws = unsafe { &mut *(state as *mut WorkerState) };
                ws.tasks.take_spawned()
            }

            #[unsafe(no_mangle)]
            pub extern "C" fn vos_extension_drop(state: *mut ()) {
                if !state.is_null() {
                    let mut ws = unsafe { Box::from_raw(state as *mut WorkerState) };
                    // Drop all in-flight futures before the actor is freed, so no
                    // parked task can deref the soon-dead actor pointer. (Belt and
                    // braces with the field-order drop: `tasks` is declared before
                    // `actor`, so this is redundant but explicit.)
                    ws.tasks.clear();
                    drop(ws);
                }
            }

            #[unsafe(no_mangle)]
            pub extern "C" fn vos_extension_free(ptr: *mut u8, len: usize, cap: usize) {
                if !ptr.is_null() && cap > 0 {
                    unsafe { drop(Vec::from_raw_parts(ptr, len, cap)) };
                }
            }

            #[unsafe(no_mangle)]
            pub extern "C" fn vos_extension_load(
                state_ptr: *const u8,
                state_len: usize,
            ) -> *mut () {
                use $crate::Actor as _;
                let bytes = unsafe { core::slice::from_raw_parts(state_ptr, state_len) };
                const STATE_MAGIC: &[u8; 8] = b"VOSXST02";
                const STATE_HEADER_LEN: usize = 24;
                if bytes.len() < STATE_HEADER_LEN || &bytes[..8] != STATE_MAGIC {
                    return core::ptr::null_mut();
                }
                let mut version_bytes = [0u8; 8];
                version_bytes.copy_from_slice(&bytes[8..16]);
                let mut fingerprint_bytes = [0u8; 8];
                fingerprint_bytes.copy_from_slice(&bytes[16..24]);
                let saved_fingerprint = u64::from_le_bytes(fingerprint_bytes);
                if u64::from_le_bytes(version_bytes)
                    != <$actor_name as $crate::Actor>::STATE_SCHEMA_VERSION
                    || (saved_fingerprint
                        != <$actor_name as $crate::Actor>::STATE_SCHEMA_FINGERPRINT
                        && !<$actor_name as $crate::Actor>::STATE_SCHEMA_LEGACY_FINGERPRINTS
                            .contains(&saved_fingerprint))
                {
                    return core::ptr::null_mut();
                }
                let Some(mut actor): Option<$actor_name> =
                    $crate::Decode::try_decode(&bytes[STATE_HEADER_LEN..])
                else {
                    // A null state tells the host that this plugin cannot
                    // decode the persisted schema. Silently constructing a
                    // default actor here can change operator configuration
                    // (and, for chain adapters, the target network).
                    return core::ptr::null_mut();
                };
                let mut tmp =
                    $crate::Context::<$actor_name>::new($crate::actors::context::ServiceId(0));
                if let Err(error) = $crate::run_blocking(actor.on_start(&mut tmp)) {
                    $crate::log::error!("extension on_start failed after restore: {:?}", error);
                    return core::ptr::null_mut();
                }
                let state = Box::new(WorkerState {
                    tasks: $crate::TaskTable::new(),
                    actor: Box::new(actor),
                });
                Box::into_raw(state) as *mut ()
            }

            #[unsafe(no_mangle)]
            pub extern "C" fn vos_extension_state_v2(
                state: *mut (),
                out_ptr: *mut *mut u8,
                out_len: *mut usize,
                out_cap: *mut usize,
            ) {
                use $crate::{Actor as _, Encode};
                let ws = unsafe { &*(state as *const WorkerState) };
                // Encode the INNER actor, not the `Box` — the blanket
                // `impl<T> Encode for T` also covers `Box<actor>` (rkyv would
                // archive a relative pointer), but `vos_extension_load` decodes
                // straight into `$actor_name`, so the two must agree on the bare
                // actor's layout.
                const STATE_MAGIC: &[u8; 8] = b"VOSXST02";
                let actor_bytes = (*ws.actor).encode();
                let mut bytes = Vec::with_capacity(24 + actor_bytes.len());
                bytes.extend_from_slice(STATE_MAGIC);
                bytes.extend_from_slice(
                    &<$actor_name as $crate::Actor>::STATE_SCHEMA_VERSION.to_le_bytes(),
                );
                bytes.extend_from_slice(
                    &<$actor_name as $crate::Actor>::STATE_SCHEMA_FINGERPRINT.to_le_bytes(),
                );
                bytes.extend_from_slice(&actor_bytes);
                unsafe {
                    *out_ptr = bytes.as_mut_ptr();
                    *out_len = bytes.len();
                    *out_cap = bytes.capacity();
                }
                core::mem::forget(bytes);
            }
        }
    };
}

#[cfg(not(feature = "extension"))]
#[macro_export]
#[doc(hidden)]
macro_rules! __vos_emit_worker_glue {
    ($($_:tt)*) => {};
}

/// Emit the WASM cdylib entry points (`vos_wasm_*` extern fns).
/// Active when `vos` is built with the `wasm` feature.
#[cfg(feature = "wasm")]
#[macro_export]
#[doc(hidden)]
macro_rules! __vos_emit_wasm_glue {
    ($actor_name:path, $enum_name:path) => {
        // Same bin-gating story as the worker glue: the
        // `vos_wasm_*` extern fns are exported symbols the
        // wasm host expects; emitting them in a dependency
        // rlib would duplicate them in the dependent's link.
        #[cfg(feature = "bin")]
        mod __vos_wasm {
            use super::*;
            use core::future::Future;
            use core::pin::Pin;

            struct WasmState {
                actor: $actor_name,
                ctx: $crate::Context<$actor_name>,
                in_flight: Option<Pin<Box<dyn Future<Output = bool>>>>,
                last_reply: Option<Vec<u8>>,
            }

            static _VOS_WASM_META: [u8; _VOS_META_ENCODED.1] = {
                let (src, len) = _VOS_META_ENCODED;
                let mut out = [0u8; _VOS_META_ENCODED.1];
                let mut i = 0;
                while i < len {
                    out[i] = src[i];
                    i += 1;
                }
                out
            };

            #[inline]
            fn pack_buf(ptr: u32, len: u32) -> u64 {
                ((ptr as u64) << 32) | (len as u64)
            }

            #[unsafe(no_mangle)]
            pub extern "C" fn vos_wasm_meta() -> u64 {
                pack_buf(_VOS_WASM_META.as_ptr() as u32, _VOS_WASM_META.len() as u32)
            }

            #[unsafe(no_mangle)]
            pub extern "C" fn vos_wasm_alloc(size: u32) -> u32 {
                let mut buf: Vec<u8> = Vec::with_capacity(size as usize);
                unsafe {
                    buf.set_len(size as usize);
                }
                let ptr = buf.as_mut_ptr() as u32;
                core::mem::forget(buf);
                ptr
            }

            #[unsafe(no_mangle)]
            pub extern "C" fn vos_wasm_free(ptr: u32, size: u32) {
                if ptr != 0 && size > 0 {
                    unsafe {
                        drop(Vec::from_raw_parts(
                            ptr as *mut u8,
                            size as usize,
                            size as usize,
                        ));
                    }
                }
            }

            #[unsafe(no_mangle)]
            pub extern "C" fn vos_wasm_create(args_ptr: u32, args_len: u32) -> u32 {
                use $crate::Actor as _;
                let mut actor = if args_ptr == 0 || args_len == 0 {
                    <$actor_name as $crate::Actor>::create()
                } else {
                    let args_bytes = unsafe {
                        core::slice::from_raw_parts(args_ptr as *const u8, args_len as usize)
                    };
                    <$actor_name>::__vos_create_with_args(args_bytes)
                };
                let mut ctx =
                    $crate::Context::<$actor_name>::new($crate::actors::context::ServiceId(0));
                let _ = $crate::run_blocking(actor.on_start(&mut ctx));
                let state = Box::new(WasmState {
                    actor,
                    ctx,
                    in_flight: None,
                    last_reply: None,
                });
                Box::into_raw(state) as u32
            }

            #[unsafe(no_mangle)]
            pub extern "C" fn vos_wasm_dispatch(state: u32, msg_ptr: u32, msg_len: u32) {
                let ws = unsafe { &mut *(state as *mut WasmState) };
                let raw =
                    unsafe { core::slice::from_raw_parts(msg_ptr as *const u8, msg_len as usize) };

                if raw.first() != Some(&$crate::value::TAG_DYNAMIC) {
                    return;
                }
                let Some(dynamic) = <$crate::value::Msg as $crate::Decode>::try_decode(&raw[1..])
                else {
                    return;
                };
                let msg = match <$enum_name as $crate::value::FromDynamic>::from_dynamic(&dynamic) {
                    Some(m) => m,
                    None => return,
                };

                let actor_ptr = &mut ws.actor as *mut $actor_name;
                let ctx_ptr = &mut ws.ctx as *mut $crate::Context<$actor_name>;
                let future: Pin<Box<dyn Future<Output = bool>>> = Box::pin(async move {
                    let actor = unsafe { &mut *actor_ptr };
                    let ctx = unsafe { &mut *ctx_ptr };
                    msg.deliver(actor, ctx).await
                });
                ws.in_flight = Some(future);
            }

            #[unsafe(no_mangle)]
            pub extern "C" fn vos_wasm_poll(state: u32) -> i32 {
                let ws = unsafe { &mut *(state as *mut WasmState) };
                let Some(future) = ws.in_flight.as_mut() else {
                    return -1;
                };
                let waker = $crate::__extension::noop_waker();
                let mut cx = core::task::Context::from_waker(&waker);
                match future.as_mut().poll(&mut cx) {
                    core::task::Poll::Ready(_stop) => {
                        ws.in_flight = None;
                        let reply = ws.ctx.take_reply_bytes();
                        ws.last_reply = if reply.is_empty() { None } else { Some(reply) };
                        0
                    }
                    core::task::Poll::Pending => 1,
                }
            }

            #[unsafe(no_mangle)]
            pub extern "C" fn vos_wasm_take_reply(state: u32) -> u64 {
                let ws = unsafe { &mut *(state as *mut WasmState) };
                match ws.last_reply.take() {
                    Some(bytes) => {
                        let mut bytes = bytes;
                        bytes.shrink_to_fit();
                        let len = bytes.len();
                        let ptr = bytes.as_mut_ptr();
                        core::mem::forget(bytes);
                        pack_buf(ptr as u32, len as u32)
                    }
                    None => 0,
                }
            }

            #[unsafe(no_mangle)]
            pub extern "C" fn vos_wasm_pending_effect(state: u32) -> u64 {
                let ws = unsafe { &mut *(state as *mut WasmState) };
                match ws.ctx.peek_host_io_request() {
                    Some(bytes) => pack_buf(bytes.as_ptr() as u32, bytes.len() as u32),
                    None => 0,
                }
            }

            #[unsafe(no_mangle)]
            pub extern "C" fn vos_wasm_provide_result(state: u32, ptr: u32, len: u32) {
                let ws = unsafe { &mut *(state as *mut WasmState) };
                let result = if ptr == 0 || len == 0 {
                    Vec::new()
                } else {
                    unsafe { core::slice::from_raw_parts(ptr as *const u8, len as usize) }.to_vec()
                };
                ws.ctx.set_host_io_result(result);
            }

            #[unsafe(no_mangle)]
            pub extern "C" fn vos_wasm_drop(state: u32) {
                if state != 0 {
                    unsafe { drop(Box::from_raw(state as *mut WasmState)) };
                }
            }

            #[unsafe(no_mangle)]
            pub extern "C" fn vos_wasm_load(state_ptr: u32, state_len: u32) -> u32 {
                use $crate::Actor as _;
                let bytes = unsafe {
                    core::slice::from_raw_parts(state_ptr as *const u8, state_len as usize)
                };
                let mut actor: $actor_name = $crate::Decode::try_decode(bytes)
                    .unwrap_or_else(<$actor_name as $crate::Actor>::create);
                let mut ctx =
                    $crate::Context::<$actor_name>::new($crate::actors::context::ServiceId(0));
                let _ = $crate::run_blocking(actor.on_start(&mut ctx));
                let state = Box::new(WasmState {
                    actor,
                    ctx,
                    in_flight: None,
                    last_reply: None,
                });
                Box::into_raw(state) as u32
            }

            #[unsafe(no_mangle)]
            pub extern "C" fn vos_wasm_state(state: u32) -> u64 {
                use $crate::Encode;
                let ws = unsafe { &*(state as *const WasmState) };
                let mut bytes = ws.actor.encode();
                bytes.shrink_to_fit();
                let len = bytes.len();
                let ptr = bytes.as_mut_ptr();
                core::mem::forget(bytes);
                pack_buf(ptr as u32, len as u32)
            }

            #[unsafe(no_mangle)]
            pub extern "C" fn vos_wasm_encode_msg(desc_ptr: u32, desc_len: u32) -> u64 {
                if desc_ptr == 0 || desc_len == 0 {
                    return 0;
                }
                let desc = unsafe {
                    core::slice::from_raw_parts(desc_ptr as *const u8, desc_len as usize)
                };
                let Some(msg) = $crate::value::desc::decode_msg(desc) else {
                    return 0;
                };
                use $crate::Encode;
                let encoded = msg.encode();
                let mut out: Vec<u8> = Vec::with_capacity(1 + encoded.len());
                out.push($crate::value::TAG_DYNAMIC);
                out.extend_from_slice(&encoded);
                out.shrink_to_fit();
                let len = out.len();
                let ptr = out.as_mut_ptr();
                core::mem::forget(out);
                pack_buf(ptr as u32, len as u32)
            }

            /// Encode an ArgsDesc into rkyv-encoded `Args` bytes, ready
            /// to pass to `vos_wasm_create` as init args.
            #[unsafe(no_mangle)]
            pub extern "C" fn vos_wasm_encode_args(desc_ptr: u32, desc_len: u32) -> u64 {
                if desc_ptr == 0 || desc_len == 0 {
                    return 0;
                }
                let desc = unsafe {
                    core::slice::from_raw_parts(desc_ptr as *const u8, desc_len as usize)
                };
                let Some(args) = $crate::value::desc::decode_args(desc) else {
                    return 0;
                };
                use $crate::Encode;
                let mut encoded = args.encode();
                encoded.shrink_to_fit();
                let len = encoded.len();
                let ptr = encoded.as_mut_ptr();
                core::mem::forget(encoded);
                pack_buf(ptr as u32, len as u32)
            }

            /// Decode a checked rkyv `Value` into the JS-friendly ValueDesc format.
            #[unsafe(no_mangle)]
            pub extern "C" fn vos_wasm_decode_value(value_ptr: u32, value_len: u32) -> u64 {
                if value_ptr == 0 || value_len == 0 {
                    return 0;
                }
                let bytes = unsafe {
                    core::slice::from_raw_parts(value_ptr as *const u8, value_len as usize)
                };
                let Some(value) = <$crate::value::Value as $crate::Decode>::try_decode(bytes)
                else {
                    return 0;
                };
                let mut out = $crate::value::desc::encode_value(&value);
                out.shrink_to_fit();
                let len = out.len();
                let ptr = out.as_mut_ptr();
                core::mem::forget(out);
                pack_buf(ptr as u32, len as u32)
            }
        }
    };
}

#[cfg(not(feature = "wasm"))]
#[macro_export]
#[doc(hidden)]
macro_rules! __vos_emit_wasm_glue {
    ($($_:tt)*) => {};
}
