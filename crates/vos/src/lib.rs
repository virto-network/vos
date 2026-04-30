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

#[cfg(feature = "storage")]
pub mod raft;

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

/// Emit the native worker plugin (`vos_worker_*` extern fns).
/// Active when `vos` is built with the `worker` feature; otherwise
/// expands to nothing.
#[cfg(feature = "worker")]
#[macro_export]
#[doc(hidden)]
macro_rules! __vos_emit_worker_glue {
    ($actor_name:path, $enum_name:path) => {
        impl $crate::WorkerActor for $actor_name {}

        #[allow(unused_imports)]
        use $crate::WorkerCtx as _;

        mod __vos_worker {
            use super::*;
            use core::future::Future;
            use core::pin::Pin;

            struct WorkerState {
                actor: $actor_name,
                ctx: $crate::Context<$actor_name>,
                in_flight: Option<Pin<Box<dyn Future<Output = bool>>>>,
            }

            static _VOS_WORKER_META: [u8; _VOS_META_ENCODED.1] = {
                let (src, len) = _VOS_META_ENCODED;
                let mut out = [0u8; _VOS_META_ENCODED.1];
                let mut i = 0;
                while i < len { out[i] = src[i]; i += 1; }
                out
            };

            #[unsafe(no_mangle)]
            pub extern "C" fn vos_worker_meta(
                out_ptr: *mut *const u8,
                out_len: *mut usize,
            ) {
                unsafe {
                    *out_ptr = _VOS_WORKER_META.as_ptr();
                    *out_len = _VOS_WORKER_META.len();
                }
            }

            #[unsafe(no_mangle)]
            pub extern "C" fn vos_worker_create(
                args_ptr: *const u8,
                args_len: usize,
            ) -> *mut () {
                use $crate::Actor as _;
                let mut actor = if args_ptr.is_null() || args_len == 0 {
                    <$actor_name as $crate::Actor>::create()
                } else {
                    let args_bytes = unsafe {
                        core::slice::from_raw_parts(args_ptr, args_len)
                    };
                    <$actor_name>::__vos_create_with_args(args_bytes)
                };
                let mut ctx = $crate::Context::<$actor_name>::new(
                    $crate::actors::context::ServiceId(0),
                );
                let _ = $crate::run_blocking(actor.on_start(&mut ctx));
                let state = Box::new(WorkerState {
                    actor,
                    ctx,
                    in_flight: None,
                });
                Box::into_raw(state) as *mut ()
            }

            #[unsafe(no_mangle)]
            pub extern "C" fn vos_worker_dispatch(
                state: *mut (),
                msg_ptr: *const u8,
                msg_len: usize,
            ) {
                let ws = unsafe { &mut *(state as *mut WorkerState) };
                let raw = unsafe { core::slice::from_raw_parts(msg_ptr, msg_len) };

                let msg = if !raw.is_empty() && raw[0] == $crate::value::TAG_DYNAMIC {
                    let dynamic: $crate::value::Msg = $crate::Decode::decode(&raw[1..]);
                    match <$enum_name as $crate::value::FromDynamic>::from_dynamic(&dynamic) {
                        Some(m) => m,
                        None => return,
                    }
                } else {
                    $crate::Decode::decode(raw)
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
            pub extern "C" fn vos_worker_poll(
                state: *mut (),
            ) -> $crate::worker::WorkerPollResult {
                let ws = unsafe { &mut *(state as *mut WorkerState) };
                let Some(future) = ws.in_flight.as_mut() else {
                    return $crate::worker::WorkerPollResult::error(
                        $crate::worker::POLL_ERR_NO_FUTURE,
                    );
                };

                let waker = $crate::__worker::noop_waker();
                let mut cx = core::task::Context::from_waker(&waker);
                match future.as_mut().poll(&mut cx) {
                    core::task::Poll::Ready(_stop) => {
                        ws.in_flight = None;
                        let reply_bytes = ws.ctx.take_reply_bytes();
                        if reply_bytes.is_empty() {
                            $crate::worker::WorkerPollResult::ready_empty()
                        } else {
                            $crate::worker::WorkerPollResult::ready(reply_bytes)
                        }
                    }
                    core::task::Poll::Pending => {
                        $crate::worker::WorkerPollResult::pending()
                    }
                }
            }

            #[unsafe(no_mangle)]
            pub extern "C" fn vos_worker_pending_effect(
                state: *mut (),
                out_ptr: *mut *const u8,
                out_len: *mut usize,
            ) {
                let ws = unsafe { &mut *(state as *mut WorkerState) };
                if let Some(request) = ws.ctx.peek_host_io_request() {
                    unsafe {
                        *out_ptr = request.as_ptr();
                        *out_len = request.len();
                    }
                } else {
                    unsafe {
                        *out_ptr = core::ptr::null();
                        *out_len = 0;
                    }
                }
            }

            #[unsafe(no_mangle)]
            pub extern "C" fn vos_worker_provide_result(
                state: *mut (),
                ptr: *const u8,
                len: usize,
            ) {
                let ws = unsafe { &mut *(state as *mut WorkerState) };
                let result = if ptr.is_null() || len == 0 {
                    Vec::new()
                } else {
                    unsafe { core::slice::from_raw_parts(ptr, len) }.to_vec()
                };
                ws.ctx.set_host_io_result(result);
            }

            #[unsafe(no_mangle)]
            pub extern "C" fn vos_worker_drop(state: *mut ()) {
                if !state.is_null() {
                    unsafe { drop(Box::from_raw(state as *mut WorkerState)) };
                }
            }

            #[unsafe(no_mangle)]
            pub extern "C" fn vos_worker_free(ptr: *mut u8, len: usize, cap: usize) {
                if !ptr.is_null() && cap > 0 {
                    unsafe { drop(Vec::from_raw_parts(ptr, len, cap)) };
                }
            }

            #[unsafe(no_mangle)]
            pub extern "C" fn vos_worker_load(
                state_ptr: *const u8,
                state_len: usize,
            ) -> *mut () {
                use $crate::Actor as _;
                let bytes = unsafe {
                    core::slice::from_raw_parts(state_ptr, state_len)
                };
                let mut actor: $actor_name = $crate::Decode::try_decode(bytes)
                    .unwrap_or_else(<$actor_name as $crate::Actor>::create);
                let mut ctx = $crate::Context::<$actor_name>::new(
                    $crate::actors::context::ServiceId(0),
                );
                let _ = $crate::run_blocking(actor.on_start(&mut ctx));
                let state = Box::new(WorkerState {
                    actor,
                    ctx,
                    in_flight: None,
                });
                Box::into_raw(state) as *mut ()
            }

            #[unsafe(no_mangle)]
            pub extern "C" fn vos_worker_state(
                state: *mut (),
                out_ptr: *mut *mut u8,
                out_len: *mut usize,
            ) {
                use $crate::Encode;
                let ws = unsafe { &*(state as *const WorkerState) };
                let mut bytes = ws.actor.encode();
                bytes.shrink_to_fit();
                unsafe {
                    *out_ptr = bytes.as_mut_ptr();
                    *out_len = bytes.len();
                }
                core::mem::forget(bytes);
            }
        }
    };
}

#[cfg(not(feature = "worker"))]
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
                while i < len { out[i] = src[i]; i += 1; }
                out
            };

            #[inline]
            fn pack_buf(ptr: u32, len: u32) -> u64 {
                ((ptr as u64) << 32) | (len as u64)
            }

            #[unsafe(no_mangle)]
            pub extern "C" fn vos_wasm_meta() -> u64 {
                pack_buf(
                    _VOS_WASM_META.as_ptr() as u32,
                    _VOS_WASM_META.len() as u32,
                )
            }

            #[unsafe(no_mangle)]
            pub extern "C" fn vos_wasm_alloc(size: u32) -> u32 {
                let mut buf: Vec<u8> = Vec::with_capacity(size as usize);
                unsafe { buf.set_len(size as usize); }
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
                let mut ctx = $crate::Context::<$actor_name>::new(
                    $crate::actors::context::ServiceId(0),
                );
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
                let raw = unsafe {
                    core::slice::from_raw_parts(msg_ptr as *const u8, msg_len as usize)
                };

                let msg = if !raw.is_empty() && raw[0] == $crate::value::TAG_DYNAMIC {
                    let dynamic: $crate::value::Msg = $crate::Decode::decode(&raw[1..]);
                    match <$enum_name as $crate::value::FromDynamic>::from_dynamic(&dynamic) {
                        Some(m) => m,
                        None => return,
                    }
                } else {
                    $crate::Decode::decode(raw)
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
                let waker = $crate::__worker::noop_waker();
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
                    unsafe {
                        core::slice::from_raw_parts(ptr as *const u8, len as usize)
                    }.to_vec()
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
                let mut ctx = $crate::Context::<$actor_name>::new(
                    $crate::actors::context::ServiceId(0),
                );
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
                if desc_ptr == 0 || desc_len == 0 { return 0; }
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
        }
    };
}

#[cfg(not(feature = "wasm"))]
#[macro_export]
#[doc(hidden)]
macro_rules! __vos_emit_wasm_glue {
    ($($_:tt)*) => {};
}

/// Emit the host-side typed `Client` struct + impl. Active when
/// `vos` is built with `std` (the Client requires `vos::node::VosNode`).
/// The user crate's `host` feature is no longer involved — it
/// remains available for the user crate's own optional deps.
#[cfg(feature = "std")]
#[macro_export]
#[doc(hidden)]
macro_rules! __vos_emit_host_client {
    {
        struct_name: $name:ident;
        methods: { $($body:tt)* }
    } => {
        pub struct $name<'a> {
            node: &'a $crate::node::VosNode,
            target: $crate::abi::service::ServiceId,
        }

        impl<'a> $name<'a> {
            pub fn at(
                node: &'a $crate::node::VosNode,
                target: $crate::abi::service::ServiceId,
            ) -> Self {
                Self { node, target }
            }

            $($body)*
        }
    };
}

#[cfg(not(feature = "std"))]
#[macro_export]
#[doc(hidden)]
macro_rules! __vos_emit_host_client {
    ($($_:tt)*) => {};
}
