//! Extension ABI and host-side runtime for native actor plugins.
//!
//! Extensions are native shared libraries (`.so`) that use the same
//! `#[actor]`/`#[messages]` DSL as PVM actors but run natively with
//! full OS access. They communicate with PVM actors through the same
//! rkyv-encoded message format.
//!
//! ## Poll-based async C ABI
//!
//! Each extension `.so` exports these symbols:
//!
//! - `vos_extension_meta` — returns a pointer to the `.vos_meta` blob
//! - `vos_extension_create` — allocates an extension instance (actor + context)
//! - `vos_extension_dispatch` — starts handling a message (stores future)
//! - `vos_extension_poll` — polls the in-flight handler once
//! - `vos_extension_pending_effect` — reads the pending host I/O request
//! - `vos_extension_provide_result` — provides the host I/O result
//! - `vos_extension_drop` — frees an extension instance
//! - `vos_extension_free` — frees a reply buffer
//!
//! The host drives the handler by polling repeatedly. When the handler
//! needs I/O (e.g. `ctx.ask()`), it yields `Pending` and the host
//! reads the request via `pending_effect`, fulfills it, writes back
//! via `provide_result`, then re-polls.
//!
//! ## Extension feature
//!
//! Crates compiled with `features = ["extension"]` get these symbols
//! generated automatically by the `#[messages]` macro.

use alloc::vec::Vec;

/// What kind of extension this is — `Actor` (request-driven, the
/// default) or `Service` (long-running, owns its own thread).
///
/// Encoded as a trailing byte in the `.vos_meta` blob;
/// pre-discriminant blobs default to `Actor`. The loader
/// dispatches into the matching symbol set in
/// `run_service_extension` / actor-mode `extension_thread`.
#[repr(u8)]
#[derive(Clone, Copy, Debug, PartialEq, Eq, Default)]
pub enum ExtensionKind {
    /// Request-driven: handler runs to completion per-dispatch.
    /// Today's behavior. The default for unspecified or
    /// previously-encoded metadata blobs.
    #[default]
    Actor = 0,
    /// Long-running: extension owns a thread + originates calls
    /// via a host-given `ServiceCtx`. Reserved — the loader does
    /// not yet route based on this value.
    Service = 1,
}

impl ExtensionKind {
    /// Decode a metadata `kind` byte. Unknown values fall back to
    /// `Actor` so newer extension blobs stay loadable on older
    /// hosts.
    pub const fn from_byte(b: u8) -> Self {
        match b {
            1 => Self::Service,
            _ => Self::Actor,
        }
    }
}

/// Result of polling a extension handler, returned across the C ABI.
#[repr(C)]
pub struct ExtensionPollResult {
    /// Status: 0 = ready, 1 = pending (need host I/O), <0 = error.
    pub status: i32,
    /// Reply bytes (only valid when status == READY).
    pub ptr: *mut u8,
    pub len: usize,
    pub cap: usize,
}

pub const POLL_READY: i32 = 0;
pub const POLL_PENDING: i32 = 1;
pub const POLL_ERR_HANDLER: i32 = -1;
pub const POLL_ERR_DECODE: i32 = -2;
pub const POLL_ERR_NO_FUTURE: i32 = -3;

impl ExtensionPollResult {
    /// Handler completed with a reply.
    pub fn ready(bytes: Vec<u8>) -> Self {
        let mut bytes = core::mem::ManuallyDrop::new(bytes);
        ExtensionPollResult {
            status: POLL_READY,
            ptr: bytes.as_mut_ptr(),
            len: bytes.len(),
            cap: bytes.capacity(),
        }
    }

    /// Handler completed with no reply.
    pub fn ready_empty() -> Self {
        ExtensionPollResult {
            status: POLL_READY,
            ptr: core::ptr::null_mut(),
            len: 0,
            cap: 0,
        }
    }

    /// Handler yielded — needs host I/O. Call `pending_effect` to read
    /// the request, then `provide_result`, then re-poll.
    pub fn pending() -> Self {
        ExtensionPollResult {
            status: POLL_PENDING,
            ptr: core::ptr::null_mut(),
            len: 0,
            cap: 0,
        }
    }

    /// Error during dispatch.
    pub fn error(status: i32) -> Self {
        ExtensionPollResult {
            status,
            ptr: core::ptr::null_mut(),
            len: 0,
            cap: 0,
        }
    }
}

// ── Service-mode C ABI (Phase 3) ───────────────────────────────────────
//
// `kind = "service"` extensions own their thread + originate calls to
// other actors via a host-given `ServiceCtx`. The host hands the
// extension a `*const HostCtxHandle` pointing at its own state plus a
// vtable of callbacks the extension uses to send / receive / check
// shutdown. Function-pointer dispatch (vs symbol resolution against
// the host process) keeps the .so independent of how the host process
// exports its own symbols.

/// Host-side reply / envelope buffer. The host allocates; the
/// extension reads the bytes; the extension calls `free_buf` when
/// done so the host can deallocate. (The vtable's `free_buf` knows
/// the layout — extensions must NOT use the system allocator on
/// these pointers.)
#[repr(C)]
#[derive(Clone, Copy)]
pub struct RecvBuf {
    pub ptr: *mut u8,
    pub len: usize,
    pub cap: usize,
}

impl RecvBuf {
    pub const fn empty() -> Self {
        Self {
            ptr: core::ptr::null_mut(),
            len: 0,
            cap: 0,
        }
    }
    pub fn is_empty(&self) -> bool {
        self.ptr.is_null() || self.len == 0
    }
}

/// Host-side envelope (sender + payload). Returned by
/// `recv_envelope` for control messages addressed to the service
/// extension that aren't replies to a pending `ask`.
#[repr(C)]
#[derive(Clone, Copy)]
pub struct RecvEnv {
    /// Sender ServiceId (raw u32 form).
    pub from: u32,
    /// Payload bytes — owned by the host until `free_buf`.
    pub payload: RecvBuf,
}

impl RecvEnv {
    pub const fn empty() -> Self {
        Self {
            from: 0,
            payload: RecvBuf::empty(),
        }
    }
}

/// Status codes returned by host-vtable callbacks. `0 = ok`,
/// `1 = timeout`, `< 0 = error`.
pub const HOST_OK: i32 = 0;
pub const HOST_TIMEOUT: i32 = 1;
pub const HOST_ERR_DISCONNECTED: i32 = -1;
pub const HOST_ERR_INVALID: i32 = -2;

/// Vtable exposed by the host to service-mode extensions. Each fn
/// takes the opaque `*mut HostCtx` as its first arg so the host can
/// recover its private state.
#[repr(C)]
pub struct HostVTable {
    /// Send a payload to `target`. Returns `HOST_OK` on enqueue,
    /// `HOST_ERR_DISCONNECTED` if the host's outbox is closed.
    pub send: unsafe extern "C" fn(
        host: *mut core::ffi::c_void,
        target: u32,
        payload: *const u8,
        len: usize,
    ) -> i32,
    /// Block until a reply from `target` arrives or `timeout_ms`
    /// elapses. Writes the reply into `out`. Caller frees via
    /// `free_buf`. `timeout_ms = 0` blocks forever (until shutdown).
    pub recv_reply: unsafe extern "C" fn(
        host: *mut core::ffi::c_void,
        target: u32,
        timeout_ms: u64,
        out: *mut RecvBuf,
    ) -> i32,
    /// Block until a non-reply envelope arrives or `timeout_ms`
    /// elapses. Writes the envelope into `out`. Caller frees the
    /// payload buffer via `free_buf`.
    pub recv_envelope: unsafe extern "C" fn(
        host: *mut core::ffi::c_void,
        timeout_ms: u64,
        out: *mut RecvEnv,
    ) -> i32,
    /// Non-blocking check: has the host signalled shutdown? Service
    /// extensions should poll this between blocking operations and
    /// exit `run` cleanly when it returns `true`.
    pub shutdown_signaled: unsafe extern "C" fn(host: *mut core::ffi::c_void) -> bool,
    /// Free a buffer previously handed to the extension by
    /// `recv_reply` / `recv_envelope` / `invoke`.
    pub free_buf: unsafe extern "C" fn(ptr: *mut u8, len: usize, cap: usize),
    /// This extension's own ServiceId (raw u32). Read-only.
    pub me: unsafe extern "C" fn(host: *mut core::ffi::c_void) -> u32,
    /// Sync invoke RPC: send `payload` to `target`, block until the
    /// reply arrives (or `timeout_ms` elapses, or shutdown). Writes
    /// the reply into `out`; caller frees via `free_buf`.
    /// `timeout_ms = 0` blocks until shutdown. Use this for
    /// `ask`-style dispatch — works for both PVM agents (which
    /// reply through the invoke channel only) and actor-mode
    /// extensions (which support both invoke and envelope replies).
    pub invoke: unsafe extern "C" fn(
        host: *mut core::ffi::c_void,
        target: u32,
        payload: *const u8,
        len: usize,
        timeout_ms: u64,
        out: *mut RecvBuf,
    ) -> i32,
}

/// Bundle of host state + vtable handed to a service extension's
/// `vos_extension_run` entry. The extension only needs to dereference
/// to call methods.
#[repr(C)]
pub struct HostCtxHandle {
    pub state: *mut core::ffi::c_void,
    pub vtable: *const HostVTable,
}

// SAFETY: HostCtxHandle is just two pointers; the underlying state
// is `Sync` by host-side design (Mutex-guarded).
unsafe impl Send for HostCtxHandle {}
unsafe impl Sync for HostCtxHandle {}

/// Safe Rust wrapper that service extensions use to talk back to the
/// host. Constructed inside the macro-emitted `vos_extension_run`
/// from the raw `*const HostCtxHandle` the host passes in.
///
/// All methods are `&self` — internal serialization is the host's
/// responsibility (the vtable callbacks lock the appropriate
/// internal channels). One in-flight `ask` per `ServiceCtx` clone
/// at a time; concurrent callers are serialized inside the host.
#[derive(Clone, Copy)]
pub struct ServiceCtx {
    handle: *const HostCtxHandle,
}

// SAFETY: ServiceCtx is a wrapper around a pointer to a host-owned
// struct; the host guarantees the pointer outlives the extension's
// `run` invocation, and the underlying state is internally
// synchronised.
unsafe impl Send for ServiceCtx {}
unsafe impl Sync for ServiceCtx {}

impl ServiceCtx {
    /// Build a `ServiceCtx` from a raw `*const HostCtxHandle`. Called
    /// by macro-generated `vos_extension_run` glue. **Unsafe** because
    /// the caller must ensure `handle` points at a live HostCtxHandle
    /// for the entire duration of the wrapping struct.
    ///
    /// # Safety
    /// `handle` must outlive every clone of the returned `ServiceCtx`.
    pub const unsafe fn from_raw(handle: *const HostCtxHandle) -> Self {
        Self { handle }
    }

    fn vtable(&self) -> &HostVTable {
        // SAFETY: vtable is a 'static reference set up by the host;
        // see service_thread in node.rs.
        unsafe { &*(*self.handle).vtable }
    }

    fn host_state(&self) -> *mut core::ffi::c_void {
        // SAFETY: same as vtable.
        unsafe { (*self.handle).state }
    }

    /// Send a payload to `target` and block until its reply arrives
    /// (or the host signals shutdown). Returns `None` on shutdown
    /// or transport error.
    pub fn ask_raw(&self, target: u32, payload: &[u8]) -> Option<Vec<u8>> {
        self.ask_raw_with_timeout(target, payload, 0)
    }

    /// Same as `ask_raw` but with a per-call timeout in milliseconds.
    /// `0 = no timeout` (block until reply or shutdown). Goes
    /// through the host-supplied sync invoke channel — works for
    /// both PVM agents (which only reply through invoke) and
    /// actor-mode extensions (which also support envelope replies).
    /// The legacy `send`/`recv_reply` vtable callbacks stay live
    /// for fire-and-forget patterns and the existing tests, but
    /// aren't on the ask hot path.
    pub fn ask_raw_with_timeout(
        &self,
        target: u32,
        payload: &[u8],
        timeout_ms: u64,
    ) -> Option<Vec<u8>> {
        let vtable = self.vtable();
        let host = self.host_state();
        let mut out = RecvBuf::empty();
        // SAFETY: vtable + handle remain live for the lifetime of
        // ServiceCtx (the host promises this in `from_raw`).
        let status = unsafe {
            (vtable.invoke)(
                host,
                target,
                payload.as_ptr(),
                payload.len(),
                timeout_ms,
                &mut out as *mut RecvBuf,
            )
        };
        if status != HOST_OK {
            return None;
        }
        // HOST_OK means a reply arrived — even empty payload is
        // valid (unit-returning handler, or dispatch-error recovery
        // from the worker glue's catch_unwind). Distinct from None,
        // which means transport error / shutdown / no reply.
        if out.is_empty() {
            return Some(Vec::new());
        }
        let bytes = unsafe { core::slice::from_raw_parts(out.ptr, out.len) }.to_vec();
        unsafe { (vtable.free_buf)(out.ptr, out.len, out.cap) };
        Some(bytes)
    }

    /// Block waiting for a non-reply envelope addressed to this
    /// extension. Returns `None` on timeout or shutdown.
    pub fn recv_envelope(&self, timeout_ms: u64) -> Option<(u32, Vec<u8>)> {
        let vtable = self.vtable();
        let host = self.host_state();
        let mut out = RecvEnv::empty();
        let status = unsafe { (vtable.recv_envelope)(host, timeout_ms, &mut out as *mut RecvEnv) };
        if status != HOST_OK || out.payload.is_empty() {
            return None;
        }
        let bytes =
            unsafe { core::slice::from_raw_parts(out.payload.ptr, out.payload.len) }.to_vec();
        unsafe { (vtable.free_buf)(out.payload.ptr, out.payload.len, out.payload.cap) };
        Some((out.from, bytes))
    }

    /// Has the host signalled shutdown? Service extensions should
    /// poll this from their run loop and exit cleanly when it
    /// returns `true`.
    pub fn is_shutdown(&self) -> bool {
        let vtable = self.vtable();
        let host = self.host_state();
        unsafe { (vtable.shutdown_signaled)(host) }
    }

    /// This extension's own ServiceId (raw `u32`). The high 16 bits
    /// are the node prefix; the low 16 bits are the local id.
    /// Useful when the extension needs to identify itself to other
    /// actors — e.g. the http-gateway passes
    /// `caller_prefix = me() >> 16` to the registry's `resolve` so
    /// the registry can derive agent ServiceIds in the gateway's
    /// node namespace.
    pub fn me(&self) -> u32 {
        let vtable = self.vtable();
        let host = self.host_state();
        unsafe { (vtable.me)(host) }
    }
}

// ── Host-side extension loader (std only) ──────────────────────────────

#[cfg(feature = "std")]
mod host {
    use super::{ExtensionKind, ExtensionPollResult, HostCtxHandle};
    use crate::actors::metadata::ParsedMeta;

    /// Type signatures for the C ABI functions exported by extension `.so` files.
    type MetaFn = unsafe extern "C" fn(out_ptr: *mut *const u8, out_len: *mut usize);
    type CreateFn = unsafe extern "C" fn(args_ptr: *const u8, args_len: usize) -> *mut ();
    type DispatchFn = unsafe extern "C" fn(state: *mut (), msg: *const u8, msg_len: usize);
    type PollFn = unsafe extern "C" fn(state: *mut ()) -> ExtensionPollResult;
    type PendingEffectFn =
        unsafe extern "C" fn(state: *mut (), out_ptr: *mut *const u8, out_len: *mut usize);
    type ProvideResultFn = unsafe extern "C" fn(state: *mut (), ptr: *const u8, len: usize);
    type DropFn = unsafe extern "C" fn(state: *mut ());
    type FreeFn = unsafe extern "C" fn(ptr: *mut u8, len: usize, cap: usize);
    type LoadFn = unsafe extern "C" fn(state_ptr: *const u8, state_len: usize) -> *mut ();
    type StateFn = unsafe extern "C" fn(state: *mut (), out_ptr: *mut *mut u8, out_len: *mut usize);
    /// Service-mode entry: `vos_extension_run(state, handle) -> i32`.
    /// Blocks the calling thread until the extension's run loop
    /// returns. Status: 0 = clean exit, < 0 = error.
    type RunFn = unsafe extern "C" fn(state: *mut (), handle: *const HostCtxHandle) -> i32;

    /// Service-mode per-invoke dispatch (Phase 5): `vos_service_handle_invoke`.
    /// Optional symbol — service-mode extensions opt in by exporting it.
    /// The host's run_service_extension sidecar thread calls this for
    /// each incoming invoke targeted at the extension's ServiceId,
    /// independently of `run()` (so HTTP-serving loops keep running).
    /// Reply bytes ride back in `ExtensionPollResult.ptr/len/cap`;
    /// `POLL_ERR_NO_FUTURE` means "no matching handler"; the host
    /// frees the buffer via `vos_extension_free` afterwards. The
    /// extension *must* be thread-safe across the run-thread / this
    /// sidecar thread when the symbol is exported.
    type DispatchInvokeFn = unsafe extern "C" fn(
        state: *mut (),
        msg_ptr: *const u8,
        msg_len: usize,
    ) -> ExtensionPollResult;

    /// A loaded extension plugin. Holds either the actor-mode symbol
    /// set or the service-mode set, depending on what the .so
    /// declared via `kind` in its meta blob.
    pub struct ExtensionPlugin {
        _lib: libloading::Library,
        // Always present.
        create_fn: CreateFn,
        drop_fn: DropFn,
        meta_bytes: Vec<u8>,
        kind: ExtensionKind,
        // Actor-mode symbols. Some(...) only for `kind = Actor`.
        actor: Option<ActorSymbols>,
        // Service-mode symbols. Some(...) only for `kind = Service`.
        service: Option<ServiceSymbols>,
    }

    struct ActorSymbols {
        dispatch_fn: DispatchFn,
        poll_fn: PollFn,
        pending_effect_fn: PendingEffectFn,
        provide_result_fn: ProvideResultFn,
        free_fn: FreeFn,
        load_fn: LoadFn,
        state_fn: StateFn,
    }

    struct ServiceSymbols {
        run_fn: RunFn,
        /// Optional: when present, the daemon spawns a sidecar
        /// thread that consumes the extension's invoke queue and
        /// dispatches each request through this fn. Service-mode
        /// extensions that don't export it remain unreachable
        /// via `vosx <ext> <method>` (Phase 5+ behaviour); their
        /// inbound invokes still pile up in the channel and the
        /// caller times out.
        dispatch_invoke_fn: Option<DispatchInvokeFn>,
        /// Required when `dispatch_invoke_fn` is present — the
        /// host frees the reply buffer the extension produced.
        /// Same shape as the actor-mode `vos_extension_free`.
        free_fn: Option<FreeFn>,
    }

    impl ExtensionPlugin {
        /// Load an extension from a shared library path.
        ///
        /// Reads `vos_extension_meta` first, decodes the kind byte,
        /// then loads either the actor-mode or service-mode symbol
        /// set.
        ///
        /// # Safety
        /// The `.so` must export the correct C ABI symbols for its
        /// declared kind.
        pub unsafe fn load(path: &std::path::Path) -> Result<Self, String> {
            let lib = unsafe {
                libloading::Library::new(path)
                    .map_err(|e| format!("failed to load {}: {e}", path.display()))?
            };

            unsafe {
                let meta_fn = *lib
                    .get::<MetaFn>(b"vos_extension_meta")
                    .map_err(|e| format!("missing vos_extension_meta: {e}"))?;
                let create_fn = *lib
                    .get::<CreateFn>(b"vos_extension_create")
                    .map_err(|e| format!("missing vos_extension_create: {e}"))?;
                let drop_fn = *lib
                    .get::<DropFn>(b"vos_extension_drop")
                    .map_err(|e| format!("missing vos_extension_drop: {e}"))?;

                // Read metadata first so we know which kind-specific
                // symbol set to expect.
                let mut meta_ptr: *const u8 = std::ptr::null();
                let mut meta_len: usize = 0;
                meta_fn(&mut meta_ptr, &mut meta_len);
                let meta_bytes = if !meta_ptr.is_null() && meta_len > 0 {
                    std::slice::from_raw_parts(meta_ptr, meta_len).to_vec()
                } else {
                    Vec::new()
                };

                let kind = crate::actors::metadata::decode(&meta_bytes)
                    .map(|m| ExtensionKind::from_byte(m.kind))
                    .unwrap_or(ExtensionKind::Actor);

                let (actor, service) = match kind {
                    ExtensionKind::Actor => {
                        let dispatch_fn = *lib
                            .get::<DispatchFn>(b"vos_extension_dispatch")
                            .map_err(|e| format!("missing vos_extension_dispatch: {e}"))?;
                        let poll_fn = *lib
                            .get::<PollFn>(b"vos_extension_poll")
                            .map_err(|e| format!("missing vos_extension_poll: {e}"))?;
                        let pending_effect_fn = *lib
                            .get::<PendingEffectFn>(b"vos_extension_pending_effect")
                            .map_err(|e| format!("missing vos_extension_pending_effect: {e}"))?;
                        let provide_result_fn = *lib
                            .get::<ProvideResultFn>(b"vos_extension_provide_result")
                            .map_err(|e| format!("missing vos_extension_provide_result: {e}"))?;
                        let free_fn = *lib
                            .get::<FreeFn>(b"vos_extension_free")
                            .map_err(|e| format!("missing vos_extension_free: {e}"))?;
                        let load_fn = *lib
                            .get::<LoadFn>(b"vos_extension_load")
                            .map_err(|e| format!("missing vos_extension_load: {e}"))?;
                        let state_fn = *lib
                            .get::<StateFn>(b"vos_extension_state")
                            .map_err(|e| format!("missing vos_extension_state: {e}"))?;
                        (
                            Some(ActorSymbols {
                                dispatch_fn,
                                poll_fn,
                                pending_effect_fn,
                                provide_result_fn,
                                free_fn,
                                load_fn,
                                state_fn,
                            }),
                            None,
                        )
                    }
                    ExtensionKind::Service => {
                        let run_fn = *lib
                            .get::<RunFn>(b"vos_extension_run")
                            .map_err(|e| format!("missing vos_extension_run: {e}"))?;
                        // Phase 5 invoke dispatch is optional —
                        // service extensions that don't declare
                        // `#[msg(cli)]` handlers just don't export
                        // these symbols and stay reachable only via
                        // their `run()` loop's external channels
                        // (HTTP, etc.). When `dispatch_invoke_fn`
                        // is present we also require `free_fn` so
                        // the host can reclaim reply buffers.
                        let dispatch_invoke_fn = lib
                            .get::<DispatchInvokeFn>(b"vos_service_handle_invoke")
                            .ok()
                            .map(|s| *s);
                        let free_fn = lib.get::<FreeFn>(b"vos_extension_free").ok().map(|s| *s);
                        if dispatch_invoke_fn.is_some() && free_fn.is_none() {
                            return Err("service extension exports vos_service_handle_invoke but \
                                 not vos_extension_free; both must be present for the host \
                                 to reclaim reply buffers"
                                .to_string());
                        }
                        (
                            None,
                            Some(ServiceSymbols {
                                run_fn,
                                dispatch_invoke_fn,
                                free_fn,
                            }),
                        )
                    }
                };

                Ok(ExtensionPlugin {
                    _lib: lib,
                    create_fn,
                    drop_fn,
                    meta_bytes,
                    kind,
                    actor,
                    service,
                })
            }
        }

        /// Which kind the loaded extension declared.
        pub fn kind(&self) -> ExtensionKind {
            self.kind
        }

        /// Parse the extension's actor metadata.
        pub fn meta(&self) -> Option<ParsedMeta> {
            crate::actors::metadata::decode(&self.meta_bytes)
        }

        /// Raw bytes from `vos_extension_meta` — the same blob
        /// `meta()` decodes. Forwarded verbatim by `vosx reconcile`
        /// to the registry's `register_extension_meta` so downstream
        /// consumers (`vosx <ext> <cmd>`) can decode against the same
        /// `vos::metadata` definition the producer used. `load()`
        /// errors out when the `.so` lacks `vos_extension_meta`, so
        /// reaching this accessor means the symbol was found; bytes
        /// can still be empty if the function returned a null
        /// pointer or zero length.
        pub fn meta_bytes(&self) -> &[u8] {
            &self.meta_bytes
        }

        /// Create a new extension instance with no init args.
        pub fn create(&self) -> ExtensionInstance<'_> {
            let state = unsafe { (self.create_fn)(std::ptr::null(), 0) };
            ExtensionInstance {
                plugin: self,
                state,
            }
        }

        /// Create a new extension instance with rkyv-encoded init args.
        pub fn create_with_args(&self, args: &[u8]) -> ExtensionInstance<'_> {
            let state = unsafe { (self.create_fn)(args.as_ptr(), args.len()) };
            ExtensionInstance {
                plugin: self,
                state,
            }
        }

        /// Restore an extension instance from previously serialized state.
        /// Actor-mode only.
        pub fn load_state(&self, state: &[u8]) -> ExtensionInstance<'_> {
            let load_fn = self.actor_syms().load_fn;
            let s = unsafe { load_fn(state.as_ptr(), state.len()) };
            ExtensionInstance {
                plugin: self,
                state: s,
            }
        }

        fn actor_syms(&self) -> &ActorSymbols {
            self.actor
                .as_ref()
                .expect("ExtensionPlugin: actor-mode method called on service-mode plugin")
        }

        fn service_syms(&self) -> &ServiceSymbols {
            self.service
                .as_ref()
                .expect("ExtensionPlugin: service-mode method called on actor-mode plugin")
        }

        /// Run a service-mode extension to completion. Blocks the
        /// calling thread until the extension's `run` returns.
        /// Returns the exit status (0 = clean, < 0 = error).
        ///
        /// # Safety
        /// `state` must be a live extension instance produced by this
        /// plugin's `create_state`. `handle` must point at a host
        /// context handle whose vtable + state remain live for the
        /// duration of the call.
        pub unsafe fn run_service(&self, state: *mut (), handle: *const HostCtxHandle) -> i32 {
            let run_fn = self.service_syms().run_fn;
            unsafe { run_fn(state, handle) }
        }

        /// `true` when this service-mode plugin exports
        /// `vos_service_handle_invoke`. Used by the daemon to decide
        /// whether to spawn the sidecar dispatch thread for the
        /// extension's invoke queue.
        pub fn service_has_invoke_dispatch(&self) -> bool {
            self.service
                .as_ref()
                .and_then(|s| s.dispatch_invoke_fn)
                .is_some()
        }

        /// Service-mode invoke dispatch (Phase 5). Calls the
        /// extension's `vos_service_handle_invoke` with the wire
        /// payload, copies the reply bytes into a Rust `Vec`, then
        /// returns the buffer to the extension's allocator via
        /// `vos_extension_free`. Returns the raw
        /// [`ExtensionPollResult`] status + bytes:
        ///
        ///   - `POLL_READY` + `Some(bytes)` → handler succeeded.
        ///   - `POLL_ERR_NO_FUTURE` → no matching handler for the
        ///     wire-payload's method name.
        ///   - other negative statuses → handler panic or decode error.
        ///
        /// The caller (daemon's sidecar thread) translates these
        /// into the on-wire invoke envelope (`STATUS_DONE`,
        /// `STATUS_NOT_FOUND`, `STATUS_PANICKED`).
        ///
        /// # Safety
        /// `state` must be a live extension instance produced by
        /// this plugin's `create_state`. The extension *must* be
        /// thread-safe with respect to its run thread when this is
        /// called from the sidecar.
        pub unsafe fn dispatch_service_invoke(
            &self,
            state: *mut (),
            msg: &[u8],
        ) -> (i32, Option<Vec<u8>>) {
            use super::{POLL_ERR_NO_FUTURE, POLL_READY};
            let svc = self.service_syms();
            let Some(dispatch_fn) = svc.dispatch_invoke_fn else {
                return (POLL_ERR_NO_FUTURE, None);
            };
            let result = unsafe { dispatch_fn(state, msg.as_ptr(), msg.len()) };
            if result.status == POLL_READY {
                let bytes = if result.ptr.is_null() || result.len == 0 {
                    Vec::new()
                } else {
                    let v = unsafe { std::slice::from_raw_parts(result.ptr, result.len) }.to_vec();
                    // SAFETY: the extension allocated the buffer in
                    // its own Vec-shaped allocator; freeing via the
                    // same .so's free_fn matches that allocator.
                    if let Some(free_fn) = svc.free_fn
                        && !result.ptr.is_null()
                        && result.cap > 0
                    {
                        unsafe { free_fn(result.ptr, result.len, result.cap) };
                    }
                    v
                };
                (super::POLL_READY, Some(bytes))
            } else {
                (result.status, None)
            }
        }

        /// Allocate a fresh state via the extension's `create` symbol
        /// without wrapping it in an `ExtensionInstance` (which is the
        /// actor-mode RAII handle). Used by service-mode where the
        /// state's lifetime is owned by service_thread.
        ///
        /// # Safety
        /// Caller must eventually pair this with `drop_state`.
        pub unsafe fn create_state(&self, args: &[u8]) -> *mut () {
            let ptr = if args.is_empty() {
                std::ptr::null()
            } else {
                args.as_ptr()
            };
            unsafe { (self.create_fn)(ptr, args.len()) }
        }

        /// Free a state pointer previously returned by `create_state`.
        ///
        /// # Safety
        /// `state` must be a live state pointer produced by this
        /// plugin and not already dropped.
        pub unsafe fn drop_state(&self, state: *mut ()) {
            unsafe { (self.drop_fn)(state) };
        }
    }

    /// A live extension instance backed by a loaded plugin.
    pub struct ExtensionInstance<'p> {
        plugin: &'p ExtensionPlugin,
        state: *mut (),
    }

    impl ExtensionInstance<'_> {
        /// Dispatch a raw message and poll to completion, fulfilling
        /// host I/O requests synchronously.
        ///
        /// For a fully async version, use `dispatch_start` + `poll_once`
        /// + `pending_effect` + `provide_result` manually.
        pub fn dispatch_raw(&mut self, msg: &[u8]) -> Result<Vec<u8>, i32> {
            let syms = self.plugin.actor_syms();
            // Start the dispatch
            unsafe {
                (syms.dispatch_fn)(self.state, msg.as_ptr(), msg.len());
            }
            // Poll loop
            loop {
                let result = unsafe { (syms.poll_fn)(self.state) };
                match result.status {
                    super::POLL_READY => {
                        let bytes = if result.ptr.is_null() || result.len == 0 {
                            Vec::new()
                        } else {
                            unsafe { std::slice::from_raw_parts(result.ptr, result.len) }.to_vec()
                        };
                        unsafe {
                            (syms.free_fn)(result.ptr, result.len, result.cap);
                        }
                        return Ok(bytes);
                    }
                    super::POLL_PENDING => {
                        // Read pending effect — for now just provide
                        // empty result (no host I/O fulfillment yet).
                        // TODO: route to host services / I/O runtime
                        let mut eff_ptr: *const u8 = std::ptr::null();
                        let mut eff_len: usize = 0;
                        unsafe {
                            (syms.pending_effect_fn)(self.state, &mut eff_ptr, &mut eff_len);
                        }
                        // For now, provide empty result to unblock
                        unsafe {
                            (syms.provide_result_fn)(self.state, std::ptr::null(), 0);
                        }
                    }
                    err => return Err(err),
                }
            }
        }

        /// Dispatch a dynamic message (encodes with TAG_DYNAMIC prefix).
        pub fn dispatch(&mut self, msg: &crate::actors::value::Msg) -> Result<Vec<u8>, i32> {
            use crate::actors::codec::Encode;
            let encoded = msg.encode();
            let mut payload = Vec::with_capacity(1 + encoded.len());
            payload.push(crate::actors::value::TAG_DYNAMIC);
            payload.extend_from_slice(&encoded);
            self.dispatch_raw(&payload)
        }

        /// Start dispatching a message without polling.
        /// Use `poll_once`, `pending_effect`, and `provide_result` to drive.
        pub fn dispatch_start(&mut self, msg: &[u8]) {
            let syms = self.plugin.actor_syms();
            unsafe {
                (syms.dispatch_fn)(self.state, msg.as_ptr(), msg.len());
            }
        }

        /// Poll the in-flight handler once.
        pub fn poll_once(&mut self) -> ExtensionPollResult {
            unsafe { (self.plugin.actor_syms().poll_fn)(self.state) }
        }

        /// Read the pending host I/O request (if poll returned Pending).
        pub fn pending_effect(&mut self) -> Vec<u8> {
            let syms = self.plugin.actor_syms();
            let mut ptr: *const u8 = std::ptr::null();
            let mut len: usize = 0;
            unsafe {
                (syms.pending_effect_fn)(self.state, &mut ptr, &mut len);
            }
            if ptr.is_null() || len == 0 {
                Vec::new()
            } else {
                unsafe { std::slice::from_raw_parts(ptr, len) }.to_vec()
            }
        }

        /// Provide the result for the pending host I/O request.
        pub fn provide_result(&mut self, result: &[u8]) {
            let syms = self.plugin.actor_syms();
            unsafe {
                (syms.provide_result_fn)(self.state, result.as_ptr(), result.len());
            }
        }

        /// Free a reply buffer from a poll result.
        pub fn free_reply(&self, result: &ExtensionPollResult) {
            let syms = self.plugin.actor_syms();
            unsafe {
                (syms.free_fn)(result.ptr, result.len, result.cap);
            }
        }

        /// Serialize the current actor state to bytes.
        /// Useful for persistence — write the bytes to your storage,
        /// later restore via `ExtensionPlugin::load_state`.
        pub fn save_state(&self) -> Vec<u8> {
            let syms = self.plugin.actor_syms();
            let mut ptr: *mut u8 = std::ptr::null_mut();
            let mut len: usize = 0;
            unsafe {
                (syms.state_fn)(self.state, &mut ptr, &mut len);
            }
            if ptr.is_null() || len == 0 {
                return Vec::new();
            }
            let bytes = unsafe { std::slice::from_raw_parts(ptr, len) }.to_vec();
            unsafe { (syms.free_fn)(ptr, len, len) };
            bytes
        }
    }

    impl Drop for ExtensionInstance<'_> {
        fn drop(&mut self) {
            if !self.state.is_null() {
                unsafe { (self.plugin.drop_fn)(self.state) };
                self.state = std::ptr::null_mut();
            }
        }
    }

    unsafe impl Send for ExtensionPlugin {}
    unsafe impl Sync for ExtensionPlugin {}
    unsafe impl Send for ExtensionInstance<'_> {}
}

#[cfg(feature = "std")]
pub use host::{ExtensionInstance, ExtensionPlugin};

// ── Service-mode host-side machinery (std only) ────────────────────────

#[cfg(feature = "std")]
pub use service_host::{HostCtx, InvokeFn, SERVICE_VTABLE};

#[cfg(feature = "std")]
mod service_host {
    use super::{HOST_ERR_DISCONNECTED, HOST_OK, HOST_TIMEOUT, HostVTable, RecvBuf, RecvEnv};
    use crate::node::Envelope;
    use std::collections::VecDeque;
    use std::sync::atomic::{AtomicBool, Ordering};
    use std::sync::mpsc;
    use std::sync::{Arc, Mutex};
    use std::time::Duration;

    /// Sync-invoke closure type the host hands to a service-mode
    /// extension. Sends `payload` to `target` and blocks until the
    /// reply arrives (or `timeout_ms` elapses, or shutdown). Returns
    /// `None` on transport error / timeout / unknown target.
    ///
    /// Implemented by `node::run_service_extension` on top of the
    /// node's `invoke_routes` table — same channel PVM agents and
    /// actor-mode extensions use. Extensions don't need to know
    /// about `InvokeRequest` internals.
    pub type InvokeFn = dyn Fn(u32, &[u8], u64) -> Option<Vec<u8>> + Send + Sync;

    /// Internal host state backing a `ServiceCtx`. Exposed to
    /// service-mode extensions via the C ABI as `*mut c_void`.
    pub struct HostCtx {
        /// ServiceId of the extension this ctx belongs to (used as
        /// `from` on outgoing envelopes).
        pub me: u32,
        /// Outbox: all envelopes the extension originates via the
        /// fire-and-forget envelope path flow here. `ask`-style
        /// dispatch goes through `invoke` instead.
        pub outbox: mpsc::Sender<Envelope>,
        /// Inbox + deferred queue, both lock-protected so the host
        /// can serve concurrent vtable calls from extension tokio
        /// runtimes. The deferred queue holds non-reply envelopes
        /// that arrived while waiting on the inbox.
        pub inbox: Mutex<mpsc::Receiver<Envelope>>,
        pub deferred: Mutex<VecDeque<Envelope>>,
        /// Flipped by service_thread when the host wants the
        /// extension to exit.
        pub shutdown: Arc<AtomicBool>,
        /// Sync-invoke channel targeting any agent or extension on
        /// the same node. The host wraps `InvokeRequest` plumbing in
        /// this closure so the extension layer can stay free of
        /// node internals.
        pub invoke: Arc<InvokeFn>,
    }

    /// Default per-call timeout for `ask` when the extension passes
    /// `0` — bounds blocked threads in case a reply never arrives.
    /// Tuned generously (5 minutes) so legitimate slow upstreams
    /// aren't cut off; explicit `ask_with_timeout` overrides.
    const DEFAULT_ASK_TIMEOUT: Duration = Duration::from_secs(300);

    /// Polling tick when an `ask`/`recv_envelope` call passes `0`
    /// (block until something arrives or shutdown). Bounds the
    /// shutdown latency on idle services to ~50ms.
    const POLL_TICK: Duration = Duration::from_millis(50);

    pub static SERVICE_VTABLE: HostVTable = HostVTable {
        send: vh_send,
        recv_reply: vh_recv_reply,
        recv_envelope: vh_recv_envelope,
        shutdown_signaled: vh_shutdown_signaled,
        free_buf: vh_free_buf,
        me: vh_me,
        invoke: vh_invoke,
    };

    unsafe extern "C" fn vh_me(host: *mut core::ffi::c_void) -> u32 {
        let ctx = unsafe { &*(host as *const HostCtx) };
        ctx.me
    }

    unsafe extern "C" fn vh_invoke(
        host: *mut core::ffi::c_void,
        target: u32,
        payload: *const u8,
        len: usize,
        timeout_ms: u64,
        out: *mut RecvBuf,
    ) -> i32 {
        let ctx = unsafe { &*(host as *const HostCtx) };
        let bytes = if payload.is_null() || len == 0 {
            &[][..]
        } else {
            unsafe { core::slice::from_raw_parts(payload, len) }
        };
        match (ctx.invoke)(target, bytes, timeout_ms) {
            Some(reply) => {
                write_recv_buf(out, reply);
                HOST_OK
            }
            None => {
                clear_recv_buf(out);
                if ctx.shutdown.load(Ordering::Relaxed) {
                    HOST_ERR_DISCONNECTED
                } else {
                    HOST_TIMEOUT
                }
            }
        }
    }

    unsafe extern "C" fn vh_send(
        host: *mut core::ffi::c_void,
        target: u32,
        payload: *const u8,
        len: usize,
    ) -> i32 {
        let ctx = unsafe { &*(host as *const HostCtx) };
        let bytes = if payload.is_null() || len == 0 {
            Vec::new()
        } else {
            unsafe { core::slice::from_raw_parts(payload, len) }.to_vec()
        };
        match ctx.outbox.send(Envelope {
            from: super::super::abi::service::ServiceId(ctx.me),
            to: super::super::abi::service::ServiceId(target),
            payload: bytes,
        }) {
            Ok(()) => HOST_OK,
            Err(_) => HOST_ERR_DISCONNECTED,
        }
    }

    unsafe extern "C" fn vh_recv_reply(
        host: *mut core::ffi::c_void,
        target: u32,
        timeout_ms: u64,
        out: *mut RecvBuf,
    ) -> i32 {
        let ctx = unsafe { &*(host as *const HostCtx) };
        let deadline_total = if timeout_ms == 0 {
            DEFAULT_ASK_TIMEOUT
        } else {
            Duration::from_millis(timeout_ms)
        };
        let start = std::time::Instant::now();

        loop {
            // 1. Drain deferred queue first looking for a reply from `target`.
            //    Replies are identified by `from == target`.
            {
                let mut deferred = ctx.deferred.lock().unwrap();
                if let Some(pos) = deferred.iter().position(|e| e.from.0 == target) {
                    let env = deferred.remove(pos).unwrap();
                    drop(deferred);
                    write_recv_buf(out, env.payload);
                    return HOST_OK;
                }
            }
            if ctx.shutdown.load(Ordering::Relaxed) {
                clear_recv_buf(out);
                return HOST_ERR_DISCONNECTED;
            }
            // 2. Block on the inbox briefly. Non-target messages
            //    get parked in the deferred queue for `recv_envelope`.
            let inbox = ctx.inbox.lock().unwrap();
            match inbox.recv_timeout(POLL_TICK) {
                Ok(env) => {
                    drop(inbox);
                    if env.from.0 == target {
                        write_recv_buf(out, env.payload);
                        return HOST_OK;
                    } else {
                        ctx.deferred.lock().unwrap().push_back(env);
                        continue;
                    }
                }
                Err(mpsc::RecvTimeoutError::Timeout) => {
                    drop(inbox);
                    if start.elapsed() >= deadline_total {
                        clear_recv_buf(out);
                        return HOST_TIMEOUT;
                    }
                    continue;
                }
                Err(mpsc::RecvTimeoutError::Disconnected) => {
                    clear_recv_buf(out);
                    return HOST_ERR_DISCONNECTED;
                }
            }
        }
    }

    unsafe extern "C" fn vh_recv_envelope(
        host: *mut core::ffi::c_void,
        timeout_ms: u64,
        out: *mut RecvEnv,
    ) -> i32 {
        let ctx = unsafe { &*(host as *const HostCtx) };
        let deadline_total = if timeout_ms == 0 {
            DEFAULT_ASK_TIMEOUT
        } else {
            Duration::from_millis(timeout_ms)
        };
        let start = std::time::Instant::now();
        loop {
            // 1. Drain deferred queue.
            {
                let mut deferred = ctx.deferred.lock().unwrap();
                if let Some(env) = deferred.pop_front() {
                    drop(deferred);
                    write_recv_env(out, env);
                    return HOST_OK;
                }
            }
            if ctx.shutdown.load(Ordering::Relaxed) {
                clear_recv_env(out);
                return HOST_ERR_DISCONNECTED;
            }
            let inbox = ctx.inbox.lock().unwrap();
            match inbox.recv_timeout(POLL_TICK) {
                Ok(env) => {
                    drop(inbox);
                    write_recv_env(out, env);
                    return HOST_OK;
                }
                Err(mpsc::RecvTimeoutError::Timeout) => {
                    drop(inbox);
                    if start.elapsed() >= deadline_total {
                        clear_recv_env(out);
                        return HOST_TIMEOUT;
                    }
                    continue;
                }
                Err(mpsc::RecvTimeoutError::Disconnected) => {
                    clear_recv_env(out);
                    return HOST_ERR_DISCONNECTED;
                }
            }
        }
    }

    unsafe extern "C" fn vh_shutdown_signaled(host: *mut core::ffi::c_void) -> bool {
        let ctx = unsafe { &*(host as *const HostCtx) };
        ctx.shutdown.load(Ordering::Relaxed)
    }

    unsafe extern "C" fn vh_free_buf(ptr: *mut u8, len: usize, cap: usize) {
        if ptr.is_null() {
            return;
        }
        unsafe {
            // Reconstitute the Vec we leaked in write_recv_buf so it
            // gets dropped via the host's allocator (matches what we
            // allocated with).
            let _ = Vec::from_raw_parts(ptr, len, cap);
        }
    }

    fn write_recv_buf(out: *mut RecvBuf, bytes: Vec<u8>) {
        let mut leaked = std::mem::ManuallyDrop::new(bytes);
        unsafe {
            (*out).ptr = leaked.as_mut_ptr();
            (*out).len = leaked.len();
            (*out).cap = leaked.capacity();
        }
    }

    fn clear_recv_buf(out: *mut RecvBuf) {
        unsafe {
            (*out).ptr = core::ptr::null_mut();
            (*out).len = 0;
            (*out).cap = 0;
        }
    }

    fn write_recv_env(out: *mut RecvEnv, env: Envelope) {
        unsafe {
            (*out).from = env.from.0;
        }
        write_recv_buf(unsafe { &raw mut (*out).payload }, env.payload);
    }

    fn clear_recv_env(out: *mut RecvEnv) {
        unsafe {
            (*out).from = 0;
        }
        clear_recv_buf(unsafe { &raw mut (*out).payload });
    }
}

#[cfg(all(test, feature = "std"))]
mod tests {
    use super::*;
    use std::path::PathBuf;

    fn echo_extension_path() -> PathBuf {
        let manifest_dir = env!("CARGO_MANIFEST_DIR");
        let workspace_root = PathBuf::from(manifest_dir).parent().unwrap().to_path_buf();
        let profile = if cfg!(debug_assertions) {
            "debug"
        } else {
            "release"
        };
        workspace_root
            .join("target")
            .join(profile)
            .join("libecho_extension.so")
    }

    #[test]
    fn load_and_dispatch_echo_extension() {
        let path = echo_extension_path();
        if !path.exists() {
            eprintln!(
                "skipping extension test: build echo-extension first (cargo build -p echo-extension)"
            );
            return;
        }

        let plugin = unsafe { ExtensionPlugin::load(&path) }.expect("load extension");

        // Check metadata
        let meta = plugin.meta().expect("extension should have metadata");
        assert_eq!(meta.actor_name, "EchoExtension");
        assert!(meta.messages.iter().any(|m| m.name == "echo"));
        assert!(meta.messages.iter().any(|m| m.name == "count"));
        // Echo declares no kind — defaults to Actor.
        assert_eq!(
            ExtensionKind::from_byte(meta.kind),
            ExtensionKind::Actor,
            "echo extension should be Actor-kind"
        );

        // Create instance and dispatch messages
        let mut instance = plugin.create();

        // Send echo message
        let msg = crate::actors::value::Msg::new("echo").with("text", "hello");
        let reply_bytes = instance.dispatch(&msg).expect("dispatch echo");
        assert!(!reply_bytes.is_empty(), "echo should return a reply");

        // Decode reply as Value
        let value: crate::actors::value::Value = crate::actors::codec::Decode::decode(&reply_bytes);
        let reply_str = value.as_str().expect("reply should be a string");
        assert_eq!(reply_str, "echo #1: hello");

        // Send another and check count increments
        let msg2 = crate::actors::value::Msg::new("echo").with("text", "world");
        let reply_bytes2 = instance.dispatch(&msg2).expect("dispatch echo 2");
        let value2: crate::actors::value::Value =
            crate::actors::codec::Decode::decode(&reply_bytes2);
        assert_eq!(value2.as_str().unwrap(), "echo #2: world");

        // Query count
        let count_msg = crate::actors::value::Msg::new("count");
        let count_bytes = instance.dispatch(&count_msg).expect("dispatch count");
        let count_val: crate::actors::value::Value =
            crate::actors::codec::Decode::decode(&count_bytes);
        assert_eq!(count_val.as_u32().unwrap(), 2);
    }

    #[test]
    fn extension_kind_from_byte_round_trip() {
        assert_eq!(ExtensionKind::from_byte(0), ExtensionKind::Actor);
        assert_eq!(ExtensionKind::from_byte(1), ExtensionKind::Service);
        // Unknown values fall back to Actor for forward-compat.
        assert_eq!(ExtensionKind::from_byte(7), ExtensionKind::Actor);
        assert_eq!(ExtensionKind::from_byte(255), ExtensionKind::Actor);
    }
}
