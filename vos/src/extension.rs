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
//! - `vos_extension_task_new_v2` / `vos_extension_task_poll` — create and drive a task
//! - `vos_extension_task_drop` — releases a completed or failed task
//! - `vos_extension_load` — restores a versioned persisted-state envelope
//! - `vos_extension_state_v2` — returns state pointer, length, and true capacity
//! - `vos_extension_drop` — frees an extension instance
//! - `vos_extension_free` — frees an extension-owned state buffer
//!
//! The host drives each task by polling repeatedly. When the handler needs I/O
//! (e.g. `ctx.ask()`), the pending poll returns the encoded effect; the host
//! fulfills it and supplies the result on the next poll.
//!
//! ## Extension feature
//!
//! Crates compiled with `features = ["extension"]` get these symbols
//! generated automatically by the `#[messages]` macro.

use alloc::vec::Vec;

const INVOCATION_CONTEXT_MAGIC: &[u8; 8] = b"VOSXCTX2";
const MAX_CALLER_WIRE_BYTES: usize = 1024;

/// Host-authenticated context installed for one native-extension invocation.
///
/// The C ABI carries this as a small, explicitly-versioned byte string instead
/// of a Rust `repr(C)` enum: [`crate::Caller::Peer`] is variable length, and no
/// Rust enum layout is stable across independently-built host/plugin binaries.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ExtensionInvocationContext {
    service_id: crate::actors::context::ServiceId,
    invocation_id: crate::service::InvocationId,
    caller: crate::Caller,
    space_role: Option<u8>,
    actor_local_role: Option<u8>,
}

impl ExtensionInvocationContext {
    pub fn new(
        service_id: crate::actors::context::ServiceId,
        invocation_id: crate::service::InvocationId,
        caller: crate::Caller,
        space_role: Option<u8>,
        actor_local_role: Option<u8>,
    ) -> Self {
        Self {
            service_id,
            invocation_id,
            caller,
            space_role,
            actor_local_role,
        }
    }

    #[doc(hidden)]
    pub fn encode(&self) -> Option<Vec<u8>> {
        let (caller_tag, caller_payload): (u8, Vec<u8>) = match &self.caller {
            crate::Caller::Unauthenticated => (0, Vec::new()),
            crate::Caller::System => (1, Vec::new()),
            crate::Caller::Peer(peer) if peer.len() <= MAX_CALLER_WIRE_BYTES => (2, peer.clone()),
            crate::Caller::Peer(_) => return None,
            crate::Caller::Member(subject) => (3, subject.0.to_vec()),
            crate::Caller::Actor(service) => (4, service.0.to_le_bytes().to_vec()),
        };
        let caller_len = u32::try_from(caller_payload.len()).ok()?;
        let mut bytes = Vec::with_capacity(53 + caller_payload.len());
        bytes.extend_from_slice(INVOCATION_CONTEXT_MAGIC);
        bytes.extend_from_slice(&self.service_id.0.to_le_bytes());
        bytes.extend_from_slice(self.invocation_id.as_bytes());
        bytes.push(caller_tag);
        bytes.extend_from_slice(&caller_len.to_le_bytes());
        bytes.extend_from_slice(&caller_payload);
        for role in [self.space_role, self.actor_local_role] {
            match role {
                Some(role) => bytes.extend_from_slice(&[1, role]),
                None => bytes.extend_from_slice(&[0, 0]),
            }
        }
        Some(bytes)
    }

    #[doc(hidden)]
    pub fn decode(bytes: &[u8]) -> Option<Self> {
        if bytes.len() < 53 || bytes.len() > 53 + MAX_CALLER_WIRE_BYTES {
            return None;
        }
        let mut offset = 0usize;
        let mut take = |len: usize| {
            let end = offset.checked_add(len)?;
            let value = bytes.get(offset..end)?;
            offset = end;
            Some(value)
        };
        if take(8)? != INVOCATION_CONTEXT_MAGIC {
            return None;
        }
        let service_id =
            crate::actors::context::ServiceId(u32::from_le_bytes(take(4)?.try_into().ok()?));
        let invocation_id = crate::service::InvocationId::new(take(32)?.try_into().ok()?);
        let caller_tag = *take(1)?.first()?;
        let caller_len = u32::from_le_bytes(take(4)?.try_into().ok()?) as usize;
        if caller_len > MAX_CALLER_WIRE_BYTES {
            return None;
        }
        let caller_payload = take(caller_len)?;
        let caller = match (caller_tag, caller_payload) {
            (0, []) => crate::Caller::Unauthenticated,
            (1, []) => crate::Caller::System,
            (2, peer) => crate::Caller::Peer(peer.to_vec()),
            (3, subject) if subject.len() == 32 => {
                crate::Caller::Member(crate::service::SubjectId::new(subject.try_into().ok()?))
            }
            (4, service) if service.len() == 4 => crate::Caller::Actor(
                crate::actors::context::ServiceId(u32::from_le_bytes(service.try_into().ok()?)),
            ),
            _ => return None,
        };
        let decode_role = |wire: &[u8]| match wire {
            [0, 0] => Some(None),
            [1, role] => Some(Some(*role)),
            _ => None,
        };
        let space_role = decode_role(take(2)?)?;
        let actor_local_role = decode_role(take(2)?)?;
        if offset != bytes.len() {
            return None;
        }
        Some(Self {
            service_id,
            invocation_id,
            caller,
            space_role,
            actor_local_role,
        })
    }

    #[doc(hidden)]
    pub fn into_actor_context<A: crate::Actor>(self) -> crate::Context<A> {
        let mut context = crate::Context::new(self.service_id);
        context.__set_invocation_id(self.invocation_id);
        context.set_caller(self.caller);
        context.set_caller_roles(self.space_role, self.actor_local_role);
        context
    }
}

impl Default for ExtensionInvocationContext {
    fn default() -> Self {
        Self::new(
            crate::actors::context::ServiceId(0),
            crate::service::InvocationId::ZERO,
            crate::Caller::Unauthenticated,
            None,
            None,
        )
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

// ── Per-task executor C ABI ─────────────────────────────────
//
// The cooperative scheduler runs **host-side** (`smol::LocalExecutor` in
// `node.rs`). The `.so` keeps only the irreducible per-task future machinery
// (`vos::actors::exec`), driven by four symbols the host calls per task:
//
//   vos_extension_task_new_v2(state, msg_ptr, msg_len, context_ptr, context_len)
//       Decode the host-authenticated invocation context, build the handler
//       future for `msg`, and return a stable non-zero task handle (0 = invalid
//       context or unknown message).
//   vos_extension_task_poll(state, handle, result_ptr, result_len) -> TaskPoll
//       Inject the host's fulfilment of the previous TASK_PENDING (empty on the
//       first poll), then poll the future once under the `.so`'s own
//       catch_unwind. Returns READY (reply bytes) / PENDING (effect-request
//       bytes) / PANIC.
//   vos_extension_task_drop(state, handle)
//       Drop the future + free its slab slot (after READY/PANIC).
//   vos_extension_take_spawned(state) -> u64
//       Drain the next spawned-child handle (reserved; currently always 0).
//
// `TaskPoll.ptr` points
// into the extension-owned `TaskState` and is valid only until the next call on
// this `state`, so the host copies the bytes immediately (the safe
// `ExtensionInstance::poll_task` wrapper does this and returns owned `Vec`s).

/// Result of one `vos_extension_task_poll`. Mirrors the per-task outcome across
/// the C ABI.
#[repr(C)]
pub struct TaskPoll {
    /// `TASK_READY` / `TASK_PENDING` / `TASK_PANIC`.
    pub kind: i32,
    /// `READY`: reply bytes. `PENDING`: effect-request bytes. `PANIC`: null.
    /// Extension-owned; valid only until the next call on this `state`.
    pub ptr: *const u8,
    pub len: usize,
}

/// The task's future completed; `ptr/len` are its reply bytes.
pub const TASK_READY: i32 = 0;
/// The task parked on a host I/O op; `ptr/len` are the effect request to fulfil
/// and feed back via the next `vos_extension_task_poll(handle, result…)`.
pub const TASK_PENDING: i32 = 1;
/// The task panicked (its per-task `catch_unwind` fired) or its handle was
/// invalid. The host frees the slot via `vos_extension_task_drop`.
pub const TASK_PANIC: i32 = -1;

impl TaskPoll {
    /// A pending poll pointing at `bytes` (the effect request, owned by the
    /// extension's `TaskState`).
    pub fn pending(ptr: *const u8, len: usize) -> Self {
        Self {
            kind: TASK_PENDING,
            ptr,
            len,
        }
    }

    /// A completed poll pointing at the reply bytes.
    pub fn ready(ptr: *const u8, len: usize) -> Self {
        Self {
            kind: TASK_READY,
            ptr,
            len,
        }
    }

    /// A panicked / invalid-handle poll (no bytes).
    pub fn panic() -> Self {
        Self {
            kind: TASK_PANIC,
            ptr: core::ptr::null(),
            len: 0,
        }
    }
}

// ── Host-side extension loader (std only) ──────────────────────────────

#[cfg(feature = "std")]
mod host {
    use crate::actors::metadata::ParsedMeta;

    /// Type signatures for the C ABI functions exported by extension `.so` files.
    use super::TaskPoll;

    type MetaFn = unsafe extern "C" fn(out_ptr: *mut *const u8, out_len: *mut usize);
    type CreateFn = unsafe extern "C" fn(args_ptr: *const u8, args_len: usize) -> *mut ();
    /// Build the handler future for `msg`, box it in the task slab, return a
    /// stable non-zero handle (0 = couldn't build, e.g. unknown method).
    type TaskNewFn = unsafe extern "C" fn(
        state: *mut (),
        msg: *const u8,
        msg_len: usize,
        context: *const u8,
        context_len: usize,
    ) -> u64;
    /// Inject `result` (the fulfilment of the previous TASK_PENDING; empty on
    /// the first poll), then poll the task's future once.
    type TaskPollFn = unsafe extern "C" fn(
        state: *mut (),
        handle: u64,
        result_ptr: *const u8,
        result_len: usize,
    ) -> TaskPoll;
    /// Drop the task's future + free its slab slot.
    type TaskDropFn = unsafe extern "C" fn(state: *mut (), handle: u64);
    /// Drain the next spawned-child handle (reserved; currently always 0).
    type TakeSpawnedFn = unsafe extern "C" fn(state: *mut ()) -> u64;
    type DropFn = unsafe extern "C" fn(state: *mut ());
    type FreeFn = unsafe extern "C" fn(ptr: *mut u8, len: usize, cap: usize);
    type LoadFn = unsafe extern "C" fn(state_ptr: *const u8, state_len: usize) -> *mut ();
    type StateFn = unsafe extern "C" fn(
        state: *mut (),
        out_ptr: *mut *mut u8,
        out_len: *mut usize,
        out_cap: *mut usize,
    );
    /// A loaded request-driven extension plugin.
    pub struct ExtensionPlugin {
        _lib: libloading::Library,
        // Always present.
        create_fn: CreateFn,
        drop_fn: DropFn,
        meta_bytes: Vec<u8>,
        // Per-task executor ABI symbols.
        actor: ActorSymbols,
    }

    struct ActorSymbols {
        task_new_fn: TaskNewFn,
        task_poll_fn: TaskPollFn,
        task_drop_fn: TaskDropFn,
        take_spawned_fn: TakeSpawnedFn,
        free_fn: FreeFn,
        load_fn: LoadFn,
        state_fn: StateFn,
    }

    impl ExtensionPlugin {
        /// Load an extension from a shared library path.
        ///
        /// Reads `vos_extension_meta`, then loads the request-driven task
        /// symbol set.
        ///
        /// # Safety
        /// The `.so` must export the correct C ABI symbols for its
        /// declared ABI.
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

                // Read and validate metadata before binding the task ABI.
                let mut meta_ptr: *const u8 = std::ptr::null();
                let mut meta_len: usize = 0;
                meta_fn(&mut meta_ptr, &mut meta_len);
                let meta_bytes = if !meta_ptr.is_null() && meta_len > 0 {
                    std::slice::from_raw_parts(meta_ptr, meta_len).to_vec()
                } else {
                    Vec::new()
                };

                let _meta = crate::actors::metadata::decode(&meta_bytes)
                    .ok_or_else(|| "missing or malformed extension metadata".to_string())?;
                // Missing canonical task functions fail to load here with a
                // clear error.
                let actor = ActorSymbols {
                    task_new_fn: *lib
                        .get::<TaskNewFn>(b"vos_extension_task_new_v2")
                        .map_err(|e| {
                            format!(
                                "missing vos_extension_task_new_v2 (rebuild the extension for the current task ABI): {e}"
                            )
                        })?,
                    task_poll_fn: *lib
                        .get::<TaskPollFn>(b"vos_extension_task_poll")
                        .map_err(|e| format!("missing vos_extension_task_poll: {e}"))?,
                    task_drop_fn: *lib
                        .get::<TaskDropFn>(b"vos_extension_task_drop")
                        .map_err(|e| format!("missing vos_extension_task_drop: {e}"))?,
                    take_spawned_fn: *lib
                        .get::<TakeSpawnedFn>(b"vos_extension_take_spawned")
                        .map_err(|e| format!("missing vos_extension_take_spawned: {e}"))?,
                    free_fn: *lib
                        .get::<FreeFn>(b"vos_extension_free")
                        .map_err(|e| format!("missing vos_extension_free: {e}"))?,
                    load_fn: *lib
                        .get::<LoadFn>(b"vos_extension_load")
                        .map_err(|e| format!("missing vos_extension_load: {e}"))?,
                    state_fn: *lib
                        .get::<StateFn>(b"vos_extension_state_v2")
                        .map_err(|e| {
                            format!(
                                "missing vos_extension_state_v2 (rebuild the extension for the current state ABI): {e}"
                            )
                        })?,
                };

                Ok(ExtensionPlugin {
                    _lib: lib,
                    create_fn,
                    drop_fn,
                    meta_bytes,
                    actor,
                })
            }
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
            self.try_create()
                .expect("extension rejected creation or startup")
        }

        /// Fallible creation used by daemon startup so constructor/start-hook
        /// failures are reported before the extension is registered.
        pub fn try_create(&self) -> Result<ExtensionInstance<'_>, String> {
            let state = unsafe { (self.create_fn)(std::ptr::null(), 0) };
            if state.is_null() {
                return Err("extension rejected creation or startup".into());
            }
            Ok(ExtensionInstance {
                plugin: self,
                state,
            })
        }

        /// Create a new extension instance with rkyv-encoded init args.
        pub fn create_with_args(&self, args: &[u8]) -> ExtensionInstance<'_> {
            self.try_create_with_args(args)
                .expect("extension rejected init arguments or startup")
        }

        /// Fallible argument-bearing creation used by daemon startup.
        pub fn try_create_with_args(&self, args: &[u8]) -> Result<ExtensionInstance<'_>, String> {
            let state = unsafe { (self.create_fn)(args.as_ptr(), args.len()) };
            if state.is_null() {
                return Err("extension rejected init arguments or startup".into());
            }
            Ok(ExtensionInstance {
                plugin: self,
                state,
            })
        }

        /// Restore an extension instance from previously serialized state.
        pub fn load_state(&self, state: &[u8]) -> Result<ExtensionInstance<'_>, String> {
            let load_fn = self.actor_syms().load_fn;
            let s = unsafe { load_fn(state.as_ptr(), state.len()) };
            if s.is_null() {
                return Err(
                    "extension rejected persisted state (corrupt or incompatible schema)".into(),
                );
            }
            Ok(ExtensionInstance {
                plugin: self,
                state: s,
            })
        }

        fn actor_syms(&self) -> &ActorSymbols {
            &self.actor
        }
    }

    /// A live extension instance backed by a loaded plugin.
    pub struct ExtensionInstance<'p> {
        plugin: &'p ExtensionPlugin,
        state: *mut (),
    }

    /// Host-side, owned outcome of one [`ExtensionInstance::poll_task`]. The
    /// bytes are copied out of the extension-owned `TaskState` immediately, so
    /// they outlive the next call — the "valid until next call" contract is
    /// therefore unbypassable at the type level.
    pub enum TaskOutcome {
        /// The task's future completed; `reply` is its (owned) reply bytes.
        Ready(Vec<u8>),
        /// The task parked on a host I/O op; fulfil it and feed the result back
        /// via the next [`ExtensionInstance::poll_task`]`(handle, result)`.
        Pending(Vec<u8>),
        /// The task panicked, or the handle was invalid.
        Panic,
    }

    impl ExtensionInstance<'_> {
        /// Build the handler future for `msg` and box it in the task slab.
        /// Returns a stable non-zero handle, or `0` when no handler matched
        /// (e.g. an unknown method) — the caller maps `0` to an error.
        pub fn new_task(&mut self, msg: &[u8]) -> u64 {
            self.new_task_with_context(msg, &super::ExtensionInvocationContext::default())
        }

        /// Build a handler future with the caller identity and authorization
        /// data authenticated by the host for this invocation.
        pub fn new_task_with_context(
            &mut self,
            msg: &[u8],
            context: &super::ExtensionInvocationContext,
        ) -> u64 {
            let Some(context) = context.encode() else {
                return 0;
            };
            let syms = self.plugin.actor_syms();
            unsafe {
                (syms.task_new_fn)(
                    self.state,
                    msg.as_ptr(),
                    msg.len(),
                    context.as_ptr(),
                    context.len(),
                )
            }
        }

        /// Inject `result` (the fulfilment of the previous [`TaskOutcome::Pending`];
        /// pass `&[]` on the first poll) and poll the task's future once, copying
        /// any returned bytes into an owned `Vec` before returning (the
        /// extension's buffer is only valid until the next call, so the copy
        /// makes the lifetime unbypassable).
        pub fn poll_task(&mut self, handle: u64, result: &[u8]) -> TaskOutcome {
            let tp = unsafe {
                (self.plugin.actor_syms().task_poll_fn)(
                    self.state,
                    handle,
                    result.as_ptr(),
                    result.len(),
                )
            };
            let copy = || {
                if tp.ptr.is_null() || tp.len == 0 {
                    Vec::new()
                } else {
                    unsafe { std::slice::from_raw_parts(tp.ptr, tp.len) }.to_vec()
                }
            };
            match tp.kind {
                super::TASK_READY => TaskOutcome::Ready(copy()),
                super::TASK_PENDING => TaskOutcome::Pending(copy()),
                _ => TaskOutcome::Panic,
            }
        }

        /// Drop the task's future + free its slab slot. Call after
        /// [`TaskOutcome::Ready`] / [`TaskOutcome::Panic`].
        pub fn drop_task(&mut self, handle: u64) {
            let syms = self.plugin.actor_syms();
            unsafe { (syms.task_drop_fn)(self.state, handle) };
        }

        /// Drain the next spawned-child handle, or `0` if none. Reserved:
        /// nothing spawns children yet, so this always returns `0`.
        pub fn take_spawned(&mut self) -> u64 {
            let syms = self.plugin.actor_syms();
            unsafe { (syms.take_spawned_fn)(self.state) }
        }

        /// Build one root task from `msg` and drive it to completion.
        ///
        /// This all-in-one helper is **synchronous and smol-free** — it stubs
        /// each `Pending` op with an empty result. Callers that need real
        /// effect fulfilment use the node's host executor (`run_ext_task` in
        /// `node.rs`) instead.
        pub fn dispatch_raw(&mut self, msg: &[u8]) -> Result<Vec<u8>, i32> {
            let handle = self.new_task(msg);
            if handle == 0 {
                // No handler matched (unknown/undecodable method).
                return Err(super::POLL_ERR_NO_FUTURE);
            }
            let mut result: Vec<u8> = Vec::new();
            loop {
                match self.poll_task(handle, &result) {
                    TaskOutcome::Ready(reply) => {
                        self.drop_task(handle);
                        return Ok(reply);
                    }
                    TaskOutcome::Pending(_) => result = Vec::new(),
                    TaskOutcome::Panic => {
                        self.drop_task(handle);
                        return Err(super::POLL_ERR_HANDLER);
                    }
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

        /// Serialize the current actor state to bytes.
        /// Useful for persistence — write the bytes to your storage,
        /// later restore via `ExtensionPlugin::load_state`.
        pub fn save_state(&self) -> Result<Vec<u8>, String> {
            let syms = self.plugin.actor_syms();
            let mut ptr: *mut u8 = std::ptr::null_mut();
            let mut len: usize = 0;
            let mut cap: usize = 0;
            unsafe {
                (syms.state_fn)(self.state, &mut ptr, &mut len, &mut cap);
            }
            if ptr.is_null() || len == 0 || cap < len {
                return Err(format!(
                    "extension returned an invalid state buffer (ptr_null={}, len={len}, cap={cap})",
                    ptr.is_null()
                ));
            }
            let bytes = unsafe { std::slice::from_raw_parts(ptr, len) }.to_vec();
            unsafe { (syms.free_fn)(ptr, len, cap) };
            Ok(bytes)
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
pub use host::{ExtensionInstance, ExtensionPlugin, TaskOutcome};

#[cfg(all(test, feature = "std"))]
mod tests {
    use super::*;
    use std::path::PathBuf;

    #[test]
    fn invocation_context_wire_round_trips_all_caller_variants() {
        let service_id = crate::actors::context::ServiceId(0x1234_5678);
        let invocation_id = crate::service::InvocationId::new([0x5a; 32]);
        let callers = [
            crate::Caller::Unauthenticated,
            crate::Caller::System,
            crate::Caller::Peer(vec![1, 2, 3, 4]),
            crate::Caller::Member(crate::service::SubjectId::new([0xa5; 32])),
            crate::Caller::Actor(crate::actors::context::ServiceId(42)),
        ];

        for caller in callers {
            let expected = ExtensionInvocationContext::new(
                service_id,
                invocation_id,
                caller,
                Some(3),
                Some(7),
            );
            let encoded = expected.encode().expect("encode invocation context");
            assert_eq!(ExtensionInvocationContext::decode(&encoded), Some(expected));
        }
    }

    #[test]
    fn invocation_context_wire_rejects_malformed_or_oversized_inputs() {
        let expected = ExtensionInvocationContext::new(
            crate::actors::context::ServiceId(9),
            crate::service::InvocationId::new([1; 32]),
            crate::Caller::Peer(vec![2; MAX_CALLER_WIRE_BYTES + 1]),
            None,
            None,
        );
        assert!(expected.encode().is_none());

        let valid = ExtensionInvocationContext::default()
            .encode()
            .expect("encode default invocation context");
        for end in 0..valid.len() {
            assert!(ExtensionInvocationContext::decode(&valid[..end]).is_none());
        }

        let mut bad_magic = valid.clone();
        bad_magic[0] ^= 0xff;
        assert!(ExtensionInvocationContext::decode(&bad_magic).is_none());

        let mut bad_caller_tag = valid.clone();
        bad_caller_tag[44] = 0xff;
        assert!(ExtensionInvocationContext::decode(&bad_caller_tag).is_none());

        let mut bad_role_tag = valid.clone();
        bad_role_tag[49] = 2;
        assert!(ExtensionInvocationContext::decode(&bad_role_tag).is_none());

        let mut trailing = valid;
        trailing.push(0);
        assert!(ExtensionInvocationContext::decode(&trailing).is_none());
    }

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
    fn native_task_construction_rejects_malformed_dynamic_messages() {
        const CHILD_ENV: &str = "VOS_MALFORMED_EXTENSION_CHILD";
        if std::env::var_os(CHILD_ENV).is_none() {
            let status = std::process::Command::new(std::env::current_exe().unwrap())
                .args([
                    "--exact",
                    "extension::tests::native_task_construction_rejects_malformed_dynamic_messages",
                    "--nocapture",
                ])
                .env(CHILD_ENV, "1")
                .status()
                .expect("spawn malformed-extension subprocess");
            assert!(
                status.success(),
                "native extension aborted while rejecting malformed dynamic bytes: {status}"
            );
            return;
        }

        let path = echo_extension_path();
        if !path.exists() {
            eprintln!(
                "skipping extension test: build echo-extension first (cargo build -p echo-extension)"
            );
            return;
        }

        let plugin = unsafe { ExtensionPlugin::load(&path) }.expect("load extension");
        let mut instance = plugin.create();
        let malformed = [crate::actors::value::TAG_DYNAMIC];
        assert_eq!(
            instance.new_task_with_context(&malformed, &ExtensionInvocationContext::default()),
            0,
        );
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
    fn corrupt_extension_state_is_rejected() {
        let path = echo_extension_path();
        if !path.exists() {
            eprintln!(
                "skipping extension test: build echo-extension first (cargo build -p echo-extension)"
            );
            return;
        }

        let plugin = unsafe { ExtensionPlugin::load(&path) }.expect("load extension");
        assert!(plugin.load_state(&[0xff]).is_err());

        let mut instance = plugin.create();
        let mut state = instance.save_state().expect("save extension state");
        assert_eq!(&state[..8], b"VOSXST02");
        let canonical = u64::from_le_bytes(state[16..24].try_into().unwrap());

        let legacy_reply = instance
            .dispatch(&crate::actors::value::Msg::new("legacy_state_fingerprint"))
            .expect("query legacy schema fingerprint");
        let legacy: crate::actors::value::Value =
            crate::actors::codec::Decode::decode(&legacy_reply);
        let legacy = legacy.as_u64().expect("legacy fingerprint reply");
        assert_ne!(canonical, legacy);
        state[16..24].copy_from_slice(&legacy.to_le_bytes());
        assert!(
            plugin.load_state(&state).is_ok(),
            "the exact pre-canonical fingerprint for this declaration must migrate"
        );

        state[8] ^= 1;
        assert!(
            plugin.load_state(&state).is_err(),
            "a snapshot from a different declared schema version must fail closed"
        );
    }
}
