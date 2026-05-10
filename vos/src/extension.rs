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
/// Phase 2 introduces this discriminant in the extension metadata
/// blob. The host loader treats every extension as `Actor` until
/// Phase 3 wires up the service ABI.
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

// ── Host-side extension loader (std only) ──────────────────────────────

#[cfg(feature = "std")]
mod host {
    use super::ExtensionPollResult;
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

    /// A loaded extension plugin.
    pub struct ExtensionPlugin {
        _lib: libloading::Library,
        create_fn: CreateFn,
        dispatch_fn: DispatchFn,
        poll_fn: PollFn,
        pending_effect_fn: PendingEffectFn,
        provide_result_fn: ProvideResultFn,
        drop_fn: DropFn,
        free_fn: FreeFn,
        load_fn: LoadFn,
        state_fn: StateFn,
        meta_bytes: Vec<u8>,
    }

    impl ExtensionPlugin {
        /// Load an extension from a shared library path.
        ///
        /// # Safety
        /// The `.so` must export the correct C ABI symbols.
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
                let drop_fn = *lib
                    .get::<DropFn>(b"vos_extension_drop")
                    .map_err(|e| format!("missing vos_extension_drop: {e}"))?;
                let free_fn = *lib
                    .get::<FreeFn>(b"vos_extension_free")
                    .map_err(|e| format!("missing vos_extension_free: {e}"))?;
                let load_fn = *lib
                    .get::<LoadFn>(b"vos_extension_load")
                    .map_err(|e| format!("missing vos_extension_load: {e}"))?;
                let state_fn = *lib
                    .get::<StateFn>(b"vos_extension_state")
                    .map_err(|e| format!("missing vos_extension_state: {e}"))?;

                // Read metadata
                let mut meta_ptr: *const u8 = std::ptr::null();
                let mut meta_len: usize = 0;
                meta_fn(&mut meta_ptr, &mut meta_len);
                let meta_bytes = if !meta_ptr.is_null() && meta_len > 0 {
                    std::slice::from_raw_parts(meta_ptr, meta_len).to_vec()
                } else {
                    Vec::new()
                };

                Ok(ExtensionPlugin {
                    _lib: lib,
                    create_fn,
                    dispatch_fn,
                    poll_fn,
                    pending_effect_fn,
                    provide_result_fn,
                    drop_fn,
                    free_fn,
                    load_fn,
                    state_fn,
                    meta_bytes,
                })
            }
        }

        /// Parse the extension's actor metadata.
        pub fn meta(&self) -> Option<ParsedMeta> {
            crate::actors::metadata::decode(&self.meta_bytes)
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
        pub fn load_state(&self, state: &[u8]) -> ExtensionInstance<'_> {
            let s = unsafe { (self.load_fn)(state.as_ptr(), state.len()) };
            ExtensionInstance {
                plugin: self,
                state: s,
            }
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
            // Start the dispatch
            unsafe {
                (self.plugin.dispatch_fn)(self.state, msg.as_ptr(), msg.len());
            }
            // Poll loop
            loop {
                let result = unsafe { (self.plugin.poll_fn)(self.state) };
                match result.status {
                    super::POLL_READY => {
                        let bytes = if result.ptr.is_null() || result.len == 0 {
                            Vec::new()
                        } else {
                            unsafe { std::slice::from_raw_parts(result.ptr, result.len) }.to_vec()
                        };
                        unsafe {
                            (self.plugin.free_fn)(result.ptr, result.len, result.cap);
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
                            (self.plugin.pending_effect_fn)(self.state, &mut eff_ptr, &mut eff_len);
                        }
                        // For now, provide empty result to unblock
                        unsafe {
                            (self.plugin.provide_result_fn)(self.state, std::ptr::null(), 0);
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
            unsafe {
                (self.plugin.dispatch_fn)(self.state, msg.as_ptr(), msg.len());
            }
        }

        /// Poll the in-flight handler once.
        pub fn poll_once(&mut self) -> ExtensionPollResult {
            unsafe { (self.plugin.poll_fn)(self.state) }
        }

        /// Read the pending host I/O request (if poll returned Pending).
        pub fn pending_effect(&mut self) -> Vec<u8> {
            let mut ptr: *const u8 = std::ptr::null();
            let mut len: usize = 0;
            unsafe {
                (self.plugin.pending_effect_fn)(self.state, &mut ptr, &mut len);
            }
            if ptr.is_null() || len == 0 {
                Vec::new()
            } else {
                unsafe { std::slice::from_raw_parts(ptr, len) }.to_vec()
            }
        }

        /// Provide the result for the pending host I/O request.
        pub fn provide_result(&mut self, result: &[u8]) {
            unsafe {
                (self.plugin.provide_result_fn)(self.state, result.as_ptr(), result.len());
            }
        }

        /// Free a reply buffer from a poll result.
        pub fn free_reply(&self, result: &ExtensionPollResult) {
            unsafe {
                (self.plugin.free_fn)(result.ptr, result.len, result.cap);
            }
        }

        /// Serialize the current actor state to bytes.
        /// Useful for persistence — write the bytes to your storage,
        /// later restore via `ExtensionPlugin::load_state`.
        pub fn save_state(&self) -> Vec<u8> {
            let mut ptr: *mut u8 = std::ptr::null_mut();
            let mut len: usize = 0;
            unsafe {
                (self.plugin.state_fn)(self.state, &mut ptr, &mut len);
            }
            if ptr.is_null() || len == 0 {
                return Vec::new();
            }
            let bytes = unsafe { std::slice::from_raw_parts(ptr, len) }.to_vec();
            unsafe { (self.plugin.free_fn)(ptr, len, len) };
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
