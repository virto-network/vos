//! Dev extension service struct + entry points.
//!
//! Phase 1.1 lays down the scaffold: a service-mode extension
//! with an idle `run()` loop and a hand-rolled invoke dispatch
//! sidecar (matching the http-gateway pattern) that today only
//! recognises `stop`. Later phases bolt `compile()` and
//! `publish()` onto the same sidecar.

use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, OnceLock};
use std::time::Duration;
use vos::extension::ServiceCtx;
use vos::log;

/// Shared runtime state — published into the `OnceLock` by
/// `run()` so the invoke sidecar can wake the shutdown loop.
pub(crate) struct Inner {
    /// Set by the `stop` handler. `run()` polls this in addition
    /// to `ctx.is_shutdown()` so an operator can quiesce the
    /// extension via `vosx dev stop` without bringing the whole
    /// daemon down.
    pub(crate) stop: AtomicBool,
}

pub struct DevExtension {
    inner: OnceLock<Arc<Inner>>,
}

impl DevExtension {
    /// Constructor invoked by `vos_extension_create`. v1 takes no
    /// init args; manifest knobs (build cache dir, default
    /// toolchain channel, …) will land in a later phase.
    pub fn new(_args: &[u8]) -> Self {
        Self {
            inner: OnceLock::new(),
        }
    }

    pub(crate) fn inner(&self) -> Option<&Arc<Inner>> {
        self.inner.get()
    }

    /// Service entry point. v1 is a passive idle loop — every
    /// real work item arrives through the invoke dispatch
    /// sidecar (`vos_service_handle_invoke`). Returns 0 on
    /// clean shutdown.
    pub fn run(&mut self, ctx: ServiceCtx) -> i32 {
        let inner = Arc::new(Inner {
            stop: AtomicBool::new(false),
        });
        if let Err(_existing) = self.inner.set(inner.clone()) {
            log::error!("dev: run() called twice — invoke sidecar would see stale state");
            return 3;
        }
        log::info!("dev: extension started");

        // Idle until shutdown. The 50ms tick is fine for now; the
        // sidecar wakes the daemon, not this loop, so latency
        // matters only for the final exit.
        while !ctx.is_shutdown() && !inner.stop.load(Ordering::Relaxed) {
            std::thread::sleep(Duration::from_millis(50));
        }

        log::info!("dev: extension stopped");
        0
    }
}

/// Service-mode invoke dispatch. Phase 1.1 only handles `stop`;
/// `compile` / `publish` / etc. land in subsequent phases. Wire
/// shape mirrors the http-gateway pattern — caller (vosx)
/// encodes a `vos::value::Msg` prefixed with `TAG_DYNAMIC`; we
/// decode, match `msg.name`, dispatch, and reply with rkyv-
/// encoded `vos::value::Value`.
///
/// # Safety
///
/// * `state` must be a live `DevExtension` pointer produced by
///   `vos_extension_create` and not yet freed.
/// * `msg_ptr` / `msg_len` must describe a valid byte slice or
///   `(null, 0)`.
/// * Only the host's service-mode dispatch sidecar should call
///   this — external callers can't satisfy the invariants.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn vos_service_handle_invoke(
    state: *mut (),
    msg_ptr: *const u8,
    msg_len: usize,
) -> vos::extension::ExtensionPollResult {
    use vos::Encode;
    use vos::extension::{ExtensionPollResult, POLL_ERR_HANDLER, POLL_ERR_NO_FUTURE};
    use vos::value::{Msg, TAG_DYNAMIC, Value};

    let result = std::panic::catch_unwind(|| {
        if state.is_null() || msg_ptr.is_null() || msg_len == 0 {
            return ExtensionPollResult::error(POLL_ERR_NO_FUTURE);
        }
        // SAFETY: invariants documented on the function.
        let dev = unsafe { &*(state as *const DevExtension) };

        let raw = unsafe { core::slice::from_raw_parts(msg_ptr, msg_len) };
        let body = if raw.first() == Some(&TAG_DYNAMIC) {
            &raw[1..]
        } else {
            raw
        };
        let Some(msg) = <Msg as vos::Decode>::try_decode(body) else {
            log::warn!("dev: vos_service_handle_invoke received malformed payload");
            return ExtensionPollResult::error(POLL_ERR_NO_FUTURE);
        };

        let reply: Value = match msg.name.as_str() {
            "stop" => {
                let Some(inner) = dev.inner() else {
                    return ExtensionPollResult::error(POLL_ERR_NO_FUTURE);
                };
                inner.stop.store(true, Ordering::Relaxed);
                log::info!("dev: stop requested");
                Value::Unit
            }
            _ => return ExtensionPollResult::error(POLL_ERR_NO_FUTURE),
        };

        ExtensionPollResult::ready(reply.encode())
    });
    match result {
        Ok(r) => r,
        Err(_) => ExtensionPollResult::error(POLL_ERR_HANDLER),
    }
}
