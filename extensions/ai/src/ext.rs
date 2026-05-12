//! AI extension service struct + entry points.
//!
//! Mirrors the dev extension's shape: `Inner` holds the live
//! `ServiceCtx` + a stop flag + the lazy-loaded model handle so
//! the `vos_service_handle_invoke` sidecar can reach all of it
//! without queuing across threads.

use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex, OnceLock};
use std::time::Duration;

use vos::extension::ServiceCtx;
use vos::log;

use crate::config::InitConfig;
use crate::generate::ModelHandle;

/// Shared runtime state. The model handle lives under a mutex
/// because (a) inference mutates the model's KV cache so two
/// concurrent generates would corrupt each other, and (b) the
/// model is too expensive to clone — single instance, serialised
/// access is the v1 design.
pub(crate) struct Inner {
    pub(crate) stop: AtomicBool,
    /// ServiceCtx captured at `run()` entry. ServiceCtx is
    /// `Copy + Send + Sync`; the host vtable serialises per-channel
    /// state behind a mutex of its own.
    #[allow(dead_code)]
    ctx: ServiceCtx,
    /// Configuration baked in at construction. Used to drive the
    /// first-call model load.
    config: InitConfig,
    /// Lazy-loaded model + tokenizer. `None` until the first
    /// `generate` invoke loads it; subsequent invokes reuse the
    /// loaded handle.
    model: Mutex<Option<ModelHandle>>,
}

pub struct AiExtension {
    inner: OnceLock<Arc<Inner>>,
    /// Init config parsed from the init-args bytes. Lives outside
    /// `Inner` so `new()` can populate it before `run()` runs (the
    /// host calls `new` then `run` on separate dispatch entries).
    config: InitConfig,
}

impl AiExtension {
    /// Constructor invoked by `vos_extension_create`. Init args
    /// are rkyv-encoded `vos::value::Args` — see
    /// [`InitConfig::from_args`] for the schema. An empty slice
    /// keeps every default.
    pub fn new(args: &[u8]) -> Self {
        let config = InitConfig::from_args(args);
        log::info!(
            "ai: configured model={}/{} tokenizer={}/{} max_seq_len={}",
            config.model_repo,
            config.model_file,
            config.tokenizer_repo,
            config.tokenizer_file,
            config.max_seq_len,
        );
        Self {
            inner: OnceLock::new(),
            config,
        }
    }

    pub(crate) fn inner(&self) -> Option<&Arc<Inner>> {
        self.inner.get()
    }

    pub fn run(&mut self, ctx: ServiceCtx) -> i32 {
        let inner = Arc::new(Inner {
            stop: AtomicBool::new(false),
            ctx,
            config: self.config.clone(),
            model: Mutex::new(None),
        });
        if let Err(_existing) = self.inner.set(inner.clone()) {
            log::error!("ai: run() called twice — invoke sidecar would see stale state");
            return 3;
        }
        log::info!("ai: extension started (model loads on first generate)");

        while !ctx.is_shutdown() && !inner.stop.load(Ordering::Relaxed) {
            std::thread::sleep(Duration::from_millis(50));
        }

        log::info!("ai: extension stopped");
        0
    }
}

/// Service-mode invoke dispatch. Same shape as the dev extension:
/// match on `msg.name`, parse args, run the handler, return a
/// `Value`-encoded reply.
///
/// # Safety
///
/// * `state` must be a live `AiExtension` pointer produced by
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
        let ai = unsafe { &*(state as *const AiExtension) };

        let raw = unsafe { core::slice::from_raw_parts(msg_ptr, msg_len) };
        let body = if raw.first() == Some(&TAG_DYNAMIC) {
            &raw[1..]
        } else {
            raw
        };
        let Some(msg) = <Msg as vos::Decode>::try_decode(body) else {
            log::warn!("ai: vos_service_handle_invoke received malformed payload");
            return ExtensionPollResult::error(POLL_ERR_NO_FUTURE);
        };

        let reply: Value = match msg.name.as_str() {
            "stop" => {
                let Some(inner) = ai.inner() else {
                    return ExtensionPollResult::error(POLL_ERR_NO_FUTURE);
                };
                inner.stop.store(true, Ordering::Relaxed);
                log::info!("ai: stop requested");
                Value::Unit
            }
            "generate" => {
                let Some(inner) = ai.inner() else {
                    log::warn!("ai: generate() invoked before run() populated the ctx");
                    return ExtensionPollResult::error(POLL_ERR_NO_FUTURE);
                };
                let Some(prompt) = msg.args.get_str("prompt") else {
                    log::warn!("ai: generate() missing prompt arg");
                    return ExtensionPollResult::error(POLL_ERR_NO_FUTURE);
                };
                // Default to a modest 256 tokens — enough for a
                // few lines of generated code without pinning a
                // CPU for minutes on the 0.5B-CPU happy path.
                let max_tokens = msg.args.get_u32("max_tokens").unwrap_or(256);
                match run_generate(inner, &prompt, max_tokens) {
                    Ok(text) => Value::Str(text),
                    Err(e) => {
                        // Errors propagate as a Str so the CLI can
                        // surface them; alternative would be a typed
                        // status code, but a free-form message is
                        // more useful at this stage of the extension.
                        log::warn!("ai: generate failed: {e:#}");
                        Value::Str(format!("error: {e}"))
                    }
                }
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

/// Acquire (or first-time-load) the model and run the prompt
/// through it. Holds the mutex across the entire inference loop
/// — concurrent callers serialise, which is fine until a real
/// throughput case arrives.
fn run_generate(inner: &Inner, prompt: &str, max_tokens: u32) -> anyhow::Result<String> {
    let mut guard = inner
        .model
        .lock()
        .map_err(|_| anyhow::anyhow!("model mutex poisoned"))?;
    if guard.is_none() {
        log::info!("ai: loading model (first-call lazy init)");
        let handle = ModelHandle::load(&inner.config)?;
        *guard = Some(handle);
    }
    let handle = guard.as_mut().expect("loaded above");
    handle.generate(prompt, max_tokens)
}
