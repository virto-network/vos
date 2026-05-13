//! AI extension service struct + entry points.
//!
//! Mirrors the dev extension's shape: `Inner` holds the live
//! `ServiceCtx` + a stop flag + the lazy-loaded model handle so
//! the `vos_service_handle_invoke` sidecar can reach all of it
//! without queuing across threads.
//!
//! Phase 6.2 adds streaming on top: the model still lives behind
//! a single mutex (one inference loop at a time), but each
//! `begin_generate` invoke spawns a worker thread that streams
//! decoded chunks into a per-request channel. `poll_generation`
//! drains those channels independently of the model mutex, so
//! polling never blocks inference and concurrent `begin_generate`
//! calls just queue at the model layer.

use std::collections::BTreeMap;
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::sync::mpsc::TryRecvError;
use std::sync::{Arc, Mutex, OnceLock};
use std::time::Duration;

use vos::extension::ServiceCtx;
use vos::log;

use crate::config::InitConfig;
use crate::generate::ModelHandle;
use crate::requests::{GenerationChunk, RequestState};

/// Shared runtime state. The model handle lives under a mutex
/// because (a) inference mutates the model's KV cache so two
/// concurrent generates would corrupt each other, and (b) the
/// model is too expensive to clone — single instance, serialised
/// access is the v1 design.
pub(crate) struct Inner {
    pub(crate) stop: AtomicBool,
    /// Configuration baked in at construction. Used to drive the
    /// first-call model load.
    config: InitConfig,
    /// Lazy-loaded model + tokenizer. `None` until the first
    /// `generate` invoke loads it; subsequent invokes reuse the
    /// loaded handle.
    model: Mutex<Option<ModelHandle>>,
    /// Outstanding streaming requests. Keyed by the request id
    /// `begin_generate` returns. An entry stays in the map until
    /// the first `poll_generation` call that observes the worker
    /// has finished — that call removes the entry.
    requests: Mutex<BTreeMap<u64, Arc<RequestState>>>,
    /// Monotonic source for request ids. u64 wraps after ~6e11
    /// years at 1k generates/sec; not worth worrying about.
    next_request_id: AtomicU64,
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
            config: self.config.clone(),
            model: Mutex::new(None),
            requests: Mutex::new(BTreeMap::new()),
            next_request_id: AtomicU64::new(1),
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

        // SAFETY: msg_ptr / msg_len are host-borrowed for this call.
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
                let max_tokens = msg.args.get_u32("max_tokens").unwrap_or(256);
                // Use the same wire shape as poll_generation
                // (GenerationChunk encoded via Args) so callers
                // get a structured `error` field instead of a
                // stringly-typed "error: ..." prefix on success.
                let chunk = match run_generate_blocking(inner, &prompt, max_tokens) {
                    Ok(text) => GenerationChunk {
                        text,
                        done: true,
                        error: String::new(),
                    },
                    Err(e) => {
                        log::warn!("ai: generate failed: {e:#}");
                        GenerationChunk {
                            text: String::new(),
                            done: true,
                            error: format!("{e}"),
                        }
                    }
                };
                Value::Bytes(chunk.to_args().encode())
            }
            "begin_generate" => {
                let Some(inner) = ai.inner() else {
                    log::warn!("ai: begin_generate() invoked before run() populated the ctx");
                    return ExtensionPollResult::error(POLL_ERR_NO_FUTURE);
                };
                let Some(prompt) = msg.args.get_str("prompt") else {
                    log::warn!("ai: begin_generate() missing prompt arg");
                    return ExtensionPollResult::error(POLL_ERR_NO_FUTURE);
                };
                let max_tokens = msg.args.get_u32("max_tokens").unwrap_or(256);
                let id = begin_generate(inner, prompt, max_tokens);
                Value::U64(id)
            }
            "poll_generation" => {
                let Some(inner) = ai.inner() else {
                    log::warn!("ai: poll_generation() invoked before run() populated the ctx");
                    return ExtensionPollResult::error(POLL_ERR_NO_FUTURE);
                };
                let Some(request_id) = msg.args.get_u64("request_id") else {
                    log::warn!("ai: poll_generation() missing request_id arg");
                    return ExtensionPollResult::error(POLL_ERR_NO_FUTURE);
                };
                let chunk = poll_generation(inner, request_id);
                // Encode as Args bytes so vosx can decode without
                // depending on this crate's wire types (which would
                // drag candle/hf-hub/tokenizers into the CLI binary).
                Value::Bytes(chunk.to_args().encode())
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

/// Run inference synchronously: lock the model, run the full
/// generate, return the concatenated text. Used by the legacy
/// `generate` dispatch arm and by tests that want a blocking
/// shape.
fn run_generate_blocking(inner: &Inner, prompt: &str, max_tokens: u32) -> anyhow::Result<String> {
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

/// Spawn a worker thread that runs inference and streams chunks
/// into a per-request channel. Returns the new request id, which
/// the caller uses to drive `poll_generation`.
fn begin_generate(inner: &Arc<Inner>, prompt: String, max_tokens: u32) -> u64 {
    let id = inner.next_request_id.fetch_add(1, Ordering::Relaxed);
    let (tx, rx) = std::sync::mpsc::channel::<String>();
    let state = Arc::new(RequestState::new(rx));
    {
        let mut requests = inner
            .requests
            .lock()
            .expect("requests mutex poisoned in begin_generate");
        requests.insert(id, state.clone());
    }
    let inner_for_worker = Arc::clone(inner);
    std::thread::Builder::new()
        .name(format!("ai-generate-{id}"))
        .spawn(move || {
            run_generate_worker(inner_for_worker, prompt, max_tokens, tx, state);
        })
        .expect("spawn ai-generate worker");
    id
}

/// Worker body: lazy-load the model (under the global model
/// mutex), then drive `generate_stream` pushing each chunk into
/// `tx`. Errors get stashed on `state.error` before the sender
/// drops so `poll_generation` can surface them to the caller.
fn run_generate_worker(
    inner: Arc<Inner>,
    prompt: String,
    max_tokens: u32,
    tx: std::sync::mpsc::Sender<String>,
    state: Arc<RequestState>,
) {
    let result: anyhow::Result<()> = (|| {
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
        handle.generate_stream(&prompt, max_tokens, |chunk| {
            // Send the chunk; bail (false → stop inference) if
            // the receiver hung up so the loop doesn't keep
            // burning CPU for output nobody will read.
            tx.send(chunk.to_string()).is_ok()
        })
    })();
    if let Err(e) = result {
        let msg = format!("{e:#}");
        log::warn!("ai: generate worker failed: {msg}");
        if let Ok(mut error) = state.error.lock() {
            *error = msg;
        }
    }
    // tx drops here as the worker exits; the poll path sees
    // Disconnected on its next try_recv and reports done.
}

/// Drain pending chunks for `request_id`. Returns the
/// concatenated text + whether the worker has finished. On
/// `done = true` the entry is removed from the map.
fn poll_generation(inner: &Inner, request_id: u64) -> GenerationChunk {
    let state = {
        let requests = inner
            .requests
            .lock()
            .expect("requests mutex poisoned in poll_generation");
        requests.get(&request_id).cloned()
    };
    let Some(state) = state else {
        return GenerationChunk {
            text: String::new(),
            done: true,
            error: format!("unknown request_id {request_id}"),
        };
    };

    let mut text = String::new();
    let mut done = false;
    {
        let mut guard = state
            .receiver
            .lock()
            .expect("receiver mutex poisoned in poll_generation");
        if let Some(rx) = guard.as_ref() {
            loop {
                match rx.try_recv() {
                    Ok(chunk) => text.push_str(&chunk),
                    Err(TryRecvError::Empty) => break,
                    Err(TryRecvError::Disconnected) => {
                        done = true;
                        // Drop the receiver so subsequent polls
                        // (if any) take the short-circuit path.
                        *guard = None;
                        break;
                    }
                }
            }
        } else {
            done = true;
        }
    }
    let error = if done {
        state.error.lock().map(|s| s.clone()).unwrap_or_default()
    } else {
        String::new()
    };
    if done {
        let mut requests = inner
            .requests
            .lock()
            .expect("requests mutex poisoned in poll_generation cleanup");
        requests.remove(&request_id);
    }
    GenerationChunk { text, done, error }
}
