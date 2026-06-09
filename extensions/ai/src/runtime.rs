//! AI extension runtime state + inference workers.
//!
//! The heavy state the actor ([`crate::AiExtension`]) holds behind its
//! `Skip`'d `OnceCell`: the lazily-loaded model handle, the
//! outstanding-request map, and the inference worker threads. Shared by `Arc`
//! so a `begin_generate` worker keeps it alive past the handler that spawned
//! it; not serialisable (mutexes + live threads), so the actor skips it when
//! persisting and re-inits lazily from the persisted [`InitConfig`].
//!
//! Streaming model: the model lives behind a single mutex (one inference loop
//! at a time), but each `begin_generate` spawns a worker thread that streams
//! decoded chunks into a per-request channel; `poll_generation` drains those
//! channels independently of the model mutex, so polling never blocks
//! inference and concurrent `begin_generate` calls just queue at the model
//! layer.

use std::collections::BTreeMap;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::mpsc::TryRecvError;
use std::sync::{Arc, Mutex};

use vos::log;

use crate::config::InitConfig;
use crate::generate::ModelHandle;
use crate::requests::{GenerationChunk, RequestState};

/// Shared runtime state. The model handle lives under a mutex because (a)
/// inference mutates the model's KV cache so two concurrent generates would
/// corrupt each other, and (b) the model is too expensive to clone — single
/// instance, serialised access is the v1 design. Shared by `Arc` with each
/// `begin_generate` worker thread.
pub(crate) struct Inner {
    /// Configuration baked in at first-use init. Used to drive the
    /// first-call model load.
    config: InitConfig,
    /// Lazy-loaded model + tokenizer. `None` until the first `generate`
    /// invoke loads it; subsequent invokes reuse the loaded handle.
    model: Mutex<Option<ModelHandle>>,
    /// Outstanding streaming requests. Keyed by the request id
    /// `begin_generate` returns. An entry stays in the map until the first
    /// `poll_generation` call that observes the worker has finished — that
    /// call removes the entry.
    requests: Mutex<BTreeMap<u64, Arc<RequestState>>>,
    /// Monotonic source for request ids. u64 wraps after ~6e11 years at 1k
    /// generates/sec; not worth worrying about.
    next_request_id: AtomicU64,
}

impl Inner {
    /// Build empty runtime state for `config` (the model loads lazily on the
    /// first generate). Called once, from the actor's `inner()` lazy init.
    pub(crate) fn new(config: InitConfig) -> Self {
        Inner {
            config,
            model: Mutex::new(None),
            requests: Mutex::new(BTreeMap::new()),
            next_request_id: AtomicU64::new(1),
        }
    }
}

/// Run inference synchronously: lock the model, run the full generate, return
/// the concatenated text. Used by the blocking `generate` handler.
pub(crate) fn run_generate_blocking(
    inner: &Inner,
    prompt: &str,
    max_tokens: u32,
) -> anyhow::Result<String> {
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

/// Spawn a worker thread that runs inference and streams chunks into a
/// per-request channel. Returns the new request id, which the caller uses to
/// drive `poll_generation`.
pub(crate) fn begin_generate(inner: &Arc<Inner>, prompt: String, max_tokens: u32) -> u64 {
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

/// Worker body: lazy-load the model (under the global model mutex), then drive
/// `generate_stream` pushing each chunk into `tx`. Errors get stashed on
/// `state.error` before the sender drops so `poll_generation` can surface them
/// to the caller.
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
            // Send the chunk; bail (false → stop inference) if the receiver
            // hung up so the loop doesn't keep burning CPU for output nobody
            // will read.
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
    // tx drops here as the worker exits; the poll path sees Disconnected on
    // its next try_recv and reports done.
}

/// Drain pending chunks for `request_id`. Returns the concatenated text +
/// whether the worker has finished. On `done = true` the entry is removed from
/// the map.
pub(crate) fn poll_generation(inner: &Inner, request_id: u64) -> GenerationChunk {
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
                        // Drop the receiver so subsequent polls (if any) take
                        // the short-circuit path.
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
