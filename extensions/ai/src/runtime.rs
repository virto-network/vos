//! AI extension runtime state + inference workers.
//!
//! The heavy state the actor ([`crate::AiExtension`]) holds behind its
//! `Skip`'d `OnceCell`: the lazily-loaded model handle and the async
//! generation jobs. Shared by `Arc` so a `generate` worker keeps it alive past
//! the handler that spawned it; not serialisable (mutexes + live threads), so
//! the actor skips it when persisting and re-inits lazily from the persisted
//! [`InitConfig`].
//!
//! Streaming model: the model lives behind a single mutex (one inference loop
//! at a time), but each `generate` spawns a worker thread that pushes decoded
//! tokens into a shared [`vos::jobs::JobQueue`]; `job_poll` drains that queue
//! independently of the model mutex, so polling never blocks inference and
//! concurrent `generate` calls just queue at the model layer. The queue sits
//! behind its own mutex because the worker threads push concurrently with the
//! actor thread's begin / poll / release.

use std::sync::{Arc, Mutex};

use vos::Encode;
use vos::jobs::JobQueue;
use vos::log;

use crate::config::InitConfig;
use crate::generate::ModelHandle;

/// Shared runtime state. The model handle lives under a mutex because (a)
/// inference mutates the model's KV cache so two concurrent generates would
/// corrupt each other, and (b) the model is too expensive to clone — single
/// instance, serialised access is the v1 design. Shared by `Arc` with each
/// `generate` worker thread.
pub(crate) struct Inner {
    /// Configuration baked in at first-use init. Used to drive the
    /// first-call model load.
    config: InitConfig,
    /// Lazy-loaded model + tokenizer. `None` until the first `generate`
    /// invoke loads it; subsequent invokes reuse the loaded handle.
    model: Mutex<Option<ModelHandle>>,
    /// Async generation jobs — output bytes + terminal state — shared with the
    /// worker threads. `job_poll` / `job_release` delegate here.
    jobs: Mutex<JobQueue>,
}

impl Inner {
    /// Build empty runtime state for `config` (the model loads lazily on the
    /// first generate). Called once, from the actor's `inner()` lazy init.
    pub(crate) fn new(config: InitConfig) -> Self {
        Inner {
            config,
            model: Mutex::new(None),
            jobs: Mutex::new(JobQueue::new()),
        }
    }
}

/// Spawn a worker thread that runs inference and pushes decoded tokens into the
/// shared job queue. Returns the new job id, which the caller uses to drive
/// `job_poll` / `job_release`.
pub(crate) fn begin_generate(inner: &Arc<Inner>, prompt: String, max_tokens: u32) -> u64 {
    let id = inner
        .jobs
        .lock()
        .expect("jobs mutex poisoned in begin_generate")
        .begin();
    let inner_for_worker = Arc::clone(inner);
    std::thread::Builder::new()
        .name(format!("ai-generate-{id}"))
        .spawn(move || run_generate_worker(inner_for_worker, id, prompt, max_tokens))
        .expect("spawn ai-generate worker");
    id
}

/// Worker body: lazy-load the model (under the global model mutex), stream
/// decoded tokens into job `id`'s output, and mark it finished (or failed).
/// Runs the full `max_tokens` even if the client stops polling — the job's
/// output just accumulates until `job_release`; nothing signals early stop.
fn run_generate_worker(inner: Arc<Inner>, id: u64, prompt: String, max_tokens: u32) {
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
            inner
                .jobs
                .lock()
                .expect("jobs mutex poisoned in worker push")
                .push(id, chunk.as_bytes());
            true
        })
    })();
    let mut jobs = inner
        .jobs
        .lock()
        .expect("jobs mutex poisoned in worker finish");
    match result {
        Ok(()) => jobs.finish(id),
        Err(e) => {
            let msg = format!("{e:#}");
            log::warn!("ai: generate worker failed: {msg}");
            jobs.fail(id, msg);
        }
    }
}

/// The standard `job_poll` reply for `id` — `Args { data, done, error }`
/// rkyv-encoded. `data` is the tokens decoded since the last poll.
pub(crate) fn poll_generation(inner: &Inner, id: u64) -> Vec<u8> {
    inner
        .jobs
        .lock()
        .expect("jobs mutex poisoned in poll_generation")
        .poll_reply(id)
        .encode()
}

/// Drop a finished generation job, returning `true` if one was present.
pub(crate) fn release_generation(inner: &Inner, id: u64) -> bool {
    inner
        .jobs
        .lock()
        .expect("jobs mutex poisoned in release_generation")
        .release(id)
}
