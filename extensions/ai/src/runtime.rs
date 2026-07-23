//! AI extension runtime state + inference workers.
//!
//! The heavy state the actor ([`crate::AiExtension`]) holds behind its
//! `Skip`'d `OnceCell`: the lazily-loaded model handle and the async
//! generation jobs. Shared by `Arc` so a worker keeps it alive past the
//! handler that spawned it; not serialisable (mutexes + live threads),
//! so the actor skips it when persisting and re-inits lazily from the
//! persisted [`InitConfig`].
//!
//! Streaming model: the model lives behind a single mutex (one inference
//! loop at a time), but each generation spawns a worker thread that
//! pushes decoded tokens into a shared [`vos::jobs::JobQueue`];
//! `job_poll` drains that queue independently of the model mutex, so
//! polling never blocks inference and concurrent generates just queue at
//! the model layer. The queue sits behind its own mutex because the
//! worker threads push concurrently with the actor thread's begin /
//! poll / release.
//!
//! `actor_change` adds an *apply* twist: its worker can't touch the
//! dev-project actor (that needs the actor's `Context`, which is not
//! `Send`), so an apply-mode job doesn't finish itself — it accumulates
//! the full generated text into an [`ApplyState`] and hands it to
//! `job_poll` (which *does* hold `Context`) to parse + commit and push
//! the summary in-band before the job's terminal `finish`.

use std::collections::HashMap;
use std::sync::{Arc, Mutex};

use vos::Encode;
use vos::jobs::JobQueue;
use vos::log;

use crate::AiCtx;
use crate::config::InitConfig;
use crate::generate::ModelHandle;

/// Shared runtime state. The model handle lives under a mutex because
/// (a) inference mutates the model's KV cache so two concurrent
/// generates would corrupt each other, and (b) the model is too
/// expensive to clone — single instance, serialised access is the v1
/// design. Shared by `Arc` with each generation worker thread.
pub(crate) struct Inner {
    /// Configuration baked in at first-use init. Drives the first-call
    /// model load.
    config: InitConfig,
    /// Lazy-loaded model + tokenizer. `None` until the first generate
    /// loads it; subsequent invokes reuse the loaded handle.
    model: Mutex<Option<ModelHandle>>,
    /// Async generation jobs — output bytes + terminal state — shared
    /// with the worker threads. `job_poll` / `job_release` delegate here.
    jobs: Mutex<JobQueue>,
    /// Per-job apply state for in-flight `actor_change --apply` jobs. A
    /// worker can't reach the dev-project actor, so it parks the full
    /// generated text here and leaves the job *not* terminal;
    /// [`maybe_finalize_apply`] (on the actor thread, with `Context`)
    /// writes the suggestion back and finishes the job.
    apply: Mutex<HashMap<u64, ApplyState>>,
}

/// The dev-project write-back context an apply-mode `actor_change` job
/// carries until its generation finishes.
struct ApplyState {
    project_id: u32,
    branch: String,
    base_commit: Vec<u8>,
    /// Full generated text, accumulated by the worker (the streamed
    /// chunks are drained by polls, so the queue can't be re-read to
    /// parse the response).
    full_text: String,
    /// Set by the worker when generation reaches a terminal state.
    gen_done: bool,
    /// `Some` when generation itself failed — skip the apply, surface
    /// the error.
    outcome_err: Option<String>,
}

impl Inner {
    /// Build empty runtime state for `config` (the model loads lazily on
    /// the first generate). Called once, from the actor's `inner()` lazy
    /// init.
    pub(crate) fn new(config: InitConfig) -> Self {
        Inner {
            config,
            model: Mutex::new(None),
            jobs: Mutex::new(JobQueue::new()),
            apply: Mutex::new(HashMap::new()),
        }
    }
}

/// Register + begin a plain streaming generation job. Returns the new
/// job id for `job_poll` / `job_release`.
pub(crate) fn begin_generate(inner: &Arc<Inner>, prompt: String, max_tokens: u32) -> u64 {
    let id = inner
        .jobs
        .lock()
        .expect("jobs mutex poisoned in begin_generate")
        .begin();
    spawn_worker(inner, id, prompt, max_tokens, false);
    id
}

/// Begin an `actor_change` generation job. `apply` == true registers an
/// [`ApplyState`] so the worker parks its full output for `job_poll` to
/// commit; `apply` == false is a read-only completion, identical to
/// [`begin_generate`] but with the caller's assembled prompt.
#[allow(clippy::too_many_arguments)]
pub(crate) fn begin_actor_change(
    inner: &Arc<Inner>,
    prompt: String,
    max_tokens: u32,
    project_id: u32,
    branch: String,
    base_commit: Vec<u8>,
    apply: bool,
) -> u64 {
    let id = inner
        .jobs
        .lock()
        .expect("jobs mutex poisoned in begin_actor_change")
        .begin();
    if apply {
        inner.apply.lock().expect("apply mutex poisoned").insert(
            id,
            ApplyState {
                project_id,
                branch,
                base_commit,
                full_text: String::new(),
                gen_done: false,
                outcome_err: None,
            },
        );
    }
    spawn_worker(inner, id, prompt, max_tokens, apply);
    id
}

/// Register an already-failed job carrying `msg`. Used when the
/// `actor_change` setup (source-commit resolution / file fetch) fails
/// before any generation starts — the driver polls once, sees the
/// error, and exits non-zero.
pub(crate) fn begin_failed(inner: &Arc<Inner>, msg: String) -> u64 {
    let mut jobs = inner
        .jobs
        .lock()
        .expect("jobs mutex poisoned in begin_failed");
    let id = jobs.begin();
    jobs.fail(id, msg);
    id
}

fn spawn_worker(inner: &Arc<Inner>, id: u64, prompt: String, max_tokens: u32, apply: bool) {
    let inner_for_worker = Arc::clone(inner);
    std::thread::Builder::new()
        .name(format!("ai-generate-{id}"))
        .spawn(move || run_generate_worker(inner_for_worker, id, prompt, max_tokens, apply))
        .expect("spawn ai-generate worker");
}

/// Worker body: lazy-load the model (under the global model mutex),
/// stream decoded tokens into job `id`'s output. A plain job finishes
/// (or fails) itself; an apply job parks its full text + outcome in the
/// [`ApplyState`] and leaves the job non-terminal for
/// [`maybe_finalize_apply`]. Runs the full `max_tokens` even if the
/// client stops polling.
fn run_generate_worker(inner: Arc<Inner>, id: u64, prompt: String, max_tokens: u32, apply: bool) {
    let mut full_text = String::new();
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
            if apply {
                full_text.push_str(chunk);
            }
            true
        })
    })();

    if apply {
        // Hand the results to the apply record; `job_poll` finalizes
        // (parse + commit + terminal) with the `Context` a worker lacks.
        // If the record vanished (released mid-flight) just terminalize.
        let mut applies = inner
            .apply
            .lock()
            .expect("apply mutex poisoned in worker finish");
        if let Some(st) = applies.get_mut(&id) {
            st.full_text = full_text;
            st.outcome_err = result.err().map(|e| format!("{e:#}"));
            st.gen_done = true;
        } else {
            drop(applies);
            terminal_direct(&inner, id, result);
        }
    } else {
        terminal_direct(&inner, id, result);
    }
}

/// Finish or fail job `id` in the queue directly (non-apply path).
fn terminal_direct(inner: &Inner, id: u64, result: anyhow::Result<()>) {
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

/// If job `id` is an apply-mode job whose generation just finished,
/// finalize it: on generation failure surface the error; otherwise parse
/// the response, write the files back to the dev-project actor, push the
/// summary in-band, and `finish`. No-op for plain generation jobs or
/// jobs still generating. Runs on the actor thread (it needs `ctx`).
pub(crate) async fn maybe_finalize_apply(inner: &Inner, ctx: &mut AiCtx, id: u64) {
    // Take the record out iff generation is done — removing it here is
    // the finalize-exactly-once guard.
    let state = {
        let mut applies = inner.apply.lock().expect("apply mutex poisoned");
        match applies.get(&id) {
            Some(st) if st.gen_done => applies.remove(&id),
            _ => None,
        }
    };
    let Some(state) = state else { return };

    if let Some(err) = state.outcome_err {
        inner
            .jobs
            .lock()
            .expect("jobs mutex poisoned")
            .fail(id, err);
        return;
    }

    match crate::actor_change::run_apply(
        ctx,
        state.project_id,
        &state.branch,
        &state.base_commit,
        &state.full_text,
    )
    .await
    {
        Ok(summary) => {
            let mut jobs = inner.jobs.lock().expect("jobs mutex poisoned");
            jobs.push(id, summary.as_bytes());
            jobs.finish(id);
        }
        Err(e) => {
            inner.jobs.lock().expect("jobs mutex poisoned").fail(id, e);
        }
    }
}

/// The standard `job_poll` reply for `id` — `Args { data, done, error }`
/// rkyv-encoded. `data` is the tokens (and, at the terminal, apply
/// summary) accumulated since the last poll.
pub(crate) fn poll_generation(inner: &Inner, id: u64) -> Vec<u8> {
    inner
        .jobs
        .lock()
        .expect("jobs mutex poisoned in poll_generation")
        .poll_reply(id)
        .encode()
}

/// Drop a generation job, returning `true` if one was present. Also
/// clears any lingering apply record (a release before finalize cancels
/// the write-back rather than orphaning the record).
pub(crate) fn release_generation(inner: &Inner, id: u64) -> bool {
    inner
        .apply
        .lock()
        .expect("apply mutex poisoned")
        .remove(&id);
    inner
        .jobs
        .lock()
        .expect("jobs mutex poisoned in release_generation")
        .release(id)
}
