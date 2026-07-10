//! AI extension — exposes a `generate(prompt, max_tokens) -> u64`
//! `#[msg(job)]` handler (returns a job id; the streamed text comes back
//! via `job_poll`) backed by a local quantized GGUF model run on the CPU
//! via `candle`.
//!
//! - **Fetch on first use.** The model and tokenizer files are
//!   downloaded from HuggingFace (`hf-hub` crate) into
//!   `$XDG_CACHE_HOME/vos-ai/hf/<repo>/<file>` the first time
//!   `generate` is called. Subsequent invocations reuse the cache.
//! - **Configurable.** Init args (`[[extension]] init = { model_repo
//!   = "...", model_file = "...", ... }` in the space manifest)
//!   override every defaultable knob. Defaults aim at a small
//!   coding model that runs on a laptop CPU
//!   (Qwen2.5-Coder-0.5B-Instruct Q4_K_M).
//! - **Job dispatch.** `generate(prompt, max_tokens) -> u64` is a
//!   `#[msg(job)]` begin: it spawns an inference worker and returns a
//!   job id, then the reserved `job_poll(job_id) -> Vec<u8>` (the
//!   standard `Args { data, done, error }` shape) drains newly-decoded
//!   tokens and `job_release(job_id) -> u8` drops the finished job. The
//!   `vosx` generic job driver polls + streams these for you.
//! - **Actor-source assistant.** `actor_change(project, branch, prompt,
//!   apply, max_tokens) -> u64` is a second `#[msg(job)]` begin: it
//!   reads a dev-project's current source over the host invoke path,
//!   builds a context-rich prompt, streams a completion, and — with
//!   `apply` — commits the parsed files back to the project. See
//!   [`actor_change`].
//!
//! ## Lifecycle
//!
//! Plain **actor-mode** extension (`#[actor]` / `#[messages]`) — request-driven,
//! no `run()` loop. The host drives one invoke (`generate` / `actor_change` /
//! `job_poll` / `job_release`) to completion at a time on this agent's thread.
//! The model loads lazily inside the first generate so daemon startup isn't
//! penalised even when the manifest enables the extension but nothing invokes
//! it. The live runtime state ([`runtime::Inner`]: model handle + the job queue)
//! sits behind a `Skip`'d `OnceCell` and re-inits lazily from the persisted
//! [`InitConfig`] after a (re)start. `inner()` itself never `.await`s, so the
//! `OnceCell` can't be raced even though `actor_change` / `job_poll` do await
//! host round-trips afterward (the host still drives one invoke at a time).
//! Quiesce one agent with the host's generic `vosx ai stop` (`__stop`).

use std::cell::OnceCell;
use std::sync::Arc;

use vos::log;
use vos::prelude::*;

use crate::runtime::Inner;

mod actor_change;
mod config;
mod fetch;
mod generate;
mod runtime;

pub use config::InitConfig;

/// This extension's actor [`vos::Context`] — the handle `actor_change`
/// threads through to reach the dev-project actor via `ctx.ask_dispatch`
/// (the host invoke path).
pub(crate) type AiCtx = vos::Context<AiExtension>;

#[actor(caps = ["fs.cache", "net.http.outbound", "net.libp2p.dial", "tokio-runtime"])]
pub struct AiExtension {
    /// Init config (rkyv-persisted) — a warm restart keeps the operator's
    /// configured model. See [`InitConfig`].
    config: InitConfig,
    /// Live runtime state, lazily built from `config` on the first generate.
    /// Skipped by rkyv (mutexes + worker threads aren't serialisable); a
    /// restored actor re-inits it on next use. `OnceCell` (single-threaded
    /// interior mutability) is safe here because the host drives this actor
    /// from one cooperative executor thread (N=1), and `inner()` never
    /// `.await`s, so two handlers can't race the cell.
    #[rkyv(with = vos::rkyv::with::Skip)]
    inner: OnceCell<Arc<Inner>>,
}

#[messages]
impl AiExtension {
    /// Constructor invoked by the host with the rkyv-encoded
    /// `vos::value::Args` init-args blob — see [`InitConfig::from_args`]
    /// for the schema. An empty slice keeps every default.
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
            config,
            inner: OnceCell::new(),
        }
    }

    /// Begin a streaming generation job; returns the job id to poll. The
    /// worker runs inference on its own thread (holding an `Arc<Inner>` clone,
    /// so it outlives this handler) and pushes decoded tokens into the shared
    /// job queue. The `vosx` generic job driver polls + streams; a scripted
    /// caller polls `job_poll` and releases with `job_release`.
    #[msg(job, cli)]
    async fn generate(
        &mut self,
        prompt: String,
        max_tokens: u32,
        _ctx: &mut Context<Self>,
    ) -> u64 {
        let inner = self.inner();
        runtime::begin_generate(&inner, prompt, max_tokens)
    }

    /// Ask the model to write or modify a VOS actor's source, with the
    /// dev-project's current files injected as context; returns the job id to
    /// poll. `project` is the dev-project instance's ServiceId (resolve the
    /// name to an id first, e.g. from `vosx space agents`). `branch` is where
    /// `--apply` commits and where the prompt context is read from — by
    /// convention `ai/<your-node-prefix>/suggested` (a per-identity side branch
    /// `vosx dev merge` also defaults to), falling back to `main` for the
    /// context when the branch doesn't exist yet. With `apply = true` the
    /// parsed fenced code blocks are committed back as a new commit on `branch`
    /// and the summary (files, commit hash, warnings) streams in-band as the
    /// job's terminal chunk; otherwise the completion is print-only.
    #[msg(job, cli)]
    async fn actor_change(
        &mut self,
        project: u32,
        branch: String,
        prompt: String,
        apply: bool,
        max_tokens: u32,
        ctx: &mut Context<Self>,
    ) -> u64 {
        let inner = self.inner();
        // Resolve the source commit + fetch the project's files up front —
        // both need the actor's `Context`, which the generation worker lacks.
        let base_commit = match actor_change::resolve_context_head(ctx, project, &branch).await {
            Ok(c) => c,
            Err(msg) => return runtime::begin_failed(&inner, msg),
        };
        let files = match actor_change::fetch_project_files(ctx, project, &base_commit).await {
            Ok(f) => f,
            Err(msg) => return runtime::begin_failed(&inner, msg),
        };
        let full_prompt = actor_change::build_prompt(&files, &prompt);
        runtime::begin_actor_change(&inner, full_prompt, max_tokens, project, branch, base_commit, apply)
    }

    /// Reserved `job_poll`: drain a generation's newly-decoded tokens as the
    /// standard `Args { data, done, error }` reply (encoded so vosx decodes it
    /// without pulling in candle/tokenizers/hf-hub). For an `actor_change
    /// --apply` job it also finalizes the write-back once generation is done —
    /// parse + commit happen here because this handler holds the `Context` the
    /// worker can't.
    #[msg]
    async fn job_poll(&mut self, job_id: u64, ctx: &mut Context<Self>) -> Vec<u8> {
        let inner = self.inner();
        runtime::maybe_finalize_apply(&inner, ctx, job_id).await;
        runtime::poll_generation(&inner, job_id)
    }

    /// Reserved `job_release`: drop a finished generation job. Idempotent —
    /// `1` if a job was removed, `0` if the id was already gone.
    #[msg]
    async fn job_release(&mut self, job_id: u64, _ctx: &mut Context<Self>) -> u8 {
        u8::from(runtime::release_generation(&self.inner(), job_id))
    }
}

impl AiExtension {
    /// Get the live [`Inner`], building it on first use from the persisted
    /// `config`. Returns a cheap `Arc` clone; the worker threads hold their
    /// own clones so `Inner` survives until the last one exits even if the
    /// actor is dropped.
    fn inner(&self) -> Arc<Inner> {
        self.inner
            .get_or_init(|| {
                log::info!("ai: initialising runtime (model loads on first generate)");
                Arc::new(Inner::new(self.config.clone()))
            })
            .clone()
    }
}
