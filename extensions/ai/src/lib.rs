//! AI extension — exposes a `generate(prompt, max_tokens) -> String`
//! handler backed by a local quantized GGUF model run on the CPU
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
//! - **Two dispatch shapes.** `generate(prompt, max_tokens) -> String`
//!   is the blocking call; `begin_generate(prompt, max_tokens) -> u64`
//!   spawns an inference worker and returns a `request_id`, then
//!   `poll_generation(request_id) -> GenerationChunk` drains
//!   newly-emitted text. Streaming is the CLI default; the
//!   blocking call stays for the `--no-stream` / scripted-JSON
//!   path.
//!
//! ## Lifecycle
//!
//! Plain **actor-mode** extension (`#[actor]` / `#[messages]`) — request-driven,
//! no `run()` loop. The host drives one invoke (`generate` / `begin_generate` /
//! `poll_generation`) to completion at a time on this agent's thread. The model
//! loads lazily inside the first generate so daemon startup isn't penalised even
//! when the manifest enables the extension but nothing invokes it. The live
//! runtime state ([`runtime::Inner`]: model handle + worker threads) sits behind
//! a `Skip`'d `OnceCell` and re-inits lazily from the persisted [`InitConfig`]
//! after a (re)start. Quiesce one agent with the host's generic `vosx ai stop`
//! (`__stop`).

use std::cell::OnceCell;
use std::sync::Arc;

use vos::log;
use vos::prelude::*;

use crate::requests::GenerationChunk;
use crate::runtime::Inner;

mod config;
mod fetch;
mod generate;
mod requests;
mod runtime;

pub use config::InitConfig;
// `GenerationChunk` is the wire payload `poll_generation` emits.
// External consumers decode the on-wire form via `vos::value::Args`
// rather than this typed struct, so it stays crate-private.

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

    /// Blocking generate: load the model on first use, run the full
    /// inference loop on this thread, reply with the concatenated text.
    /// Replies with a `GenerationChunk` (encoded via `Args` → `Value::Bytes`,
    /// same wire shape as `poll_generation`) so callers get a structured
    /// `error` field rather than a stringly-typed prefix. This call blocks
    /// the agent for the whole inference (acceptable: N=1, the `--no-stream`
    /// / scripted path); streaming callers use `begin_generate` instead.
    #[msg(cli)]
    async fn generate(
        &mut self,
        prompt: String,
        max_tokens: u32,
        _ctx: &mut Context<Self>,
    ) -> Vec<u8> {
        let inner = self.inner();
        let chunk = match runtime::run_generate_blocking(&inner, &prompt, max_tokens) {
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
        chunk.to_args().encode()
    }

    /// Spawn a streaming inference worker and return its `request_id`. The
    /// worker runs on its own thread (holding an `Arc<Inner>` clone, so it
    /// outlives this handler); the caller drains chunks via `poll_generation`.
    #[msg(cli)]
    async fn begin_generate(
        &mut self,
        prompt: String,
        max_tokens: u32,
        _ctx: &mut Context<Self>,
    ) -> u64 {
        let inner = self.inner();
        runtime::begin_generate(&inner, prompt, max_tokens)
    }

    /// Drain newly-emitted text for a streaming `request_id`. Replies with a
    /// `GenerationChunk` (encoded via `Args` → `Value::Bytes` so vosx decodes
    /// it without pulling in candle/tokenizers/hf-hub). On `done = true` the
    /// request entry is removed.
    #[msg(cli)]
    async fn poll_generation(&mut self, request_id: u64, _ctx: &mut Context<Self>) -> Vec<u8> {
        let inner = self.inner();
        let chunk = runtime::poll_generation(&inner, request_id);
        chunk.to_args().encode()
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
