//! AI extension — exposes a `generate(prompt, max_tokens) -> String`
//! handler backed by a local quantized GGUF model run on the CPU
//! via `candle`.
//!
//! Phase 6 scaffold:
//!
//! - **Fetch on first use.** The model and tokenizer files are
//!   downloaded from HuggingFace (`hf-hub` crate) into
//!   `$XDG_CACHE_HOME/vos-ai/models/<repo>/<file>` the first time
//!   `generate` is called. Subsequent invocations reuse the cache.
//! - **Configurable.** Init args (`[[extension]] init = { model_repo
//!   = "...", model_file = "...", ... }` in the space manifest)
//!   override every defaultable knob. Defaults aim at a small
//!   coding model that runs on a laptop CPU
//!   (Qwen2.5-Coder-0.5B-Instruct Q4_K_M).
//! - **Synchronous.** v1 returns the full completion in one reply;
//!   streaming + cancellation are deferred until the generate
//!   loop has a real backpressure story.
//!
//! ## Lifecycle
//!
//! Service-mode extension. `run()` idles in a shutdown poll; all
//! real work arrives through `vos_service_handle_invoke`. The
//! model loads lazily inside the first `generate` call so daemon
//! startup isn't penalised even when the manifest enables the
//! extension but nothing invokes it.

mod config;
mod ext;
mod fetch;
mod generate;

pub use config::InitConfig;

vos::service_main!(
    ext::AiExtension,
    caps = ["fs.cache", "net.http.outbound", "tokio-runtime"],
    cli = [stop],
);
