//! AI extension — exposes a `generate(prompt, max_tokens) -> String`
//! handler backed by a local quantized GGUF model run on the CPU
//! via `candle`.
//!
//! Phase 6 scaffold:
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
//! Service-mode extension. `run()` idles in a shutdown poll; all
//! real work arrives through `vos_service_handle_invoke`. The
//! model loads lazily inside the first `generate` / `begin_generate`
//! call so daemon startup isn't penalised even when the manifest
//! enables the extension but nothing invokes it.

mod config;
mod ext;
mod fetch;
mod generate;
mod requests;

pub use config::InitConfig;
// `GenerationChunk` is the wire payload `poll_generation` emits.
// External consumers decode the on-wire form via `vos::value::Args`
// rather than this typed struct, so it stays crate-private.

vos::service_main!(
    ext::AiExtension,
    caps = [
        "fs.cache",
        "net.http.outbound",
        "net.libp2p.dial",
        "tokio-runtime",
    ],
    cli = [stop],
);
