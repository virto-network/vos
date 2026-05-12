//! Inference: load the GGUF model + tokenizer, run a token loop,
//! return decoded text.
//!
//! v1 is the simplest correct loop:
//!
//! - **Greedy-ish sampling** through candle's `LogitsProcessor`
//!   with a temperature of 0.7 + top-p 0.9, fixed seed. Tunable
//!   knobs land later when there's a use case asking for them.
//! - **No streaming.** The caller waits for the full completion;
//!   the reply carries the decoded text once the loop hits EOS or
//!   `max_tokens`. Streaming would be a second handler that
//!   returns a request id + a poll endpoint.
//! - **Single-threaded.** The owning extension wraps `ModelHandle`
//!   in a mutex; concurrent `generate` invokes serialise.
//!
//! The chat-template logic is hand-rolled for Qwen2.5-Instruct
//! (`<|im_start|>{role}\n{text}<|im_end|>`). Other models will
//! need their own template — keeping it inline rather than
//! pulling in a templating crate so the dep surface stays small.

use std::path::PathBuf;

use anyhow::{Context, Result, anyhow, bail};
use candle_core::{Device, Tensor};
use candle_transformers::generation::LogitsProcessor;
use candle_transformers::models::quantized_qwen2::ModelWeights;
use tokenizers::Tokenizer;

use crate::config::InitConfig;
use crate::fetch::fetch_to_cache;

/// Owned, loaded model + tokenizer. Cheap to clone-via-reference
/// (the underlying weights aren't), expensive to construct (we
/// pay the GGUF read + tokenizer parse). The extension creates
/// exactly one of these per running process, lazily on the first
/// `generate` call.
pub struct ModelHandle {
    model: ModelWeights,
    tokenizer: Tokenizer,
    device: Device,
    eos_token_id: u32,
    /// Cached from the init config so the loop can refuse a
    /// caller-requested `max_tokens` that would blow past the
    /// model's context window. v1 uses this as a soft cap;
    /// hitting it just stops generation.
    max_seq_len: usize,
}

impl ModelHandle {
    /// Fetch (or reuse cached) model + tokenizer files and load
    /// them into memory. CPU-only in v1 — `Device::Cpu` keeps the
    /// build from needing CUDA/Metal feature flags at this stage.
    pub fn load(config: &InitConfig) -> Result<Self> {
        let model_path =
            fetch_to_cache(&config.model_repo, &config.model_file).context("fetch model GGUF")?;
        let tokenizer_path = fetch_to_cache(&config.tokenizer_repo, &config.tokenizer_file)
            .context("fetch tokenizer.json")?;

        let device = Device::Cpu;
        let model = load_model_weights(&model_path, &device)?;
        let tokenizer = Tokenizer::from_file(&tokenizer_path)
            .map_err(|e| anyhow!("parse tokenizer.json at {}: {e}", tokenizer_path.display()))?;

        // Qwen2.5-Instruct uses `<|im_end|>` as the conversation-
        // turn terminator. If the tokenizer doesn't know about it
        // (e.g. an operator pointed `tokenizer_repo` at a base
        // model), fail loudly rather than silently generating
        // forever — the alternative is a runaway loop that hits
        // max_tokens every time.
        let eos_token_id = tokenizer.token_to_id("<|im_end|>").ok_or_else(|| {
            anyhow!("tokenizer has no <|im_end|> token (need an Instruct variant)")
        })?;

        Ok(Self {
            model,
            tokenizer,
            device,
            eos_token_id,
            max_seq_len: config.max_seq_len as usize,
        })
    }

    /// Generate up to `max_tokens` tokens for `prompt`, calling
    /// `on_chunk` with each newly-decoded text chunk (the diff
    /// between successive incremental decodes). The callback is
    /// invoked at least once on success (possibly with an empty
    /// string if the model emits EOS immediately) and returns
    /// `false` to abort the loop early; `true` to keep going.
    ///
    /// We decode the *cumulative* token list each iteration and
    /// emit only the suffix that's new since the last emit. This
    /// is the standard pattern when token boundaries don't line
    /// up with UTF-8 codepoints — naively decoding each token in
    /// isolation produces replacement characters for multi-byte
    /// sequences split across tokens.
    pub fn generate_stream<F>(
        &mut self,
        prompt: &str,
        max_tokens: u32,
        mut on_chunk: F,
    ) -> Result<()>
    where
        F: FnMut(&str) -> bool,
    {
        // Apply the Qwen2.5-Instruct chat template manually.
        // Single-user-turn shape; multi-turn history is a v2 concern.
        let templated = format!("<|im_start|>user\n{prompt}<|im_end|>\n<|im_start|>assistant\n");
        let encoding = self
            .tokenizer
            .encode(templated, true)
            .map_err(|e| anyhow!("tokenize prompt: {e}"))?;
        let prompt_tokens: Vec<u32> = encoding.get_ids().to_vec();
        if prompt_tokens.is_empty() {
            bail!("prompt encoded to zero tokens — refusing to generate");
        }

        // 0.7 temperature + 0.9 top-p gives mildly creative output
        // without obvious wandering. Seed is fixed for determinism
        // in this v1 — once the extension has a per-call args
        // surface we can let the caller pick.
        let mut logits_processor = LogitsProcessor::new(42, Some(0.7), Some(0.9));

        let cap = (prompt_tokens.len() + max_tokens as usize).min(self.max_seq_len);
        let max_new = cap.saturating_sub(prompt_tokens.len());
        if max_new == 0 {
            // Prompt already fills the context — nothing left to
            // generate. Emit one empty chunk so the caller sees a
            // single "done" signal and exits cleanly.
            on_chunk("");
            return Ok(());
        }

        // ── Prompt-prefill pass: feed every prompt token at once
        //    to populate the model's KV cache. We only sample
        //    after this — the prefill's last-token logits are the
        //    first new token's distribution.
        let input = Tensor::new(prompt_tokens.as_slice(), &self.device)?.unsqueeze(0)?;
        let logits = self.model.forward(&input, 0)?;
        let mut next_token = sample_last(&mut logits_processor, &logits)?;
        let mut generated: Vec<u32> = Vec::with_capacity(max_new);
        let mut emitted_bytes: usize = 0;
        let mut idx_pos = prompt_tokens.len();

        // ── Decode loop. Each iteration appends the sampled
        //    token, decodes the cumulative list, emits the suffix
        //    that's new since last time. Breaks on EOS, the
        //    max_tokens cap, or the callback returning false.
        loop {
            if next_token == self.eos_token_id {
                break;
            }
            generated.push(next_token);

            // Re-decode the whole token list. Cheaper than it
            // looks — the tokenizer's BPE is linear in the token
            // count and 0.5B-Q4 inference is the bottleneck by
            // orders of magnitude.
            let text = self
                .tokenizer
                .decode(&generated, true)
                .map_err(|e| anyhow!("decode generated tokens: {e}"))?;
            if text.len() > emitted_bytes {
                // Carve off the new suffix. `decode` is stable
                // enough across appends that the prefix is
                // byte-identical to the prior call's output, so a
                // simple byte-slice gives us the new chunk.
                let chunk = &text[emitted_bytes..];
                if !on_chunk(chunk) {
                    return Ok(());
                }
                emitted_bytes = text.len();
            }

            if generated.len() >= max_new {
                break;
            }
            let input = Tensor::new(&[next_token], &self.device)?.unsqueeze(0)?;
            let logits = self.model.forward(&input, idx_pos)?;
            next_token = sample_last(&mut logits_processor, &logits)?;
            idx_pos += 1;
        }

        // If we exited the loop without ever emitting (e.g. the
        // very first sampled token was EOS), give the caller one
        // empty chunk so its "done" signal fires cleanly.
        if emitted_bytes == 0 {
            on_chunk("");
        }
        Ok(())
    }

    /// Blocking wrapper around [`generate_stream`]: drains every
    /// chunk into one `String` and returns. Used by the old
    /// `generate` dispatch arm + the CLI's `--no-stream` mode.
    pub fn generate(&mut self, prompt: &str, max_tokens: u32) -> Result<String> {
        let mut buf = String::new();
        self.generate_stream(prompt, max_tokens, |chunk| {
            buf.push_str(chunk);
            true
        })?;
        Ok(buf)
    }
}

/// Open the GGUF file and hand it to candle's quantized Qwen2
/// loader. Pulled out so the file-handle lifetime is explicit —
/// `Content::read` keeps borrowing the file across the subsequent
/// `from_gguf` call.
fn load_model_weights(path: &PathBuf, device: &Device) -> Result<ModelWeights> {
    let mut file = std::fs::File::open(path).with_context(|| format!("open {}", path.display()))?;
    let content = candle_core::quantized::gguf_file::Content::read(&mut file)
        .with_context(|| format!("read GGUF header from {}", path.display()))?;
    ModelWeights::from_gguf(content, &mut file, device)
        .context("build Qwen2 ModelWeights from GGUF")
}

/// Extract the last-position logits from a `(batch, seq, vocab)` or
/// `(batch, vocab)` tensor and sample. Candle's quantized models
/// vary in shape between prefill and decode steps — this helper
/// hides that.
fn sample_last(processor: &mut LogitsProcessor, logits: &Tensor) -> Result<u32> {
    let logits = logits.squeeze(0)?;
    let logits = if logits.dims().len() == 2 {
        let last = logits.dim(0)? - 1;
        logits.get(last)?
    } else {
        logits
    };
    Ok(processor.sample(&logits)?)
}
