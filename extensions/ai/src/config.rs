//! Init-arg parsing for the AI extension.
//!
//! Init args arrive at `vos_extension_create` as a raw byte slice
//! — same wire shape `Msg::args` uses inside the rest of the
//! system. The extension parses an rkyv-encoded
//! `vos::value::Args` map; missing keys fall back to the defaults
//! below.
//!
//! Supported keys (all optional):
//!
//! - `model_repo` (str) — HuggingFace repo containing the GGUF.
//! - `model_file` (str) — GGUF filename inside that repo.
//! - `tokenizer_repo` (str) — HuggingFace repo containing the
//!   tokenizer.json. Often the un-quantized sibling of the GGUF
//!   repo, which is why it's a separate field.
//! - `tokenizer_file` (str) — Tokenizer filename inside the repo.
//! - `max_seq_len` (u32) — Maximum context window. Capped at the
//!   model's own limit at load time; defaults to 2048 so a 4-bit
//!   0.5B model fits in <1.5 GB of RAM.

use vos::value::Args;

#[derive(Clone, Debug)]
pub struct InitConfig {
    pub model_repo: String,
    pub model_file: String,
    pub tokenizer_repo: String,
    pub tokenizer_file: String,
    pub max_seq_len: u32,
}

impl Default for InitConfig {
    /// Defaults target Qwen2.5-Coder-0.5B-Instruct, a small
    /// coding-focused model that runs at single-digit tokens/sec
    /// on a laptop CPU. ~400MB on disk after Q4_K_M quantization,
    /// ~1GB resident.
    fn default() -> Self {
        Self {
            model_repo: "Qwen/Qwen2.5-Coder-0.5B-Instruct-GGUF".to_string(),
            model_file: "qwen2.5-coder-0.5b-instruct-q4_k_m.gguf".to_string(),
            tokenizer_repo: "Qwen/Qwen2.5-Coder-0.5B-Instruct".to_string(),
            tokenizer_file: "tokenizer.json".to_string(),
            max_seq_len: 2048,
        }
    }
}

impl InitConfig {
    /// Decode the rkyv-encoded `Args` blob and overlay each
    /// present key onto a default config. Unrecognised keys are
    /// ignored — the extension's defaults already cover everything
    /// the v1 generate path needs.
    pub fn from_args(args: &[u8]) -> Self {
        let mut cfg = Self::default();
        if args.is_empty() {
            return cfg;
        }
        let Some(decoded) = <Args as vos::Decode>::try_decode(args) else {
            vos::log::warn!("ai: failed to decode init args; falling back to defaults");
            return cfg;
        };
        if let Some(s) = decoded.get_str("model_repo") {
            cfg.model_repo = s;
        }
        if let Some(s) = decoded.get_str("model_file") {
            cfg.model_file = s;
        }
        if let Some(s) = decoded.get_str("tokenizer_repo") {
            cfg.tokenizer_repo = s;
        }
        if let Some(s) = decoded.get_str("tokenizer_file") {
            cfg.tokenizer_file = s;
        }
        if let Some(n) = decoded.get_u32("max_seq_len") {
            cfg.max_seq_len = n;
        }
        cfg
    }
}
