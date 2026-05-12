//! Fetch model + tokenizer files from HuggingFace into a local
//! cache on first use.
//!
//! Cache layout: `$XDG_CACHE_HOME/vos-ai/hf/<repo>/<file>` —
//! `hf-hub`'s native layout, just rooted under `vos-ai/` so a
//! single XDG_CACHE_HOME override scopes the whole extension's
//! state.

use std::path::PathBuf;

use anyhow::{Context, Result};
use hf_hub::api::sync::ApiBuilder;

/// Download `file` from `repo` if it isn't in the cache yet, and
/// return the local path. The first call for a fresh cache pays
/// the network round-trip; subsequent calls resolve from disk.
///
/// We pin `hf-hub`'s cache directory to our own `vos-ai/hf/`
/// subtree instead of `~/.cache/huggingface/`, so an `rm -rf` on
/// `vos-ai` clears everything the AI extension owns without
/// nuking unrelated HF state the user might have.
pub fn fetch_to_cache(repo: &str, file: &str) -> Result<PathBuf> {
    let cache_root = cache_root();
    std::fs::create_dir_all(&cache_root)
        .with_context(|| format!("create cache root {}", cache_root.display()))?;

    let api = ApiBuilder::new()
        .with_cache_dir(cache_root.clone())
        .with_progress(false)
        .build()
        .context("build hf-hub api")?;
    let path = api
        .model(repo.to_string())
        .get(file)
        .with_context(|| format!("download {repo}/{file}"))?;
    Ok(path)
}

/// `$XDG_CACHE_HOME/vos-ai/hf` — sits alongside vosx's blob cache
/// (`$XDG_CACHE_HOME/vosx/blobs`) and the dev extension's source
/// cache (`$XDG_CACHE_HOME/vos-dev/source-cache`). Same XDG
/// semantics as `vosx::paths::xdg_root`: accept whatever the env
/// var resolves to (no absolute-path filter), fall back to
/// `$HOME/.cache`, then a relative `.cache` as last resort.
fn cache_root() -> PathBuf {
    let from_home = || std::env::var_os("HOME").map(|h| PathBuf::from(h).join(".cache"));
    let base = std::env::var_os("XDG_CACHE_HOME")
        .map(PathBuf::from)
        .or_else(from_home)
        .unwrap_or_else(|| PathBuf::from(".cache"));
    base.join("vos-ai").join("hf")
}
