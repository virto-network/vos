//! Fetch model + tokenizer files from HuggingFace into a local
//! cache on first use.
//!
//! Cache layout: `$XDG_CACHE_HOME/vos-ai/hf/<repo>/<file>` —
//! `hf-hub`'s native layout, just rooted under `vos-ai/` so a
//! single XDG_CACHE_HOME override scopes the whole extension's
//! state.

use std::path::PathBuf;
use std::sync::OnceLock;

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
///
/// Progress reporting is enabled when stderr is a tty — gives
/// the operator a visible indicator on the first ~400MB fetch.
/// Disabled on non-tty stderr (CI, log capture) to keep output
/// clean.
pub fn fetch_to_cache(repo: &str, file: &str) -> Result<PathBuf> {
    let cache_root = cache_root_ensured()?;

    let api = ApiBuilder::new()
        .with_cache_dir(cache_root.to_path_buf())
        .with_progress(stderr_is_tty())
        .build()
        .context("build hf-hub api")?;
    let path = api
        .model(repo.to_string())
        .get(file)
        .with_context(|| format!("download {repo}/{file}"))?;
    Ok(path)
}

/// Resolve and create the cache root once per process; subsequent
/// calls hit the OnceLock without touching the filesystem. The
/// per-fetch `create_dir_all` we used to run was harmless but
/// wasteful — fetches happen on the hot path of `generate`.
fn cache_root_ensured() -> Result<&'static PathBuf> {
    static ROOT: OnceLock<PathBuf> = OnceLock::new();
    if let Some(p) = ROOT.get() {
        return Ok(p);
    }
    let path = cache_root();
    std::fs::create_dir_all(&path)
        .with_context(|| format!("create cache root {}", path.display()))?;
    // First writer wins; if two threads race, the other's value
    // is dropped but the on-disk state is identical.
    Ok(ROOT.get_or_init(|| path))
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

/// Cheap stderr-isatty check. Falls back to "no" on platforms
/// where the syscall is missing — the worst case is a silent
/// download, which is the prior behavior.
fn stderr_is_tty() -> bool {
    // SAFETY: isatty is a thread-safe syscall on every Unix the
    // workspace supports; the fd 2 we hand it is always valid
    // for the lifetime of the process. libc::STDERR_FILENO is 2;
    // hard-coded to avoid a libc dependency just for one constant.
    #[cfg(unix)]
    unsafe extern "C" {
        fn isatty(fd: i32) -> i32;
    }
    #[cfg(unix)]
    {
        unsafe { isatty(2) == 1 }
    }
    #[cfg(not(unix))]
    {
        false
    }
}
