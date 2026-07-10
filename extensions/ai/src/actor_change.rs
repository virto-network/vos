//! `actor_change` — ask the model to write or modify a VOS actor's
//! source, with the project's current files injected into the prompt
//! as context, and (optionally) commit the parsed result back.
//!
//! This is the extension-side of what used to be `vosx ai actor`: the
//! orchestration that bridges a dev-project actor's commit DAG and the
//! model runtime now lives here, reached over the host invoke path with
//! [`vos::Context::ask_dispatch`] instead of a client-side daemon dial.
//!
//! Flow (driven by [`crate::AiExtension::actor_change`]):
//!
//! 1. Resolve the source commit — the head of `branch`, falling back to
//!    `main` when the side branch doesn't exist yet — and walk its
//!    `files`, decoding each source-ish blob as UTF-8 under a per-file
//!    cap ([`fetch_project_files`]).
//! 2. Build a prompt: a fixed preamble of VOS actor conventions + one
//!    canonical example + the current source + the task ([`build_prompt`]).
//! 3. Stream generation as a job (the runtime worker pushes tokens into
//!    the shared [`vos::jobs::JobQueue`]).
//! 4. On `apply`, once generation finishes, parse the fenced code blocks
//!    out of the reply and write them back as a commit on `branch`
//!    ([`run_apply`]) — the summary (commit hash, files, warnings) is
//!    streamed in-band as the job's terminal chunk.

use std::time::{SystemTime, UNIX_EPOCH};

use vos::actors::context::ServiceId;
use vos::value::{Msg, TAG_DYNAMIC, Value};
use vos::{Decode, Encode};

use crate::AiCtx;

/// Per-file content cap when stuffing the prompt. A few-KB budget per
/// file keeps the context window from blowing out even on multi-file
/// projects; v1 truncates with an explicit marker so the model knows
/// the file was clipped.
const PER_FILE_BYTE_CAP: usize = 4096;

/// Whole-tree byte cap for the prompt's source-injection section. Hit
/// it and we stop including files; the preamble + task still go through.
const TOTAL_SOURCE_CAP: usize = 32_768;

// ── Host round-trip plumbing ─────────────────────────────────────────

/// Wrap a dynamic `Msg` as the `TAG_DYNAMIC` invoke payload the host
/// dispatch path expects (same shape the dev extension sends).
fn dyn_payload(msg: &Msg) -> Vec<u8> {
    let encoded = msg.encode();
    let mut payload = Vec::with_capacity(1 + encoded.len());
    payload.push(TAG_DYNAMIC);
    payload.extend_from_slice(&encoded);
    payload
}

/// Dispatch `msg` to the local dev-project actor at `project_id` and
/// decode the raw reply into a `Value`. `Err` carries a human-readable
/// reason (transport failure or an undecodable reply).
async fn invoke(ctx: &mut AiCtx, project_id: u32, msg: &Msg) -> Result<Value, String> {
    let raw = ctx
        .ask_dispatch(ServiceId(project_id), &dyn_payload(msg))
        .await
        .ok_or_else(|| format!("dev-project {project_id}: no reply (transport error)"))?;
    <Value as Decode>::try_decode(&raw)
        .ok_or_else(|| format!("dev-project {project_id}: reply didn't decode as a Value"))
}

/// Extract `Vec<u8>` from a typed-handler reply. `Value::Unit` maps to
/// an empty vec (the caller decides whether "empty" means "missing").
fn value_bytes(v: Value, label: &str) -> Result<Vec<u8>, String> {
    match v {
        Value::Bytes(b) => Ok(b),
        Value::Unit => Ok(Vec::new()),
        other => Err(format!("{label} returned {other:?}, expected Bytes")),
    }
}

// ── Source-commit resolution + file fetch ────────────────────────────

/// Fetch a branch's head, or `None` when the branch doesn't exist (the
/// actor replies with empty bytes in that case).
async fn fetch_branch_head(
    ctx: &mut AiCtx,
    project_id: u32,
    branch: &str,
) -> Result<Option<Vec<u8>>, String> {
    let reply = invoke(ctx, project_id, &Msg::new("head").with("branch", branch.to_string())).await?;
    let bytes = value_bytes(reply, &format!("head('{branch}')"))?;
    Ok(if bytes.is_empty() { None } else { Some(bytes) })
}

/// Pick the commit we show the model + base the working change on: the
/// target branch's head when it exists, else `main`'s. Bails if neither
/// has a head yet.
pub(crate) async fn resolve_context_head(
    ctx: &mut AiCtx,
    project_id: u32,
    branch: &str,
) -> Result<Vec<u8>, String> {
    if let Some(head) = fetch_branch_head(ctx, project_id, branch).await? {
        return Ok(head);
    }
    if branch == "main" {
        return Err("project has no 'main' branch yet — commit source first".to_string());
    }
    fetch_branch_head(ctx, project_id, "main").await?.ok_or_else(|| {
        format!("project has no '{branch}' or 'main' branch yet — commit source first")
    })
}

/// One source file lifted out of the project's commit tree.
pub(crate) struct ProjectFile {
    path: String,
    content: String,
    /// `true` if we truncated the bytes at `PER_FILE_BYTE_CAP`.
    truncated: bool,
}

/// Walk `commit_hash`'s file tree and pull the source-ish files (.rs,
/// .toml, .md, …) as UTF-8, each capped at `PER_FILE_BYTE_CAP` and the
/// whole set at `TOTAL_SOURCE_CAP`. Binary metadata and RustAst blobs
/// are skipped (rendering AST back to text would pull the dev-ast crate
/// in for a prompt-context feature that doesn't warrant it).
pub(crate) async fn fetch_project_files(
    ctx: &mut AiCtx,
    project_id: u32,
    commit_hash: &[u8],
) -> Result<Vec<ProjectFile>, String> {
    let reply = invoke(
        ctx,
        project_id,
        &Msg::new("get_commit").with("hash", commit_hash.to_vec()),
    )
    .await?;
    let commit_bytes = value_bytes(reply, "get_commit")?;
    if commit_bytes.is_empty() {
        return Err("get_commit returned empty bytes — commit not stored".to_string());
    }
    let commit = <dev_project::CommitNode as Decode>::try_decode(&commit_bytes)
        .ok_or_else(|| "get_commit reply isn't a valid CommitNode".to_string())?;

    let mut total = 0usize;
    let mut out: Vec<ProjectFile> = Vec::new();
    for file in &commit.files {
        if !is_interesting_path(&file.path) {
            continue;
        }
        let blob_reply = invoke(
            ctx,
            project_id,
            &Msg::new("get_blob").with("hash", file.blob.to_vec()),
        )
        .await?;
        let blob_bytes = match blob_reply {
            Value::Bytes(b) if !b.is_empty() => b,
            _ => continue,
        };
        let blob = match <dev_project::BlobObject as Decode>::try_decode(&blob_bytes) {
            Some(b) => b,
            None => continue,
        };
        // Only Raw blobs are prompt-injectable text; RustAst needs the
        // dev-ast renderer, which this extension deliberately doesn't
        // pull in.
        if !matches!(blob.kind, dev_project::BlobKind::Raw) {
            continue;
        }
        let mut text = match String::from_utf8(blob.bytes) {
            Ok(s) => s,
            Err(_) => continue,
        };
        let truncated = text.len() > PER_FILE_BYTE_CAP;
        if truncated {
            let cut = nearest_char_boundary(&text, PER_FILE_BYTE_CAP);
            text.truncate(cut);
            text.push_str("\n/* … truncated for prompt context */\n");
        }
        total += text.len();
        out.push(ProjectFile {
            path: file.path.clone(),
            content: text,
            truncated,
        });
        if total >= TOTAL_SOURCE_CAP {
            break;
        }
    }
    Ok(out)
}

fn nearest_char_boundary(s: &str, target: usize) -> usize {
    if target >= s.len() {
        return s.len();
    }
    let mut i = target;
    while i > 0 && !s.is_char_boundary(i) {
        i -= 1;
    }
    i
}

fn is_interesting_path(p: &str) -> bool {
    p.ends_with(".rs")
        || p.ends_with(".toml")
        || p.ends_with(".md")
        || p.ends_with(".txt")
        || p.ends_with(".json")
}

// ── Prompt assembly ──────────────────────────────────────────────────

/// Compose the full prompt the model sees. Layout: preamble (VOS actor
/// conventions + a canonical example) → current source fenced by path →
/// the task → response-format instructions.
pub(crate) fn build_prompt(files: &[ProjectFile], user_prompt: &str) -> String {
    let mut s = String::with_capacity(8192);
    s.push_str(PROMPT_PREAMBLE);
    s.push_str("\n\n# Current project source\n\n");
    if files.is_empty() {
        s.push_str("(The project has no source files yet — start fresh.)\n");
    } else {
        for f in files {
            let lang = if f.path.ends_with(".rs") {
                "rust"
            } else if f.path.ends_with(".toml") {
                "toml"
            } else if f.path.ends_with(".json") {
                "json"
            } else {
                ""
            };
            s.push_str(&format!("## {}\n```{lang}\n", f.path));
            s.push_str(&f.content);
            if !f.content.ends_with('\n') {
                s.push('\n');
            }
            s.push_str("```\n\n");
            if f.truncated {
                s.push_str("(this file was truncated for prompt context)\n\n");
            }
        }
    }
    s.push_str("\n# Task\n\n");
    s.push_str(user_prompt.trim());
    s.push_str("\n\n# Response\n\n");
    s.push_str(
        "Return the new or updated files as one fenced code block per file. \
         Put the file path on a line by itself immediately before each block, \
         like:\n\n\
         src/lib.rs:\n\
         ```rust\n\
         …\n\
         ```\n\n\
         Only emit files you are creating or changing. Keep the response \
         focused — no extra commentary outside the code blocks.\n",
    );
    s
}

const PROMPT_PREAMBLE: &str = r#"# VOS Actor Conventions

You are helping a developer write a Rust actor for VOS, a peer-to-peer
OS. Actors are small Rust crates that compile to a Polkadot Virtual
Machine (PVM) blob and run inside a space. The shape is:

```rust
use vos::prelude::*;

#[actor]
pub struct Counter {
    count: u32,
}

#[messages]
impl Counter {
    fn new() -> Self {
        Self { count: 0 }
    }

    #[msg]
    async fn inc(&mut self) -> u32 {
        self.count += 1;
        self.count
    }

    #[msg]
    async fn get(&self) -> u32 {
        self.count
    }
}
```

Rules every actor follows:

- The struct is annotated with `#[actor]`. Fields hold the persistent
  state.
- The constructor is `fn new(args…) -> Self` (sync, takes init args).
- Handler methods are inside `#[messages] impl ...` and marked `#[msg]`.
- Every handler is `async fn`, with `&mut self` for mutating handlers
  and `&self` for read-only ones.
- Argument and return types must be rkyv-serializable primitives
  (`u32`, `u64`, `i32`, `String`, `Vec<u8>`, `bool`) or rkyv-derived
  custom structs.
- `use vos::prelude::*;` brings the macros in scope. The crate is
  `no_std`-compatible on the PVM target — prefer `alloc` types.

The project's `Cargo.toml` should keep the dev extension's
synthesised dependencies untouched; you usually only need to edit
`src/lib.rs`."#;

// ── Response parsing (--apply) ───────────────────────────────────────

/// One file extracted from the model's response.
#[derive(Debug, PartialEq, Eq)]
struct ParsedFile {
    path: String,
    content: String,
}

/// Aggregate result of parsing the model's response: the files to write
/// + non-fatal warnings surfaced to the operator (duplicate paths,
/// unclosed fences, etc.).
#[derive(Debug, PartialEq, Eq)]
struct ParseResult {
    files: Vec<ParsedFile>,
    warnings: Vec<String>,
}

/// Parse the model's response into `(path, content)` pairs. Tolerates
/// several Markdown path-hint shapes (`path:`, `## path`, `**path:**`,
/// `- path`) followed by a ``` fenced block. Paths are validated (no
/// leading `/`, no `..`, no backslash/null). Two non-fatal failure
/// modes surface as warnings: a duplicate path (last block wins) and an
/// unclosed fence (dropped — committing partial source is worse than
/// committing nothing).
fn parse_response(text: &str) -> ParseResult {
    let mut files: Vec<ParsedFile> = Vec::new();
    let mut warnings: Vec<String> = Vec::new();
    let lines: Vec<&str> = text.lines().collect();
    let mut i = 0;
    let lookback = 3usize;
    while i < lines.len() {
        if is_fence(lines[i]) {
            let mut path: Option<String> = None;
            let start = i.saturating_sub(lookback);
            for j in (start..i).rev() {
                if let Some(p) = extract_path(lines[j]) {
                    path = Some(p);
                    break;
                }
            }
            let mut j = i + 1;
            let mut content = String::new();
            let mut saw_close = false;
            while j < lines.len() {
                if is_fence(lines[j]) {
                    saw_close = true;
                    break;
                }
                content.push_str(lines[j]);
                content.push('\n');
                j += 1;
            }

            if let Some(p) = path {
                if !saw_close {
                    warnings.push(format!(
                        "unclosed code block for '{p}' — likely a truncated \
                         response (max_tokens cut mid-block); skipped",
                    ));
                } else if let Some(existing_pos) = files.iter().position(|f| f.path == p) {
                    warnings.push(format!(
                        "duplicate path '{p}' in response — keeping the later block",
                    ));
                    files[existing_pos] = ParsedFile { path: p, content };
                } else {
                    files.push(ParsedFile { path: p, content });
                }
            }
            i = j.saturating_add(1);
        } else {
            i += 1;
        }
    }
    ParseResult { files, warnings }
}

/// Does this line look like ``` (with or without a language hint)?
fn is_fence(line: &str) -> bool {
    line.trim_start().starts_with("```")
}

/// Pull a path-shaped string out of one line, or `None` when the line
/// doesn't look like a path hint. Handles common Markdown decorations.
fn extract_path(line: &str) -> Option<String> {
    let mut s = line.trim().to_string();
    if s.is_empty() {
        return None;
    }
    while s.starts_with('#') {
        s.remove(0);
    }
    s = s.trim().to_string();
    s = s
        .trim_matches('*')
        .trim_matches('`')
        .trim_matches('_')
        .to_string();
    s = s.trim_end_matches(':').trim().to_string();
    s = s
        .trim_start_matches('-')
        .trim_start_matches('*')
        .trim()
        .to_string();
    if s.is_empty() {
        return None;
    }
    if s.contains(' ') || s.contains('\\') || s.contains('\0') {
        return None;
    }
    if s.starts_with('/') {
        return None;
    }
    for seg in s.split('/') {
        if seg.is_empty() || seg == "." || seg == ".." {
            return None;
        }
    }
    let has_slash = s.contains('/');
    let known_exts = [".rs", ".toml", ".md", ".txt", ".json", ".yaml", ".yml"];
    let has_ext = known_exts.iter().any(|ext| s.ends_with(ext));
    if has_slash || has_ext { Some(s) } else { None }
}

// ── --apply: write parsed files back as a commit ─────────────────────

/// Parse `response` and, if it yields files, write them back to the
/// project as a new commit on `branch` (off `base_commit`). Returns a
/// human-readable summary — warnings, the files written, and the new
/// commit hash — streamed in-band as the job's terminal chunk so the
/// operator never loses a warning. `Err` is reserved for hard host
/// failures (a dev-project round-trip refused or didn't decode).
pub(crate) async fn run_apply(
    ctx: &mut AiCtx,
    project_id: u32,
    branch: &str,
    base_commit: &[u8],
    response: &str,
) -> Result<String, String> {
    let parsed = parse_response(response);
    let mut summary = String::new();
    summary.push_str("\n\n--- apply ---\n");
    for w in &parsed.warnings {
        summary.push_str(&format!("warning: {w}\n"));
    }
    let files = parsed.files;
    if files.is_empty() {
        summary.push_str(
            "no files detected in the response — the reply had no recognised \
             `path:` + fenced-block pair; nothing was written.\n",
        );
        return Ok(summary);
    }
    summary.push_str(&format!(
        "writing {} file(s) to branch '{branch}':\n",
        files.len()
    ));
    for f in &files {
        summary.push_str(&format!("  - {} ({} bytes)\n", f.path, f.content.len()));
    }

    let change_id = open_change(ctx, project_id, base_commit).await?;
    for f in &files {
        let blob_hash = put_blob(ctx, project_id, f.content.as_bytes()).await?;
        put_file_working(ctx, project_id, &change_id, &f.path, &blob_hash).await?;
    }
    let ts_ms = now_ms();
    let commit_hash = commit_change(
        ctx,
        project_id,
        &change_id,
        branch,
        dev_project::INTENT_EDIT,
        ts_ms,
    )
    .await?;
    summary.push_str(&format!(
        "committed {} on '{branch}'\n",
        hex::encode(&commit_hash)
    ));
    if branch != "main" {
        summary.push_str(&format!(
            "review, then promote with `vosx dev merge --from {branch}`\n"
        ));
    }
    Ok(summary)
}

fn now_ms() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_millis() as u64)
        .unwrap_or(0)
}

/// Decode a `HashResult`-shaped reply, checking status + hash length.
fn decode_hash_result(bytes: &[u8], label: &str) -> Result<Vec<u8>, String> {
    if bytes.is_empty() {
        return Err(format!("{label} returned empty bytes"));
    }
    let result = <dev_project::HashResult as Decode>::try_decode(bytes)
        .ok_or_else(|| format!("{label} reply isn't a valid HashResult"))?;
    if result.status != dev_project::STATUS_OK {
        return Err(format!("{label} rejected: status={}", result.status));
    }
    if result.hash.len() != 32 {
        return Err(format!(
            "{label} returned hash of wrong length: {}",
            result.hash.len()
        ));
    }
    Ok(result.hash)
}

async fn open_change(ctx: &mut AiCtx, project_id: u32, base: &[u8]) -> Result<Vec<u8>, String> {
    let reply = invoke(
        ctx,
        project_id,
        &Msg::new("open_change").with("base", base.to_vec()),
    )
    .await?;
    let bytes = value_bytes(reply, "open_change")?;
    decode_hash_result(&bytes, "open_change")
}

async fn put_blob(ctx: &mut AiCtx, project_id: u32, bytes: &[u8]) -> Result<Vec<u8>, String> {
    let reply = invoke(
        ctx,
        project_id,
        &Msg::new("put_blob").with("bytes", bytes.to_vec()),
    )
    .await?;
    let hash = value_bytes(reply, "put_blob")?;
    if hash.len() != 32 {
        return Err(format!("put_blob returned hash of wrong length: {}", hash.len()));
    }
    Ok(hash)
}

async fn put_file_working(
    ctx: &mut AiCtx,
    project_id: u32,
    change_id: &[u8],
    path: &str,
    blob_hash: &[u8],
) -> Result<(), String> {
    let reply = invoke(
        ctx,
        project_id,
        &Msg::new("put_file_working")
            .with("change_id", change_id.to_vec())
            .with("path", path.to_string())
            .with("blob_hash", blob_hash.to_vec()),
    )
    .await?;
    // put_file_working returns a u8 status; codegen may surface a
    // primitive as U8/U32/U64 or a 1-byte Bytes.
    let status = match reply {
        Value::U8(s) => s,
        Value::U32(s) => s as u8,
        Value::U64(s) => s as u8,
        Value::Bytes(b) if !b.is_empty() => b[0],
        other => return Err(format!("put_file_working returned {other:?}, expected u8 status")),
    };
    if status != dev_project::STATUS_OK {
        return Err(format!("put_file_working rejected (path={path}): status={status}"));
    }
    Ok(())
}

async fn commit_change(
    ctx: &mut AiCtx,
    project_id: u32,
    change_id: &[u8],
    branch: &str,
    intent_tag: u8,
    ts_ms: u64,
) -> Result<Vec<u8>, String> {
    let reply = invoke(
        ctx,
        project_id,
        &Msg::new("commit_change")
            .with("change_id", change_id.to_vec())
            .with("branch", branch.to_string())
            .with("intent_tag", intent_tag)
            .with("intent_data", Vec::<u8>::new())
            .with("author", Vec::<u8>::new())
            .with("ts_ms", ts_ms),
    )
    .await?;
    let bytes = value_bytes(reply, "commit_change")?;
    decode_hash_result(&bytes, "commit_change")
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn extract_path_handles_plain_colon() {
        assert_eq!(extract_path("src/lib.rs:"), Some("src/lib.rs".to_string()));
        assert_eq!(
            extract_path("  src/lib.rs:  "),
            Some("src/lib.rs".to_string())
        );
    }

    #[test]
    fn extract_path_handles_markdown_header() {
        assert_eq!(
            extract_path("## src/lib.rs"),
            Some("src/lib.rs".to_string())
        );
        assert_eq!(
            extract_path("### src/lib.rs:"),
            Some("src/lib.rs".to_string())
        );
    }

    #[test]
    fn extract_path_handles_bold_and_bullets() {
        assert_eq!(
            extract_path("**src/lib.rs:**"),
            Some("src/lib.rs".to_string())
        );
        assert_eq!(extract_path("- src/lib.rs"), Some("src/lib.rs".to_string()));
        assert_eq!(
            extract_path("* src/lib.rs:"),
            Some("src/lib.rs".to_string())
        );
    }

    #[test]
    fn extract_path_accepts_top_level_files_with_known_ext() {
        assert_eq!(extract_path("Cargo.toml"), Some("Cargo.toml".to_string()));
        assert_eq!(extract_path("README.md:"), Some("README.md".to_string()));
    }

    #[test]
    fn extract_path_rejects_sentences() {
        assert_eq!(extract_path("Here is the file:"), None);
        assert_eq!(extract_path("Below is the code"), None);
        assert_eq!(extract_path(""), None);
        assert_eq!(extract_path("```rust"), None); // fence, not a path
    }

    #[test]
    fn extract_path_rejects_dangerous_paths() {
        assert_eq!(extract_path("/etc/passwd"), None);
        assert_eq!(extract_path("../escape.rs"), None);
        assert_eq!(extract_path("src/../etc/foo.rs"), None);
        assert_eq!(extract_path("src\\windows.rs"), None);
    }

    #[test]
    fn parse_response_extracts_single_file() {
        let text = "\
src/lib.rs:
```rust
pub fn hello() -> &'static str { \"hi\" }
```
";
        let r = parse_response(text);
        assert_eq!(r.files.len(), 1);
        assert_eq!(r.files[0].path, "src/lib.rs");
        assert!(r.files[0].content.contains("pub fn hello"));
        assert!(r.warnings.is_empty());
    }

    #[test]
    fn parse_response_extracts_multiple_files() {
        let text = "\
## src/lib.rs
```rust
fn one() {}
```

## Cargo.toml
```toml
[package]
name = \"foo\"
```
";
        let r = parse_response(text);
        assert_eq!(r.files.len(), 2);
        assert_eq!(r.files[0].path, "src/lib.rs");
        assert_eq!(r.files[1].path, "Cargo.toml");
        assert!(r.files[0].content.contains("fn one"));
        assert!(r.files[1].content.contains("[package]"));
        assert!(r.warnings.is_empty());
    }

    #[test]
    fn parse_response_drops_unattributed_blocks() {
        let text = "\
Here is some example code:
```rust
fn example() {}
```

src/lib.rs:
```rust
fn real() {}
```
";
        let r = parse_response(text);
        assert_eq!(r.files.len(), 1);
        assert_eq!(r.files[0].path, "src/lib.rs");
        assert!(r.files[0].content.contains("fn real"));
    }

    #[test]
    fn parse_response_handles_empty_input() {
        assert!(parse_response("").files.is_empty());
        assert!(
            parse_response("just some prose with no code")
                .files
                .is_empty()
        );
    }

    #[test]
    fn parse_response_dedupes_duplicate_paths_last_wins() {
        let text = "\
src/lib.rs:
```rust
fn echo() {}
```

src/lib.rs:
```rust
fn real() {}
```
";
        let r = parse_response(text);
        assert_eq!(r.files.len(), 1, "duplicate paths should collapse to one");
        assert_eq!(r.files[0].path, "src/lib.rs");
        assert!(r.files[0].content.contains("fn real"));
        assert!(!r.files[0].content.contains("fn echo"));
        assert_eq!(r.warnings.len(), 1);
        assert!(
            r.warnings[0].contains("duplicate path"),
            "warning should call out the duplicate: {:?}",
            r.warnings[0],
        );
    }

    #[test]
    fn parse_response_drops_unclosed_fence_with_warning() {
        let text = "\
src/lib.rs:
```rust
pub fn hello() -> &'static str {
    \"hello, w";
        let r = parse_response(text);
        assert_eq!(
            r.files.len(),
            0,
            "unclosed block should be dropped, not committed"
        );
        assert_eq!(r.warnings.len(), 1);
        assert!(
            r.warnings[0].contains("unclosed"),
            "warning should mention 'unclosed': {:?}",
            r.warnings[0],
        );
    }

    #[test]
    fn parse_response_handles_fence_without_language_tag() {
        let text = "\
src/notes.md:
```
just a note
```
";
        let r = parse_response(text);
        assert_eq!(r.files.len(), 1);
        assert_eq!(r.files[0].path, "src/notes.md");
        assert!(r.files[0].content.contains("just a note"));
    }

    #[test]
    fn parse_response_preserves_content_verbatim() {
        let text = "\
src/lib.rs:
```rust
use vos::prelude::*;

#[actor]
struct A;
```
";
        let r = parse_response(text);
        let expected = "use vos::prelude::*;\n\n#[actor]\nstruct A;\n";
        assert_eq!(r.files[0].content, expected);
    }
}
