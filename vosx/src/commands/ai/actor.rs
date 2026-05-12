//! `vosx ai actor` — ask the AI extension to write or modify a
//! VOS actor's source, with the project's current files injected
//! into the prompt as context.
//!
//! Bridges the dev-project actor's commit DAG and the ai
//! extension's generate handler so the operator types one
//! sentence ("add a reset handler") and gets a completion that
//! already knows what files exist, what they currently say, and
//! what the VOS actor conventions are.
//!
//! Flow:
//!
//! 1. Resolve the dev-project actor instance (`--project NAME`)
//!    and the AI extension (`--extension`, default `ai`).
//! 2. Fetch the head of the project's `main` branch and walk the
//!    commit's `files` list. For each path that looks like
//!    source (.rs, .toml, .md) under a small per-file cap,
//!    decode the blob bytes as UTF-8.
//! 3. Build a prompt: a fixed preamble explaining VOS actor
//!    conventions + one canonical example + the current source
//!    files + the user's task description.
//! 4. Drive the ai extension's streaming dispatch
//!    (`begin_generate` + `poll_generation`) and flush each
//!    chunk to stdout as it arrives.
//!
//! Read-only by default — the model's reply lands on stdout for
//! the operator to inspect. Pass `--apply` to write the parsed
//! files back as a working change on the project's `main`
//! branch (one new commit per `--apply` run).

use std::io::Write as _;
use std::thread;
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use vos::Decode;
use vos::Encode;
use vos::abi::service::ServiceId;
use vos::value::{Args as WireArgs, Msg, Value};

use crate::commands::space::client::DaemonClient;

/// Tick interval for `poll_generation`. Same value as the plain
/// `vosx ai generate` streaming path.
const POLL_INTERVAL: Duration = Duration::from_millis(100);
const MAX_EMPTY_TICKS: u32 = 600;

/// Per-file content cap when stuffing the prompt. A few-KB
/// budget per file keeps the context window from blowing out
/// even on multi-file projects.  v1 truncates with an explicit
/// marker so the model knows the file was clipped.
const PER_FILE_BYTE_CAP: usize = 4096;

/// Whole-tree byte cap for the prompt's source-injection
/// section. Hit it and we just stop including files; the
/// preamble + user prompt still go through.
const TOTAL_SOURCE_CAP: usize = 32_768;

pub struct Args {
    pub space: String,
    pub project: String,
    pub prompt: String,
    pub max_tokens: u32,
    pub extension: String,
    pub commit: Option<String>,
    pub apply: bool,
}

pub fn run(args: Args) -> anyhow::Result<()> {
    DaemonClient::with_connect(&args.space, |client| {
        let project_id = client.resolve_target(&args.project)?;
        let extension_id = client.resolve_target(&args.extension).map_err(|_| {
            anyhow::anyhow!(
                "no '{}' extension loaded in this space — \
                 add `[[extension]] name = \"{}\"` to the \
                 space's manifest and restart `vosx space up`",
                args.extension,
                args.extension,
            )
        })?;

        // ── Resolve the source commit. Default: main branch head.
        let commit_bytes = match args.commit.as_deref() {
            Some(hex) => parse_hex32(hex)?,
            None => fetch_head_main(client, project_id, &args.project)?,
        };

        // ── Fetch the commit's file tree.
        let files = fetch_project_files(client, project_id, &commit_bytes)?;

        // ── Build the prompt.
        let full_prompt = build_prompt(&files, &args.prompt);

        // ── Stream generation, accumulating into a string so
        //    `--apply` has the full response to parse afterwards.
        let response = stream_generate(client, extension_id, &full_prompt, args.max_tokens)?;

        if args.apply {
            apply_response(client, project_id, &args.project, &commit_bytes, &response)?;
        }

        Ok(())
    })
}

fn parse_hex32(hex_str: &str) -> anyhow::Result<Vec<u8>> {
    let bytes = hex::decode(hex_str).map_err(|e| anyhow::anyhow!("--commit hex parse: {e}"))?;
    if bytes.len() != 32 {
        anyhow::bail!(
            "--commit must be 64 hex chars (32 bytes), got {} bytes",
            bytes.len()
        );
    }
    Ok(bytes)
}

fn fetch_head_main(
    client: &DaemonClient,
    project_id: ServiceId,
    project_name: &str,
) -> anyhow::Result<Vec<u8>> {
    let head = client.invoke_dyn(project_id, &Msg::new("head").with("branch", "main"))?;
    let bytes = match head {
        Value::Bytes(b) => b,
        other => anyhow::bail!("project '{project_name}' head returned non-bytes: {other:?}"),
    };
    if bytes.is_empty() {
        anyhow::bail!(
            "project '{project_name}' has no 'main' branch yet — commit source \
             first or pass --commit"
        );
    }
    Ok(bytes)
}

/// One source file lifted out of the project's commit tree.
struct ProjectFile {
    path: String,
    content: String,
    /// `true` if we truncated the bytes at `PER_FILE_BYTE_CAP`.
    truncated: bool,
}

fn fetch_project_files(
    client: &DaemonClient,
    project_id: ServiceId,
    commit_hash: &[u8],
) -> anyhow::Result<Vec<ProjectFile>> {
    let commit_reply = client.invoke_dyn(
        project_id,
        &Msg::new("get_commit").with("hash", commit_hash.to_vec()),
    )?;
    let commit_bytes = match commit_reply {
        Value::Bytes(b) => b,
        Value::Unit => anyhow::bail!("get_commit returned Unit — commit not stored?"),
        other => anyhow::bail!("get_commit returned {other:?}, expected Bytes"),
    };
    if commit_bytes.is_empty() {
        anyhow::bail!("get_commit returned empty bytes — commit not stored");
    }
    let commit = <dev_project::CommitNode as Decode>::try_decode(&commit_bytes)
        .ok_or_else(|| anyhow::anyhow!("get_commit reply isn't a valid CommitNode"))?;

    let mut total = 0usize;
    let mut out: Vec<ProjectFile> = Vec::new();
    for file in &commit.files {
        // Filter to source-ish paths so we don't dump binary
        // blobs (compiled artifacts, archived metadata) into the
        // prompt. `.vos-project.rkyv` is the metadata blob;
        // skip it — its content isn't human-meaningful.
        if !is_interesting_path(&file.path) {
            continue;
        }
        let blob_reply = client.invoke_dyn(
            project_id,
            &Msg::new("get_blob").with("hash", file.blob.to_vec()),
        )?;
        let blob_bytes = match blob_reply {
            Value::Bytes(b) => b,
            Value::Unit => continue,
            _ => continue,
        };
        if blob_bytes.is_empty() {
            continue;
        }
        let blob = match <dev_project::BlobObject as Decode>::try_decode(&blob_bytes) {
            Some(b) => b,
            None => continue,
        };
        // RustAst blobs need rendering back to text. Skip them
        // in v1 — the dev-ast crate lives behind the dev
        // extension's build, and pulling it into vosx just for
        // this feature is more dep weight than the feature
        // warrants. The Raw kind is what `vosx dev` writes today.
        if !matches!(blob.kind, dev_project::BlobKind::Raw) {
            continue;
        }
        let mut text = match String::from_utf8(blob.bytes) {
            Ok(s) => s,
            Err(_) => continue,
        };
        let truncated = text.len() > PER_FILE_BYTE_CAP;
        if truncated {
            // Truncate on a char boundary to keep the resulting
            // String valid utf-8; the model handles the marker.
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
    // Source-ish + manifest-ish paths the model can usefully
    // read. .vos-project.rkyv is binary metadata.
    p.ends_with(".rs")
        || p.ends_with(".toml")
        || p.ends_with(".md")
        || p.ends_with(".txt")
        || p.ends_with(".json")
}

/// Compose the full prompt the AI extension sees. Layout:
///
///   <preamble: VOS actor conventions + canonical example>
///   <current source files, fenced by path>
///   <user task description>
///   <response instructions>
fn build_prompt(files: &[ProjectFile], user_prompt: &str) -> String {
    let mut s = String::with_capacity(8192);
    s.push_str(PROMPT_PREAMBLE);
    s.push_str("\n\n# Current project source\n\n");
    if files.is_empty() {
        s.push_str("(The project has no source files yet — start fresh.)\n");
    } else {
        for f in files {
            // Pick a fence language hint from the extension so
            // the model knows it's looking at Rust/TOML/etc.
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

/// Drive the streaming dispatch: send `begin_generate`, then poll
/// until done, printing each text chunk as it arrives. Returns
/// the accumulated text so the `--apply` path can parse it.
fn stream_generate(
    client: &DaemonClient,
    extension_id: ServiceId,
    prompt: &str,
    max_tokens: u32,
) -> anyhow::Result<String> {
    let begin_reply = client.invoke_dyn(
        extension_id,
        &Msg::new("begin_generate")
            .with("prompt", prompt.to_string())
            .with("max_tokens", max_tokens),
    )?;
    let request_id = match begin_reply {
        Value::U64(id) => id,
        Value::U32(id) => id as u64,
        other => anyhow::bail!("ai begin_generate returned unexpected value: {other:?}"),
    };

    let mut empty_ticks: u32 = 0;
    let mut accumulated = String::new();
    loop {
        let poll_reply = client.invoke_dyn(
            extension_id,
            &Msg::new("poll_generation").with("request_id", request_id),
        )?;
        let chunk_bytes = match poll_reply {
            Value::Bytes(b) => b,
            other => anyhow::bail!("poll_generation returned {other:?}, expected Bytes"),
        };
        let chunk_args = <WireArgs as Decode>::try_decode(&chunk_bytes)
            .ok_or_else(|| anyhow::anyhow!("poll_generation reply isn't a valid Args"))?;
        let text = chunk_args.get_str("text").unwrap_or_default();
        let done = chunk_args.get_bool("done").unwrap_or(false);
        let error = chunk_args.get_str("error").unwrap_or_default();

        if !text.is_empty() {
            print!("{text}");
            let _ = std::io::stdout().flush();
            accumulated.push_str(&text);
            empty_ticks = 0;
        } else if !done {
            empty_ticks += 1;
            if empty_ticks > MAX_EMPTY_TICKS {
                anyhow::bail!(
                    "ai poll_generation: no output for {}s — worker may be wedged",
                    MAX_EMPTY_TICKS / 10,
                );
            }
        }
        if done {
            if !accumulated.ends_with('\n') {
                println!();
            }
            if !error.is_empty() {
                anyhow::bail!("ai generate failed mid-stream: {error}");
            }
            return Ok(accumulated);
        }
        thread::sleep(POLL_INTERVAL);
    }
}

// ── --apply: parse fenced code blocks + write back as a commit ──────

/// One file extracted from the model's response.
#[derive(Debug, PartialEq, Eq)]
pub(crate) struct ParsedFile {
    pub path: String,
    pub content: String,
}

/// Parse the AI extension's response into a list of (path,
/// content) pairs. Tolerates several common Markdown patterns
/// the model emits even when the prompt asks for a specific
/// shape:
///
///   src/lib.rs:           ← plain "path:" line
///   ## src/lib.rs         ← Markdown header
///   ## src/lib.rs:        ← header + colon
///   **src/lib.rs:**       ← bold path
///
/// followed by a ``` / ```rust / ```toml fenced block. The path
/// hint must appear within the few lines immediately preceding
/// the fence opening.
///
/// Paths are validated: no leading `/`, no `..` segments,
/// no embedded null/backslash. Files that don't match a
/// detected path are dropped silently — the response often
/// contains explanatory code snippets the model wants to show
/// but not save (e.g. the canonical example replayed back).
pub(crate) fn parse_response(text: &str) -> Vec<ParsedFile> {
    let mut out: Vec<ParsedFile> = Vec::new();
    let lines: Vec<&str> = text.lines().collect();
    let mut i = 0;
    // Recent non-empty lines we'll scan as path candidates when
    // we hit a fence opener. 3 lines back is plenty; the typical
    // shape is "path:\n```lang".
    let lookback = 3usize;
    while i < lines.len() {
        if is_fence(lines[i]) {
            // Find a path among the preceding lines.
            let mut path: Option<String> = None;
            let start = i.saturating_sub(lookback);
            for j in (start..i).rev() {
                if let Some(p) = extract_path(lines[j]) {
                    path = Some(p);
                    break;
                }
            }
            // Walk forward to the closing fence.
            let mut j = i + 1;
            let mut content = String::new();
            while j < lines.len() && !is_fence(lines[j]) {
                content.push_str(lines[j]);
                content.push('\n');
                j += 1;
            }
            // Save if we found a usable path. Drop the block
            // otherwise — the model likes to echo example code
            // back without a path; only files with explicit
            // hints get written.
            if let Some(p) = path {
                out.push(ParsedFile { path: p, content });
            }
            i = j.saturating_add(1);
        } else {
            i += 1;
        }
    }
    out
}

/// Does this line look like ``` (with or without a language
/// hint)? Tolerates leading whitespace.
fn is_fence(line: &str) -> bool {
    let s = line.trim_start();
    s.starts_with("```")
}

/// Pull a path-shaped string out of one line. Returns `None`
/// when the line doesn't look like a path hint. Handles common
/// Markdown decorations.
fn extract_path(line: &str) -> Option<String> {
    let mut s = line.trim().to_string();
    if s.is_empty() {
        return None;
    }
    // Strip leading Markdown header markers (`#`, `##`, ...).
    while s.starts_with('#') {
        s.remove(0);
    }
    s = s.trim().to_string();
    // Strip surrounding bold/italic/backtick markers.
    s = s
        .trim_matches('*')
        .trim_matches('`')
        .trim_matches('_')
        .to_string();
    // Strip a trailing colon (the prompt-suggested form is
    // "path:") and any whitespace.
    s = s.trim_end_matches(':').trim().to_string();
    // Strip surrounding bullets / list markers.
    s = s
        .trim_start_matches('-')
        .trim_start_matches('*')
        .trim()
        .to_string();
    if s.is_empty() {
        return None;
    }
    // Reject anything that doesn't look like a file path. The
    // model occasionally emits free-form sentences before a
    // fence ("Here is the file:"); none of those should match.
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
    // Heuristic: a real path either contains a `/` or has a
    // file-like extension.
    let has_slash = s.contains('/');
    let known_exts = [".rs", ".toml", ".md", ".txt", ".json", ".yaml", ".yml"];
    let has_ext = known_exts.iter().any(|ext| s.ends_with(ext));
    if has_slash || has_ext { Some(s) } else { None }
}

/// Apply the parsed files to the project: open a working change
/// off `base_commit`, put_blob + put_file_working for each, then
/// commit_change on `main`. Prints a summary including the new
/// commit hash so the operator can chain into `vosx dev compile`.
fn apply_response(
    client: &DaemonClient,
    project_id: ServiceId,
    project_name: &str,
    base_commit: &[u8],
    response: &str,
) -> anyhow::Result<()> {
    let files = parse_response(response);
    if files.is_empty() {
        eprintln!(
            "\n--apply: no files detected in the response. The model's reply \
             didn't include a recognised `path:` + fenced-block pair; nothing \
             was written.",
        );
        return Ok(());
    }
    eprintln!(
        "\n--apply: writing {} file(s) to project '{project_name}':",
        files.len()
    );
    for f in &files {
        eprintln!("  - {} ({} bytes)", f.path, f.content.len());
    }

    // Open a working change off the same commit we showed the
    // model. `base_commit` empty means "fresh project, no prior
    // commit" — open_change accepts that.
    let change_id = open_change(client, project_id, base_commit)?;

    // For each file: put_blob to land the bytes, then
    // put_file_working to stage the overlay under its path.
    for f in &files {
        let blob_hash = put_blob(client, project_id, f.content.as_bytes())?;
        put_file_working(client, project_id, &change_id, &f.path, &blob_hash)?;
    }

    // Snapshot the change as a commit on `main`. Caller can
    // walk the resulting commit via `vosx dev log --branch main
    // <project>` once that command surfaces the commit graph.
    let ts_ms = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_millis() as u64)
        .unwrap_or(0);
    let commit_hash = commit_change(
        client,
        project_id,
        &change_id,
        "main",
        dev_project::INTENT_EDIT,
        ts_ms,
    )?;
    eprintln!(
        "--apply: committed {} on main\n         next: `vosx dev compile --space <space> {project_name}`",
        hex::encode(&commit_hash),
    );
    Ok(())
}

fn open_change(
    client: &DaemonClient,
    project_id: ServiceId,
    base: &[u8],
) -> anyhow::Result<Vec<u8>> {
    let reply = client.invoke_dyn(
        project_id,
        &Msg::new("open_change").with("base", base.to_vec()),
    )?;
    let bytes = expect_bytes(reply, "open_change")?;
    let result = <dev_project::HashResult as Decode>::try_decode(&bytes)
        .ok_or_else(|| anyhow::anyhow!("open_change reply isn't a valid HashResult"))?;
    if result.status != dev_project::STATUS_OK {
        anyhow::bail!("open_change rejected: status={}", result.status);
    }
    if result.hash.len() != 32 {
        anyhow::bail!(
            "open_change returned hash of wrong length: {}",
            result.hash.len()
        );
    }
    Ok(result.hash)
}

fn put_blob(client: &DaemonClient, project_id: ServiceId, bytes: &[u8]) -> anyhow::Result<Vec<u8>> {
    let reply = client.invoke_dyn(
        project_id,
        &Msg::new("put_blob").with("bytes", bytes.to_vec()),
    )?;
    let hash_bytes = expect_bytes(reply, "put_blob")?;
    if hash_bytes.len() != 32 {
        anyhow::bail!(
            "put_blob returned hash of wrong length: {}",
            hash_bytes.len()
        );
    }
    Ok(hash_bytes)
}

fn put_file_working(
    client: &DaemonClient,
    project_id: ServiceId,
    change_id: &[u8],
    path: &str,
    blob_hash: &[u8],
) -> anyhow::Result<()> {
    let reply = client.invoke_dyn(
        project_id,
        &Msg::new("put_file_working")
            .with("change_id", change_id.to_vec())
            .with("path", path.to_string())
            .with("blob_hash", blob_hash.to_vec()),
    )?;
    // Returns a u8 status. Status 0 = OK, anything else = error.
    let status = match reply {
        Value::U8(s) => s,
        Value::U32(s) => s as u8,
        Value::U64(s) => s as u8,
        Value::Bytes(b) if !b.is_empty() => b[0],
        other => anyhow::bail!("put_file_working returned {other:?}, expected u8 status"),
    };
    if status != dev_project::STATUS_OK {
        anyhow::bail!("put_file_working rejected (path={path}): status={status}");
    }
    Ok(())
}

fn commit_change(
    client: &DaemonClient,
    project_id: ServiceId,
    change_id: &[u8],
    branch: &str,
    intent_tag: u8,
    ts_ms: u64,
) -> anyhow::Result<Vec<u8>> {
    let intent_data: Vec<u8> = <() as Encode>::encode(&());
    // Use empty intent_data — INTENT_EDIT doesn't carry typed
    // payload today.
    let reply = client.invoke_dyn(
        project_id,
        &Msg::new("commit_change")
            .with("change_id", change_id.to_vec())
            .with("branch", branch.to_string())
            .with("intent_tag", intent_tag)
            .with("intent_data", intent_data)
            .with("author", Vec::<u8>::new())
            .with("ts_ms", ts_ms),
    )?;
    let bytes = expect_bytes(reply, "commit_change")?;
    let result = <dev_project::HashResult as Decode>::try_decode(&bytes)
        .ok_or_else(|| anyhow::anyhow!("commit_change reply isn't a valid HashResult"))?;
    if result.status != dev_project::STATUS_OK {
        anyhow::bail!("commit_change rejected: status={}", result.status);
    }
    if result.hash.len() != 32 {
        anyhow::bail!(
            "commit_change returned hash of wrong length: {}",
            result.hash.len()
        );
    }
    Ok(result.hash)
}

fn expect_bytes(value: Value, label: &str) -> anyhow::Result<Vec<u8>> {
    match value {
        Value::Bytes(b) if !b.is_empty() => Ok(b),
        Value::Bytes(_) => anyhow::bail!("{label} returned empty bytes"),
        Value::Unit => anyhow::bail!("{label} returned Unit"),
        other => anyhow::bail!("{label} returned {other:?}, expected Bytes"),
    }
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
        let files = parse_response(text);
        assert_eq!(files.len(), 1);
        assert_eq!(files[0].path, "src/lib.rs");
        assert!(files[0].content.contains("pub fn hello"));
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
        let files = parse_response(text);
        assert_eq!(files.len(), 2);
        assert_eq!(files[0].path, "src/lib.rs");
        assert_eq!(files[1].path, "Cargo.toml");
        assert!(files[0].content.contains("fn one"));
        assert!(files[1].content.contains("[package]"));
    }

    #[test]
    fn parse_response_drops_unattributed_blocks() {
        // A fenced block with no preceding path hint should be
        // ignored — the model often echoes example code back
        // without intending it as a file.
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
        let files = parse_response(text);
        assert_eq!(files.len(), 1);
        assert_eq!(files[0].path, "src/lib.rs");
        assert!(files[0].content.contains("fn real"));
    }

    #[test]
    fn parse_response_handles_empty_input() {
        assert!(parse_response("").is_empty());
        assert!(parse_response("just some prose with no code").is_empty());
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
        let files = parse_response(text);
        let expected = "use vos::prelude::*;\n\n#[actor]\nstruct A;\n";
        assert_eq!(files[0].content, expected);
    }
}
