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
//! v1 stays read-only: the model's reply lands on stdout, the
//! operator pastes the new source back into the project via
//! `vosx dev` or by editing files locally. An `--apply` flag is
//! a follow-up.

use std::io::Write as _;
use std::thread;
use std::time::Duration;

use vos::Decode;
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

        // ── Stream generation.
        stream_generate(client, extension_id, &full_prompt, args.max_tokens)?;

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
/// until done, printing each text chunk as it arrives.
fn stream_generate(
    client: &DaemonClient,
    extension_id: ServiceId,
    prompt: &str,
    max_tokens: u32,
) -> anyhow::Result<()> {
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
            return Ok(());
        }
        thread::sleep(POLL_INTERVAL);
    }
}
