//! `vosx ai generate` — single-prompt completion, streaming by
//! default.
//!
//! Two paths through the dispatcher:
//!
//! - **Streaming (default)**: send `begin_generate` → loop
//!   `poll_generation` at ~100ms ticks, printing each non-empty
//!   `text` chunk as it arrives. Exits when `done = true`.
//! - **Blocking (`--no-stream` or `--format json`)**: send the
//!   original `generate` invoke and print the full completion.
//!   Used by JSON consumers that want a single well-formed reply.
//!
//! Both paths decode the AI extension's wire shape into the same
//! `Args { text, done, error }` triple — the streaming path
//! receives it incrementally, the blocking path in one go.
//!
//! Error surface:
//!
//! - Outer transport errors (daemon unreachable, timeout) bubble
//!   up via the DaemonClient `?`.
//! - In-flight inference errors land in the structured `error`
//!   field once the worker terminates. Either path surfaces them
//!   as a non-zero CLI exit so scripts catch them.

use std::thread;
use std::time::Duration;

use serde::Serialize;
use vos::abi::service::ServiceId;
use vos::value::{Args as WireArgs, Msg, Value};

use crate::commands::ai::actor::decode_request_id;
use crate::commands::space::client::DaemonClient;
use crate::output;

/// Tick interval for the poll loop. Small enough to feel
/// streaming on a typical 2-20 tok/s CPU run; large enough that
/// the libp2p round-trip doesn't dominate.
const POLL_INTERVAL: Duration = Duration::from_millis(100);

/// Bound on consecutive empty polls before we bail out. Protects
/// against a wedged worker that never reports `done`; at 100ms
/// ticks this is 3 minutes of silence — generous enough to cover
/// debug-build prefill on the larger actor-context prompts
/// (`vosx ai actor`) without false-firing.
const MAX_EMPTY_TICKS: u32 = 1800;

#[derive(Serialize)]
struct CompletionView<'a> {
    prompt: &'a str,
    completion: &'a str,
    max_tokens: u32,
}

/// CLI-level arguments for `vosx ai generate`. Named with the
/// `Generate` prefix so it doesn't collide with `vos::value::Args`
/// (the wire-arguments type the streaming code decodes).
pub struct Args {
    pub space: String,
    pub prompt: String,
    pub max_tokens: u32,
    pub extension: String,
    pub no_stream: bool,
}

pub fn run(args: Args) -> anyhow::Result<()> {
    DaemonClient::with_connect(&args.space, |client| {
        let extension_id = client.resolve_target(&args.extension).map_err(|_| {
            anyhow::anyhow!(
                "no '{}' extension loaded in this space — \
                 add `[[extension]] name = \"{}\"` to the \
                 space's manifest and restart `vosx space up`",
                args.extension,
                args.extension,
            )
        })?;

        // JSON output needs the whole completion in one chunk so
        // the consumer gets a single well-formed reply. Streaming
        // would print incremental text chunks that aren't JSON.
        let use_stream = !args.no_stream && !output::is_json();

        if use_stream {
            run_streaming(client, extension_id, &args)
        } else {
            run_blocking(client, extension_id, &args)
        }
    })
}

/// Streaming path: begin_generate → poll until done.
fn run_streaming(
    client: &DaemonClient,
    extension_id: ServiceId,
    args: &Args,
) -> anyhow::Result<()> {
    let begin_reply = client.invoke_dyn(
        extension_id,
        &Msg::new("begin_generate")
            .with("prompt", args.prompt.clone())
            .with("max_tokens", args.max_tokens),
    )?;
    let request_id = decode_request_id(begin_reply)?;

    let mut accumulated = String::new();
    let mut empty_ticks: u32 = 0;
    loop {
        let poll_reply = client.invoke_dyn(
            extension_id,
            &Msg::new("poll_generation").with("request_id", request_id),
        )?;
        let chunk_args = decode_chunk_args(poll_reply)?;
        let text = chunk_args.get_str("text").unwrap_or_default();
        let done = chunk_args.get_bool("done").unwrap_or(false);
        let error = chunk_args.get_str("error").unwrap_or_default();

        if !text.is_empty() {
            // Print + flush immediately so the user sees tokens
            // as they arrive, not buffered until newline.
            use std::io::Write as _;
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

/// Blocking path: single `generate` invoke. The extension's
/// `generate` handler returns the same `Args { text, done,
/// error }` shape `poll_generation` uses, so error surfaces are
/// structured instead of relying on a stringly-typed prefix.
fn run_blocking(client: &DaemonClient, extension_id: ServiceId, args: &Args) -> anyhow::Result<()> {
    let reply = client.invoke_dyn(
        extension_id,
        &Msg::new("generate")
            .with("prompt", args.prompt.clone())
            .with("max_tokens", args.max_tokens),
    )?;

    let chunk_args = decode_chunk_args(reply)?;
    let completion = chunk_args.get_str("text").unwrap_or_default();
    let error = chunk_args.get_str("error").unwrap_or_default();

    if !error.is_empty() {
        anyhow::bail!("ai generate failed: {error}");
    }

    if output::is_json() {
        output::print_json(&CompletionView {
            prompt: &args.prompt,
            completion: &completion,
            max_tokens: args.max_tokens,
        });
    } else {
        print!("{completion}");
        if !completion.ends_with('\n') {
            println!();
        }
    }
    Ok(())
}

/// Decode the `Value::Bytes(rkyv-encoded Args)` payload that both
/// `generate` (post-Phase-6.2 cleanup) and `poll_generation`
/// return. Matches the shape `GenerationChunk::to_args` produces
/// in the ai extension.
fn decode_chunk_args(value: Value) -> anyhow::Result<WireArgs> {
    let bytes = match value {
        Value::Bytes(b) => b,
        Value::Unit => anyhow::bail!("ai handler returned Unit — request id unknown?"),
        other => anyhow::bail!("ai handler returned {other:?}, expected Bytes"),
    };
    if bytes.is_empty() {
        anyhow::bail!("ai handler returned empty bytes");
    }
    <WireArgs as vos::Decode>::try_decode(&bytes)
        .ok_or_else(|| anyhow::anyhow!("ai handler reply isn't a valid Args"))
}
