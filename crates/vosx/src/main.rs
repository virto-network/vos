//! `vosx` — JAM-aligned PVM executor + space orchestrator.
//!
//! Top-level surface is intentionally tiny: every space-related
//! operation lives under `vosx space *`. The remaining
//! top-level commands are for things that don't fit the space
//! model — currently just `run` for raw ELF/PVM execution.
//!
//! The earlier manifest-driven commands (`new`, `up`, `join`,
//! `ls`, `ps`, `call`) folded into `vosx space *`; they had
//! different semantics (`up` started a node from a TOML
//! template; `space up` boots the registry-driven daemon)
//! and the registry-as-truth model supersedes the
//! manifest-as-truth model that originally drove them.
//! `space up --manifest <path>` (declarative reconciliation
//! of a manifest into a space's registry) is a future addition.

use clap::{CommandFactory, Parser, Subcommand};
use std::path::PathBuf;

mod blob_store;
mod bundled;
mod commands;
mod help_schema;
mod output;
mod paths;
mod spaces_index;

use output::Format;
use spaces_index::IndexError;

/// Exit codes. Anything not listed here is `0` (success).
///
/// - `1` — runtime error (I/O, network, daemon hung, registry
///   returned an error status). The default; agents can retry.
/// - `2` — usage error. Clap exits 2 on parse failures, and we
///   reuse the same code when the binary is invoked with no
///   command.
/// - `3` — not found. The space, agent, or program named in
///   the command doesn't exist locally / on the daemon. Agents
///   can treat this as "fix your input" rather than "retry".
const EXIT_RUNTIME_ERROR: i32 = 1;
const EXIT_USAGE_ERROR: i32 = 2;
const EXIT_NOT_FOUND: i32 = 3;

#[derive(Parser)]
#[command(name = "vosx", about = "JAM-aligned PVM executor + space orchestrator")]
struct Cli {
    #[command(subcommand)]
    command: Option<Command>,

    /// Raw ELF/PVM blob to run as a one-shot. Equivalent to
    /// `vosx run <file>`. Anything space-related needs an
    /// explicit `vosx space *` subcommand.
    file: Option<PathBuf>,

    /// Output format. `text` (default) is human-readable;
    /// `json` emits a single JSON value per command for scripts
    /// and LLM consumption. Inherited by all subcommands.
    #[arg(long, value_enum, default_value_t = Format::Text, global = true)]
    format: Format,
}

#[derive(Subcommand)]
enum Command {
    /// Run a single PVM/ELF program with no manifest (one-shot).
    /// No registry, no networking — just boot the kernel,
    /// deliver the supplied work items, halt.
    Run {
        program: PathBuf,
        /// Deliver file contents as a FETCH work item (repeatable).
        #[arg(long, value_name = "FILE")]
        payload: Vec<PathBuf>,
        /// Deliver hex-encoded bytes as a FETCH work item (repeatable).
        #[arg(long, value_name = "HEX")]
        hex: Vec<String>,
        /// Set gas limit.
        #[arg(long, default_value_t = 100_000_000)]
        gas: u64,
    },
    /// Per-space lifecycle and operations.
    Space {
        #[command(subcommand)]
        command: commands::space::SpaceCommand,
    },
    /// Emit the full CLI schema as pretty-printed JSON. Walks
    /// every subcommand + argument from clap's introspection,
    /// so the dump always matches what the binary accepts.
    /// Designed for LLM and tooling consumption — pipe into
    /// `jq '.subcommands[] | .name'` to enumerate verbs.
    HelpSchema,
}

/// Initialize the global tracing subscriber from `RUST_LOG`,
/// defaulting to `warn`. Idempotent — multiple calls are no-ops.
fn init_tracing() {
    let _ = tracing_subscriber::fmt()
        .with_env_filter(
            tracing_subscriber::EnvFilter::try_from_default_env()
                .unwrap_or_else(|_| tracing_subscriber::EnvFilter::new("warn")),
        )
        .with_writer(std::io::stderr)
        .try_init();
}

fn main() {
    init_tracing();
    let cli = Cli::parse();
    output::set(cli.format);

    match cli.command {
        Some(Command::Run { program, payload, hex, gas }) => {
            commands::run::run(&program, &payload, &hex, gas);
        }
        Some(Command::Space { command }) => {
            if let Err(e) = commands::space::run(command) {
                report_error(e);
            }
        }
        Some(Command::HelpSchema) => {
            let schema = help_schema::build(&Cli::command());
            match serde_json::to_string_pretty(&schema) {
                Ok(s) => println!("{s}"),
                Err(e) => {
                    eprintln!("error: {e}");
                    std::process::exit(EXIT_RUNTIME_ERROR);
                }
            }
        }
        None => match cli.file {
            Some(p) => commands::run::run(&p, &[], &[], 100_000_000),
            None => {
                eprintln!(
                    "vosx: no command. Try `vosx space new --name foo`, \
                     `vosx run path/to.elf`, or `vosx --help`."
                );
                std::process::exit(EXIT_USAGE_ERROR);
            }
        },
    }
}

/// Print an error and exit with the appropriate code. In JSON
/// mode the error envelope goes to stderr too — tools parsing
/// stdout get nothing on the failure path, and structured
/// failure detail is one line away on fd 2.
fn report_error(e: anyhow::Error) -> ! {
    let code = exit_code_for(&e);
    if output::is_json() {
        let envelope = serde_json::json!({
            "error": e.to_string(),
            "code": code,
        });
        eprintln!("{envelope}");
    } else {
        eprintln!("error: {e}");
    }
    std::process::exit(code)
}

/// Inspect the error chain to pick a code. `IndexError::NotFound`
/// is the only "not found" we can detect typed today (returned
/// by `spaces_index::find` when a space name/id doesn't match);
/// registry-status not-founds still surface as plain anyhow
/// strings and map to runtime-error.
fn exit_code_for(e: &anyhow::Error) -> i32 {
    if let Some(IndexError::NotFound(_)) = e.downcast_ref::<IndexError>() {
        return EXIT_NOT_FOUND;
    }
    EXIT_RUNTIME_ERROR
}
