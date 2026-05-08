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

use clap::{Parser, Subcommand};
use std::path::PathBuf;

mod blob_store;
mod bundled;
mod commands;
mod output;
mod paths;
mod spaces_index;

use output::Format;

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
                eprintln!("error: {e}");
                std::process::exit(1);
            }
        }
        None => match cli.file {
            Some(p) => commands::run::run(&p, &[], &[], 100_000_000),
            None => {
                eprintln!(
                    "vosx: no command. Try `vosx space new --name foo`, \
                     `vosx run path/to.elf`, or `vosx --help`."
                );
                std::process::exit(2);
            }
        },
    }
}
