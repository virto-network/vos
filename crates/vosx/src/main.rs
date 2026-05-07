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
mod paths;
mod spaces_index;
mod util;

use util::init_tracing;

#[derive(Parser)]
#[command(name = "vosx", about = "JAM-aligned PVM executor + space orchestrator")]
struct Cli {
    #[command(subcommand)]
    command: Option<Command>,

    /// Raw ELF/PVM blob to run as a one-shot. Equivalent to
    /// `vosx run <file>`. Anything space-related needs an
    /// explicit `vosx space *` subcommand.
    file: Option<PathBuf>,
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

fn main() {
    init_tracing();
    let cli = Cli::parse();

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
