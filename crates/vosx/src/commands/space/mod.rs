//! `vosx space *` — per-space lifecycle commands.
//!
//! Phase 1a covers the offline scaffolding — `new`, `list`,
//! `info`. Running an existing space (`up`), exporting its
//! state to TOML (`export`), and joining a remote space
//! (`join`) require running-registry lifecycle work tracked
//! as Phase 1b/1c.

use clap::Subcommand;
use std::path::PathBuf;

pub mod info;
pub mod list;
pub mod new;

#[derive(Subcommand, Debug)]
pub enum SpaceCommand {
    /// Create a new space — scaffold identity, initial data
    /// dir, and add to the local spaces index.
    New {
        /// Short name for the space. Used in listings and as the
        /// default lookup key.
        #[arg(long)]
        name: String,
        /// Source for the space-registry actor blob: file path,
        /// 64-hex content hash (cache lookup), `ipfs:<cid>`, or
        /// `https://…`. Required until a bundled fallback ships.
        #[arg(long, value_name = "SOURCE")]
        registry: String,
        /// libp2p multiaddr to listen on. Repeatable.
        #[arg(long, value_name = "MULTIADDR")]
        listen: Vec<String>,
        /// Override the per-space data directory (default:
        /// `~/.local/share/vosx/<space_id>`).
        #[arg(long, value_name = "DIR")]
        data_dir: Option<PathBuf>,
    },
    /// List spaces in the local index.
    List,
    /// Alias of `list`.
    Ls,
    /// Show details for a single space (by id-prefix or name).
    Info {
        /// Space id (full hex) or name. If omitted, shows the
        /// space whose `data_dir` matches the current directory
        /// when present, else errors.
        space: Option<String>,
    },
}

pub fn run(cmd: SpaceCommand) -> anyhow::Result<()> {
    match cmd {
        SpaceCommand::New {
            name,
            registry,
            listen,
            data_dir,
        } => new::run(new::Args {
            name,
            registry,
            listen,
            data_dir,
        }),
        SpaceCommand::List | SpaceCommand::Ls => list::run(),
        SpaceCommand::Info { space } => info::run(space.as_deref()),
    }
}
