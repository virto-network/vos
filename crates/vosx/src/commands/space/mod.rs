//! `vosx space *` — per-space lifecycle commands.
//!
//! Phase 1a covers the offline scaffolding — `new`, `list`,
//! `info`. Running an existing space (`up`), exporting its
//! state to TOML (`export`), and joining a remote space
//! (`join`) require running-registry lifecycle work tracked
//! as Phase 1b/1c.

use clap::Subcommand;
use std::path::PathBuf;

pub mod agents;
pub mod delete;
pub mod export;
pub mod info;
pub mod install;
pub mod join;
pub mod list;
pub mod members;
pub mod new;
pub mod programs;
pub mod publish;
pub mod transient;
pub mod uninstall;
pub mod unpublish;
pub mod up;
pub mod upgrade;

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
        /// `https://…`. Optional — falls back to the registry
        /// blob bundled into the vosx binary at build time.
        #[arg(long, value_name = "SOURCE")]
        registry: Option<String>,
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
    /// Join a remote space — register it locally so
    /// `space up` can dial the bootnode and start syncing.
    Join {
        /// `<space-id>@<bootnode-multiaddr>`. The space-id half
        /// is 64 hex chars; the bootnode half is whatever
        /// follows the `@`.
        bootstrap: String,
        /// Source for the space-registry actor blob. Optional —
        /// falls back to the bundled blob.
        #[arg(long, value_name = "SOURCE")]
        registry: Option<String>,
        /// Local short-name for the space. Defaults to a short
        /// hex prefix of the space_id.
        #[arg(long)]
        name: Option<String>,
        /// libp2p multiaddr to listen on (optional). Repeatable.
        #[arg(long, value_name = "MULTIADDR")]
        listen: Vec<String>,
        /// Override the per-space data directory.
        #[arg(long, value_name = "DIR")]
        data_dir: Option<std::path::PathBuf>,
    },
    /// Boot a saved space — load the registry from cache,
    /// register it as `ServiceId::REGISTRY`, run forever.
    Up {
        /// Space id (full hex) or name.
        space: String,
        /// Exit when the registry goes idle (smoke-test mode).
        #[arg(long)]
        once: bool,
    },
    /// Query a space's registry and emit a round-trippable
    /// TOML manifest to stdout.
    Export {
        /// Space id (full hex) or name.
        space: String,
    },
    /// Add a program (PVM blob) to the catalog with an
    /// immutable `(name, version)` tag.
    Publish {
        /// Space id or name.
        space: String,
        /// `name` or `name:version`. Bare `name` ⇒ `name:latest`.
        program_ref: String,
        /// Blob source: file path, hash, ipfs:<cid>, or URL.
        source: String,
    },
    /// Remove a program from the catalog. Errors if any
    /// installed agent still references the version.
    Unpublish {
        space: String,
        /// `name:version` (both required).
        program_ref: String,
    },
    /// List programs in the catalog.
    Programs {
        space: String,
    },
    /// Instantiate a published program as an installed agent.
    Install {
        /// Space id or name.
        space: String,
        /// Program ref: `name`, `name:version`. Bare `name`
        /// resolves to `name:latest`.
        program_ref: String,
        /// Override the install/instance name. Defaults to
        /// the program's `name`.
        #[arg(long)]
        name: Option<String>,
        /// Init args as `key=value` pairs (repeatable). Values
        /// are typed as u64 / bool / String in that order.
        #[arg(long, value_name = "KEY=VALUE")]
        init: Vec<String>,
        /// Consistency mode: ephemeral, local, crdt, or raft.
        #[arg(long, default_value = "crdt")]
        consistency: String,
        /// Optional explicit replication id (64 hex). Default:
        /// blake2b("vos-replication-id/v1" || instance_name ||
        /// 0 || program_hash).
        #[arg(long, value_name = "HEX")]
        replication_id: Option<String>,
    },
    /// Tombstone an installed agent.
    Uninstall {
        space: String,
        instance: String,
    },
    /// Repoint an installed agent at a different program
    /// version. State is preserved (same replication_id, same
    /// redb); replicas restart on next sync.
    Upgrade {
        space: String,
        instance: String,
        /// New program ref: `name:version`.
        program_ref: String,
    },
    /// List installed agents.
    Agents {
        space: String,
    },
    /// Manage Node + Identity members. Subcommands: list,
    /// add-node, remove-node, add-identity, remove-identity.
    /// Bare `space members <space>` lists.
    Members {
        space: String,
        #[command(subcommand)]
        command: Option<members::MembersCommand>,
    },
    /// Remove a local space — wipes the per-space data dir and
    /// the spaces.toml entry. The shared blob cache is kept.
    Delete {
        space: String,
        /// Skip the confirmation prompt.
        #[arg(long)]
        yes: bool,
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
        SpaceCommand::Join {
            bootstrap,
            registry,
            name,
            listen,
            data_dir,
        } => join::run(join::Args {
            bootstrap,
            registry,
            name,
            listen,
            data_dir,
        }),
        SpaceCommand::Up { space, once } => up::run(up::Args { query: space, once }),
        SpaceCommand::Export { space } => export::run(export::Args { query: space }),
        SpaceCommand::Publish {
            space,
            program_ref,
            source,
        } => publish::run(publish::Args {
            space,
            program_ref,
            source,
        }),
        SpaceCommand::Unpublish {
            space,
            program_ref,
        } => unpublish::run(unpublish::Args {
            space,
            program_ref,
        }),
        SpaceCommand::Programs { space } => programs::run(&space),
        SpaceCommand::Install {
            space,
            program_ref,
            name,
            init,
            consistency,
            replication_id,
        } => install::run(install::Args {
            space,
            program_ref,
            name,
            init,
            consistency,
            replication_id,
        }),
        SpaceCommand::Uninstall { space, instance } => uninstall::run(&space, &instance),
        SpaceCommand::Upgrade {
            space,
            instance,
            program_ref,
        } => upgrade::run(upgrade::Args {
            space,
            instance,
            program_ref,
        }),
        SpaceCommand::Agents { space } => agents::run(&space),
        SpaceCommand::Members { space, command } => {
            members::run(members::Args { space, command })
        }
        SpaceCommand::Delete { space, yes } => {
            delete::run(delete::Args { space, yes })
        }
    }
}
