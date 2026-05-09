//! `vosx` — JAM-aligned PVM executor + space orchestrator.
//!
//! The single binary covers five subcommands:
//!
//! - `run` — execute a single ELF/PVM blob (no manifest, no
//!   networking). Useful for raw smoke-testing.
//! - `node` — run several ELFs side-by-side without a manifest;
//!   the simplest way to wire a few actors + workers together.
//! - `start` — boot a space described by a `space.toml`. The
//!   primary entry point; auto-spawns the hyperspace registry
//!   when declared, announces every local service, runs
//!   `run_forever` when the network's attached.
//! - `list` — print a manifest's actors + workers + their
//!   declared messages, recovered from each ELF's `.vos_meta`.
//! - `invoke` — send a typed message to any actor in the
//!   hyperspace from a transient peer, print the reply.
//!
//! Each subcommand lives in `commands/`; this file owns the
//! CLI surface (clap structs) and dispatch.

use clap::{Parser, Subcommand};
use std::path::{Path, PathBuf};

mod commands;
mod hyperspace;
mod manifest;
mod network;
mod query;
mod util;

use manifest::manifest_from;
use util::init_tracing;

#[derive(Parser)]
#[command(name = "vosx", about = "JAM-aligned PVM executor")]
struct Cli {
    #[command(subcommand)]
    command: Option<Command>,

    /// Program or manifest to run (auto-detected by extension).
    file: Option<PathBuf>,
}

#[derive(clap::ValueEnum, Clone, Copy, Debug)]
enum ConsistencyArg {
    Ephemeral,
    Local,
    Crdt,
}

impl From<ConsistencyArg> for vos::node::Consistency {
    fn from(a: ConsistencyArg) -> Self {
        match a {
            ConsistencyArg::Ephemeral => vos::node::Consistency::Ephemeral,
            ConsistencyArg::Local => vos::node::Consistency::Local,
            ConsistencyArg::Crdt => vos::node::Consistency::Crdt,
        }
    }
}

#[derive(Subcommand)]
enum Command {
    /// Run a PVM/ELF program.
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
    /// Run multiple agents concurrently.
    Node {
        programs: Vec<PathBuf>,
        /// Load a registry service at ServiceId(0).
        #[arg(long, value_name = "FILE")]
        registry: Option<PathBuf>,
        /// Load native worker plugins. Optional init args after a colon:
        ///   --worker libfoo.so
        ///   --worker libfoo.so:key=hello,n=42
        #[arg(long, value_name = "FILE[:KEY=VAL,...]")]
        worker: Vec<String>,
        /// Data directory for state persistence. Workers are stored in
        /// `{data_dir}/workers/{name}.redb`. Default: no persistence.
        #[arg(long, value_name = "DIR", default_value = "data")]
        data_dir: Option<PathBuf>,
        /// Disable state persistence (overrides --data-dir).
        #[arg(long)]
        no_persist: bool,
        /// Replication / persistence semantics for the PVM agents.
        #[arg(long, value_name = "MODE", default_value = "ephemeral")]
        consistency: ConsistencyArg,
    },
    /// Start the space defined by a manifest. With no path, looks
    /// for `space.toml` in the current directory.
    Start {
        manifest: Option<PathBuf>,
        /// Override the data directory (default: `data`).
        #[arg(long, value_name = "DIR", default_value = "data")]
        data_dir: Option<PathBuf>,
        /// Disable state persistence entirely (overrides --data-dir).
        #[arg(long)]
        no_persist: bool,
        /// libp2p multiaddr to listen on.
        #[arg(long, value_name = "MULTIADDR")]
        listen: Vec<String>,
        /// libp2p multiaddr to dial at startup. Repeatable.
        #[arg(long, value_name = "MULTIADDR")]
        connect: Vec<String>,
    },
    /// List actors in a manifest.
    List { manifest: Option<PathBuf> },
    /// Snapshot of a hyperspace: local identity, connected
    /// peers, and the registry's contents. Joins the manifest's
    /// hyperspace as a transient peer (same model as `invoke`).
    Status {
        manifest: Option<PathBuf>,
        /// libp2p multiaddr to dial at startup. Repeatable.
        #[arg(long, value_name = "MULTIADDR")]
        connect: Vec<String>,
        /// Seconds to wait for registry sync before printing.
        #[arg(long, default_value_t = 3)]
        sync_timeout: u64,
    },
    /// Resolve a service name (or accept a `0x…` ServiceId) and
    /// invoke a typed message on it. Joins the manifest's
    /// hyperspace as a transient peer, looks the name up via
    /// the registry actor, then forwards the call.
    Invoke {
        /// Service name (looked up in registry) or a literal
        /// `0xHEX` ServiceId.
        target: String,
        /// Message name (e.g. `inc`, `get`, `lookup`).
        msg: String,
        /// Repeatable: `--arg key=value`. Auto-typed: integer
        /// → u64, `true`/`false` → bool, everything else → str.
        #[arg(long, value_name = "KEY=VALUE")]
        arg: Vec<String>,
        /// Manifest path. Defaults to `space.toml`.
        manifest: Option<PathBuf>,
        /// libp2p multiaddr to dial at startup. Repeatable.
        #[arg(long, value_name = "MULTIADDR")]
        connect: Vec<String>,
        /// Seconds to wait for registry sync before resolving
        /// the target name. Ignored when target is `0x…`.
        #[arg(long, default_value_t = 3)]
        sync_timeout: u64,
    },
}

fn main() {
    init_tracing();
    let cli = Cli::parse();

    match cli.command {
        Some(Command::Run {
            program,
            payload,
            hex,
            gas,
        }) => {
            commands::run::run(&program, &payload, &hex, gas);
        }
        Some(Command::Node {
            programs,
            registry,
            worker,
            data_dir,
            no_persist,
            consistency,
        }) => {
            let dir = if no_persist {
                None
            } else {
                data_dir.as_deref()
            };
            commands::node::run(
                &programs,
                registry.as_deref(),
                &worker,
                dir,
                consistency.into(),
            );
        }
        Some(Command::Start {
            manifest,
            data_dir,
            no_persist,
            listen,
            connect,
        }) => {
            let (m, dir) = manifest_from(manifest);
            commands::start::run(&m, &dir, data_dir.as_deref(), no_persist, &listen, &connect);
        }
        Some(Command::List { manifest }) => {
            let (m, dir) = manifest_from(manifest);
            commands::list::run(&m, &dir);
        }
        Some(Command::Status {
            manifest,
            connect,
            sync_timeout,
        }) => {
            let (m, dir) = manifest_from(manifest);
            commands::status::run(&m, &dir, &connect, sync_timeout);
        }
        Some(Command::Invoke {
            target,
            msg,
            arg,
            manifest,
            connect,
            sync_timeout,
        }) => {
            let (m, dir) = manifest_from(manifest);
            commands::invoke::run(&m, &dir, &target, &msg, &arg, &connect, sync_timeout);
        }
        None if cli.file.as_ref().is_some_and(|p| !manifest::is_manifest(p)) => {
            commands::run::run(cli.file.as_ref().unwrap(), &[], &[], 100_000_000);
        }
        None => {
            let (m, dir) = manifest_from(cli.file);
            commands::start::run(&m, &dir, Some(Path::new("data")), false, &[], &[]);
        }
    }
}
