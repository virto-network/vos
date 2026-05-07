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

mod blob_store;
mod commands;
mod hyperspace;
mod identity;
mod manifest;
mod network;
mod paths;
mod query;
mod spaces_index;
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
    Raft,
}

impl From<ConsistencyArg> for vos::node::Consistency {
    fn from(a: ConsistencyArg) -> Self {
        match a {
            ConsistencyArg::Ephemeral => vos::node::Consistency::Ephemeral,
            ConsistencyArg::Local => vos::node::Consistency::Local,
            ConsistencyArg::Crdt => vos::node::Consistency::Crdt,
            ConsistencyArg::Raft => vos::node::Consistency::Raft,
        }
    }
}

#[derive(Subcommand)]
enum Command {
    /// Scaffold a new space — creates `<name>/space.toml` and a
    /// starter actor crate so you can `cd <name> && vosx up` to
    /// see something working.
    New {
        /// Directory name for the new space.
        name: String,
    },
    /// Boot the space defined by `space.toml` (default).
    /// With no path, looks for `space.toml` in the current
    /// directory. Runs until Ctrl-C; pass `--once` for the
    /// "exit when actors go idle" smoke-test mode.
    Up {
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
        /// Joins existing Raft groups via auto-discovery once
        /// the bootnodes complete the Hello handshake.
        #[arg(long, value_name = "MULTIADDR")]
        connect: Vec<String>,
        /// Exit once every actor has been idle for ~2s instead
        /// of running until Ctrl-C. For tests and smoke checks.
        #[arg(long)]
        once: bool,
    },
    /// Join an existing cluster as a fresh node. Dials the
    /// bootnode, fetches its `space.toml` + actor blobs (unless
    /// `--manifest` is given), then sends a `RaftJoin` request
    /// for every Raft agent the manifest declares. The local
    /// node attaches as a voter and runs forever.
    Join {
        /// Bootnode multiaddr (e.g.
        /// `/ip4/192.0.2.10/tcp/4811/p2p/12D3...`).
        bootnode: String,
        /// Use a local `space.toml` instead of fetching from the
        /// bootnode. Required if the bootnode doesn't expose its
        /// manifest.
        #[arg(long, value_name = "FILE")]
        manifest: Option<PathBuf>,
        /// Override the data directory (default: `data`).
        #[arg(long, value_name = "DIR", default_value = "data")]
        data_dir: Option<PathBuf>,
        /// Disable state persistence entirely (overrides --data-dir).
        #[arg(long)]
        no_persist: bool,
        /// libp2p multiaddr to listen on. Empty → ephemeral.
        #[arg(long, value_name = "MULTIADDR")]
        listen: Vec<String>,
    },
    /// Run a single PVM/ELF program with no manifest (one-shot).
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
    /// List actors declared in a manifest.
    Ls {
        manifest: Option<PathBuf>,
    },
    /// Live cluster status — one row per service: name, role
    /// (leader/follower/...), term, last_applied, peer count.
    Ps {
        manifest: Option<PathBuf>,
        /// libp2p multiaddr to dial at startup. Repeatable.
        #[arg(long, value_name = "MULTIADDR")]
        connect: Vec<String>,
        /// Seconds to wait for registry sync before printing.
        #[arg(long, default_value_t = 3)]
        sync_timeout: u64,
    },
    /// Per-space lifecycle commands. New / list / info land in
    /// Phase 1a; up / export / join in Phase 1b/1c.
    Space {
        #[command(subcommand)]
        command: commands::space::SpaceCommand,
    },
    /// Invoke a typed message on a service:
    ///   `vosx call counter.inc 5`
    /// Resolves the target via the manifest's registry, types
    /// the positional args from the actor's `Message::META`.
    Call {
        /// `<agent>.<msg>` — e.g. `counter.inc`. Plain
        /// `0xHEX.msg` also accepted when bypassing the registry.
        target: String,
        /// Positional args for the message. Auto-typed against
        /// the handler's parameter list (resolved from the actor's
        /// `Message::META`). For backward-compat, `key=value`
        /// pairs are still accepted.
        args: Vec<String>,
        /// Manifest path. Defaults to `space.toml`.
        manifest: Option<PathBuf>,
        /// libp2p multiaddr to dial at startup. Repeatable.
        #[arg(long, value_name = "MULTIADDR")]
        connect: Vec<String>,
        /// Seconds to wait for registry sync before resolving
        /// the target name.
        #[arg(long, default_value_t = 3)]
        sync_timeout: u64,
    },
}

fn main() {
    init_tracing();
    let cli = Cli::parse();

    match cli.command {
        Some(Command::New { name }) => {
            commands::new::run(&name);
        }
        Some(Command::Up { manifest, data_dir, no_persist, listen, connect, once }) => {
            let (m, dir, toml) = manifest_from(manifest);
            commands::start::run(&m, &dir, &toml, data_dir.as_deref(), no_persist, &listen, &connect, once);
        }
        Some(Command::Join { bootnode, manifest, data_dir, no_persist, listen }) => {
            commands::join::run(
                &bootnode,
                manifest.as_deref(),
                data_dir.as_deref(),
                no_persist,
                &listen,
            );
        }
        Some(Command::Run { program, payload, hex, gas }) => {
            commands::run::run(&program, &payload, &hex, gas);
        }
        Some(Command::Ls { manifest }) => {
            let (m, dir, _toml) = manifest_from(manifest);
            commands::list::run(&m, &dir);
        }
        Some(Command::Ps { manifest, connect, sync_timeout }) => {
            let (m, dir, _toml) = manifest_from(manifest);
            commands::status::run(&m, &dir, &connect, sync_timeout);
        }
        Some(Command::Call { target, args, manifest, connect, sync_timeout }) => {
            let (m, dir, _toml) = manifest_from(manifest);
            commands::invoke::run_call(&m, &dir, &target, &args, &connect, sync_timeout);
        }
        Some(Command::Space { command }) => {
            if let Err(e) = commands::space::run(command) {
                eprintln!("error: {e}");
                std::process::exit(1);
            }
        }
        None if cli.file.as_ref().is_some_and(|p| !manifest::is_manifest(p)) => {
            commands::run::run(cli.file.as_ref().unwrap(), &[], &[], 100_000_000);
        }
        None => {
            let (m, dir, toml) = manifest_from(cli.file);
            commands::start::run(&m, &dir, &toml, Some(Path::new("data")), false, &[], &[], false);
        }
    }
}
