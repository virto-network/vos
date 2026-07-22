//! `vosx space *` — per-space lifecycle, daemon control,
//! and registry-mediated agent management.
//!
//! Three groups of commands:
//!
//! - **Offline**: `new`, `list`, `info`, `delete`, `export`
//!   (read-only). Operate on `~/.config/vosx/spaces.toml` and
//!   per-space data dirs without contacting a daemon. Joining a
//!   remote space is folded into `space up <token>`.
//! - **Daemon**: `up` runs the libp2p server that owns the
//!   redb. One daemon per space, identified by an
//!   `<data_dir>/.endpoint` file.
//! - **Client**: `publish`, `install`, `upgrade`, `uninstall`,
//!   `unpublish`, `programs`, `agents`, `members`, `call`.
//!   Each spawns a tiny libp2p peer, dials the daemon's
//!   endpoint, sends one registry invoke, and exits. Same
//!   plumbing under `DaemonClient` — `call` is the floor
//!   primitive, the rest are typed sugar.

use clap::Subcommand;
use std::path::PathBuf;

pub mod agents;
pub mod apply;
pub mod call;
pub mod caps;
pub mod client;
pub mod common;
pub mod describe;
pub mod down;
pub mod endpoint;
pub mod export;
pub mod forget;
pub mod info;
pub mod install;
pub mod invite;
pub mod list;
pub mod members;
pub mod new;
pub mod op_sign;
pub mod programs;
pub mod publish;
pub mod raft_status;
pub mod reconcile;
pub mod role;
pub mod subscriptions;
pub mod uninstall;
pub mod unpublish;
pub mod up;
pub mod upgrade;
pub mod verify;

#[derive(Subcommand, Debug)]
pub enum SpaceCommand {
    /// Create a new space — scaffold identity, initial data
    /// dir, and add to the local spaces index. Doesn't run
    /// any daemon; `space up` is what binds a network. Set
    /// the daemon's persistent listen addrs by editing the
    /// per-space `local.toml`'s `listen = […]`, or pass
    /// `--listen` to `space up` per-run.
    New {
        /// Short name for the space. Used in listings and as the
        /// default lookup key.
        name: String,
        /// Source for the space-registry actor blob: file path,
        /// 64-hex content hash (cache lookup), `ipfs:<cid>`, or
        /// `https://…`. Optional — falls back to the registry
        /// blob bundled into the vosx binary at build time.
        #[arg(long, value_name = "SOURCE")]
        registry: Option<String>,
        /// Override the per-space data directory (default:
        /// `~/.local/share/vosx/<space_id>`).
        #[arg(long, value_name = "DIR")]
        data_dir: Option<PathBuf>,
        /// Optional recipe TOML to apply on the space's first `space
        /// up` (recorded as the pending recipe — a one-shot genesis
        /// apply, not a boot-time reconcile).
        #[arg(long, value_name = "FILE")]
        recipe: Option<PathBuf>,
    },
    /// List spaces in the local index.
    List,
    /// Show details for a single space (by id-prefix or name).
    Info {
        /// Space id (full hex) or name.
        space: String,
    },
    /// Mint a `vos1…` invite token for a running space. Requires the
    /// operator to hold ADMIN. The joiner redeems it with `space up
    /// <token>`. Tokens grant `member` or `developer`; promote admins
    /// explicitly with `space role grant` after admission. Subcommands:
    /// `list` shows recorded invites (rows appear on redemption or
    /// revocation), `revoke <token_pub-prefix>` invalidates one; bare
    /// `space invite <space>` mints.
    Invite {
        /// Space id (full hex) or name.
        space: String,
        /// Role the token grants: `member` (default) | `developer`.
        /// Mint only.
        #[arg(long)]
        role: Option<String>,
        /// Expiry window: `7d` (default) / `24h` / `30m` / `90s` /
        /// bare seconds. Mint only.
        #[arg(long)]
        expires: Option<String>,
        /// Bootnode multiaddr(s) to embed. Repeatable. Defaults to the
        /// running daemon's published listen addrs. Mint only.
        #[arg(long, value_name = "MULTIADDR")]
        bootnode: Vec<String>,
        /// `list` / `revoke <token_pub-prefix>`; omit to mint.
        #[command(subcommand)]
        command: Option<invite::InviteCommand>,
    },
    /// Boot a space — THE onboarding command. The positional is
    /// trivalent: an existing `.toml` recipe path (create-if-missing +
    /// one-shot genesis apply + boot), a `vos1…` invite token
    /// (join-if-needed + boot + auto-redeem), or a space name / id
    /// (boot a known space). `-` reads a token from stdin. Loads the
    /// registry from cache, registers it as `ServiceId::REGISTRY`, and
    /// runs forever.
    Up {
        /// Recipe path, `vos1…` token, `-` (token via stdin), or a
        /// known space id (full hex) / name.
        space: String,
        /// Exit when the registry goes idle (smoke-test mode).
        #[arg(long)]
        once: bool,
        /// libp2p multiaddr to listen on. Repeatable. Overrides
        /// the saved `listen` field on the spaces.toml entry
        /// for this run.
        #[arg(long, value_name = "MULTIADDR")]
        listen: Vec<String>,
        /// libp2p multiaddr to dial at startup. Repeatable.
        /// Extends the saved `bootnodes` field on the
        /// spaces.toml entry for this run.
        #[arg(long, value_name = "MULTIADDR")]
        connect: Vec<String>,
        /// Exact generic service PVM used by installed `.vos` v2 packages.
        #[arg(long, value_name = "FILE")]
        service_pvm: Option<PathBuf>,
    },
    /// Stop a running `space up` daemon by signalling its PID.
    /// SIGTERM by default (daemon flushes state, removes the
    /// endpoint file, exits); `--force` upgrades to SIGKILL if
    /// the daemon doesn't exit within `--grace` seconds.
    Down {
        /// Space id (full hex) or name.
        space: String,
        /// Skip the SIGTERM grace window and SIGKILL immediately.
        #[arg(long)]
        force: bool,
        /// Seconds to wait for graceful shutdown before
        /// (optionally, with `--force`) escalating.
        #[arg(long, default_value_t = 5)]
        grace: u64,
    },
    /// Query a space's registry and emit a round-trippable
    /// TOML recipe to stdout.
    Export {
        /// Space id (full hex) or name.
        space: String,
    },
    /// Apply a recipe TOML to a running space: publish + install any
    /// missing agents (the replicated half → the registry) and project
    /// the recipe's node-local half (`tick_ms` / `intra_caps` /
    /// `device_secret`, `cap_policy`, `[[extension]]`) into `local.toml`.
    /// Idempotent — a re-apply of the same recipe is all-skips.
    Apply {
        /// Space id (full hex) or name.
        space: String,
        /// Recipe TOML path.
        recipe: PathBuf,
        /// Print the plan (create / skip / upgrade + local.toml
        /// changes) and exit without mutating anything.
        #[arg(long)]
        diff: bool,
        /// Re-point installed agents whose catalog blob differs from the
        /// recipe. Without it, a differing blob is flagged, not applied.
        #[arg(long)]
        upgrade: bool,
    },
    /// Add a signed `.vos` v2 package to the catalog with an immutable
    /// `(name, version)` tag.
    Publish {
        /// Space id or name.
        space: String,
        /// `name` or `name:version`. Bare `name` ⇒ `name:latest`.
        program_ref: String,
        /// Signed `.vos` source: file path, hash, ipfs:<cid>, or URL.
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
    Programs { space: String },
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
        /// Consistency mode: ephemeral, local, crdt, or raft.
        #[arg(long, default_value = "local")]
        consistency: String,
        /// Optional explicit replication id (64 hex). Default:
        /// blake2b("vos-replication-id/v1" || instance_name ||
        /// 0 || program_hash).
        #[arg(long, value_name = "HEX")]
        replication_id: Option<String>,
        /// Serving-side sync floor: public | member | private.
        #[arg(long, default_value = "member")]
        sync: String,
    },
    /// Tombstone an installed agent.
    Uninstall { space: String, instance: String },
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
    Agents { space: String },
    /// Show an installed agent's schema — message names, arg
    /// types, and constructor params. Pulls the `.vos_meta`
    /// blob the registry has on file (same data the gateway
    /// serves at `GET /__schema/<agent>`). Use `--format json`
    /// for machine consumption.
    Describe {
        space: String,
        /// Instance name as it appears in `vosx space agents`.
        instance: String,
    },
    /// Show the effective relay `intra_caps` the running daemon
    /// loaded for each service extension — the per-target role
    /// ceilings an extension may relay (deny-all when empty).
    /// Daemon-local host policy, read from the endpoint descriptor.
    /// Pass an instance to filter; `--format json` for machine
    /// consumption.
    Caps {
        space: String,
        /// Optional extension instance name to filter to.
        instance: Option<String>,
    },
    /// Show the connected daemon's view of a Raft agent's group —
    /// role, term, leader, and member node prefixes. Reads the
    /// existing `RaftStatusReq` plumbing; use it to find the leader
    /// before an Operator-gated write and to watch failover.
    /// `--format json` for machine consumption.
    RaftStatus {
        space: String,
        /// Raft agent instance name (as in `vosx space agents`).
        instance: String,
    },
    /// Manage Node + Identity members. Subcommands: list,
    /// add-node, remove-node, add-identity, remove-identity.
    /// Bare `space members <space>` lists.
    Members {
        space: String,
        #[command(subcommand)]
        command: Option<members::MembersCommand>,
    },
    /// Manage auth-role grants. Subcommands: list, grant, revoke.
    /// Bare `space role <space>` lists. Registry-mutation handlers
    /// are gated behind `AUTH_ROLE_ADMIN`; this is the table the
    /// dispatch-layer gate consults. The space creator is
    /// auto-enrolled as admin by `space new` via a signed
    /// `grant_role` baked into the genesis DAG.
    Role {
        space: String,
        #[command(subcommand)]
        command: Option<role::RoleCommand>,
    },
    /// Drop the local copy of a space — wipes the per-space
    /// data dir and the spaces.toml entry. The shared blob
    /// cache is kept and the space stays alive on its peers;
    /// this is purely a local operation.
    Forget {
        space: String,
        /// Skip the confirmation prompt.
        #[arg(long)]
        yes: bool,
    },
    /// Per-node subscription filter. Empty filter (the default)
    /// = sync every installed agent; non-empty = sync only the
    /// listed instances. Stored in `<data_dir>/local.toml`.
    /// Bare `space subs <space>` lists.
    Subs {
        space: String,
        #[command(subcommand)]
        command: Option<subscriptions::SubsCommand>,
    },
    /// Invoke any agent on the running daemon. Generic floor
    /// primitive; `publish` / `install` / etc. are typed sugar
    /// wrappers around the same plumbing.
    ///
    /// `target` accepts:
    /// - `registry` — the well-known per-space registry
    /// - `<instance_name>` — an installed agent (resolved via
    ///   the daemon's registry)
    /// - `0xHEX` — bare 32-bit ServiceId
    Call {
        space: String,
        target: String,
        method: String,
        /// Positional `key=value` args. Numbers and booleans
        /// are auto-typed; everything else is a string.
        args: Vec<String>,
    },
}

pub fn run(cmd: SpaceCommand) -> anyhow::Result<()> {
    match cmd {
        SpaceCommand::New {
            name,
            registry,
            data_dir,
            recipe,
        } => new::run(new::Args {
            name,
            registry,
            data_dir,
            recipe,
        }),
        SpaceCommand::List => list::run(),
        SpaceCommand::Info { space } => info::run(&space),
        SpaceCommand::Invite {
            space,
            role,
            expires,
            bootnode,
            command,
        } => invite::run(invite::Args {
            space,
            role,
            expires,
            bootnode,
            command,
        }),
        SpaceCommand::Up {
            space,
            once,
            listen,
            connect,
            service_pvm,
        } => up::run(up::Args {
            query: space,
            once,
            listen,
            connect,
            service_pvm,
        }),
        SpaceCommand::Down {
            space,
            force,
            grace,
        } => down::run(down::Args {
            query: space,
            force,
            grace_secs: grace,
        }),
        SpaceCommand::Export { space } => export::run(export::Args { query: space }),
        SpaceCommand::Apply {
            space,
            recipe,
            diff,
            upgrade,
        } => apply::run(apply::Args {
            space,
            recipe,
            diff,
            upgrade,
        }),
        SpaceCommand::Publish {
            space,
            program_ref,
            source,
        } => publish::run(publish::Args {
            space,
            program_ref,
            source,
        }),
        SpaceCommand::Unpublish { space, program_ref } => {
            unpublish::run(unpublish::Args { space, program_ref })
        }
        SpaceCommand::Programs { space } => programs::run(&space),
        SpaceCommand::Install {
            space,
            program_ref,
            name,
            consistency,
            replication_id,
            sync,
        } => install::run(install::Args {
            space,
            program_ref,
            name,
            consistency,
            replication_id,
            sync,
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
        SpaceCommand::Describe { space, instance } => describe::run(&space, &instance),
        SpaceCommand::Caps { space, instance } => caps::run(&space, instance.as_deref()),
        SpaceCommand::RaftStatus { space, instance } => raft_status::run(&space, &instance),
        SpaceCommand::Members { space, command } => members::run(members::Args { space, command }),
        SpaceCommand::Role { space, command } => role::run(role::Args { space, command }),
        SpaceCommand::Forget { space, yes } => forget::run(forget::Args { space, yes }),
        SpaceCommand::Call {
            space,
            target,
            method,
            args,
        } => call::run(call::Args {
            space,
            target,
            method,
            args,
        }),
        SpaceCommand::Subs { space, command } => subscriptions::run(&space, command),
    }
}
