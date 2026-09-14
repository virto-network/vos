//! `vosx space *` — local space lifecycle and daemon control.
//!
//! Clean-generation administration includes fresh Local Create and exact
//! retained-request retries. Install and ordinary Shared-Agent provisioning
//! remain unwired.

use clap::Subcommand;
use std::path::PathBuf;

#[cfg(target_os = "linux")]
pub(crate) mod authority_projection_authenticator;
pub mod backup;
pub mod caps;
// The hardened store depends on Unix dirfd, no-follow, ownership, link-count,
// and durable-directory semantics. It is intentionally unavailable where
// those guarantees cannot be enforced.
#[cfg(target_os = "linux")]
#[allow(dead_code)] // Wired by the clean native startup owner in this chapter.
pub(crate) mod clean_genesis_archive;
#[allow(dead_code)]
pub(crate) mod clean_identity;
#[cfg(target_os = "linux")]
pub(crate) mod clean_startup;
#[cfg(unix)]
#[allow(dead_code)]
pub(crate) mod clean_store;
pub mod client;
pub mod common;
pub mod down;
pub mod endpoint;
pub mod forget;
pub mod info;
#[cfg(target_os = "linux")]
pub(crate) mod invocation_progress;
pub mod list;
pub mod local_config;
#[cfg(target_os = "linux")]
pub(crate) mod local_create;
#[cfg(target_os = "linux")]
pub(crate) mod local_install;
#[cfg(target_os = "linux")]
pub(crate) mod local_invocation;
pub mod new;
pub mod op_sign;
#[cfg(target_os = "linux")]
mod operation_authorization;
pub mod reconcile;
mod space_lock;
pub mod up;
pub mod verify;

#[derive(Subcommand, Debug)]
pub enum SpaceCommand {
    /// Submit or retry exact AOQ1 authorization; retain the verified decision.
    #[cfg(target_os = "linux")]
    SubmitAgentAuthorization {
        request_dir: PathBuf,
        /// Initial signed AOQ1; ignored after a request has been retained.
        #[arg(long)]
        request: Option<PathBuf>,
        /// Loopback HTTP only; no proxies or redirects.
        #[arg(long)]
        http: std::net::SocketAddr,
    },
    /// Resume retained yielded work and retire its terminal delivery exactly.
    #[cfg(target_os = "linux")]
    ContinueAgentInvocation {
        request_dir: PathBuf,
        #[arg(long)]
        http: std::net::SocketAddr,
    },
    /// Deliver or retry exact canonical ASQ1; retains the first bound response.
    #[cfg(target_os = "linux")]
    SubmitAgentInvocation {
        request_dir: PathBuf,
        /// Initial ASQ1 input, ignored after an invocation has been retained.
        #[arg(long)]
        request: Option<PathBuf>,
        #[arg(long)]
        http: std::net::SocketAddr,
    },
    /// Install a signed actor package into an operator-owned Local Agent.
    #[cfg(target_os = "linux")]
    InstallLocalActor(local_install::InstallLocalArgs),
    /// Submit or retry an already retained signed Local Install request.
    #[cfg(target_os = "linux")]
    SubmitLocalInstall {
        request_dir: PathBuf,
        /// Local plaintext daemon socket; no proxies or redirects.
        #[arg(long)]
        http: std::net::SocketAddr,
    },
    /// Create an operator-owned Local Agent with the bundled runtime.
    #[cfg(target_os = "linux")]
    CreateLocalAgent {
        space: String,
        /// Override the configured local plaintext HTTP endpoint.
        #[arg(long)]
        http: Option<std::net::SocketAddr>,
        /// Resume the latest retained operation without changing signed bytes.
        #[arg(long)]
        resume: bool,
    },
    /// Submit or retry an already retained signed Local Create request.
    #[cfg(target_os = "linux")]
    SubmitLocalCreate {
        /// Private request-store directory; existing bytes are never replaced.
        request_dir: PathBuf,
        /// Local daemon HTTP socket (loopback only; no proxy or redirects).
        #[arg(long)]
        http: std::net::SocketAddr,
    },
    /// Create a local space identity and data directory.
    New {
        name: String,
        /// Registry blob source: path, hash, `ipfs:<cid>`, or `https://…`.
        #[arg(long, value_name = "SOURCE")]
        registry: Option<String>,
        /// Override the per-space data directory.
        #[arg(long, value_name = "DIR")]
        data_dir: Option<PathBuf>,
    },
    /// List spaces in the local index.
    List,
    /// Show local details for a space.
    Info { space: String },
    /// Run a known space's registry/platform daemon.
    Up {
        /// Known space id (full hex) or name.
        space: String,
        /// Exit when the registry goes idle (smoke-test mode).
        #[arg(long)]
        once: bool,
        /// Listen multiaddr. Repeatable and overrides saved addresses.
        #[arg(long, value_name = "MULTIADDR")]
        listen: Vec<String>,
        /// Startup peer multiaddr. Repeatable.
        #[arg(long, value_name = "MULTIADDR")]
        connect: Vec<String>,
    },
    /// Stop a running local daemon.
    Down {
        space: String,
        #[arg(long)]
        force: bool,
        #[arg(long, default_value_t = 5)]
        grace: u64,
    },
    /// Create a verified offline backup of one space.
    Backup { space: String, output: PathBuf },
    /// Verify and restore a `space backup` directory.
    Restore {
        backup: PathBuf,
        /// Separately retained per-space node key.
        #[arg(long, value_name = "FILE", required = true)]
        node_key: PathBuf,
        #[arg(long, value_name = "DIR")]
        data_dir: Option<PathBuf>,
        /// Preserve the previous destination under a recoverable sibling path.
        #[arg(long)]
        replace: bool,
        #[arg(long)]
        name: Option<String>,
    },
    /// Show local extension relay capability ceilings.
    Caps {
        space: String,
        instance: Option<String>,
    },
    /// Remove the local copy of a stopped space.
    Forget {
        space: String,
        #[arg(long)]
        yes: bool,
    },
}

pub fn run(cmd: SpaceCommand) -> anyhow::Result<()> {
    match cmd {
        #[cfg(target_os = "linux")]
        SpaceCommand::SubmitAgentAuthorization {
            request_dir,
            request,
            http,
        } => operation_authorization::run(&request_dir, request.as_deref(), http),
        #[cfg(target_os = "linux")]
        SpaceCommand::ContinueAgentInvocation { request_dir, http } => {
            invocation_progress::run(&request_dir, http)
        }
        #[cfg(target_os = "linux")]
        SpaceCommand::SubmitAgentInvocation {
            request_dir,
            request,
            http,
        } => local_invocation::run(&request_dir, request.as_deref(), http),
        #[cfg(target_os = "linux")]
        SpaceCommand::InstallLocalActor(args) => local_install::run_install(args),
        #[cfg(target_os = "linux")]
        SpaceCommand::CreateLocalAgent {
            space,
            http,
            resume,
        } => local_create::run_create(&space, http, resume),
        #[cfg(target_os = "linux")]
        SpaceCommand::SubmitLocalInstall { request_dir, http } => {
            local_install::run_submit(&request_dir, http)
        }
        #[cfg(target_os = "linux")]
        SpaceCommand::SubmitLocalCreate { request_dir, http } => {
            local_create::run_submit(&request_dir, http)
        }
        SpaceCommand::New {
            name,
            registry,
            data_dir,
        } => new::run(new::Args {
            name,
            registry,
            data_dir,
        }),
        SpaceCommand::List => list::run(),
        SpaceCommand::Info { space } => info::run(&space),
        SpaceCommand::Up {
            space,
            once,
            listen,
            connect,
        } => up::run(up::Args {
            query: space,
            once,
            listen,
            connect,
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
        SpaceCommand::Backup { space, output } => backup::run_backup(&space, &output),
        SpaceCommand::Restore {
            backup: archive,
            node_key,
            data_dir,
            replace,
            name,
        } => backup::run_restore(
            &archive,
            &node_key,
            data_dir.as_deref(),
            replace,
            name.as_deref(),
        ),
        SpaceCommand::Caps { space, instance } => caps::run(&space, instance.as_deref()),
        SpaceCommand::Forget { space, yes } => forget::run(forget::Args { space, yes }),
    }
}
