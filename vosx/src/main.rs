//! `vosx` — AgentActor authoring and local space orchestration.
//!
//! Top-level surface is intentionally tiny: every space-related
//! operation lives under `vosx space *`. Top-level commands build canonical
//! packages and manage platform artifacts.
//!
//! Operational Agent installation is intentionally not exposed by this
//! clean-generation CLI until the system authority and catalog bootstrap
//! path is complete.

use clap::{Args as ClapArgs, CommandFactory, Parser, Subcommand};
use std::path::PathBuf;

mod blob_store;
mod bundled;
mod commands;
mod help_schema;
mod identity;
mod output;
mod paths;
mod secure_file;
mod shutdown;
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
#[command(
    name = "vosx",
    version,
    about = "VOS host CLI — build actors, manage spaces, talk to peers"
)]
struct Cli {
    #[command(subcommand)]
    command: Option<Command>,

    /// Output format. `text` (default) is human-readable;
    /// `json` emits a single JSON value per command for scripts
    /// and LLM consumption. Inherited by all subcommands.
    #[arg(long, value_enum, default_value_t = Format::Text, global = true)]
    format: Format,

    /// Enable progress / status chatter on stderr. Off by
    /// default — only warnings and errors print. Inherited by
    /// all subcommands.
    #[arg(short, long, global = true)]
    verbose: bool,
}

#[derive(Subcommand)]
enum Command {
    /// Build and scaffold portable actors hosted by an Agent.
    Actor {
        #[command(subcommand)]
        command: ActorCommand,
    },
    /// Transpile and validate a standard agent-runtime PVM.
    AgentRuntimePvm {
        /// `agent_runtime.elf` built from an agent-runtime guest. Omit it to
        /// verify the runtime embedded in this vosx binary.
        elf: Option<PathBuf>,
        /// Output path; defaults to the input path with a `.pvm` extension.
        #[arg(long)]
        out: Option<PathBuf>,
    },
    /// Package or verify the protocol-pinned production runtime artifacts.
    Release {
        #[command(subcommand)]
        command: commands::production_release::ReleaseCommand,
    },
    /// Per-space lifecycle and operations.
    Space {
        #[command(subcommand)]
        command: commands::space::SpaceCommand,
    },
    /// Provable-program pinning: `vosx zk pin` measures a provable actor's
    /// canonical commitment allowlist + entering-image root + witness address
    /// and writes them to a catalog artifact verifiers trust. The heavy proof
    /// work runs in the prover extension (`measure_catalog`), so this needs a
    /// space that's `up` with the prover extension loaded; `vosx` itself pulls
    /// no prover dependency.
    Zk {
        #[command(subcommand)]
        command: commands::zk::ZkCommand,
    },
    /// Emit the full CLI schema as pretty-printed JSON. Walks
    /// every subcommand + argument from clap's introspection,
    /// so the dump always matches what the binary accepts.
    /// Designed for LLM and tooling consumption — pipe into
    /// `jq '.subcommands[] | .name'` to enumerate verbs.
    HelpSchema,
    /// Print the operator's persistent libp2p PeerId — the
    /// identity the daemon sees when this `vosx` invocation
    /// dials it. Creates the keypair on first run at
    /// `$XDG_CONFIG_HOME/vosx/identity.key`. Useful for
    /// enrolling the operator into a space's `members` ACL.
    Whoami {
        /// Emit JSON `{"peer_id": "...", "path": "..."}` instead
        /// of plain text. Pipe into `jq` for scripting.
        #[arg(long)]
        json: bool,
    },
}

#[derive(ClapArgs)]
struct ActorBuildOptions {
    /// AgentActor project directory, ELF, or canonical standard PVM.
    program: PathBuf,
    #[arg(long)]
    name: Option<String>,
    #[arg(long, default_value = "dist")]
    out_dir: PathBuf,
    /// Exact `.vos_meta` producer metadata when PROGRAM is a PVM.
    #[arg(long)]
    metadata: Option<PathBuf>,
    /// Exact AAS2 `.vos_agent` bytes when PROGRAM is a PVM.
    #[arg(long)]
    agent_schema: Option<PathBuf>,
    /// Exact AAM1 `.vos_agent_auth` bytes when PROGRAM is a PVM.
    #[arg(long)]
    agent_authorizations: Option<PathBuf>,
    /// Prebuilt AMP2 accepted only when it byte-equals generated policy.
    #[arg(long)]
    method_policy: Option<PathBuf>,
    /// Canonical Task project directory or ELF dependency. May be repeated.
    #[arg(long = "task")]
    tasks: Vec<PathBuf>,
    /// Validate that the actor's derived state lanes are merge-only.
    #[arg(long)]
    crdt: bool,
    /// Explicitly require scheduler support; never inferred from Job methods.
    #[arg(long)]
    scheduling: bool,
    /// Exact nonzero proof-system identity used by every attested method and
    /// provable Task dependency (64 lowercase hexadecimal characters).
    #[arg(long, value_parser = parse_proof_system)]
    proof_system: Option<vos::agent::sdk::Hash>,
}

impl ActorBuildOptions {
    fn into_build_args(self) -> commands::build::Args {
        commands::build::Args {
            program: self.program,
            name: self.name,
            out_dir: self.out_dir,
            method_policy: self.method_policy,
            schemas: self.metadata,
            agent_schema: self.agent_schema,
            agent_authorizations: self.agent_authorizations,
            tasks: self.tasks,
            crdt: self.crdt,
            scheduling: self.scheduling,
            proof_system: self.proof_system,
        }
    }
}

fn parse_proof_system(value: &str) -> Result<vos::agent::sdk::Hash, String> {
    if value.len() != 64
        || value
            .as_bytes()
            .iter()
            .any(|byte| !byte.is_ascii_digit() && !(b'a'..=b'f').contains(byte))
    {
        return Err("proof system must be exactly 64 lowercase hexadecimal characters".into());
    }
    let bytes = hex::decode(value).map_err(|_| "proof system is not hexadecimal")?;
    let bytes: [u8; 32] = bytes
        .try_into()
        .map_err(|_| "proof system must decode to exactly 32 bytes")?;
    if bytes == [0; 32] {
        return Err("proof system must be nonzero".into());
    }
    Ok(vos::agent::sdk::Hash(bytes))
}

#[derive(Subcommand)]
enum ActorCommand {
    /// Create a minimal portable AgentActor project.
    New {
        path: PathBuf,
        /// Scaffold an actor whose state uses only the merge lane.
        #[arg(long)]
        crdt: bool,
    },
    /// Build one portable AgentActor PVM and signed clean-generation VOS3
    /// package. PVM inputs require exact producer metadata artifacts.
    Build {
        #[command(flatten)]
        options: Box<ActorBuildOptions>,
    },
}

/// Initialize the global tracing subscriber. Default level is
/// `warn` (quiet); `-v` raises it to `info` for one-time state
/// changes; `RUST_LOG` overrides everything for power users
/// who want `debug` or per-target filtering. Also bridges the
/// `log` facade so vos's actor-side `log::*` calls reach the
/// same subscriber.
fn init_tracing(verbose: bool) {
    let default_level = if verbose { "info" } else { "warn" };
    let filter = tracing_subscriber::EnvFilter::try_from_default_env()
        .unwrap_or_else(|_| tracing_subscriber::EnvFilter::new(default_level));
    let _ = tracing_subscriber::fmt()
        .with_env_filter(filter)
        .with_writer(std::io::stderr)
        .try_init();
    let _ = tracing_log::LogTracer::init();
}

fn main() {
    // Restore default SIGPIPE so `vosx … | head` exits quietly when the
    // reader closes, instead of panicking on a broken stdout — piping
    // command output (e.g. capturing an invite token) is a documented
    // pattern. Rust runtimes ignore SIGPIPE by default.
    // SAFETY: signal(2) with SIG_DFL is a scalar handler reset, done
    // before any threads exist.
    #[cfg(unix)]
    unsafe {
        libc::signal(libc::SIGPIPE, libc::SIG_DFL);
    }
    commands::build::maybe_run_canonical_rustc_wrapper();

    let cli = Cli::parse();
    init_tracing(cli.verbose);
    output::set(cli.format);

    match cli.command {
        Some(Command::Actor { command }) => match command {
            ActorCommand::New { path, crdt } => {
                if let Err(error) = commands::new_project::run(path, crdt) {
                    report_error(error);
                }
            }
            ActorCommand::Build { options } => {
                if let Err(error) = commands::build::run((*options).into_build_args()) {
                    report_error(error);
                }
            }
        },
        Some(Command::AgentRuntimePvm { elf, out }) => {
            if let Err(error) = commands::agent_runtime_pvm::run(elf.as_deref(), out) {
                report_error(error);
            }
        }
        Some(Command::Release { command }) => {
            if let Err(error) = commands::production_release::run(command) {
                report_error(error);
            }
        }
        Some(Command::Space { command }) => {
            if let Err(e) = commands::space::run(command) {
                report_error(e);
            }
        }
        Some(Command::Zk { command }) => {
            if let Err(e) = commands::zk::run(command) {
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
        Some(Command::Whoami { json }) => {
            let path = paths::client_identity_path();
            let kp = match identity::load_or_create() {
                Ok(kp) => kp,
                Err(e) => report_error(e),
            };
            let peer_id = libp2p::PeerId::from(kp.public()).to_string();
            if json {
                let view = serde_json::json!({
                    "peer_id": peer_id,
                    "path": path.display().to_string(),
                });
                match serde_json::to_string_pretty(&view) {
                    Ok(s) => println!("{s}"),
                    Err(e) => {
                        eprintln!("error: {e}");
                        std::process::exit(EXIT_RUNTIME_ERROR);
                    }
                }
            } else {
                println!("peer_id = {peer_id}");
                println!("path    = {}", path.display());
            }
        }
        None => {
            eprintln!("vosx: no command. Try `vosx space new foo` or `vosx --help`.");
            std::process::exit(EXIT_USAGE_ERROR);
        }
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

#[cfg(test)]
mod routing_tests {
    use super::{ActorCommand, Cli, Command, parse_proof_system};
    use clap::{CommandFactory, Parser, error::ErrorKind};

    #[test]
    fn proof_system_identity_is_exact_lowercase_hex_and_nonzero() {
        assert_eq!(parse_proof_system(&"42".repeat(32)).unwrap().0, [0x42; 32]);
        for invalid in [
            "42".repeat(31),
            "42".repeat(33),
            "GG".repeat(32),
            "AA".repeat(32),
            "00".repeat(32),
        ] {
            assert!(parse_proof_system(&invalid).is_err());
        }
    }

    #[test]
    fn actor_owns_authoring_and_retired_spellings_have_no_aliases() {
        let parsed = Cli::try_parse_from(["vosx", "actor", "new", "counter"]).unwrap();
        assert!(matches!(
            parsed.command,
            Some(Command::Actor {
                command: ActorCommand::New { .. }
            })
        ));
        assert!(Cli::try_parse_from(["vosx", "actor", "build", "counter"]).is_ok());

        for argv in [
            ["vosx", "new", "counter"],
            ["vosx", "build", "counter"],
            ["vosx", "agent", "new"],
            ["vosx", "service-pvm", "service.elf"],
        ] {
            let error = Cli::try_parse_from(argv)
                .err()
                .expect("retired spelling must be rejected");
            assert_eq!(error.kind(), ErrorKind::InvalidSubcommand, "argv={argv:?}");
        }
    }

    #[test]
    fn clap_help_exposes_only_the_actor_authoring_namespace() {
        let names = Cli::command()
            .get_subcommands()
            .map(|command| command.get_name().to_owned())
            .collect::<Vec<_>>();
        assert!(names.iter().any(|name| name == "actor"));
        for retired in ["new", "build", "agent", "service-pvm"] {
            assert!(
                !names.iter().any(|name| name == retired),
                "retired command={retired}"
            );
        }
        assert!(names.iter().any(|name| name == "agent-runtime-pvm"));
    }
}
