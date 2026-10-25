//! The command line: its commands, and the arguments they share.

use std::net::SocketAddr;
use std::path::{Path, PathBuf};

use clap::{Parser, Subcommand};
use vos_node::client::Target;
use vos_node::tls::{IngressTls, Trust};

use crate::{at, failed, key_bytes};

/// The version, saying so when the build injects faults.
const VERSION: &str = if cfg!(feature = "faults") {
    concat!(env!("CARGO_PKG_VERSION"), " (faults: a test build)")
} else {
    env!("CARGO_PKG_VERSION")
};

#[derive(Parser)]
#[command(
    name = "vos",
    version = VERSION,
    about = "Run a VOS node, operate it, and call its agents"
)]
pub struct Cli {
    #[command(subcommand)]
    pub command: Command,
}

#[derive(Subcommand)]
pub enum Command {
    /// Nodes.
    Node {
        #[command(subcommand)]
        command: NodeCommand,
    },
    /// Client keys.
    Key {
        #[command(subcommand)]
        command: KeyCommand,
    },
    /// The space the nodes run in.
    Space {
        #[command(subcommand)]
        command: SpaceCommand,
    },
    /// Agents, with the node's admin token.
    Agent {
        #[command(subcommand)]
        command: AgentCommand,
    },
    /// Install a package, an actor's ELF, as an instance of an agent, with
    /// the admin token: prints the programs the node derived from it.
    Install(InstallArgs),
    /// Grant a client key a role in an agent, or revoke it, with the admin
    /// token.
    Role(RoleArgs),
    /// Call a command, signed with a client key.
    Call(CallArgs),
    /// Run a query, signed with a client key, on state that holds every
    /// answer the key was given for the agent.
    Query {
        #[command(flatten)]
        call: CallArgs,
        /// Read state that holds every call answered anywhere before the
        /// query: the replica asks the agent's leader how far to apply.
        #[arg(long)]
        linearizable: bool,
    },
    /// Read a workflow the client key started, by the id its start was
    /// answered with: where it stands, or its result once it ended.
    Workflow(WorkflowArgs),
    /// The program id of an actor's attestable method's kernel, derived
    /// from its ELF as an install derives it: eight M31 words, in decimal.
    /// With `--circuits`, the circuits' constants instead, each a line of
    /// its name and its words or bytes.
    #[cfg(feature = "prover")]
    ProgramId {
        /// The actor's package, the ELF its crate built.
        #[arg(required_unless_present = "circuits")]
        elf: Option<std::path::PathBuf>,
        /// The attestable method.
        #[arg(required_unless_present = "circuits")]
        method: Option<String>,
        /// Print `H_FOLD`, `WRAP_ROOT_28` and `WRAP_ROOT_39`, computed.
        #[arg(long, conflicts_with_all = ["elf", "method"])]
        circuits: bool,
    },
}

#[derive(Subcommand)]
pub enum NodeCommand {
    /// Run a node until it is killed. Without TLS, it listens on a
    /// loopback address only.
    Run(RunArgs),
    /// Print a node's public key, its identity.
    Info {
        #[command(flatten)]
        node: NodeArgs,
    },
    /// The keys a node signs its space's anchors with.
    AnchorKey {
        #[command(subcommand)]
        command: AnchorKeyCommand,
    },
}

#[derive(Subcommand)]
pub enum AnchorKeyCommand {
    /// Make a new anchor key, kept in the node's store, and print its
    /// public key for the space's controller to register at each venue
    /// (`add_authority`). The node signs with it once a venue lists it;
    /// the controller then removes the old key (`remove_anchor_key`).
    Rotate {
        /// The node's data directory, its node stopped.
        #[arg(long)]
        data: PathBuf,
    },
}

#[derive(clap::Args)]
pub struct RunArgs {
    /// The node's data directory: its store and admin token.
    #[arg(long)]
    pub data: PathBuf,
    #[arg(long, default_value = "127.0.0.1:7700")]
    pub listen: SocketAddr,
    /// The agent program, as built by `just build-agent`.
    #[arg(long, env = "VOS_AGENT")]
    pub agent: PathBuf,
    #[command(flatten)]
    pub tls: TlsArgs,
    /// The space's nodes, one per line: number, key, peer address and
    /// ingress address. Without it, the node is a space of one.
    #[arg(long)]
    pub space: Option<PathBuf>,
    /// The node's settings, a TOML file: `executors`, `queue`,
    /// `max_inputs`, `max_bytes`, `linger_ms`, `ingress_connections`,
    /// `election_timeout_ms` (its two ends) and `heartbeat_ms`, each
    /// optional. Without it, the defaults.
    #[arg(long)]
    pub config: Option<PathBuf>,
    /// Bind the peer endpoint here rather than at the address the
    /// space lists for this node, as behind port forwarding.
    #[arg(long)]
    pub peer_bind: Option<SocketAddr>,
}

#[derive(Subcommand)]
pub enum SpaceCommand {
    /// Found the space of a space file: its genesis, of the nodes it lists
    /// and a clock, written once beside it (`<space>.genesis`), never
    /// replaced. The space's id, its genesis's hash, is printed.
    ///
    /// Found it before creating any agent: an agent records its space at
    /// its first install, for good, so one created before the founding
    /// belongs to no space forever. Then copy `<space>.genesis` beside
    /// every node's space file and restart the nodes.
    Up {
        /// The space file: number, key, peer address and ingress address
        /// per line.
        #[arg(long)]
        space: PathBuf,
        /// The founding node's data directory, its node stopped: the
        /// founding is refused when its store holds an agent.
        #[arg(long)]
        data: PathBuf,
        /// Each window's length, in milliseconds: from 120,000 to
        /// 3,600,000.
        #[arg(long, default_value_t = vos_wire::vos_anchor::DEFAULT_LENGTH_MS)]
        window_ms: u64,
        /// Where window 0 starts, in milliseconds since the Unix epoch: the
        /// founding time by default.
        #[arg(long)]
        origin_ms: Option<u64>,
    },
    /// Create the space's representative, with the admin token of the
    /// space's first founding node, which creates it once: its id is
    /// printed. Then install the representative's package as its instance.
    Representative {
        #[command(flatten)]
        operator: OperatorArgs,
        /// The founding nodes to replicate it on, by number: `1,2,3`. The
        /// node alone by default.
        #[arg(long, value_delimiter = ',')]
        replicas: Vec<u8>,
    },
}

#[derive(Subcommand)]
pub enum KeyCommand {
    /// Make a client key: its seed goes to FILE, readable by its owner only,
    /// and its public key is printed.
    New {
        #[arg(long)]
        out: PathBuf,
    },
}

#[derive(Subcommand)]
pub enum AgentCommand {
    /// Create an agent: its id is printed.
    Create {
        #[command(flatten)]
        operator: OperatorArgs,
        /// The nodes to replicate it on, by number: `1,2,3`. The node
        /// alone by default.
        #[arg(long, value_delimiter = ',')]
        replicas: Vec<u8>,
    },
    /// Replace one of an agent's replicas by another node, at its leader:
    /// the replicas are printed once the change committed.
    Replace {
        #[command(flatten)]
        operator: OperatorArgs,
        #[arg(long)]
        agent: u32,
        /// The replica that leaves, by number.
        #[arg(long)]
        remove: u8,
        /// The node that takes its place, by number.
        #[arg(long)]
        add: u8,
    },
}

#[derive(clap::Args)]
pub struct InstallArgs {
    #[command(flatten)]
    pub operator: OperatorArgs,
    #[arg(long)]
    pub agent: u32,
    #[arg(long)]
    pub instance: u32,
    /// The package: the ELF the actor's crate built with the guest
    /// toolchain, uploaded as it is. The node derives the actor's program
    /// and its attestable methods' kernels from it.
    #[arg(long)]
    pub elf: PathBuf,
    /// A role name's byte: `NAME=BYTE`.
    #[arg(long = "role", value_parser = named_role)]
    pub roles: Vec<(Vec<u8>, u8)>,
}

#[derive(clap::Args)]
pub struct RoleArgs {
    #[command(flatten)]
    pub operator: OperatorArgs,
    #[arg(long)]
    pub agent: u32,
    /// The client's public key, in hex.
    #[arg(long)]
    pub principal: String,
    /// The role's byte, or `none` to revoke.
    #[arg(long, value_parser = granted)]
    pub role: Granted,
}

/// TLS on a node's ingress.
#[derive(clap::Args)]
pub struct TlsArgs {
    /// Serve TLS with a certificate for the node's own key, which clients
    /// pin.
    #[arg(long, conflicts_with = "tls_cert")]
    tls: bool,
    /// A name the certificate for the node's key holds: a host name or an
    /// address. Repeat for more.
    #[arg(long = "tls-name", requires = "tls")]
    tls_names: Vec<String>,
    /// Serve TLS with this PEM certificate chain, which clients trust by
    /// its CA.
    #[arg(long, requires = "tls_key")]
    tls_cert: Option<PathBuf>,
    /// The PEM key of `--tls-cert`.
    #[arg(long, requires = "tls_cert")]
    tls_key: Option<PathBuf>,
}

impl TlsArgs {
    pub fn ingress(self) -> Option<IngressTls> {
        match (self.tls_cert, self.tls_key) {
            (Some(chain), Some(key)) => Some(IngressTls::Files { chain, key }),
            _ if self.tls => Some(IngressTls::NodeKey {
                names: self.tls_names,
            }),
            _ => None,
        }
    }
}

/// A node to reach, and how to trust it.
#[derive(clap::Args)]
pub struct NodeArgs {
    /// The node's address: `http://` reaches a loopback address only,
    /// `https://` needs `--node-key` or `--ca`.
    #[arg(long, default_value = "http://127.0.0.1:7700")]
    node: String,
    /// The node's key, in hex, which its TLS must show: as `vos node run`
    /// printed it. It wins over `--ca`.
    #[arg(long, env = "VOS_NODE_KEY")]
    node_key: Option<String>,
    /// A PEM file of the CAs that the node's TLS certificate must chain to.
    #[arg(long, env = "VOS_CA")]
    ca: Option<PathBuf>,
}

impl NodeArgs {
    pub fn target(&self) -> Result<Target, String> {
        self.target_or(None)
    }

    /// The target, pinned by the key in `kept` when neither a key nor a CA
    /// is given for an `https://` node.
    pub fn target_or(&self, kept: Option<&Path>) -> Result<Target, String> {
        let kept = kept.filter(|_| self.node.starts_with("https://"));
        let trust = match (&self.node_key, &self.ca, kept) {
            (Some(key), _, _) => Trust::NodeKey(key_bytes(key)?),
            (None, Some(ca), _) => Trust::ca_file(ca)?,
            (None, None, Some(kept)) => {
                let key = std::fs::read_to_string(kept).map_err(at(kept))?;
                Trust::NodeKey(key_bytes(&key)?)
            }
            (None, None, None) => Trust::Loopback,
        };
        Target::new(&self.node, trust).map_err(failed)
    }
}

#[derive(clap::Args)]
pub struct OperatorArgs {
    #[command(flatten)]
    pub node: NodeArgs,
    /// The node's data directory, which holds its admin token: operator
    /// commands run on the node's host.
    #[arg(long)]
    pub data: PathBuf,
}

#[derive(clap::Args)]
pub struct WorkflowArgs {
    #[command(flatten)]
    pub node: NodeArgs,
    /// The client key's seed file, from `vos key new`: the key that
    /// started the workflow.
    #[arg(long)]
    pub key: PathBuf,
    #[arg(long)]
    pub agent: u32,
    /// The workflow's id, as `started` printed it.
    #[arg(long)]
    pub id: u64,
    /// Wait this many seconds, at most 30, for the workflow to end.
    #[arg(long, default_value_t = 0)]
    pub wait: u64,
    /// Read state that holds every call answered anywhere before the read.
    #[arg(long)]
    pub linearizable: bool,
}

#[derive(clap::Args)]
pub struct CallArgs {
    #[command(flatten)]
    pub node: NodeArgs,
    /// The client key's seed file, from `vos key new`.
    #[arg(long)]
    pub key: PathBuf,
    #[arg(long)]
    pub agent: u32,
    #[arg(long)]
    pub instance: u32,
    /// The method's name, as the installed schema has it.
    #[arg(long)]
    pub method: String,
    /// The arguments, SCALE-encoded, in hex.
    #[arg(long, default_value = "", value_parser = hex_bytes)]
    pub args: Hex,
}

/// The role a grant gives, or (`None`) its revocation.
#[derive(Clone, Copy)]
pub struct Granted(pub Option<u8>);

/// Bytes given in hex.
#[derive(Clone)]
pub struct Hex(pub Vec<u8>);

fn role_byte(byte: &str) -> Result<u8, String> {
    byte.parse().map_err(|_| format!("a role byte: {byte}"))
}

/// `NAME=BYTE`: a role's name and its byte.
fn named_role(pair: &str) -> Result<(Vec<u8>, u8), String> {
    let (name, byte) = pair
        .split_once('=')
        .ok_or_else(|| format!("expected NAME=VALUE: {pair}"))?;
    Ok((name.as_bytes().to_vec(), role_byte(byte)?))
}

/// A role's byte, or `none`.
fn granted(text: &str) -> Result<Granted, String> {
    match text {
        "none" => Ok(Granted(None)),
        byte => role_byte(byte).map(|byte| Granted(Some(byte))),
    }
}

fn hex_bytes(text: &str) -> Result<Hex, String> {
    hex::decode(text.trim())
        .map(Hex)
        .map_err(|error| error.to_string())
}
