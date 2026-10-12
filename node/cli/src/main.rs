//! `vos`: run a node, operate it with its admin token, and call its agents
//! with a client key.

use std::collections::HashMap;
use std::net::SocketAddr;
use std::path::{Path, PathBuf};
use std::process::ExitCode;

use clap::{Parser, Subcommand};
use ed25519_dalek::SigningKey;
use vos_node::client::{self, Client, ClientError, Operator, Target};
use vos_node::tls::{IngressTls, Trust};
use vos_node::{ADMIN_TOKEN, Config, NODE_KEY, Node, Space};
use vos_wire::Encode;
use vos_wire::abi::refusal;
use vos_wire::ids::{AgentId, InstanceId, MethodId, Principal};
use vos_wire::ingress::{Answer, Consistency, Install};
use vos_wire::result::Outcome;
use vos_wire::schema::Schema;

/// mimalloc, unless built without it: a thread frees memory another thread
/// allocated without taking that thread's lock, as the node's executors,
/// writer and store workers do all the time.
#[cfg(feature = "mimalloc")]
#[global_allocator]
static ALLOCATOR: mimalloc::MiMalloc = mimalloc::MiMalloc;

/// With mimalloc, transparent huge pages are off for the process. Backing
/// its arenas with 2 MiB pages kept about a fifth more of a node resident
/// under load; without them it holds about what the system allocator does
/// with them, for about 8% less CPU a commit. Off, they cost about 2% more
/// cycles (TLB misses), for either allocator. Processes it starts inherit
/// the setting: it spawns none today.
fn huge_pages_off() {
    #[cfg(all(feature = "mimalloc", target_os = "linux"))]
    {
        let (on, none): (libc::c_ulong, libc::c_ulong) = (1, 0);
        // SAFETY: it sets a flag on this process; no memory is passed.
        let set = unsafe { libc::prctl(libc::PR_SET_THP_DISABLE, on, none, none, none) };
        if set != 0 {
            eprintln!(
                "vos: transparent huge pages stay on ({}): more memory stays resident",
                std::io::Error::last_os_error()
            );
        }
    }
}

/// With `VOS_PVM_PERF_MAP` set, the code the PVM compiles is named in
/// `/tmp/perf-<pid>.map`, so perf attributes guest time to its programs.
fn perf_map() {
    #[cfg(all(target_os = "linux", target_arch = "x86_64"))]
    if std::env::var_os("VOS_PVM_PERF_MAP").is_some()
        && let Err(error) = vos_pvm::perf_map::enable()
    {
        eprintln!("vos: the PVM's perf map is off ({error})");
    }
}

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
struct Cli {
    #[command(subcommand)]
    command: Command,
}

#[derive(Subcommand)]
enum Command {
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
    /// Agents, with the node's admin token.
    Agent {
        #[command(subcommand)]
        command: AgentCommand,
    },
    /// Install a package as an instance of an agent, with the admin token.
    Install {
        #[command(flatten)]
        operator: OperatorArgs,
        #[arg(long)]
        agent: u32,
        #[arg(long)]
        instance: u32,
        /// The actor program, an ELF built with the guest toolchain.
        #[arg(long)]
        program: PathBuf,
        /// An attestable method's program: `METHOD=ELF`.
        #[arg(long = "attestable")]
        attestables: Vec<String>,
        /// A role name's byte: `NAME=BYTE`.
        #[arg(long = "role")]
        roles: Vec<String>,
    },
    /// Grant a client key a role in an agent, or revoke it, with the admin
    /// token.
    Role {
        #[command(flatten)]
        operator: OperatorArgs,
        #[arg(long)]
        agent: u32,
        /// The client's public key, in hex.
        #[arg(long)]
        principal: String,
        /// The role's byte, or `none` to revoke.
        #[arg(long)]
        role: String,
    },
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
}

#[derive(Subcommand)]
enum NodeCommand {
    /// Run a node until it is killed. Without TLS, it listens on a
    /// loopback address only.
    Run {
        /// The node's data directory: its store and admin token.
        #[arg(long)]
        data: PathBuf,
        #[arg(long, default_value = "127.0.0.1:7700")]
        listen: SocketAddr,
        /// The agent program, as built by `just build-agent`.
        #[arg(long, env = "VOS_AGENT")]
        agent: PathBuf,
        #[command(flatten)]
        tls: TlsArgs,
        /// The space's nodes, one per line: number, key, peer address and
        /// ingress address. Without it, the node is a space of one.
        #[arg(long)]
        space: Option<PathBuf>,
        /// Bind the peer endpoint here rather than at the address the
        /// space lists for this node, as behind port forwarding.
        #[arg(long)]
        peer_bind: Option<SocketAddr>,
        /// Threads that run the node's tasks: its groups, their leader and
        /// apply loops, its ingress and its peers' messages. For
        /// measuring: more than one has run under no fault suite.
        #[arg(long, default_value_t = 1, hide = true)]
        runtime_threads: usize,
    },
    /// Print a node's public key, its identity.
    Info {
        #[command(flatten)]
        node: NodeArgs,
    },
}

#[derive(Subcommand)]
enum KeyCommand {
    /// Make a client key: its seed goes to FILE, readable by its owner only,
    /// and its public key is printed.
    New {
        #[arg(long)]
        out: PathBuf,
    },
}

#[derive(Subcommand)]
enum AgentCommand {
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

/// TLS on a node's ingress.
#[derive(clap::Args)]
struct TlsArgs {
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
    fn ingress(&self) -> Option<IngressTls> {
        match (&self.tls_cert, &self.tls_key) {
            (Some(chain), Some(key)) => Some(IngressTls::Files {
                chain: chain.clone(),
                key: key.clone(),
            }),
            _ if self.tls => Some(IngressTls::NodeKey {
                names: self.tls_names.clone(),
            }),
            _ => None,
        }
    }
}

/// A node to reach, and how to trust it.
#[derive(clap::Args)]
struct NodeArgs {
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
    fn target(&self) -> Result<Target, String> {
        self.target_or(None)
    }

    /// The target, pinned by the key in `kept` when neither a key nor a CA
    /// is given for an `https://` node.
    fn target_or(&self, kept: Option<&Path>) -> Result<Target, String> {
        let kept = kept.filter(|_| self.node.starts_with("https://"));
        let trust = match (&self.node_key, &self.ca, kept) {
            (Some(key), _, _) => Trust::NodeKey(key_bytes(key)?),
            (None, Some(ca), _) => Trust::ca_file(ca)?,
            (None, None, Some(kept)) => {
                let key = std::fs::read_to_string(kept)
                    .map_err(|error| format!("{}: {error}", kept.display()))?;
                Trust::NodeKey(key_bytes(&key)?)
            }
            (None, None, None) => Trust::Loopback,
        };
        Target::new(&self.node, trust).map_err(failed)
    }
}

#[derive(clap::Args)]
struct OperatorArgs {
    #[command(flatten)]
    node: NodeArgs,
    /// The node's data directory, which holds its admin token: operator
    /// commands run on the node's host.
    #[arg(long)]
    data: PathBuf,
}

#[derive(clap::Args)]
struct CallArgs {
    #[command(flatten)]
    node: NodeArgs,
    /// The client key's seed file, from `vos key new`.
    #[arg(long)]
    key: PathBuf,
    #[arg(long)]
    agent: u32,
    #[arg(long)]
    instance: u32,
    /// The method's name, as the installed schema has it.
    #[arg(long)]
    method: String,
    /// The arguments, SCALE-encoded, in hex.
    #[arg(long, default_value = "")]
    args: String,
}

fn main() -> ExitCode {
    huge_pages_off();
    perf_map();
    match run(Cli::parse()) {
        Ok(()) => ExitCode::SUCCESS,
        Err(error) => {
            eprintln!("vos: {error}");
            ExitCode::FAILURE
        }
    }
}

fn run(cli: Cli) -> Result<(), String> {
    match cli.command {
        Command::Node {
            command:
                NodeCommand::Run {
                    data,
                    listen,
                    agent,
                    tls,
                    space,
                    peer_bind,
                    runtime_threads,
                },
        } => node(
            &data,
            listen,
            &agent,
            tls.ingress(),
            space.as_deref(),
            peer_bind,
            runtime_threads,
        ),
        Command::Node {
            command: NodeCommand::Info { node },
        } => {
            let id = vos_node::client::node_id(&node.target()?).map_err(failed)?;
            println!("{}", hex::encode(id.0));
            Ok(())
        }
        Command::Key {
            command: KeyCommand::New { out },
        } => new_key(&out),
        Command::Agent {
            command:
                AgentCommand::Replace {
                    operator,
                    agent,
                    remove,
                    add,
                },
        } => match operator_of(&operator)?
            .replace(AgentId(agent), remove, add)
            .map_err(failed)?
        {
            Answer::Placed(replicas) => {
                let replicas: Vec<String> = replicas.iter().map(u8::to_string).collect();
                println!("{}", replicas.join(","));
                Ok(())
            }
            Answer::TimedOut => {
                Err("not committed in time: the agent's leader goes on with the change".into())
            }
            other => Err(format!("{other:?}")),
        },
        Command::Agent {
            command: AgentCommand::Create { operator, replicas },
        } => match operator_of(&operator)?
            .create_agent(replicas)
            .map_err(failed)?
        {
            Answer::Created(agent) => {
                println!("{}", agent.0);
                Ok(())
            }
            Answer::Unconfirmed(agent) => {
                println!("{}", agent.0);
                eprintln!("vos: a majority of its replicas does not hold it yet");
                Ok(())
            }
            other => Err(describe(&other)),
        },
        Command::Install {
            operator,
            agent,
            instance,
            program,
            attestables,
            roles,
        } => {
            let program = link(&program)?;
            let schema = schema_of(&program)?;
            let attestables = attestables
                .iter()
                .map(|pair| {
                    let (name, path) = split(pair)?;
                    Ok((method_named(&schema, name)?, link(Path::new(path))?))
                })
                .collect::<Result<Vec<_>, String>>()?;
            let roles = roles
                .iter()
                .map(|pair| {
                    let (name, byte) = split(pair)?;
                    let byte = byte
                        .parse::<u8>()
                        .map_err(|_| format!("a role byte: {byte}"))?;
                    Ok((name.as_bytes().to_vec(), byte))
                })
                .collect::<Result<Vec<_>, String>>()?;
            let install = Install {
                instance: InstanceId(instance),
                program,
                attestables,
                roles,
            };
            let answer = operator_of(&operator)?
                .install(AgentId(agent), &install)
                .map_err(failed)?;
            print_answer(&answer)
        }
        Command::Role {
            operator,
            agent,
            principal,
            role,
        } => {
            let key = key_bytes(&principal)?;
            let role = match role.as_str() {
                "none" => None,
                byte => Some(
                    byte.parse::<u8>()
                        .map_err(|_| format!("a role byte: {byte}"))?,
                ),
            };
            let answer = operator_of(&operator)?
                .grant(AgentId(agent), Principal::Client(key), role)
                .map_err(failed)?;
            print_answer(&answer)
        }
        Command::Call(call) => invoke(&call, None),
        Command::Query { call, linearizable } => invoke(&call, Some(linearizable)),
    }
}

fn failed(error: vos_node::client::ClientError) -> String {
    format!("{error:?}")
}

fn node(
    data: &Path,
    listen: SocketAddr,
    agent: &Path,
    tls: Option<IngressTls>,
    space: Option<&Path>,
    peer_bind: Option<SocketAddr>,
    runtime_threads: usize,
) -> Result<(), String> {
    // The node's log, on stderr: `VOS_LOG` names the level, `info` unless
    // it says otherwise.
    let level = std::env::var("VOS_LOG")
        .ok()
        .and_then(|level| level.parse().ok())
        .unwrap_or(tracing_subscriber::filter::LevelFilter::INFO);
    tracing_subscriber::fmt()
        .with_writer(std::io::stderr)
        .with_max_level(level)
        .init();
    let mut config = Config::new(link(agent)?);
    config.ingress_tls = tls;
    config.space = space.map(Space::read).transpose()?;
    config.peer_bind = peer_bind;
    config.runtime_threads = runtime_threads;
    #[cfg(feature = "faults")]
    {
        eprintln!("vos: WARNING: this build injects faults; it is for tests only");
        if let Some(path) = std::env::var_os("VOS_FAULTS") {
            vos_node::faults::Faults::install(&mut config, Path::new(&path))
                .map_err(|error| error.to_string())?;
        }
    }
    let node = Node::open(data, config).map_err(|error| format!("{error:?}"))?;
    let address = node.serve(listen).map_err(|error| format!("{error:?}"))?;
    println!("listening on {address}");
    println!("node {}", hex::encode(node.id().0));
    loop {
        std::thread::park();
    }
}

fn new_key(out: &Path) -> Result<(), String> {
    use std::io::Write;
    use std::os::unix::fs::OpenOptionsExt;
    let mut seed = [0u8; 32];
    getrandom::getrandom(&mut seed).map_err(|error| error.to_string())?;
    let mut file = std::fs::OpenOptions::new()
        .write(true)
        .create_new(true)
        .mode(0o600)
        .open(out)
        .map_err(|error| format!("{}: {error}", out.display()))?;
    file.write_all(hex::encode(seed).as_bytes())
        .map_err(|error| error.to_string())?;
    println!(
        "{}",
        hex::encode(SigningKey::from_bytes(&seed).verifying_key().to_bytes())
    );
    Ok(())
}

fn operator_of(args: &OperatorArgs) -> Result<Operator, String> {
    let path = args.data.join(ADMIN_TOKEN);
    let token =
        std::fs::read_to_string(&path).map_err(|error| format!("{}: {error}", path.display()))?;
    // On the node's host, its data directory holds its key.
    let target = args.node.target_or(Some(&args.data.join(NODE_KEY)))?;
    Ok(Operator::new(&target, &token))
}

/// A standard program from an ELF built with the guest toolchain. With the
/// PVM's perf map on, its functions are named in it.
fn link(path: &Path) -> Result<Vec<u8>, String> {
    let elf = std::fs::read(path).map_err(|error| format!("{}: {error}", path.display()))?;
    let failed = |error| format!("{}: {error:?}", path.display());
    #[cfg(all(target_os = "linux", target_arch = "x86_64"))]
    if vos_pvm::perf_map::enabled() {
        let (blob, functions) =
            vos_pvm_compiler::link_elf_spi_with_symbols(&elf).map_err(failed)?;
        if let Some(program) = vos_pvm::spi::parse_standard_program(&blob) {
            vos_pvm::perf_map::register(&program.code.code, functions);
        }
        return Ok(blob);
    }
    vos_pvm_compiler::link_elf_spi(&elf).map_err(failed)
}

fn schema_of(program: &[u8]) -> Result<Schema, String> {
    let parsed = vos_pvm::spi::parse_standard_program(program).ok_or("not a standard program")?;
    Schema::read(&parsed.ro_data).map_err(|error| format!("its schema: {error:?}"))
}

fn method_named(schema: &Schema, name: &str) -> Result<MethodId, String> {
    schema
        .methods
        .iter()
        .find(|method| method.name == name.as_bytes())
        .map(|method| method.id)
        .ok_or_else(|| format!("no method {name}"))
}

fn split(pair: &str) -> Result<(&str, &str), String> {
    pair.split_once('=')
        .ok_or_else(|| format!("expected NAME=VALUE: {pair}"))
}

fn key_bytes(text: &str) -> Result<[u8; 32], String> {
    let bytes = hex::decode(text.trim()).map_err(|error| error.to_string())?;
    bytes
        .try_into()
        .map_err(|_| "a 32-byte key in hex".to_string())
}

/// A key's sessions, kept next to the key file so calls go on in them:
/// each agent's session, its identity once fetched, its floor (so queries
/// read the key's own writes across commands), and a call that failed
/// before its answer, by its digest and when, until it is answered.
#[derive(Default)]
struct Kept {
    sessions: HashMap<AgentId, client::Kept>,
    identities: HashMap<AgentId, [u8; 32]>,
    floors: HashMap<AgentId, u64>,
    /// Each agent's call left unanswered, by its digest.
    pending: HashMap<AgentId, [u8; 32]>,
}

impl Kept {
    fn path(key: &Path) -> PathBuf {
        let mut path = key.as_os_str().to_owned();
        path.push(".session");
        PathBuf::from(path)
    }

    /// What the key kept; nothing when there is no file. A file with a
    /// line this command cannot read is refused, not dropped: it may hold
    /// a call whose fate is unknown.
    fn load(key: &Path) -> Result<Self, String> {
        let path = Self::path(key);
        let text = match std::fs::read_to_string(&path) {
            Ok(text) => text,
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => {
                return Ok(Self::default());
            }
            Err(error) => return Err(format!("{}: {error}", path.display())),
        };
        Self::parse(&text).map_err(|line| {
            format!(
                "{}: a line this command cannot read ({line:?}); fix or remove it",
                path.display()
            )
        })
    }

    /// The kept file's contents, or the first line that does not read.
    fn parse(text: &str) -> Result<Self, String> {
        let mut kept = Self::default();
        let agent = |text: &str| text.parse().ok().map(AgentId);
        for line in text.lines() {
            let fields: Vec<&str> = line.split_whitespace().collect();
            let mut read = || -> Option<()> {
                match fields.as_slice() {
                    [] => {}
                    ["session", id, name, t0, next] => {
                        let name = hex::decode(name).ok()?.try_into().ok()?;
                        let session = client::Kept {
                            name,
                            t0: t0.parse().ok()?,
                            next: next.parse().ok()?,
                        };
                        kept.sessions.insert(agent(id)?, session);
                    }
                    ["identity", id, identity] => {
                        kept.identities
                            .insert(agent(id)?, key_bytes(identity).ok()?);
                    }
                    ["at", id, at] => {
                        kept.floors.insert(agent(id)?, at.parse().ok()?);
                    }
                    // Earlier versions kept the time it was left too.
                    ["pending", id, digest] | ["pending", id, digest, _] => {
                        kept.pending.insert(agent(id)?, key_bytes(digest).ok()?);
                    }
                    _ => return None,
                }
                Some(())
            };
            read().ok_or_else(|| line.to_string())?;
        }
        Ok(kept)
    }

    fn save(&self, key: &Path) -> Result<(), String> {
        let mut text = String::new();
        for (agent, session) in &self.sessions {
            text.push_str(&format!(
                "session {} {} {} {}\n",
                agent.0,
                hex::encode(session.name),
                session.t0,
                session.next
            ));
        }
        for (agent, identity) in &self.identities {
            text.push_str(&format!("identity {} {}\n", agent.0, hex::encode(identity)));
        }
        for (agent, at) in &self.floors {
            text.push_str(&format!("at {} {at}\n", agent.0));
        }
        for (agent, digest) in &self.pending {
            text.push_str(&format!("pending {} {}\n", agent.0, hex::encode(digest)));
        }
        // Replaced whole: a write cut short must not lose a pending call.
        let path = Self::path(key);
        let mut partial = path.clone().into_os_string();
        partial.push(".partial");
        std::fs::write(&partial, text)
            .and_then(|()| std::fs::rename(&partial, &path))
            .map_err(|error| format!("{}: {error}", path.display()))
    }
}

/// A call, or (`Some(linearizable)`) a query.
fn invoke(call: &CallArgs, query: Option<bool>) -> Result<(), String> {
    let seed = std::fs::read_to_string(&call.key)
        .map_err(|error| format!("{}: {error}", call.key.display()))?;
    let key = SigningKey::from_bytes(&key_bytes(&seed)?);
    let arguments = hex::decode(call.args.trim()).map_err(|error| error.to_string())?;
    let agent = AgentId(call.agent);
    let instance = InstanceId(call.instance);
    let target = call.node.target()?;
    let mut kept = Kept::load(&call.key)?;
    let mut client = Client::resume(&target, key, kept.sessions.clone(), kept.identities.clone());
    for (agent, at) in &kept.floors {
        client.raise_floor(*agent, *at);
    }
    let schema = client
        .schema(agent, instance)
        .map_err(failed)?
        .ok_or_else(|| format!("nothing is installed as instance {}", call.instance))?;
    let method = method_named(&schema, &call.method)?;
    let answer = if let Some(linearizable) = query {
        let not_after = vos_node::wall_clock() + 60_000;
        let consistency = if linearizable {
            Consistency::Linearizable
        } else {
            Consistency::Applied {
                at: client.floor(agent),
            }
        };
        client.query_with(agent, instance, method, &arguments, not_after, consistency)
    } else {
        // A call that failed before its answer goes again with its
        // sequence, and is answered once. Another call leaves that session
        // first, so the earlier one's answer is never taken for its own.
        let digest =
            vos_pvm::precompile::blake2b_256(&(instance, method, arguments.clone()).encode());
        match kept.pending.remove(&agent) {
            Some(pending) if pending != digest => {
                eprintln!(
                    "an earlier call to agent {} was never answered: whether it ran stays unknown",
                    agent.0
                );
                client.renew(agent);
            }
            // A refusal of its session proves nothing of the first: copies
            // may be on their way, or its session collected.
            Some(_) => client.repeats_unknown(agent),
            None => {}
        }
        let answer = client.call(agent, instance, method, &arguments);
        // Unanswered: the call may have run, or may yet. A lost one can be
        // answered no more.
        let unanswered = match &answer {
            Err(ClientError::Lost) => false,
            Err(_) => true,
            Ok(answer) => matches!(
                answer,
                Answer::Stopped | Answer::NotLeader { .. } | Answer::Unavailable | Answer::TimedOut
            ),
        };
        if unanswered {
            kept.pending.insert(agent, digest);
        }
        answer
    };
    kept.sessions = client.sessions();
    kept.identities = client.identities();
    kept.floors = client.floors();
    kept.save(&call.key)?;
    match answer {
        Ok(answer) => print_answer(&answer),
        Err(ClientError::Lost) => Err(
            "the call may have run, and its session is gone: its answer is lost for good".into(),
        ),
        Err(error) if query.is_none() => Err(format!(
            "{}; the call may have run: run it again to learn its answer",
            failed(error)
        )),
        Err(error) => Err(failed(error)),
    }
}

fn describe(answer: &Answer) -> String {
    match answer {
        Answer::Ran {
            outcome: Outcome::Done(reply),
            ..
        } => format!("done {}", hex::encode(reply)),
        Answer::Ran {
            outcome: Outcome::Failed { code, detail },
            ..
        } => {
            format!("failed {code} {}", hex::encode(detail))
        }
        Answer::Refused(code) => match *code {
            refusal::SESSIONS_FULL => {
                "refused: the agent holds as many sessions as it may; try again later".into()
            }
            refusal::KEY_SESSIONS_FULL => {
                "refused: this key holds as many sessions at the agent as it may".into()
            }
            code => format!("refused {code}"),
        },
        other => format!("{other:?}"),
    }
}

fn print_answer(answer: &Answer) -> Result<(), String> {
    match answer {
        Answer::Ran { .. } => {
            println!("{}", describe(answer));
            Ok(())
        }
        other => Err(describe(other)),
    }
}
