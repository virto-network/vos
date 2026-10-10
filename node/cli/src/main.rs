//! `vos`: run a node, operate it with its admin token, and call its agents
//! with a client key.

use std::collections::HashMap;
use std::net::SocketAddr;
use std::path::{Path, PathBuf};
use std::process::ExitCode;

use clap::{Parser, Subcommand};
use ed25519_dalek::SigningKey;
use vos_node::client::{Client, Operator, Target};
use vos_node::tls::{IngressTls, Trust};
use vos_node::{ADMIN_TOKEN, Config, NODE_KEY, Node, Space};
use vos_wire::abi::refusal;
use vos_wire::ids::{AgentId, InstanceId, MethodId, Principal, SessionId};
use vos_wire::ingress::{Answer, Install, Rejection};
use vos_wire::result::Outcome;
use vos_wire::schema::Schema;

#[derive(Parser)]
#[command(
    name = "vos",
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
    /// Run a query, signed with a client key.
    Query(CallArgs),
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
                },
        } => node(&data, listen, &agent, tls.ingress(), space.as_deref()),
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
        Command::Call(call) => invoke(&call, false),
        Command::Query(call) => invoke(&call, true),
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
) -> Result<(), String> {
    let mut config = Config::new(link(agent)?);
    config.ingress_tls = tls;
    config.space = space.map(Space::read).transpose()?;
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

/// A standard program from an ELF built with the guest toolchain.
fn link(path: &Path) -> Result<Vec<u8>, String> {
    let elf = std::fs::read(path).map_err(|error| format!("{}: {error}", path.display()))?;
    vos_pvm_compiler::link_elf_spi(&elf).map_err(|error| format!("{}: {error:?}", path.display()))
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

/// A key's session on one node, kept next to the key file so calls go on
/// in one session: its node, id, when it was opened, and each agent's next
/// sequence.
struct Kept {
    node: [u8; 32],
    session: u64,
    opened: u64,
    next: HashMap<AgentId, u64>,
}

impl Kept {
    fn path(key: &Path) -> PathBuf {
        let mut path = key.as_os_str().to_owned();
        path.push(".session");
        PathBuf::from(path)
    }

    fn load(key: &Path) -> Option<Self> {
        let text = std::fs::read_to_string(Self::path(key)).ok()?;
        let mut kept = Kept {
            node: [0; 32],
            session: 0,
            opened: 0,
            next: HashMap::new(),
        };
        for line in text.lines() {
            let fields: Vec<&str> = line.split_whitespace().collect();
            match fields.as_slice() {
                ["node", node] => kept.node = key_bytes(node).ok()?,
                ["session", session] => kept.session = session.parse().ok()?,
                ["opened", opened] => kept.opened = opened.parse().ok()?,
                ["next", agent, sequence] => {
                    kept.next
                        .insert(AgentId(agent.parse().ok()?), sequence.parse().ok()?);
                }
                _ => return None,
            }
        }
        Some(kept)
    }

    fn save(&self, key: &Path) -> Result<(), String> {
        let mut text = format!(
            "node {}\nsession {}\nopened {}\n",
            hex::encode(self.node),
            self.session,
            self.opened
        );
        for (agent, sequence) in &self.next {
            text.push_str(&format!("next {} {sequence}\n", agent.0));
        }
        std::fs::write(Self::path(key), text).map_err(|error| error.to_string())
    }
}

/// Open a new session, signed later than the key's last open.
fn open(node: &Target, key: &SigningKey, last: u64) -> Result<(Client, Kept), String> {
    let time = vos_node::wall_clock().max(last + 1);
    let client = Client::open(node, key.clone(), time).map_err(failed)?;
    let kept = Kept {
        node: client.node().0,
        session: client.session().0,
        opened: time,
        next: HashMap::new(),
    };
    Ok((client, kept))
}

fn invoke(call: &CallArgs, query: bool) -> Result<(), String> {
    let seed = std::fs::read_to_string(&call.key)
        .map_err(|error| format!("{}: {error}", call.key.display()))?;
    let key = SigningKey::from_bytes(&key_bytes(&seed)?);
    let arguments = hex::decode(call.args.trim()).map_err(|error| error.to_string())?;
    let agent = AgentId(call.agent);
    let instance = InstanceId(call.instance);
    let target = call.node.target()?;
    let node = vos_node::client::node_id(&target).map_err(failed)?;
    let kept = Kept::load(&call.key).filter(|kept| kept.node == node.0);
    let last = kept.as_ref().map_or(0, |kept| kept.opened);
    let (mut client, mut kept) = match kept {
        Some(kept) => (
            Client::resume(
                &target,
                key.clone(),
                node,
                SessionId(kept.session),
                kept.next.clone(),
            ),
            kept,
        ),
        None => open(&target, &key, last)?,
    };
    let schema = client
        .schema(agent, instance)
        .map_err(failed)?
        .ok_or_else(|| format!("nothing is installed as instance {}", call.instance))?;
    let method = method_named(&schema, &call.method)?;
    let send = |client: &mut Client| {
        if query {
            let not_after = vos_node::wall_clock() + 60_000;
            client.query(agent, instance, method, &arguments, not_after)
        } else {
            client.call(agent, instance, method, &arguments)
        }
        .map_err(failed)
    };
    let mut answer = send(&mut client)?;
    // A session the node forgot or the agent let expire: open another.
    if matches!(
        answer,
        Answer::Rejected(Rejection::UnknownSession) | Answer::Refused(refusal::EXPIRED)
    ) {
        (client, kept) = open(&target, &key, kept.opened)?;
        answer = send(&mut client)?;
    }
    kept.next = client.next().clone();
    kept.save(&call.key)?;
    print_answer(&answer)
}

fn describe(answer: &Answer) -> String {
    match answer {
        Answer::Ran(Outcome::Done(reply)) => format!("done {}", hex::encode(reply)),
        Answer::Ran(Outcome::Failed { code, detail }) => {
            format!("failed {code} {}", hex::encode(detail))
        }
        Answer::Refused(code) => format!("refused {code}"),
        other => format!("{other:?}"),
    }
}

fn print_answer(answer: &Answer) -> Result<(), String> {
    match answer {
        Answer::Ran(_) => {
            println!("{}", describe(answer));
            Ok(())
        }
        other => Err(describe(other)),
    }
}
