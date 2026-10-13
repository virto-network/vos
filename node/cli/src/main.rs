//! `vos`: run a node, operate it with its admin token, and call its agents
//! with a client key.

mod args;
mod call;
mod kept;

use std::fmt::Display;
use std::path::Path;
use std::process::ExitCode;

use clap::Parser;
use ed25519_dalek::SigningKey;
use vos_node::client::{ClientError, Operator};
use vos_node::{ADMIN_TOKEN, Config, NODE_KEY, Node, Space};
use vos_wire::ids::{AgentId, InstanceId, MethodId, Principal};
use vos_wire::ingress::{Answer, Install};
use vos_wire::schema::Schema;

use args::{
    AgentCommand, Cli, Command, InstallArgs, KeyCommand, NodeCommand, OperatorArgs, RoleArgs,
    RunArgs,
};
use call::{invoke, print_admin_answer, said};

/// mimalloc, unless built without it: a thread frees memory another thread
/// allocated without taking that thread's lock, as the node's executors,
/// writer and store workers do all the time.
#[cfg(feature = "mimalloc")]
#[global_allocator]
static ALLOCATOR: mimalloc::MiMalloc = mimalloc::MiMalloc;

/// With mimalloc, transparent huge pages are off: 2 MiB pages under its
/// arenas keep more of a node resident, at the cost of some TLB misses
/// without them. Processes it starts inherit this.
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
        Command::Node { command } => command.run(),
        Command::Key { command } => command.run(),
        Command::Agent { command } => command.run(),
        Command::Install(install) => install.run(),
        Command::Role(role) => role.run(),
        Command::Call(call) => invoke(&call, None),
        Command::Query { call, linearizable } => invoke(&call, Some(linearizable)),
    }
}

impl NodeCommand {
    fn run(self) -> Result<(), String> {
        match self {
            NodeCommand::Run(node) => node.serve(),
            NodeCommand::Info { node } => {
                let id = vos_node::client::node_id(&node.target()?).map_err(failed)?;
                println!("{}", hex::encode(id.0));
                Ok(())
            }
        }
    }
}

impl RunArgs {
    /// Run the node until it is killed.
    fn serve(self) -> Result<(), String> {
        // The node's log, on stderr: `VOS_LOG` names the level, `info`
        // unless it says otherwise.
        let level = std::env::var("VOS_LOG")
            .ok()
            .and_then(|level| level.parse().ok())
            .unwrap_or(tracing_subscriber::filter::LevelFilter::INFO);
        tracing_subscriber::fmt()
            .with_writer(std::io::stderr)
            .with_max_level(level)
            .init();
        let mut config = Config::new(link(&self.agent)?);
        config.ingress_tls = self.tls.ingress();
        config.space = self.space.as_deref().map(Space::read).transpose()?;
        config.peer_bind = self.peer_bind;
        #[cfg(feature = "faults")]
        {
            eprintln!("vos: WARNING: this build injects faults; it is for tests only");
            if let Some(path) = std::env::var_os("VOS_FAULTS") {
                vos_node::faults::Faults::install(&mut config, Path::new(&path))
                    .map_err(|error| error.to_string())?;
            }
        }
        let node = Node::open(&self.data, config).map_err(|error| format!("{error:?}"))?;
        let address = node
            .serve(self.listen)
            .map_err(|error| format!("{error:?}"))?;
        println!("listening on {address}");
        println!("node {}", hex::encode(node.id().0));
        loop {
            std::thread::park();
        }
    }
}

impl KeyCommand {
    fn run(self) -> Result<(), String> {
        let KeyCommand::New { out } = self;
        new_key(&out)
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
        .map_err(at(out))?;
    file.write_all(hex::encode(seed).as_bytes())
        .map_err(|error| error.to_string())?;
    println!(
        "{}",
        hex::encode(SigningKey::from_bytes(&seed).verifying_key().to_bytes())
    );
    Ok(())
}

fn key_bytes(text: &str) -> Result<[u8; 32], String> {
    let bytes = hex::decode(text.trim()).map_err(|error| error.to_string())?;
    bytes
        .try_into()
        .map_err(|_| "a 32-byte key in hex".to_string())
}

impl AgentCommand {
    fn run(self) -> Result<(), String> {
        match self {
            AgentCommand::Create { operator, replicas } => match operator_of(&operator)?
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
                other => {
                    let (Ok(text) | Err(text)) = said(&other);
                    Err(text)
                }
            },
            AgentCommand::Replace {
                operator,
                agent,
                remove,
                add,
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
        }
    }
}

impl InstallArgs {
    fn run(self) -> Result<(), String> {
        let program = link(&self.program)?;
        let schema = schema_of(&program)?;
        let attestables = self
            .attestables
            .iter()
            .map(|pair| {
                let (name, path) = split(pair)?;
                Ok((method_named(&schema, name)?, link(Path::new(path))?))
            })
            .collect::<Result<Vec<_>, String>>()?;
        let roles = self
            .roles
            .iter()
            .map(|pair| {
                let (name, byte) = split(pair)?;
                Ok((name.as_bytes().to_vec(), role_byte(byte)?))
            })
            .collect::<Result<Vec<_>, String>>()?;
        let install = Install {
            instance: InstanceId(self.instance),
            program,
            attestables,
            roles,
        };
        let answer = operator_of(&self.operator)?
            .install(AgentId(self.agent), &install)
            .map_err(failed)?;
        print_admin_answer(&answer)
    }
}

impl RoleArgs {
    fn run(self) -> Result<(), String> {
        let key = key_bytes(&self.principal)?;
        let role = match self.role.as_str() {
            "none" => None,
            byte => Some(role_byte(byte)?),
        };
        let answer = operator_of(&self.operator)?
            .grant(AgentId(self.agent), Principal::Client(key), role)
            .map_err(failed)?;
        print_admin_answer(&answer)
    }
}

fn role_byte(byte: &str) -> Result<u8, String> {
    byte.parse().map_err(|_| format!("a role byte: {byte}"))
}

fn operator_of(args: &OperatorArgs) -> Result<Operator, String> {
    let path = args.data.join(ADMIN_TOKEN);
    let token = std::fs::read_to_string(&path).map_err(at(&path))?;
    // On the node's host, its data directory holds its key.
    let target = args.node.target_or(Some(&args.data.join(NODE_KEY)))?;
    Ok(Operator::new(&target, &token))
}

/// A standard program from an ELF built with the guest toolchain. With the
/// PVM's perf map on, its functions are named in it.
fn link(path: &Path) -> Result<Vec<u8>, String> {
    let elf = std::fs::read(path).map_err(at(path))?;
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
        .method_id(name)
        .ok_or_else(|| format!("no method {name}"))
}

fn split(pair: &str) -> Result<(&str, &str), String> {
    pair.split_once('=')
        .ok_or_else(|| format!("expected NAME=VALUE: {pair}"))
}

fn failed(error: ClientError) -> String {
    format!("{error:?}")
}

/// An error with the file at `path`, as `map_err` takes it.
fn at<E: Display>(path: &Path) -> impl FnOnce(E) -> String {
    move |error| format!("{}: {error}", path.display())
}
