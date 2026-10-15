//! `vos`: run a node, operate it with its admin token, and call its agents
//! with a client key.

mod args;
mod call;
mod jam;
mod kept;
mod operator;

use std::fmt::Display;
use std::path::Path;
use std::process::ExitCode;

use clap::Parser;
use ed25519_dalek::SigningKey;
use vos_node::client::ClientError;
use vos_node::{Config, Node, Space};
use vos_wire::ids::MethodId;
use vos_wire::schema::Schema;

use args::{Cli, Command, KeyCommand, NodeCommand, RunArgs};
use call::{invoke, read_workflow};

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
        Command::Workflow(read) => read_workflow(&read),
        Command::Jam { command } => command.run(),
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

fn method_named(schema: &Schema, name: &str) -> Result<MethodId, String> {
    schema
        .method_id(name)
        .ok_or_else(|| format!("no method {name}"))
}

fn failed(error: ClientError) -> String {
    format!("{error:?}")
}

/// An error with the file at `path`, as `map_err` takes it.
fn at<E: Display>(path: &Path) -> impl FnOnce(E) -> String {
    move |error| format!("{}: {error}", path.display())
}
