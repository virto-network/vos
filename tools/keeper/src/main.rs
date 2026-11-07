//! `vos-keeper`: the home's keeper, run on the operator's host under an
//! operator key every node of the home lists (`vos_keeper`).

use std::path::PathBuf;
use std::process::ExitCode;

use clap::{Parser, Subcommand};
use ed25519_dalek::SigningKey;
use vos_keeper::{Home, Keeper};
use vos_node::client::{self, Client, Operator, Target};
use vos_node::tls::Trust;
use vos_wire::ids::{AgentId, InstanceId};

#[derive(Parser)]
#[command(about = "Keep a home's pool of personal agents")]
struct Args {
    /// The operator key's file: its 32-byte seed in hex, as a node's
    /// `operator.key`.
    #[arg(long)]
    key: PathBuf,
    /// Each node of the home, by number from 1: its API's socket
    /// (`unix:<path>`) or a loopback gateway's `http://` address.
    #[arg(long = "node", required = true)]
    nodes: Vec<String>,
    /// The home's agent, which holds `Homes` and the credential actor.
    #[arg(long)]
    home: u32,
    /// `Homes`' instance there.
    #[arg(long, default_value_t = 3)]
    homes: u32,
    /// `Personal`'s instance in each pool agent.
    #[arg(long, default_value_t = 1)]
    personal: u32,
    /// The nodes each new agent is replicated on.
    #[arg(long, value_delimiter = ',', default_values_t = [1, 2, 3])]
    replicas: Vec<u8>,
    #[command(subcommand)]
    command: Command,
}

#[derive(Subcommand)]
enum Command {
    /// Make and stock agents until the pool holds `to`.
    TopUp {
        #[arg(long)]
        to: u32,
        /// `Personal`'s ELF.
        #[arg(long)]
        elf: PathBuf,
        /// Agents made at once.
        #[arg(long, default_value_t = 16)]
        batch: usize,
    },
    /// Stock agents made otherwise.
    Stock { agents: Vec<u32> },
    /// Install `Personal` anew over every agent of the pool, a batch at a
    /// time, stopping at the first refusal.
    Upgrade {
        #[arg(long)]
        elf: PathBuf,
        #[arg(long, default_value_t = 16)]
        batch: usize,
    },
    /// The pool's counts.
    Tally,
}

fn keeper(args: &Args) -> Result<Keeper, String> {
    let text = std::fs::read_to_string(&args.key)
        .map_err(|error| format!("{}: {error}", args.key.display()))?;
    let seed: [u8; 32] = hex::decode(text.trim())
        .ok()
        .and_then(|bytes| bytes.try_into().ok())
        .ok_or("the key is not 32 bytes of hex")?;
    let key = SigningKey::from_bytes(&seed);
    let mut operators = Vec::new();
    let mut routes = std::collections::HashMap::new();
    let mut first = None;
    for url in &args.nodes {
        let target = Target::new(url, Trust::Loopback).map_err(|error| error.to_string())?;
        let node = client::node_id(&target).map_err(|error| format!("{url}: {error}"))?;
        operators.push(Operator::signing(&target, key.clone(), node));
        routes.insert(node.0, target.clone());
        first.get_or_insert(target);
    }
    let first = first.ok_or("no node")?;
    let caller = Client::new(&first, key).with_routes(routes);
    let home = Home {
        agent: AgentId(args.home),
        homes: InstanceId(args.homes),
        personal: InstanceId(args.personal),
    };
    Ok(Keeper::new(operators, caller, home, args.replicas.clone()))
}

fn run(args: Args) -> Result<(), String> {
    let keeper = keeper(&args)?;
    let read = |path: &PathBuf| {
        std::fs::read(path).map_err(|error| format!("{}: {error}", path.display()))
    };
    match &args.command {
        Command::TopUp { to, elf, batch } => {
            let pooled = keeper
                .top_up(*to, &read(elf)?, *batch)
                .map_err(|error| error.to_string())?;
            println!("pooled {pooled}");
        }
        Command::Stock { agents } => {
            let agents: Vec<AgentId> = agents.iter().copied().map(AgentId).collect();
            let pooled = keeper.stock(&agents).map_err(|error| error.to_string())?;
            println!("pooled {pooled}");
        }
        Command::Upgrade { elf, batch } => {
            let upgraded = keeper
                .upgrade(&read(elf)?, *batch)
                .map_err(|error| error.to_string())?;
            println!("upgraded {upgraded}");
        }
        Command::Tally => {
            let counts = keeper.tally().map_err(|error| error.to_string())?;
            println!(
                "pooled {} claimed {} assigned {}",
                counts.pooled, counts.claimed, counts.assigned
            );
        }
    }
    Ok(())
}

fn main() -> ExitCode {
    match run(Args::parse()) {
        Ok(()) => ExitCode::SUCCESS,
        Err(error) => {
            eprintln!("vos-keeper: {error}");
            ExitCode::FAILURE
        }
    }
}
